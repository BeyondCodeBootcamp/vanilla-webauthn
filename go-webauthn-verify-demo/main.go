package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/go-webauthn/webauthn/protocol"
)

type WebAuthn struct {
	AppID            string
	RPID             string
	AllowedOrigins   []string
	TopOrigins       []string
	UserVerification bool
}

func (w *WebAuthn) verifyAuthAttemptByRegisteredCredential(
	parsedCredentialCreation *protocol.ParsedCredentialCreationData,
	challenge string,
	credentialRequestResponse []byte,
) (*protocol.ParsedCredentialAssertionData, error) {

	parsedCredentialRequest, err := protocol.ParseCredentialRequestResponseBytes(credentialRequestResponse)
	if err != nil {
		return nil, err
	}

	err = parsedCredentialRequest.Verify(
		challenge,
		w.RPID,
		w.AllowedOrigins,
		w.TopOrigins,
		protocol.TopOriginAutoVerificationMode,
		w.AppID,
		w.UserVerification,
		parsedCredentialCreation.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
	)
	return parsedCredentialRequest, err
}

// These are for testing only
type CredentialCreationResponse struct {
	ID       string
	Response struct {
		PublicKey      string           `json:"publicKey"`
		PublicKeyECDSA *ecdsa.PublicKey `json:"-"`
	} `json:"response"`
}
type CredentialRequestResponse struct {
	ID       string
	Response struct {
		ClientDataJSON  string `json:"clientDataJSON"`
		ClientDataBytes []byte `json:"-"`
		ClientData      struct {
			Challenge string `json:"challenge"`
		} `json:"-"`
		AuthenticatorData  string `json:"authenticatorData"`
		AuthenticatorBytes []byte `json:"-"`
		Signature          string `json:"signature"`
		SignatureBytes     []byte `json:"-"`
		VerifiableBytes    []byte `json:"-"`
	} `json:"response"`
}

func decodeCredentialCretionResponse(credentialCreationResponse []byte) (*CredentialCreationResponse, error) {
	credCreation := &CredentialCreationResponse{}
	if err := json.Unmarshal(credentialCreationResponse, credCreation); err != nil {
		return nil, err
	}

	publicKeyDER, err := base64.RawURLEncoding.DecodeString(
		credCreation.Response.PublicKey,
	)
	if err != nil {
		return nil, err
	}

	credCreation.Response.PublicKeyECDSA, err = parseECDSAPublicKey(publicKeyDER)
	if err != nil {
		return nil, err
	}

	return credCreation, nil
}

func parseECDSAPublicKey(derBytes []byte) (*ecdsa.PublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
	}

	// Type assert to *ecdsa.PublicKey
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPublicKey, nil
}

func decodeCredentialRequestResponse(credentialRequestResponse []byte) (*CredentialRequestResponse, error) {
	credReq := &CredentialRequestResponse{}
	if err := json.Unmarshal(credentialRequestResponse, credReq); err != nil {
		return nil, err
	}
	fmt.Println()
	fmt.Println("Credential ID:", credReq.ID)

	clientDataBytes, err := base64.RawURLEncoding.DecodeString(
		credReq.Response.ClientDataJSON,
	)
	if err != nil {
		return nil, err
	}

	credReq.Response.ClientDataBytes = clientDataBytes
	fmt.Println(
		"Client Data JSON:",
		string(clientDataBytes),
	)
	fmt.Println()

	if err := json.Unmarshal(clientDataBytes, &credReq.Response.ClientData); err != nil {
		return nil, err
	}

	authenticatorBytes, err := base64.RawURLEncoding.DecodeString(credReq.Response.AuthenticatorData)
	if err != nil {
		return nil, err
	}
	credReq.Response.AuthenticatorBytes = authenticatorBytes

	signatureBytes, err := base64.RawURLEncoding.DecodeString(credReq.Response.Signature)
	if err != nil {
		return nil, err
	}
	credReq.Response.SignatureBytes = signatureBytes

	clientDataHash := sha256.Sum256(credReq.Response.ClientDataBytes)
	verifiableData := append(credReq.Response.AuthenticatorBytes, clientDataHash[:]...)
	// each algo specifies the SHA-xxx hash in its name
	// exception: SHA512 used for EDDSA
	verifiableHash := sha256.Sum256(verifiableData)

	credReq.Response.VerifiableBytes = verifiableHash[:]

	return credReq, nil
}

func getPreviouslyStoredChallenge(credReqResp *CredentialRequestResponse) (string, error) {
	// for the demo we just use the requests own challenge
	return credReqResp.Response.ClientData.Challenge, nil
}

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "show fully parsed credential request")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		log.Fatalf("Usage: %s <./fixtures/01-create.json> <./fixtures/01-request.json>", os.Args[0])
	}

	attestationFile := args[0]
	assertionFile := args[1]

	fmt.Printf(
		"Credential Creation Fixture (01): %s\n",
		filepath.Base(attestationFile),
	)
	fmt.Printf(
		"Credential Request Fixture (02): %s\n",
		filepath.Base(assertionFile),
	)

	credentialCreationResponse, err := os.ReadFile(attestationFile)
	if err != nil {
		log.Fatalf("Failed to read attestation file: %v", err)
	}
	credentialRequestResponse, err := os.ReadFile(assertionFile)
	if err != nil {
		log.Fatalf("Failed to read assertion file: %v", err)
	}

	RPID := "local.pocketid.app"
	webauthn := WebAuthn{
		AppID:            "",
		RPID:             RPID,
		AllowedOrigins:   []string{fmt.Sprintf("https://%s", RPID)},
		TopOrigins:       nil,
		UserVerification: true,
	}

	parsedCredentialCreation, err := protocol.ParseCredentialCreationResponseBytes(credentialCreationResponse)
	if err != nil {
		log.Fatalf("Failed to parse credential creation response: %v", err)
	}

	credCreation, err := decodeCredentialCretionResponse(credentialCreationResponse)
	if err != nil {
		log.Fatalf("Could not decode credentialCreation: %v", err)
	}

	credReq, err := decodeCredentialRequestResponse(credentialRequestResponse)
	if err != nil {
		log.Fatalf("Could not decode credentialRequest: %v", err)
	}

	verified := ecdsa.VerifyASN1(
		credCreation.Response.PublicKeyECDSA,
		credReq.Response.VerifiableBytes,
		credReq.Response.SignatureBytes,
	)
	if !verified {
		log.Fatalf("Could not verify signature bytes")
	}

	fmt.Println("Verified:", verified)
	fmt.Println("")

	// typically the challenge would be looked up from storage for verification
	storedChallenge, err := getPreviouslyStoredChallenge(credReq)
	if err != nil {
		log.Fatalf("Could not find challenging matching the request: %v", err)
	}
	fmt.Printf("Would-be Stored Challenge (03): %s\n", storedChallenge)

	auth, err := webauthn.verifyAuthAttemptByRegisteredCredential(parsedCredentialCreation, storedChallenge, credentialRequestResponse)
	if err != nil {
		log.Fatalf("Error: verification failed: %v", err)
	}

	if debug {
		fmt.Printf("\n%#+v\n", auth)
	}

	fmt.Println()
	fmt.Println("Success: Verified")
	fmt.Println()
}
