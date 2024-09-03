package main

import (
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
type CredentialRequest struct {
	ID       string
	Response struct {
		ClientDataJSON string `json:"clientDataJSON"`
	} `json:"response"`
}
type ClientData struct {
	Challenge string `json:"challenge"`
}

// this should fetch the challenge from the database, not the object
func getMatchingChallenge(credentialRequestResponse []byte) (string, error) {
	// use the data to lookup the challenge
	credReq := &CredentialRequest{}
	if err := json.Unmarshal(credentialRequestResponse, credReq); err != nil {
		return "", err
	}
	fmt.Println()
	fmt.Println("Credential ID:", credReq.ID)

	clientDataJSON, err := base64.RawURLEncoding.DecodeString(
		credReq.Response.ClientDataJSON,
	)
	if err != nil {
		return "", err
	}
	fmt.Println(
		"Client Data JSON:",
		string(clientDataJSON),
	)
	fmt.Println()

	clientData := &ClientData{}
	if err := json.Unmarshal(clientDataJSON, clientData); err != nil {
		return "", err
	}

	// for the demo we just use the requests own challenge
	return clientData.Challenge, nil
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

	// typically the challenge would be looked up from storage for verification
	storedChallenge, err := getMatchingChallenge(credentialRequestResponse)
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
