package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/go-webauthn/webauthn/protocol"
)

type CredentialIDString = string
type ChallengeString = string

func main() {
	challengeDB := map[CredentialIDString]bool{}
	regDB := map[ChallengeString]*protocol.ParsedCredentialCreationData{}

	var debug bool
	flag.BoolVar(&debug, "debug", false, "show fully parsed credential request")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		log.Fatalf("Usage: %s <./fixtures/01-create.json> <./fixtures/01-request.json>", os.Args[0])
	}

	attestationFile := args[0]
	assertionFile := args[1]

	{
		// CHALLENGE would be created BEFORE getting the authenticator registration

		fmt.Printf(
			"[Registration] Credential Creation Fixture (01): %s\n",
			filepath.Base(attestationFile),
		)

		credentialCreationResponse, err := os.ReadFile(attestationFile)
		if err != nil {
			log.Fatalf("Failed to read attestation file: %v", err)
		}
		registration, err := protocol.ParseCredentialCreationResponseBytes(credentialCreationResponse)
		if err != nil {
			log.Fatalf("Failed to parse credential creation response: %v", err)
		}

		fmt.Println("Credential ID (Registration):", registration.ID)
		if debug {
			fmt.Printf("\n%#+v\n", registration)
		}

		challengeWeWouldCreateAbove := registration.Response.CollectedClientData.Challenge
		challengeDB[challengeWeWouldCreateAbove] = true

		if _, ok := challengeDB[registration.Response.CollectedClientData.Challenge]; !ok {
			log.Fatalf("Challenge was not found in db, Registration rejected")
		}
		delete(challengeDB, registration.Response.CollectedClientData.Challenge)

		regDB[registration.ID] = registration
	}

	var assertion *protocol.ParsedCredentialAssertionData
	{
		// CHALLENGE would be created BEFORE getting the authenticator response

		fmt.Printf(
			"[Assertion] Credential Request Fixture (02): %s\n",
			filepath.Base(assertionFile),
		)

		credentialRequestResponse, err := os.ReadFile(assertionFile)
		if err != nil {
			log.Fatalf("Failed to read assertion file: %v", err)
		}
		assertion, err = protocol.ParseCredentialRequestResponseBytes(credentialRequestResponse)
		if err != nil {
			log.Fatalf("Could not decode credentialRequest: %v", err)
		}

		fmt.Println("Credential ID (Assertion):", assertion.ID)
		if debug {
			fmt.Printf("\n%#+v\n", assertion)
		}

		challengeWeWouldCreateAbove := assertion.Response.CollectedClientData.Challenge
		challengeDB[challengeWeWouldCreateAbove] = true
	}

	{
		originalChallenge := assertion.Response.CollectedClientData.Challenge
		if _, ok := challengeDB[originalChallenge]; !ok {
			log.Fatalf("Challenge was not found in db, Assertion rejected")
		}
		delete(challengeDB, originalChallenge)

		registration, ok := regDB[assertion.ID]
		if !ok {
			log.Fatalf("passkey has been deleted from user's account")
		}

		RPID := "local.pocketid.app"
		config := struct {
			AppID            string
			RPID             string
			AllowedOrigins   []string
			TopOrigins       []string
			UserVerification bool
		}{
			"",
			RPID,
			[]string{fmt.Sprintf("https://%s", RPID)},
			nil,
			true,
		}
		if err := assertion.Verify(
			originalChallenge,
			config.RPID,
			config.AllowedOrigins,
			config.TopOrigins,
			protocol.TopOriginAutoVerificationMode,
			config.AppID,
			config.UserVerification,
			registration.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
		); err != nil {
			log.Fatalf("%s", err)
			return
		}
	}

	fmt.Println()
	fmt.Println("Success: Verified")
	fmt.Println()
}
