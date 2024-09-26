# PassKeys with the Go Stanard Library

WebAuthn is much simpler than it looks.

```sh
go run ./cmd/passkey-verify/ ../fixtures/apple-m2-01-credential-creation-response.json ../fixtures/apple-m2-02-credential-request-response.json
```

Most of the complexity lies in "security" features that were DOA - Apple,
Google, Microsoft, Brave, etc - never implemented them, ostensibly due to
various concerns related to privacy and the limitations of trusted platform
computing.

The practical security model is much more similar to OIDC (the standardized
implementaiton of OAuth2).

## Countering Hardware Cloning

One of the most practically useful features is that if an authenticator has ever
given a counter, then any subsequent use must have a counter higher than the
previous one, or it should fail. This prevents hardware cloning.

# PassKeys with go-webauthn/webauthn

This follows all of the WebAuthn _ceremonies_, but implements far more than is
used in a practical setting among any of the authenticators that implement
WebAuthn, which can be confusing.

```sh
go run ./cmd/webauthn-verify/ ../fixtures/apple-m2-01-credential-creation-response.json ../fixtures/apple-m2-02-credential-request-response.json
```

The key bits that you'll need to know are:

```go
err = parsedCredentialRequest.Verify(
		challenge,
		rpID,
		allowedOrigins,
		topOrigins,
		protocol.TopOriginAutoVerificationMode,
		appId,
		userVerification,
		parsedCredentialCreation.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
	)
```
