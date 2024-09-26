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
