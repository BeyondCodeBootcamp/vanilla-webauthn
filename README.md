# [Passkeys](https://github.com/BeyondCodeBootcamp/passkeys)

A Simple, Vanilla WebAuthn Demo

## PassKey

WebAuthn is very simple - so much so that having a framework or library around
it almost seems absurd.

However, much like WebCrypto, there's a lot of unfortunate boilerplate, opaque
objects, and unintuitive discovery mechanisms (or lack thereof) that make it
cumbersome and confusing.

The goal of the `PassKey` is not to provide a "framework" or abstraction around
WebAuthn, but more just to make the subset of the spec that's commonly
implemented more straightforward and approachable.

## Table of Contents

- Example
  - Register Passkey
  - Use Passkey to Authenticate
- API (PassKey)
- PassUI (Example UI)

## Example

How to Register and Authenticate via WebAuthn Passkeys.

### Register Passkey

"Register" is a "Create or Replace" operation.

It gives back the public key and device information about the authenticator.

```js
let regRequest = window.structuredClone(PassKey.reg.defaultOpts);
console.log(regRequest);
/*
    {
      publicKey: {
        signal: null,
        attestation: "none",
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "discouraged", // TOFU*
        },
        challenge: new Uint8Array(0),
        excludeCredentials: [],
        pubKeyCredParams: [
          { type: "public-key", alg: PassKey.reg.COSE_ES256 },
          { type: "public-key", alg: PassKey.reg.COSE_RS256 },
        ],
        rp: { id: window.location.hostname, name: "" },
        timeout: 180 * 1000,
        user: { id: new Uint8Array(0), name: "", displayName: "" },
      },
    }
*/

// these are required and have no reasonable defaults
regRequest.publicKey.rp.name = "Example App";
regRequest.publicKey.user.name = "jon@example.com";
regRequest.publicKey.user.displayName = "Jon";

// Note: `regRequest.publicKey.user.id` can hold 64 bytes of aribtrary data,
// but will be made random by PassKey.reg.createOrReplace() if not non-zero

// exclude all USER IDs to prevent them from being deleted and replaced
regRequest.publicKey.excludeCredentials = [
  { id: authResp.response.userHandle },
];

// 'signal' is managed between webauthn operations and 'challenge' is created if none is provided
let regResp = await PassKey.reg.createOrReplace(regRequest);
let regResult = PassKey.reg.responseToJSON(regResp);
console.log(regResult);
/*
    {
      "authenticatorAttachment": "platform",
      "id": "<same as rawId, but base64 rather than hex>",
      "rawId": "<hex-encoded credential id>",
      "response": {
        "attestationObject": "<hex of cbor of authenticator details>",
        "authenticatorData": "<subset of attestation data>",
        "clientDataJSON": "<preserved byte order for signature verification>",
        "publicKey": "<asn1-der-encoded key>",
        "publicKeyAlgorithm": "ES256",
        "transports": [ "hybrid", "internal" ]
      },
      "type": "public-key"
    }
 */
```

<small>TOFU means "Trust on First Use" - meaning that you don't need someone to
do biometrics when they create an account because they don't have any
significance yet. However, from a UX perspective it can be more reassuring to
the user to feel like they did something "secure" to create their account, which
is what most OSes require.</small>

### Use Passkey to Authenticate

"Authenticate" is a "Get" operation.

It gives back a `signature`, `userHandle`, and some data about the authenticator
device.

Note: `userHandle` is not returned on `silent` requests.

### Authenticate with Passkey

```js
let authRequest = window.structuredClone(PassKey.auth.defaultOpts);
console.log(authRequest);
/*
    {
      mediation: "optional",
      publicKey: {
        allowCredentials: [
          // { id: credentialId, transports: ["usb", "internal", "..."], type: "public-key" },
        ],
        challenge: new Uint8Array(0), // for signature
        rpId: PassKey.relyingParty.id,
        timeout: 180 * 1000,
        userVerification: "preferred",
      },
    }
*/

// "conditional" is used for autofill
authRequest.mediation = "conditional";
authRequest.allowedCredentials = [{ id: "<base64-id>" }];

// 'challenge' is set on each call if not provided
let authResp = await PassKey.auth.request(authRequest);
let authResult = PassKey.auth.responseToJSON(authResp);
console.log(authResult);
/*
    {
      "authenticatorAttachment": "platform",
      "id": "<same as rawId, but base64 rather than hex>",
      "rawId": "<hex-encoded credential id>",
      "response": {
        "authenticatorData": "<subset of attestation data>",
        "clientDataJSON": "<preserved byte order for signature verification>",
        "signature": "<asn1-der-signature>",
        getClientSecretUserHandleHex() // "<hex-encoded bytes of given user.id>"
      },
      "type": "public-key"
    }
 */
```

## API

```js
/**
 * A template for navigator.credentials.create(opts)
 * @type {PublicKeyCredentialCreationOptions}
 */
PassKey.reg.defaultOpts = {
  /* see example above */
};

/**
 * Requests to create or replace a key
 *   - for the given domain (relyingParty.id)
 *   - by the given email or username (as user.id bytes)
 *   - excluding the given Credential IDs (as excludedCredentials[].id)
 * @param {CredentialCreationOptions} pubkeyRegOpts
 */
PassKey.reg.createOrReplace(pubkeyRegOpts, abortMsg);

/**
 * Makes a plain copy of the opaque object, which can be serialized and POSTed
 * @param {PublicKeyCredential} attestationResponse
 */
PassKey.reg.responseToJSON(attestationResponse);

/** Supported by Apple Touch ID, Face ID, Windows Hello, Android Unlock and WebCrypto */
PassKey.reg.COSE_ES256 = -7;
PassKey.reg.COSE_RS256 = -257;
PassKey.reg.keyTypes["-7"] = "ES256";
PassKey.reg.keyTypes["-257"] = "RS256";
```

```js
/**
 * Checks for WebAuthn support and sets some variables
 * @param {String} name - a friendly title for the site or app
 * @param {Base64} challenge - from the server
 */
await PassKey.init({ name, challenge });

/**
 * Indicates which features are supported
 * @type {Object.<String, Boolean>}
 */
PassKey.support = { webauthn, platform, conditional, ctap2 };
```

```js
/**
 * "conditional" will WAIT to prompt until the user selects from autocomplete or
 *               the reuest is abort()d (which PassKey does) before requesting another mode
 * "optional" will IMMEDIATELY open a passkey selection prompt
 * Used to help maintwill be set as
 */
PassKey.auth.mediation = "optional";

PassKey.auth.defaultOpts = {
  /* see example above */
};

/**
 * Requests a Passkey with the given characteristics
 * @param {CredentialRequestOptions} authRequestOpts
 */
PassKey.auth.request(authRequestOpts);

/**
 * Forces 'conditional' and handles abort signal
 * @param {CredentialRequestOptions} authRequestOpts
 */
PassKey.auth.requestAutocomplete(authRequestOpts);

/**
 * Makes a plain copy of the opaque object, which can be serialized and POSTed
 * @param {PublicKeyCredential} assertionResponse
 */
PassKey.auth.responseToJSON(assertionResponse);
```

```js
/**
 * Whether to use any, internal (OS, Browser), external (security key), or combined passkeys
 * Examples: "", "platform", "cross-platform", "hybrid"
 */
PassKey.attachment = ""; //

/**
 * 'name' is ONLY for REGISTRATION and should be the name of your Website / App / Product
 * 'id' must be window.location.hostname or a parent domain (up to the PSL apex)
 * Examples: 'bar.foo.example.com' or 'foo.example.com' or 'example.com',
 *           but not 'baz.example.com' or 'com' (assuming the first is location.hostname)
 */
PassKey.relyingParty = { id: window.location.hostname, name: "what you want" };

/** For converting user.id to bytes from user.name */
PassKey.textEncoder = new TextEncoder();

/**
 * For convenience in performing the the spec'd .toJSON() that the browser doesn't provide
 * @param {Uint8Array|ArrayBuffer} buffer
 */
PassKey.bufferToBase64(uint8ArrayOrArrayBuffer);
```

## PassUI

These are the pieces that are used for the demo which may server as a good
example, but are not generally reusable.

### Create or Replace Passkey

```html
<button
  type="button"
  onclick="
    PassUI.reg.createOrReplaceKey(window.event);
  "
>
  Create Account
</button>
```

### Search for and Sign Challenge with Passkey

```html
<button
  type="button"
  onclick="
    PassUI.auth.mediation = 'optional';
    PassUI.auth.requestKey(window.event);
  "
>
  Login
</button>
```

### Skip Password with Passkey Autocomplete

```html
<input type="email" autocomplete="username webauthn" />
<input type="password" autocomplete="password webauthn" />

<button
  type="button"
  onclick="
    PassUI.auth.mediation = 'conditional';
    PassUI.auth.requestKey(window.event);
  "
>
  Enable Autocomplete
</button>
```

### Change Prompt Preference

Only 'conditional' (autocomplete) and 'optional' (selection modal) appear to be
implemented.

```html
<select name="mediation" onchange="PassUI.auth.setMediation(event)">
  <option value="conditional" selected>
    conditional (Autocomplete Keypass)
  </option>
  <option value="silent">silent*</option>
  <option value="optional">optional (Prompt for Keypass)</option>
  <option value="required">required*</option>
</select>
```

NOT used for registration, ONLY authentication.

### Change Device Preference

These suggest whether internal (OS, Browser) or external (Security Key) means
should be used to complete the authentication. However, they seem to be ignored.

```html
<select name="attachment" onchange="PassUI.setAttachment(window.event)">
  <option value="" selected>(allow all)</option>
  <option value="platform">platform (computer, phone)</option>
  <option value="cross-platform">cross-platform (key, tag)</option>
</select>
```
