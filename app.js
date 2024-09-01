"use strict";

/**
 * Select first matching element, just like console $
 * @param {String} cssSelector
 * @param {ParentNode} [$parent=document]
 */
function $(cssSelector, $parent = document) {
  let $child = $parent.querySelector(cssSelector);
  return $child;
}

let textEncoder = new TextEncoder();
// let textDecoder = new TextDecoder();

// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
const COSE_ES256 = -7;
//const COSE_EDDSA = -8;
//const COSE_PS256 = -37;
const COSE_RS256 = -257;

let challenge = new Uint8Array(32);
let emptyUserId = new Uint8Array(0);
/** @type {CredentialMediationRequirement} */
let currentMediation = "optional";
let currentAttachment = "";
let currentAbort = "";
let abortController = new AbortController();

let relyingParty = {
  // https://github.com/w3c/webauthn/wiki/Explainer:-Related-origin-requests
  id: location.host, // varies pubkey, may be set to parent but not child
  name: $("title")?.textContent || "",
};

/**
 * @type {CredentialCreationOptions}
 * https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
 * https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
 */
let defaultCreateOrReplaceCredOpts = {
  // signal: abortController.signal,

  // Pick ONE of password, identity, federated, publicKey

  // // https://caniuse.com/mdn-api_federatedcredential
  // federated: null, // poor support
  // // https://caniuse.com/mdn-api_passwordcredential
  // password: null, // poor support

  // https://caniuse.com/mdn-api_publickeycredential
  // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
  publicKey: {
    attestation: "none",
    // attestationFormats: [],
    authenticatorSelection: {
      // leave empty to allow either OS/Browser (platform) or Key (BLE, FIDO)
      // authenticatorAttachment: "platform", // "cross-platform" key-only

      // 'credentialId' will be created by the authenticator
      // (rather than server-side)
      residentKey: "required",
      //requireResidentKey: true, // deprecated

      userVerification: "discouraged", // implicit register // "preferred", "required"
    },
    challenge: challenge, // for attestation
    // don't create for
    excludeCredentials: [], // { id, transports, type }
    // https://caniuse.com/mdn-api_credentialscontainer_create_publickey_option_extensions
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: COSE_ES256,
      },
      {
        type: "public-key",
        alg: COSE_RS256,
      },
    ],
    // extensions: [],
    rp: relyingParty,
    timeout: 180 * 1000,
    user: { id: emptyUserId, name: "", displayName: "" },
    // hints: [], // "security-key" (key), "client-device" (phone), "hybrid" (more)
  },
};

/**
 * Converts a WebAuthn Public Key Credential response to plain JSON with base64 encoding for byte array fields.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
 * @param {PublicKeyCredential} cred
 */
function pubkeyRegisterToJSON(cred) {
  /** @type {AuthenticatorAttestationResponse} */ //@ts-ignore
  let attResp = cred.response;

  // Convert the credential response to plain JSON
  let jsonCred = {
    authenticatorAttachment: cred.authenticatorAttachment,
    id: cred.id,
    rawId: bufferToHex(cred.rawId),
    response: {
      attestationObject: bufferToHex(attResp.attestationObject),
      clientDataJSON: bufferToHex(attResp.clientDataJSON),
    },
    type: cred.type,
  };

  return jsonCred;
}

// /**
//  * @type {PasswordCredential}
//  * https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/store
//  * https://developer.mozilla.org/en-US/docs/Web/API/Credential
//  * https://developer.mozilla.org/en-US/docs/Web/API/PasswordCredential
//  *
//  * Requires header 'Permissions-Policy: publickey-credentials-create=<allowlist>'
//  * https://caniuse.com/mdn-api_publickeycredential
//  */
// let defaultStoreCredOpts = {
//   id: emptyUserId,
//   name: "",
//   password: "",
// };

/**
 * @type {CredentialRequestOptions}
 * https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
 * https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
 */
let defaultGetCredOpts = {
  // "optional" // default
  // "required" // does nothing
  // "conditional" // for autofill
  // "silent" // implicit (no interaction) // does nothing
  mediation: currentMediation,

  // signal: abortController.signal,

  // Pick ONE of password, identity, federated, publicKey

  // // https://caniuse.com/mdn-api_passwordcredential
  // password: null, // poor support
  // // https://developer.mozilla.org/en-US/docs/Web/API/IdentityCredential
  // identity: null, // federated, poor support
  // // https://caniuse.com/mdn-api_federatedcredential
  // federated: null, // poor support
  // // https://developer.mozilla.org/en-US/docs/Web/API/OTPCredential
  // otp: null, // poor support

  // https://caniuse.com/mdn-api_publickeycredential
  // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
  publicKey: {
    allowCredentials: [
      // {
      //     id: credentialId,
      //     transports: ["usb", "ble", "nfc", "internal"],
      //     type: "public-key",
      // },
    ],
    challenge: challenge, // for signature
    // extensions: [],
    // hints: [],
    // can make Cross-Origin requests
    //   Cross-Origin-Opener-Policy: same-origin
    //   Cross-Origin-Embedder-Policy: require-corp
    rpId: relyingParty.id,
    timeout: 180 * 1000,
    userVerification: "preferred", // "required" (explicit), "discouraged" (implicit)
  },
};

/**
 * Converts a WebAuthn Public Key Credential response to plain JSON with base64 encoding for byte array fields.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 * @param {PublicKeyCredential} cred
 */
function pubkeyAuthToJSON(cred) {
  /** @type {AuthenticatorAssertionResponse} */ //@ts-ignore
  let assResp = cred.response;

  // Convert the credential response to plain JSON
  let jsonCred = {
    authenticatorAttachment: cred.authenticatorAttachment,
    id: cred.id,
    rawId: bufferToHex(cred.rawId),
    response: {
      authenticatorData: bufferToHex(assResp.authenticatorData),
      clientDataJSON: bufferToHex(assResp.clientDataJSON),
      signature: bufferToHex(assResp.signature),
      userHandle: bufferToHex(assResp.userHandle),
    },
    type: cred.type,
  };

  return jsonCred;
}

Object.assign(window, {
  createOrReplacePublicKey,
  getPublicKey,
  setMediation,
  setAttachment,
});

/**
 * Converts a WebAuthn Public Key Credential response to plain JSON with base64 encoding for byte array fields.
 * @param {CredentialCreationOptions} pubkeyRegOpts
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
 * https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
 */
async function setPasskey(pubkeyRegOpts) {
  console.log("createOrReplacePublicKey() pubkeyRegOpts", pubkeyRegOpts);

  abortController.abort(currentAbort);
  abortController = new AbortController();
  pubkeyRegOpts.signal = abortController.signal;

  void globalThis.crypto.getRandomValues(challenge);
  if (!pubkeyRegOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }
  pubkeyRegOpts.publicKey.challenge = challenge;

  const pubkeyRegResp = await navigator.credentials
    .create(pubkeyRegOpts)
    .catch(function (err) {
      // this may never fire
      console.warn("Error: navigator.credentials.create():");
      console.log(err);
      return null;
    });

  if (!pubkeyRegResp) {
    console.warn("WebAuthn was changed, restarted, failed, or canceled");
    if (currentMediation === "conditional") {
      let authRequestOpts = globalThis.structuredClone(defaultGetCredOpts);
      authRequestOpts.mediation = currentMediation;
      void (await authorizePasskey(authRequestOpts));
    }
    return;
  }
  /** @type {PublicKeyCredential} */ //@ts-ignore
  let pubkeyRegistration = pubkeyRegResp;

  console.log(`createCredential response opaque:`);
  console.log(pubkeyRegistration);
  let registerResult = pubkeyRegisterToJSON(pubkeyRegistration);
  console.log(`createCredential response JSON:`);
  console.log(registerResult);
}

/**
 * @param {Event} event
 */
async function createOrReplacePublicKey(event) {
  event.preventDefault();
  currentAbort = "changed webauthn to register";

  let pubkeyRegOpts = globalThis.structuredClone(
    defaultCreateOrReplaceCredOpts,
  );
  if (!pubkeyRegOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }

  if (currentAttachment) {
    let attachment = currentAttachment;
    //@ts-ignore
    pubkeyRegOpts.publicKey.authenticatorSelection.attachment = attachment;
  }

  //@ts-ignore
  let username = $("input[name=username]").value;
  if (!username) {
    window.alert("missing username");
    return;
  }

  let lowername = username.toLowerCase();
  let userId = textEncoder.encode(lowername);
  if (userId.length > 64) {
    window.alert("username must be less than 64 characters long");
    return;
  }
  let authUser = {
    id: userId, // up to 64 bytes userHandle varies pubkey
    name: lowername, // email, phone, username
    displayName: username.replace(/(\w)@.*/, "$1"),
  };

  pubkeyRegOpts.publicKey.user = authUser;

  // to prevent overwriting the ID / public key when creating
  // (or to not show the current user in a login-is prompt)
  // excludeCredentials: [ { type: 'public-key', id: 'base64id' }]
  pubkeyRegOpts.publicKey.excludeCredentials = [];

  await setPasskey(pubkeyRegOpts).catch(catchUiError);
}

/**
 * Converts a WebAuthn Public Key Credential response to plain JSON with base64 encoding for byte array fields.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 * @param {CredentialRequestOptions} authRequestOpts
 * https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
 */
async function authorizePasskey(authRequestOpts) {
  console.log("getPublicKey() authRequestOpts", authRequestOpts);

  void globalThis.crypto.getRandomValues(challenge);
  if (!authRequestOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }
  authRequestOpts.publicKey.challenge = challenge;

  abortController.abort(currentAbort);
  abortController = new AbortController();
  authRequestOpts.signal = abortController.signal;

  const pubkeyAuthResp = await navigator.credentials
    .get(authRequestOpts)
    .catch(function (err) {
      // errors never fire when `authRequestOpts.mediation = "conditional";`
      console.warn("Error: navigator.credentials.get():");
      console.log(err);
      return null;
    });
  if (!pubkeyAuthResp) {
    console.warn("WebAuthn was changed, restarted, failed, or canceled");
    return;
  }
  /** @type {PublicKeyCredential} */ //@ts-ignore
  let pubkeyAuthentication = pubkeyAuthResp;

  console.log("getPublicKey() pubkeyAuthReq", pubkeyAuthentication);
  let authResult = pubkeyAuthToJSON(pubkeyAuthentication);
  console.log(`getCredential response JSON:`);
  console.log(authResult);
}

/**
 * @param {Event} event
 */
async function getPublicKey(event) {
  if (currentMediation === "conditional") {
    let $mediation = $('select[name="mediation"]');
    //@ts-ignore
    $mediation.value = "optional";
    //@ts-ignore
    $mediation.onchange();
  }
  currentAbort = "changed webauthn to auth";

  let authRequestOpts = globalThis.structuredClone(defaultGetCredOpts);

  authRequestOpts.mediation = currentMediation;

  // to prevent overwriting the ID / public key when creating
  // (or to not show the current user in a login-is prompt)
  // excludeCredentials: [ { type: 'public-key', id: 'base64id' }]

  await authorizePasskey(authRequestOpts).catch(catchUiError);
}

/**
 * @param {Event} event
 */
async function setAttachment(event) {
  //@ts-ignore
  let newAttachment = $('select[name="attachment"]').value || "";
  currentAttachment = newAttachment;
  currentAbort = `changed webauthn attachment to ${currentAttachment}`;

  if (currentMediation === "conditional") {
    let authRequestOpts = globalThis.structuredClone(defaultGetCredOpts);
    authRequestOpts.mediation = currentMediation;
    void (await authorizePasskey(authRequestOpts).catch(catchUiError));
    return;
  }
}

/**
 * @param {Event} event
 */
async function setMediation(event) {
  //@ts-ignore
  let newMediation = $('select[name="mediation"]').value || "";
  if (!newMediation) {
    throw new Error("mediation option box must exist");
  }
  currentMediation = newMediation;
  currentAbort = `changed webauthn mediation to ${currentMediation}`;

  if (newMediation === "conditional") {
    //@ts-ignore
    $('[data-id="register"]').hidden = false;
    //@ts-ignore
    $('[data-id="username"]').hidden = false;

    let authRequestOpts = globalThis.structuredClone(defaultGetCredOpts);
    authRequestOpts.mediation = currentMediation;
    void (await authorizePasskey(authRequestOpts).catch(catchUiError));
    return;
  }

  //@ts-ignore
  $('[data-id="register"]').hidden = true;
  //@ts-ignore
  $('[data-id="username"]').hidden = true;
}

/**
 * @param {Error} err
 */
async function catchUiError(err) {
  console.warn(`Caught bubbled-up UI error:`);
  console.error(err);
  window.alert(err.message);
}

///**
// * @param {Uint8Array|ArrayBuffer} buffer
// */
//function bufferToBase64(buffer) {
//  let bytes = new Uint8Array(buffer);
//  //@ts-ignore
//  let binstr = String.fromCharCode.apply(null, bytes);
//  return btoa(binstr);
//}

/**
 * @param {Uint8Array|ArrayBuffer?} [buffer]
 */
function bufferToHex(buffer) {
  if (!buffer) {
    return "";
  }

  let bytes = new Uint8Array(buffer);
  /** @type {Array<String>} */
  let hex = [];

  for (let b of bytes) {
    let h = b.toString(16);
    h = h.padStart(2, "0");
    hex.push(h);
  }

  return hex.join("");
}

async function main() {
  let hasWebAuthn = false;
  let hasWebAuthnAutocomplete = false;

  if (
    //@ts-ignore - tsc says these exist (i.e. in node), but we test because browsers don't always agree
    globalThis.navigator?.credentials?.create &&
    //@ts-ignore
    globalThis.navigator?.credentials?.get &&
    globalThis.PublicKeyCredential
  ) {
    hasWebAuthn = true;
  }

  //@ts-ignore
  if (globalThis.PublicKeyCredential?.isConditionalMediationAvailable) {
    hasWebAuthnAutocomplete =
      await window.PublicKeyCredential.isConditionalMediationAvailable();
  }

  console.log("WebAuthn Public Key Support?", hasWebAuthn);
  console.log("WebAuthn Mediation Support?", hasWebAuthnAutocomplete);

  if (hasWebAuthnAutocomplete) {
    let $mediation = $('select[name="mediation"]');
    //@ts-ignore
    $mediation.value = "conditional";
    //@ts-ignore
    $mediation.onchange();
  }
}

main().catch(function (err) {
  console.error("main() caught uncaught error:");
  console.error(err.message);
});
