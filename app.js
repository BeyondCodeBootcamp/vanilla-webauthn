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
let textDecoder = new TextDecoder();

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
let abortController = new AbortController();

let relyingParty = {
  // https://github.com/w3c/webauthn/wiki/Explainer:-Related-origin-requests
  id: location.host, // varies pubkey, may be set to parent but not child
  name: $("title")?.textContent || "",
};

/**
 * @type {CredentialCreationOptions}
 * https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
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
    challenge: challenge,
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

// let defaultStoreCredOpts = {
//     // Requires header 'Permissions-Policy: publickey-credentials-create=<allowlist>'
//     // https://caniuse.com/mdn-api_publickeycredential
//     publicKey: {},
// };

/**
 * @type {CredentialRequestOptions}
 * https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
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
    challenge: challenge,
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

// TODO https://github.com/DefinitelyTyped/DefinitelyTyped/blob/a98404407d08f8d85544b3f9b431a10ce3772b4a/types/webappsec-credential-management/index.d.ts#L437

/**
 * The auth response object is opaque (i.e. no JSON.stringify() or Object.keys()),
 * and can only be used if you already know the keys.
 * @param {PublicKeyCredential} authResp
 */
// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
function logAuthResponse(authResp) {
  console.log("type:", authResp.type);
  console.log("id:", authResp.id); // rawId

  // let pubBytes = authResp.response.getPublicKey();
  // console.log("publicKey:", pubBytes);
  // console.log("authenticatorAttachment:", authResp.authenticatorAttachment);

  // likely to be the same for the same data
  let authtBytes = new Uint8Array(authResp.response.authenticatorData);
  let authenticatorHex = bytesToHex(authtBytes);
  console.log("authenticatorData:", authenticatorHex);

  // info for the webserver, same for same challenge, origin, etc
  let clientData = textDecoder.decode(authResp.response.clientDataJSON);
  console.log("clientData:", clientData);

  // likely to be the same as the userId, but it's device specific
  let userHandle = textDecoder.decode(authResp.response.userHandle);
  console.log("userHandle:", userHandle);

  // likely to be different even for the same key and payload
  let sigBytes = new Uint8Array(authResp.response.signature);
  let sigHex = bytesToHex(sigBytes);
  console.log("signature (salted):", sigHex);
}

Object.assign(window, {
  createOrReplacePublicKey,
  getPublicKey,
  setMediation,
  setAttachment,
});

async function createOrReplacePublicKey(event) {
  event.preventDefault();

  let credOpts = globalThis.structuredClone(defaultCreateOrReplaceCredOpts);

  abortController.abort();
  abortController = new AbortController();
  credOpts.signal = abortController.signal;
  if (currentAttachment) {
    let attachment = currentAttachment;
    //@ts-ignore
    credOpts.publicKey.authenticatorSelection.attachment = attachment;
  }

  void globalThis.crypto.getRandomValues(challenge);
  if (!credOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }
  credOpts.publicKey.challenge = challenge;

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

  credOpts.publicKey.user = authUser;

  // to prevent overwriting the ID / public key when creating
  // (or to not show the current user in a login-is prompt)
  // excludeCredentials: [ { type: 'public-key', id: 'base64id' }]
  credOpts.publicKey.excludeCredentials = [];

  console.log("createOrReplacePublicKey() credOpts", credOpts);
  const credential = await navigator.credentials
    .create(credOpts)
    .catch(function (err) {
      // this may never fire
      console.log("Error: navigator.credentials.get():");
      console.log(err);
      return null;
    });

  if (!credential) {
    console.warn("WebAuthn was changed, restarted, failed, or canceled");
    return;
  }
  /** @type {PublicKeyCredential} */
  //@ts-ignore
  let pubkeyCred = credential;

  logAuthResponse(pubkeyCred);
  console.log("WebAuthn successful", credential);
}

async function getPublicKey() {
  if (currentMediation === "conditional") {
    let $mediation = $('select[name="mediation"]');
    //@ts-ignore
    $mediation.value = "optional";
    //@ts-ignore
    $mediation.onchange();
  }

  let credOpts = globalThis.structuredClone(defaultGetCredOpts);

  abortController.abort();
  abortController = new AbortController();
  credOpts.signal = abortController.signal;

  if (!credOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }
  credOpts.publicKey.challenge = challenge;
  void globalThis.crypto.getRandomValues(challenge);

  credOpts.mediation = currentMediation;

  // to prevent overwriting the ID / public key when creating
  // (or to not show the current user in a login-is prompt)
  // excludeCredentials: [ { type: 'public-key', id: 'base64id' }]

  console.log("getPublicKey() credOpts", credOpts);
  const credential = await navigator.credentials
    .get(credOpts)
    .catch(function (err) {
      // this may never fire
      console.log("Error: navigator.credentials.get():");
      console.log(err);
      return null;
    });

  if (!credential) {
    console.warn("WebAuthn was changed, restarted, failed, or canceled");
    return;
  }

  logAuthResponse(credential);
  console.log("WebAuthn successful", credential);
}

async function setAttachment() {
  //@ts-ignore
  let newAttachment = $('select[name="attachment"]').value || "";
  currentAttachment = newAttachment;

  if (currentMediation === "conditional") {
    abortController.abort();
    abortController = new AbortController();
    void enableWebAuthnAutocomplete();
    return;
  }
}

async function setMediation() {
  abortController.abort();
  abortController = new AbortController();

  //@ts-ignore
  let newMediation = $('select[name="mediation"]').value || "";
  if (!newMediation) {
    throw new Error("mediation option box must exist");
  }
  currentMediation = newMediation;

  if (newMediation === "conditional") {
    //@ts-ignore
    $('[data-id="register"]').hidden = false;
    //@ts-ignore
    $('[data-id="username"]').hidden = false;

    void enableWebAuthnAutocomplete();
    return;
  }

  //@ts-ignore
  $('[data-id="register"]').hidden = true;
  //@ts-ignore
  $('[data-id="username"]').hidden = true;
}

async function enableWebAuthnAutocomplete() {
  let credOpts = globalThis.structuredClone(defaultGetCredOpts);

  abortController.abort();
  abortController = new AbortController();
  credOpts.signal = abortController.signal;

  if (currentMediation !== "conditional") {
    let msg = `'mediation' must be 'conditional' for user autocomplete`;
    window.alert(msg);
    throw new Error(msg);
  }
  credOpts.mediation = currentMediation;

  console.log("enableWebAuthnAutocomplete() credOpts", credOpts);
  let credential = await navigator.credentials
    .get(credOpts)
    .catch(function (err) {
      // this may never fire
      console.log("Error: navigator.credentials.get():");
      console.log(err);
      return null;
    });

  if (!credential) {
    console.warn("WebAuthn was changed, restarted, failed, or canceled");
    return;
  }

  logAuthResponse(credential);
  console.log("WebAuthn successful", credential);
}

/**
 * @param {Uint8Array} bytes
 */
function bytesToHex(bytes) {
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
  let userCanAutocomplete = false;
  if (window.PublicKeyCredential?.isConditionalMediationAvailable) {
    userCanAutocomplete =
      await window.PublicKeyCredential.isConditionalMediationAvailable();
    let $mediation = $('select[name="mediation"]');
    //@ts-ignore
    $mediation.value = "conditional";
    //@ts-ignore
    $mediation.onchange();
  }
  console.log("WebAuthn Medation Supported?", userCanAutocomplete);
}

main().catch(function (err) {
  console.error("main() caught uncaught error:");
  console.error(err.message);
});
