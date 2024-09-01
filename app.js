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

/**
 * PassKey is a namespace for relations of WebAuthn PublicKey
 * singleton because it relies on navigator state, of which there is only one
 */
let PassKey = {};
PassKey.attachment = "";

PassKey.reg = {};
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
PassKey.reg.COSE_ES256 = -7;
//PassKey.reg.COSE_EDDSA = -8;
//PassKey.reg.COSE_PS256 = -37;
PassKey.reg.COSE_RS256 = -257;

PassKey.auth = {};
/** @type {CredentialMediationRequirement} */
PassKey.auth.mediation = "optional";

PassKey.textEncoder = new TextEncoder();
// let textDecoder = new TextDecoder();

///**
// * @param {Uint8Array|ArrayBuffer} buffer
// */
//PassKey._bufferToBase64 = function (buffer) {
//  let bytes = new Uint8Array(buffer);
//  //@ts-ignore
//  let binstr = String.fromCharCode.apply(null, bytes);
//  return btoa(binstr);
//}

/**
 * @param {Uint8Array|ArrayBuffer?} [buffer]
 */
PassKey._bufferToHex = function (buffer) {
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
};

PassKey._abortCtrlr = new AbortController();
PassKey._challenge = new Uint8Array(32);
PassKey._emptyUserId = new Uint8Array(0);
PassKey.relyingParty = {
  // https://github.com/w3c/webauthn/wiki/Explainer:-Related-origin-requests
  id: location.host, // varies pubkey, may be set to parent but not child
  name: $("title")?.textContent || "",
};

/**
 * @type {CredentialCreationOptions}
 * https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
 * https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
 */
PassKey.reg.defaultOpts = {
  // signal: PassKey._abortCtrlr.signal,

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
    challenge: PassKey._challenge, // for attestation
    // don't create for
    excludeCredentials: [], // { id, transports, type }
    // https://caniuse.com/mdn-api_credentialscontainer_create_publickey_option_extensions
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: PassKey.reg.COSE_ES256,
      },
      {
        type: "public-key",
        alg: PassKey.reg.COSE_RS256,
      },
    ],
    // extensions: [],
    rp: PassKey.relyingParty,
    timeout: 180 * 1000,
    user: { id: PassKey._emptyUserId, name: "", displayName: "" },
    // hints: [], // "security-key" (key), "client-device" (phone), "hybrid" (more)
  },
};

/**
 * Converts a WebAuthn Public Key Credential response to plain JSON with base64 encoding for byte array fields.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
 * @param {PublicKeyCredential} cred
 */
PassKey.reg.responseToJSON = function (cred) {
  /** @type {AuthenticatorAttestationResponse} */ //@ts-ignore
  let attResp = cred.response;

  // Convert the credential response to plain JSON
  let jsonCred = {
    authenticatorAttachment: cred.authenticatorAttachment,
    id: cred.id,
    rawId: PassKey._bufferToHex(cred.rawId),
    response: {
      attestationObject: PassKey._bufferToHex(attResp.attestationObject),
      clientDataJSON: PassKey._bufferToHex(attResp.clientDataJSON),
    },
    type: cred.type,
  };

  return jsonCred;
};

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
PassKey.auth.defaultOpts = {
  // "optional" // default
  // "required" // does nothing
  // "conditional" // for autofill
  // "silent" // implicit (no interaction) // does nothing
  mediation: PassKey.auth.mediation,

  // signal: PassKey._abortCtrlr.signal,

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
    challenge: PassKey._challenge, // for signature
    // extensions: [],
    // hints: [],
    // can make Cross-Origin requests
    //   Cross-Origin-Opener-Policy: same-origin
    //   Cross-Origin-Embedder-Policy: require-corp
    rpId: PassKey.relyingParty.id,
    timeout: 180 * 1000,
    userVerification: "preferred", // "required" (explicit), "discouraged" (implicit)
  },
};

/**
 * Converts a WebAuthn Public Key Credential response to plain JSON with base64 encoding for byte array fields.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 * @param {PublicKeyCredential} cred
 */
PassKey.auth.responseToJSON = function (cred) {
  /** @type {AuthenticatorAssertionResponse} */ //@ts-ignore
  let assResp = cred.response;

  // Convert the credential response to plain JSON
  let jsonCred = {
    authenticatorAttachment: cred.authenticatorAttachment,
    id: cred.id,
    rawId: PassKey._bufferToHex(cred.rawId),
    response: {
      authenticatorData: PassKey._bufferToHex(assResp.authenticatorData),
      clientDataJSON: PassKey._bufferToHex(assResp.clientDataJSON),
      signature: PassKey._bufferToHex(assResp.signature),
      userHandle: PassKey._bufferToHex(assResp.userHandle),
    },
    type: cred.type,
  };

  return jsonCred;
};

/**
 * Converts a WebAuthn Public Key Credential response to plain JSON with base64 encoding for byte array fields.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
 * https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
 * @param {CredentialCreationOptions} pubkeyRegOpts
 * @param {String} [abortMsg] - any existing webauthn attempt (including autocomplete) will be canceled with this message
 */
PassKey.reg.set = async function (
  pubkeyRegOpts,
  abortMsg = "switch to explicit register",
) {
  console.log("PassKey.reg.set() pubkeyRegOpts", pubkeyRegOpts);

  PassKey._abortCtrlr.abort(abortMsg);
  PassKey._abortCtrlr = new AbortController();
  pubkeyRegOpts.signal = PassKey._abortCtrlr.signal;

  void globalThis.crypto.getRandomValues(PassKey._challenge);
  if (!pubkeyRegOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }
  pubkeyRegOpts.publicKey.challenge = PassKey._challenge;

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
    if (PassKey.auth.mediation === "conditional") {
      let abortMsg = "change from canceled registration to additional login";
      let authRequestOpts = globalThis.structuredClone(
        PassKey.auth.defaultOpts,
      );
      authRequestOpts.mediation = PassKey.auth.mediation;
      void (await PassKey.auth.getOrWaitFor(authRequestOpts, abortMsg));
    }
    return;
  }
  /** @type {PublicKeyCredential} */ //@ts-ignore
  let pubkeyRegistration = pubkeyRegResp;

  console.log(`createCredential response opaque:`);
  console.log(pubkeyRegistration);
  let registerResult = PassKey.reg.responseToJSON(pubkeyRegistration);
  console.log(`createCredential response JSON:`);
  console.log(registerResult);
};

/**
 * Converts a WebAuthn Public Key Credential response to plain JSON with base64 encoding for byte array fields.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 * https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
 * @param {CredentialRequestOptions} authRequestOpts
 * @param {String} [abortMsg] - any existing webauthn attempt (including autocomplete) will be canceled with this message
 */
PassKey.auth.getOrWaitFor = async function (authRequestOpts, abortMsg) {
  if (!abortMsg) {
    abortMsg = `switch to '${PassKey.auth.mediation}' key request`;
  }
  console.log("getPublicKey() authRequestOpts", authRequestOpts);

  void globalThis.crypto.getRandomValues(PassKey._challenge);
  if (!authRequestOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }
  authRequestOpts.publicKey.challenge = PassKey._challenge;

  PassKey._abortCtrlr.abort(abortMsg);
  PassKey._abortCtrlr = new AbortController();
  authRequestOpts.signal = PassKey._abortCtrlr.signal;

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
  let authResult = PassKey.auth.responseToJSON(pubkeyAuthentication);
  console.log(`getCredential response JSON:`);
  console.log(authResult);
};

let PassUI = {};
PassUI.reg = {};
PassUI.auth = {};

/**
 * @param {Event} event
 */
PassUI.reg.createOrReplaceKey = async function (event) {
  event.preventDefault();
  let abortMsg = "changed webauthn to register";

  let pubkeyRegOpts = globalThis.structuredClone(PassKey.reg.defaultOpts);
  if (!pubkeyRegOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }

  if (PassKey.attachment) {
    let attachment = PassKey.attachment;
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
  let userId = PassKey.textEncoder.encode(lowername);
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

  if (PassKey.auth.mediation === "conditional") {
    // by selecting explicit register we're canceling the
    // conditional state and should trigger the UI to update to match
    let $mediation = $('select[name="mediation"]');
    //@ts-ignore
    $mediation.value = "optional";
    //@ts-ignore
    $mediation.onchange();
  }
  await PassKey.reg
    .set(pubkeyRegOpts, abortMsg)
    .then(function () {
      //@ts-ignore
      $("input[name=username]").value = "";
    })
    .catch(PassUI._alertError);
};

/**
 * @param {Event} event
 */
PassUI.auth.requestKey = async function (event) {
  if (PassKey.auth.mediation === "conditional") {
    let $mediation = $('select[name="mediation"]');
    //@ts-ignore
    $mediation.value = "optional";
    //@ts-ignore
    $mediation.onchange();
  }
  let abortMsg = "changed webauthn to auth";

  let authRequestOpts = globalThis.structuredClone(PassKey.auth.defaultOpts);

  authRequestOpts.mediation = PassKey.auth.mediation;

  // to prevent overwriting the ID / public key when creating
  // (or to not show the current user in a login-is prompt)
  // excludeCredentials: [ { type: 'public-key', id: 'base64id' }]

  await PassKey.auth
    .getOrWaitFor(authRequestOpts, abortMsg)
    .catch(PassUI._alertError);
};

/**
 * @param {Event} event
 */
PassUI.setAttachment = async function (event) {
  //@ts-ignore
  let newAttachment = $('select[name="attachment"]').value || "";
  PassKey.attachment = newAttachment;
  let abortMsg = `changed webauthn attachment to ${PassKey.attachment}`;

  if (PassKey.auth.mediation === "conditional") {
    let authRequestOpts = globalThis.structuredClone(PassKey.auth.defaultOpts);
    authRequestOpts.mediation = PassKey.auth.mediation;
    void (await PassKey.auth
      .getOrWaitFor(authRequestOpts, abortMsg)
      .catch(PassUI._alertError));
    return;
  }
};

/**
 * @param {Event} event
 */
PassUI.auth.setMediation = async function (event) {
  //@ts-ignore
  let newMediation = $('select[name="mediation"]').value || "";
  if (!newMediation) {
    throw new Error("mediation option box must exist");
  }
  PassKey.auth.mediation = newMediation;
  let abortMsg = `changed webauthn mediation to ${PassKey.auth.mediation}`;

  if (newMediation === "conditional") {
    //@ts-ignore
    $('[data-id="register"]').hidden = false;
    //@ts-ignore
    $('[data-id="username"]').hidden = false;

    let authRequestOpts = globalThis.structuredClone(PassKey.auth.defaultOpts);
    authRequestOpts.mediation = PassKey.auth.mediation;
    void (await PassKey.auth
      .getOrWaitFor(authRequestOpts, abortMsg)
      .catch(PassUI._alertError));
    return;
  }

  //@ts-ignore
  $('[data-id="register"]').hidden = true;
  //@ts-ignore
  $('[data-id="username"]').hidden = true;
};

/**
 * @param {Error} err
 */
PassUI._alertError = async function (err) {
  console.warn(`Caught bubbled-up UI error:`);
  console.error(err);
  window.alert(err.message);
};

Object.assign(window, { PassUI });

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
