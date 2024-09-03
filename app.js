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
PassKey.reg.coseAlgos = {};
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
PassKey.reg.COSE_ES256 = -7;
PassKey.reg.coseAlgos["-7"] = "ES256";
//PassKey.reg.COSE_EDDSA = -8;
// PassKey.reg.coseAlgos["-8"] = "EDDSA";
//PassKey.reg.COSE_PS256 = -37;
// PassKey.reg.coseAlgos["-37"] = "PS256";
PassKey.reg.COSE_RS256 = -257;
PassKey.reg.coseAlgos["-257"] = "RS256";

PassKey.auth = {};
PassKey.textEncoder = new TextEncoder();
// let textDecoder = new TextDecoder();

/**
 * @param {Uint8Array|ArrayBuffer?} buffer
 */
PassKey._bufferToBase64 = function (buffer) {
  if (!buffer?.byteLength) {
    return null;
  }

  let bytes = new Uint8Array(buffer);
  //@ts-ignore
  let binstr = String.fromCharCode.apply(null, bytes);
  let rfcBase64 = btoa(binstr);

  let urlBase64 = rfcBase64.replace(/=+$/g, "");
  urlBase64 = urlBase64.replace(/[/]/g, "_");
  urlBase64 = urlBase64.replace(/[+]/g, "-");
  return urlBase64;
};

/**
 * @param {Uint8Array|ArrayBuffer?} buffer
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
  id: location.hostname, // varies pubkey, may be set to parent but not child
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
    challenge: new Uint8Array(0), // for attestation
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
 * @param {void|PublicKeyCredential?} cred
 */
PassKey.reg.responseToJSON = function (cred) {
  if (!cred) {
    return null;
  }

  /** @type {AuthenticatorAttestationResponse} */ //@ts-ignore
  let attResp = cred.response;
  let authenticatorData = attResp.getAuthenticatorData();
  let asn1Pubkey = attResp.getPublicKey();
  let coseKeyType = attResp.getPublicKeyAlgorithm();
  let keyTypeName = "";
  if (coseKeyType === -7) {
    keyTypeName = "ES256";
  } else if (-257) {
    keyTypeName = "RS256";
  } else {
    throw new Error(
      `COSE algorithm #${coseKeyType} is not known to be widely supported`,
    );
  }

  // Convert the credential response to plain JSON
  let jsonCred = {
    authenticatorAttachment: cred.authenticatorAttachment,
    id: cred.id,
    rawId: PassKey._bufferToBase64(cred.rawId), // same as cred.id
    rawIdHex: PassKey._bufferToHex(cred.rawId), // same as cred.id
    response: {
      attestationObject: PassKey._bufferToBase64(attResp.attestationObject),
      attestationObjectHex: PassKey._bufferToHex(attResp.attestationObject),
      // https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
      // a subset of attestationObject
      authenticatorData: PassKey._bufferToBase64(authenticatorData),
      authenticatorDataHex: PassKey._bufferToHex(authenticatorData),
      clientDataJSON: PassKey._bufferToBase64(attResp.clientDataJSON),
      clientDataJSONHex: PassKey._bufferToHex(attResp.clientDataJSON),
      publicKey: PassKey._bufferToBase64(asn1Pubkey),
      publicKeyHex: PassKey._bufferToHex(asn1Pubkey),
      publicKeyAlgorithm: coseKeyType,
      publicKeyAlgorithmName: keyTypeName,
      transports: attResp.getTransports(),
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
  mediation: "optional",

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
    challenge: new Uint8Array(0), // for signature
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
 * Note: 'userHandle' is a client-side secret, or at least it  allows up to 64-bytes,
 * some of which may be used for a local encryption key.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 * @param {void|PublicKeyCredential?} cred
 */
PassKey.auth.responseToJSON = function (cred) {
  if (!cred) {
    return null;
  }

  /** @type {AuthenticatorAssertionResponse} */ //@ts-ignore
  let assResp = cred.response;
  let userHandleHex = PassKey._bufferToHex(assResp.userHandle);

  // Convert the credential response to plain JSON
  let jsonCred = {
    authenticatorAttachment: cred.authenticatorAttachment,
    id: cred.id,
    rawId: PassKey._bufferToBase64(cred.rawId), // same as cred.id
    rawIdHex: PassKey._bufferToHex(cred.rawId), // same as cred.id
    response: {
      authenticatorData: PassKey._bufferToBase64(assResp.authenticatorData),
      authenticatorDataHex: PassKey._bufferToHex(assResp.authenticatorData),
      clientDataJSON: PassKey._bufferToBase64(assResp.clientDataJSON),
      clientDataJSONHex: PassKey._bufferToHex(assResp.clientDataJSON),
      signature: PassKey._bufferToBase64(assResp.signature),
      signatureHex: PassKey._bufferToHex(assResp.signature),
      getClientSecretUserHandleHex: function () {
        // this is a client-side secret and should NOT be disclosed to the server
        return userHandleHex;
      },
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
  PassKey._abortCtrlr.abort(abortMsg);
  PassKey._abortCtrlr = new AbortController();
  pubkeyRegOpts.signal = PassKey._abortCtrlr.signal;

  if (!pubkeyRegOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }
  if (!pubkeyRegOpts.publicKey.challenge.byteLength) {
    void globalThis.crypto.getRandomValues(PassKey._challenge);
    pubkeyRegOpts.publicKey.challenge = PassKey._challenge;
  }

  console.log(`rp.id:`, pubkeyRegOpts.publicKey.rp.id);
  let challengeHex = PassKey._bufferToHex(PassKey._challenge);
  console.log(`challenge: ${challengeHex}`);
  let pubkeyRegResp = await navigator.credentials
    .create(pubkeyRegOpts)
    .catch(function (err) {
      // this may never fire
      console.warn("Error: navigator.credentials.create():");
      console.log(err);
      return null;
    });
  if (!pubkeyRegResp) {
    return null;
  }

  /** @type {PublicKeyCredential} */ //@ts-ignore
  let pubkeyRegistration = pubkeyRegResp;
  return pubkeyRegistration;
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
    abortMsg = `switch to '${authRequestOpts.mediation}' key request`;
  }
  PassKey._abortCtrlr.abort(abortMsg);
  PassKey._abortCtrlr = new AbortController();
  authRequestOpts.signal = PassKey._abortCtrlr.signal;

  if (!authRequestOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }
  if (!authRequestOpts.publicKey.challenge.byteLength) {
    void globalThis.crypto.getRandomValues(PassKey._challenge);
    authRequestOpts.publicKey.challenge = PassKey._challenge;
  }

  console.log(`rpId:`, authRequestOpts.publicKey.rpId);
  let challengeHex = PassKey._bufferToHex(PassKey._challenge);
  console.log(`challenge: ${challengeHex}`);
  let pubkeyAuthResp = await navigator.credentials
    .get(authRequestOpts)
    .catch(function (err) {
      // errors never fire when `authRequestOpts.mediation = "conditional";`
      console.warn("Error: navigator.credentials.get():");
      console.log(err);
      return null;
    });
  if (!pubkeyAuthResp) {
    return null;
  }

  /** @type {PublicKeyCredential} */ //@ts-ignore
  let pubkeyAuthentication = pubkeyAuthResp;
  return pubkeyAuthentication;
};

let PassUI = {};
PassUI.reg = {};
PassUI.auth = {};

/** @type {CredentialMediationRequirement} */
PassUI.auth.mediation = "optional";

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

  if (PassUI.auth.mediation === "conditional") {
    // by selecting explicit register we're canceling the
    // conditional state and should trigger the UI to update to match
    let $mediation = $('select[name="mediation"]');
    //@ts-ignore
    $mediation.value = "optional";
    //@ts-ignore
    $mediation.onchange();
  }

  console.log("PassUI.reg.createOrReplaceKey() pubkeyRegOpts", pubkeyRegOpts);
  let regResult = await PassKey.reg
    .set(pubkeyRegOpts, abortMsg)
    .then(function (regResult) {
      //@ts-ignore
      $("input[name=username]").value = "";
      return regResult;
    })
    .catch(PassUI._alertError);
  if (regResult) {
    await PassUI.reg.handleResult(regResult);
    return;
  }

  if (PassUI.auth.mediation === "conditional") {
    let abortMsg = "change from canceled registration to additional login";
    let authRequestOpts = globalThis.structuredClone(PassKey.auth.defaultOpts);
    authRequestOpts.mediation = PassUI.auth.mediation;
    console.log(
      "PassUI.reg.createOrReplaceKey() authRequestOpts [conditional]",
      authRequestOpts,
    );
    void (await PassKey.auth
      .getOrWaitFor(authRequestOpts, abortMsg)
      .then(PassUI.auth.handleResult));
    return;
  }
  console.warn("WebAuthn was changed, restarted, failed, or canceled");
};

/**
 * @param {Event} event
 */
PassUI.auth.requestKey = async function (event) {
  if (PassUI.auth.mediation === "conditional") {
    let $mediation = $('select[name="mediation"]');
    //@ts-ignore
    $mediation.value = "optional";
    //@ts-ignore
    $mediation.onchange();
  }
  let abortMsg = "changed webauthn to auth";

  let authRequestOpts = globalThis.structuredClone(PassKey.auth.defaultOpts);

  authRequestOpts.mediation = PassUI.auth.mediation;

  // to prevent overwriting the ID / public key when creating
  // (or to not show the current user in a login-is prompt)
  // excludeCredentials: [ { type: 'public-key', id: 'base64id' }]

  console.log("PassUI.auth.requestKey() authRequestOpts", authRequestOpts);
  void (await PassKey.auth
    .getOrWaitFor(authRequestOpts, abortMsg)
    .then(PassUI.auth.handleResult)
    .catch(PassUI._alertError));
};

/**
 * @param {Event} event
 */
PassUI.setAttachment = async function (event) {
  //@ts-ignore
  let newAttachment = $('select[name="attachment"]').value || "";
  PassKey.attachment = newAttachment;
  let abortMsg = `changed webauthn attachment to ${PassKey.attachment}`;

  if (PassUI.auth.mediation === "conditional") {
    let authRequestOpts = globalThis.structuredClone(PassKey.auth.defaultOpts);
    authRequestOpts.mediation = PassUI.auth.mediation;

    console.log("PassUI.setAttachment(): authRequestOpts", authRequestOpts);
    void (await PassKey.auth
      .getOrWaitFor(authRequestOpts, abortMsg)
      .then(PassUI.auth.handleResult)
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
  PassUI.auth.mediation = newMediation;
  let abortMsg = `changed webauthn mediation to ${PassUI.auth.mediation}`;

  if (newMediation === "conditional") {
    //@ts-ignore
    $('[data-id="register"]').hidden = false;
    //@ts-ignore
    $('[data-id="username"]').hidden = false;

    let authRequestOpts = globalThis.structuredClone(PassKey.auth.defaultOpts);
    authRequestOpts.mediation = PassUI.auth.mediation;

    console.log("PassUI.setMediation(): authRequestOpts", authRequestOpts);
    void (await PassKey.auth
      .getOrWaitFor(authRequestOpts, abortMsg)
      .then(PassUI.auth.handleResult)
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

/**
 * @param {void|PublicKeyCredential?} regResp
 */
PassUI.reg.handleResult = async function (regResp) {
  if (!regResp) {
    console.warn("WebAuthn was changed, restarted, failed, or canceled");
    return null;
  }

  console.log(`PassUI.reg.handleResult (opaque):`);
  console.log(regResp);
  let regResult = PassKey.reg.responseToJSON(regResp);
  console.log(`PassUI.reg.handleResult (JSON):`);
  console.log(regResult);
};

/**
 * @param {void|PublicKeyCredential?} authResp
 */
PassUI.auth.handleResult = async function (authResp) {
  if (!authResp) {
    console.warn("WebAuthn was changed, restarted, failed, or canceled");
    return null;
  }

  console.log(`PassUI.auth.handleResult (opaque):`);
  console.log(authResp);
  let authResult = PassKey.auth.responseToJSON(authResp);
  console.log(`PassUI.auth.handleResult (JSON):`);
  console.log(authResult);
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
