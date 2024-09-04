"use strict";

/** @typedef {String} URLBase64 */

/**
 * PassKey is a namespace for relations of WebAuthn PublicKey
 * singleton because it relies on navigator state, of which there is only one
 */
let PassKey = {};

PassKey.support = {
  webauthn: false,
  conditional: false, // mediation = 'conditional'
  platform: false,
  ctap2: false, // beyond FIDO2
};

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
PassKey.bufferToBase64 = function (buffer) {
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
 * @param {URLBase64} urlBase64
 */
PassKey.base64ToBytes = function (urlBase64) {
  let rfcBase64 = urlBase64.replace(/_/g, "/");
  rfcBase64 = rfcBase64.replace(/-/g, "+");
  while (rfcBase64.length % 4) {
    rfcBase64 += "=";
  }

  let binstr = atob(rfcBase64);
  let bytes = new Uint8Array(binstr.length);
  for (let i = 0; i < binstr.length; i += 1) {
    bytes[i] = binstr.charCodeAt(i);
  }

  return bytes;
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

/**
 * @param {any} any
 */
PassKey.throwIfEmpty = function (any) {
  if (any) {
    return any;
  }
  let err = new Error(`empty webauthn result`);
  Object.assign(err, { code: "E_WEBAUTHN_EMPTY" });
  throw err;
};

/**
 * @param {Error} err
 */
PassKey.ignoreIfCanceled = function (err) {
  let wasCanceledByUser = /timed out|not allowed|empty/.test(err.message);
  if (wasCanceledByUser) {
    return null;
  }

  throw err;
};

/**
 * @param {Error} err
 */
PassKey.ignoreIfAborted = function (err) {
  if (err.name === "AbortError") {
    return null;
  }

  throw err;
};

PassKey._challenge = new Uint8Array(32);
PassKey._emptyUserId = new Uint8Array(0);
PassKey.relyingParty = {
  // https://github.com/w3c/webauthn/wiki/Explainer:-Related-origin-requests
  id: location.hostname, // varies pubkey, may be set to parent but not child
  name: "",
};

/**
 * @param {Object} opts
 * @param {URLBase64?} [opts.challenge]
 * @param {String} [opts.name]
 */
PassKey.init = async function (opts = {}) {
  let { name, challenge } = opts;
  if (
    globalThis.PublicKeyCredential &&
    //@ts-ignore - tsc says these exist (i.e. in node), but we test because browsers don't always agree
    globalThis.navigator?.credentials?.create &&
    //@ts-ignore
    globalThis.navigator?.credentials?.get
  ) {
    PassKey.support.webauthn = true;
  }

  if (challenge) {
    let challengeBytes = PassKey.base64ToBytes(challenge);
    PassKey._challenge = challengeBytes;
  }
  if (name) {
    PassKey.relyingParty.name = name;
  }

  //@ts-ignore
  if (globalThis.PublicKeyCredential?.isConditionalMediationAvailable) {
    PassKey.support.conditional =
      await globalThis.PublicKeyCredential.isConditionalMediationAvailable();
  }

  //@ts-ignore
  if (
    globalThis.PublicKeyCredential
      ?.isUserVerifyingPlatformAuthenticatorAvailable
  ) {
    PassKey.support.platform =
      await globalThis.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  }

  //@ts-ignore
  if (globalThis.PublicKeyCredential?.isExternalCTAP2SecurityKeySupported) {
    PassKey.support.ctap2 =
      //@ts-ignore
      await globalThis.PublicKeyCredential.isExternalCTAP2SecurityKeySupported();
  }
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
      // leave undefined to allow either OS/Browser (platform) or Key (BLE, FIDO)
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
    rawId: PassKey.bufferToBase64(cred.rawId), // same as cred.id
    rawIdHex: PassKey._bufferToHex(cred.rawId), // same as cred.id
    response: {
      attestationObject: PassKey.bufferToBase64(attResp.attestationObject),
      attestationObjectHex: PassKey._bufferToHex(attResp.attestationObject),
      // https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
      // a subset of attestationObject
      authenticatorData: PassKey.bufferToBase64(authenticatorData),
      authenticatorDataHex: PassKey._bufferToHex(authenticatorData),
      clientDataJSON: PassKey.bufferToBase64(attResp.clientDataJSON),
      clientDataJSONHex: PassKey._bufferToHex(attResp.clientDataJSON),
      publicKey: PassKey.bufferToBase64(asn1Pubkey),
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
    rawId: PassKey.bufferToBase64(cred.rawId), // same as cred.id
    rawIdHex: PassKey._bufferToHex(cred.rawId), // same as cred.id
    response: {
      authenticatorData: PassKey.bufferToBase64(assResp.authenticatorData),
      authenticatorDataHex: PassKey._bufferToHex(assResp.authenticatorData),
      clientDataJSON: PassKey.bufferToBase64(assResp.clientDataJSON),
      clientDataJSONHex: PassKey._bufferToHex(assResp.clientDataJSON),
      signature: PassKey.bufferToBase64(assResp.signature),
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

/** @type {AbortController?} */
PassKey.auth._autocompleteController = null;

/**
 * Converts a WebAuthn Public Key Credential response to plain JSON with base64 encoding for byte array fields.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
 * https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
 * @param {CredentialCreationOptions} pubkeyRegOpts
 * @param {String} [abortMsg] - any existing webauthn attempt (including autocomplete) will be canceled with this message
 */
PassKey.reg.createOrReplace = async function (
  pubkeyRegOpts,
  abortMsg = "switch to explicit register",
) {
  if (PassKey.auth._autocompleteController) {
    let err = new Error(abortMsg);
    err.name = "AbortError";
    PassKey.auth._autocompleteController.abort(err);
    PassKey.auth._autocompleteController = null;
  }

  if (!pubkeyRegOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }

  console.log(`rp.id:`, pubkeyRegOpts.publicKey.rp.id);

  if (!pubkeyRegOpts.publicKey.challenge?.byteLength) {
    pubkeyRegOpts.publicKey.challenge = PassKey._challenge;
  }
  //@ts-ignore
  let challengeHex = PassKey._bufferToHex(pubkeyRegOpts.publicKey.challenge);
  console.log(
    `challenge (${pubkeyRegOpts.publicKey.challenge.byteLength}): ${challengeHex}`,
  );
  let pubkeyRegResp = await navigator.credentials
    .create(pubkeyRegOpts)
    .then(PassKey.throwIfEmpty);
  console.log("[PassKey.reg].create() complete:", pubkeyRegResp);

  /** @type {PublicKeyCredential} */ //@ts-ignore
  let pubkeyRegistration = pubkeyRegResp;
  return pubkeyRegistration;
};

/**
 * Immediately requests existing credentials, canceling any pending autocomplete.
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 * https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
 * @param {CredentialRequestOptions} authRequestOpts
 * @param {String} [abortMsg] - any existing webauthn attempt (including autocomplete) will be canceled with this message
 */
PassKey.auth.request = async function (authRequestOpts, abortMsg) {
  if (PassKey.auth._autocompleteController) {
    if (!abortMsg) {
      abortMsg = `switch to '${authRequestOpts.mediation}' key request`;
    }
    let err = new Error(abortMsg);
    err.name = "AbortError";
    PassKey.auth._autocompleteController.abort(err);
    PassKey.auth._autocompleteController = null;
  }

  return await PassKey.auth._request(authRequestOpts);
};

/**
 * Enables credential autocomplete.
 * @param {CredentialRequestOptions} authRequestOpts
 * @param {String} [abortMsg] - any existing webauthn attempt (including autocomplete) will be canceled with this message
 */
PassKey.auth.requestAutocomplete = async function (authRequestOpts, abortMsg) {
  if (PassKey.auth._autocompleteController) {
    let err = new Error(abortMsg);
    err.name = "AbortError";
    PassKey.auth._autocompleteController.abort(err);
    PassKey.auth._autocompleteController = null;
  }

  authRequestOpts.mediation = "conditional";
  PassKey.auth._autocompleteController = new AbortController();
  authRequestOpts.signal = PassKey.auth._autocompleteController.signal;
  return await PassKey.auth._request(authRequestOpts);
};

/**
 * @param {CredentialRequestOptions} authRequestOpts
 */
PassKey.auth._request = async function (authRequestOpts) {
  if (!authRequestOpts.publicKey) {
    throw new Error(".publicKey must exist");
  }

  console.log(`rpId:`, authRequestOpts.publicKey.rpId);
  if (!authRequestOpts.publicKey.challenge?.byteLength) {
    authRequestOpts.publicKey.challenge = PassKey._challenge;
  }
  //@ts-ignore
  let challengeHex = PassKey._bufferToHex(authRequestOpts.publicKey.challenge);
  console.log(
    `challenge (${authRequestOpts.publicKey.challenge.byteLength}): ${challengeHex}`,
  );
  let pubkeyAuthResp = await navigator.credentials
    .get(authRequestOpts)
    .then(PassKey.throwIfEmpty);
  console.log("[PassKey.auth].get() complete:", pubkeyAuthResp);

  /** @type {PublicKeyCredential} */ //@ts-ignore
  let pubkeyAuthentication = pubkeyAuthResp;
  return pubkeyAuthentication;
};

/**
 * Select first matching element, just like console $
 * @param {String} cssSelector
 * @param {ParentNode} [$parent=document]
 */
function $(cssSelector, $parent = document) {
  let $child = $parent.querySelector(cssSelector);
  return $child;
}

let PassUI = {};

/** @type {AuthenticatorAttachment?} */
PassUI.attachment = null;

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
  if (!pubkeyRegOpts.publicKey.authenticatorSelection) {
    throw new Error(".publicKey.authenticatorSelection must exist");
  }

  if (PassUI.attachment) {
    pubkeyRegOpts.publicKey.authenticatorSelection.authenticatorAttachment =
      PassUI.attachment;
  }

  //@ts-ignore
  let username = $("input[name=username]").value;
  if (!username) {
    window.alert("missing username");
    return;
  }

  let lowername = username.toLowerCase();
  let clientSecretUserHandle = PassKey.textEncoder.encode(lowername);
  if (clientSecretUserHandle.length > 64) {
    window.alert("username must be less than 64 characters long");
    return;
  }
  let authUser = {
    id: clientSecretUserHandle, // up to 64 bytes userHandle varies pubkey, which prevents overwriting the key
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
  void (await PassKey.reg
    .createOrReplace(pubkeyRegOpts, abortMsg)
    .then(PassUI.reg.handleBuffers)
    .catch(function (err) {
      console.warn(
        "PassUI.auth.requestKey() was canceled or failed:",
        err.message,
      );
      void PassUI.auth.keepAutocompleteAlive();
      throw err;
    })
    .catch(PassKey.ignoreIfCanceled)
    .catch(PassUI._alertError));
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

  let authRequestOpts = globalThis.structuredClone(PassKey.auth.defaultOpts);
  authRequestOpts.mediation = PassUI.auth.mediation;

  // TODO read from local storage for IDs
  // to prevent overwriting the ID / public key when creating
  // (or to not show the current user in a login-is prompt)
  // excludeCredentials: [ { type: 'public-key', id: 'base64id' }]

  console.log("PassUI.auth.requestKey() authRequestOpts", authRequestOpts);
  void (await PassKey.auth
    .request(authRequestOpts, "switch to explicit request")
    .then(PassUI.auth.handleBuffers)
    .catch(function (err) {
      console.warn(
        "PassUI.auth.requestKey() was canceled or failed:",
        err.message,
      );
      void PassUI.auth.keepAutocompleteAlive();
      throw err;
    })
    .catch(PassKey.ignoreIfCanceled)
    .catch(PassUI._alertError));
};

PassUI.auth.keepAutocompleteAlive = async function () {
  let $mediation = $('select[name="mediation"]');
  //@ts-ignore
  if ($mediation.value !== "conditional") {
    //@ts-ignore
    $mediation.value = "conditional";
    //@ts-ignore
    $mediation.onchange();
    return;
  }

  void PassUI.auth._keepAutocompleteAlive();
};

PassUI.auth._keepAutocompleteAlive = async function () {
  console.log(
    `PassUI.auth.keepAutocompleteAlive(${PassKey.support.conditional})`,
  );
  if (!PassKey.support.conditional) {
    return;
  }

  let autocompleteOpts = globalThis.structuredClone(PassKey.auth.defaultOpts);
  void (await PassKey.auth
    .requestAutocomplete(autocompleteOpts, "restarting autocomplete")
    //@ts-ignore
    .then(PassUI.auth.handleBuffers)
    .catch(PassKey.ignoreIfCanceled)
    .then(function () {
      void PassUI.auth.keepAutocompleteAlive();
    })
    .catch(PassKey.ignoreIfAborted)
    /** @param {Error} err */
    .catch(PassUI._alertError));
};

/**
 * @param {Event} event
 */
PassUI.setAttachment = async function (event) {
  //@ts-ignore
  let newAttachment = $('select[name="attachment"]').value || "";
  PassUI.attachment = newAttachment;

  console.log(`PassUI.setAttachment(${PassUI.attachment})`);

  void PassUI.auth._keepAutocompleteAlive();
};

/**
 * @param {Event} event
 */
PassUI.auth.setMediation = async function (event) {
  //@ts-ignore
  let newMediation = $('select[name="mediation"]').value || "";
  PassUI.auth.mediation = newMediation;

  console.log(`PassUI.setMediation(${PassUI.auth.mediation})`);

  if (PassUI.auth.mediation !== "conditional") {
    //@ts-ignore
    $('[data-id="register"]').hidden = true;
    //@ts-ignore
    $('[data-id="username"]').hidden = true;
    return;
  }

  //@ts-ignore
  $('[data-id="register"]').hidden = false;
  //@ts-ignore
  $('[data-id="username"]').hidden = false;

  void PassUI.auth._keepAutocompleteAlive();
};

/**
 * @param {Error} err
 */
PassUI._alertError = async function (err) {
  // most errors aren't errors as much as just timeout, cancellation, or some thing like that.

  let msg = `Unexpected Credential Error:`;
  console.error(msg);

  console.warn(`Caught bubbled-up UI error:`);
  //@ts-ignore
  console.error(`err.code: ${err.code}`);
  //@ts-ignore
  console.error(`err.type: ${err.type}`);
  console.error(`err.name: ${err.name}`);
  console.error(`err.message: ${err.message}`);
  console.error(err);
  window.alert(`${msg}\n\n${err.message}`);
};

/**
 * @param {void|PublicKeyCredential?} regResp
 */
PassUI.reg.handleBuffers = async function (regResp) {
  console.log(`PassUI.reg.handleBuffers (opaque):`);
  console.log(regResp);

  let regResult = PassKey.reg.responseToJSON(regResp);
  console.log(`PassUI.auth.handleObject (JSON):`);
  console.log(regResult);
  let regResultJSON = JSON.stringify(regResult, null, 2);
  console.log(regResultJSON);
  window.alert(
    `[default PassUI.auth.handleObject]\nCreate or Replace Passkey was Successful:\n\n${regResultJSON}`,
  );

  //@ts-ignore
  $("input[name=username]").value = "";
};

/**
 * @param {PublicKeyCredential} authResp
 */
PassUI.auth.handleBuffers = async function (authResp) {
  console.log(`PassUI.auth.handleBuffers (opaque):`);
  console.log(authResp);

  let authResult = PassKey.auth.responseToJSON(authResp);
  console.log(`PassUI.auth.handleObject (JSON):`);
  console.log(authResult);
  let authResultJSON = JSON.stringify(authResult, null, 2);
  console.log(authResultJSON);
  window.alert(
    `[default PassUI.auth.handleObject]\nAuth via Saved Passkey was Successful:\n\n${authResultJSON}`,
  );
};

Object.assign(window, { PassUI });

async function mockChallengeFromServer() {
  // mocking a server challenge
  let nonceBytes = new Uint8Array(32);
  void globalThis.crypto.getRandomValues(nonceBytes);
  let nonce = PassKey.bufferToBase64(nonceBytes);
  // return nonce;

  let sigBytes = new Uint8Array(32);
  void globalThis.crypto.getRandomValues(sigBytes);
  let signature = PassKey.bufferToBase64(nonceBytes);

  let headerJSON = JSON.stringify({ alg: "bogo" });
  let headerBytes = PassKey.textEncoder.encode(headerJSON);
  let header = PassKey.bufferToBase64(headerBytes);

  let claimsJSON = JSON.stringify({ nonce });
  let claimsBytes = PassKey.textEncoder.encode(claimsJSON);
  let claims = PassKey.bufferToBase64(claimsBytes);

  let challengeString = `${header}.${claims}.${signature}`;
  let challengeBytes = PassKey.textEncoder.encode(challengeString);
  let challenge = PassKey.bufferToBase64(challengeBytes);

  return challenge;
}

async function main() {
  let name = $("title")?.textContent || "";
  let challenge = await mockChallengeFromServer();

  await PassKey.init({ name, challenge });
  console.log("WebAuthn Support?", PassKey.support);

  void PassUI.auth.keepAutocompleteAlive();
}

main().catch(function (err) {
  console.error("main() caught uncaught error:");
  console.error(err.message);
});
