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
 * @param {Boolean} rfc
 */
PassKey.bufferToBase64 = function (buffer, rfc) {
  if (!buffer?.byteLength) {
    return "";
  }

  let bytes = new Uint8Array(buffer);
  //@ts-ignore
  let binstr = String.fromCharCode.apply(null, bytes);
  let rfcBase64 = btoa(binstr);
  if (rfc) {
    return rfcBase64;
  }

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
    attestation: "direct", // "none"
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
 * @param {PublicKeyCredential} cred
 */
PassKey.reg.responseToJSON = function (cred) {
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
 * @param {PublicKeyCredential} cred
 */
PassKey.auth.responseToJSON = function (cred) {
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
      getClientSecretUserHandle: function () {
        return assResp.userHandle;
      },
      getClientSecretUserHandleHex: function () {
        // this is a client-side secret and should NOT be disclosed to the server
        // (up to 64 bytes of arbitrary data, some of which may be made public)
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
  if (!pubkeyRegOpts.publicKey.user.id.byteLength) {
    pubkeyRegOpts.publicKey.user.id = new Uint8Array(32);
    //@ts-ignore - trust me bro, it's a Uint8Array ^^
    globalThis.crypto.getRandomValues(pubkeyRegOpts.publicKey.user.id);
  }
  if (pubkeyRegOpts.publicKey.user.id.byteLength > 64) {
    throw new Error("publicKey.user.id must be less than 64 bytes");
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

  pubkeyRegOpts.publicKey.user.name = lowername;
  pubkeyRegOpts.publicKey.user.displayName = username.replace(/(\w)@.*/, "$1");

  // to prevent overwriting the ID / public key when creating
  // (or to not show the current user in a login-is prompt)
  // excludeCredentials: [ { type: 'public-key', id: ArrayBuffer }]
  pubkeyRegOpts.publicKey.excludeCredentials = [];
  let idsMap = await PassUI.storage.get(`webauthn:ids`);
  let ids = Object.keys(idsMap);
  for (let id of ids) {
    let idBytes = PassKey.base64ToBytes(id);
    pubkeyRegOpts.publicKey.excludeCredentials.push({
      type: "public-key",
      id: idBytes,
    });

    let data = sessionStorage.getItem(`webauthn:cred-${id}-data`);
    if (!data) {
      continue;
    }
    let dataBytes = PassKey.base64ToBytes(data);
    pubkeyRegOpts.publicKey.excludeCredentials.push({
      type: "public-key",
      id: dataBytes,
    });
  }

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
    .then(PassUI.reg.handleBuffersFor(pubkeyRegOpts))
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
    .then(PassUI.auth.handleBuffersFor(authRequestOpts))
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
    .then(PassUI.auth.handleBuffersFor(autocompleteOpts))
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
 * @param {CredentialCreationOptions} pubkeyRegOpts
 */
PassUI.reg.handleBuffersFor = function (pubkeyRegOpts) {
  /**
   * @param {void|PublicKeyCredential?} regResp
   */
  return async function (regResp) {
    console.log(`PassUI.reg.handleBuffers (opaque):`);
    console.log(regResp);
    if (!regResp) {
      throw new Error(
        "[Developer Error] expected credential registration but got nothing",
      );
    }

    let regResult = PassKey.reg.responseToJSON(regResp);
    //@ts-ignore - publicKey exists
    Object.assign(regResult, { _name: pubkeyRegOpts.publicKey.user.name });
    console.log(`PassUI.auth.handleObject (JSON):`);
    console.log(regResult);

    let regResultJSON = JSON.stringify(regResult, null, 2);
    console.log(regResultJSON);
    window.alert(
      `[default PassUI.auth.handleObject]\nCreate or Replace Passkey was Successful:\n\n${regResultJSON}`,
    );

    localStorage.setItem(`webauthn:cred-${regResult.id}-reg`, regResultJSON);
    {
      // @ts-ignore - publicKey exists
      let data = pubkeyRegOpts.publicKey.user.id || null;
      // @ts-ignore - trust me bro, it's a buffer
      let dataHex = PassKey._bufferToHex(data);
      sessionStorage.setItem(`webauthn:cred-${regResult.id}-data`, dataHex);
      let idsMap = await PassUI.storage.get(`webauthn:ids`);
      idsMap[regResult.id] = true;
      PassUI.storage.set(`webauthn:ids`, idsMap);
    }

    //@ts-ignore
    $("input[name=username]").value = "";
  };
};

/**
 * @param {CredentialRequestOptions} authRequestOpts
 */
PassUI.auth.handleBuffersFor = function (authRequestOpts) {
  /**
   * @param {PublicKeyCredential} authResp
   */
  return async function (authResp) {
    console.log(`PassUI.auth.handleBuffers (opaque):`);
    console.log(authResp);
    if (!authResp) {
      throw new Error(
        "[Developer Error] expected credential response but got nothing",
      );
    }

    let authResult = PassKey.auth.responseToJSON(authResp);
    console.log(`PassUI.auth.handleObject (JSON):`);
    console.log(authResult);
    let authResultJSON = JSON.stringify(authResult, null, 2);
    console.log(authResultJSON);
    window.alert(
      `[default PassUI.auth.handleObject]\nAuth via Saved Passkey was Successful:\n\n${authResultJSON}`,
    );

    localStorage.setItem(`webauthn:cred-${authResult.id}-auth`, authResultJSON);

    {
      let dataBytes = authResult.response.getClientSecretUserHandle();
      let data = PassKey.bufferToBase64(dataBytes);
      sessionStorage.setItem(`webauthn:cred-${authResult.id}-data`, data);
      let idsMap = await PassUI.storage.get(`webauthn:ids`);
      idsMap[authResult.id] = true;
      PassUI.storage.set(`webauthn:ids`, idsMap);
    }
  };
};

PassUI.storage = {};
PassUI.storage.all = async function () {
  /** @type {Array<any>} */
  let results = [];
  let vacuum = [];

  for (let i = 0; i < localStorage.length; i += 1) {
    let key = localStorage.getKey(i);
    let isWebAuthn = key.startsWith("webauthn:");
    if (!isWebAuthn) {
      continue;
    }

    let dataJSON = localStorage.getItem(key);
    if (!dataJSON) {
      vacuum.push(key);
      continue;
    }

    let data;
    try {
      data = JSON.parse(dataJSON);
    } catch (e) {
      continue;
    }
    results.push(data);
  }

  for (let key of vacuum) {
    localStorage.removeItem(key);
  }

  return results;
};
/**
 * @param {String} key
 * @param {any} [defaultValue]
 */
PassUI.storage.get = async function (key, defaultValue) {
  let value;
  try {
    let valueJSON = localStorage.getItem(key);
    if (valueJSON) {
      value = JSON.parse(valueJSON);
    }
  } catch (e) {
    // ignore
  }
  if (!value) {
    value = defaultValue || null;
  }
  return value;
};
/**
 * @param {String} key
 * @param {any} value
 */
PassUI.storage.set = async function (key, value) {
  let valueJSON = JSON.stringify(value);
  localStorage.setItem(key, valueJSON);
};

PassUI.views = {
  /**
   * @param {String} str
   * @param {Number} chunkSize
   */
  _splitString: function (str, chunkSize = 32, padLen = 0) {
    let lines = [];

    for (let i = 0; i < str.length; i += chunkSize) {
      let substr = str.substr(i, chunkSize);
      let pad = " ".repeat(padLen);
      let padded = `${pad}${substr}`;
      lines.push(padded);
    }

    let block = lines.join("\n");
    block = block.trim();
    return block;
  },
  credentials: {
    render: async function () {
      /** @type {HTMLElement} */ // @ts-ignore
      let $tmplRow = $('template[data-tmpl="webauthn-credential"]');
      let idsMap = await PassUI.storage.get(`webauthn:ids`);
      let ids = Object.keys(idsMap);

      let domRows = document.createDocumentFragment();
      for (let id of ids) {
        let reg = await PassUI.storage.get(`webauthn:cred-${id}-reg`, null);
        let auth = await PassUI.storage.get(`webauthn:cred-${id}-auth`, null);
        let secret = sessionStorage.getItem(`webauthn:cred-${id}-data`);

        /** @type {HTMLElement} */ // @ts-ignore
        let $row = $tmplRow.content.cloneNode(true);

        let info = [];
        if (reg) {
          /** @type {HTMLElement} */ // @ts-ignore
          $row.querySelector('[data-name="name"]').textContent = reg._name;

          info.push(`Attachment:  ${reg.authenticatorAttachment}`);

          let credId = PassUI.views._splitString(reg.id, 40, 13);
          info.push(`Credential:  ${credId}`);

          let attBytes = PassKey.base64ToBytes(reg.response.attestationObject);
          let attHex = PassKey._bufferToHex(attBytes);
          let att = PassUI.views._splitString(attHex, 40, 13);
          let attObj;
          try {
            let CBOR = window.CBOR;
            let cbor = CBOR.create(attBytes.buffer);
            attObj = cbor.parse();
            console.log(`attestation:`);
            console.log(attObj);
          } catch (e) {
            console.error(e);
          }
          if (attObj?.attStmt?.x5c) {
            let x5c = PassKey.bufferToBase64(attObj.attStmt.x5c[0], true);
            let pem = PassUI.views._splitString(x5c, 64);
            pem = `-----BEGIN CERTIFICATE-----\n${pem}\n-----END CERTIFICATE-----`;
            let queryIter = new URLSearchParams({ cert: pem });
            let search = queryIter.toString();
            info.push(
              `<a href="https://x5c.bnna.net/#/?${search}" target="_blank">Attestation</a>: ${att}`,
            );
          } else {
            info.push(`Attestation: ${att}`);
          }

          let pubKeyHex = PassUI.views._splitString(
            reg.response.publicKeyHex,
            40,
            13,
          );
          info.push(`PubKey DER:  ${pubKeyHex}`);
          info.push(`Algorithm:   ${reg.response.publicKeyAlgorithmName}`);
          info.push(`Transports:  ${reg.response.transports}`);
        } else if (auth) {
          info.push(`Attachment:  ${auth.authenticatorAttachment}`);
          let credId = PassUI.views._splitString(auth.id, 40, 12);
          info.push(`Credential:  ${credId}`);
        } else if (!secret) {
          continue;
        }
        info.push(`Type:        public-key`);

        /** @type {HTMLElement} */ // @ts-ignore
        $row.querySelector('[data-name="data"]').innerHTML = info.join("\n");

        if (secret) {
          /** @type {HTMLElement} */ // @ts-ignore
          $row.querySelector('[data-name="secret"]').textContent =
            PassUI.views._splitString(secret, 32);
        }
        domRows.appendChild($row);
      }

      /** @type {HTMLElement} */ // @ts-ignore
      let $credBody = $('[data-id="webauthn-credentials"]');
      requestAnimationFrame(function () {
        $credBody.textContent = "";
        $credBody.appendChild(domRows);
      });
    },
  },
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

  let idsMap = await PassUI.storage.get(`webauthn:ids`, {});
  await PassUI.storage.set(`webauthn:ids`, idsMap);

  console.log("[LISTEN] semtab:credentials");
  document.body.addEventListener(`semtab:credentials`, function () {
    console.log(`[semtab:credentials] render`);
    PassUI.views.credentials.render();
  });

  //@ts-ignore
  let SemTabs = window.SemTabs;
  SemTabs.init({ aliases: { ids: "credentials" } });
}

main().catch(function (err) {
  console.error("main() caught uncaught error:");
  console.error(err.message);
});
