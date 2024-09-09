"use strict";

import PassKey from "./passkey.js";
import LocalStore from "./localstore.js";

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
  let idsMap = await LocalStore.get(`webauthn:ids`);
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
    .catch(
      /** @param {Error} err */
      function (err) {
        console.warn(
          "PassUI.auth.requestKey() was canceled or failed:",
          err.message,
        );
        void PassUI.auth.keepAutocompleteAlive();
        throw err;
      },
    )
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
    .catch(
      /** @param {Error} err */
      function (err) {
        console.warn(
          "PassUI.auth.requestKey() was canceled or failed:",
          err.message,
        );
        void PassUI.auth.keepAutocompleteAlive();
        throw err;
      },
    )
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

    LocalStore.set(`webauthn:cred-${regResult.id}-reg`, regResult);
    {
      // @ts-ignore - publicKey exists
      let data = pubkeyRegOpts.publicKey.user.id || null;
      // @ts-ignore - trust me bro, it's a buffer
      let dataHex = PassKey._bufferToHex(data);
      sessionStorage.setItem(`webauthn:cred-${regResult.id}-data`, dataHex);
      let idsMap = await LocalStore.get(`webauthn:ids`);
      idsMap[regResult.id] = true;
      LocalStore.set(`webauthn:ids`, idsMap);
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

    LocalStore.set(`webauthn:cred-${authResult.id}-auth`, authResult);

    {
      let dataBytes = authResult.response.getClientSecretUserHandle();
      let data = PassKey.bufferToBase64(dataBytes);
      sessionStorage.setItem(`webauthn:cred-${authResult.id}-data`, data);
      let idsMap = await LocalStore.get(`webauthn:ids`);
      idsMap[authResult.id] = true;
      LocalStore.set(`webauthn:ids`, idsMap);
    }
  };
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
      let idsMap = await LocalStore.get(`webauthn:ids`);
      let ids = Object.keys(idsMap);

      let domRows = document.createDocumentFragment();
      for (let id of ids) {
        let reg = await LocalStore.get(`webauthn:cred-${id}-reg`, null);
        let auth = await LocalStore.get(`webauthn:cred-${id}-auth`, null);
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

  void (await LocalStore.init(`webauthn:ids`, {}));

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
