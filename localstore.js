"use strict";

let LocalStore = {};

/**
 * @param {String} key
 * @param {any} val
 */
LocalStore.init = async function (key, val) {
  let cur = await LocalStore.get(key);
  if (cur !== null) {
    return;
  }
  await LocalStore.set(key, val);
};

// LocalStore.all = async function (prefix) {
//   /** @type {Array<any>} */
//   let results = [];
//   let vacuum = [];

//   for (let i = 0; i < localStorage.length; i += 1) {
//     let key = localStorage.getKey(i);
//     let isWebAuthn = key.startsWith(prefix);
//     if (!isWebAuthn) {
//       continue;
//     }

//     let dataJSON = localStorage.getItem(key);
//     if (dataJSON === null) {
//       vacuum.push(key);
//       continue;
//     }

//     let data;
//     try {
//       data = JSON.parse(dataJSON);
//     } catch (e) {
//       continue;
//     }
//     results.push(data);
//   }

//   for (let key of vacuum) {
//     localStorage.removeItem(key);
//   }

//   return results;
// };

/**
 * @param {String} key
 * @param {any} [defaultValue]
 */
LocalStore.get = async function (key, defaultValue) {
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
LocalStore.set = async function (key, value) {
  let valueJSON = JSON.stringify(value);
  localStorage.setItem(key, valueJSON);
};

export default LocalStore;
