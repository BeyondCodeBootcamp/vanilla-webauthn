"use strict";
/* jshint bitwise: false */

var CBOR = {};

CBOR.create = function (bytes) {
  let dataView = new DataView(bytes.buffer || bytes);
  let offset = 0;

  function parse() {
    let [value, newOffset] = CBOR._decodeValue(dataView, offset);
    offset = newOffset;
    return value;
  }

  return {
    parse,
  };
};

CBOR._decodeValue = function (dataView, offset) {
  let byte = dataView.getUint8(offset);
  let majorType = byte >> 5; // first 3 bits
  let additionalInfo = byte & 0x1f; // last 5 bits
  offset += 1; // Move past the initial byte

  if (majorType === 0) {
    return CBOR._decodeUnsignedInteger(dataView, offset, additionalInfo);
  }
  if (majorType === 1) {
    return CBOR._decodeNegativeInteger(dataView, offset, additionalInfo);
  }
  if (majorType === 2) {
    return CBOR._decodeByteString(dataView, offset, additionalInfo);
  }
  if (majorType === 3) {
    return CBOR._decodeTextString(dataView, offset, additionalInfo);
  }
  if (majorType === 4) {
    return CBOR._decodeArray(dataView, offset, additionalInfo);
  }
  if (majorType === 5) {
    return CBOR._decodeMap(dataView, offset, additionalInfo);
  }
  if (majorType === 7) {
    return CBOR._decodeSpecial(dataView, offset, additionalInfo);
  }
  throw new Error(`Unsupported major type: ${majorType}`);
};

CBOR._decodeUnsignedInteger = function (dataView, offset, additionalInfo) {
  return CBOR._decodeInteger(dataView, offset, additionalInfo);
};

CBOR._decodeNegativeInteger = function (dataView, offset, additionalInfo) {
  let [value, newOffset] = CBOR._decodeInteger(
    dataView,
    offset,
    additionalInfo,
  );
  return [-1 - value, newOffset];
};

CBOR._decodeInteger = function (dataView, offset, additionalInfo) {
  if (additionalInfo < 24) {
    return [additionalInfo, offset];
  }
  if (additionalInfo === 24) {
    let value = dataView.getUint8(offset);
    return [value, offset + 1];
  }
  if (additionalInfo === 25) {
    let value = dataView.getUint16(offset);
    return [value, offset + 2];
  }
  if (additionalInfo === 26) {
    let value = dataView.getUint32(offset);
    return [value, offset + 4];
  }
  if (additionalInfo === 27) {
    let high = dataView.getUint32(offset);
    let low = dataView.getUint32(offset + 4);
    let b = (BigInt(high) << 32n) | BigInt(low);
    return [b, offset + 8];
  }
  throw new Error("Unsupported integer encoding");
};

CBOR._decodeByteString = function (dataView, offset, additionalInfo) {
  let [length, newOffset] = CBOR._decodeInteger(
    dataView,
    offset,
    additionalInfo,
  );
  let bytes = new Uint8Array(dataView.buffer, newOffset, length);
  return [bytes, newOffset + length];
};

CBOR._decodeTextString = function (dataView, offset, additionalInfo) {
  let [length, newOffset] = CBOR._decodeInteger(
    dataView,
    offset,
    additionalInfo,
  );
  let bytes = new Uint8Array(dataView.buffer, newOffset, length);
  let text = new TextDecoder().decode(bytes); // Decode UTF-8 text
  return [text, newOffset + length];
};

CBOR._decodeArray = function (dataView, offset, additionalInfo) {
  let [length, newOffset] = CBOR._decodeInteger(
    dataView,
    offset,
    additionalInfo,
  );
  let array = [];
  for (let i = 0; i < length; i += 1) {
    let [value, nextOffset] = CBOR._decodeValue(dataView, newOffset);
    array.push(value);
    newOffset = nextOffset;
  }
  return [array, newOffset];
};

CBOR._decodeMap = function (dataView, offset, additionalInfo) {
  let [length, newOffset] = CBOR._decodeInteger(
    dataView,
    offset,
    additionalInfo,
  );
  let map = {};
  for (let i = 0; i < length; i += 1) {
    let [key, keyOffset] = CBOR._decodeValue(dataView, newOffset);
    let [value, valueOffset] = CBOR._decodeValue(dataView, keyOffset);
    map[key] = value;
    newOffset = valueOffset;
  }
  return [map, newOffset];
};

CBOR._decodeSpecial = function (dataView, offset, additionalInfo) {
  if (additionalInfo === 20) {
    return [false, offset];
  }
  if (additionalInfo === 21) {
    return [true, offset];
  }
  if (additionalInfo === 22) {
    return [null, offset];
  }
  if (additionalInfo === 23) {
    return [undefined, offset];
  }

  if (additionalInfo === 25) {
    let value = dataView.getFloat16(offset);
    return [value, offset + 2];
  }
  if (additionalInfo === 26) {
    let value = dataView.getFloat32(offset);
    return [value, offset + 4];
  }
  if (additionalInfo === 27) {
    let value = dataView.getFloat64(offset);
    return [value, offset + 8];
  }

  throw new Error(`Unsupported special value encoding: ${additionalInfo}`);
};
