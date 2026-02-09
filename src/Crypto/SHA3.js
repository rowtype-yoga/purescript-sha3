export function bufferToArray(buf) {
  return Array.from(buf);
}

export function bufferFromArray(arr) {
  return Buffer.from(arr);
}

export function bufferToHex(buf) {
  return buf.toString("hex");
}

export function bufferFromHex(success) {
  return function(failure) {
    return function(str) {
      if (str.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(str)) {
        return failure;
      }
      return success(Buffer.from(str, "hex"));
    };
  };
}

export function stringToUtf8Buffer(str) {
  return Buffer.from(str, "utf8");
}

export function eqBuffer(a) {
  return function(b) {
    return a.equals(b);
  };
}