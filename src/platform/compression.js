import { deflateSync, inflateSync } from "fflate";

export function deflateRawSync(bytes) {
  return deflateSync(bytes);
}

export function inflateRawSync(bytes, options = {}) {
  const { maxOutputLength } = options;
  if (maxOutputLength === undefined) return inflateSync(bytes);
  if (!Number.isSafeInteger(maxOutputLength) || maxOutputLength < 0 ||
      maxOutputLength === Number.MAX_SAFE_INTEGER) {
    throw new RangeError("maxOutputLength must be a nonnegative safe integer");
  }
  const maximum = maxOutputLength + 1;
  let capacity = Math.min(maximum, 0x10000);
  while (true) {
    const output = inflateSync(bytes, { out: new Uint8Array(capacity) });
    if (output.length < capacity) return output;
    if (capacity === maximum) {
      throw new RangeError(`Decompressed data exceeds ${maxOutputLength} bytes`);
    }
    capacity = Math.min(maximum, capacity * 2);
  }
}
