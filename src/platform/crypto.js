import forge from "node-forge";
import { binaryStringToBytes, bytesToBinaryString } from "./bytes.js";

export function createHash(name) {
  const factory = forge.md[name];
  if (!factory) throw new RangeError(`Unsupported hash algorithm ${name}`);
  const digest = factory.create();
  return {
    update(bytes) {
      digest.update(bytesToBinaryString(bytes));
      return this;
    },
    digest() {
      return binaryStringToBytes(digest.digest().getBytes());
    }
  };
}
