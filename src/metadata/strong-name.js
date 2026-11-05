import forge from "node-forge";
import { FormatError, UnsupportedFormatError } from "../binary/errors.js";
import { binaryStringToBytes, bytesToBinaryString } from "../platform/bytes.js";

const rsaSignAlgorithm = 0x00002400;
const sha1Algorithm = 0x00008004;
const hashNames = new Map([
  [sha1Algorithm, "sha1"],
  [0x0000800c, "sha256"],
  [0x0000800d, "sha384"],
  [0x0000800e, "sha512"]
]);

export function getStrongNameHashName(algorithm) {
  const resolvedAlgorithm = algorithm || sha1Algorithm;
  const name = hashNames.get(resolvedAlgorithm);
  if (!name) {
    throw new UnsupportedFormatError(
      `Strong-name hash algorithm 0x${resolvedAlgorithm.toString(16)} is unsupported`
    );
  }
  return name;
}

function binaryIntegerBytes(value, length) {
  let hex = value.toString(16);
  if ((hex.length & 1) !== 0) hex = `0${hex}`;
  const encoded = binaryStringToBytes(forge.util.hexToBytes(hex));
  if (encoded.length > length) throw new FormatError("RSA integer exceeds its declared size");
  const output = new Uint8Array(length);
  output.set(encoded, length - encoded.length);
  return output;
}

function getRsaModulusBits(key) {
  return key.n.bitLength();
}

export function importStrongNamePrivateKey(input) {
  if (input && typeof input === "object" && input.n && input.e && input.d) return input;
  let pem = input;
  if (input && typeof input === "object" && input.type === "private" &&
      typeof input.export === "function") {
    if (input.asymmetricKeyType !== "rsa") {
      throw new UnsupportedFormatError("Strong-name signing requires an RSA private key");
    }
    pem = input.export({ format: "pem", type: "pkcs8" });
  } else if (input instanceof Uint8Array) {
    pem = new TextDecoder("ascii", { fatal: true }).decode(input);
  }
  if (typeof pem !== "string") {
    throw new UnsupportedFormatError("Strong-name signing requires an RSA PEM or private key");
  }
  const key = forge.pki.privateKeyFromPem(pem);
  if (!key.n || !key.e || !key.d) {
    throw new UnsupportedFormatError("Strong-name signing requires an RSA private key");
  }
  return key;
}

export function encodeStrongNamePublicKey(keyInput, hashAlgorithm) {
  const hashName = getStrongNameHashName(hashAlgorithm);
  const key = importStrongNamePrivateKey(keyInput);
  const modulusBits = getRsaModulusBits(key);
  const modulusLength = Math.ceil(modulusBits / 8);
  const modulus = binaryIntegerBytes(key.n, modulusLength);
  const exponent = Number(key.e.toString(10));
  if (modulusBits % 8 !== 0) {
    throw new UnsupportedFormatError("Strong-name RSA modulus length must be byte-aligned");
  }
  if (exponent < 3 || exponent % 2 === 0) {
    throw new UnsupportedFormatError("Strong-name RSA public exponent is invalid");
  }

  const capiKey = new Uint8Array(20 + modulus.length);
  const capiView = new DataView(capiKey.buffer);
  capiKey[0] = 0x06;
  capiKey[1] = 0x02;
  capiView.setUint32(4, rsaSignAlgorithm, true);
  capiView.setUint32(8, 0x31415352, true);
  capiView.setUint32(12, modulusBits, true);
  capiView.setUint32(16, exponent, true);
  for (let index = 0; index < modulus.length; index++) {
    capiKey[20 + index] = modulus[modulus.length - 1 - index];
  }

  const hashAlgorithmId = [...hashNames].find(([, name]) => name === hashName)?.[0];
  const publicKey = new Uint8Array(12 + capiKey.length);
  const publicKeyView = new DataView(publicKey.buffer);
  publicKeyView.setUint32(0, rsaSignAlgorithm, true);
  publicKeyView.setUint32(4, hashAlgorithmId, true);
  publicKeyView.setUint32(8, capiKey.length, true);
  publicKey.set(capiKey, 12);
  return typeof Buffer === "undefined" ? publicKey : Buffer.from(publicKey);
}

export function decodeStrongNamePublicKey(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 32) {
    throw new FormatError("Strong-name public key is truncated");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const signatureAlgorithm = view.getUint32(0, true);
  const hashAlgorithm = view.getUint32(4, true);
  const publicKeySize = view.getUint32(8, true);
  if (signatureAlgorithm !== rsaSignAlgorithm || publicKeySize !== bytes.length - 12) {
    throw new UnsupportedFormatError("Strong-name public key uses an unsupported algorithm or size");
  }
  getStrongNameHashName(hashAlgorithm);
  if (bytes[12] !== 0x06 || bytes[13] !== 0x02 ||
      view.getUint16(14, true) !== 0 ||
      view.getUint32(16, true) !== rsaSignAlgorithm ||
      view.getUint32(20, true) !== 0x31415352) {
    throw new UnsupportedFormatError("Strong-name public key does not contain a supported CAPI RSA key");
  }
  const modulusBits = view.getUint32(24, true);
  const exponent = view.getUint32(28, true);
  if (modulusBits === 0 || modulusBits % 8 !== 0 ||
      publicKeySize !== 20 + modulusBits / 8 || exponent < 3 || exponent % 2 === 0) {
    throw new FormatError("Strong-name CAPI RSA key has inconsistent dimensions");
  }
  const modulus = Uint8Array.from(bytes.subarray(32)).reverse();
  if ((modulus[0] & 0x80) === 0) {
    throw new FormatError("Strong-name RSA modulus does not match its declared bit length");
  }
  const modulusHex = forge.util.bytesToHex(bytesToBinaryString(modulus));
  const publicKey = forge.pki.rsa.setPublicKey(
    new forge.jsbn.BigInteger(modulusHex, 16),
    new forge.jsbn.BigInteger(String(exponent), 10)
  );
  return {
    publicKey,
    hashAlgorithm,
    signatureSize: modulusBits / 8
  };
}

export function assertStrongNamePEProfile(pe) {
  const fixedOptionalHeaderSize = pe.optionalHeaderMagic === 0x10b ? 96 : 112;
  if (pe.optionalHeaderSize !== fixedOptionalHeaderSize + 16 * 8 ||
      pe.directories.length < 15 || pe.directories.length > 16) {
    throw new UnsupportedFormatError(
      "Strong-name signing requires the standard PE optional header with 15 or 16 declared data directories"
    );
  }
  return fixedOptionalHeaderSize;
}

function getStrongNameRanges(bytes, pe, cli) {
  const fixedOptionalHeaderSize = assertStrongNamePEProfile(pe);
  const signature = cli.strongNameSignature;
  if (signature.rva === 0 || signature.size === 0) {
    throw new UnsupportedFormatError("Strong-name signing requires a reserved signature directory");
  }
  const signatureOffset = pe.rvaToOffset(signature.rva, signature.size);
  const signatureEnd = signatureOffset + signature.size;
  const containingSection = pe.sections.find((section) =>
    signatureOffset >= section.rawPointer &&
    signatureEnd <= section.rawPointer + section.rawSize
  );
  if (!containingSection) {
    throw new FormatError("Strong-name signature slot is not contained in section data");
  }
  return { signatureOffset, signatureEnd, fixedOptionalHeaderSize };
}

function updateStrongNameData(signer, bytes, pe, ranges) {
  const update = (part) => signer.update(bytesToBinaryString(part));
  update(bytes.subarray(0, pe.peOffset));
  update(bytes.subarray(pe.peOffset, pe.peOffset + 24));

  const optionalHeader = Uint8Array.from(bytes.subarray(
    pe.optionalHeaderOffset,
    pe.optionalHeaderOffset + ranges.fixedOptionalHeaderSize
  ));
  optionalHeader.fill(0, 64, 68);
  update(optionalHeader);

  const directoriesOffset = pe.optionalHeaderOffset + ranges.fixedOptionalHeaderSize;
  const directories = Uint8Array.from(bytes.subarray(directoriesOffset, directoriesOffset + 16 * 8));
  directories.fill(0, 4 * 8, 5 * 8);
  update(directories);
  update(bytes.subarray(pe.sectionOffset, pe.sectionOffset + pe.sectionCount * 40));

  for (const section of pe.sections) {
    const start = section.rawPointer;
    const end = start + section.rawSize;
    const beforeEnd = Math.min(end, ranges.signatureOffset);
    if (start < beforeEnd) update(bytes.subarray(start, beforeEnd));
    const afterStart = Math.max(start, ranges.signatureEnd);
    if (afterStart < end) update(bytes.subarray(afterStart, end));
  }
}

export function signStrongNameImage(bytes, pe, cli, privateKey, hashAlgorithm) {
  const hashName = getStrongNameHashName(hashAlgorithm);
  const output = Uint8Array.from(bytes);
  const ranges = getStrongNameRanges(output, pe, cli);
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  view.setUint32(cli.strongNameFlagOffset, cli.flags | 0x08, true);

  const signer = forge.md[hashName].create();
  updateStrongNameData(signer, output, pe, ranges);
  const signature = binaryStringToBytes(privateKey.sign(signer)).reverse();
  if (signature.length !== cli.strongNameSignature.size) {
    throw new FormatError(
      `Strong-name signature size ${signature.length} does not match reserved slot ${cli.strongNameSignature.size}`
    );
  }
  output.set(signature, ranges.signatureOffset);
  return output;
}

export function verifyStrongNameImage(bytes, pe, cli, publicKeyBytes, hashAlgorithm) {
  if ((cli.flags & 0x08) === 0) return false;
  const key = decodeStrongNamePublicKey(publicKeyBytes);
  const hashName = getStrongNameHashName(hashAlgorithm || key.hashAlgorithm);
  if (cli.strongNameSignature.size !== key.signatureSize) return false;
  const ranges = getStrongNameRanges(bytes, pe, cli);
  const signature = bytesToBinaryString(
    Uint8Array.from(bytes.subarray(ranges.signatureOffset, ranges.signatureEnd)).reverse()
  );
  const verifier = forge.md[hashName].create();
  updateStrongNameData(verifier, bytes, pe, ranges);
  try {
    return key.publicKey.verify(verifier.digest().getBytes(), signature);
  } catch (error) {
    if (error instanceof Error && error.message === "Encryption block is invalid.") return false;
    throw error;
  }
}
