import {
  createPrivateKey,
  createPublicKey,
  createSign,
  createVerify
} from "node:crypto";
import { FormatError, UnsupportedFormatError } from "../binary/errors.js";

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

export function importStrongNamePrivateKey(input) {
  const key = input && typeof input === "object" && input.type === "private"
    ? input
    : createPrivateKey(input);
  if (key.asymmetricKeyType !== "rsa") {
    throw new UnsupportedFormatError("Strong-name signing requires an RSA private key");
  }
  if (!key.asymmetricKeyDetails?.modulusLength) {
    throw new UnsupportedFormatError("Strong-name RSA key does not expose its modulus length");
  }
  return key;
}

function getRsaJwk(key) {
  const jwk = createPublicKey(key).export({ format: "jwk" });
  if (!jwk.n || !jwk.e || jwk.kty !== "RSA") {
    throw new UnsupportedFormatError("Strong-name key is not a usable RSA key");
  }
  return jwk;
}

function getRsaModulus(key, jwk) {
  const modulusLength = Math.ceil(key.asymmetricKeyDetails.modulusLength / 8);
  const encoded = Buffer.from(jwk.n, "base64url");
  if (encoded.length > modulusLength) {
    throw new FormatError("RSA modulus exceeds its declared bit length");
  }
  const modulus = Buffer.alloc(modulusLength);
  encoded.copy(modulus, modulusLength - encoded.length);
  return modulus;
}

function getRsaExponent(jwk) {
  const bytes = Buffer.from(jwk.e, "base64url");
  if (bytes.length === 0 || bytes.length > 4) {
    throw new UnsupportedFormatError("Strong-name RSA public exponent exceeds the CAPI format");
  }
  let exponent = 0;
  for (const byte of bytes) exponent = exponent * 256 + byte;
  return exponent;
}

export function encodeStrongNamePublicKey(key, hashAlgorithm) {
  const hashName = getStrongNameHashName(hashAlgorithm);
  const jwk = getRsaJwk(key);
  const modulus = getRsaModulus(key, jwk);
  const exponent = getRsaExponent(jwk);
  const modulusBits = key.asymmetricKeyDetails.modulusLength;
  if (modulusBits % 8 !== 0) {
    throw new UnsupportedFormatError("Strong-name RSA modulus length must be byte-aligned");
  }

  const capiKey = Buffer.alloc(20 + modulus.length);
  capiKey[0] = 0x06;
  capiKey[1] = 0x02;
  capiKey.writeUInt32LE(rsaSignAlgorithm, 4);
  capiKey.writeUInt32LE(0x31415352, 8);
  capiKey.writeUInt32LE(modulusBits, 12);
  capiKey.writeUInt32LE(exponent, 16);
  Buffer.from(modulus).reverse().copy(capiKey, 20);

  const hashAlgorithmId = [...hashNames].find(([, name]) => name === hashName)?.[0];
  const publicKey = Buffer.alloc(12 + capiKey.length);
  publicKey.writeUInt32LE(rsaSignAlgorithm, 0);
  publicKey.writeUInt32LE(hashAlgorithmId, 4);
  publicKey.writeUInt32LE(capiKey.length, 8);
  capiKey.copy(publicKey, 12);
  return publicKey;
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
  const modulus = Buffer.from(bytes.subarray(32)).reverse();
  if ((modulus[0] & 0x80) === 0) {
    throw new FormatError("Strong-name RSA modulus does not match its declared bit length");
  }
  const exponentBytes = Buffer.alloc(4);
  exponentBytes.writeUInt32BE(exponent);
  let exponentStart = 0;
  while (exponentStart < exponentBytes.length - 1 && exponentBytes[exponentStart] === 0) exponentStart++;
  const jwk = {
    kty: "RSA",
    n: modulus.toString("base64url"),
    e: exponentBytes.subarray(exponentStart).toString("base64url")
  };
  const publicKey = createPublicKey({ key: jwk, format: "jwk" });
  return {
    publicKey,
    hashAlgorithm,
    signatureSize: modulusBits / 8
  };
}

function getStrongNameRanges(bytes, pe, cli) {
  const fixedOptionalHeaderSize = pe.optionalHeaderMagic === 0x10b ? 96 : 112;
  if (pe.optionalHeaderSize !== fixedOptionalHeaderSize + 16 * 8 ||
      pe.directories.length !== 16) {
    throw new UnsupportedFormatError(
      "Strong-name signing requires the standard PE optional header with 16 data directories"
    );
  }
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
  signer.update(bytes.subarray(0, pe.peOffset));
  signer.update(bytes.subarray(pe.peOffset, pe.peOffset + 24));

  const optionalHeader = Buffer.from(bytes.subarray(
    pe.optionalHeaderOffset,
    pe.optionalHeaderOffset + ranges.fixedOptionalHeaderSize
  ));
  optionalHeader.fill(0, 64, 68);
  signer.update(optionalHeader);

  const directoriesOffset = pe.optionalHeaderOffset + ranges.fixedOptionalHeaderSize;
  const directories = Buffer.from(bytes.subarray(directoriesOffset, directoriesOffset + 16 * 8));
  directories.fill(0, 4 * 8, 5 * 8);
  signer.update(directories);
  signer.update(bytes.subarray(pe.sectionOffset, pe.sectionOffset + pe.sectionCount * 40));

  for (const section of pe.sections) {
    const start = section.rawPointer;
    const end = start + section.rawSize;
    const beforeEnd = Math.min(end, ranges.signatureOffset);
    if (start < beforeEnd) signer.update(bytes.subarray(start, beforeEnd));
    const afterStart = Math.max(start, ranges.signatureEnd);
    if (afterStart < end) signer.update(bytes.subarray(afterStart, end));
  }
}

export function signStrongNameImage(bytes, pe, cli, privateKey, hashAlgorithm) {
  const hashName = getStrongNameHashName(hashAlgorithm);
  const output = Uint8Array.from(bytes);
  const ranges = getStrongNameRanges(output, pe, cli);
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  view.setUint32(cli.strongNameFlagOffset, cli.flags | 0x08, true);

  const signer = createSign(hashName);
  updateStrongNameData(signer, output, pe, ranges);
  const signature = Buffer.from(signer.sign(privateKey)).reverse();
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
  const signature = Buffer.from(bytes.subarray(ranges.signatureOffset, ranges.signatureEnd)).reverse();
  const verifier = createVerify(hashName);
  updateStrongNameData(verifier, bytes, pe, ranges);
  return verifier.verify(key.publicKey, signature);
}
