import { FormatError, UnsupportedFormatError } from "../binary/errors.js";
import { BinaryReader, readCompressedUInt } from "../binary/reader.js";
import { appendCompressedUInt } from "./writer.js";

const primitiveTypes = new Set([0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d]);
const enumTypes = new Set([0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]);
const maxValueDepth = 32;

function readSerString(reader) {
  if (reader.remaining === 0) throw new FormatError("Custom-attribute SerString is truncated");
  if (reader.bytes[reader.position] === 0xff) {
    reader.u1();
    return null;
  }
  const length = readCompressedUInt(reader);
  const bytes = reader.take(length);
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch (error) {
    throw new FormatError(`Invalid custom-attribute SerString: ${error.message}`);
  }
}

function encodeUtf8(value, context) {
  if (typeof value !== "string") throw new TypeError(`${context} must be a string`);
  const bytes = new TextEncoder().encode(value);
  if (new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) !== value) {
    throw new TypeError(`${context} must contain valid Unicode`);
  }
  return bytes;
}

function writeSerString(output, value) {
  if (value === null) {
    output.push(0xff);
    return;
  }
  const bytes = encodeUtf8(value, "Custom-attribute SerString values");
  for (const byte of appendCompressedUInt(bytes.length)) output.push(byte);
  for (const byte of bytes) output.push(byte);
}

function readFieldOrPropertyType(reader, resolveEnum, depth = 0) {
  if (depth > maxValueDepth) throw new FormatError("Custom-attribute type nesting exceeds supported depth");
  const code = reader.u1();
  if (primitiveTypes.has(code)) return { kind: "primitive", elementType: code };
  if (code === 0x0e) return { kind: "string" };
  if (code === 0x50) return { kind: "type" };
  if (code === 0x51) return { kind: "object" };
  if (code === 0x1d) {
    return { kind: "array", elementType: readFieldOrPropertyType(reader, resolveEnum, depth + 1) };
  }
  if (code === 0x55) {
    const name = readSerString(reader);
    if (name === null) throw new FormatError("Custom-attribute enum type name cannot be null");
    const elementType = resolveEnum(name);
    if (!enumTypes.has(elementType)) {
      throw new UnsupportedFormatError(`Unsupported custom-attribute enum underlying type for ${name}`);
    }
    return { kind: "enum", name, elementType };
  }
  throw new UnsupportedFormatError(`Unsupported custom-attribute field/property type 0x${code.toString(16)}`);
}

function readPrimitive(reader, elementType) {
  if (elementType === 0x02) {
    const value = reader.u1();
    if (value > 1) throw new FormatError("Custom-attribute Boolean must be encoded as zero or one");
    return value !== 0;
  }
  if (elementType === 0x03) return reader.u2();
  if (elementType === 0x04) return reader.i1();
  if (elementType === 0x05) return reader.u1();
  if (elementType === 0x06) return reader.i2();
  if (elementType === 0x07) return reader.u2();
  if (elementType === 0x08) return reader.i4();
  if (elementType === 0x09) return reader.u4();
  if (elementType === 0x0a) {
    reader.ensure(8);
    const value = reader.view.getBigInt64(reader.position, true);
    reader.position += 8;
    return value;
  }
  if (elementType === 0x0b) return reader.u8();
  if (elementType === 0x0c) return reader.f4();
  if (elementType === 0x0d) return reader.f8();
  throw new UnsupportedFormatError(`Unsupported custom-attribute primitive 0x${elementType.toString(16)}`);
}

function writePrimitive(output, elementType, value) {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  if (elementType === 0x02) {
    if (typeof value !== "boolean") throw new TypeError("Custom-attribute Boolean values must be booleans");
    output.push(value ? 1 : 0);
    return;
  }
  if (elementType === 0x03 || elementType === 0x07) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new RangeError("Custom-attribute value is outside u2 range");
    view.setUint16(0, value, true); output.push(view.getUint8(0), view.getUint8(1)); return;
  }
  if (elementType === 0x04) {
    if (!Number.isInteger(value) || value < -0x80 || value > 0x7f) throw new RangeError("Custom-attribute value is outside i1 range");
    view.setInt8(0, value); output.push(view.getUint8(0)); return;
  }
  if (elementType === 0x05) {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new RangeError("Custom-attribute value is outside u1 range");
    output.push(value); return;
  }
  if (elementType === 0x06 || elementType === 0x08 || elementType === 0x0a) {
    if (typeof value !== "number" && typeof value !== "bigint") {
      throw new TypeError("Custom-attribute integer values must be numbers or bigints");
    }
    const big = typeof value === "bigint" ? value : BigInt(value);
    if (elementType === 0x06) {
      if (big < -0x8000n || big > 0x7fffn) throw new RangeError("Custom-attribute value is outside i2 range");
      view.setInt16(0, Number(big), true); output.push(view.getUint8(0), view.getUint8(1)); return;
    }
    if (elementType === 0x08) {
      if (big < -0x80000000n || big > 0x7fffffffn) throw new RangeError("Custom-attribute value is outside i4 range");
      view.setInt32(0, Number(big), true); output.push(...new Uint8Array(buffer, 0, 4)); return;
    }
    if (big < -0x8000000000000000n || big > 0x7fffffffffffffffn) {
      throw new RangeError("Custom-attribute value is outside i8 range");
    }
    view.setBigInt64(0, big, true); output.push(...new Uint8Array(buffer)); return;
  }
  if (elementType === 0x09 || elementType === 0x0b) {
    if (typeof value !== "number" && typeof value !== "bigint") {
      throw new TypeError("Custom-attribute integer values must be numbers or bigints");
    }
    const big = typeof value === "bigint" ? value : BigInt(value);
    const max = elementType === 0x09 ? 0xffffffffn : 0xffffffffffffffffn;
    if (big < 0n || big > max) throw new RangeError("Custom-attribute value is outside unsigned range");
    view.setBigUint64(0, big, true);
    output.push(...new Uint8Array(buffer, 0, elementType === 0x09 ? 4 : 8));
    return;
  }
  if (elementType === 0x0c || elementType === 0x0d) {
    if (typeof value !== "number") throw new TypeError("Custom-attribute floating-point values must be numbers");
    if (elementType === 0x0c) {
      view.setFloat32(0, value, true); output.push(...new Uint8Array(buffer, 0, 4)); return;
    }
    view.setFloat64(0, value, true); output.push(...new Uint8Array(buffer)); return;
  }
  throw new UnsupportedFormatError(`Unsupported custom-attribute primitive 0x${elementType.toString(16)}`);
}

function readValue(reader, type, resolveEnum, depth = 0) {
  if (depth > maxValueDepth) throw new FormatError("Custom-attribute value nesting exceeds supported depth");
  if (type.kind === "primitive") return readPrimitive(reader, type.elementType);
  if (type.kind === "enum") return readPrimitive(reader, type.elementType);
  if (type.kind === "string" || type.kind === "type") return readSerString(reader);
  if (type.kind === "object") {
    if (reader.bytes[reader.position] === 0xff) return readSerString(reader);
    const boxedType = readFieldOrPropertyType(reader, resolveEnum, depth + 1);
    return { type: boxedType, value: readValue(reader, boxedType, resolveEnum, depth + 1) };
  }
  if (type.kind === "array") {
    const count = reader.u4();
    if (count === 0xffffffff) return null;
    if (count > reader.remaining) throw new FormatError("Custom-attribute array count exceeds remaining blob data");
    return Array.from({ length: count }, () => readValue(reader, type.elementType, resolveEnum, depth + 1));
  }
  throw new UnsupportedFormatError(`Unsupported custom-attribute value kind ${type.kind}`);
}

function writeValue(output, type, value, depth = 0) {
  if (depth > maxValueDepth) throw new RangeError("Custom-attribute value nesting exceeds supported depth");
  if (type.kind === "enum") {
    if (!enumTypes.has(type.elementType)) {
      throw new UnsupportedFormatError("Unsupported custom-attribute enum underlying type");
    }
    writePrimitive(output, type.elementType, value);
    return;
  }
  if (type.kind === "primitive") {
    writePrimitive(output, type.elementType, value);
    return;
  }
  if (type.kind === "string" || type.kind === "type") {
    writeSerString(output, value);
    return;
  }
  if (type.kind === "object") {
    if (value === null) {
      output.push(0xff);
      return;
    }
    if (!value || typeof value !== "object" || !value.type) {
      throw new TypeError("Boxed custom-attribute values require { type, value }");
    }
    writeFieldOrPropertyType(output, value.type, depth + 1);
    writeValue(output, value.type, value.value, depth + 1);
    return;
  }
  if (type.kind === "array") {
    if (value === null) {
      output.push(0xff, 0xff, 0xff, 0xff);
      return;
    }
    if (!Array.isArray(value)) throw new TypeError("Custom-attribute array values must be arrays or null");
    if (value.length > 0xffffffff) throw new RangeError("Custom-attribute array exceeds 32-bit length");
    const buffer = new ArrayBuffer(4);
    new DataView(buffer).setUint32(0, value.length, true);
    output.push(...new Uint8Array(buffer));
    for (const item of value) writeValue(output, type.elementType, item, depth + 1);
    return;
  }
  throw new UnsupportedFormatError(`Unsupported custom-attribute value kind ${type.kind}`);
}

function writeFieldOrPropertyType(output, type, depth = 0) {
  if (depth > maxValueDepth) throw new RangeError("Custom-attribute type nesting exceeds supported depth");
  if (type.kind === "primitive") {
    if (!primitiveTypes.has(type.elementType)) {
      throw new UnsupportedFormatError("Unsupported custom-attribute primitive type");
    }
    output.push(type.elementType);
  } else if (type.kind === "string") output.push(0x0e);
  else if (type.kind === "type") output.push(0x50);
  else if (type.kind === "object") output.push(0x51);
  else if (type.kind === "array") {
    output.push(0x1d);
    writeFieldOrPropertyType(output, type.elementType, depth + 1);
  } else if (type.kind === "enum") {
    if (!enumTypes.has(type.elementType)) {
      throw new UnsupportedFormatError("Unsupported custom-attribute enum underlying type");
    }
    if (typeof type.name !== "string") {
      throw new TypeError("Custom-attribute enum types require a name");
    }
    output.push(0x55);
    writeSerString(output, type.name);
  } else {
    throw new UnsupportedFormatError(`Unsupported custom-attribute field/property type ${type.kind}`);
  }
}

function readNamedArguments(reader, resolveEnum) {
  const namedCount = reader.u2();
  const namedArguments = [];
  for (let index = 0; index < namedCount; index++) {
    const kind = reader.u1();
    if (kind !== 0x53 && kind !== 0x54) {
      throw new FormatError("Custom-attribute named argument kind is invalid");
    }
    const type = readFieldOrPropertyType(reader, resolveEnum);
    const name = readSerString(reader);
    if (name === null) throw new FormatError("Custom-attribute named argument name cannot be null");
    namedArguments.push({
      kind: kind === 0x53 ? "field" : "property",
      type,
      name,
      value: readValue(reader, type, resolveEnum)
    });
  }
  return namedArguments;
}

function writeNamedArguments(output, namedArguments) {
  if (!Array.isArray(namedArguments)) {
    throw new TypeError("Custom-attribute namedArguments must be an array");
  }
  if (namedArguments.length > 0xffff) throw new RangeError("Too many custom-attribute named arguments");
  output.push(namedArguments.length & 0xff, namedArguments.length >>> 8);
  for (const argument of namedArguments) {
    if (!argument || typeof argument !== "object") {
      throw new TypeError("Custom-attribute named arguments must be objects");
    }
    const kind = argument.kind === "field" ? 0x53 : argument.kind === "property" ? 0x54 : 0;
    if (kind === 0) throw new TypeError("Custom-attribute named argument kind must be field or property");
    if (typeof argument.name !== "string") {
      throw new TypeError("Custom-attribute named arguments require a name");
    }
    output.push(kind);
    writeFieldOrPropertyType(output, argument.type);
    writeSerString(output, argument.name);
    writeValue(output, argument.type, argument.value);
  }
}

export function parseCustomAttribute(bytes, fixedTypes, resolveEnum = () => {
  throw new UnsupportedFormatError("Custom-attribute enum type is not resolvable");
}) {
  const reader = new BinaryReader(bytes, { context: "custom attribute" });
  if (reader.u2() !== 1) throw new FormatError("Custom-attribute prolog is invalid");
  const fixedArguments = fixedTypes.map((type) => readValue(reader, type, resolveEnum));
  const namedArguments = readNamedArguments(reader, resolveEnum);
  if (reader.remaining !== 0) throw new FormatError("Trailing bytes after custom-attribute value");
  return { fixedArguments, namedArguments };
}

export function parsePermissionSet(bytes, resolveEnum = () => {
  throw new UnsupportedFormatError("PermissionSet enum type is not resolvable");
}) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("PermissionSet data must be a Uint8Array");
  }
  if (bytes[0] !== 0x2e) {
    let xml;
    try {
      xml = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (error) {
      throw new UnsupportedFormatError(`XML PermissionSet encoding is unsupported: ${error.message}`);
    }
    if (xml.charCodeAt(0) === 0xfeff) xml = xml.slice(1);
    const trimmedXml = xml.trim();
    if (xml.includes("\0") || !trimmedXml.startsWith("<") || !trimmedXml.endsWith(">")) {
      throw new FormatError("XML PermissionSet payload is not UTF-8 XML text");
    }
    return { format: "xml", xml };
  }
  const reader = new BinaryReader(bytes, { context: "PermissionSet" });
  reader.u1();
  const attributeCount = readCompressedUInt(reader);
  if (attributeCount > Math.floor(reader.remaining / 2)) {
    throw new FormatError("PermissionSet attribute count exceeds remaining blob data");
  }
  const attributes = [];
  for (let index = 0; index < attributeCount; index++) {
    const typeName = readSerString(reader);
    if (typeName === null) throw new FormatError("PermissionSet attribute type name cannot be null");
    const attributeBlob = reader.take(readCompressedUInt(reader));
    const attributeReader = new BinaryReader(attributeBlob, { context: "PermissionSet attribute" });
    const namedArguments = readNamedArguments(attributeReader, resolveEnum);
    if (attributeReader.remaining !== 0) {
      throw new FormatError("Trailing bytes after PermissionSet attribute data");
    }
    attributes.push({ typeName, namedArguments });
  }
  if (reader.remaining !== 0) throw new FormatError("Trailing bytes after PermissionSet blob");
  return { format: "binary", attributes };
}

export function encodePermissionSet(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("PermissionSet value must be an object");
  }
  if (value.format === "xml") {
    const bytes = encodeUtf8(value.xml, "XML PermissionSet");
    const xml = value.xml.trim();
    if (value.xml.includes("\0") || !xml.startsWith("<") || !xml.endsWith(">")) {
      throw new FormatError("XML PermissionSet payload is not UTF-8 XML text");
    }
    return bytes;
  }
  if (value.format !== "binary" || !Array.isArray(value.attributes)) {
    throw new TypeError("Binary PermissionSet values require an attributes array");
  }
  const output = [0x2e, ...appendCompressedUInt(value.attributes.length)];
  for (const attribute of value.attributes) {
    if (!attribute || typeof attribute !== "object" || typeof attribute.typeName !== "string") {
      throw new TypeError("PermissionSet attributes require a typeName");
    }
    const attributeData = [];
    writeNamedArguments(attributeData, attribute.namedArguments);
    writeSerString(output, attribute.typeName);
    for (const byte of appendCompressedUInt(attributeData.length)) output.push(byte);
    for (const byte of attributeData) output.push(byte);
  }
  return Uint8Array.from(output);
}

export function encodeCustomAttribute(value, fixedTypes) {
  if (!value || !Array.isArray(value.fixedArguments) || !Array.isArray(value.namedArguments)) {
    throw new TypeError("Custom-attribute value requires fixedArguments and namedArguments arrays");
  }
  if (value.fixedArguments.length !== fixedTypes.length) {
    throw new RangeError("Custom-attribute fixed-argument count does not match its constructor");
  }
  if (value.namedArguments.length > 0xffff) throw new RangeError("Too many custom-attribute named arguments");
  const output = [1, 0];
  for (let index = 0; index < fixedTypes.length; index++) {
    writeValue(output, fixedTypes[index], value.fixedArguments[index]);
  }
  writeNamedArguments(output, value.namedArguments);
  return Uint8Array.from(output);
}
