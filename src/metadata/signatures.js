import { FormatError } from "../binary/errors.js";
import { BinaryReader, readCompressedInt, readCompressedUInt } from "../binary/reader.js";
import { appendCompressedInt, appendCompressedUInt } from "./writer.js";
import { decodeCodedIndex, encodeCodedIndex } from "./tables.js";

const primitiveTypes = new Set([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
  0x16, 0x18, 0x19, 0x1c
]);
const methodCallingConventions = new Set([0, 1, 2, 3, 4, 5, 9, 11]);
const maxNestingDepth = 100;

function fail(reader, message) {
  throw new FormatError(message, { offset: reader.absoluteOffset, context: "metadata signature" });
}

function readCount(reader, label) {
  const count = readCompressedUInt(reader);
  if (count > reader.remaining) fail(reader, `${label} exceeds the remaining signature data`);
  return count;
}

function readTypeDefOrRef(reader, counts) {
  const raw = readCompressedUInt(reader);
  const target = decodeCodedIndex(raw, "TypeDefOrRef");
  if (!target) fail(reader, "Signature type reference cannot be nil");
  if (counts && target.rid > counts[target.table]) {
    fail(reader, `Signature references missing ${target.tableName} row ${target.rid}`);
  }
  return target;
}

function readType(reader, depth, { allowVoid = false, allowPinned = false, counts } = {}) {
  if (depth > maxNestingDepth) fail(reader, "Signature type nesting limit exceeded");
  const modifiers = [];
  while (reader.remaining > 0 && (reader.bytes[reader.position] === 0x1f || reader.bytes[reader.position] === 0x20)) {
    const required = reader.u1() === 0x1f;
    modifiers.push({ required, type: readTypeDefOrRef(reader, counts) });
  }
  if (reader.remaining > 0 && reader.bytes[reader.position] === 0x45) {
    if (!allowPinned) fail(reader, "PINNED is only valid in a local-variable signature");
    reader.u1();
    const pinned = { kind: "pinned", type: readType(reader, depth + 1, { counts }) };
    return modifiers.length === 0 ? pinned : { kind: "modified", modifiers, type: pinned };
  }

  const elementType = reader.u1();
  let type;
  if (primitiveTypes.has(elementType)) {
    if (elementType === 0x01 && !allowVoid) fail(reader, "VOID is not valid in this signature position");
    type = { kind: "primitive", elementType };
  } else if (elementType === 0x0f || elementType === 0x10 || elementType === 0x1d) {
    const kind = elementType === 0x0f ? "pointer" : elementType === 0x10 ? "byRef" : "szArray";
    type = {
      kind,
      type: readType(reader, depth + 1, { allowVoid: elementType === 0x0f, counts })
    };
  } else if (elementType === 0x11 || elementType === 0x12) {
    type = {
      kind: elementType === 0x11 ? "valueType" : "class",
      type: readTypeDefOrRef(reader, counts)
    };
  } else if (elementType === 0x13 || elementType === 0x1e) {
    type = {
      kind: elementType === 0x13 ? "typeParameter" : "methodParameter",
      index: readCompressedUInt(reader)
    };
  } else if (elementType === 0x14) {
    const arrayType = readType(reader, depth + 1, { counts });
    const rank = readCompressedUInt(reader);
    if (rank === 0) fail(reader, "Array signature rank must be greater than zero");
    const sizeCount = readCount(reader, "Array size count");
    if (sizeCount > rank) fail(reader, "Array size count exceeds its rank");
    const sizes = Array.from({ length: sizeCount }, () => readCompressedUInt(reader));
    const lowerBoundCount = readCount(reader, "Array lower-bound count");
    if (lowerBoundCount > rank) fail(reader, "Array lower-bound count exceeds its rank");
    const lowerBounds = Array.from({ length: lowerBoundCount }, () => readCompressedInt(reader));
    type = { kind: "array", type: arrayType, rank, sizes, lowerBounds };
  } else if (elementType === 0x15) {
    const category = reader.u1();
    if (category !== 0x11 && category !== 0x12) {
      fail(reader, "GENERICINST must be followed by CLASS or VALUETYPE");
    }
    const genericType = readTypeDefOrRef(reader, counts);
    const argumentCount = readCount(reader, "Generic argument count");
    if (argumentCount === 0) fail(reader, "GENERICINST must contain at least one argument");
    const argumentsList = Array.from({ length: argumentCount }, () => readType(reader, depth + 1, { counts }));
    type = {
      kind: "genericInstance",
      valueType: category === 0x11,
      genericType,
      arguments: argumentsList
    };
  } else if (elementType === 0x1b) {
    type = { kind: "functionPointer", signature: readMethodSignature(reader, depth + 1, undefined, counts) };
  } else if (elementType === 0x41) {
    fail(reader, "SENTINEL is only valid between method parameters");
  } else {
    fail(reader, `Unsupported signature element type 0x${elementType.toString(16)}`);
  }
  return modifiers.length === 0 ? type : { kind: "modified", modifiers, type };
}

function readMethodSignature(reader, depth, header = reader.u1(), counts) {
  if (depth > maxNestingDepth) fail(reader, "Signature nesting limit exceeded");
  if ((header & 0x80) !== 0) fail(reader, "Reserved method-signature calling-convention bit is set");
  const callingConvention = header & 0x0f;
  if (!methodCallingConventions.has(callingConvention)) {
    fail(reader, `Unsupported method calling convention ${callingConvention}`);
  }
  const generic = (header & 0x10) !== 0;
  const hasThis = (header & 0x20) !== 0;
  const explicitThis = (header & 0x40) !== 0;
  if (explicitThis && !hasThis) fail(reader, "EXPLICITTHIS requires HASTHIS");
  const genericParameterCount = generic ? readCompressedUInt(reader) : 0;
  if (generic && genericParameterCount === 0) {
    fail(reader, "Generic method signature must declare at least one type parameter");
  }
  const parameterCount = readCount(reader, "Method parameter count");
  const returnType = readType(reader, depth + 1, { allowVoid: true, counts });
  const parameters = [];
  let sentinelIndex = null;
  for (let index = 0; index < parameterCount; index++) {
    if (reader.remaining > 0 && reader.bytes[reader.position] === 0x41) {
      if (sentinelIndex !== null || (callingConvention !== 5 && callingConvention !== 11)) {
        fail(reader, "SENTINEL is invalid for this method signature");
      }
      reader.u1();
      sentinelIndex = index;
    }
    parameters.push(readType(reader, depth + 1, { counts }));
  }
  if (reader.remaining > 0 && reader.bytes[reader.position] === 0x41) {
    if (sentinelIndex !== null || (callingConvention !== 5 && callingConvention !== 11)) {
      fail(reader, "SENTINEL is invalid for this method signature");
    }
    fail(reader, "SENTINEL must precede an optional method parameter");
  }
  return {
    kind: "method",
    callingConvention,
    generic,
    hasThis,
    explicitThis,
    genericParameterCount,
    returnType,
    parameters,
    sentinelIndex
  };
}

function writeTypeDefOrRef(type) {
  return appendCompressedUInt(encodeCodedIndex(type.table, type.rid, "TypeDefOrRef"));
}

function writeType(output, type, depth = 0) {
  if (depth > maxNestingDepth) throw new RangeError("Signature type nesting limit exceeded");
  if (type.kind === "modified") {
    for (const modifier of type.modifiers) {
      output.push(modifier.required ? 0x1f : 0x20, ...writeTypeDefOrRef(modifier.type));
    }
    writeType(output, type.type, depth + 1);
    return;
  }
  if (type.kind === "pinned") {
    output.push(0x45);
    writeType(output, type.type, depth + 1);
    return;
  }
  if (type.kind === "primitive") {
    output.push(type.elementType);
  } else if (type.kind === "pointer" || type.kind === "byRef" || type.kind === "szArray") {
    output.push(type.kind === "pointer" ? 0x0f : type.kind === "byRef" ? 0x10 : 0x1d);
    writeType(output, type.type, depth + 1);
  } else if (type.kind === "class" || type.kind === "valueType") {
    output.push(type.kind === "class" ? 0x12 : 0x11, ...writeTypeDefOrRef(type.type));
  } else if (type.kind === "typeParameter" || type.kind === "methodParameter") {
    output.push(type.kind === "typeParameter" ? 0x13 : 0x1e, ...appendCompressedUInt(type.index));
  } else if (type.kind === "array") {
    if (!Number.isInteger(type.rank) || type.rank <= 0) {
      throw new RangeError("Array signature rank must be a positive integer");
    }
    if (!Array.isArray(type.sizes) || !Array.isArray(type.lowerBounds) ||
        type.sizes.length > type.rank || type.lowerBounds.length > type.rank) {
      throw new RangeError("Array signature size and lower-bound counts cannot exceed its rank");
    }
    output.push(0x14);
    writeType(output, type.type, depth + 1);
    output.push(...appendCompressedUInt(type.rank), ...appendCompressedUInt(type.sizes.length));
    for (const size of type.sizes) output.push(...appendCompressedUInt(size));
    output.push(...appendCompressedUInt(type.lowerBounds.length));
    for (const bound of type.lowerBounds) output.push(...appendCompressedInt(bound));
  } else if (type.kind === "genericInstance") {
    if (!Array.isArray(type.arguments) || type.arguments.length === 0) {
      throw new RangeError("Generic instances must contain at least one type argument");
    }
    output.push(0x15, type.valueType ? 0x11 : 0x12, ...writeTypeDefOrRef(type.genericType));
    output.push(...appendCompressedUInt(type.arguments.length));
    for (const argument of type.arguments) writeType(output, argument, depth + 1);
  } else if (type.kind === "functionPointer") {
    output.push(0x1b);
    writeMethodSignature(output, type.signature, depth + 1);
  } else {
    throw new TypeError(`Unsupported signature type kind ${type.kind}`);
  }
}

function writeMethodSignature(output, signature, depth = 0) {
  if (depth > maxNestingDepth) throw new RangeError("Signature nesting limit exceeded");
  const generic = signature.generic ?? signature.genericParameterCount > 0;
  const genericParameterCount = signature.genericParameterCount ?? 0;
  if (!methodCallingConventions.has(signature.callingConvention)) {
    throw new RangeError(`Unsupported method calling convention ${signature.callingConvention}`);
  }
  if (signature.explicitThis && !signature.hasThis) {
    throw new RangeError("EXPLICITTHIS requires HASTHIS");
  }
  if (!Number.isInteger(genericParameterCount) || genericParameterCount < 0) {
    throw new RangeError("Generic method parameter count must be a nonnegative integer");
  }
  if (generic && genericParameterCount === 0) {
    throw new RangeError("Generic method signatures require at least one type parameter");
  }
  if (!generic && genericParameterCount !== 0) {
    throw new RangeError("Generic method flag and generic parameter count are inconsistent");
  }
  if (signature.sentinelIndex !== undefined && signature.sentinelIndex !== null &&
      ((signature.callingConvention !== 5 && signature.callingConvention !== 11) ||
       !Number.isInteger(signature.sentinelIndex) ||
       signature.sentinelIndex < 0 ||
       signature.sentinelIndex >= signature.parameters.length)) {
    throw new RangeError("SENTINEL must precede an optional parameter in a vararg signature");
  }
  output.push(
    signature.callingConvention |
    (generic ? 0x10 : 0) |
    (signature.hasThis ? 0x20 : 0) |
    (signature.explicitThis ? 0x40 : 0)
  );
  if (generic) output.push(...appendCompressedUInt(genericParameterCount));
  output.push(...appendCompressedUInt(signature.parameters.length));
  writeType(output, signature.returnType, depth + 1);
  signature.parameters.forEach((parameter, index) => {
    if (signature.sentinelIndex === index) output.push(0x41);
    writeType(output, parameter, depth + 1);
  });
  if (signature.sentinelIndex === signature.parameters.length) output.push(0x41);
}

export function parseSignature(input, { counts } = {}) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const reader = new BinaryReader(bytes, { context: "metadata signature" });
  const header = reader.u1();
  let signature;
  if (header === 0x06) {
    signature = { kind: "field", type: readType(reader, 0, { counts }) };
  } else if (header === 0x07) {
    const count = readCount(reader, "Local-variable count");
    signature = {
      kind: "locals",
      locals: Array.from({ length: count }, () => readType(reader, 0, { allowPinned: true, counts }))
    };
  } else if ((header & 0x0f) === 0x08) {
    if ((header & 0x90) !== 0) fail(reader, "Invalid property-signature flags");
    const hasThis = (header & 0x20) !== 0;
    const explicitThis = (header & 0x40) !== 0;
    if (explicitThis && !hasThis) fail(reader, "EXPLICITTHIS requires HASTHIS");
    const parameterCount = readCount(reader, "Property parameter count");
    const returnType = readType(reader, 0, { allowVoid: true, counts });
    signature = {
      kind: "property",
      hasThis,
      explicitThis,
      returnType,
      parameters: Array.from({ length: parameterCount }, () => readType(reader, 0, { counts }))
    };
  } else if (header === 0x0a) {
    const count = readCount(reader, "Method-instantiation argument count");
    if (count === 0) fail(reader, "Method instantiation must contain at least one argument");
    signature = {
      kind: "methodInstantiation",
      arguments: Array.from({ length: count }, () => readType(reader, 0, { counts }))
    };
  } else {
    signature = readMethodSignature(reader, 0, header, counts);
  }
  if (reader.remaining !== 0) fail(reader, "Trailing bytes after metadata signature");
  return signature;
}

export function parseTypeSignature(input, { counts } = {}) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const reader = new BinaryReader(bytes, { context: "metadata type signature" });
  const signature = readType(reader, 0, { counts });
  if (reader.remaining !== 0) fail(reader, "Trailing bytes after metadata type signature");
  return signature;
}

export function encodeSignature(signature) {
  const output = [];
  if (signature.kind === "field") {
    output.push(0x06);
    writeType(output, signature.type);
  } else if (signature.kind === "locals") {
    output.push(0x07, ...appendCompressedUInt(signature.locals.length));
    for (const local of signature.locals) writeType(output, local);
  } else if (signature.kind === "property") {
    output.push(0x08 | (signature.hasThis ? 0x20 : 0) | (signature.explicitThis ? 0x40 : 0));
    output.push(...appendCompressedUInt(signature.parameters.length));
    writeType(output, signature.returnType);
    for (const parameter of signature.parameters) writeType(output, parameter);
  } else if (signature.kind === "methodInstantiation") {
    output.push(0x0a, ...appendCompressedUInt(signature.arguments.length));
    for (const argument of signature.arguments) writeType(output, argument);
  } else if (signature.kind === "method") {
    writeMethodSignature(output, signature);
  } else {
    throw new TypeError(`Unsupported metadata signature kind ${signature.kind}`);
  }
  return Uint8Array.from(output);
}

export function encodeTypeSignature(signature) {
  const output = [];
  writeType(output, signature);
  return Uint8Array.from(output);
}

export function remapTypeReferences(signature, remapRid, tableId = 1) {
  function remap(value) {
    if (Array.isArray(value)) return value.map(remap);
    if (!value || typeof value !== "object") return value;
    if (value.table === tableId && Number.isInteger(value.rid)) {
      return { ...value, rid: remapRid(value.rid) };
    }
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, remap(child)]));
  }
  return remap(signature);
}
