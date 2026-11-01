import { createHash } from "node:crypto";
import { FormatError, UnsupportedFormatError } from "./binary/errors.js";
import {
  parseEmbeddedPortablePdbData,
  parsePE,
  parseCliHeader
} from "./pe/headers.js";
import { parseMetadataRoot, MetadataHeaps } from "./metadata/streams.js";
import { parseTablesStream } from "./metadata/tables.js";
import {
  parseClassicPdb as parseClassicPdbFile,
  replaceClassicPdbFileChecksum as replaceClassicPdbFileChecksumFile,
  replaceClassicPdbLineInfo as replaceClassicPdbLineInfoFile,
  replaceClassicPdbModuleNames as replaceClassicPdbModuleNamesFile,
  replaceClassicPdbStringTableName as replaceClassicPdbStringTableNameFile,
  replaceClassicPdbSymbolName as replaceClassicPdbSymbolNameFile
} from "./metadata/classic-pdb.js";
import { parseMethodBody } from "./il/body.js";
import { encodeInstruction, encodeOpcode, formatInstruction, getInstructionSize } from "./il/instructions.js";
import { listOpcodes } from "./il/opcodes.js";
import {
  createStructuralState,
  insertInstruction as insertStructuralInstruction,
  layoutStructuralState,
  removeInstruction as removeStructuralInstruction,
  updateStructuralOperand
} from "./il/rewrite.js";
import { resolveMethodParameters, resolveTypes } from "./resolution/module.js";
import { applyPatches, createOperandPatches } from "./writer/patch.js";
import { serializeStructural } from "./writer/structural.js";
import { appendBlobHeap, appendStringHeap, appendUserStringHeap } from "./metadata/writer.js";
import { parseManifestResources } from "./metadata/resources.js";
import {
  validatePortablePdbAssemblyReferences,
  validatePortablePdbCodeViewIdentity,
  updateEmbeddedPortablePdbRowCounts,
  insertEmbeddedPortablePdbMethod as insertPortablePdbMethod,
  remapEmbeddedPortablePdbLocalSignatures as remapPortablePdbLocalSignatures,
  remapEmbeddedPortablePdbTypeDefinitions as remapPortablePdbTypeDefinitions,
  removeEmbeddedPortablePdbMethod as removePortablePdbMethod,
  refreshEmbeddedPortablePdbId,
  addEmbeddedPortablePdbSourceLink as addPortablePdbSourceLink,
  addEmbeddedPortablePdbSource as addPortablePdbSource,
  removeEmbeddedPortablePdbSourceLink as removePortablePdbSourceLink,
  removeEmbeddedPortablePdbSource as removePortablePdbSource,
  removeEmbeddedPortablePdbCustomDebugInformation as removePortablePdbCustomDebugInformation,
  replaceEmbeddedPortablePdbMethodOffsets as replacePortablePdbMethodOffsets,
  addEmbeddedPortablePdbDocument as addPortablePdbDocument,
  insertEmbeddedPortablePdbDocument as insertPortablePdbDocument,
  addEmbeddedPortablePdbTypeDefinitionDocuments as addPortablePdbTypeDefinitionDocuments,
  removeEmbeddedPortablePdbDocument as removePortablePdbDocument,
  replaceEmbeddedPortablePdbDocumentMetadata as replacePortablePdbDocumentMetadata,
  replaceEmbeddedPortablePdbTypeDefinitionDocuments as replacePortablePdbTypeDefinitionDocuments,
  replaceEmbeddedPortablePdbDocumentName as replacePortablePdbDocumentName,
  replaceEmbeddedPortablePdbSequencePoints as replacePortablePdbSequencePoints,
  replaceEmbeddedPortablePdbSource as replacePortablePdbSource,
  replaceEmbeddedPortablePdbSourceLink as replacePortablePdbSourceLink
} from "./metadata/portable-pdb.js";
import {
  assertStrongNamePEProfile,
  encodeStrongNamePublicKey,
  getStrongNameHashName,
  importStrongNamePrivateKey,
  signStrongNameImage,
  verifyStrongNameImage
} from "./metadata/strong-name.js";
import {
  encodeCustomAttribute as encodeCustomAttributeBlob,
  encodePermissionSet as encodePermissionSetBlob,
  parseCustomAttribute as parseCustomAttributeBlob,
  parsePermissionSet as parsePermissionSetBlob
} from "./metadata/custom-attributes.js";
import {
  encodeCodedIndex,
  metadataTableId,
  metadataTableNames,
  metadataTableSchemas
} from "./metadata/tables.js";
import {
  encodeSignature,
  encodeTypeSignature,
  parseSignature,
  parseTypeSignature,
  remapTypeReferences
} from "./metadata/signatures.js";
const methodTokenOpcodes = new Set(["jmp", "call", "callvirt", "newobj", "ldftn", "ldvirtftn"]);
const fieldTokenOpcodes = new Set(["ldfld", "ldflda", "stfld", "ldsfld", "ldsflda", "stsfld"]);
const typeTokenOpcodes = new Set([
  "cpobj", "ldobj", "castclass", "isinst", "unbox", "stobj", "box", "newarr", "ldelema",
  "ldelem", "stelem", "unbox.any", "refanyval", "mkrefany", "initobj", "constrained.", "sizeof"
]);
const customAttributeEnumTypes = new Set([0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]);

function formatPortablePdbGuid(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const first = view.getUint32(0, true).toString(16).padStart(8, "0");
  const second = view.getUint16(4, true).toString(16).padStart(4, "0");
  const third = view.getUint16(6, true).toString(16).padStart(4, "0");
  const tail = [...bytes.subarray(8)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${first}-${second}-${third}-${tail.slice(0, 4)}-${tail.slice(4)}`;
}

function readDebugRecord(assembly, entry) {
  const { pe } = assembly;
  const offset = entry.pointerToRawData !== 0
    ? entry.pointerToRawData
    : pe.rvaToOffset(entry.addressOfRawData, entry.sizeOfData);
  const bytes = pe.bytes.slice(offset, offset + entry.sizeOfData);
  for (const patch of assembly._patches) {
    const overlapStart = Math.max(offset, patch.offset);
    const overlapEnd = Math.min(offset + bytes.length, patch.offset + patch.bytes.length);
    if (overlapStart < overlapEnd) {
      bytes.set(
        patch.bytes.subarray(overlapStart - patch.offset, overlapEnd - patch.offset),
        overlapStart - offset
      );
    }
  }
  return bytes;
}

function allowedTokenTables(opcodeName) {
  if (opcodeName === "calli") return [17];
  if (opcodeName === "ldtoken") return [1, 2, 4, 6, 10, 27, 43];
  if (methodTokenOpcodes.has(opcodeName)) return [6, 10, 43];
  if (fieldTokenOpcodes.has(opcodeName)) return [4, 10];
  if (typeTokenOpcodes.has(opcodeName)) return [1, 2, 27];
  return [];
}

function getManagedTypeName(assembly, reference) {
  if (reference?.table === 1) {
    const type = assembly.typeRefs[reference.rid - 1];
    return type ? `${type.namespace ? `${type.namespace}.` : ""}${type.name}` : null;
  }
  if (reference?.table === 2) {
    const type = assembly.types[reference.rid - 1];
    return type ? getManagedTypeDefinitionName(assembly, type) : null;
  }
  if (reference?.table === 27) {
    const typeReference = getManagedTypeDefinitionReference(assembly, reference);
    return typeReference ? getManagedTypeName(assembly, typeReference) : null;
  }
  return null;
}

function getManagedTypeDefinitionReference(assembly, reference, visited = new Set()) {
  if (reference?.table === 2 || reference?.table === 1) return reference;
  if (reference?.table !== 27) return null;
  if (visited.has(reference.rid)) {
    throw new FormatError(`TypeSpec row ${reference.rid} contains a recursive TypeSpec reference`);
  }
  visited.add(reference.rid);
  const signature = assembly.typeSpecs[reference.rid - 1]?.parsedSignature;
  const nested = signature?.kind === "genericInstance"
    ? signature.genericType
    : signature?.kind === "class" || signature?.kind === "valueType"
      ? signature.type
      : null;
  const result = nested
    ? getManagedTypeDefinitionReference(assembly, nested, visited)
    : null;
  visited.delete(reference.rid);
  return result;
}

function validateLocalTypeInheritance(assembly) {
  const states = new Uint8Array(assembly.types.length + 1);
  for (const type of assembly.types) {
    if (states[type.rid] === 2) continue;
    const path = [];
    let current = type;
    while (current && states[current.rid] === 0) {
      states[current.rid] = 1;
      path.push(current.rid);
      const base = getManagedTypeDefinitionReference(assembly, current.extends);
      current = base?.table === 2 ? assembly.types[base.rid - 1] : null;
    }
    if (current && states[current.rid] === 1) {
      throw new FormatError("TypeDef inheritance contains a cycle");
    }
    for (const rid of path) states[rid] = 2;
  }
}

function getManagedTypeDefinitionName(assembly, type, visited = new Set()) {
  if (!type) return null;
  if (visited.has(type.rid)) {
    throw new FormatError("Nested TypeDef relationships contain a cycle");
  }
  visited.add(type.rid);
  const nesting = (assembly.tables.rows.get(41) ?? [])
    .find((row) => row.NestedClass.rid === type.rid);
  if (!nesting) return `${type.namespace ? `${type.namespace}.` : ""}${type.name}`;
  const enclosingType = assembly.types[nesting.EnclosingClass.rid - 1];
  const enclosingName = getManagedTypeDefinitionName(assembly, enclosingType, visited);
  return enclosingName ? `${enclosingName}+${type.name}` : null;
}

function resolveEnumElementType(assembly, name) {
  const fullName = name.split(",", 1)[0].trim();
  const definition = assembly.types.find((type) =>
    getManagedTypeDefinitionName(assembly, type) === fullName
  );
  if (!definition || getManagedTypeName(assembly, definition.extends) !== "System.Enum") {
    throw new UnsupportedFormatError(
      `Custom-attribute enum ${name} is not defined in this assembly or does not derive from System.Enum`
    );
  }
  const underlyingFields = definition.fields.filter((field) => field.name === "value__");
  if (underlyingFields.length !== 1) {
    throw new UnsupportedFormatError(`Custom-attribute enum ${name} is not defined in this assembly`);
  }
  const underlyingField = underlyingFields[0];
  if ((underlyingField.flags & 0x10) !== 0) {
    throw new UnsupportedFormatError(`Custom-attribute enum ${name} has a static underlying field`);
  }
  const signature = parseSignature(underlyingField.signature);
  const elementType = signature.kind === "field" && signature.type?.kind === "primitive"
    ? signature.type.elementType
    : 0;
  if (![0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b].includes(elementType)) {
    throw new UnsupportedFormatError(`Custom-attribute enum ${name} has an unsupported underlying type`);
  }
  return elementType;
}

function validateGenericVariableReferences(
  signature,
  typeArity,
  assembly = null,
  typeSpecOverride = null,
  methodArity = 0
) {
  function visitMethod(method) {
    const currentMethodArity = method.generic ? method.genericParameterCount : methodArity;
    visitType(method.returnType, currentMethodArity);
    for (const parameter of method.parameters) visitType(parameter, currentMethodArity);
  }

  function visitType(type, methodArity) {
    if (type.kind === "typeParameter" && typeArity !== null && type.index >= typeArity) {
      throw new FormatError(`Type generic variable !${type.index} exceeds its declaring type's arity`);
    }
    if (type.kind === "methodParameter" && type.index >= methodArity) {
      throw new FormatError(`Method generic variable !!${type.index} exceeds its method's arity`);
    }
    if (type.kind === "modified") {
      for (const modifier of type.modifiers) {
        if (assembly && modifier.type.table === 27) {
          validateTypeSpecGenericContext(
            assembly, modifier.type.rid, typeArity, methodArity, new Set(), typeSpecOverride
          );
        }
      }
      visitType(type.type, methodArity);
    } else if (["array", "szArray", "pointer", "byRef", "pinned"].includes(type.kind)) {
      visitType(type.type, methodArity);
    } else if (type.kind === "genericInstance") {
      if (assembly && type.genericType.table === 27) {
        validateTypeSpecGenericContext(
          assembly, type.genericType.rid, typeArity, methodArity, new Set(), typeSpecOverride
        );
      }
      for (const argument of type.arguments) visitType(argument, methodArity);
    } else if (type.kind === "class" || type.kind === "valueType") {
      if (assembly && type.type.table === 27) {
        validateTypeSpecGenericContext(
          assembly, type.type.rid, typeArity, methodArity, new Set(), typeSpecOverride
        );
      }
    } else if (type.kind === "functionPointer") {
      visitMethod(type.signature);
    }
  }

  if (signature.kind === "method") {
    visitMethod(signature);
  } else if (signature.kind === "field") {
    visitType(signature.type, typeArity);
  } else if (signature.kind === "property") {
    visitType(signature.returnType, typeArity);
    for (const parameter of signature.parameters) visitType(parameter, typeArity);
  } else if (signature.kind === "methodInstantiation") {
    for (const argument of signature.arguments) visitType(argument, methodArity);
  } else if (signature.kind === "locals") {
    for (const local of signature.locals) visitType(local, methodArity);
  }
}

function getGenericParameterArity(parameters, ownerTable, ownerRid) {
  return parameters.reduce((arity, parameter) =>
    parameter.owner.table === ownerTable && parameter.owner.rid === ownerRid
      ? Math.max(arity, parameter.number + 1)
      : arity, 0
  );
}

function getTypeRefGenericArity(
  assembly,
  rid,
  typeRefOverride = null,
  activeTypeRefs = new Set()
) {
  if (activeTypeRefs.has(rid)) {
    throw new FormatError(`TypeRef row ${rid} has a recursive ResolutionScope reference`);
  }
  const typeRef = typeRefOverride?.rid === rid
    ? typeRefOverride
    : assembly.typeRefs[rid - 1];
  if (!typeRef) throw new FormatError(`Generic instance references missing TypeRef row ${rid}`);
  activeTypeRefs.add(rid);
  try {
    const aritySuffix = /`([0-9]+)$/.exec(typeRef.name);
    if (!aritySuffix) return null;
    let arity = Number(aritySuffix[1]);
    if (!Number.isSafeInteger(arity)) {
      throw new FormatError(`TypeRef row ${rid} has an unsupported generic arity suffix`);
    }
    if (typeRef.resolutionScope?.table === 1) {
      const enclosingArity = getTypeRefGenericArity(
        assembly,
        typeRef.resolutionScope.rid,
        typeRefOverride,
        activeTypeRefs
      );
      if (enclosingArity === null) return null;
      arity += enclosingArity;
      if (!Number.isSafeInteger(arity)) {
        throw new FormatError(`TypeRef row ${rid} has an unsupported generic arity`);
      }
    }
    return arity;
  } finally {
    activeTypeRefs.delete(rid);
  }
}

function validateTypeSpecDefinitions(
  assembly,
  type,
  typeRefOverride = null,
  activeTypeSpecs = new Set(),
  typeSpecOverride = null
) {
  const validateTypeSpecReference = (rid) => {
    const referencedTypeSpec = typeSpecOverride?.rid === rid
      ? typeSpecOverride
      : assembly.typeSpecs[rid - 1];
    if (!referencedTypeSpec) {
      throw new FormatError(`TypeSpec signature references missing TypeSpec row ${rid}`);
    }
    if (activeTypeSpecs.has(rid)) {
      throw new FormatError(`TypeSpec row ${rid} contains a recursive TypeSpec reference`);
    }
    activeTypeSpecs.add(rid);
    try {
      validateTypeSpecDefinitions(
        assembly,
        referencedTypeSpec.parsedSignature,
        typeRefOverride,
        activeTypeSpecs,
        typeSpecOverride
      );
    } finally {
      activeTypeSpecs.delete(rid);
    }
  };
  if (type.kind === "modified") {
    for (const modifier of type.modifiers) {
      if (modifier.type.table === 27) {
        validateTypeSpecReference(modifier.type.rid);
      }
    }
    validateTypeSpecDefinitions(
      assembly,
      type.type,
      typeRefOverride,
      activeTypeSpecs,
      typeSpecOverride
    );
  } else if (type.kind === "genericInstance") {
    if (type.genericType.table === 27) {
      validateTypeSpecReference(type.genericType.rid);
    } else if (type.genericType.table === 2) {
      const expectedArity = getGenericParameterArity(assembly.genericParams, 2, type.genericType.rid);
      if (type.arguments.length !== expectedArity) {
        throw new FormatError(
          `TypeSpec generic instance has ${type.arguments.length} arguments for TypeDef arity ${expectedArity}`
        );
      }
    } else if (type.genericType.table === 1) {
      const expectedArity = getTypeRefGenericArity(
        assembly, type.genericType.rid, typeRefOverride
      );
      if (expectedArity !== null && type.arguments.length !== expectedArity) {
        throw new FormatError(
          `TypeSpec generic instance has ${type.arguments.length} arguments for TypeRef arity ${expectedArity}`
        );
      }
    }
    for (const argument of type.arguments) {
      validateTypeSpecDefinitions(
        assembly,
        argument,
        typeRefOverride,
        activeTypeSpecs,
        typeSpecOverride
      );
    }
  } else if (["array", "szArray", "pointer", "byRef", "pinned"].includes(type.kind)) {
    validateTypeSpecDefinitions(
      assembly,
      type.type,
      typeRefOverride,
      activeTypeSpecs,
      typeSpecOverride
    );
  } else if ((type.kind === "class" || type.kind === "valueType") &&
      type.type.table === 27) {
    validateTypeSpecReference(type.type.rid);
  } else if (type.kind === "functionPointer") {
    validateTypeSpecDefinitions(
      assembly,
      type.signature.returnType,
      typeRefOverride,
      activeTypeSpecs,
      typeSpecOverride
    );
    for (const parameter of type.signature.parameters) {
      validateTypeSpecDefinitions(
        assembly,
        parameter,
        typeRefOverride,
        activeTypeSpecs,
        typeSpecOverride
      );
    }
  }
}

function validateTypeSpecGenericContext(
  assembly,
  rid,
  typeArity,
  methodArity = 0,
  active = new Set(),
  typeSpecOverride = null
) {
  const typeSpec = typeSpecOverride?.rid === rid
    ? typeSpecOverride
    : assembly.typeSpecs[rid - 1];
  if (!typeSpec) throw new FormatError(`Generic context references missing TypeSpec row ${rid}`);
  if (active.has(rid)) throw new FormatError(`TypeSpec row ${rid} contains a recursive TypeSpec reference`);
  active.add(rid);
  const visitMethod = (signature) => {
    const nestedMethodArity = signature.generic ? signature.genericParameterCount : methodArity;
    visitType(signature.returnType, nestedMethodArity);
    for (const parameter of signature.parameters) visitType(parameter, nestedMethodArity);
  };
  const visitType = (type, currentMethodArity = methodArity) => {
    if (type.kind === "typeParameter" && typeArity !== null && type.index >= typeArity) {
      throw new FormatError(`TypeSpec generic variable !${type.index} exceeds its declaring type's arity`);
    }
    if (type.kind === "methodParameter" && type.index >= currentMethodArity) {
      throw new FormatError(`TypeSpec generic variable !!${type.index} exceeds its declaring method's arity`);
    }
    if (type.kind === "modified") {
      for (const modifier of type.modifiers) {
        if (modifier.type.table === 27) {
          validateTypeSpecGenericContext(
            assembly, modifier.type.rid, typeArity, currentMethodArity, active, typeSpecOverride
          );
        }
      }
      visitType(type.type, currentMethodArity);
    } else if (["array", "szArray", "pointer", "byRef", "pinned"].includes(type.kind)) {
      visitType(type.type, currentMethodArity);
    } else if (type.kind === "genericInstance") {
      if (type.genericType.table === 27) {
        validateTypeSpecGenericContext(
          assembly, type.genericType.rid, typeArity, currentMethodArity, active, typeSpecOverride
        );
      }
      for (const argument of type.arguments) visitType(argument, currentMethodArity);
    } else if (type.kind === "class" || type.kind === "valueType") {
      if (type.type.table === 27) {
        validateTypeSpecGenericContext(
          assembly, type.type.rid, typeArity, currentMethodArity, active, typeSpecOverride
        );
      }
    } else if (type.kind === "functionPointer") {
      visitMethod(type.signature);
    }
  };
  try {
    visitType(typeSpec.parsedSignature);
  } finally {
    active.delete(rid);
  }
}

function validateMemberRefGenericContext(
  assembly,
  parent,
  signature,
  typeSpecOverride = null,
  typeRefOverride = null
) {
  const parentTable = metadataTableId(parent?.table);
  if (parentTable === 2) {
    const ownerType = assembly.types[parent.rid - 1];
    if (!ownerType) throw new FormatError(`MemberRef parent references a missing TypeDef row ${parent.rid}`);
    validateGenericVariableReferences(
      signature,
      getGenericParameterArity(assembly.genericParams, 2, ownerType.rid),
      assembly
    );
  } else if (parentTable === 1) {
    const typeRef = typeRefOverride?.rid === parent.rid
      ? typeRefOverride
      : assembly.typeRefs[parent.rid - 1];
    if (!typeRef) throw new FormatError(`MemberRef parent references a missing TypeRef row ${parent.rid}`);
    const typeArity = getTypeRefGenericArity(assembly, parent.rid, typeRefOverride);
    validateGenericVariableReferences(signature, typeArity, assembly, typeSpecOverride);
  } else if (parentTable === 27) {
    const typeSpec = typeSpecOverride?.rid === parent.rid
      ? typeSpecOverride
      : assembly.typeSpecs[parent.rid - 1];
    if (!typeSpec) throw new FormatError(`MemberRef parent references a missing TypeSpec row ${parent.rid}`);
    validateTypeSpecDefinitions(assembly, typeSpec.parsedSignature);
    const signatureType = typeSpec.parsedSignature.kind === "modified"
      ? typeSpec.parsedSignature.type
      : typeSpec.parsedSignature;
    const typeArity = signatureType.kind === "genericInstance"
      ? signatureType.arguments.length
      : 0;
    validateGenericVariableReferences(signature, typeArity, assembly, typeSpecOverride);
  }
}

function getGenericParameterOwnerContext(assembly, parameter) {
  const owner = parameter?.owner;
  if (owner?.table === 2) {
    return {
      typeArity: getGenericParameterArity(assembly.genericParams, 2, owner.rid),
      methodArity: 0
    };
  }
  if (owner?.table === 6) {
    const method = assembly.methods[owner.rid - 1];
    const declaringType = assembly.types.find((type) => type.methodRids.includes(owner.rid));
    const signature = method
      ? parseSignature(method.signature, { counts: assembly.tables.counts })
      : null;
    return {
      typeArity: declaringType
        ? getGenericParameterArity(assembly.genericParams, 2, declaringType.rid)
        : 0,
      methodArity: signature?.kind === "method" && signature.generic
        ? signature.genericParameterCount
        : 0
    };
  }
  return { typeArity: 0, methodArity: 0 };
}

function validateMethodSpecUseAtCallSite(assembly, methodRid, methodSpec, typeSpecOverride = null) {
  const { typeArity, methodArity } = getMethodGenericArities(assembly, methodRid);
  validateGenericVariableReferences(
    methodSpec.parsedInstantiation,
    typeArity,
    assembly,
    typeSpecOverride,
    methodArity
  );
}

function getMethodGenericArities(assembly, methodRid) {
  const method = assembly.methods[methodRid - 1];
  if (!method) throw new FormatError(`CIL call site references missing MethodDef row ${methodRid}`);
  const signature = parseSignature(method.signature, { counts: assembly.tables.counts });
  if (signature.kind !== "method") {
    throw new FormatError(`MethodDef row ${methodRid} has an invalid method signature`);
  }
  const declaringType = assembly.types.find((type) => type.methodRids.includes(methodRid));
  return {
    typeArity: declaringType
      ? getGenericParameterArity(assembly.genericParams, 2, declaringType.rid)
      : 0,
    methodArity: signature.generic ? signature.genericParameterCount : 0
  };
}

function validateStandAloneSigCallSite(assembly, methodRid, signatureRid) {
  const row = assembly.tables.row(17, signatureRid);
  if (!row) throw new FormatError(`CIL references missing StandAloneSig row ${signatureRid}`);
  const signature = parseSignature(assembly.heaps.getBlob(row.Signature), {
    counts: assembly.tables.counts
  });
  if (signature.kind !== "method") {
    throw new FormatError("calli operand must identify a StandAloneSig method signature");
  }
  const { typeArity, methodArity } = getMethodGenericArities(assembly, methodRid);
  validateGenericVariableReferences(
    signature,
    typeArity,
    assembly,
    null,
    methodArity
  );
  return signature;
}

function validateLocalSignatureCallSite(assembly, methodRid, signatureRid) {
  const row = assembly.tables.row(17, signatureRid);
  if (!row) throw new FormatError(`Method body references missing StandAloneSig row ${signatureRid}`);
  const signature = parseSignature(assembly.heaps.getBlob(row.Signature), {
    counts: assembly.tables.counts
  });
  if (signature.kind !== "locals") {
    throw new FormatError("Method local signature token must identify a local-variable signature");
  }
  const { typeArity, methodArity } = getMethodGenericArities(assembly, methodRid);
  validateGenericVariableReferences(signature, typeArity, assembly, null, methodArity);
  return signature;
}

function validateMethodSpecUseSites(
  assembly,
  methodSpecRid = null,
  typeSpecOverride = null,
  methodSpecOverride = null
) {
  for (const method of assembly.methods) {
    const body = assembly.getMethodBody(method.rid);
    if (!body) continue;
    validateGenericUsesInBody(
      assembly, method, body, methodSpecRid, typeSpecOverride, methodSpecOverride
    );
  }
}

function validateGenericUsesInBody(
  assembly,
  method,
  body,
  methodSpecRid = null,
  typeSpecOverride = null,
  methodSpecOverride = null
) {
  if (body.localVarSigToken !== 0) {
    const table = body.localVarSigToken >>> 24;
    const rid = body.localVarSigToken & 0x00ffffff;
    if (table !== 0x11 || rid === 0) {
      throw new FormatError(`MethodDef row ${method.rid} has an invalid local signature token`);
    }
    validateLocalSignatureCallSite(assembly, method.rid, rid);
  }
  for (const instruction of body.instructions) {
    const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
    const currentRid = token & 0x00ffffff;
    if (instruction.opcode.name === "calli") {
      if ((token >>> 24) !== 0x11 || currentRid === 0) {
        throw new FormatError("calli operand must identify a StandAloneSig method signature");
      }
      validateStandAloneSigCallSite(assembly, method.rid, currentRid);
      continue;
    }
    if ((token >>> 24) !== 0x2b ||
        (methodSpecRid !== null && currentRid !== methodSpecRid)) continue;
    const methodSpec = methodSpecOverride?.rid === currentRid
      ? methodSpecOverride
      : assembly.methodSpecs[currentRid - 1];
    if (!methodSpec) {
      throw new FormatError(`CIL references missing MethodSpec row ${currentRid}`);
    }
    validateMethodSpecUseAtCallSite(assembly, method.rid, methodSpec, typeSpecOverride);
  }
}

function validateNewMethodBody(assembly, bodyBytes, ownerType, methodRid, methodArity = 0) {
  if (!(bodyBytes instanceof Uint8Array) || bodyBytes.length === 0) {
    throw new TypeError("Method body must be a non-empty Uint8Array");
  }
  const body = parseMethodBody(bodyBytes, 0, 0);
  if (body.endOffset !== bodyBytes.length) {
    throw new FormatError("Method body contains trailing bytes");
  }
  if ((body.flags & ~(0x03 | 0x08 | 0x10)) !== 0) {
    throw new UnsupportedFormatError("Method body uses unsupported header flags");
  }
  const typeArity = getGenericParameterArity(assembly.genericParams, 2, ownerType.rid);
  if (body.localVarSigToken !== 0) {
    const table = body.localVarSigToken >>> 24;
    const rid = body.localVarSigToken & 0x00ffffff;
    if (table !== 17 || rid === 0 || rid > (assembly.tables.counts[17] ?? 0)) {
      throw new FormatError("Method local signature token must identify an existing StandAloneSig row");
    }
    const signatureRow = assembly.tables.row(17, rid);
    if (!signatureRow) throw new FormatError(`StandAloneSig row ${rid} is missing`);
    const signature = parseSignature(assembly.heaps.getBlob(signatureRow.Signature), {
      counts: assembly.tables.counts
    });
    if (signature.kind !== "locals") {
      throw new FormatError("Method local signature token must identify a local-variable signature");
    }
    validateGenericVariableReferences(signature, typeArity, assembly, null, methodArity);
  }
  for (const instruction of body.instructions) {
    if (instruction.opcode.name === "ldstr") {
      const token = instruction.operand.value;
      if ((token >>> 24) !== 0x70) {
        throw new FormatError("ldstr operand must be a 0x70-prefixed user-string token");
      }
      assembly.heaps.getUserString(token);
      continue;
    }
    if (instruction.operand?.kind !== "token") continue;
    const token = instruction.operand.value;
    const table = token >>> 24;
    const rid = token & 0x00ffffff;
    if (!allowedTokenTables(instruction.opcode.name).includes(table)) {
      throw new FormatError(`Metadata table ${table} is not valid for ${instruction.opcode.name}`);
    }
    const count = assembly.tables.counts[table] ?? 0;
    const referencesNewMethod = table === 6 && rid === methodRid;
    if (rid === 0 || (!referencesNewMethod && rid > count)) {
      throw new RangeError(`${instruction.opcode.name} references missing ${metadataTableNames[table]} row ${rid}`);
    }
    if (table === 17) {
      const signatureRow = assembly.tables.row(17, rid);
      if (!signatureRow) throw new FormatError(`StandAloneSig row ${rid} is missing`);
      const signature = parseSignature(assembly.heaps.getBlob(signatureRow.Signature), {
        counts: assembly.tables.counts
      });
      if (signature.kind !== "method") {
        throw new FormatError("calli operand must identify a StandAloneSig method signature");
      }
      validateGenericVariableReferences(signature, typeArity, assembly, null, methodArity);
    } else if (table === 43) {
      const methodSpec = assembly.methodSpecs[rid - 1];
      if (!methodSpec) throw new FormatError(`CIL references missing MethodSpec row ${rid}`);
      validateGenericVariableReferences(
        methodSpec.parsedInstantiation, typeArity, assembly, null, methodArity
      );
    }
  }
  for (const section of body.sections) {
    for (const clause of section.clauses) {
      if (![0, 1, 2, 4].includes(clause.flags)) {
        throw new UnsupportedFormatError(`Unsupported exception clause flags 0x${clause.flags.toString(16)}`);
      }
      if (clause.flags !== 0) continue;
      const table = clause.classTokenOrFilterOffset >>> 24;
      const rid = clause.classTokenOrFilterOffset & 0x00ffffff;
      if (![1, 2, 27].includes(table) || rid === 0 ||
          rid > (assembly.tables.counts[table] ?? 0)) {
        throw new FormatError("Catch clause must reference an existing TypeDef, TypeRef, or TypeSpec token");
      }
    }
  }
  return body;
}

function collectCatchTokenRemaps(body, tableId, rowCount, remapRid, tableName, removedRid = null) {
  const patches = [];
  const updates = [];
  for (const section of body.sections) {
    const clauseSize = section.fat ? 24 : 12;
    for (let index = 0; index < section.clauses.length; index++) {
      const clause = section.clauses[index];
      if (clause.flags !== 0) continue;
      const token = clause.classTokenOrFilterOffset;
      if ((token >>> 24) !== tableId) continue;
      const rid = token & 0x00ffffff;
      if (rid === 0 || rid > rowCount) {
        throw new FormatError(`Catch clause references missing ${tableName} row ${rid}`);
      }
      if (rid === removedRid) {
        throw new FormatError(`${tableName} row ${rid} is referenced by a catch clause`);
      }
      const remappedRid = remapRid(rid);
      if (remappedRid === rid) continue;
      const replacement = (tableId << 24) | remappedRid;
      const tokenOffset = section.offset + 4 + index * clauseSize + (section.fat ? 20 : 8);
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, replacement, true);
      patches.push({ offset: tokenOffset, bytes });
      updates.push({ clause, replacement });
    }
  }
  return { patches, updates };
}

function collectEncTokenRemaps(tables, tokenTableId, remapRid) {
  const changes = [];
  for (const tableId of [30, 31]) {
    for (const row of tables.get(tableId)) {
      const token = row.Token;
      if ((token >>> 24) !== tokenTableId) continue;
      const rid = token & 0x00ffffff;
      const remappedRid = remapRid(rid);
      if (remappedRid !== rid) {
        changes.push({
          row,
          columnName: "Token",
          value: (tokenTableId << 24) | remappedRid
        });
      }
    }
  }
  return changes;
}

function getBijectivePointerRows(assembly, pointerTableId, targetTableId, columnName) {
  if ((assembly.tables.valid & (1n << BigInt(pointerTableId))) === 0n) return null;
  const pointers = assembly.tables.rows.get(pointerTableId) ?? [];
  const targetCount = assembly.tables.counts[targetTableId] ?? 0;
  if (pointers.length !== targetCount ||
      pointers.length !== (assembly.tables.counts[pointerTableId] ?? 0)) {
    throw new UnsupportedFormatError(
      `${metadataTableNames[pointerTableId]} append requires a one-to-one mapping to ${metadataTableNames[targetTableId]}`
    );
  }
  const seen = new Set();
  for (const pointer of pointers) {
    const target = pointer[columnName];
    if (target?.table !== targetTableId || !Number.isInteger(target.rid) ||
        target.rid < 1 || target.rid > targetCount || seen.has(target.rid)) {
      throw new UnsupportedFormatError(
        `${metadataTableNames[pointerTableId]} append requires a one-to-one mapping to ${metadataTableNames[targetTableId]}`
      );
    }
    seen.add(target.rid);
  }
  return pointers;
}

const constantFixedSizes = new Map([
  [0x02, 1], [0x03, 2], [0x04, 1], [0x05, 1], [0x06, 2], [0x07, 2],
  [0x08, 4], [0x09, 4], [0x0a, 8], [0x0b, 8], [0x0c, 4], [0x0d, 8]
]);

function validateConstantValue(type, value) {
  if (!Number.isInteger(type) ||
      (!constantFixedSizes.has(type) && type !== 0x0e && type !== 0x12)) {
    throw new RangeError("Constant type must be a supported CLI constant element type");
  }
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("Constant value must be a Uint8Array of encoded constant bytes");
  }
  const expectedSize = constantFixedSizes.get(type);
  if (expectedSize !== undefined && value.length !== expectedSize) {
    throw new FormatError(`Constant element type 0x${type.toString(16)} requires ${expectedSize} value bytes`);
  }
  if (type === 0x0e && value.length % 2 !== 0) {
    throw new FormatError("String constants must contain an even number of UTF-16 bytes");
  }
  if (type === 0x02 && value[0] > 1) {
    throw new FormatError("Boolean constants must be encoded as zero or one");
  }
  if (type === 0x12 && (value.length !== 4 || value.some((byte) => byte !== 0))) {
    throw new FormatError("Class constants must encode a null reference");
  }
}

function validateFieldRva(assembly, fieldRid, rva) {
  const fieldRow = assembly.tables.row(4, fieldRid);
  let field = null;
  for (const type of assembly.types) {
    field = type.fields.find((candidate) => candidate.rid === fieldRid) ?? field;
  }
  if (!Number.isInteger(fieldRid) || fieldRid < 1 || !fieldRow || !field) {
    throw new RangeError(`Invalid Field row ID ${fieldRid}`);
  }
  if ((fieldRow.Flags & 0x10) === 0) {
    throw new FormatError("FieldRVA requires a static Field");
  }
  if (!Number.isInteger(rva) || rva <= 0 || rva > 0xffffffff) {
    throw new RangeError("FieldRVA must be a non-zero unsigned 32-bit RVA");
  }
  const parsed = parseSignature(field.signature, { counts: assembly.tables.counts });
  if (parsed.kind !== "field" || parsed.type.kind !== "primitive" ||
      !constantFixedSizes.has(parsed.type.elementType)) {
    throw new UnsupportedFormatError(
      "FieldRVA editing currently supports only fixed-width primitive Field types"
    );
  }
  assembly.pe.rvaToOffset(rva, constantFixedSizes.get(parsed.type.elementType));
  return field;
}

function validateNestedTypeRelationship(assembly, nestedRid, enclosingRid, ignoredRid = 0) {
  const rows = assembly.tables.rows.get(41) ?? [];
  let currentRid = enclosingRid;
  const visited = new Set();
  while (currentRid !== 0) {
    if (currentRid === nestedRid) {
      throw new FormatError("NestedClass relationship would create a TypeDef cycle");
    }
    if (visited.has(currentRid)) {
      throw new FormatError("Existing NestedClass relationships contain a cycle");
    }
    visited.add(currentRid);
    currentRid = rows.find((row) =>
      row.rid !== ignoredRid && row.NestedClass.rid === currentRid
    )?.EnclosingClass.rid ?? 0;
  }
}

function getMethodImplReference(assembly, reference) {
  const table = metadataTableId(reference?.table);
  const rid = reference?.rid;
  if (![6, 10].includes(table) || !Number.isInteger(rid) ||
      rid < 1 || rid > (assembly.tables.counts[table] ?? 0)) {
    throw new RangeError("MethodImpl body and declaration must identify an existing MethodDef or MemberRef");
  }
  if (table === 10) {
    const memberRef = assembly.memberRefs[rid - 1];
    if (!memberRef || parseSignature(memberRef.signature, { counts: assembly.tables.counts }).kind !== "method") {
      throw new FormatError("MethodImpl references must resolve to method signatures");
    }
  }
  return {
    raw: encodeCodedIndex(table, rid, "MethodDefOrRef"),
    target: { table, tableName: metadataTableNames[table], rid }
  };
}

function getForwardedMember(assembly, member) {
  const table = metadataTableId(member?.table);
  const rid = member?.rid;
  if (![4, 6].includes(table) || !Number.isInteger(rid) ||
      rid < 1 || rid > (assembly.tables.counts[table] ?? 0)) {
    throw new RangeError("ImplMap member must identify an existing Field or MethodDef row");
  }
  const row = assembly.tables.row(table, rid);
  if (!row || (row.Flags & 0x2000) === 0) {
    throw new FormatError("ImplMap member must have its PInvokeImpl flag set");
  }
  return {
    raw: encodeCodedIndex(table, rid, "MemberForwarded"),
    target: { table, tableName: metadataTableNames[table], rid },
    row
  };
}

function validateTypeSpecUseSites(assembly, typeSpecOverride) {
  for (const type of assembly.types) {
    const typeArity = getGenericParameterArity(assembly.genericParams, 2, type.rid);
    if (type.extends?.table === 27) {
      validateTypeSpecGenericContext(
        assembly, type.extends.rid, typeArity, 0, new Set(), typeSpecOverride
      );
    }
    for (const method of type.methods) {
      validateGenericVariableReferences(
        parseSignature(method.signature, { counts: assembly.tables.counts }),
        typeArity,
        assembly,
        typeSpecOverride
      );
    }
    for (const field of type.fields) {
      validateGenericVariableReferences(
        parseSignature(field.signature, { counts: assembly.tables.counts }),
        typeArity,
        assembly,
        typeSpecOverride
      );
    }
    for (const property of type.properties) {
      validateGenericVariableReferences(
        parseSignature(property.signature, { counts: assembly.tables.counts }),
        typeArity,
        assembly,
        typeSpecOverride
      );
    }
    for (const event of type.events) {
      if (event.eventType?.table === 27) {
        validateTypeSpecGenericContext(
          assembly, event.eventType.rid, typeArity, 0, new Set(), typeSpecOverride
        );
      }
    }
  }
  for (const interfaceImpl of assembly.tables.get(9)) {
    if (interfaceImpl.Interface.target?.table !== 27) continue;
    const typeArity = getGenericParameterArity(assembly.genericParams, 2, interfaceImpl.Class.rid);
    validateTypeSpecGenericContext(
      assembly, interfaceImpl.Interface.target.rid, typeArity, 0, new Set(), typeSpecOverride
    );
  }
  for (const constraint of assembly.genericParamConstraints) {
    if (constraint.constraint.table !== 27) continue;
    const parameter = assembly.genericParams[constraint.ownerRid - 1];
    const { typeArity, methodArity } = getGenericParameterOwnerContext(assembly, parameter);
    validateTypeSpecGenericContext(
      assembly, constraint.constraint.rid, typeArity, methodArity, new Set(), typeSpecOverride
    );
  }
  for (const memberRef of assembly.memberRefs) {
    validateMemberRefGenericContext(
      assembly,
      memberRef.parent,
      parseSignature(memberRef.signature, { counts: assembly.tables.counts }),
      typeSpecOverride
    );
  }
  validateMethodSpecUseSites(assembly, null, typeSpecOverride);
}

function canPreservePortablePdbCustomDebugInformation(pdb) {
  return pdb.customDebugInformation.every((record) =>
    (record.embeddedSource instanceof Uint8Array && record.Parent.target?.table === 48) ||
    (record.sourceLink && record.Parent.target?.table === 0) ||
    (typeof record.defaultNamespace === "string" && record.Parent.target?.table === 0) ||
    (record.dynamicLocalVariables instanceof Uint8Array &&
      [51, 52].includes(record.Parent.target?.table)) ||
    (Array.isArray(record.compilationOptions) && record.Parent.target?.table === 0) ||
    (Array.isArray(record.compilationMetadataReferences) && record.Parent.target?.table === 0) ||
    (Array.isArray(record.typeDefinitionDocuments) &&
      record.Parent.target?.table === 2)
  );
}

function sameEncodedType(left, right) {
  const leftBytes = encodeTypeSignature(left);
  const rightBytes = encodeTypeSignature(right);
  return leftBytes.length === rightBytes.length &&
    leftBytes.every((byte, index) => byte === rightBytes[index]);
}

function containsMetadataReference(value, table, rid, visited = new Set()) {
  if (!value || typeof value !== "object" || visited.has(value)) return false;
  visited.add(value);
  if (value.table === table && value.rid === rid) return true;
  return Object.values(value).some((item) =>
    Array.isArray(item)
      ? item.some((entry) => containsMetadataReference(entry, table, rid, visited))
      : containsMetadataReference(item, table, rid, visited)
  );
}

function validatePropertyAccessors(
  assembly,
  propertyRid,
  signature,
  semanticsRows = assembly.tables.get(24)
) {
  for (const semantics of semanticsRows) {
    if (semantics.Association.target?.table !== 23 ||
        semantics.Association.target.rid !== propertyRid ||
        (semantics.Semantics & 0x03) === 0) continue;
    const method = assembly.methods[semantics.Method.rid - 1];
    const methodSignature = method
      ? parseSignature(method.signature, { counts: assembly.tables.counts })
      : null;
    if (methodSignature?.kind !== "method" || methodSignature.generic ||
        methodSignature.sentinelIndex !== null) {
      throw new FormatError(`Property row ${propertyRid} has an unsupported accessor signature`);
    }
    if ((semantics.Semantics & 0x02) !== 0) {
      if (methodSignature.parameters.length !== signature.parameters.length ||
          !sameEncodedType(methodSignature.returnType, signature.returnType) ||
          methodSignature.parameters.some((parameter, index) =>
            !sameEncodedType(parameter, signature.parameters[index])
          )) {
        throw new FormatError(`Property row ${propertyRid} replacement is incompatible with its getter`);
      }
    }
    if ((semantics.Semantics & 0x01) !== 0) {
      const propertyParameters = signature.parameters;
      if (methodSignature.parameters.length !== propertyParameters.length + 1 ||
          methodSignature.returnType.kind !== "primitive" ||
          methodSignature.returnType.elementType !== 0x01 ||
          !sameEncodedType(methodSignature.parameters.at(-1), signature.returnType) ||
          propertyParameters.some((parameter, index) =>
            !sameEncodedType(methodSignature.parameters[index], parameter)
          )) {
        throw new FormatError(`Property row ${propertyRid} replacement is incompatible with its setter`);
      }
    }
  }
}

function validateEventAccessors(
  assembly,
  eventRid,
  eventType,
  semanticsRows = assembly.tables.get(24)
) {
  const expectedType = eventType.table === 27
    ? assembly.typeSpecs[eventType.rid - 1]?.parsedSignature
    : { kind: "class", type: eventType };
  if (!expectedType) throw new FormatError(`Event row ${eventRid} references a missing TypeSpec`);
  for (const semantics of semanticsRows) {
    if (semantics.Association.target?.table !== 20 ||
        semantics.Association.target.rid !== eventRid ||
        (semantics.Semantics & 0x18) === 0) continue;
    const method = assembly.methods[semantics.Method.rid - 1];
    const signature = method
      ? parseSignature(method.signature, { counts: assembly.tables.counts })
      : null;
    if (signature?.kind !== "method" || signature.generic ||
        signature.parameters.length !== 1 ||
        signature.returnType.kind !== "primitive" ||
        signature.returnType.elementType !== 0x01 ||
        !sameEncodedType(signature.parameters[0], expectedType)) {
      throw new FormatError(`Event row ${eventRid} replacement is incompatible with its add/remove accessor`);
    }
  }
}

function validateMethodSemanticsRecord(
  assembly,
  semantics,
  methodRid,
  associationTable,
  associationRid,
  semanticsRows
) {
  const allowedSemantics = associationTable === 23
    ? new Set([0x01, 0x02, 0x04])
    : new Set([0x04, 0x08, 0x10, 0x20]);
  if (!allowedSemantics.has(semantics)) {
    throw new RangeError("MethodSemantics value is not valid for the association type");
  }
  const methodOwner = assembly.types.find((type) => type.methodRids.includes(methodRid));
  const associationOwner = assembly.types.find((type) =>
    (associationTable === 20 ? type.eventRids : type.propertyRids).includes(associationRid)
  );
  if (!methodOwner || !associationOwner || methodOwner.rid !== associationOwner.rid) {
    throw new FormatError("MethodSemantics method and association must belong to the same TypeDef");
  }
  const method = assembly.methods[methodRid - 1];
  if (semantics === 0x01 || semantics === 0x02) {
    const property = assembly.types[associationOwner.rid - 1].properties
      .find((item) => item.rid === associationRid);
    if (!property) throw new FormatError(`Missing Property row ${associationRid}`);
    validatePropertyAccessors(
      assembly,
      associationRid,
      parseSignature(property.signature, { counts: assembly.tables.counts }),
      semanticsRows
    );
  } else if (associationTable === 20 && semantics !== 0x04) {
    const event = assembly.types[associationOwner.rid - 1].events
      .find((item) => item.rid === associationRid);
    if (!event) throw new FormatError(`Missing Event row ${associationRid}`);
    validateEventAccessors(assembly, associationRid, event.eventType, semanticsRows);
  }
  if (!method) throw new FormatError(`Missing MethodDef row ${methodRid}`);
}

function getCustomAttributeEnumResolver(assembly, resolver) {
  if (resolver !== undefined && typeof resolver !== "function") {
    throw new TypeError("Custom-attribute enum resolver must be a function");
  }
  return (name) => {
    const resolved = resolver?.(name);
    const elementType = resolved === undefined ? resolveEnumElementType(assembly, name) : resolved;
    if (!customAttributeEnumTypes.has(elementType)) {
      throw new UnsupportedFormatError(`Unsupported custom-attribute enum underlying type for ${name}`);
    }
    return elementType;
  };
}

function getCustomAttributeArgumentType(assembly, signatureType, resolveEnum) {
  if (signatureType.kind === "primitive") {
    if (signatureType.elementType === 0x0e) return { kind: "string" };
    if (signatureType.elementType === 0x1c) return { kind: "object" };
    if ([0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d].includes(signatureType.elementType)) {
      return { kind: "primitive", elementType: signatureType.elementType };
    }
  }
  if (signatureType.kind === "szArray") {
    return {
      kind: "array",
      elementType: getCustomAttributeArgumentType(assembly, signatureType.type, resolveEnum)
    };
  }
  if (signatureType.kind === "class" || signatureType.kind === "valueType") {
    const name = getManagedTypeName(assembly, signatureType.type);
    if (name === "System.Type") return { kind: "type" };
    if (name === "System.Object") return { kind: "object" };
    if (name) return { kind: "enum", name, elementType: resolveEnum(name) };
  }
  throw new UnsupportedFormatError(`Unsupported custom-attribute constructor parameter type ${signatureType.kind}`);
}

function getLocalCustomAttributeBaseStatus(assembly, type, visited = new Set()) {
  if (!type) return false;
  const name = getManagedTypeDefinitionName(assembly, type);
  if (name === "System.Attribute") return true;
  if (visited.has(type.rid)) {
    throw new FormatError("Custom-attribute constructor type inheritance contains a cycle");
  }
  visited.add(type.rid);
  const base = getManagedTypeDefinitionReference(assembly, type.extends);
  if (base?.table === 2) {
    return getLocalCustomAttributeBaseStatus(
      assembly,
      assembly.types[base.rid - 1],
      visited
    );
  }
  if (base?.table === 1) {
    const baseName = getManagedTypeName(assembly, base);
    if (baseName === "System.Attribute") return true;
    if (baseName === "System.Object") return false;
  }
  return null;
}

function findLocalCustomAttributeNamedMember(
  assembly,
  type,
  kind,
  name,
  visited = new Set(),
  typeArguments = []
) {
  if (!type) return { member: null, complete: false, typeArguments };
  if (visited.has(type.rid)) {
    throw new FormatError("Custom-attribute named-member inheritance contains a cycle");
  }
  visited.add(type.rid);
  const members = kind === "field"
    ? type.fields.filter((field) => field.name === name)
    : type.properties.filter((property) => property.name === name);
  if (members.length > 1) {
    throw new FormatError(`Custom-attribute named ${kind} ${name} is ambiguous`);
  }
  if (members.length === 1) {
    return { member: members[0], complete: true, typeArguments };
  }
  const baseReference = getManagedTypeDefinitionReference(assembly, type.extends);
  if (baseReference?.table === 2) {
    const extendsSignature = type.extends.table === 27
      ? assembly.typeSpecs[type.extends.rid - 1]?.parsedSignature
      : null;
    const baseType = assembly.types[baseReference.rid - 1];
    const baseTypeArguments = extendsSignature?.kind === "genericInstance"
      ? typeArguments === null
        ? null
        : extendsSignature.arguments.map((argument) =>
          substituteCustomAttributeType(argument, typeArguments)
        )
      : baseType?.genericParams.length === 0
        ? []
        : null;
    return findLocalCustomAttributeNamedMember(
      assembly,
      baseType,
      kind,
      name,
      visited,
      baseTypeArguments
    );
  }
  if (baseReference?.table === 1 &&
      getManagedTypeName(assembly, baseReference) === "System.Attribute") {
    return { member: null, complete: true, typeArguments };
  }
  return { member: null, complete: false, typeArguments };
}

function substituteCustomAttributeType(type, typeArguments) {
  if (!type || typeArguments === null) return type;
  if (type.kind === "typeParameter") {
    return typeArguments[type.index] ?? type;
  }
  if (type.kind === "modified") {
    return { ...type, type: substituteCustomAttributeType(type.type, typeArguments) };
  }
  if (["array", "szArray", "pointer", "byRef", "pinned"].includes(type.kind)) {
    return { ...type, type: substituteCustomAttributeType(type.type, typeArguments) };
  }
  if (type.kind === "genericInstance") {
    return {
      ...type,
      arguments: type.arguments.map((argument) =>
        substituteCustomAttributeType(argument, typeArguments)
      )
    };
  }
  if (type.kind === "functionPointer") {
    return {
      ...type,
      signature: {
        ...type.signature,
        returnType: substituteCustomAttributeType(type.signature.returnType, typeArguments),
        parameters: type.signature.parameters.map((parameter) =>
          substituteCustomAttributeType(parameter, typeArguments)
        )
      }
    };
  }
  return type;
}

function hasOpenCustomAttributeType(type) {
  if (!type) return true;
  if (type.kind === "typeParameter" || type.kind === "methodParameter") return true;
  if (type.kind === "modified") return hasOpenCustomAttributeType(type.type);
  if (["array", "szArray", "pointer", "byRef", "pinned"].includes(type.kind)) {
    return hasOpenCustomAttributeType(type.type);
  }
  if (type.kind === "genericInstance") {
    return type.arguments.some(hasOpenCustomAttributeType);
  }
  if (type.kind === "functionPointer") {
    return hasOpenCustomAttributeType(type.signature.returnType) ||
      type.signature.parameters.some(hasOpenCustomAttributeType);
  }
  return false;
}

function sameCustomAttributeArgumentType(left, right) {
  if (!left || !right || left.kind !== right.kind) return false;
  if (left.kind === "primitive") return left.elementType === right.elementType;
  if (left.kind === "enum") {
    return left.elementType === right.elementType &&
      left.name.split(",", 1)[0].trim() === right.name.split(",", 1)[0].trim();
  }
  if (left.kind === "array") {
    return sameCustomAttributeArgumentType(left.elementType, right.elementType);
  }
  return ["string", "type", "object"].includes(left.kind);
}

function validateLocalCustomAttributeNamedArguments(
  assembly,
  ownerType,
  typeArguments,
  namedArguments,
  resolveEnum
) {
  if (!ownerType) return;
  for (const argument of namedArguments) {
    const located = findLocalCustomAttributeNamedMember(
      assembly,
      ownerType,
      argument.kind,
      argument.name,
      new Set(),
      typeArguments
    );
    if (!located.member) {
      if (located.complete) {
        throw new FormatError(
          `Custom-attribute named ${argument.kind} ${argument.name} does not exist on its constructor type`
        );
      }
      continue;
    }
    if (argument.kind === "field") {
      const field = located.member;
      if ((field.flags & 0x7) !== 0x6 || (field.flags & 0x70) !== 0) {
        throw new FormatError(
          `Custom-attribute named field ${argument.name} must be public, writable, and nonstatic`
        );
      }
      const signature = parseSignature(field.signature, { counts: assembly.tables.counts });
      if (signature.kind !== "field") {
        throw new FormatError(`Custom-attribute named field ${argument.name} has an invalid signature`);
      }
      const fieldType = substituteCustomAttributeType(signature.type, located.typeArguments);
      if (!hasOpenCustomAttributeType(fieldType) &&
          !sameCustomAttributeArgumentType(
            getCustomAttributeArgumentType(assembly, fieldType, resolveEnum),
            argument.type
          )) {
        throw new FormatError(
          `Custom-attribute named field ${argument.name} has a type that does not match its signature`
        );
      }
      continue;
    }

    const property = located.member;
    const propertySignature = parseSignature(property.signature, {
      counts: assembly.tables.counts
    });
    if (propertySignature.kind !== "property" || propertySignature.parameters.length !== 0) {
      throw new FormatError(
        `Custom-attribute named property ${argument.name} must not have index parameters`
      );
    }
    const propertyType = substituteCustomAttributeType(
      propertySignature.returnType,
      located.typeArguments
    );
    if (!hasOpenCustomAttributeType(propertyType) &&
        !sameCustomAttributeArgumentType(
          getCustomAttributeArgumentType(assembly, propertyType, resolveEnum),
          argument.type
        )) {
      throw new FormatError(
        `Custom-attribute named property ${argument.name} has a type that does not match its signature`
      );
    }
    const setterSemantics = assembly.tables.get(24).filter((row) =>
      row.Association.target?.table === 23 &&
      row.Association.target.rid === property.rid &&
      (row.Semantics & 0x01) !== 0
    );
    if (setterSemantics.length !== 1) {
      throw new FormatError(
        `Custom-attribute named property ${argument.name} must have one setter`
      );
    }
    const setter = assembly.methods[setterSemantics[0].Method.rid - 1];
    const setterSignature = setter
      ? parseSignature(setter.signature, { counts: assembly.tables.counts })
      : null;
    const setterParameterType = setterSignature?.parameters.length === 1
      ? substituteCustomAttributeType(
        setterSignature.parameters[0],
        located.typeArguments
      )
      : null;
    const setterParameterMatches = hasOpenCustomAttributeType(setterParameterType) ||
      sameCustomAttributeArgumentType(
        getCustomAttributeArgumentType(assembly, setterParameterType, resolveEnum),
        argument.type
      );
    if (!setter || (setter.flags & 0x7) !== 0x6 || (setter.flags & 0x10) !== 0 ||
        setterSignature.kind !== "method" || !setterSignature.hasThis ||
        setterSignature.explicitThis || setterSignature.generic ||
        setterSignature.parameters.length !== 1 ||
        setterSignature.returnType.kind !== "primitive" ||
        setterSignature.returnType.elementType !== 0x01 ||
        !setterParameterMatches) {
      throw new FormatError(
        `Custom-attribute named property ${argument.name} must have a public instance setter of the matching type`
      );
    }
  }
}

function getLocalPermissionSetAttributeType(assembly, typeName) {
  let bracketDepth = 0;
  let nameEnd = typeName.length;
  for (let index = 0; index < typeName.length; index++) {
    if (typeName[index] === "[") bracketDepth++;
    else if (typeName[index] === "]") bracketDepth--;
    else if (typeName[index] === "," && bracketDepth === 0) {
      nameEnd = index;
      break;
    }
  }
  const fullName = typeName.slice(0, nameEnd).trim();
  return assembly.types.find((type) =>
    getManagedTypeName(assembly, { table: 2, rid: type.rid }) === fullName
  ) ?? null;
}

function validateLocalPermissionSetNamedArguments(assembly, permissionSet, resolveEnum) {
  if (permissionSet.format !== "binary") return;
  for (const attribute of permissionSet.attributes) {
    const ownerType = getLocalPermissionSetAttributeType(assembly, attribute.typeName);
    if (!ownerType) continue;
    validateLocalCustomAttributeNamedArguments(
      assembly,
      ownerType,
      ownerType.genericParams.length > 0 ? null : [],
      attribute.namedArguments,
      resolveEnum
    );
  }
}

function getCustomAttributeConstructor(assembly, attribute, resolveEnum) {
  const constructor = attribute.constructor;
  let method;
  let ownerType;
  let localOwnerType = null;
  let typeArguments = null;
  if (constructor?.table === 6) {
    method = assembly.methods[constructor.rid - 1];
    localOwnerType = assembly.types.find((type) => type.methodRids.includes(constructor.rid));
    ownerType = localOwnerType;
    typeArguments = localOwnerType?.genericParams.length === 0 ? [] : null;
  } else if (constructor?.table === 10) {
    method = assembly.memberRefs.find((reference) => reference.rid === constructor.rid);
    ownerType = method ? getManagedTypeName(assembly, method.parent) : null;
    const ownerReference = method
      ? getManagedTypeDefinitionReference(assembly, method.parent)
      : null;
    if (ownerReference?.table === 2) {
      localOwnerType = assembly.types[ownerReference.rid - 1] ?? null;
    }
    const parentSignature = method?.parent?.table === 27
      ? assembly.typeSpecs[method.parent.rid - 1]?.parsedSignature
      : null;
    typeArguments = parentSignature?.kind === "genericInstance"
      ? parentSignature.arguments
      : localOwnerType?.genericParams.length === 0
        ? []
        : null;
  }
  if (!method || method.name !== ".ctor") {
    throw new FormatError(`CustomAttribute row ${attribute.rid} does not reference a supported constructor`);
  }
  const signature = parseSignature(method.signature);
  if (signature.kind !== "method" || signature.callingConvention !== 0 ||
      !signature.hasThis || signature.explicitThis || signature.generic ||
      signature.sentinelIndex !== null) {
    throw new UnsupportedFormatError(`CustomAttribute row ${attribute.rid} has an unsupported constructor signature`);
  }
  if (signature.returnType.kind !== "primitive" || signature.returnType.elementType !== 0x01) {
    throw new FormatError(`CustomAttribute row ${attribute.rid} constructor must return void`);
  }
  if (constructor.table === 6 && !ownerType) {
    throw new FormatError(`CustomAttribute row ${attribute.rid} constructor has no declaring type`);
  }
  if (localOwnerType && getLocalCustomAttributeBaseStatus(assembly, localOwnerType) === false) {
    throw new FormatError(
      `CustomAttribute row ${attribute.rid} constructor type does not derive from System.Attribute`
    );
  }
  return {
    signature,
    localOwnerType,
    typeArguments,
    fixedTypes: signature.parameters.map((parameter) =>
      getCustomAttributeArgumentType(assembly, parameter, resolveEnum)
    )
  };
}

export { FormatError, UnsupportedFormatError } from "./binary/errors.js";
export { BinaryReader, readCompressedInt, readCompressedUInt } from "./binary/reader.js";
export {
  decodeInstructions,
  encodeInstruction,
  encodeOpcode,
  formatInstruction,
  encodeOperand,
  getInstructionSize
} from "./il/instructions.js";
export { parseMethodBody } from "./il/body.js";
export {
  codedIndexWidth,
  decodeCodedIndex,
  encodeCodedIndex,
  metadataTableNames,
  parseTablesStream,
  tableIndexWidth
} from "./metadata/tables.js";
export { MetadataHeaps, parseMetadataRoot } from "./metadata/streams.js";
export {
  parseClassicPdbFile as parseClassicPdb,
  replaceClassicPdbFileChecksumFile as replaceClassicPdbFileChecksum,
  replaceClassicPdbLineInfoFile as replaceClassicPdbLineInfo,
  replaceClassicPdbModuleNamesFile as replaceClassicPdbModuleNames,
  replaceClassicPdbStringTableNameFile as replaceClassicPdbStringTableName,
  replaceClassicPdbSymbolNameFile as replaceClassicPdbSymbolName
};
export {
  encodeCustomAttribute,
  encodePermissionSet,
  parseCustomAttribute,
  parsePermissionSet
} from "./metadata/custom-attributes.js";
export {
  appendPortablePdbDocumentName,
  decodePortablePdbDocumentName,
  decodePortablePdbSequencePoints,
  encodePortablePdbDocumentName,
  encodePortablePdbSequencePoints,
  addEmbeddedPortablePdbDocument,
  insertEmbeddedPortablePdbDocument,
  addEmbeddedPortablePdbTypeDefinitionDocuments,
  removeEmbeddedPortablePdbDocument,
  replaceEmbeddedPortablePdbDocumentMetadata,
  replaceEmbeddedPortablePdbTypeDefinitionDocuments,
  replaceEmbeddedPortablePdbDocumentName,
  replaceEmbeddedPortablePdbSequencePoints,
  addEmbeddedPortablePdbSource,
  removeEmbeddedPortablePdbSource,
  removeEmbeddedPortablePdbSourceLink,
  removeEmbeddedPortablePdbCustomDebugInformation,
  replaceEmbeddedPortablePdbSource,
  addEmbeddedPortablePdbSourceLink,
  replaceEmbeddedPortablePdbSourceLink,
  serializeEmbeddedPortablePdb
} from "./metadata/portable-pdb.js";
export {
  encodeSignature,
  encodeTypeSignature,
  parseSignature,
  parseTypeSignature,
  remapTypeReferences
} from "./metadata/signatures.js";
export { parseCliHeader, parsePE } from "./pe/headers.js";

export class Assembly {
  #bytes;
  #strongNamePrivateKey = null;
  #strongNameHashAlgorithm = 0;
  #strongNameSignatureSize = 0;
  #hasAuthenticodeCertificate;
  #hasDebugDirectory;

  constructor(input) {
    this.#bytes = input instanceof Uint8Array ? Uint8Array.from(input) : new Uint8Array(input);
    this.pe = parsePE(this.#bytes);
    this.pe.bytes = Uint8Array.from(this.pe.bytes);
    this.pe.sections = Object.freeze(this.pe.sections.map((section) => Object.freeze(section)));
    this.pe.directories = Object.freeze(this.pe.directories.map((directory) => Object.freeze(directory)));
    this.pe.debugDirectoryEntries = Object.freeze(
      this.pe.debugDirectoryEntries.map((entry) => Object.freeze(entry))
    );
    this.#hasAuthenticodeCertificate = Boolean(
      this.pe.directories[4] && (this.pe.directories[4].rva !== 0 || this.pe.directories[4].size !== 0)
    );
    this.#hasDebugDirectory = Boolean(
      this.pe.directories[6] && (this.pe.directories[6].rva !== 0 || this.pe.directories[6].size !== 0)
    );
    const cli = parseCliHeader(this.pe);
    this.cli = Object.freeze({
      ...cli,
      strongNameSignature: Object.freeze(cli.strongNameSignature)
    });
    this.pe = Object.freeze(this.pe);
    if (this.cli.metadataRva === 0 || this.cli.metadataSize === 0) {
      throw new FormatError("CLI header has no metadata directory", { offset: this.cli.offset, context: "CLI header" });
    }
    const metadataOffset = this.pe.rvaToOffset(this.cli.metadataRva, this.cli.metadataSize);
    this.metadataRoot = parseMetadataRoot(this.#bytes, metadataOffset, this.cli.metadataSize);
    const compressedTables = this.metadataRoot.streams.get("#~");
    const uncompressedTables = this.metadataRoot.streams.get("#-");
    if (compressedTables && uncompressedTables) {
      throw new FormatError("Metadata root contains both #~ and #- table streams");
    }
    const tableStream = compressedTables ?? uncompressedTables;
    if (!tableStream) throw new FormatError("Metadata root has neither #~ nor #- table stream");
    this.tables = parseTablesStream(tableStream);
    const embeddedPortablePdb = this.pe.debugDirectoryEntries
      .find((entry) => entry.embeddedPortablePdb)?.embeddedPortablePdb;
    if (embeddedPortablePdb) {
      validatePortablePdbAssemblyReferences(
        embeddedPortablePdb,
        this.tables.counts
      );
      const codeViewEntry = this.pe.debugDirectoryEntries
        .find((entry) => entry.codeView?.format === "RSDS");
      if (codeViewEntry) {
        validatePortablePdbCodeViewIdentity(
          embeddedPortablePdb,
          codeViewEntry.codeView,
          codeViewEntry.minorVersion === 0x504d ? codeViewEntry.timeDateStamp : undefined
        );
      }
    }
    if (this.tables.get(0).length !== 1) {
      throw new FormatError("Metadata must contain exactly one Module row");
    }
    if (this.tables.get(32).length > 1) {
      throw new FormatError("Metadata must not contain more than one Assembly row");
    }
    if (this.tables.get(2).length === 0) {
      throw new FormatError("Metadata must contain the special <Module> TypeDef row");
    }
    this.heaps = new MetadataHeaps(this.metadataRoot.streams);
    for (const [tableId, rows] of this.tables.rows) {
      for (const row of rows) {
        for (const [kind, value, name] of metadataTableSchemas[tableId]) {
          const heapIndex = row[name ?? value];
          if (kind === "str") this.heaps.getString(heapIndex);
          else if (kind === "blob") this.heaps.getBlob(heapIndex);
          else if (kind === "guid") this.heaps.getGuid(heapIndex);
        }
      }
    }
    const signatureColumns = new Map([
      [4, "Signature"], [6, "Signature"], [10, "Signature"], [17, "Signature"],
      [23, "Type"], [43, "Instantiation"]
    ]);
    for (const [tableId, column] of signatureColumns) {
      for (const row of this.tables.get(tableId)) {
        parseSignature(this.heaps.getBlob(row[column]), { counts: this.tables.counts });
      }
    }
    for (const row of this.tables.get(27)) {
      parseTypeSignature(this.heaps.getBlob(row.Signature), { counts: this.tables.counts });
    }
    const methodParameterRids = resolveMethodParameters(this.tables);
    this.methods = this.tables.get("MethodDef").map((row, index) => ({
      rid: row.rid,
      rva: row.RVA,
      flags: row.Flags,
      implFlags: row.ImplFlags,
      name: this.heaps.getString(row.Name),
      signature: this.heaps.getBlob(row.Signature),
      parameterRids: methodParameterRids[index],
      parameters: methodParameterRids[index].map((rid) => {
        const parameter = this.tables.row(8, rid);
        return {
          rid,
          flags: parameter.Flags,
          sequence: parameter.Sequence,
          name: this.heaps.getString(parameter.Name)
        };
      }),
      row
    }));
    this.typeRefs = this.tables.get("TypeRef").map((row) => ({
      rid: row.rid,
      name: this.heaps.getString(row.TypeName),
      namespace: this.heaps.getString(row.TypeNamespace),
      resolutionScope: row.ResolutionScope.target
    }));
    this.typeSpecs = this.tables.get("TypeSpec").map((row) => ({
      rid: row.rid,
      signature: this.heaps.getBlob(row.Signature),
      parsedSignature: parseTypeSignature(this.heaps.getBlob(row.Signature), { counts: this.tables.counts })
    }));
    this.standAloneSigs = this.tables.get("StandAloneSig").map((row) => {
      const signature = this.heaps.getBlob(row.Signature);
      const parsedSignature = parseSignature(signature, { counts: this.tables.counts });
      if (!["method", "locals"].includes(parsedSignature.kind)) {
        throw new FormatError(
          `StandAloneSig row ${row.rid} must contain a method or local-variable signature`
        );
      }
      return { rid: row.rid, signature, parsedSignature };
    });
    this.methodSpecs = this.tables.get("MethodSpec").map((row) => ({
      rid: row.rid,
      method: row.Method.target,
      instantiation: this.heaps.getBlob(row.Instantiation),
      parsedInstantiation: parseSignature(this.heaps.getBlob(row.Instantiation), { counts: this.tables.counts })
    }));
    for (const methodSpec of this.methodSpecs) {
      if (methodSpec.parsedInstantiation.kind !== "methodInstantiation") {
        throw new FormatError(
          `MethodSpec row ${methodSpec.rid} does not contain a method-instantiation signature`
        );
      }
      if (!methodSpec.method) {
        throw new FormatError(`MethodSpec row ${methodSpec.rid} has a nil method reference`);
      }
      const methodRow = this.tables.row(methodSpec.method.table, methodSpec.method.rid);
      if (!methodRow) {
        throw new FormatError(
          `MethodSpec row ${methodSpec.rid} references a missing method row`
        );
      }
      const methodSignature = parseSignature(
        this.heaps.getBlob(methodRow.Signature),
        { counts: this.tables.counts }
      );
      if (methodSignature.kind !== "method" || !methodSignature.generic ||
          methodSignature.genericParameterCount !== methodSpec.parsedInstantiation.arguments.length) {
        throw new FormatError(`MethodSpec row ${methodSpec.rid} does not match its generic method signature`);
      }
    }
    this.genericParams = this.tables.get("GenericParam").map((row) => ({
      rid: row.rid,
      number: row.Number,
      flags: row.Flags,
      owner: row.Owner.target,
      name: this.heaps.getString(row.Name)
    }));
    const genericParamsByOwner = new Map();
    for (const parameter of this.genericParams) {
      const ownerKey = `${parameter.owner.table}:${parameter.owner.rid}`;
      if (!genericParamsByOwner.has(ownerKey)) genericParamsByOwner.set(ownerKey, []);
      genericParamsByOwner.get(ownerKey).push(parameter.number);
      if (parameter.owner.table !== 6) continue;
      const method = this.methods[parameter.owner.rid - 1];
      const signature = method ? parseSignature(method.signature, { counts: this.tables.counts }) : null;
      if (signature?.kind !== "method" || !signature.generic ||
          parameter.number >= signature.genericParameterCount) {
        throw new FormatError(`GenericParam row ${parameter.rid} exceeds its method signature's generic arity`);
      }
    }
    for (const numbers of genericParamsByOwner.values()) {
      numbers.sort((left, right) => left - right);
      if (numbers.some((number, index) => number !== index)) {
        throw new FormatError("GenericParam rows must define each owner's parameter numbers from zero without gaps");
      }
    }
    for (const method of this.methods) {
      const signature = parseSignature(method.signature, { counts: this.tables.counts });
      if (signature.kind !== "method" || !signature.generic) continue;
      const parameterCount = genericParamsByOwner.get(`6:${method.rid}`)?.length ?? 0;
      if (parameterCount !== signature.genericParameterCount) {
        throw new FormatError(`Generic method ${method.rid} signature arity does not match its GenericParam rows`);
      }
    }
    this.genericParamConstraints = this.tables.get("GenericParamConstraint").map((row) => ({
      rid: row.rid,
      ownerRid: row.Owner.rid,
      constraint: row.Constraint.target
    }));
    this.memberRefs = this.tables.get("MemberRef").map((row) => ({
      rid: row.rid,
      name: this.heaps.getString(row.Name),
      parent: row.Class.target,
      signature: this.heaps.getBlob(row.Signature)
    }));
    this.assemblyRefs = this.tables.get("AssemblyRef").map((row) => ({
      rid: row.rid,
      name: this.heaps.getString(row.Name),
      culture: this.heaps.getString(row.Culture),
      version: [row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber],
      publicKeyOrToken: this.heaps.getBlob(row.PublicKeyOrToken)
    }));
    this.moduleRefs = this.tables.get("ModuleRef").map((row) => ({
      rid: row.rid,
      name: this.heaps.getString(row.Name)
    }));
    this.files = this.tables.get("File").map((row) => ({
      rid: row.rid,
      flags: row.Flags,
      name: this.heaps.getString(row.Name),
      hashValue: this.heaps.getBlob(row.HashValue)
    }));
    this.exportedTypes = this.tables.get("ExportedType").map((row) => ({
      rid: row.rid,
      flags: row.Flags,
      typeDefId: row.TypeDefId,
      name: this.heaps.getString(row.TypeName),
      namespace: this.heaps.getString(row.TypeNamespace),
      implementation: row.Implementation.target
    }));
    this.resources = parseManifestResources(
      this.#bytes,
      this.cli.resources,
      this.tables.get("ManifestResource"),
      this.heaps,
      this.pe.rvaToOffset
    );
    this.types = resolveTypes(this.tables, this.heaps);
    if (this.types[0]?.name !== "<Module>" || this.types[0]?.namespace !== "") {
      throw new FormatError("The first TypeDef row must be the special <Module> type with an empty namespace");
    }
    validateLocalTypeInheritance(this);
    const fieldRvas = new Map(this.tables.get("FieldRVA").map((row) => [row.Field.rid, row.RVA]));
    for (const parameter of this.genericParams) {
      if ((parameter.flags & 0x03) === 0 || parameter.owner.table !== 2) continue;
      const ownerType = this.types[parameter.owner.rid - 1];
      const base = ownerType?.extends;
      const baseType = base?.table === 1
        ? this.typeRefs[base.rid - 1]
        : base?.table === 2
          ? this.types[base.rid - 1]
          : null;
      if ((ownerType?.flags & 0x20) === 0 &&
          `${baseType?.namespace ?? ""}.${baseType?.name ?? ""}` !== "System.MulticastDelegate") {
        throw new FormatError(`GenericParam row ${parameter.rid} declares variance on a non-interface, non-delegate type`);
      }
    }
    for (const type of this.types) {
      type.methods = type.methodRids.map((rid) => this.methods[rid - 1]).filter(Boolean);
      type.fields = type.fieldRids.map((rid) => {
        const row = this.tables.row("Field", rid);
        return row ? {
          rid,
          flags: row.Flags,
          name: this.heaps.getString(row.Name),
          signature: this.heaps.getBlob(row.Signature),
          rva: fieldRvas.get(rid) ?? null
        } : null;
      }).filter(Boolean);
      type.events = type.eventRids.map((rid) => {
        const row = this.tables.row(20, rid);
        return row ? {
          rid,
          flags: row.EventFlags,
          name: this.heaps.getString(row.Name),
          eventType: row.EventType.target
        } : null;
      }).filter(Boolean);
      type.properties = type.propertyRids.map((rid) => {
        const row = this.tables.row(23, rid);
        return row ? {
          rid,
          flags: row.Flags,
          name: this.heaps.getString(row.Name),
          signature: this.heaps.getBlob(row.Type)
        } : null;
      }).filter(Boolean);
      type.genericParams = this.genericParams.filter((parameter) =>
        parameter.owner.table === 2 && parameter.owner.rid === type.rid
      );
      const typeArity = type.genericParams.length;
      if (type.extends?.table === 27) {
        validateTypeSpecGenericContext(this, type.extends.rid, typeArity);
      }
      for (const interfaceImpl of this.tables.get(9)) {
        if (interfaceImpl.Class.rid === type.rid && interfaceImpl.Interface.target?.table === 27) {
          validateTypeSpecGenericContext(this, interfaceImpl.Interface.target.rid, typeArity);
        }
      }
      for (const event of type.events) {
        if (event.eventType?.table === 27) {
          validateTypeSpecGenericContext(this, event.eventType.rid, typeArity);
        }
      }
      for (const method of type.methods) {
        validateGenericVariableReferences(
          parseSignature(method.signature, { counts: this.tables.counts }),
          typeArity,
          this
        );
      }
      for (const field of type.fields) {
        validateGenericVariableReferences(
          parseSignature(field.signature, { counts: this.tables.counts }),
          typeArity,
          this
        );
      }
      for (const propertyRid of type.propertyRids) {
        const property = this.tables.row(23, propertyRid);
        if (!property) throw new FormatError(`Property row ${propertyRid} is missing from its declaring type`);
        validateGenericVariableReferences(
          parseSignature(this.heaps.getBlob(property.Type), { counts: this.tables.counts }),
          typeArity,
          this
        );
      }
    }
    for (const typeSpec of this.typeSpecs) {
      validateTypeSpecDefinitions(this, typeSpec.parsedSignature);
    }
    for (const memberRef of this.memberRefs) {
      validateMemberRefGenericContext(
        this,
        memberRef.parent,
        parseSignature(memberRef.signature, { counts: this.tables.counts })
      );
    }
    for (const method of this.methods) {
      method.genericParams = this.genericParams.filter((parameter) =>
        parameter.owner.table === 6 && parameter.owner.rid === method.rid
      );
    }
    for (const parameter of this.genericParams) parameter.constraints = [];
    for (const constraint of this.genericParamConstraints) {
      const owner = this.genericParams[constraint.ownerRid - 1];
      if (!owner) {
        throw new FormatError(
          `GenericParamConstraint row ${constraint.rid} references missing GenericParam row ${constraint.ownerRid}`
        );
      }
      owner.constraints.push(constraint);
      if (constraint.constraint.table === 27) {
        let typeArity = 0;
        let methodArity = 0;
        if (owner.owner.table === 2) {
          typeArity = getGenericParameterArity(this.genericParams, 2, owner.owner.rid);
        } else if (owner.owner.table === 6) {
          const method = this.methods[owner.owner.rid - 1];
          const declaringType = this.types.find((type) => type.methodRids.includes(owner.owner.rid));
          typeArity = declaringType
            ? getGenericParameterArity(this.genericParams, 2, declaringType.rid)
            : 0;
          const methodSignature = method
            ? parseSignature(method.signature, { counts: this.tables.counts })
            : null;
          methodArity = methodSignature?.kind === "method" && methodSignature.generic
            ? methodSignature.genericParameterCount
            : 0;
        }
        validateTypeSpecGenericContext(this, constraint.constraint.rid, typeArity, methodArity);
      }
    }
    const moduleRow = this.tables.get("Module")[0];
    const assemblyRow = this.tables.get("Assembly")[0];
    this.module = moduleRow ? {
      generation: moduleRow.Generation,
      name: this.heaps.getString(moduleRow.Name),
      mvid: this.heaps.getGuid(moduleRow.Mvid),
      assembly: assemblyRow ? {
        name: this.heaps.getString(assemblyRow.Name),
        culture: this.heaps.getString(assemblyRow.Culture),
        version: [assemblyRow.MajorVersion, assemblyRow.MinorVersion, assemblyRow.BuildNumber, assemblyRow.RevisionNumber]
      } : null
    } : null;
    this.customAttributes = this.tables.get("CustomAttribute").map((row) => ({
      rid: row.rid,
      parent: row.Parent.target,
      constructor: row.Type.target,
      value: this.heaps.getBlob(row.Value)
    }));
    this.assemblyRefs = Object.freeze(this.assemblyRefs);
    this._bodyCache = new Map();
    this._patches = [];
    this._structuralBodies = new Map();
    this._addedMethodBodies = new Map();
    this._metadataDirty = false;
    this._heapStreams = null;
    this._resourceEdits = new Map();
    this._embeddedPortablePdbEdits = new Map();
    this._debugRecordEdits = new Map();
    this._portablePdbOffsetBaselines = new Map();
    this._clearResourcesDirectory = false;
  }

  #createStructuralState(methodRid) {
    const existing = this._structuralBodies.get(methodRid);
    const body = existing?.body ?? this.getMethodBody(methodRid);
    if (!body) throw new FormatError("Method has no CIL body");
    const state = createStructuralState(body);
    if (existing) state.maxStack = existing.maxStack;
    return state;
  }

  #commitStructuralState(methodRid, state) {
    const previousBody = this._bodyCache.get(methodRid);
    const offsetsChanged = previousBody &&
      (state.instructions.length !== previousBody.instructions.length ||
       state.instructions.some((instruction, index) =>
         instruction.offset !== previousBody.instructions[index]?.offset
       ));
    if (this.#hasDebugDirectory && offsetsChanged) {
      const embeddedPdbIndices = this.pe.debugDirectoryEntries.flatMap((entry, index) =>
        entry.embeddedPortablePdb ? [index] : []
      );
      if (embeddedPdbIndices.length !== 1) {
        throw new UnsupportedFormatError(
          "Instruction-offset changes cannot be combined with PE debug information without exactly one embedded Portable PDB"
        );
      }
      const debugEntryIndex = embeddedPdbIndices[0];
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      const pdb = this.#getPortablePdbForEdit(debugEntryIndex, entry);
      const methodCustomDebugInformation = pdb.customDebugInformation.filter((record) =>
        record.Parent.target?.table === 6 && record.Parent.target.rid === methodRid
      );
      if (methodCustomDebugInformation.some((record) =>
        !Array.isArray(record.stateMachineHoistedLocalScopes) &&
        !Array.isArray(record.editAndContinueStateMachineStateMap) &&
        !record.asyncMethodSteppingInformation &&
        !record.editAndContinueLocalSlotMap &&
        !record.editAndContinueLambdaAndClosureMap
      )) {
        throw new UnsupportedFormatError(
          "Instruction-offset changes cannot rewrite opaque method-scoped custom debug information"
        );
      }
      const methodInfo = pdb.methodDebugInformation[methodRid - 1];
      const baseline = this._portablePdbOffsetBaselines.get(methodRid) ?? {
        codeSize: previousBody.codeSize,
        localSignatureRid: methodInfo?.localSignatureRid ?? 0,
        points: methodInfo?.sequencePoints.map((point) => ({ ...point })) ?? [],
        scopes: (pdb.tables.rows.get(50) ?? [])
          .filter((scope) => scope.Method.rid === methodRid)
          .map((scope) => ({
            rid: scope.rid,
            startOffset: scope.StartOffset,
            endOffset: scope.StartOffset + scope.Length
          })),
        stateMachineHoistedLocalScopes: methodCustomDebugInformation
          .filter((record) => Array.isArray(record.stateMachineHoistedLocalScopes))
          .map((record) => ({
            rid: record.rid,
            scopes: record.stateMachineHoistedLocalScopes.map((scope) => ({ ...scope }))
          })),
        asyncMethodSteppingInformation: methodCustomDebugInformation
          .filter((record) => record.asyncMethodSteppingInformation)
          .map((record) => ({
            rid: record.rid,
            catchHandlerOffset: record.asyncMethodSteppingInformation.catchHandlerOffset,
            steps: record.asyncMethodSteppingInformation.steps.map((step) => ({ ...step }))
          }))
      };
      const offsets = new Map();
      for (const instruction of state.instructions) {
        if (instruction.originalOffset === null || instruction.originalOffset === undefined) continue;
        if (offsets.has(instruction.originalOffset)) {
          throw new FormatError("Structural IL state contains duplicate original instruction offsets");
        }
        offsets.set(instruction.originalOffset, instruction.offset);
      }
      offsets.set(baseline.codeSize, state.body.codeSize);
      const remapOffset = (oldOffset, context) => {
        const newOffset = offsets.get(oldOffset);
        if (newOffset === undefined) {
          throw new UnsupportedFormatError(
            `Cannot preserve Portable PDB ${context} at removed IL_${oldOffset.toString(16)}`
          );
        }
        return newOffset;
      };
      const points = baseline.points.map((point) => ({
        ...point,
        offset: remapOffset(point.offset, "sequence point")
      }));
      const scopes = baseline.scopes.map((scope) => {
        const startOffset = remapOffset(scope.startOffset, "local-scope start");
        const endOffset = remapOffset(scope.endOffset, "local-scope end");
        return {
          rid: scope.rid,
          startOffset,
          length: endOffset - startOffset
        };
      });
      const stateMachineHoistedLocalScopes = baseline.stateMachineHoistedLocalScopes.map(
        (record) => ({
          rid: record.rid,
          scopes: record.scopes.map((scope) => {
            const startOffset = remapOffset(
              scope.startOffset,
              "state-machine hoisted-local scope start"
            );
            const endOffset = remapOffset(
              scope.startOffset + scope.length,
              "state-machine hoisted-local scope end"
            );
            return { startOffset, length: endOffset - startOffset };
          })
        })
      );
      const asyncMethodSteppingInformation =
        baseline.asyncMethodSteppingInformation.map((record) => ({
          rid: record.rid,
          catchHandlerOffset: record.catchHandlerOffset < 0
            ? record.catchHandlerOffset
            : remapOffset(record.catchHandlerOffset, "async catch-handler offset"),
          steps: record.steps.map((step) => ({
            ...step,
            yieldOffset: remapOffset(step.yieldOffset, "async yield offset"),
            resumeOffset: remapOffset(step.resumeOffset, "async resume offset")
          }))
        }));
      if (points.some((point, index) =>
        index > 0 && point.offset <= points[index - 1].offset
      )) {
        throw new FormatError("Portable PDB sequence-point offsets are not strictly increasing after IL edits");
      }
      if (points.some((point) => point.offset >= state.body.codeSize) ||
          scopes.some((scope) => scope.length < 0 ||
            scope.startOffset + scope.length > state.body.codeSize) ||
          stateMachineHoistedLocalScopes.some((record) => record.scopes.some((scope) =>
            scope.length <= 0 || scope.startOffset + scope.length > state.body.codeSize
          )) ||
          asyncMethodSteppingInformation.some((record) =>
            record.catchHandlerOffset >= state.body.codeSize ||
            record.steps.some((step) =>
              step.yieldOffset >= state.body.codeSize ||
              step.resumeOffset >= state.body.codeSize
            )
          )) {
        throw new FormatError("Portable PDB offsets exceed the rewritten method body");
      }
      if (points.some((point, index) =>
        point.offset !== baseline.points[index]?.offset
      ) || scopes.some((scope, index) =>
        scope.startOffset !== baseline.scopes[index]?.startOffset ||
        scope.length !== baseline.scopes[index]?.endOffset -
          baseline.scopes[index]?.startOffset
      ) || stateMachineHoistedLocalScopes.some((record, index) =>
        record.scopes.some((scope, scopeIndex) =>
          scope.startOffset !== baseline.stateMachineHoistedLocalScopes[index]
            ?.scopes[scopeIndex]?.startOffset ||
          scope.length !== baseline.stateMachineHoistedLocalScopes[index]
            ?.scopes[scopeIndex]?.length
        )
      ) || asyncMethodSteppingInformation.some((record, index) =>
        record.catchHandlerOffset !== baseline.asyncMethodSteppingInformation[index]
          ?.catchHandlerOffset ||
        record.steps.some((step, stepIndex) =>
          step.yieldOffset !== baseline.asyncMethodSteppingInformation[index]
            ?.steps[stepIndex]?.yieldOffset ||
          step.resumeOffset !== baseline.asyncMethodSteppingInformation[index]
            ?.steps[stepIndex]?.resumeOffset
        )
      )) {
        const updatedPdb = replacePortablePdbMethodOffsets(
          pdb,
          methodRid,
          {
            sequencePoints: baseline.points.length > 0 ? points : null,
            localSignatureRid: baseline.localSignatureRid,
            scopes,
            stateMachineHoistedLocalScopes,
            asyncMethodSteppingInformation
          }
        );
        this.replaceEmbeddedPortablePdb(debugEntryIndex, updatedPdb);
      }
      this._portablePdbOffsetBaselines.set(methodRid, baseline);
    }
    this._addedMethodBodies.delete(methodRid);
    this._structuralBodies.set(methodRid, state);
    this._bodyCache.set(methodRid, state.body);
  }

  #getPortablePdbForEdit(debugEntryIndex, entry) {
    const replacement = this._embeddedPortablePdbEdits.get(debugEntryIndex);
    return replacement
      ? parseEmbeddedPortablePdbData(replacement, 0, replacement.length)
      : entry.embeddedPortablePdb;
  }

  static from(input) {
    return new Assembly(input);
  }

  get modified() {
    return this._patches.length > 0 || this._structuralBodies.size > 0 ||
      this._addedMethodBodies.size > 0 || this._metadataDirty ||
      this._resourceEdits.size > 0 || this._clearResourcesDirectory ||
      this.#strongNamePrivateKey !== null;
  }

  get bytes() {
    return Uint8Array.from(this.#bytes);
  }

  getMethodBody(methodRid) {
    if (!Number.isInteger(methodRid) || methodRid < 1 || methodRid > this.methods.length) {
      throw new RangeError(`Invalid MethodDef row ID ${methodRid}`);
    }
    if (this._bodyCache.has(methodRid)) return this._bodyCache.get(methodRid);
    const method = this.methods[methodRid - 1];
    if (method.rva === 0) return null;
    const offset = this.pe.rvaToOffset(method.rva, 1);
    const body = parseMethodBody(this.#bytes, offset, method.rva);
    validateGenericUsesInBody(this, method, body);
    this._bodyCache.set(methodRid, body);
    return body;
  }

  getInstructions(methodRid) {
    return this.getMethodBody(methodRid)?.instructions ?? [];
  }

  parseCustomAttribute(rid, { resolveEnum } = {}) {
    if (!Number.isInteger(rid) || rid < 1 || rid > this.customAttributes.length) {
      throw new RangeError(`Invalid CustomAttribute row ID ${rid}`);
    }
    const attribute = this.customAttributes[rid - 1];
    const enumResolver = getCustomAttributeEnumResolver(this, resolveEnum);
    const { fixedTypes, localOwnerType, typeArguments } =
      getCustomAttributeConstructor(this, attribute, enumResolver);
    const parsed = parseCustomAttributeBlob(
      attribute.value,
      fixedTypes,
      enumResolver
    );
    validateLocalCustomAttributeNamedArguments(
      this,
      localOwnerType,
      typeArguments,
      parsed.namedArguments,
      enumResolver
    );
    return parsed;
  }

  parseDeclSecurity(rid, { resolveEnum } = {}) {
    const row = this.tables.row(14, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid DeclSecurity row ID ${rid}`);
    }
    const enumResolver = getCustomAttributeEnumResolver(this, resolveEnum);
    const permissionSet = parsePermissionSetBlob(
      this.heaps.getBlob(row.PermissionSet),
      enumResolver
    );
    validateLocalPermissionSetNamedArguments(this, permissionSet, enumResolver);
    return {
      rid,
      action: row.Action,
      parent: row.Parent.target,
      permissionSet
    };
  }

  replaceCustomAttribute(rid, value, { resolveEnum } = {}) {
    this.#ensureEditable();
    if (!Number.isInteger(rid) || rid < 1 || rid > this.customAttributes.length) {
      throw new RangeError(`Invalid CustomAttribute row ID ${rid}`);
    }
    const attribute = this.customAttributes[rid - 1];
    const enumResolver = getCustomAttributeEnumResolver(this, resolveEnum);
    const { fixedTypes, localOwnerType, typeArguments } =
      getCustomAttributeConstructor(this, attribute, enumResolver);
    const encoded = encodeCustomAttributeBlob(value, fixedTypes);
    const parsed = parseCustomAttributeBlob(encoded, fixedTypes, enumResolver);
    validateLocalCustomAttributeNamedArguments(
      this,
      localOwnerType,
      typeArguments,
      parsed.namedArguments,
      enumResolver
    );
    const row = this.tables.row(12, rid);
    if (!row) throw new FormatError(`CustomAttribute row ${rid} is missing from metadata tables`);
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), encoded);
    heapStreams.set("#Blob", blob.heap);
    row.Value = blob.index;
    attribute.value = encoded.slice();
    attribute.parsedValue = parsed;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  addCustomAttribute({ parent, constructor, value, resolveEnum }) {
    return this.#writeCustomAttribute(
      { parent, constructor, value, resolveEnum },
      false
    ).token;
  }

  insertCustomAttribute({ parent, constructor, value, resolveEnum }) {
    return this.#writeCustomAttribute(
      { parent, constructor, value, resolveEnum },
      true
    );
  }

  #writeCustomAttribute({ parent, constructor, value, resolveEnum }, insertSorted) {
    this.#ensureEditable();
    const parentTable = metadataTableId(parent?.table);
    if (!parent || parentTable < 0 || !Number.isInteger(parent.rid) || parent.rid < 1 ||
        parent.rid > (this.tables.counts[parentTable] ?? 0)) {
      throw new RangeError("CustomAttribute parent must identify an existing metadata row");
    }
    const constructorTable = metadataTableId(constructor?.table);
    if (!constructor || ![6, 10].includes(constructorTable) || !Number.isInteger(constructor.rid) ||
        constructor.rid < 1 || constructor.rid > (this.tables.counts[constructorTable] ?? 0)) {
      throw new RangeError("CustomAttribute constructor must identify an existing MethodDef or MemberRef row");
    }
    const customRows = this.tables.rows.get(12) ?? [];
    if (customRows.length >= 0x00ffffff) {
      throw new RangeError("CustomAttribute token row ID exceeds 24-bit range");
    }
    const parentRaw = encodeCodedIndex(parentTable, parent.rid, "HasCustomAttribute");
    const constructorRaw = encodeCodedIndex(constructorTable, constructor.rid, "CustomAttributeType");
    let insertionIndex = customRows.length;
    if (insertSorted) {
      for (let index = 1; index < customRows.length; index++) {
        if (customRows[index - 1].Parent.raw > customRows[index].Parent.raw) {
          throw new UnsupportedFormatError(
            "Sorted CustomAttribute insertion requires rows already ordered by Parent"
          );
        }
      }
      const laterParent = customRows.findIndex((row) => row.Parent.raw > parentRaw);
      if (laterParent !== -1) insertionIndex = laterParent;
    } else if ((this.tables.sorted & (1n << 12n)) !== 0n &&
        customRows.at(-1)?.Parent.raw > parentRaw) {
      throw new FormatError("Appending this CustomAttribute would violate the table's sorted Parent order");
    }
    const rid = insertionIndex + 1;
    if (rid > 0x00ffffff) {
      throw new RangeError("CustomAttribute token row ID exceeds 24-bit range");
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(12, rid, customRows.length, "CustomAttribute");

    const enumResolver = getCustomAttributeEnumResolver(this, resolveEnum);
    const newAttribute = {
      rid,
      parent: { table: parentTable, tableName: metadataTableNames[parentTable], rid: parent.rid },
      constructor: {
        table: constructorTable,
        tableName: metadataTableNames[constructorTable],
        rid: constructor.rid
      },
      value: new Uint8Array()
    };
    const { fixedTypes, localOwnerType, typeArguments } =
      getCustomAttributeConstructor(this, newAttribute, enumResolver);
    const encoded = encodeCustomAttributeBlob(value, fixedTypes);
    const parsed = parseCustomAttributeBlob(encoded, fixedTypes, enumResolver);
    validateLocalCustomAttributeNamedArguments(
      this,
      localOwnerType,
      typeArguments,
      parsed.namedArguments,
      enumResolver
    );
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), encoded);
    heapStreams.set("#Blob", blob.heap);

    const newRow = {
      table: 12,
      tableName: metadataTableNames[12],
      rid,
      Parent: { raw: parentRaw, target: newAttribute.parent },
      Type: { raw: constructorRaw, target: newAttribute.constructor },
      Value: blob.index
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of customRows) {
      if (row.rid >= rid) row.rid++;
    }
    customRows.splice(insertionIndex, 0, newRow);
    this.tables.rows.set(12, customRows);
    this.tables.valid |= 1n << 12n;
    this.tables.counts[12] = customRows.length;
    newAttribute.value = encoded.slice();
    newAttribute.parsedValue = parsed;
    for (const attribute of this.customAttributes) {
      if (attribute.rid >= rid) attribute.rid++;
    }
    this.customAttributes.splice(insertionIndex, 0, newAttribute);
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { token: 0x0c000000 + rid, rid, tokenMap };
  }

  removeCustomAttribute(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError(
        "CustomAttribute removal cannot be combined with structural method edits"
      );
    }
    this.#ensureTokenRemappingSafe("CustomAttribute");
    const rows = this.tables.rows.get(12) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid CustomAttribute row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap CustomAttribute tokens with unrecognized metadata stream ${streamName}`
        );
      }
    }
    if (this.customAttributes.length !== rows.length ||
        this.customAttributes.some((attribute, index) => attribute.rid !== index + 1)) {
      throw new FormatError("CustomAttribute semantic rows do not match the metadata table");
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        const columnName = name ?? value;
        if (kind !== "u4" || columnName !== "Token" || ![30, 31].includes(tableId)) continue;
        for (const row of tableRows) {
          const token = row[columnName];
          if ((token >>> 24) !== 0x0c) continue;
          const targetRid = token & 0x00ffffff;
          if (targetRid === rid) {
            throw new FormatError(`CustomAttribute row ${rid} is referenced by ${metadataTableNames[tableId]}.Token`);
          }
          if (targetRid > rid) {
            rowChanges.push({
              row,
              columnName,
              value: 0x0c000000 + targetRid - 1
            });
          }
        }
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x0c) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing CustomAttribute row ${targetRid}`);
        }
        if (targetRid === rid) {
          throw new FormatError(`CustomAttribute row ${rid} is referenced by CIL`);
        }
        if (targetRid > rid) {
          const replacement = 0x0c000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x0c000000 + oldRid, 0x0c000000 + oldRid - 1);
    }

    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingAttributes = this.customAttributes.filter((attribute) => attribute.rid !== rid);
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    remainingAttributes.forEach((attribute, index) => {
      attribute.rid = index + 1;
    });
    this.tables.rows.set(12, remainingRows);
    this.tables.counts[12] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 12n);
    this.customAttributes.splice(0, this.customAttributes.length, ...remainingAttributes);
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  replaceMethodSignature(rid, signature) {
    this.#ensureEditable();
    if (!Number.isInteger(rid) || rid < 1 || rid > this.methods.length) {
      throw new RangeError(`Invalid MethodDef row ID ${rid}`);
    }
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
      throw new TypeError("Method signature must be a non-empty Uint8Array");
    }
    const parsed = parseSignature(signature, { counts: this.tables.counts });
    if (parsed.kind !== "method") {
      throw new FormatError("MethodDef signature must use the method signature form");
    }
    const declaringType = this.types.find((type) => type.methodRids.includes(rid));
    const typeArity = declaringType
      ? getGenericParameterArity(this.genericParams, 2, declaringType.rid)
      : 0;
    validateGenericVariableReferences(parsed, typeArity, this);
    const existingParams = this.genericParams.filter((parameter) =>
      parameter.owner.table === 6 && parameter.owner.rid === rid
    );
    if (existingParams.some((parameter) =>
      !parsed.generic || parameter.number >= parsed.genericParameterCount
    )) {
      throw new FormatError("Replacement method signature is incompatible with its GenericParam rows");
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Blob", blob.heap);
    const method = this.methods[rid - 1];
    method.row.Signature = blob.index;
    method.signature = signature.slice();
    method.parsedSignature = parsed;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  replaceMethod(rid, { name, flags, implFlags } = {}) {
    this.#ensureEditable();
    const method = this.methods[rid - 1];
    if (!Number.isInteger(rid) || rid < 1 || !method) {
      throw new RangeError(`Invalid MethodDef row ID ${rid}`);
    }
    const nextName = name === undefined ? method.name : name;
    const nextFlags = flags === undefined ? method.row.Flags : flags;
    const nextImplFlags = implFlags === undefined ? method.row.ImplFlags : implFlags;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("Method name must be a non-empty null-free string");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 0xffff) {
      throw new RangeError("Method flags must be an unsigned 16-bit integer");
    }
    if (!Number.isInteger(nextImplFlags) || nextImplFlags < 0 || nextImplFlags > 0xffff) {
      throw new RangeError("Method implementation flags must be an unsigned 16-bit integer");
    }
    if (nextName === method.name && nextFlags === method.row.Flags &&
        nextImplFlags === method.row.ImplFlags) return this;
    this.#validateAssociatedFlags(6, rid, nextFlags);

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== method.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      method.row.Name = stringHeap.index;
    }
    method.row.Flags = nextFlags;
    method.row.ImplFlags = nextImplFlags;
    method.name = nextName;
    method.flags = nextFlags;
    method.implFlags = nextImplFlags;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  addTypeDef({ name, namespace = "", flags = 0, extends: baseType = null }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("TypeDef name must be a non-empty null-free string");
    }
    if (typeof namespace !== "string" || namespace.includes("\0")) {
      throw new TypeError("TypeDef namespace must be a null-free string");
    }
    if (name === "<Module>" && namespace === "") {
      throw new FormatError("The special <Module> TypeDef must remain unique to the first row");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffffffff) {
      throw new RangeError("TypeDef flags must be an unsigned 32-bit integer");
    }
    const rows = this.tables.rows.get(2) ?? [];
    if (rows.length !== this.tables.counts[2] || rows.length >= 0x00ffffff) {
      throw new RangeError("TypeDef row count is inconsistent or exceeds the metadata token range");
    }
    let baseTarget = null;
    if (baseType !== null) {
      const baseTable = metadataTableId(baseType?.table);
      if (![1, 2, 27].includes(baseTable) || !Number.isInteger(baseType.rid) ||
          baseType.rid < 1 || baseType.rid > (this.tables.counts[baseTable] ?? 0)) {
        throw new RangeError("TypeDef base type must identify an existing TypeDef, TypeRef, or TypeSpec row");
      }
      baseTarget = { table: baseTable, tableName: metadataTableNames[baseTable], rid: baseType.rid };
      if (baseTable === 27) validateTypeSpecGenericContext(this, baseType.rid, 0, 0);
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const nameHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const namespaceHeap = appendStringHeap(nameHeap.heap, namespace);
    heapStreams.set("#Strings", namespaceHeap.heap);
    const rid = rows.length + 1;
    const extendsRaw = baseTarget
      ? encodeCodedIndex(baseTarget.table, baseTarget.rid, "TypeDefOrRef")
      : 0;
    const fieldPointer = (this.tables.valid & (1n << 3n)) !== 0n;
    const methodPointer = (this.tables.valid & (1n << 5n)) !== 0n;
    const fieldListRid = (this.tables.counts[fieldPointer ? 3 : 4] ?? 0) + 1;
    const methodListRid = (this.tables.counts[methodPointer ? 5 : 6] ?? 0) + 1;
    const typeRow = {
      table: 2,
      tableName: metadataTableNames[2],
      rid,
      Flags: flags,
      TypeName: nameHeap.index,
      TypeNamespace: namespaceHeap.index,
      Extends: { raw: extendsRaw, target: baseTarget },
      FieldList: {
        raw: fieldListRid,
        table: fieldPointer ? 3 : 4,
        tableName: metadataTableNames[fieldPointer ? 3 : 4],
        rid: fieldListRid
      },
      MethodList: {
        raw: methodListRid,
        table: methodPointer ? 5 : 6,
        tableName: metadataTableNames[methodPointer ? 5 : 6],
        rid: methodListRid
      }
    };
    rows.push(typeRow);
    this.tables.rows.set(2, rows);
    this.tables.counts[2] = rid;
    this.tables.valid |= 1n << 2n;
    this.types.push({
      rid,
      flags,
      name,
      namespace,
      extends: baseTarget,
      fieldRids: [],
      methodRids: [],
      eventRids: [],
      propertyRids: [],
      methods: [],
      fields: [],
      events: [],
      properties: [],
      genericParams: []
    });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return 0x02000000 + rid;
  }

  insertTypeDef({ beforeRid, name, namespace = "", flags = 0, extends: baseType = null }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("TypeDef name must be a non-empty null-free string");
    }
    if (typeof namespace !== "string" || namespace.includes("\0")) {
      throw new TypeError("TypeDef namespace must be a null-free string");
    }
    if (name === "<Module>" && namespace === "") {
      throw new FormatError("The special <Module> TypeDef must remain unique to the first row");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffffffff) {
      throw new RangeError("TypeDef flags must be an unsigned 32-bit integer");
    }
    const rows = this.tables.rows.get(2) ?? [];
    if (rows.length !== (this.tables.counts[2] ?? 0) || rows.length !== this.types.length) {
      throw new FormatError("TypeDef row count is inconsistent with its semantic records");
    }
    if (!Number.isInteger(beforeRid) || beforeRid < 2 || beforeRid > rows.length + 1) {
      throw new RangeError(`Invalid TypeDef insertion position ${beforeRid}`);
    }
    if (rows.length >= 0x00ffffff) {
      throw new RangeError("TypeDef token row ID exceeds 24-bit range");
    }

    let baseTarget = null;
    if (baseType !== null) {
      const baseTable = metadataTableId(baseType?.table);
      if (![1, 2, 27].includes(baseTable) || !Number.isInteger(baseType.rid) ||
          baseType.rid < 1 || baseType.rid > (this.tables.counts[baseTable] ?? 0)) {
        throw new RangeError("TypeDef base type must identify an existing TypeDef, TypeRef, or TypeSpec row");
      }
      if (baseTable === 27) validateTypeSpecGenericContext(this, baseType.rid, 0, 0);
    }

    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(2, beforeRid, rows.length, "TypeDef");
    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    const sortedKeys = new Map([
      [9, (row) => [row.Class.rid]],
      [10, (row) => [row.Class.raw]],
      [12, (row) => [row.Parent.raw]],
      [14, (row) => [row.Parent.raw]],
      [15, (row) => [row.Parent.rid]],
      [18, (row) => [row.Parent.rid]],
      [21, (row) => [row.Parent.rid]],
      [25, (row) => [row.Class.rid]],
      [41, (row) => [row.NestedClass.rid]],
      [42, (row) => [row.Owner.raw, row.Number]]
    ]);
    for (const [tableId, keyOf] of sortedKeys) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = null;
      for (const row of this.tables.get(tableId)) {
        const changes = changesByRow.get(row);
        const current = keyOf(new Proxy(row, {
          get(target, property) {
            return changes?.get(property) ?? target[property];
          }
        }));
        let outOfOrder = false;
        if (previous) {
          for (let index = 0; index < current.length; index++) {
            if (current[index] === previous[index]) continue;
            outOfOrder = current[index] < previous[index];
            break;
          }
        }
        if (outOfOrder) {
          throw new FormatError(
            `TypeDef token remapping would violate sorted ${metadataTableNames[tableId]} order`
          );
        }
        previous = current;
      }
    }
    let portablePdbUpdate = null;
    if (beforeRid <= rows.length) {
      const oldCounts = [...this.tables.counts];
      const newCounts = [...oldCounts];
      newCounts[2]++;
      portablePdbUpdate = this.#preparePortablePdbTypeDefRemapping(
        beforeRid,
        oldCounts,
        newCounts,
        "insert"
      );
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const signatureColumns = new Map([
      [4, "Signature"], [6, "Signature"], [10, "Signature"], [17, "Signature"],
      [23, "Type"], [43, "Instantiation"]
    ]);
    const signatureChanges = [];
    const remapTypeRid = (oldRid) => oldRid >= beforeRid ? oldRid + 1 : oldRid;
    for (const [tableId, columnName] of signatureColumns) {
      for (const row of this.tables.get(tableId)) {
        const parsed = parseSignature(this.heaps.getBlob(row[columnName]), {
          counts: this.tables.counts
        });
        if (!rows.slice(beforeRid - 1).some((candidate) =>
          containsMetadataReference(parsed, 2, candidate.rid)
        )) continue;
        const remapped = remapTypeReferences(parsed, remapTypeRid, 2);
        const blob = appendBlobHeap(
          heapStreams.get("#Blob") ?? new Uint8Array(),
          encodeSignature(remapped)
        );
        heapStreams.set("#Blob", blob.heap);
        signatureChanges.push({ row, columnName, index: blob.index });
      }
    }
    for (const row of this.tables.get(27)) {
      const parsed = parseTypeSignature(this.heaps.getBlob(row.Signature), {
        counts: this.tables.counts
      });
      if (!rows.slice(beforeRid - 1).some((candidate) =>
        containsMetadataReference(parsed, 2, candidate.rid)
      )) continue;
      const remapped = remapTypeReferences(parsed, remapTypeRid, 2);
      const blob = appendBlobHeap(
        heapStreams.get("#Blob") ?? new Uint8Array(),
        encodeTypeSignature(remapped)
      );
      heapStreams.set("#Blob", blob.heap);
      signatureChanges.push({ row, columnName: "Signature", index: blob.index });
    }

    const tokenUpdatesForExceptions = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      const catchRemaps = collectCatchTokenRemaps(
        body,
        2,
        rows.length,
        remapTypeRid,
        "TypeDef"
      );
      patches.push(...catchRemaps.patches);
      tokenUpdatesForExceptions.push(...catchRemaps.updates);
    }

    const nameHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const namespaceHeap = appendStringHeap(nameHeap.heap, namespace);
    heapStreams.set("#Strings", namespaceHeap.heap);
    if (baseType !== null) {
      const baseTable = metadataTableId(baseType.table);
      const baseRid = baseTable === 2 && baseType.rid >= beforeRid
        ? baseType.rid + 1
        : baseType.rid;
      baseTarget = { table: baseTable, tableName: metadataTableNames[baseTable], rid: baseRid };
    }
    const fieldPointer = (this.tables.valid & (1n << 3n)) !== 0n;
    const methodPointer = (this.tables.valid & (1n << 5n)) !== 0n;
    const fieldListRid = beforeRid <= rows.length
      ? rows[beforeRid - 1].FieldList.rid
      : (this.tables.counts[fieldPointer ? 3 : 4] ?? 0) + 1;
    const methodListRid = beforeRid <= rows.length
      ? rows[beforeRid - 1].MethodList.rid
      : (this.tables.counts[methodPointer ? 5 : 6] ?? 0) + 1;
    const rid = beforeRid;
    const row = {
      table: 2,
      tableName: metadataTableNames[2],
      rid,
      Flags: flags,
      TypeName: nameHeap.index,
      TypeNamespace: namespaceHeap.index,
      Extends: {
        raw: baseTarget
          ? encodeCodedIndex(baseTarget.table, baseTarget.rid, "TypeDefOrRef")
          : 0,
        target: baseTarget
      },
      FieldList: {
        raw: fieldListRid,
        table: fieldPointer ? 3 : 4,
        tableName: metadataTableNames[fieldPointer ? 3 : 4],
        rid: fieldListRid
      },
      MethodList: {
        raw: methodListRid,
        table: methodPointer ? 5 : 6,
        tableName: metadataTableNames[methodPointer ? 5 : 6],
        rid: methodListRid
      }
    };

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of signatureChanges) change.row[change.columnName] = change.index;
    rows.splice(rid - 1, 0, row);
    rows.forEach((typeRow, index) => {
      typeRow.rid = index + 1;
    });
    this.tables.rows.set(2, rows);
    this.tables.valid |= 1n << 2n;
    this.tables.counts[2] = rows.length;
    this.types.splice(rid - 1, 0, {
      rid,
      flags,
      name,
      namespace,
      extends: baseTarget,
      fieldRids: [],
      methodRids: [],
      eventRids: [],
      propertyRids: [],
      methods: [],
      fields: [],
      events: [],
      properties: [],
      genericParams: []
    });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this.types.forEach((type, index) => {
      type.rid = index + 1;
      type.extends = this.tables.row(2, type.rid).Extends.target;
      for (const event of type.events) {
        event.eventType = this.tables.row(20, event.rid).EventType.target;
      }
    });
    for (const typeRef of this.typeRefs) {
      typeRef.resolutionScope = this.tables.row(1, typeRef.rid).ResolutionScope.target;
    }
    for (const memberRef of this.memberRefs) {
      const memberRow = this.tables.row(10, memberRef.rid);
      memberRef.parent = memberRow.Class.target;
      memberRef.signature = this.heaps.getBlob(memberRow.Signature);
    }
    for (const parameter of this.genericParams) {
      parameter.owner = this.tables.row(42, parameter.rid).Owner.target;
    }
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    for (const constraint of this.genericParamConstraints) {
      constraint.constraint = this.tables.row(44, constraint.rid).Constraint.target;
    }
    for (const type of this.types) {
      for (const field of type.fields) {
        field.signature = this.heaps.getBlob(this.tables.row(4, field.rid).Signature);
      }
      for (const property of type.properties) {
        property.signature = this.heaps.getBlob(this.tables.row(23, property.rid).Type);
      }
    }
    for (const method of this.methods) {
      method.signature = this.heaps.getBlob(method.row.Signature);
    }
    for (const typeSpec of this.typeSpecs) {
      const typeSpecRow = this.tables.row(27, typeSpec.rid);
      typeSpec.signature = this.heaps.getBlob(typeSpecRow.Signature);
      typeSpec.parsedSignature = parseTypeSignature(typeSpec.signature, {
        counts: this.tables.counts
      });
    }
    for (const methodSpec of this.methodSpecs) {
      const methodSpecRow = this.tables.row(43, methodSpec.rid);
      methodSpec.instantiation = this.heaps.getBlob(methodSpecRow.Instantiation);
      methodSpec.parsedInstantiation = parseSignature(methodSpec.instantiation, {
        counts: this.tables.counts
      });
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    for (const update of tokenUpdatesForExceptions) {
      update.clause.classTokenOrFilterOffset = update.replacement;
    }
    this._patches.push(...patches);
    this._metadataDirty = true;
    this.#applyPortablePdbTypeDefRemapping(portablePdbUpdate);
    return { token: 0x02000000 + rid, tokenMap };
  }

  replaceTypeDef(rid, { name, namespace, flags, extends: baseType } = {}) {
    this.#ensureEditable();
    const type = this.types[rid - 1];
    const row = this.tables.row(2, rid);
    if (!Number.isInteger(rid) || rid < 1 || !type || !row) {
      throw new RangeError(`Invalid TypeDef row ID ${rid}`);
    }
    const nextName = name === undefined ? type.name : name;
    const nextNamespace = namespace === undefined ? type.namespace : namespace;
    const nextFlags = flags === undefined ? type.flags : flags;
    const nextBaseType = baseType === undefined ? type.extends : baseType;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("TypeDef name must be a non-empty null-free string");
    }
    if (typeof nextNamespace !== "string" || nextNamespace.includes("\0")) {
      throw new TypeError("TypeDef namespace must be a null-free string");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 0xffffffff) {
      throw new RangeError("TypeDef flags must be an unsigned 32-bit integer");
    }
    if (rid === 1 && (nextName !== "<Module>" || nextNamespace !== "")) {
      throw new FormatError("The first TypeDef must remain the special <Module> type");
    }
    let nextBaseTarget = null;
    if (nextBaseType !== null) {
      const baseTable = metadataTableId(nextBaseType?.table);
      if (![1, 2, 27].includes(baseTable) || !Number.isInteger(nextBaseType.rid) ||
          nextBaseType.rid < 1 || nextBaseType.rid > (this.tables.counts[baseTable] ?? 0)) {
        throw new RangeError("TypeDef base type must identify an existing TypeDef, TypeRef, or TypeSpec row");
      }
      if (baseTable === 2 && nextBaseType.rid === rid) {
        throw new FormatError("A TypeDef cannot extend itself");
      }
      nextBaseTarget = {
        table: baseTable,
        tableName: metadataTableNames[baseTable],
        rid: nextBaseType.rid
      };
      if (baseTable === 27) {
        validateTypeSpecGenericContext(
          this,
          nextBaseType.rid,
          getGenericParameterArity(this.genericParams, 2, rid),
          0
        );
      }
    }
    const baseUnchanged = type.extends?.table === nextBaseTarget?.table &&
      type.extends?.rid === nextBaseTarget?.rid;
    if (nextName === type.name && nextNamespace === type.namespace &&
        nextFlags === type.flags && baseUnchanged) return this;
    this.#validateAssociatedFlags(2, rid, nextFlags);

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== type.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.TypeName = stringHeap.index;
    }
    if (nextNamespace !== type.namespace) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextNamespace);
      heapStreams.set("#Strings", stringHeap.heap);
      row.TypeNamespace = stringHeap.index;
    }
    row.Flags = nextFlags;
    row.Extends = nextBaseTarget
      ? {
          raw: encodeCodedIndex(nextBaseTarget.table, nextBaseTarget.rid, "TypeDefOrRef"),
          target: nextBaseTarget
        }
      : { raw: 0, target: null };
    type.name = nextName;
    type.namespace = nextNamespace;
    type.flags = nextFlags;
    type.extends = nextBaseTarget;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeTypeDef(rid) {
    this.#ensureEditable();
    const rows = this.tables.rows.get(2) ?? [];
    const type = this.types[rid - 1];
    if (rows.length !== this.tables.counts[2] || rows.length !== this.types.length) {
      throw new FormatError("TypeDef row count is inconsistent with its semantic records");
    }
    if (!Number.isInteger(rid) || rid < 2 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid || !type) {
      throw new RangeError(`Invalid non-module TypeDef row ID ${rid}`);
    }
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("TypeDef removal cannot be combined with structural method edits");
    }
    const shiftsTypeRids = rid < rows.length;
    this.#ensureTokenRemappingSafe("TypeDef");
    if (shiftsTypeRids) {
      if (this._addedMethodBodies.size > 0) {
        throw new UnsupportedFormatError(
          "TypeDef RID remapping cannot be combined with added method bodies"
        );
      }
    }
    if (type.fieldRids.length || type.methodRids.length ||
        type.eventRids.length || type.propertyRids.length || type.genericParams.length) {
      throw new UnsupportedFormatError("TypeDef removal requires an owner with no fields, methods, events, properties, or generic parameters");
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remove TypeDef rows with unrecognized metadata stream ${streamName}`
        );
      }
    }
    for (const [tableId, tableRows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      if (!schema) {
        throw new UnsupportedFormatError(`Cannot check TypeDef references in unknown metadata table ${tableId}`);
      }
      for (const [kind, value, columnName] of schema) {
        const name = columnName ?? value;
        for (const row of tableRows) {
          const column = row[name];
          const target = kind === "coded"
            ? column?.target
            : kind === "table"
              ? { table: column?.table ?? value, rid: column?.rid }
              : null;
          if (target?.table === 2 && target.rid === rid) {
            throw new FormatError(
              `TypeDef row ${rid} is referenced by ${metadataTableNames[tableId]}.${name}`
            );
          }
          if (kind === "u4" && [30, 31].includes(tableId)) {
            const token = column ?? 0;
            if ((token >>> 24) === 0x02 && (token & 0x00ffffff) === rid) {
              throw new FormatError(
                `TypeDef row ${rid} is referenced by ${metadataTableNames[tableId]}.${name}`
              );
            }
          }
        }
      }
    }

    const tokenMap = new Map();
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x02000000 + oldRid, 0x02000000 + oldRid - 1);
    }
    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      for (const row of tableRows) {
        for (const [kind, value, columnName] of schema) {
          const name = columnName ?? value;
          if (kind === "u4" && [30, 31].includes(tableId) && name === "Token" &&
              (row[name] >>> 24) === 0x02) {
            const targetRid = row[name] & 0x00ffffff;
            if (targetRid > rid) {
              rowChanges.push({ row, columnName: name, value: row[name] - 1 });
            }
            continue;
          }
          const target = kind === "coded"
            ? row[name]?.target
            : kind === "table" ? row[name] : null;
          if (target?.table !== 2 || target.rid <= rid) continue;
          const remappedTarget = { ...target, rid: target.rid - 1 };
          rowChanges.push({
            row,
            columnName: name,
            value: kind === "coded"
              ? {
                raw: encodeCodedIndex(2, remappedTarget.rid, value),
                target: remappedTarget
              }
              : { ...target, raw: remappedTarget.rid, rid: remappedTarget.rid }
          });
        }
      }
    }
    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    const sortedKeys = new Map([
      [9, (row) => [row.Class.rid]],
      [10, (row) => [row.Class.raw]],
      [12, (row) => [row.Parent.raw]],
      [14, (row) => [row.Parent.raw]],
      [15, (row) => [row.Parent.rid]],
      [18, (row) => [row.Parent.rid]],
      [21, (row) => [row.Parent.rid]],
      [25, (row) => [row.Class.rid]],
      [41, (row) => [row.NestedClass.rid]],
      [42, (row) => [row.Owner.raw, row.Number]]
    ]);
    for (const [tableId, keyOf] of sortedKeys) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = null;
      for (const row of this.tables.get(tableId)) {
        const changes = changesByRow.get(row);
        const current = keyOf(new Proxy(row, {
          get(target, property) {
            return changes?.get(property) ?? target[property];
          }
        }));
        let outOfOrder = false;
        if (previous) {
          for (let index = 0; index < current.length; index++) {
            if (current[index] === previous[index]) continue;
            outOfOrder = current[index] < previous[index];
            break;
          }
        }
        if (outOfOrder) {
          throw new FormatError(
            `TypeDef token remapping would violate sorted ${metadataTableNames[tableId]} order`
          );
        }
        previous = current;
      }
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const signatureColumns = new Map([
      [4, "Signature"], [6, "Signature"], [10, "Signature"], [17, "Signature"],
      [23, "Type"], [43, "Instantiation"]
    ]);
    const signatureChanges = [];
    const remapTypeRid = (oldRid) => oldRid > rid ? oldRid - 1 : oldRid;
    for (const [tableId, columnName] of signatureColumns) {
      for (const row of this.tables.get(tableId)) {
        const parsed = parseSignature(this.heaps.getBlob(row[columnName]), {
          counts: this.tables.counts
        });
        if (containsMetadataReference(parsed, 2, rid)) {
          throw new FormatError(
            `TypeDef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
          );
        }
        const shiftedReference = shiftsTypeRids && rows.slice(rid).some((candidate) =>
          containsMetadataReference(parsed, 2, candidate.rid)
        );
        if (!shiftedReference) continue;
        const remapped = remapTypeReferences(parsed, remapTypeRid, 2);
        const blob = appendBlobHeap(
          heapStreams.get("#Blob") ?? new Uint8Array(),
          encodeSignature(remapped)
        );
        heapStreams.set("#Blob", blob.heap);
        signatureChanges.push({ row, columnName, index: blob.index });
      }
    }
    for (const row of this.tables.get(27)) {
      const parsed = parseTypeSignature(this.heaps.getBlob(row.Signature), {
        counts: this.tables.counts
      });
      if (containsMetadataReference(parsed, 2, rid)) {
        throw new FormatError(`TypeDef row ${rid} is referenced by TypeSpec.Signature`);
      }
      const shiftedReference = shiftsTypeRids && rows.slice(rid).some((candidate) =>
        containsMetadataReference(parsed, 2, candidate.rid)
      );
      if (!shiftedReference) continue;
      const remapped = remapTypeReferences(parsed, remapTypeRid, 2);
      const blob = appendBlobHeap(
        heapStreams.get("#Blob") ?? new Uint8Array(),
        encodeTypeSignature(remapped)
      );
      heapStreams.set("#Blob", blob.heap);
      signatureChanges.push({ row, columnName: "Signature", index: blob.index });
    }

    const tokenUpdates = [];
    const exceptionTokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x02) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing TypeDef row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`TypeDef row ${rid} is referenced by CIL`);
        if (shiftsTypeRids && targetRid > rid) {
          const replacement = token - 1;
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
      const catchRemaps = collectCatchTokenRemaps(
        body,
        2,
        rows.length,
        (oldRid) => shiftsTypeRids && oldRid > rid ? oldRid - 1 : oldRid,
        "TypeDef",
        rid
      );
      patches.push(...catchRemaps.patches);
      exceptionTokenUpdates.push(...catchRemaps.updates);
    }

    const oldCounts = [...this.tables.counts];
    const newCounts = [...oldCounts];
    newCounts[2]--;
    const portablePdbUpdate = this.#preparePortablePdbTypeDefRemapping(
      rid,
      oldCounts,
      newCounts,
      "remove"
    );
    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingTypes = this.types.filter((candidate) => candidate.rid !== rid);
    if (remainingRows.length !== remainingTypes.length) {
      throw new FormatError(`TypeDef row ${rid} has no semantic record`);
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of signatureChanges) change.row[change.columnName] = change.index;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
      remainingTypes[index].rid = index + 1;
    });
    this.tables.rows.set(2, remainingRows);
    this.tables.counts[2] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 2n);
    this.types.splice(0, this.types.length, ...remainingTypes);
    for (const candidate of this.types) {
      candidate.extends = this.tables.row(2, candidate.rid).Extends.target;
      for (const event of candidate.events) {
        event.eventType = this.tables.row(20, event.rid).EventType.target;
      }
    }
    for (const typeRef of this.typeRefs) {
      typeRef.resolutionScope = this.tables.row(1, typeRef.rid).ResolutionScope.target;
    }
    for (const memberRef of this.memberRefs) {
      const row = this.tables.row(10, memberRef.rid);
      memberRef.parent = row.Class.target;
      memberRef.signature = this.heaps.getBlob(row.Signature);
    }
    for (const parameter of this.genericParams) {
      parameter.owner = this.tables.row(42, parameter.rid).Owner.target;
    }
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    for (const constraint of this.genericParamConstraints) {
      constraint.constraint = this.tables.row(44, constraint.rid).Constraint.target;
    }
    if (signatureChanges.length > 0) {
      this._heapStreams = heapStreams;
      this.#refreshHeaps();
      for (const candidate of this.types) {
        for (const field of candidate.fields) {
          field.signature = this.heaps.getBlob(this.tables.row(4, field.rid).Signature);
        }
        for (const property of candidate.properties) {
          property.signature = this.heaps.getBlob(this.tables.row(23, property.rid).Type);
        }
      }
      for (const method of this.methods) {
        method.signature = this.heaps.getBlob(method.row.Signature);
      }
      for (const memberRef of this.memberRefs) {
        const row = this.tables.row(10, memberRef.rid);
        memberRef.signature = this.heaps.getBlob(row.Signature);
      }
      for (const typeSpec of this.typeSpecs) {
        const row = this.tables.row(27, typeSpec.rid);
        typeSpec.signature = this.heaps.getBlob(row.Signature);
        typeSpec.parsedSignature = parseTypeSignature(typeSpec.signature, {
          counts: this.tables.counts
        });
      }
      for (const methodSpec of this.methodSpecs) {
        const row = this.tables.row(43, methodSpec.rid);
        methodSpec.instantiation = this.heaps.getBlob(row.Instantiation);
        methodSpec.parsedInstantiation = parseSignature(methodSpec.instantiation, {
          counts: this.tables.counts
        });
      }
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    for (const update of exceptionTokenUpdates) {
      update.clause.classTokenOrFilterOffset = update.replacement;
    }
    this._patches.push(...patches);
    this._metadataDirty = true;
    this.#applyPortablePdbTypeDefRemapping(portablePdbUpdate);
    return shiftsTypeRids ? tokenMap : this;
  }

  replaceCodeViewPath(debugEntryIndex, path) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    if (typeof path !== "string" || path.length === 0 || path.includes("\0")) {
      throw new TypeError("CodeView PDB path must be a non-empty null-free string");
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    const codeView = entry.codeView;
    if (entry.type !== 2 || !codeView || !["RSDS", "NB10"].includes(codeView.format)) {
      throw new UnsupportedFormatError("Debug-directory entry is not a supported CodeView record");
    }
    const encodedPath = new TextEncoder().encode(path);
    if (new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(encodedPath) !== path) {
      throw new TypeError("CodeView PDB path must be valid UTF-8 text");
    }
    const pathSlotSize = entry.sizeOfData - codeView.pathOffset;
    if (encodedPath.length + 1 > pathSlotSize) {
      throw new UnsupportedFormatError(
        "CodeView PDB path replacement must fit within its existing record"
      );
    }
    const dataOffset = entry.pointerToRawData !== 0
      ? entry.pointerToRawData
      : this.pe.rvaToOffset(entry.addressOfRawData, entry.sizeOfData);
    const pathBytes = new Uint8Array(pathSlotSize);
    pathBytes.set(encodedPath);
    this._patches.push({
      offset: dataOffset + codeView.pathOffset,
      bytes: pathBytes
    });
    const stagedDebugRecord = this._debugRecordEdits.get(debugEntryIndex);
    if (stagedDebugRecord) {
      const stagedBytes = Uint8Array.from(stagedDebugRecord.bytes);
      stagedBytes.set(pathBytes, codeView.pathOffset);
      this._debugRecordEdits.set(debugEntryIndex, {
        ...stagedDebugRecord,
        bytes: stagedBytes
      });
    }
    codeView.path = path;
    codeView.pathByteLength = encodedPath.length;
    return this;
  }

  replaceEmbeddedPortablePdb(debugEntryIndex, data) {
    return this.#replaceEmbeddedPortablePdb(debugEntryIndex, data, this.tables.counts);
  }

  #replaceEmbeddedPortablePdb(debugEntryIndex, data, assemblyRowCounts) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    if (!(data instanceof Uint8Array)) {
      throw new TypeError("Embedded Portable PDB replacement must be a Uint8Array");
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    if ([...this._embeddedPortablePdbEdits.keys()].some((index) =>
      index !== debugEntryIndex
    )) {
      throw new UnsupportedFormatError(
        "Only one embedded Portable PDB can be edited per assembly"
      );
    }
    const pdb = parseEmbeddedPortablePdbData(data, 0, data.length);
    validatePortablePdbAssemblyReferences(pdb, assemblyRowCounts);
    const previousEdit = this._embeddedPortablePdbEdits.get(debugEntryIndex);
    if (previousEdit) {
      const previousPdb = parseEmbeddedPortablePdbData(previousEdit, 0, previousEdit.length);
      if (pdb.id.length !== previousPdb.id.length ||
          pdb.id.some((byte, index) => byte !== previousPdb.id[index])) {
        throw new FormatError("Embedded Portable PDB replacement does not match the staged PDB identity");
      }
    }
    const codeViewEntry = this.pe.debugDirectoryEntries
      .find((candidate) => candidate.codeView?.format === "RSDS");
    if (codeViewEntry && !previousEdit) {
      validatePortablePdbCodeViewIdentity(
        pdb,
        codeViewEntry.codeView,
        codeViewEntry.minorVersion === 0x504d ? codeViewEntry.timeDateStamp : undefined
      );
    }
    const refreshed = refreshEmbeddedPortablePdbId(pdb);
    const oldGuid = formatPortablePdbGuid(pdb.id.subarray(0, 16));
    const newTimestamp = new DataView(
      refreshed.id.buffer,
      refreshed.id.byteOffset,
      refreshed.id.byteLength
    ).getUint32(16, true);
    const debugRecordEdits = new Map();
    for (let index = 0; index < this.pe.debugDirectoryEntries.length; index++) {
      const debugEntry = this.pe.debugDirectoryEntries[index];
      if (debugEntry.codeView?.format !== "RSDS") continue;
      const previousDebugEdit = this._debugRecordEdits.get(index);
      const currentCodeViewBytes = previousDebugEdit?.bytes ??
        readDebugRecord(this, debugEntry);
      const currentGuid = formatPortablePdbGuid(currentCodeViewBytes.subarray(4, 20));
      if (currentGuid === oldGuid) {
        if (debugEntry.codeView.age !== 1) {
          throw new FormatError("Embedded Portable PDB CodeView age must be one");
        }
        const codeViewBytes = Uint8Array.from(currentCodeViewBytes);
        codeViewBytes.set(refreshed.id.subarray(0, 16), 4);
        debugRecordEdits.set(index, {
          bytes: codeViewBytes,
          ...(debugEntry.minorVersion === 0x504d
            ? { timeDateStamp: newTimestamp }
            : {})
        });
      }
    }
    const checksumEntries = this.pe.debugDirectoryEntries
      .map((debugEntry, index) => ({ debugEntry, index }))
      .filter(({ debugEntry }) => debugEntry.type === 19);
    if (checksumEntries.length > 1) {
      throw new UnsupportedFormatError(
        "Embedded Portable PDB editing cannot disambiguate multiple PDB checksum records"
      );
    }
    for (const { debugEntry, index } of checksumEntries) {
      if (debugEntry.majorVersion !== 1 || debugEntry.minorVersion !== 0) {
        throw new UnsupportedFormatError("PDB checksum debug-directory version is unsupported");
      }
      const checksumBytes = readDebugRecord(this, debugEntry);
      const terminator = checksumBytes.indexOf(0);
      if (terminator <= 0 || terminator > 64 ||
          checksumBytes.subarray(0, terminator).some((byte) => byte > 0x7f)) {
        throw new FormatError("PDB checksum record has an invalid algorithm name");
      }
      let algorithm;
      try {
        algorithm = new TextDecoder("ascii", { fatal: true })
          .decode(checksumBytes.subarray(0, terminator));
      } catch (error) {
        throw new FormatError(`PDB checksum algorithm name is invalid: ${error.message}`);
      }
      const digest = refreshed.hashes.get(algorithm);
      if (!digest) {
        throw new UnsupportedFormatError(
          `Embedded Portable PDB checksum algorithm ${JSON.stringify(algorithm)} is unsupported`
        );
      }
      if (checksumBytes.length !== terminator + 1 + digest.length) {
        throw new FormatError("PDB checksum record has an invalid digest length");
      }
      checksumBytes.set(digest, terminator + 1);
      debugRecordEdits.set(index, { bytes: checksumBytes });
    }
    this._embeddedPortablePdbEdits.set(debugEntryIndex, refreshed.bytes);
    this._debugRecordEdits = debugRecordEdits;
    return this;
  }

  #preparePortablePdbTypeDefRemapping(typeRid, oldCounts, newCounts, operation) {
    const entries = this.pe.debugDirectoryEntries
      .map((entry, index) => ({ entry, index }))
      .filter(({ entry }) => entry.embeddedPortablePdb);
    if (entries.length === 0) return null;
    if (entries.length !== 1) {
      throw new UnsupportedFormatError(
        "TypeDef remapping requires exactly one embedded Portable PDB"
      );
    }
    const { entry, index } = entries[0];
    const staged = this._embeddedPortablePdbEdits.get(index);
    const pdb = staged
      ? parseEmbeddedPortablePdbData(staged, 0, staged.length)
      : entry.embeddedPortablePdb;
    return {
      index,
      data: remapPortablePdbTypeDefinitions(
        pdb,
        typeRid,
        oldCounts,
        newCounts,
        operation
      )
    };
  }

  #applyPortablePdbTypeDefRemapping(update) {
    if (update) {
      this.#replaceEmbeddedPortablePdb(update.index, update.data, this.tables.counts);
    }
  }

  #synchronizeEmbeddedPortablePdbRowCounts() {
    const entries = this.pe.debugDirectoryEntries
      .map((entry, index) => ({ entry, index }))
      .filter(({ entry }) => entry.embeddedPortablePdb);
    if (entries.length === 0) return;

    const updates = entries.map(({ entry, index }) => {
      const staged = this._embeddedPortablePdbEdits.get(index);
      const pdb = staged
        ? parseEmbeddedPortablePdbData(staged, 0, staged.length)
        : entry.embeddedPortablePdb;
      return {
        index,
        data: updateEmbeddedPortablePdbRowCounts(pdb, this.tables.counts)
      };
    }).filter(({ data }) => data !== null);
    if (updates.length === 0) return;
    if (entries.length !== 1) {
      throw new UnsupportedFormatError(
        "Type-system row additions cannot update multiple embedded Portable PDBs"
      );
    }
    this.#replaceEmbeddedPortablePdb(
      updates[0].index,
      updates[0].data,
      this.tables.counts
    );
  }

  addEmbeddedPortablePdbDocument(debugEntryIndex, name, options) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = addPortablePdbDocument(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      name,
      options
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  insertEmbeddedPortablePdbDocument(debugEntryIndex, options) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = insertPortablePdbDocument(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      options
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  addEmbeddedPortablePdbTypeDefinitionDocuments(
    debugEntryIndex,
    typeRid,
    documentRids
  ) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = addPortablePdbTypeDefinitionDocuments(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      typeRid,
      documentRids
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  removeEmbeddedPortablePdbDocument(debugEntryIndex, documentRid) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = removePortablePdbDocument(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      documentRid
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  replaceEmbeddedPortablePdbTypeDefinitionDocuments(
    debugEntryIndex,
    typeRid,
    documentRids
  ) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = replacePortablePdbTypeDefinitionDocuments(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      typeRid,
      documentRids
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  replaceEmbeddedPortablePdbDocumentMetadata(debugEntryIndex, documentRid, options) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = replacePortablePdbDocumentMetadata(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      documentRid,
      options
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  replaceEmbeddedPortablePdbDocumentName(debugEntryIndex, documentRid, name, separator) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = replacePortablePdbDocumentName(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      documentRid,
      name,
      separator
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  replaceEmbeddedPortablePdbSequencePoints(debugEntryIndex, methodRid, sequencePoints) {
    this.#ensureEditable();
    if (this._portablePdbOffsetBaselines.has(methodRid)) {
      throw new UnsupportedFormatError(
        "Portable PDB sequence points cannot be replaced after IL offset remapping has been staged"
      );
    }
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = replacePortablePdbSequencePoints(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      methodRid,
      sequencePoints
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  replaceEmbeddedPortablePdbSource(debugEntryIndex, documentRid, source, options) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = replacePortablePdbSource(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      documentRid,
      source,
      options
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  addEmbeddedPortablePdbSource(debugEntryIndex, documentRid, source, options) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = addPortablePdbSource(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      documentRid,
      source,
      options
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  removeEmbeddedPortablePdbSource(debugEntryIndex, documentRid) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = removePortablePdbSource(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      documentRid
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  removeEmbeddedPortablePdbCustomDebugInformation(debugEntryIndex, recordRid) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = removePortablePdbCustomDebugInformation(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      recordRid
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  replaceEmbeddedPortablePdbSourceLink(debugEntryIndex, sourceLink) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = replacePortablePdbSourceLink(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      sourceLink
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  removeEmbeddedPortablePdbSourceLink(debugEntryIndex) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = removePortablePdbSourceLink(
      this.#getPortablePdbForEdit(debugEntryIndex, entry)
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  addEmbeddedPortablePdbSourceLink(debugEntryIndex, sourceLink) {
    this.#ensureEditable();
    if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
        debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
      throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
    }
    const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
    if (entry.type !== 17 || !entry.embeddedPortablePdb) {
      throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
    }
    const data = addPortablePdbSourceLink(
      this.#getPortablePdbForEdit(debugEntryIndex, entry),
      sourceLink
    );
    return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
  }

  replaceFieldSignature(rid, signature) {
    this.#ensureEditable();
    const row = this.tables.row(4, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid Field row ID ${rid}`);
    }
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
      throw new TypeError("Field signature must be a non-empty Uint8Array");
    }
    const parsed = parseSignature(signature, { counts: this.tables.counts });
    if (parsed.kind !== "field") {
      throw new FormatError("Field signature must use the field signature form");
    }
    const fieldRva = (this.tables.rows.get(29) ?? []).find((item) => item.Field.rid === rid);
    if (fieldRva) {
      if (parsed.type.kind !== "primitive" ||
          !constantFixedSizes.has(parsed.type.elementType)) {
        throw new UnsupportedFormatError(
          "A Field with FieldRVA must retain a fixed-width primitive signature"
        );
      }
      this.pe.rvaToOffset(fieldRva.RVA, constantFixedSizes.get(parsed.type.elementType));
    }
    const declaringType = this.types.find((type) => type.fieldRids.includes(rid));
    const typeArity = declaringType
      ? getGenericParameterArity(this.genericParams, 2, declaringType.rid)
      : 0;
    validateGenericVariableReferences(parsed, typeArity, this);
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Blob", blob.heap);
    row.Signature = blob.index;
    for (const type of this.types) {
      const field = type.fields.find((item) => item.rid === rid);
      if (field) field.signature = signature.slice();
    }
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  replaceField(rid, { name, flags } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(4, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid Field row ID ${rid}`);
    }
    const field = this.types.flatMap((type) => type.fields).find((item) => item.rid === rid);
    if (!field) throw new UnsupportedFormatError(`Field row ${rid} has no resolved TypeDef owner`);
    const nextName = name === undefined ? field.name : name;
    const nextFlags = flags === undefined ? row.Flags : flags;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("Field name must be a non-empty null-free string");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 0xffff) {
      throw new RangeError("Field flags must be an unsigned 16-bit integer");
    }
    if ((this.tables.rows.get(29) ?? []).some((item) => item.Field.rid === rid) &&
        (nextFlags & 0x10) === 0) {
      throw new FormatError("A Field with FieldRVA must remain static");
    }
    if (nextName === field.name && nextFlags === row.Flags) return this;
    this.#validateAssociatedFlags(4, rid, nextFlags);

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== field.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.Name = stringHeap.index;
    }
    row.Flags = nextFlags;
    field.name = nextName;
    field.flags = nextFlags;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  addFieldRva(fieldRid, rva) {
    return this.#writeFieldRva(fieldRid, rva, false).rid;
  }

  insertFieldRva(fieldRid, rva) {
    return this.#writeFieldRva(fieldRid, rva, true);
  }

  #writeFieldRva(fieldRid, rva, insertSorted) {
    this.#ensureEditable();
    const rows = this.tables.rows.get(29) ?? [];
    if (rows.length !== this.tables.counts[29] || rows.length >= 0x00ffffff) {
      throw new RangeError("FieldRVA row count is inconsistent or exceeds the metadata table limit");
    }
    const field = validateFieldRva(this, fieldRid, rva);
    if (rows.some((row) => row.Field.rid === fieldRid)) {
      throw new FormatError("The FieldRVA table already has a row for this Field");
    }
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].Field.rid > rows[index].Field.rid) {
          throw new UnsupportedFormatError(
            "Sorted FieldRVA insertion requires rows already ordered by Field"
          );
        }
      }
      const laterField = rows.findIndex((row) => row.Field.rid > fieldRid);
      if (laterField !== -1) insertionIndex = laterField;
    } else if ((this.tables.sorted & (1n << 29n)) !== 0n &&
        rows.at(-1)?.Field.rid > fieldRid) {
      throw new UnsupportedFormatError("FieldRVA append would violate declared Field ordering");
    }
    const rid = insertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = insertSorted
      ? this.#prepareTokenRowInsertion(29, rid, rows.length, "FieldRVA")
      : { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] };
    const candidate = { table: 29, tableName: metadataTableNames[29], rid, RVA: rva,
      Field: { rid: fieldRid } };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, candidate);
    this.tables.rows.set(29, rows);
    this.tables.counts[29] = rows.length;
    this.tables.valid |= 1n << 29n;
    this.#updateMetadataFlags(4, fieldRid, { set: 0x0100 });
    field.rva = rva;
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceFieldRva(rid, rva) {
    this.#ensureEditable();
    const row = this.tables.row(29, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid FieldRVA row ID ${rid}`);
    }
    const field = validateFieldRva(this, row.Field.rid, rva);
    if (row.RVA === rva) return this;
    row.RVA = rva;
    field.rva = rva;
    this._metadataDirty = true;
    return this;
  }

  removeFieldRva(rid) {
    this.#ensureEditable();
    const rows = this.tables.rows.get(29) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid FieldRVA row ID ${rid}`);
    }
    const field = this.types.flatMap((type) => type.fields)
      .find((candidate) => candidate.rid === rows[rid - 1].Field.rid);
    if (!field) throw new FormatError("FieldRVA row has no resolved Field");
    const tokenMap = this.#removeTokenRow(29, rid, "FieldRVA");
    this.#updateMetadataFlags(4, field.rid, { clear: 0x0100 });
    field.rva = null;
    return tokenMap;
  }

  removeField(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("Field removal cannot be combined with structural method edits");
    }
    this.#ensureAddedMethodBodiesSafe("Field removal");
    this.#ensureTokenRemappingSafe("Field");
    const rows = this.tables.rows.get(4) ?? [];
    if (rows.length !== this.tables.counts[4]) {
      throw new FormatError("Field row count is inconsistent with the metadata table header");
    }
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid Field row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap Field tokens with unrecognized metadata stream ${streamName}`
        );
      }
    }
    const ownerTypes = this.types.filter((type) => type.fieldRids.includes(rid));
    const field = this.types.flatMap((type) => type.fields).find((item) => item.rid === rid);
    if (ownerTypes.length !== 1 || !field || field.rid !== rid) {
      throw new FormatError(`Field row ${rid} has no unique resolved TypeDef owner`);
    }

    const pointerPresent = (this.tables.valid & (1n << 3n)) !== 0n;
    const pointerRows = this.tables.rows.get(3) ?? [];
    let pointerRid = 0;
    if (pointerPresent) {
      const pointedRids = pointerRows.map((pointer) => pointer.Field?.rid);
      if (pointerRows.length !== this.tables.counts[3] ||
          pointerRows.length !== rows.length ||
          pointedRids.some((fieldRid) => !Number.isInteger(fieldRid) || fieldRid < 1 ||
            fieldRid > rows.length) ||
          new Set(pointedRids).size !== rows.length) {
        throw new UnsupportedFormatError("Field removal requires a one-to-one FieldPtr table");
      }
      pointerRid = pointedRids.indexOf(rid) + 1;
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        const columnName = name ?? value;
        if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId)) {
          for (const row of tableRows) {
            const token = row[columnName];
            if ((token >>> 24) !== 0x04) continue;
            const targetRid = token & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(
                `Field row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (targetRid > rid) {
              rowChanges.push({ row, columnName, value: 0x04000000 + targetRid - 1 });
            }
          }
          continue;
        }
        if (kind === "coded") {
          for (const row of tableRows) {
            const target = row[columnName]?.target;
            if (target?.table !== 4) continue;
            if (target.rid === rid) {
              throw new FormatError(
                `Field row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (target.rid > rid) {
              const remappedTarget = { ...target, rid: target.rid - 1 };
              rowChanges.push({
                row,
                columnName,
                value: {
                  raw: encodeCodedIndex(4, remappedTarget.rid, value),
                  target: remappedTarget
                }
              });
            }
          }
          continue;
        }
        if (kind !== "table" || value !== 4 ||
            (tableId === 2 && columnName === "FieldList")) continue;
        for (const row of tableRows) {
          const targetRid = row[columnName]?.rid;
          if (tableId === 3 && columnName === "Field" && targetRid === rid) continue;
          if (targetRid === rid) {
            throw new FormatError(
              `Field row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
            );
          }
          if (targetRid > rid) {
            const target = { ...row[columnName], rid: targetRid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: { ...target, raw: targetRid - 1 }
            });
          }
        }
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x04) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing Field row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`Field row ${rid} is referenced by CIL`);
        if (targetRid > rid) {
          const replacement = 0x04000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x04000000 + oldRid, 0x04000000 + oldRid - 1);
    }

    const typeListChanges = this.tables.get(2).map((typeRow) => {
      const start = typeRow.FieldList.rid;
      const boundary = pointerPresent ? pointerRid : rid;
      return {
        row: typeRow,
        value: start > boundary ? start - 1 : start
      };
    });
    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingFields = this.types.flatMap((type) =>
      type.fields.filter((item) => item.rid !== rid)
    );
    if (remainingRows.length !== remainingFields.length) {
      throw new FormatError(`Field row ${rid} has inconsistent semantic records`);
    }

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of typeListChanges) {
      change.row.FieldList = {
        ...change.row.FieldList,
        raw: change.value,
        rid: change.value
      };
    }
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.tables.rows.set(4, remainingRows);
    this.tables.counts[4] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 4n);
    if (pointerPresent) {
      const remainingPointers = pointerRows.filter((pointer) => pointer.rid !== pointerRid);
      remainingPointers.forEach((pointer, index) => {
        pointer.rid = index + 1;
      });
      this.tables.rows.set(3, remainingPointers);
      this.tables.counts[3] = remainingPointers.length;
    }
    for (const type of this.types) {
      type.fieldRids = type.fieldRids
        .filter((fieldRid) => fieldRid !== rid)
        .map((fieldRid) => fieldRid > rid ? fieldRid - 1 : fieldRid);
      type.fields = type.fields
        .filter((item) => item.rid !== rid)
        .map((item) => {
          if (item.rid > rid) item.rid--;
          return item;
        });
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  addConstant({ parent, type, value }) {
    return this.#writeConstant({ parent, type, value }, false).token;
  }

  insertConstant({ parent, type, value }) {
    return this.#writeConstant({ parent, type, value }, true);
  }

  #writeConstant({ parent, type, value }, insertSorted) {
    this.#ensureEditable();
    const parentTable = metadataTableId(parent?.table);
    if (![4, 8, 23].includes(parentTable) || !Number.isInteger(parent.rid) ||
        parent.rid < 1 || parent.rid > (this.tables.counts[parentTable] ?? 0)) {
      throw new RangeError("Constant parent must identify an existing Field, Param, or Property row");
    }
    validateConstantValue(type, value);
    const parentRow = this.tables.row(parentTable, parent.rid);
    if (!parentRow) throw new FormatError("Constant parent row is missing from its metadata table");
    const rows = this.tables.rows.get(11) ?? [];
    if (rows.length !== this.tables.counts[11] || rows.length >= 0x00ffffff) {
      throw new RangeError("Constant row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) =>
      row.Parent.target?.table === parentTable && row.Parent.target.rid === parent.rid
    )) {
      throw new FormatError("The Constant table already has a value for this parent");
    }
    const encodedParent = encodeCodedIndex(parentTable, parent.rid, "HasConstant");
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].Parent.raw > rows[index].Parent.raw) {
          throw new UnsupportedFormatError(
            "Sorted Constant insertion requires rows already ordered by Parent"
          );
        }
      }
      const laterParent = rows.findIndex((row) => row.Parent.raw > encodedParent);
      if (laterParent !== -1) insertionIndex = laterParent;
    } else if ((this.tables.sorted & (1n << 11n)) !== 0n &&
        rows.at(-1)?.Parent.raw > encodedParent) {
      throw new UnsupportedFormatError("Constant append would violate declared Parent ordering");
    }
    const rid = insertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = insertSorted
      ? this.#prepareTokenRowInsertion(11, rid, rows.length, "Constant")
      : { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] };

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), value);
    heapStreams.set("#Blob", blob.heap);
    const newRow = {
      table: 11,
      tableName: metadataTableNames[11],
      rid,
      Type: type,
      Padding: 0,
      Parent: {
        raw: encodedParent,
        target: { table: parentTable, tableName: metadataTableNames[parentTable], rid: parent.rid }
      },
      Value: blob.index
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, newRow);
    this.tables.rows.set(11, rows);
    this.tables.counts[11] = rows.length;
    this.tables.valid |= 1n << 11n;
    this.#updateMetadataFlags(parentTable, parent.rid, {
      set: parentTable === 4 ? 0x8000 : 0x1000
    });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { token: 0x0b000000 + rid, rid, tokenMap };
  }

  replaceConstant(rid, { type, value } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(11, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid Constant row ID ${rid}`);
    }
    const nextType = type === undefined ? row.Type : type;
    const currentValue = this.heaps.getBlob(row.Value);
    const nextValue = value === undefined ? currentValue : value;
    validateConstantValue(nextType, nextValue);
    const valueChanged = nextValue.length !== currentValue.length ||
      !nextValue.every((byte, index) => byte === currentValue[index]);
    if (nextType === row.Type && !valueChanged && row.Padding === 0) return this;

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (valueChanged) {
      const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), nextValue);
      heapStreams.set("#Blob", blob.heap);
      row.Value = blob.index;
    }
    row.Type = nextType;
    row.Padding = 0;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeConstant(rid) {
    this.#ensureEditable();
    const row = this.tables.row(11, rid);
    if (!row) return this.#removeTokenRow(11, rid, "Constant");
    const parent = row.Parent.target;
    const tokenMap = this.#removeTokenRow(11, rid, "Constant");
    if (!(this.tables.rows.get(11) ?? []).some((candidate) =>
      candidate.Parent.target?.table === parent.table &&
      candidate.Parent.target.rid === parent.rid
    )) {
      const flag = parent.table === 4 ? 0x8000 : 0x1000;
      this.#updateMetadataFlags(parent.table, parent.rid, { clear: flag });
    }
    return tokenMap;
  }

  addFieldMarshal({ parent, nativeType }) {
    this.#writeFieldMarshal({ parent, nativeType }, false);
    return this;
  }

  insertFieldMarshal({ parent, nativeType }) {
    return this.#writeFieldMarshal({ parent, nativeType }, true);
  }

  #writeFieldMarshal({ parent, nativeType }, insertSorted) {
    this.#ensureEditable();
    const parentTable = metadataTableId(parent?.table);
    if (![4, 8].includes(parentTable) || !Number.isInteger(parent.rid) ||
        parent.rid < 1 || parent.rid > (this.tables.counts[parentTable] ?? 0)) {
      throw new RangeError("FieldMarshal parent must identify an existing Field or Param row");
    }
    if (!(nativeType instanceof Uint8Array) || nativeType.length === 0) {
      throw new TypeError("Native type descriptor must be a non-empty Uint8Array");
    }
    const rows = this.tables.rows.get(13) ?? [];
    if (rows.length !== this.tables.counts[13] || rows.length >= 0x00ffffff) {
      throw new RangeError("FieldMarshal row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) =>
      row.Parent.target?.table === parentTable && row.Parent.target.rid === parent.rid
    )) {
      throw new FormatError("The FieldMarshal table already has a descriptor for this parent");
    }
    const encodedParent = encodeCodedIndex(parentTable, parent.rid, "HasFieldMarshal");
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].Parent.raw > rows[index].Parent.raw) {
          throw new UnsupportedFormatError(
            "Sorted FieldMarshal insertion requires rows already ordered by Parent"
          );
        }
      }
      const laterParent = rows.findIndex((row) => row.Parent.raw > encodedParent);
      if (laterParent !== -1) insertionIndex = laterParent;
    } else if ((this.tables.sorted & (1n << 13n)) !== 0n &&
        rows.at(-1)?.Parent.raw > encodedParent) {
      throw new UnsupportedFormatError("FieldMarshal append would violate declared Parent ordering");
    }
    const rid = insertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = insertSorted
      ? this.#prepareTokenRowInsertion(13, rid, rows.length, "FieldMarshal")
      : { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] };

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), nativeType);
    heapStreams.set("#Blob", blob.heap);
    const newRow = {
      table: 13,
      tableName: metadataTableNames[13],
      rid,
      Parent: {
        raw: encodedParent,
        target: { table: parentTable, tableName: metadataTableNames[parentTable], rid: parent.rid }
      },
      NativeType: blob.index
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, newRow);
    this.tables.rows.set(13, rows);
    this.tables.counts[13] = rows.length;
    this.tables.valid |= 1n << 13n;
    this.#updateMetadataFlags(parentTable, parent.rid, {
      set: parentTable === 4 ? 0x1000 : 0x2000
    });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceFieldMarshal(rid, nativeType) {
    this.#ensureEditable();
    const row = this.tables.row(13, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid FieldMarshal row ID ${rid}`);
    }
    if (!(nativeType instanceof Uint8Array) || nativeType.length === 0) {
      throw new TypeError("Native type descriptor must be a non-empty Uint8Array");
    }
    const currentValue = this.heaps.getBlob(row.NativeType);
    if (nativeType.length === currentValue.length &&
        nativeType.every((byte, index) => byte === currentValue[index])) return this;

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), nativeType);
    heapStreams.set("#Blob", blob.heap);
    row.NativeType = blob.index;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeFieldMarshal(rid) {
    this.#ensureEditable();
    const row = this.tables.row(13, rid);
    if (!row) return this.#removeTokenRow(13, rid, "FieldMarshal");
    const parent = row.Parent.target;
    const tokenMap = this.#removeTokenRow(13, rid, "FieldMarshal");
    if (!(this.tables.rows.get(13) ?? []).some((candidate) =>
      candidate.Parent.target?.table === parent.table &&
      candidate.Parent.target.rid === parent.rid
    )) {
      const flag = parent.table === 4 ? 0x1000 : 0x2000;
      this.#updateMetadataFlags(parent.table, parent.rid, { clear: flag });
    }
    return tokenMap;
  }

  addClassLayout({ owner, packingSize = 0, classSize = 0 }) {
    return this.#writeClassLayout({ owner, packingSize, classSize }, false).rid;
  }

  insertClassLayout({ owner, packingSize = 0, classSize = 0 }) {
    return this.#writeClassLayout({ owner, packingSize, classSize }, true);
  }

  #writeClassLayout({ owner, packingSize, classSize }, insertSorted) {
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || ownerRid > this.tables.counts[2]) {
      throw new RangeError("ClassLayout owner must identify an existing TypeDef row");
    }
    if (![0, 1, 2, 4, 8, 16, 32, 64, 128].includes(packingSize)) {
      throw new RangeError("ClassLayout packing size must be zero or a power of two through 128");
    }
    if (!Number.isInteger(classSize) || classSize < 0 || classSize > 0xffffffff) {
      throw new RangeError("ClassLayout class size must be an unsigned 32-bit integer");
    }
    const rows = this.tables.rows.get(15) ?? [];
    if (rows.length !== this.tables.counts[15] || rows.length >= 0x00ffffff) {
      throw new RangeError("ClassLayout row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.Parent.rid === ownerRid)) {
      throw new FormatError("The ClassLayout table already has a row for this TypeDef");
    }
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].Parent.rid > rows[index].Parent.rid) {
          throw new UnsupportedFormatError(
            "Sorted ClassLayout insertion requires rows already ordered by Parent"
          );
        }
      }
      const laterParent = rows.findIndex((row) => row.Parent.rid > ownerRid);
      if (laterParent !== -1) insertionIndex = laterParent;
    } else if ((this.tables.sorted & (1n << 15n)) !== 0n &&
        rows.at(-1)?.Parent.rid > ownerRid) {
      throw new UnsupportedFormatError("ClassLayout append would violate declared Parent ordering");
    }
    const rid = insertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = insertSorted
      ? this.#prepareTokenRowInsertion(15, rid, rows.length, "ClassLayout")
      : { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] };
    const candidate = { table: 15, tableName: metadataTableNames[15], rid, PackingSize: packingSize,
      ClassSize: classSize, Parent: { rid: ownerRid } };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, candidate);
    this.tables.rows.set(15, rows);
    this.tables.counts[15] = rows.length;
    this.tables.valid |= 1n << 15n;
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceClassLayout(rid, { packingSize, classSize } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(15, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid ClassLayout row ID ${rid}`);
    }
    const nextPackingSize = packingSize === undefined ? row.PackingSize : packingSize;
    const nextClassSize = classSize === undefined ? row.ClassSize : classSize;
    if (![0, 1, 2, 4, 8, 16, 32, 64, 128].includes(nextPackingSize)) {
      throw new RangeError("ClassLayout packing size must be zero or a power of two through 128");
    }
    if (!Number.isInteger(nextClassSize) || nextClassSize < 0 || nextClassSize > 0xffffffff) {
      throw new RangeError("ClassLayout class size must be an unsigned 32-bit integer");
    }
    if (nextPackingSize === row.PackingSize && nextClassSize === row.ClassSize) return this;
    row.PackingSize = nextPackingSize;
    row.ClassSize = nextClassSize;
    this._metadataDirty = true;
    return this;
  }

  removeClassLayout(rid) {
    this.#ensureEditable();
    return this.#removeTokenRow(15, rid, "ClassLayout");
  }

  addFieldLayout({ fieldRid, offset }) {
    return this.#writeFieldLayout({ fieldRid, offset }, false).rid;
  }

  insertFieldLayout({ fieldRid, offset }) {
    return this.#writeFieldLayout({ fieldRid, offset }, true);
  }

  #writeFieldLayout({ fieldRid, offset }, insertSorted) {
    this.#ensureEditable();
    if (!Number.isInteger(fieldRid) || fieldRid < 1 || fieldRid > this.tables.counts[4]) {
      throw new RangeError("FieldLayout parent must identify an existing Field row");
    }
    if (!Number.isInteger(offset) || offset < 0 || offset > 0xffffffff) {
      throw new RangeError("FieldLayout offset must be an unsigned 32-bit integer");
    }
    const rows = this.tables.rows.get(16) ?? [];
    if (rows.length !== this.tables.counts[16] || rows.length >= 0x00ffffff) {
      throw new RangeError("FieldLayout row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.Field.rid === fieldRid)) {
      throw new FormatError("The FieldLayout table already has a row for this Field");
    }
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].Field.rid > rows[index].Field.rid) {
          throw new UnsupportedFormatError(
            "Sorted FieldLayout insertion requires rows already ordered by Field"
          );
        }
      }
      const laterField = rows.findIndex((row) => row.Field.rid > fieldRid);
      if (laterField !== -1) insertionIndex = laterField;
    } else if ((this.tables.sorted & (1n << 16n)) !== 0n &&
        rows.at(-1)?.Field.rid > fieldRid) {
      throw new UnsupportedFormatError("FieldLayout append would violate declared Field ordering");
    }
    const rid = insertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = insertSorted
      ? this.#prepareTokenRowInsertion(16, rid, rows.length, "FieldLayout")
      : { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] };
    const candidate = { table: 16, tableName: metadataTableNames[16], rid, Offset: offset,
      Field: { rid: fieldRid } };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, candidate);
    this.tables.rows.set(16, rows);
    this.tables.counts[16] = rows.length;
    this.tables.valid |= 1n << 16n;
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceFieldLayout(rid, offset) {
    this.#ensureEditable();
    const row = this.tables.row(16, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid FieldLayout row ID ${rid}`);
    }
    if (!Number.isInteger(offset) || offset < 0 || offset > 0xffffffff) {
      throw new RangeError("FieldLayout offset must be an unsigned 32-bit integer");
    }
    if (row.Offset === offset) return this;
    row.Offset = offset;
    this._metadataDirty = true;
    return this;
  }

  removeFieldLayout(rid) {
    this.#ensureEditable();
    return this.#removeTokenRow(16, rid, "FieldLayout");
  }

  addNestedClass({ nestedType, enclosingType }) {
    this.#ensureEditable();
    const nestedRid = metadataTableId(nestedType?.table) === 2 ? nestedType.rid : 0;
    const enclosingRid = metadataTableId(enclosingType?.table) === 2 ? enclosingType.rid : 0;
    if (!Number.isInteger(nestedRid) || nestedRid < 1 || nestedRid > this.tables.counts[2] ||
        !Number.isInteger(enclosingRid) || enclosingRid < 1 ||
        enclosingRid > this.tables.counts[2]) {
      throw new RangeError("NestedClass and EnclosingClass must identify existing TypeDef rows");
    }
    if (nestedRid === enclosingRid) {
      throw new FormatError("A TypeDef cannot be nested inside itself");
    }
    const rows = this.tables.rows.get(41) ?? [];
    if (rows.length !== this.tables.counts[41] || rows.length >= 0xffffffff) {
      throw new RangeError("NestedClass row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.NestedClass.rid === nestedRid)) {
      throw new FormatError("The NestedClass table already has an enclosing TypeDef for this row");
    }
    if ((this.tables.sorted & (1n << 41n)) !== 0n && rows.at(-1)?.NestedClass.rid > nestedRid) {
      throw new UnsupportedFormatError(
        "NestedClass append would violate declared NestedClass ordering"
      );
    }
    validateNestedTypeRelationship(this, nestedRid, enclosingRid);
    const rid = rows.length + 1;
    rows.push({
      table: 41,
      tableName: metadataTableNames[41],
      rid,
      NestedClass: { raw: nestedRid, table: 2, tableName: metadataTableNames[2], rid: nestedRid },
      EnclosingClass: { raw: enclosingRid, table: 2, tableName: metadataTableNames[2], rid: enclosingRid }
    });
    this.tables.rows.set(41, rows);
    this.tables.counts[41] = rid;
    this.tables.valid |= 1n << 41n;
    this._metadataDirty = true;
    return rid;
  }

  insertNestedClass({ nestedType, enclosingType }) {
    this.#ensureEditable();
    const nestedRid = metadataTableId(nestedType?.table) === 2 ? nestedType.rid : 0;
    const enclosingRid = metadataTableId(enclosingType?.table) === 2 ? enclosingType.rid : 0;
    if (!Number.isInteger(nestedRid) || nestedRid < 1 || nestedRid > this.tables.counts[2] ||
        !Number.isInteger(enclosingRid) || enclosingRid < 1 ||
        enclosingRid > this.tables.counts[2]) {
      throw new RangeError("NestedClass and EnclosingClass must identify existing TypeDef rows");
    }
    if (nestedRid === enclosingRid) {
      throw new FormatError("A TypeDef cannot be nested inside itself");
    }
    const rows = this.tables.rows.get(41) ?? [];
    if (rows.length !== (this.tables.counts[41] ?? 0) || rows.length >= 0xffffffff) {
      throw new RangeError("NestedClass row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.NestedClass.rid === nestedRid)) {
      throw new FormatError("The NestedClass table already has an enclosing TypeDef for this row");
    }
    for (let index = 1; index < rows.length; index++) {
      if (rows[index - 1].NestedClass.rid > rows[index].NestedClass.rid) {
        throw new UnsupportedFormatError(
          "Sorted NestedClass insertion requires rows already ordered by NestedClass"
        );
      }
    }
    validateNestedTypeRelationship(this, nestedRid, enclosingRid);
    const laterNestedType = rows.findIndex((row) => row.NestedClass.rid > nestedRid);
    const insertionIndex = laterNestedType === -1 ? rows.length : laterNestedType;
    const rid = insertionIndex + 1;
    if (rid > 0x00ffffff) {
      throw new RangeError("NestedClass token row ID exceeds 24-bit range");
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(41, rid, rows.length, "NestedClass");
    const newRow = {
      table: 41,
      tableName: metadataTableNames[41],
      rid,
      NestedClass: {
        raw: nestedRid,
        table: 2,
        tableName: metadataTableNames[2],
        rid: nestedRid
      },
      EnclosingClass: {
        raw: enclosingRid,
        table: 2,
        tableName: metadataTableNames[2],
        rid: enclosingRid
      }
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, newRow);
    this.tables.rows.set(41, rows);
    this.tables.counts[41] = rows.length;
    this.tables.valid |= 1n << 41n;
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceNestedClass(rid, { enclosingType } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(41, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid NestedClass row ID ${rid}`);
    }
    const enclosingRid = enclosingType === undefined
      ? row.EnclosingClass.rid
      : metadataTableId(enclosingType?.table) === 2 ? enclosingType.rid : 0;
    if (!Number.isInteger(enclosingRid) || enclosingRid < 1 ||
        enclosingRid > this.tables.counts[2]) {
      throw new RangeError("EnclosingClass must identify an existing TypeDef row");
    }
    if (row.NestedClass.rid === enclosingRid) {
      throw new FormatError("A TypeDef cannot be nested inside itself");
    }
    validateNestedTypeRelationship(this, row.NestedClass.rid, enclosingRid, rid);
    if (row.EnclosingClass.rid === enclosingRid) return this;
    row.EnclosingClass = {
      raw: enclosingRid,
      table: 2,
      tableName: metadataTableNames[2],
      rid: enclosingRid
    };
    this._metadataDirty = true;
    return this;
  }

  removeNestedClass(rid) {
    this.#ensureEditable();
    return this.#removeTokenRow(41, rid, "NestedClass");
  }

  addImplMap({ member, moduleRefRid, importName, mappingFlags = 0 }) {
    return this.#writeImplMap(
      { member, moduleRefRid, importName, mappingFlags },
      false
    ).rid;
  }

  insertImplMap({ member, moduleRefRid, importName, mappingFlags = 0 }) {
    return this.#writeImplMap(
      { member, moduleRefRid, importName, mappingFlags },
      true
    );
  }

  #writeImplMap({ member, moduleRefRid, importName, mappingFlags }, insertSorted) {
    this.#ensureEditable();
    const forwarded = getForwardedMember(this, member);
    if (!Number.isInteger(moduleRefRid) || moduleRefRid < 1 ||
        moduleRefRid > this.tables.counts[26]) {
      throw new RangeError("ImplMap scope must identify an existing ModuleRef row");
    }
    if (typeof importName !== "string" || importName.length === 0 || importName.includes("\0")) {
      throw new TypeError("ImplMap import name must be a non-empty null-free string");
    }
    if (!Number.isInteger(mappingFlags) || mappingFlags < 0 || mappingFlags > 0xffff) {
      throw new RangeError("ImplMap flags must be an unsigned 16-bit integer");
    }
    const rows = this.tables.rows.get(28) ?? [];
    if (rows.length !== this.tables.counts[28] || rows.length >= 0x00ffffff) {
      throw new RangeError("ImplMap row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.MemberForwarded.raw === forwarded.raw)) {
      throw new FormatError("The ImplMap table already has a mapping for this member");
    }
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].MemberForwarded.raw > rows[index].MemberForwarded.raw) {
          throw new UnsupportedFormatError(
            "Sorted ImplMap insertion requires rows already ordered by MemberForwarded"
          );
        }
      }
      const laterMember = rows.findIndex((row) => row.MemberForwarded.raw > forwarded.raw);
      if (laterMember !== -1) insertionIndex = laterMember;
    } else if ((this.tables.sorted & (1n << 28n)) !== 0n &&
        rows.at(-1)?.MemberForwarded.raw > forwarded.raw) {
      throw new UnsupportedFormatError("ImplMap append would violate declared MemberForwarded ordering");
    }
    const rid = insertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = insertSorted
      ? this.#prepareTokenRowInsertion(28, rid, rows.length, "ImplMap")
      : { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] };
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), importName);
    heapStreams.set("#Strings", stringHeap.heap);
    const candidate = {
      table: 28,
      tableName: metadataTableNames[28],
      rid,
      MappingFlags: mappingFlags,
      MemberForwarded: forwarded,
      ImportName: stringHeap.index,
      ImportScope: { raw: moduleRefRid, table: 26, tableName: metadataTableNames[26], rid: moduleRefRid }
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, candidate);
    this.tables.rows.set(28, rows);
    this.tables.counts[28] = rows.length;
    this.tables.valid |= 1n << 28n;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceImplMap(rid, { moduleRefRid, importName, mappingFlags } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(28, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid ImplMap row ID ${rid}`);
    }
    const nextModuleRefRid = moduleRefRid === undefined ? row.ImportScope.rid : moduleRefRid;
    const nextImportName = importName === undefined
      ? this.heaps.getString(row.ImportName)
      : importName;
    const nextMappingFlags = mappingFlags === undefined ? row.MappingFlags : mappingFlags;
    if (!Number.isInteger(nextModuleRefRid) || nextModuleRefRid < 1 ||
        nextModuleRefRid > this.tables.counts[26]) {
      throw new RangeError("ImplMap scope must identify an existing ModuleRef row");
    }
    if (typeof nextImportName !== "string" || nextImportName.length === 0 ||
        nextImportName.includes("\0")) {
      throw new TypeError("ImplMap import name must be a non-empty null-free string");
    }
    if (!Number.isInteger(nextMappingFlags) || nextMappingFlags < 0 || nextMappingFlags > 0xffff) {
      throw new RangeError("ImplMap flags must be an unsigned 16-bit integer");
    }
    if (nextModuleRefRid === row.ImportScope.rid &&
        nextImportName === this.heaps.getString(row.ImportName) &&
        nextMappingFlags === row.MappingFlags) return this;
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextImportName !== this.heaps.getString(row.ImportName)) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextImportName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.ImportName = stringHeap.index;
    }
    row.MappingFlags = nextMappingFlags;
    row.ImportScope = {
      raw: nextModuleRefRid,
      table: 26,
      tableName: metadataTableNames[26],
      rid: nextModuleRefRid
    };
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeImplMap(rid) {
    this.#ensureEditable();
    const rows = this.tables.rows.get(28) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid ImplMap row ID ${rid}`);
    }
    const member = rows[rid - 1].MemberForwarded.target;
    const memberRow = this.tables.row(member.table, member.rid);
    if (!memberRow || (memberRow.Flags & 0x2000) === 0) {
      throw new FormatError("ImplMap member row is missing its PInvokeImpl flag");
    }
    const tokenMap = this.#removeTokenRow(28, rid, "ImplMap");
    memberRow.Flags &= ~0x2000;
    if (member.table === 4) {
      const field = this.types.flatMap((type) => type.fields)
        .find((item) => item.rid === member.rid);
      if (field) field.flags = memberRow.Flags;
    } else {
      const method = this.methods[member.rid - 1];
      if (method) method.flags = memberRow.Flags;
    }
    this._metadataDirty = true;
    return tokenMap;
  }

  addMethodImpl({ owner, body, declaration }) {
    return this.#writeMethodImpl({ owner, body, declaration }, false).rid;
  }

  insertMethodImpl({ owner, body, declaration }) {
    return this.#writeMethodImpl({ owner, body, declaration }, true);
  }

  #writeMethodImpl({ owner, body, declaration }, insertSorted) {
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || ownerRid > this.tables.counts[2]) {
      throw new RangeError("MethodImpl owner must identify an existing TypeDef row");
    }
    const bodyReference = getMethodImplReference(this, body);
    const declarationReference = getMethodImplReference(this, declaration);
    if (bodyReference.target.table === 6 &&
        !this.types[ownerRid - 1]?.methodRids.includes(bodyReference.target.rid)) {
      throw new FormatError("MethodImpl MethodDef body must belong to its owning TypeDef");
    }
    const rows = this.tables.rows.get(25) ?? [];
    if (rows.length !== this.tables.counts[25] || rows.length >= 0xffffffff) {
      throw new RangeError("MethodImpl row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) =>
      row.Class.rid === ownerRid &&
      row.MethodBody.raw === bodyReference.raw &&
      row.MethodDeclaration.raw === declarationReference.raw
    )) {
      throw new FormatError("The MethodImpl table already contains this implementation mapping");
    }
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].Class.rid > rows[index].Class.rid) {
          throw new UnsupportedFormatError(
            "Sorted MethodImpl insertion requires rows already ordered by Class"
          );
        }
      }
      const laterOwner = rows.findIndex((row) => row.Class.rid > ownerRid);
      if (laterOwner !== -1) insertionIndex = laterOwner;
    } else if ((this.tables.sorted & (1n << 25n)) !== 0n &&
        rows.at(-1)?.Class.rid > ownerRid) {
      throw new UnsupportedFormatError("MethodImpl append would violate declared Class ordering");
    }
    const rid = insertionIndex + 1;
    if (rid > 0x00ffffff) {
      throw new RangeError("MethodImpl token row ID exceeds 24-bit range");
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(25, rid, rows.length, "MethodImpl");
    const newRow = {
      table: 25,
      tableName: metadataTableNames[25],
      rid,
      Class: { raw: ownerRid, table: 2, tableName: metadataTableNames[2], rid: ownerRid },
      MethodBody: bodyReference,
      MethodDeclaration: declarationReference
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, newRow);
    this.tables.rows.set(25, rows);
    this.tables.counts[25] = rows.length;
    this.tables.valid |= 1n << 25n;
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceMethodImpl(rid, { body, declaration } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(25, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid MethodImpl row ID ${rid}`);
    }
    const nextBody = body === undefined ? row.MethodBody : getMethodImplReference(this, body);
    const nextDeclaration = declaration === undefined
      ? row.MethodDeclaration
      : getMethodImplReference(this, declaration);
    if (nextBody.target.table === 6 &&
        !this.types[row.Class.rid - 1]?.methodRids.includes(nextBody.target.rid)) {
      throw new FormatError("MethodImpl MethodDef body must belong to its owning TypeDef");
    }
    if (this.tables.rows.get(25).some((other) =>
      other.rid !== rid &&
      other.Class.rid === row.Class.rid &&
      other.MethodBody.raw === nextBody.raw &&
      other.MethodDeclaration.raw === nextDeclaration.raw
    )) {
      throw new FormatError("The MethodImpl table already contains this implementation mapping");
    }
    if (nextBody.raw === row.MethodBody.raw &&
        nextDeclaration.raw === row.MethodDeclaration.raw) return this;
    row.MethodBody = nextBody;
    row.MethodDeclaration = nextDeclaration;
    this._metadataDirty = true;
    return this;
  }

  removeMethodImpl(rid) {
    this.#ensureEditable();
    return this.#removeTokenRow(25, rid, "MethodImpl");
  }

  addDeclSecurity({ parent, action, permissionSet, resolveEnum }) {
    return this.#writeDeclSecurity({ parent, action, permissionSet, resolveEnum }, false).rid;
  }

  insertDeclSecurity({ parent, action, permissionSet, resolveEnum }) {
    return this.#writeDeclSecurity({ parent, action, permissionSet, resolveEnum }, true);
  }

  #writeDeclSecurity({ parent, action, permissionSet, resolveEnum }, insertSorted) {
    this.#ensureEditable();
    const parentTable = metadataTableId(parent?.table);
    if (![2, 6, 32].includes(parentTable) || !Number.isInteger(parent.rid) ||
        parent.rid < 1 || parent.rid > (this.tables.counts[parentTable] ?? 0)) {
      throw new RangeError("DeclSecurity parent must identify an existing TypeDef, MethodDef, or Assembly row");
    }
    if (!Number.isInteger(action) || action < 2 || action > 14) {
      throw new RangeError("DeclSecurity action must be a supported CLI security action");
    }
    const permissionSetBytes = permissionSet instanceof Uint8Array
      ? permissionSet
      : encodePermissionSetBlob(permissionSet);
    if (permissionSetBytes.length === 0) {
      throw new TypeError("PermissionSet must be non-empty");
    }
    const enumResolver = getCustomAttributeEnumResolver(this, resolveEnum);
    if (!(permissionSet instanceof Uint8Array)) {
      validateLocalPermissionSetNamedArguments(this, permissionSet, enumResolver);
    }
    const rows = this.tables.rows.get(14) ?? [];
    if (rows.length !== this.tables.counts[14] || rows.length >= 0xffffffff) {
      throw new RangeError("DeclSecurity row count is inconsistent or exceeds the metadata table limit");
    }
    const encodedParent = encodeCodedIndex(parentTable, parent.rid, "HasDeclSecurity");
    if (rows.some((row) => row.Parent.raw === encodedParent && row.Action === action)) {
      throw new FormatError("Duplicate DeclSecurity action for parent");
    }
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].Parent.raw > rows[index].Parent.raw) {
          throw new UnsupportedFormatError(
            "Sorted DeclSecurity insertion requires rows already ordered by Parent"
          );
        }
      }
      const laterParent = rows.findIndex((row) => row.Parent.raw > encodedParent);
      if (laterParent !== -1) insertionIndex = laterParent;
    } else if ((this.tables.sorted & (1n << 14n)) !== 0n &&
        rows.at(-1)?.Parent.raw > encodedParent) {
      throw new UnsupportedFormatError(
        "DeclSecurity append would violate declared Parent ordering"
      );
    }
    const rid = insertionIndex + 1;
    if (rid > 0x00ffffff) {
      throw new RangeError("DeclSecurity token row ID exceeds 24-bit range");
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(14, rid, rows.length, "DeclSecurity");

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), permissionSetBytes);
    heapStreams.set("#Blob", blob.heap);
    const newRow = {
      table: 14,
      tableName: metadataTableNames[14],
      rid,
      Action: action,
      Parent: {
        raw: encodedParent,
        target: { table: parentTable, tableName: metadataTableNames[parentTable], rid: parent.rid }
      },
      PermissionSet: blob.index
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, newRow);
    this.tables.rows.set(14, rows);
    this.tables.counts[14] = rows.length;
    this.tables.valid |= 1n << 14n;
    if (parentTable === 2 || parentTable === 6) {
      this.#updateMetadataFlags(parentTable, parent.rid, {
        set: parentTable === 2 ? 0x00040000 : 0x4000
      });
    }
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceDeclSecurity(rid, { action, permissionSet, resolveEnum } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(14, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid DeclSecurity row ID ${rid}`);
    }
    const nextAction = action === undefined ? row.Action : action;
    const nextPermissionSet = permissionSet === undefined
      ? null
      : permissionSet instanceof Uint8Array
        ? permissionSet
        : encodePermissionSetBlob(permissionSet);
    if (!Number.isInteger(nextAction) || nextAction < 2 || nextAction > 14) {
      throw new RangeError("DeclSecurity action must be a supported CLI security action");
    }
    if (nextPermissionSet !== null &&
        nextPermissionSet.length === 0) {
      throw new TypeError("PermissionSet must be non-empty");
    }
    if (permissionSet !== undefined && !(permissionSet instanceof Uint8Array)) {
      const enumResolver = getCustomAttributeEnumResolver(this, resolveEnum);
      validateLocalPermissionSetNamedArguments(this, permissionSet, enumResolver);
    }
    if (nextAction === row.Action && nextPermissionSet === null) return this;
    if (this.tables.rows.get(14).some((other) =>
      other.rid !== rid && other.Parent.raw === row.Parent.raw && other.Action === nextAction
    )) {
      throw new FormatError("The DeclSecurity table already has this action for its parent");
    }

    if (nextPermissionSet !== null) {
      const heapStreams = new Map(
        [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
          [streamName, stream.bytes]
        )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
      );
      const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), nextPermissionSet);
      heapStreams.set("#Blob", blob.heap);
      row.PermissionSet = blob.index;
      this._heapStreams = heapStreams;
      this.#refreshHeaps();
    }
    row.Action = nextAction;
    this._metadataDirty = true;
    return this;
  }

  removeDeclSecurity(rid) {
    this.#ensureEditable();
    const row = this.tables.row(14, rid);
    if (!row) return this.#removeTokenRow(14, rid, "DeclSecurity");
    const parent = row.Parent.target;
    const tokenMap = this.#removeTokenRow(14, rid, "DeclSecurity");
    if ((parent.table === 2 || parent.table === 6) &&
        !(this.tables.rows.get(14) ?? []).some((candidate) =>
          candidate.Parent.target?.table === parent.table &&
          candidate.Parent.target.rid === parent.rid
        )) {
      this.#updateMetadataFlags(parent.table, parent.rid, {
        clear: parent.table === 2 ? 0x00040000 : 0x4000
      });
    }
    return tokenMap;
  }

  addMethod({ owner, name, flags, implFlags = 0, signature, body: bodyBytes }) {
    return this.#writeMethod(
      { owner, name, flags, implFlags, signature, body: bodyBytes },
      false
    ).token;
  }

  insertMethod({ owner, name, flags, implFlags = 0, signature, body: bodyBytes }) {
    return this.#writeMethod(
      { owner, name, flags, implFlags, signature, body: bodyBytes },
      true
    );
  }

  #writeMethod({ owner, name, flags, implFlags = 0, signature, body: bodyBytes }, insertIntoOwner) {
    this.#ensureEditable();
    const embeddedPdbIndices = this.pe.debugDirectoryEntries.flatMap((entry, index) =>
      entry.embeddedPortablePdb ? [index] : []
    );
    if (embeddedPdbIndices.length > 1) {
      throw new UnsupportedFormatError(
        "MethodDef insertion supports only one embedded Portable PDB"
      );
    }
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    const ownerType = this.types[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !ownerType) {
      throw new RangeError("Method owner must identify an existing TypeDef");
    }
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("Method name must be a non-empty null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffff) {
      throw new RangeError("Method flags must be an unsigned 16-bit integer");
    }
    if (!Number.isInteger(implFlags) || implFlags < 0 || implFlags > 0xffff) {
      throw new RangeError("Method implementation flags must be an unsigned 16-bit integer");
    }
    if (!(signature instanceof Uint8Array)) {
      throw new TypeError("Method signature must be a Uint8Array");
    }
    const parsedSignature = parseSignature(signature, { counts: this.tables.counts });
    if (parsedSignature.kind !== "method") {
      throw new FormatError("MethodDef requires a method-form signature");
    }
    validateGenericVariableReferences(
      parsedSignature,
      getGenericParameterArity(this.genericParams, 2, ownerRid),
      this,
      null,
      parsedSignature.genericParameterCount ?? 0
    );
    const hasBody = bodyBytes !== undefined;
    let parsedBody = null;
    if (hasBody) {
      if ((flags & (0x0400 | 0x2000)) !== 0 || (implFlags & 0x0007) !== 0) {
        throw new UnsupportedFormatError(
          "Method bodies are supported only for concrete managed IL methods"
        );
      }
    } else {
      if ((flags & 0x0400) === 0 || (flags & 0x0040) === 0 ||
          (flags & 0x2000) !== 0 || (implFlags & 0x0003) !== 0) {
        throw new UnsupportedFormatError(
          "A bodyless MethodDef must be an abstract virtual IL method"
        );
      }
      if ((ownerType.flags & 0x0080) === 0 && (ownerType.flags & 0x0020) === 0) {
        throw new FormatError("An abstract method requires an abstract or interface TypeDef owner");
      }
    }

    const methodRows = this.tables.rows.get(6) ?? [];
    const originalMethodCount = methodRows.length;
    if (methodRows.length !== this.tables.counts[6] || methodRows.length !== this.methods.length ||
        methodRows.length >= 0x00ffffff) {
      throw new RangeError("MethodDef row count is inconsistent or exceeds the metadata token range");
    }
    const pointerPresent = (this.tables.valid & (1n << 5n)) !== 0n;
    const pointerRows = getBijectivePointerRows(this, 5, 6, "Method");
    if (pointerPresent && !pointerRows) {
      throw new FormatError("MethodPtr must be a one-to-one mapping to MethodDef rows");
    }
    const typeRows = this.tables.rows.get(2) ?? [];
    if (typeRows.length !== (this.tables.counts[2] ?? 0)) {
      throw new FormatError("TypeDef row count is inconsistent with the metadata table header");
    }
    const ownerRow = typeRows[ownerRid - 1];
    if (ownerRow?.rid !== ownerRid || !Number.isInteger(ownerRow.MethodList?.rid)) {
      throw new FormatError(`TypeDef row ${ownerRid} has an inconsistent MethodList`);
    }
    const methodListRows = pointerRows ?? methodRows;
    const endRid = typeRows[ownerRid]?.MethodList.rid ?? methodListRows.length + 1;
    const ownedRids = pointerRows
      ? pointerRows.slice(ownerRow.MethodList.rid - 1, endRid - 1)
        .map((pointer) => pointer.Method.rid)
      : Array.from(
        { length: Math.max(0, endRid - ownerRow.MethodList.rid) },
        (_, index) => ownerRow.MethodList.rid + index
      );
    if (endRid > methodListRows.length + 1 ||
        ownedRids.length !== ownerType.methodRids.length ||
        ownedRids.some((methodRid, index) => methodRid !== ownerType.methodRids[index])) {
      throw new UnsupportedFormatError("Method insertion requires a valid contiguous owner range");
    }
    if (!insertIntoOwner && endRid !== methodListRows.length + 1) {
      throw new UnsupportedFormatError("Method append requires the owner's methods to be contiguous at the end");
    }
    const parameterRows = this.tables.rows.get(8) ?? [];
    if (parameterRows.length !== this.tables.counts[8]) {
      throw new FormatError("Param row count is inconsistent with the metadata table header");
    }
    const parameterPointerPresent = (this.tables.valid & (1n << 7n)) !== 0n;
    const parameterPointerRows = getBijectivePointerRows(this, 7, 8, "Param");
    if (parameterPointerPresent && !parameterPointerRows) {
      throw new FormatError("ParamPtr must be a one-to-one mapping to Param rows");
    }
    const rid = pointerRows ? methodRows.length + 1 : endRid;
    const pointerInsertionIndex = pointerRows
      ? ownerRow.MethodList.rid - 1 + ownedRids.length
      : -1;
    const pointerRid = pointerInsertionIndex + 1;
    const nextMethodListRow = methodListRows[endRid - 1];
    const nextMethodRid = pointerRows
      ? nextMethodListRow?.Method.rid
      : nextMethodListRow?.rid;
    const parameterListRid = pointerRows
      ? (parameterPointerRows?.length ?? parameterRows.length) + 1
      : nextMethodRid
        ? methodRows[nextMethodRid - 1]?.ParamList.rid
        : (parameterPointerRows?.length ?? parameterRows.length) + 1;
    if (!Number.isInteger(parameterListRid)) {
      throw new FormatError("Method insertion could not resolve the next ParamList boundary");
    }
    if (hasBody) {
      parsedBody = validateNewMethodBody(
        this, bodyBytes, ownerType, rid, parsedSignature.genericParameterCount ?? 0
      );
    }
    const parameterListTable = parameterPointerRows ? 7 : 8;
    const { tokenMap, rowChanges, tokenUpdates, patches } = pointerRows
      ? { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] }
      : this.#prepareTokenRowInsertion(
        6,
        rid,
        methodRows.length,
        "MethodDef",
        { allowEmbeddedPortablePdb: embeddedPdbIndices.length === 1 }
      );
    const cliEntryPointToken = this._cliEntryPointToken ?? this.cli.entryPointToken;
    const isManagedMethodEntryPoint =
      (this.cli.flags & 0x10) === 0 &&
      (cliEntryPointToken >>> 24) === 6;
    const cliEntryPointRid = cliEntryPointToken & 0x00ffffff;
    if (isManagedMethodEntryPoint &&
        (cliEntryPointRid === 0 || cliEntryPointRid > originalMethodCount)) {
      throw new FormatError("CLI entry point references a missing MethodDef");
    }
    const remappedCliEntryPointToken = isManagedMethodEntryPoint &&
      cliEntryPointRid >= rid
      ? cliEntryPointToken + 1
      : cliEntryPointToken;
    let updatedEmbeddedPdb = null;
    let updatedCounts = null;
    if (embeddedPdbIndices.length === 1) {
      updatedCounts = [...this.tables.counts];
      updatedCounts[6]++;
      if (pointerRows) updatedCounts[5]++;
      const debugEntryIndex = embeddedPdbIndices[0];
      const debugEntry = this.pe.debugDirectoryEntries[debugEntryIndex];
      updatedEmbeddedPdb = insertPortablePdbMethod(
        this.#getPortablePdbForEdit(debugEntryIndex, debugEntry),
        rid,
        this.tables.counts,
        updatedCounts
      );
    }
    const insertedBody = hasBody ? bodyBytes.slice() : null;
    if (parsedBody && insertedBody) {
      for (const instruction of parsedBody.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if (!tokenMap.has(token)) continue;
        const replacement = tokenMap.get(token);
        for (const patch of createOperandPatches(instruction, replacement)) {
          if (patch.offset < 0 || patch.offset + patch.bytes.length > insertedBody.length) {
            throw new FormatError("Inserted method token patch is outside its body");
          }
          insertedBody.set(patch.bytes, patch.offset);
        }
        instruction.operand.value = replacement;
      }
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Strings", stringHeap.heap);
    heapStreams.set("#Blob", blobHeap.heap);

    const row = {
      table: 6,
      tableName: metadataTableNames[6],
      rid,
      RVA: 0,
      ImplFlags: implFlags,
      Flags: flags,
      Name: stringHeap.index,
      Signature: blobHeap.index,
      ParamList: {
        raw: parameterListRid,
        table: parameterListTable,
        tableName: metadataTableNames[parameterListTable],
        rid: parameterListRid
      }
    };
    const method = {
      rid,
      rva: 0,
      flags,
      implFlags,
      name,
      signature: signature.slice(),
      parameterRids: [],
      parameters: [],
      genericParams: [],
      row
    };
    if (updatedEmbeddedPdb) {
      this.#replaceEmbeddedPortablePdb(
        embeddedPdbIndices[0],
        updatedEmbeddedPdb,
        updatedCounts
      );
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const existingRow of methodRows) {
      if (existingRow.rid >= rid) existingRow.rid++;
    }
    methodRows.splice(rid - 1, 0, row);
    this.tables.rows.set(6, methodRows);
    this.tables.counts[6] = methodRows.length;
    this.tables.valid |= 1n << 6n;
    if (pointerRows) {
      for (const pointer of pointerRows) {
        if (pointer.rid >= pointerRid) pointer.rid++;
      }
      pointerRows.splice(pointerInsertionIndex, 0, {
        table: 5,
        tableName: metadataTableNames[5],
        rid: pointerRid,
        Method: { raw: rid, table: 6, tableName: metadataTableNames[6], rid }
      });
      this.tables.rows.set(5, pointerRows);
      this.tables.counts[5] = pointerRows.length;
    }
    if (pointerRows || rid > originalMethodCount) {
      for (let index = ownerRid; index < typeRows.length; index++) {
        typeRows[index].MethodList.rid++;
        typeRows[index].MethodList.raw++;
      }
    }
    if (!pointerRows) {
      for (const candidate of this.methods) {
        if (candidate.rid >= rid) candidate.rid++;
      }
      for (const type of this.types) {
        type.methodRids = type.methodRids.map((methodRid) =>
          methodRid >= rid ? methodRid + 1 : methodRid
        );
      }
      for (const parameter of this.genericParams) {
        if (parameter.owner.table === 6 && parameter.owner.rid >= rid) {
          parameter.owner.rid++;
        }
      }
      this._bodyCache = new Map([...this._bodyCache].map(([methodRid, body]) => [
        methodRid >= rid ? methodRid + 1 : methodRid,
        body
      ]));
    }
    this.methods.splice(rid - 1, 0, method);
    if (parsedBody) {
      this._addedMethodBodies.set(rid, insertedBody);
      this._bodyCache.set(rid, parsedBody);
    }
    ownerType.methodRids.push(rid);
    ownerType.methods.push(method);
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    if (remappedCliEntryPointToken !== cliEntryPointToken) {
      const entryPointBytes = new Uint8Array(4);
      new DataView(entryPointBytes.buffer).setUint32(0, remappedCliEntryPointToken, true);
      patches.push({
        offset: this.cli.offset + 20,
        bytes: entryPointBytes
      });
      this._cliEntryPointToken = remappedCliEntryPointToken;
    }
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { token: 0x06000000 + rid, tokenMap };
  }

  removeMethod(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("Method removal cannot be combined with structural method edits");
    }
    const embeddedPdbIndices = this.pe.debugDirectoryEntries.flatMap((entry, index) =>
      entry.embeddedPortablePdb ? [index] : []
    );
    this.#ensureTokenRemappingSafe("MethodDef", {
      allowEmbeddedPortablePdb: embeddedPdbIndices.length === 1
    });
    const rows = this.tables.rows.get(6) ?? [];
    if (rows.length !== this.tables.counts[6] || rows.length !== this.methods.length) {
      throw new FormatError("MethodDef row count is inconsistent with the metadata table header");
    }
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid MethodDef row ID ${rid}`);
    }
    const cliEntryPointToken = this._cliEntryPointToken ?? this.cli.entryPointToken;
    const isManagedMethodEntryPoint =
      (this.cli.flags & 0x10) === 0 &&
      (cliEntryPointToken >>> 24) === 6;
    const cliEntryPointRid = cliEntryPointToken & 0x00ffffff;
    if (isManagedMethodEntryPoint &&
        (cliEntryPointRid === 0 || cliEntryPointRid > rows.length)) {
      throw new FormatError("CLI entry point references a missing MethodDef");
    }
    if (isManagedMethodEntryPoint && cliEntryPointRid === rid) {
      throw new FormatError(`MethodDef row ${rid} is the CLI entry point`);
    }
    const remappedCliEntryPointToken = isManagedMethodEntryPoint &&
      cliEntryPointRid > rid
      ? cliEntryPointToken - 1
      : cliEntryPointToken;
    const shiftsMethodRids = rid < rows.length;
    if (shiftsMethodRids && this._addedMethodBodies.size > 0) {
      throw new UnsupportedFormatError(
        "MethodDef RID remapping cannot be combined with added method bodies"
      );
    }
    const method = this.methods[rid - 1];
    if (method?.rid !== rid) throw new FormatError(`MethodDef row ${rid} has inconsistent semantic records`);
    const genericParamRows = this.tables.rows.get(42) ?? [];
    if (genericParamRows.length !== (this.tables.counts[42] ?? 0)) {
      throw new FormatError("GenericParam row count is inconsistent with the metadata table header");
    }
    const genericParamRids = new Set(method.genericParams.map((parameter) => parameter.rid));
    if (genericParamRids.size !== method.genericParams.length ||
        method.genericParams.length !== this.genericParams.filter(
          (parameter) => parameter.owner.table === 6 && parameter.owner.rid === rid
        ).length) {
      throw new FormatError(`MethodDef row ${rid} has inconsistent GenericParam ownership`);
    }
    if (genericParamRids.size > 0) {
      const sortedGenericParamRids = [...genericParamRids].sort((a, b) => a - b);
      const firstGenericParamRid = sortedGenericParamRids[0];
      if (firstGenericParamRid < 1 ||
          sortedGenericParamRids.some((parameterRid, index) =>
            parameterRid !== firstGenericParamRid + index
          ) || sortedGenericParamRids.at(-1) > genericParamRows.length) {
        throw new UnsupportedFormatError(
          "MethodDef removal requires its GenericParam rows to form a contiguous table range"
        );
      }
    }
    const genericParamConstraintRows = this.tables.rows.get(44) ?? [];
    if (genericParamConstraintRows.length !== (this.tables.counts[44] ?? 0) ||
        genericParamConstraintRows.length !== this.genericParamConstraints.length) {
      throw new FormatError("GenericParamConstraint row count is inconsistent with the metadata table header");
    }
    const genericParamConstraintRids = new Set(
      this.genericParamConstraints
        .filter((constraint) => genericParamRids.has(constraint.ownerRid))
        .map((constraint) => constraint.rid)
    );
    if (genericParamConstraintRids.size > 0) {
      for (const [tableId, tableRows] of this.tables.rows) {
        const schema = metadataTableSchemas[tableId];
        if (!schema) {
          throw new UnsupportedFormatError(
            `Cannot remove MethodDef row ${rid} with unknown metadata table ${tableId}`
          );
        }
        for (const row of tableRows) {
          if (tableId === 44 && genericParamConstraintRids.has(row.rid)) continue;
          for (const [kind, value, name] of schema) {
            const columnName = name ?? value;
            const column = row[columnName];
            const target = kind === "coded"
              ? column?.target
              : kind === "table" ? { table: value, rid: column?.rid } : null;
            if (target?.table === 44 && genericParamConstraintRids.has(target.rid)) {
              throw new FormatError(
                `GenericParamConstraint row ${target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                columnName === "Token" && row[columnName] >>> 24 === 44 &&
                genericParamConstraintRids.has(row[columnName] & 0x00ffffff)) {
              throw new FormatError(
                `GenericParamConstraint row ${row[columnName] & 0x00ffffff} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
          }
        }
      }
      for (const candidate of this.methods) {
        for (const instruction of this.getMethodBody(candidate.rid)?.instructions ?? []) {
          const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
          if ((token >>> 24) === 44 && genericParamConstraintRids.has(token & 0x00ffffff)) {
            throw new FormatError(
              `GenericParamConstraint row ${token & 0x00ffffff} is referenced by CIL in MethodDef row ${candidate.rid}`
            );
          }
        }
      }
    }
    const parameterRows = this.tables.rows.get(8) ?? [];
    if (parameterRows.length !== (this.tables.counts[8] ?? 0)) {
      throw new FormatError("Param row count is inconsistent with the metadata table header");
    }
    const parameterRids = new Set(method.parameterRids);
    if (method.parameterRids.length !== method.parameters.length ||
        parameterRids.size !== method.parameterRids.length) {
      throw new FormatError(`MethodDef row ${rid} has inconsistent Param ownership`);
    }
    if (parameterRids.size > 0) {
      const sortedParameterRids = [...parameterRids].sort((a, b) => a - b);
      const firstParameterRid = sortedParameterRids[0];
      if (firstParameterRid < 1 ||
          sortedParameterRids.some((parameterRid, index) => parameterRid !== firstParameterRid + index) ||
          sortedParameterRids.at(-1) > parameterRows.length) {
        throw new UnsupportedFormatError(
          "MethodDef removal requires its Param rows to form a contiguous table range"
        );
      }
    }
    const owners = this.types.filter((type) => type.methodRids.includes(rid));
    if (owners.length !== 1 || !owners[0].methods.some((candidate) => candidate.rid === rid)) {
      throw new FormatError(`MethodDef row ${rid} has no unique resolved TypeDef owner`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remove MethodDef row ${rid} with unrecognized metadata stream ${streamName}`
        );
      }
    }

    const paramPointerRows = parameterRids.size > 0
      ? getBijectivePointerRows(this, 7, 8, "Param")
      : null;
    if (parameterRids.size > 0 && (this.tables.valid & (1n << 7n)) !== 0n) {
      const pointerRids = paramPointerRows
        .filter((pointer) => parameterRids.has(pointer.Param.rid))
        .map((pointer) => pointer.rid);
      const firstPointerRid = Math.min(...pointerRids);
      if (pointerRids.length !== parameterRids.size ||
          [...pointerRids].sort((a, b) => a - b)
            .some((pointerRid, index) => pointerRid !== firstPointerRid + index)) {
        throw new UnsupportedFormatError(
          "MethodDef removal requires its ParamPtr rows to form a contiguous pointer range"
        );
      }
    }
    if (parameterRids.size > 0) {
      for (const [tableId, tableRows] of this.tables.rows) {
        const schema = metadataTableSchemas[tableId];
        if (!schema) {
          throw new UnsupportedFormatError(
            `Cannot remove MethodDef row ${rid} with unknown metadata table ${tableId}`
          );
        }
        for (const row of tableRows) {
          for (const [kind, value, name, pointer] of schema) {
            const columnName = name ?? value;
            if (kind === "coded" && row[columnName]?.target?.table === 8 &&
                parameterRids.has(row[columnName].target.rid)) {
              throw new FormatError(
                `Param row ${row[columnName].target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (kind === "table") {
              const targetTable = pointer !== undefined &&
                (this.tables.valid & (1n << BigInt(pointer))) !== 0n ? pointer : value;
              if (targetTable !== 8 || (tableId === 6 && columnName === "ParamList") ||
                  (tableId === 7 && columnName === "Param")) continue;
              if (parameterRids.has(row[columnName]?.rid)) {
                throw new FormatError(
                  `Param row ${row[columnName].rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
            }
            if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                columnName === "Token" && row[columnName] >>> 24 === 8 &&
                parameterRids.has(row[columnName] & 0x00ffffff)) {
              throw new FormatError(
                `Param row ${row[columnName] & 0x00ffffff} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
          }
        }
      }
    }
    if (genericParamRids.size > 0) {
      for (const [tableId, tableRows] of this.tables.rows) {
        const schema = metadataTableSchemas[tableId];
        if (!schema) {
          throw new UnsupportedFormatError(
            `Cannot remove MethodDef row ${rid} with unknown metadata table ${tableId}`
          );
        }
        for (const row of tableRows) {
          if (tableId === 44 && genericParamConstraintRids.has(row.rid)) continue;
          for (const [kind, value, name] of schema) {
            const columnName = name ?? value;
            const column = row[columnName];
            const target = kind === "coded"
              ? column?.target
              : kind === "table" ? { table: value, rid: column?.rid } : null;
            if (target?.table === 42 && genericParamRids.has(target.rid)) {
              throw new FormatError(
                `GenericParam row ${target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                columnName === "Token" && row[columnName] >>> 24 === 42 &&
                genericParamRids.has(row[columnName] & 0x00ffffff)) {
              throw new FormatError(
                `GenericParam row ${row[columnName] & 0x00ffffff} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
          }
        }
      }
    }

    const pointerRows = getBijectivePointerRows(this, 5, 6, "Method");
    const pointerRid = pointerRows
      ? pointerRows.findIndex((pointer) => pointer.Method.rid === rid) + 1
      : 0;
    if (pointerRows && pointerRid === 0) {
      throw new FormatError(`MethodPtr has no pointer to MethodDef row ${rid}`);
    }
    const tokenMap = new Map();
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x06000000 + oldRid, 0x06000000 + oldRid - 1);
    }
    const lastParameterRid = parameterRids.size > 0
      ? Math.max(...parameterRids)
      : 0;
    const remapParameterRid = (oldRid) =>
      oldRid > lastParameterRid ? oldRid - parameterRids.size : oldRid;
    if (parameterRids.size > 0) {
      for (let oldRid = lastParameterRid + 1; oldRid <= parameterRows.length; oldRid++) {
        tokenMap.set(0x08000000 + oldRid, 0x08000000 + remapParameterRid(oldRid));
      }
    }
    const lastGenericParamRid = genericParamRids.size > 0
      ? Math.max(...genericParamRids)
      : 0;
    const remapGenericParamRid = (oldRid) =>
      oldRid > lastGenericParamRid ? oldRid - genericParamRids.size : oldRid;
    if (genericParamRids.size > 0) {
      for (let oldRid = lastGenericParamRid + 1; oldRid <= genericParamRows.length; oldRid++) {
        tokenMap.set(0x2a000000 + oldRid, 0x2a000000 + remapGenericParamRid(oldRid));
      }
    }
    const remapGenericParamConstraintRid = (oldRid) => oldRid -
      [...genericParamConstraintRids].filter((constraintRid) => constraintRid < oldRid).length;
    if (genericParamConstraintRids.size > 0) {
      for (let oldRid = 1; oldRid <= genericParamConstraintRows.length; oldRid++) {
        if (genericParamConstraintRids.has(oldRid)) continue;
        tokenMap.set(
          0x2c000000 + oldRid,
          0x2c000000 + remapGenericParamConstraintRid(oldRid)
        );
      }
    }
    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      if (!schema) {
        throw new UnsupportedFormatError(
          `Cannot remove MethodDef row ${rid} with unknown metadata table ${tableId}`
        );
      }
      for (const row of tableRows) {
        if (tableId === 44 && genericParamConstraintRids.has(row.rid)) continue;
        for (const [kind, value, name, pointer] of schema) {
          const columnName = name ?? value;
          if (kind === "coded") {
            const target = row[columnName]?.target;
            if (target?.table === 44) {
              if (genericParamConstraintRids.has(target.rid)) {
                throw new FormatError(
                  `GenericParamConstraint row ${target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              const remappedRid = remapGenericParamConstraintRid(target.rid);
              if (remappedRid !== target.rid) {
                const remappedTarget = { ...target, rid: remappedRid };
                rowChanges.push({
                  row,
                  columnName,
                  value: {
                    raw: encodeCodedIndex(44, remappedRid, value),
                    target: remappedTarget
                  }
                });
              }
              continue;
            }
            if (target?.table === 8 || target?.table === 42) {
              const removedRids = target.table === 8 ? parameterRids : genericParamRids;
              if (removedRids.has(target.rid)) {
                throw new FormatError(
                  `${metadataTableNames[target.table]} row ${target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              const remappedRid = target.table === 8
                ? remapParameterRid(target.rid)
                : remapGenericParamRid(target.rid);
              if (remappedRid !== target.rid) {
                const remappedTarget = { ...target, rid: remappedRid };
                rowChanges.push({
                  row,
                  columnName,
                  value: {
                    raw: encodeCodedIndex(target.table, remappedRid, value),
                    target: remappedTarget
                  }
                });
              }
              continue;
            }
            if (target?.table !== 6) continue;
            if (tableId === 42 && columnName === "Owner" &&
                genericParamRids.has(row.rid)) continue;
            if (target.rid === rid) {
              throw new FormatError(`MethodDef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (target.rid > rid) {
              const remappedTarget = { ...target, rid: target.rid - 1 };
              rowChanges.push({
                row,
                columnName,
                value: {
                  raw: encodeCodedIndex(6, remappedTarget.rid, value),
                  target: remappedTarget
                }
              });
            }
          } else if (kind === "u4" && (tableId === 30 || tableId === 31) &&
              columnName === "Token" && [8, 42].includes(row[columnName] >>> 24)) {
            const tokenTable = row[columnName] >>> 24;
            const targetRid = row[columnName] & 0x00ffffff;
            const removedRids = tokenTable === 8 ? parameterRids : genericParamRids;
            if (removedRids.has(targetRid)) {
              throw new FormatError(
                `${metadataTableNames[tokenTable]} row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            const remappedRid = tokenTable === 8
              ? remapParameterRid(targetRid)
              : remapGenericParamRid(targetRid);
            if (remappedRid !== targetRid) {
              rowChanges.push({
                row,
                columnName,
                value: (tokenTable << 24) | remappedRid
              });
            }
          } else if (kind === "u4" && (tableId === 30 || tableId === 31) &&
              columnName === "Token" && row[columnName] >>> 24 === 44) {
            const targetRid = row[columnName] & 0x00ffffff;
            if (genericParamConstraintRids.has(targetRid)) {
              throw new FormatError(
                `GenericParamConstraint row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            const remappedRid = remapGenericParamConstraintRid(targetRid);
            if (remappedRid !== targetRid) {
              rowChanges.push({
                row,
                columnName,
                value: 0x2c000000 | remappedRid
              });
            }
          } else if (kind === "u4" && (tableId === 30 || tableId === 31) &&
              columnName === "Token" && row[columnName] >>> 24 === 6 &&
              (row[columnName] & 0x00ffffff) === rid) {
            throw new FormatError(`MethodDef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
          } else if (kind === "u4" && (tableId === 30 || tableId === 31) &&
              columnName === "Token" && row[columnName] >>> 24 === 6 &&
              (row[columnName] & 0x00ffffff) > rid) {
            const oldToken = row[columnName];
            rowChanges.push({ row, columnName, value: oldToken - 1 });
          } else if (kind === "table") {
            if (tableId === 2 && columnName === "MethodList") continue;
            const targetTable = pointer !== undefined &&
              (this.tables.valid & (1n << BigInt(pointer))) !== 0n ? pointer : value;
            const targetRid = row[columnName]?.rid;
            if (targetTable === 8) {
              if ((tableId === 6 && columnName === "ParamList") ||
                  (tableId === 7 && columnName === "Param")) continue;
              if (parameterRids.has(targetRid)) {
                throw new FormatError(
                  `Param row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              const remappedRid = remapParameterRid(targetRid);
              if (remappedRid !== targetRid) {
                rowChanges.push({
                  row,
                  columnName,
                  value: { ...row[columnName], raw: remappedRid, rid: remappedRid }
                });
              }
              continue;
            }
            if (targetTable === 42) {
              if (genericParamRids.has(targetRid)) {
                throw new FormatError(
                  `GenericParam row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              const remappedRid = remapGenericParamRid(targetRid);
              if (remappedRid !== targetRid) {
                rowChanges.push({
                  row,
                  columnName,
                  value: { ...row[columnName], raw: remappedRid, rid: remappedRid }
                });
              }
              continue;
            }
            if (targetTable === 44) {
              if (genericParamConstraintRids.has(targetRid)) {
                throw new FormatError(
                  `GenericParamConstraint row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              const remappedRid = remapGenericParamConstraintRid(targetRid);
              if (remappedRid !== targetRid) {
                rowChanges.push({
                  row,
                  columnName,
                  value: { ...row[columnName], raw: remappedRid, rid: remappedRid }
                });
              }
              continue;
            }
            if (targetTable !== 6) continue;
            if (tableId === 5 && columnName === "Method") {
              if (row.rid === pointerRid) continue;
              if (targetRid === rid) {
                throw new FormatError(`MethodDef row ${rid} is referenced by MethodPtr.Method`);
              }
              continue;
            }
            if (targetRid === rid) {
              throw new FormatError(`MethodDef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (targetRid > rid) {
              rowChanges.push({
                row,
                columnName,
                value: { ...row[columnName], raw: targetRid - 1, rid: targetRid - 1 }
              });
            }
          }
        }
      }
    }
    const tokenUpdates = [];
    const patches = [];
    for (const candidate of this.methods) {
      if (candidate.rid === rid) continue;
      const body = this.getMethodBody(candidate.rid);
      for (const instruction of body?.instructions ?? []) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 6) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === rid) {
          throw new FormatError(`MethodDef row ${rid} is referenced by CIL in MethodDef row ${candidate.rid}`);
        }
        if (targetRid > rid) {
          const replacement = token - 1;
          tokenUpdates.push({ instruction, replacement });
          patches.push(...createOperandPatches(instruction, replacement));
        }
      }
    }
    const sortedKeyColumns = new Map([
      [10, "Class"], [11, "Parent"], [12, "Parent"], [13, "Parent"], [14, "Parent"],
      [28, "MemberForwarded"], [42, "Owner"], [43, "Method"]
    ]);
    const changedSortedKeys = new Map(rowChanges
      .filter((change) => [...sortedKeyColumns.values()].includes(change.columnName))
      .map((change) => [change.row, change.value]));
    for (const [tableId, keyOf] of [
      [10, (row) => [row.Class.raw]],
      [11, (row) => [row.Parent.raw]],
      [12, (row) => [row.Parent.raw]],
      [13, (row) => [row.Parent.raw]],
      [14, (row) => [row.Parent.raw, row.Action]],
      [28, (row) => [row.MemberForwarded.raw]],
      [42, (row) => [row.Owner.raw, row.Number]],
      [43, (row) => [row.Method.raw]]
    ]) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = null;
      for (const row of this.tables.get(tableId)) {
        const changedKey = changedSortedKeys.get(row);
        const current = keyOf(row);
        if (changedKey) current[0] = changedKey.raw ?? changedKey;
        let outOfOrder = false;
        if (previous) {
          for (let index = 0; index < current.length; index++) {
            if (current[index] === previous[index]) continue;
            outOfOrder = current[index] < previous[index];
            break;
          }
        }
        if (outOfOrder) {
          throw new FormatError(
            `MethodDef token remapping would violate sorted ${metadataTableNames[tableId]} order`
          );
        }
        previous = current;
      }
    }

    const methodPointerPresent = pointerRows !== null;
    if (embeddedPdbIndices.length === 1) {
      const updatedCounts = [...this.tables.counts];
      updatedCounts[6]--;
      if (methodPointerPresent) updatedCounts[5]--;
      if (parameterRids.size > 0) {
        updatedCounts[8] -= parameterRids.size;
        if (paramPointerRows) updatedCounts[7] -= parameterRids.size;
      }
      if (genericParamRids.size > 0) updatedCounts[42] -= genericParamRids.size;
      if (genericParamConstraintRids.size > 0) {
        updatedCounts[44] -= genericParamConstraintRids.size;
      }
      const debugEntryIndex = embeddedPdbIndices[0];
      const debugEntry = this.pe.debugDirectoryEntries[debugEntryIndex];
      const pdb = this.#getPortablePdbForEdit(debugEntryIndex, debugEntry);
      const updatedPdb = removePortablePdbMethod(
        pdb,
        rid,
        this.tables.counts,
        updatedCounts
      );
      this.#replaceEmbeddedPortablePdb(debugEntryIndex, updatedPdb, updatedCounts);
    }
    if (remappedCliEntryPointToken !== cliEntryPointToken) {
      const entryPointBytes = new Uint8Array(4);
      new DataView(entryPointBytes.buffer).setUint32(0, remappedCliEntryPointToken, true);
      patches.push({
        offset: this.cli.offset + 20,
        bytes: entryPointBytes
      });
      this._cliEntryPointToken = remappedCliEntryPointToken;
    }
    if (methodPointerPresent) {
      const remainingPointers = pointerRows.filter((pointer) => pointer.rid !== pointerRid);
      remainingPointers.forEach((pointer, index) => {
        pointer.rid = index + 1;
        if (pointer.Method.rid > rid) {
          pointer.Method = {
            ...pointer.Method,
            raw: pointer.Method.rid - 1,
            rid: pointer.Method.rid - 1
          };
        }
      });
      this.tables.rows.set(5, remainingPointers);
      this.tables.counts[5] = remainingPointers.length;
      if (remainingPointers.length === 0) this.tables.valid &= ~(1n << 5n);
    }
    const listBoundary = methodPointerPresent ? pointerRid : rid;
    const listChanges = [];
    for (const typeRow of this.tables.rows.get(2) ?? []) {
      if (typeRow.MethodList.rid > listBoundary) {
        listChanges.push({
          row: typeRow,
          value: {
            ...typeRow.MethodList,
            raw: typeRow.MethodList.rid - 1,
            rid: typeRow.MethodList.rid - 1
          }
        });
      }
    }
    const removedParamListPositions = paramPointerRows
      ? paramPointerRows.filter((pointer) => parameterRids.has(pointer.Param.rid))
        .map((pointer) => pointer.rid)
      : [...parameterRids];
    const paramListChanges = [];
    if (removedParamListPositions.length > 0) {
      for (const methodRow of this.tables.get(6)) {
        const oldBoundary = methodRow.ParamList.rid;
        const newBoundary = oldBoundary -
          removedParamListPositions.filter((position) => position < oldBoundary).length;
        if (newBoundary === oldBoundary) continue;
        paramListChanges.push({
          row: methodRow,
          value: {
            ...methodRow.ParamList,
            raw: newBoundary,
            rid: newBoundary
          }
        });
      }
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of listChanges) change.row.MethodList = change.value;
    for (const change of paramListChanges) change.row.ParamList = change.value;
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    if (parameterRids.size > 0) {
      const remainingParams = parameterRows.filter((parameter) => !parameterRids.has(parameter.rid));
      remainingParams.forEach((parameter) => {
        parameter.rid = remapParameterRid(parameter.rid);
      });
      this.tables.rows.set(8, remainingParams);
      this.tables.counts[8] = remainingParams.length;
      if (remainingParams.length === 0) this.tables.valid &= ~(1n << 8n);
      if (paramPointerRows) {
        const remainingParamPointers = paramPointerRows.filter((pointer) =>
          !parameterRids.has(pointer.Param.rid)
        );
        remainingParamPointers.forEach((pointer, index) => {
          pointer.rid = index + 1;
          const remappedRid = remapParameterRid(pointer.Param.rid);
          if (remappedRid !== pointer.Param.rid) {
            pointer.Param = {
              ...pointer.Param,
              raw: remappedRid,
              rid: remappedRid
            };
          }
        });
        this.tables.rows.set(7, remainingParamPointers);
        this.tables.counts[7] = remainingParamPointers.length;
        if (remainingParamPointers.length === 0) this.tables.valid &= ~(1n << 7n);
      }
      for (const candidate of this.methods) {
        candidate.parameterRids = candidate.parameterRids
          .filter((parameterRid) => !parameterRids.has(parameterRid))
          .map(remapParameterRid);
        candidate.parameters = candidate.parameters
          .filter((parameter) => !parameterRids.has(parameter.rid))
          .map((parameter) => {
            parameter.rid = remapParameterRid(parameter.rid);
            return parameter;
          });
      }
    }
    if (genericParamRids.size > 0) {
      const remainingGenericParams = genericParamRows.filter((parameter) =>
        !genericParamRids.has(parameter.rid)
      );
      remainingGenericParams.forEach((parameter) => {
        parameter.rid = remapGenericParamRid(parameter.rid);
      });
      this.tables.rows.set(42, remainingGenericParams);
      this.tables.counts[42] = remainingGenericParams.length;
      if (remainingGenericParams.length === 0) this.tables.valid &= ~(1n << 42n);
      this.genericParams = this.genericParams.filter((parameter) =>
        !genericParamRids.has(parameter.rid)
      );
      for (const parameter of this.genericParams) {
        parameter.rid = remapGenericParamRid(parameter.rid);
      }
      for (const constraint of this.genericParamConstraints) {
        constraint.ownerRid = remapGenericParamRid(constraint.ownerRid);
      }
    }
    if (genericParamConstraintRids.size > 0) {
      const remainingConstraints = this.genericParamConstraints.filter((constraint) =>
        !genericParamConstraintRids.has(constraint.rid)
      );
      remainingConstraints.forEach((constraint) => {
        constraint.rid = remapGenericParamConstraintRid(constraint.rid);
      });
      this.genericParamConstraints.splice(
        0,
        this.genericParamConstraints.length,
        ...remainingConstraints
      );
      const remainingConstraintRows = genericParamConstraintRows.filter((constraint) =>
        !genericParamConstraintRids.has(constraint.rid)
      );
      remainingConstraintRows.forEach((constraint) => {
        constraint.rid = remapGenericParamConstraintRid(constraint.rid);
      });
      this.tables.rows.set(44, remainingConstraintRows);
      this.tables.counts[44] = remainingConstraintRows.length;
      if (remainingConstraintRows.length === 0) this.tables.valid &= ~(1n << 44n);
    }
    if (parameterRids.size > 0 || genericParamRids.size > 0) {
      for (const attribute of this.customAttributes) {
        if (attribute.parent?.table === 8 && !parameterRids.has(attribute.parent.rid)) {
          attribute.parent = {
            ...attribute.parent,
            rid: remapParameterRid(attribute.parent.rid)
          };
        } else if (attribute.parent?.table === 42 &&
            !genericParamRids.has(attribute.parent.rid)) {
          attribute.parent = {
            ...attribute.parent,
            rid: remapGenericParamRid(attribute.parent.rid)
          };
        } else if (attribute.parent?.table === 44 &&
            !genericParamConstraintRids.has(attribute.parent.rid)) {
          attribute.parent = {
            ...attribute.parent,
            rid: remapGenericParamConstraintRid(attribute.parent.rid)
          };
        }
      }
    }
    const remainingRows = rows.filter((row) => row.rid !== rid);
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.tables.rows.set(6, remainingRows);
    this.tables.counts[6] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 6n);
    for (const type of this.types) {
      type.methodRids = type.methodRids
        .filter((methodRid) => methodRid !== rid)
        .map((methodRid) => methodRid > rid ? methodRid - 1 : methodRid);
      type.methods = type.methods.filter((candidate) => candidate.rid !== rid);
      for (const candidate of type.methods) {
        if (candidate.rid > rid) candidate.rid--;
      }
    }
    this.methods.splice(rid - 1, 1);
    this.methods.forEach((candidate, index) => {
      candidate.rid = index + 1;
    });
    for (const parameter of this.genericParams) {
      if (parameter.owner.table === 6 && parameter.owner.rid > rid) {
        parameter.owner = { ...parameter.owner, rid: parameter.owner.rid - 1 };
      }
    }
    for (const memberRef of this.memberRefs) {
      if (memberRef.parent?.table === 6 && memberRef.parent.rid > rid) {
        memberRef.parent = { ...memberRef.parent, rid: memberRef.parent.rid - 1 };
      }
    }
    for (const methodSpec of this.methodSpecs) {
      if (methodSpec.method?.table === 6 && methodSpec.method.rid > rid) {
        methodSpec.method = { ...methodSpec.method, rid: methodSpec.method.rid - 1 };
      }
    }
    for (const attribute of this.customAttributes) {
      if (attribute.parent?.table === 6 && attribute.parent.rid > rid) {
        attribute.parent = { ...attribute.parent, rid: attribute.parent.rid - 1 };
      }
    }
    const remappedBodyCache = new Map();
    for (const [methodRid, body] of this._bodyCache) {
      if (methodRid === rid) continue;
      remappedBodyCache.set(methodRid > rid ? methodRid - 1 : methodRid, body);
    }
    this._bodyCache = remappedBodyCache;
    this._addedMethodBodies.delete(rid);
    this._bodyCache.delete(rid);
    this._metadataDirty = true;
    return tokenMap;
  }

  addParam({ owner, name = "", sequence, flags = 0 }) {
    return this.#writeParam({ owner, name, sequence, flags }, false).rid;
  }

  insertParam({ owner, name = "", sequence, flags = 0 }) {
    return this.#writeParam({ owner, name, sequence, flags }, true);
  }

  #writeParam({ owner, name = "", sequence, flags = 0 }, insertIntoOwner) {
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 6 ? owner.rid : 0;
    const method = this.methods[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !method) {
      throw new RangeError("Param owner must identify an existing MethodDef");
    }
    if (typeof name !== "string" || name.includes("\0")) {
      throw new TypeError("Param name must be a null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffff) {
      throw new RangeError("Param flags must be an unsigned 16-bit integer");
    }
    if (!Number.isInteger(sequence) || sequence < 0 || sequence > 0xffff) {
      throw new RangeError("Param sequence must be an unsigned 16-bit integer");
    }
    const signature = parseSignature(method.signature, { counts: this.tables.counts });
    if (signature.kind !== "method" || sequence > signature.parameters.length) {
      throw new RangeError("Param sequence exceeds the MethodDef signature parameter count");
    }
    if (method.parameters.some((parameter) => parameter.sequence === sequence)) {
      throw new FormatError(`MethodDef row ${ownerRid} already has Param sequence ${sequence}`);
    }
    if (insertIntoOwner && method.parameters.some((parameter, index) =>
      index > 0 && parameter.sequence <= method.parameters[index - 1].sequence
    )) {
      throw new UnsupportedFormatError(
        "Param insertion requires the method's existing parameters to be in sequence order"
      );
    }
    const parameterIndex = method.parameters.findIndex((parameter) =>
      parameter.sequence > sequence
    );
    if (!insertIntoOwner && parameterIndex !== -1) {
      throw new UnsupportedFormatError("Param append must preserve the method's sequence order");
    }

    const rows = this.tables.rows.get(8) ?? [];
    const originalRowCount = rows.length;
    if (rows.length !== this.tables.counts[8] || rows.length >= 0x00ffffff) {
      throw new RangeError("Param row count is inconsistent or exceeds the metadata table limit");
    }
    const methodRows = this.tables.rows.get(6) ?? [];
    if (methodRows.length !== (this.tables.counts[6] ?? 0) ||
        methodRows.length !== this.methods.length) {
      throw new FormatError("MethodDef row count is inconsistent with the metadata table header");
    }
    const ownerRow = methodRows[ownerRid - 1];
    if (ownerRow?.rid !== ownerRid || !Number.isInteger(ownerRow.ParamList?.rid)) {
      throw new FormatError(`MethodDef row ${ownerRid} has an inconsistent ParamList`);
    }
    const pointerPresent = (this.tables.valid & (1n << 7n)) !== 0n;
    const pointerRows = getBijectivePointerRows(this, 7, 8, "Param");
    if (pointerPresent && !pointerRows) {
      throw new FormatError("ParamPtr must be a one-to-one mapping to Param rows");
    }
    const listRows = pointerRows ?? rows;
    const endRid = methodRows[ownerRid]?.ParamList.rid ?? listRows.length + 1;
    const ownedRids = pointerRows
      ? pointerRows.slice(ownerRow.ParamList.rid - 1, endRid - 1)
        .map((pointer) => pointer.Param.rid)
      : Array.from(
        { length: Math.max(0, endRid - ownerRow.ParamList.rid) },
        (_, index) => ownerRow.ParamList.rid + index
      );
    if (endRid > listRows.length + 1 ||
        ownedRids.length !== method.parameterRids.length ||
        ownedRids.some((paramRid, index) => paramRid !== method.parameterRids[index])) {
      throw new UnsupportedFormatError("Param insertion requires a valid contiguous method range");
    }
    if (!insertIntoOwner && endRid !== listRows.length + 1) {
      throw new UnsupportedFormatError("Param append requires the method's parameters to be contiguous at the end");
    }
    const insertionIndex = parameterIndex === -1 ? method.parameters.length : parameterIndex;
    const rid = pointerRows ? rows.length + 1 : ownerRow.ParamList.rid + insertionIndex;
    const pointerInsertionIndex = pointerRows
      ? ownerRow.ParamList.rid - 1 + insertionIndex
      : -1;
    const pointerRid = pointerInsertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = pointerRows
      ? { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] }
      : this.#prepareTokenRowInsertion(8, rid, rows.length, "Param");

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    heapStreams.set("#Strings", stringHeap.heap);
    const paramRow = {
      table: 8,
      tableName: metadataTableNames[8],
      rid,
      Flags: flags,
      Sequence: sequence,
      Name: stringHeap.index
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(rid - 1, 0, paramRow);
    this.tables.rows.set(8, rows);
    this.tables.counts[8] = rows.length;
    this.tables.valid |= 1n << 8n;
    if (pointerRows) {
      for (const row of pointerRows) {
        if (row.rid >= pointerRid) row.rid++;
      }
      pointerRows.splice(pointerInsertionIndex, 0, {
        table: 7,
        tableName: metadataTableNames[7],
        rid: pointerRid,
        Param: { raw: rid, table: 8, tableName: metadataTableNames[8], rid }
      });
      this.tables.rows.set(7, pointerRows);
      this.tables.counts[7] = pointerRows.length;
    }
    if (pointerRows || rid > originalRowCount) {
      for (let index = ownerRid; index < methodRows.length; index++) {
        methodRows[index].ParamList.rid++;
        methodRows[index].ParamList.raw++;
      }
    }
    for (const candidate of this.methods) {
      if (!pointerRows) {
        candidate.parameterRids = candidate.parameterRids.map((paramRid) =>
          paramRid >= rid ? paramRid + 1 : paramRid
        );
        for (const parameter of candidate.parameters) {
          if (parameter.rid >= rid) parameter.rid++;
        }
      }
    }
    method.parameterRids.splice(insertionIndex, 0, rid);
    method.parameters.splice(insertionIndex, 0, { rid, flags, sequence, name });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceParam(rid, { name, flags } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(8, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid Param row ID ${rid}`);
    }
    const parameter = this.methods.flatMap((method) => method.parameters)
      .find((item) => item.rid === rid);
    if (!parameter) throw new UnsupportedFormatError(`Param row ${rid} has no resolved MethodDef owner`);
    const nextName = name === undefined ? parameter.name : name;
    const nextFlags = flags === undefined ? row.Flags : flags;
    if (typeof nextName !== "string" || nextName.includes("\0")) {
      throw new TypeError("Param name must be a null-free string");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 0xffff) {
      throw new RangeError("Param flags must be an unsigned 16-bit integer");
    }
    if (nextName === parameter.name && nextFlags === row.Flags) return this;
    this.#validateAssociatedFlags(8, rid, nextFlags);

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== parameter.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.Name = stringHeap.index;
    }
    row.Flags = nextFlags;
    parameter.name = nextName;
    parameter.flags = nextFlags;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeParam(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("Param removal cannot be combined with structural method edits");
    }
    const rows = this.tables.rows.get(8) ?? [];
    if (rows.length !== this.tables.counts[8]) {
      throw new FormatError("Param row count is inconsistent with the metadata table header");
    }
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid Param row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap Param rows with unrecognized metadata stream ${streamName}`
        );
      }
    }
    const owners = this.methods.filter((method) => method.parameterRids.includes(rid));
    const parameter = this.methods.flatMap((method) => method.parameters)
      .find((item) => item.rid === rid);
    if (owners.length !== 1 || !parameter) {
      throw new FormatError(`Param row ${rid} has no unique resolved MethodDef owner`);
    }

    const pointerPresent = (this.tables.valid & (1n << 7n)) !== 0n;
    const pointerRows = this.tables.rows.get(7) ?? [];
    let pointerRid = 0;
    if (pointerPresent) {
      const pointedRids = pointerRows.map((pointer) => pointer.Param?.rid);
      if (pointerRows.length !== this.tables.counts[7] ||
          pointerRows.length !== rows.length ||
          pointedRids.some((paramRid) => !Number.isInteger(paramRid) || paramRid < 1 ||
            paramRid > rows.length) ||
          new Set(pointedRids).size !== rows.length) {
        throw new UnsupportedFormatError("Param removal requires a one-to-one ParamPtr table");
      }
      pointerRid = pointedRids.indexOf(rid) + 1;
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        const columnName = name ?? value;
        if (kind === "coded") {
          for (const row of tableRows) {
            const target = row[columnName]?.target;
            if (target?.table !== 8) continue;
            if (target.rid === rid) {
              throw new FormatError(
                `Param row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (target.rid > rid) {
              const remappedTarget = { ...target, rid: target.rid - 1 };
              rowChanges.push({
                row,
                columnName,
                value: {
                  raw: encodeCodedIndex(8, remappedTarget.rid, value),
                  target: remappedTarget
                }
              });
            }
          }
          continue;
        }
        if (kind !== "table" || value !== 8 ||
            (tableId === 6 && columnName === "ParamList")) continue;
        for (const row of tableRows) {
          const targetRid = row[columnName]?.rid;
          if (tableId === 7 && columnName === "Param" && targetRid === rid) continue;
          if (targetRid === rid) {
            throw new FormatError(
              `Param row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
            );
          }
          if (targetRid > rid) {
            rowChanges.push({
              row,
              columnName,
              value: { ...row[columnName], raw: targetRid - 1, rid: targetRid - 1 }
            });
          }
        }
      }
    }

    const listChanges = this.tables.get(6).map((methodRow) => {
      const start = methodRow.ParamList.rid;
      const boundary = pointerPresent ? pointerRid : rid;
      return { row: methodRow, value: start > boundary ? start - 1 : start };
    });
    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingParameters = this.methods.flatMap((method) =>
      method.parameters.filter((item) => item.rid !== rid)
    );
    if (remainingRows.length !== remainingParameters.length) {
      throw new FormatError(`Param row ${rid} has inconsistent semantic records`);
    }

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of listChanges) {
      change.row.ParamList = {
        ...change.row.ParamList,
        raw: change.value,
        rid: change.value
      };
    }
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.tables.rows.set(8, remainingRows);
    this.tables.counts[8] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 8n);
    if (pointerPresent) {
      const remainingPointers = pointerRows.filter((pointer) => pointer.rid !== pointerRid);
      remainingPointers.forEach((pointer, index) => {
        pointer.rid = index + 1;
      });
      this.tables.rows.set(7, remainingPointers);
      this.tables.counts[7] = remainingPointers.length;
    }
    for (const method of this.methods) {
      method.parameterRids = method.parameterRids
        .filter((parameterRid) => parameterRid !== rid)
        .map((parameterRid) => parameterRid > rid ? parameterRid - 1 : parameterRid);
      method.parameters = method.parameters
        .filter((item) => item.rid !== rid)
        .map((item) => {
          if (item.rid > rid) item.rid--;
          return item;
        });
    }
    this._metadataDirty = true;
    return new Map(
      Array.from({ length: rows.length - rid }, (_, index) =>
        [rid + index + 1, rid + index]
      )
    );
  }

  reorderPointerTable(pointerTable, targetRids) {
    this.#ensureEditable();
    const pointerTableId = metadataTableId(pointerTable);
    const definitions = new Map([
      [3, { targetTableId: 4, column: "Field", owners: this.types, list: "fieldRids", records: "fields" }],
      [5, { targetTableId: 6, column: "Method", owners: this.types, list: "methodRids", records: "methods" }],
      [7, {
        targetTableId: 8,
        column: "Param",
        owners: this.methods,
        list: "parameterRids",
        records: "parameters"
      }],
      [19, { targetTableId: 20, column: "Event", owners: this.types, list: "eventRids", records: "events" }],
      [22, {
        targetTableId: 23,
        column: "Property",
        owners: this.types,
        list: "propertyRids",
        records: "properties"
      }]
    ]);
    const definition = definitions.get(pointerTableId);
    if (!definition) {
      throw new TypeError("Pointer table must be FieldPtr, MethodPtr, ParamPtr, EventPtr, or PropertyPtr");
    }
    const allowsCrossOwnerFields = pointerTableId === 3;
    const allowsCrossOwnerMethods = pointerTableId === 5;
    const allowsCrossOwnerParameters = pointerTableId === 7;
    const allowsCrossOwnerEvents = pointerTableId === 19;
    const allowsCrossOwnerProperties = pointerTableId === 22;
    if ((this.tables.valid & (1n << BigInt(pointerTableId))) === 0n) {
      throw new UnsupportedFormatError(`${metadataTableNames[pointerTableId]} is not present`);
    }
    const pointerRows = getBijectivePointerRows(
      this,
      pointerTableId,
      definition.targetTableId,
      definition.column
    );
    if (!pointerRows) {
      throw new FormatError(
        `${metadataTableNames[pointerTableId]} must be a one-to-one mapping to ${metadataTableNames[definition.targetTableId]}`
      );
    }
    const targetCount = this.tables.counts[definition.targetTableId] ?? 0;
    if (!Array.isArray(targetRids) || targetRids.length !== targetCount) {
      throw new RangeError("Pointer table order must contain every target row exactly once");
    }
    const newRids = [...targetRids];
    const uniqueRids = new Set(newRids);
    if (uniqueRids.size !== targetCount ||
        newRids.some((rid) => !Number.isInteger(rid) || rid < 1 || rid > targetCount)) {
      throw new RangeError("Pointer table order must contain every target row exactly once");
    }

    const ownerGroups = definition.owners.map((owner) => owner[definition.list]);
    const currentOwnerRids = ownerGroups.flat();
    if (currentOwnerRids.length !== targetCount ||
        new Set(currentOwnerRids).size !== targetCount) {
      throw new FormatError(
        `${metadataTableNames[definition.targetTableId]} ownership does not cover every row exactly once`
      );
    }
    const currentOwnerByRid = new Map();
    for (let index = 0; index < ownerGroups.length; index++) {
      for (const rid of ownerGroups[index]) {
        currentOwnerByRid.set(rid, definition.owners[index].rid);
      }
    }
    const assignments = [];
    let offset = 0;
    const recordsByRid = new Map(
      definition.owners.flatMap((owner) =>
        owner[definition.records].map((record) => [record.rid, record])
      )
    );
    for (let index = 0; index < definition.owners.length; index++) {
      const owner = definition.owners[index];
      const oldGroup = ownerGroups[index];
      const nextGroup = newRids.slice(offset, offset + oldGroup.length);
      offset += oldGroup.length;
      const oldSet = new Set(oldGroup);
      const movesRowsAcrossOwners = nextGroup.some((rid) => !oldSet.has(rid));
      const allowsCrossOwnerRows = allowsCrossOwnerFields || allowsCrossOwnerMethods ||
        allowsCrossOwnerParameters || allowsCrossOwnerEvents || allowsCrossOwnerProperties;
      if (!allowsCrossOwnerRows && movesRowsAcrossOwners) {
        throw new UnsupportedFormatError("Pointer reordering cannot change row ownership");
      }
      const nextRecords = nextGroup.map((rid) => recordsByRid.get(rid));
      if (nextRecords.some((record) => !record)) {
        throw new FormatError(`${metadataTableNames[definition.targetTableId]} ownership has no semantic record`);
      }
      const movedRecords = nextRecords.filter((record) =>
        currentOwnerByRid.get(record.rid) !== owner.rid
      );
      if (allowsCrossOwnerFields) {
        for (const record of movedRecords) {
          const parsed = parseSignature(record.signature, { counts: this.tables.counts });
          if (parsed.kind !== "field") {
            throw new FormatError(`Field row ${record.rid} has a non-field signature`);
          }
          validateGenericVariableReferences(
            parsed,
            getGenericParameterArity(this.genericParams, 2, owner.rid),
            this
          );
          if ((this.tables.rows.get(16) ?? []).some((layout) =>
            layout.Field.rid === record.rid
          ) && (owner.flags & 0x0018) !== 0x0010) {
            throw new UnsupportedFormatError(
              `Field row ${record.rid} has an explicit offset and requires an explicit-layout owner`
            );
          }
        }
      }
      if (allowsCrossOwnerParameters && movesRowsAcrossOwners) {
        const signature = parseSignature(owner.signature, { counts: this.tables.counts });
        if (signature.kind !== "method") {
          throw new FormatError(`MethodDef row ${owner.rid} has a non-method signature`);
        }
        const sequences = new Set();
        for (const record of nextRecords) {
          if (!Number.isInteger(record.sequence) || record.sequence < 0 ||
              record.sequence > signature.parameters.length) {
            throw new FormatError(
              `Param row ${record.rid} sequence exceeds MethodDef row ${owner.rid}'s signature`
            );
          }
          if (sequences.has(record.sequence)) {
            throw new FormatError(
              `MethodDef row ${owner.rid} would have duplicate Param sequence ${record.sequence}`
            );
          }
          sequences.add(record.sequence);
        }
      }
      if (allowsCrossOwnerMethods && movesRowsAcrossOwners) {
        if ((owner.flags & (0x0080 | 0x0020)) === 0) {
          throw new UnsupportedFormatError(
            "Pointer reordering cannot move abstract methods to a non-abstract TypeDef"
          );
        }
        for (const record of movedRecords) {
          if (record.rva !== 0 || (record.flags & 0x0440) !== 0x0440 ||
              record.genericParams.length > 0) {
            throw new UnsupportedFormatError(
              "Cross-owner MethodPtr reordering supports only bodyless, non-generic abstract virtual methods"
            );
          }
          const signature = parseSignature(record.signature, { counts: this.tables.counts });
          if (signature.kind !== "method") {
            throw new FormatError(`MethodDef row ${record.rid} has a non-method signature`);
          }
          if ((signature.genericParameterCount ?? 0) > 0) {
            throw new UnsupportedFormatError(
              "Cross-owner MethodPtr reordering does not support generic methods"
            );
          }
          validateGenericVariableReferences(
            signature,
            getGenericParameterArity(this.genericParams, 2, owner.rid),
            this,
            null,
            signature.genericParameterCount ?? 0
          );
          const hasMethodSemantics = (this.tables.rows.get(24) ?? []).some((row) =>
            row.Method.rid === record.rid
          );
          const hasMethodImpl = (this.tables.rows.get(25) ?? []).some((row) =>
            row.MethodBody.target?.table === 6 && row.MethodBody.target.rid === record.rid ||
            row.MethodDeclaration.target?.table === 6 && row.MethodDeclaration.target.rid === record.rid
          );
          if (hasMethodSemantics || hasMethodImpl) {
            throw new UnsupportedFormatError(
              "Pointer reordering cannot change row ownership for methods with semantics or MethodImpl rows"
            );
          }
        }
      }
      if (allowsCrossOwnerEvents && movesRowsAcrossOwners) {
        for (const record of movedRecords) {
          const hasSemantics = (this.tables.rows.get(24) ?? []).some((row) =>
            row.Association.target?.table === 20 && row.Association.target.rid === record.rid
          );
          if (hasSemantics) {
            throw new UnsupportedFormatError(
              "Pointer reordering cannot change row ownership for events with MethodSemantics rows"
            );
          }
          if (record.eventType.table === 27) {
            const typeArity = getGenericParameterArity(this.genericParams, 2, owner.rid);
            const typeSpec = this.typeSpecs[record.eventType.rid - 1];
            if (!typeSpec) {
              throw new FormatError(`Event row ${record.rid} references missing TypeSpec row ${record.eventType.rid}`);
            }
            validateTypeSpecDefinitions(this, typeSpec.parsedSignature);
            validateTypeSpecGenericContext(this, record.eventType.rid, typeArity);
          }
        }
      }
      if (allowsCrossOwnerProperties && movesRowsAcrossOwners) {
        for (const record of movedRecords) {
          const hasSemantics = (this.tables.rows.get(24) ?? []).some((row) =>
            row.Association.target?.table === 23 && row.Association.target.rid === record.rid
          );
          if (hasSemantics) {
            throw new UnsupportedFormatError(
              "Pointer reordering cannot change row ownership for properties with MethodSemantics rows"
            );
          }
          const signature = parseSignature(record.signature, { counts: this.tables.counts });
          if (signature.kind !== "property") {
            throw new FormatError(`Property row ${record.rid} has a non-property signature`);
          }
          validateGenericVariableReferences(
            signature,
            getGenericParameterArity(this.genericParams, 2, owner.rid),
            this
          );
        }
      }
      assignments.push({ owner, nextGroup, nextRecords });
    }
    if (offset !== targetCount) {
      throw new FormatError(
        `${metadataTableNames[definition.targetTableId]} ownership does not cover every row exactly once`
      );
    }

    const nextPointerRows = newRids.map((rid, index) => ({
      ...pointerRows[index],
      rid: index + 1,
      [definition.column]: {
        raw: rid,
        table: definition.targetTableId,
        tableName: metadataTableNames[definition.targetTableId],
        rid
      }
    }));
    this.tables.rows.set(pointerTableId, nextPointerRows);
    for (const assignment of assignments) {
      assignment.owner[definition.list] = assignment.nextGroup;
      assignment.owner[definition.records] = assignment.nextRecords;
    }
    this._metadataDirty = true;
    return this;
  }

  addField({ owner, name, flags = 0, signature }) {
    return this.#writeField({ owner, name, flags, signature }, false).token;
  }

  insertField({ owner, name, flags = 0, signature }) {
    return this.#writeField({ owner, name, flags, signature }, true);
  }

  #writeField({ owner, name, flags, signature }, insertIntoOwner) {
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    const ownerType = this.types[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !ownerType) {
      throw new RangeError("Field owner must identify an existing TypeDef");
    }
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("Field name must be a non-empty null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffff) {
      throw new RangeError("Field flags must be an unsigned 16-bit integer");
    }
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
      throw new TypeError("Field signature must be a non-empty Uint8Array");
    }
    const parsedSignature = parseSignature(signature, { counts: this.tables.counts });
    if (parsedSignature.kind !== "field") {
      throw new FormatError("Field signature must use the field signature form");
    }
    validateGenericVariableReferences(
      parsedSignature,
      getGenericParameterArity(this.genericParams, 2, ownerRid),
      this
    );
    const fieldRows = this.tables.rows.get(4) ?? [];
    const originalFieldCount = fieldRows.length;
    if (fieldRows.length !== this.tables.counts[4] ||
        fieldRows.length >= 0x00ffffff) {
      throw new RangeError("Field token row ID exceeds 24-bit range or table counts are inconsistent");
    }
    const typeRows = this.tables.rows.get(2) ?? [];
    if (typeRows.length !== (this.tables.counts[2] ?? 0)) {
      throw new FormatError("TypeDef row count is inconsistent with the metadata table header");
    }
    const ownerRow = typeRows[ownerRid - 1];
    if (ownerRow?.rid !== ownerRid || !Number.isInteger(ownerRow.FieldList?.rid)) {
      throw new FormatError(`TypeDef row ${ownerRid} has an inconsistent FieldList`);
    }
    const pointerPresent = (this.tables.valid & (1n << 3n)) !== 0n;
    const pointerRows = getBijectivePointerRows(this, 3, 4, "Field");
    if (pointerPresent && !pointerRows) {
      throw new FormatError("FieldPtr must be a one-to-one mapping to Field rows");
    }
    const listRows = pointerRows ?? fieldRows;
    const endRid = typeRows[ownerRid]?.FieldList.rid ?? listRows.length + 1;
    const ownedRids = pointerRows
      ? pointerRows.slice(ownerRow.FieldList.rid - 1, endRid - 1)
        .map((pointer) => pointer.Field.rid)
      : Array.from(
        { length: Math.max(0, endRid - ownerRow.FieldList.rid) },
        (_, index) => ownerRow.FieldList.rid + index
      );
    if (endRid > listRows.length + 1 ||
        ownedRids.length !== ownerType.fieldRids.length ||
        ownedRids.some((rid, index) => rid !== ownerType.fieldRids[index])) {
      throw new UnsupportedFormatError("Field insertion requires a valid contiguous owner range");
    }
    if (!insertIntoOwner && endRid !== listRows.length + 1) {
      throw new UnsupportedFormatError("Field append requires the owner's fields to be contiguous at the end");
    }
    const rid = pointerRows ? fieldRows.length + 1 : endRid;
    const pointerInsertionIndex = pointerRows
      ? ownerRow.FieldList.rid - 1 + ownedRids.length
      : -1;
    const pointerRid = pointerInsertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = pointerRows
      ? { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] }
      : this.#prepareTokenRowInsertion(4, rid, fieldRows.length, "Field");
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Strings", stringHeap.heap);
    heapStreams.set("#Blob", blobHeap.heap);
    const fieldRow = {
      table: 4,
      tableName: metadataTableNames[4],
      rid,
      Flags: flags,
      Name: stringHeap.index,
      Signature: blobHeap.index
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of fieldRows) {
      if (row.rid >= rid) row.rid++;
    }
    fieldRows.splice(rid - 1, 0, fieldRow);
    this.tables.rows.set(4, fieldRows);
    this.tables.valid |= 1n << 4n;
    this.tables.counts[4] = fieldRows.length;
    if (pointerRows) {
      for (const row of pointerRows) {
        if (row.rid >= pointerRid) row.rid++;
      }
      pointerRows.splice(pointerInsertionIndex, 0, {
        table: 3,
        tableName: metadataTableNames[3],
        rid: pointerRid,
        Field: { raw: rid, table: 4, tableName: metadataTableNames[4], rid }
      });
      this.tables.rows.set(3, pointerRows);
      this.tables.counts[3] = pointerRows.length;
    }
    if (pointerRows || rid > originalFieldCount) {
      for (let index = ownerRid; index < typeRows.length; index++) {
        typeRows[index].FieldList.rid++;
        typeRows[index].FieldList.raw++;
      }
    }
    for (const type of this.types) {
      if (!pointerRows) {
        type.fieldRids = type.fieldRids.map((fieldRid) => fieldRid >= rid ? fieldRid + 1 : fieldRid);
        for (const field of type.fields) {
          if (field.rid >= rid) field.rid++;
        }
      }
    }
    ownerType.fieldRids.push(rid);
    ownerType.fields.push({ rid, flags, name, signature: signature.slice() });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { token: 0x04000000 + rid, tokenMap };
  }

  addMethodSemantics({ methodRid, association, semantics }) {
    return this.#writeMethodSemantics({ methodRid, association, semantics }, false).rid;
  }

  insertMethodSemantics({ methodRid, association, semantics }) {
    return this.#writeMethodSemantics({ methodRid, association, semantics }, true);
  }

  #writeMethodSemantics({ methodRid, association, semantics }, insertSorted) {
    this.#ensureEditable();
    const associationTable = metadataTableId(association?.table);
    if (![20, 23].includes(associationTable) || !Number.isInteger(association.rid) ||
        association.rid < 1 || association.rid > (this.tables.counts[associationTable] ?? 0)) {
      throw new RangeError("MethodSemantics association must identify an existing Event or Property row");
    }
    if (!Number.isInteger(methodRid) || methodRid < 1 || methodRid > (this.tables.counts[6] ?? 0)) {
      throw new RangeError("MethodSemantics method must identify an existing MethodDef row");
    }
    const associationRaw = encodeCodedIndex(associationTable, association.rid, "HasSemantics");
    const rows = this.tables.rows.get(24) ?? [];
    if (rows.length !== (this.tables.counts[24] ?? 0) || rows.length >= 0x00ffffff) {
      throw new RangeError("MethodSemantics row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.Association.raw === associationRaw && row.Semantics === semantics)) {
      throw new FormatError("MethodSemantics association already has this semantic");
    }
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].Association.raw > rows[index].Association.raw) {
          throw new UnsupportedFormatError(
            "Sorted MethodSemantics insertion requires rows already ordered by Association"
          );
        }
      }
      const laterAssociation = rows.findIndex((row) => row.Association.raw > associationRaw);
      if (laterAssociation !== -1) insertionIndex = laterAssociation;
    } else if ((this.tables.sorted & (1n << 24n)) !== 0n &&
        rows.at(-1)?.Association.raw > associationRaw) {
      throw new UnsupportedFormatError("MethodSemantics append would violate declared Association ordering");
    }
    const rid = insertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = insertSorted
      ? this.#prepareTokenRowInsertion(24, rid, rows.length, "MethodSemantics")
      : { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] };
    const candidate = {
      table: 24,
      tableName: metadataTableNames[24],
      rid,
      Semantics: semantics,
      Method: { raw: methodRid, table: 6, tableName: metadataTableNames[6], rid: methodRid },
      Association: {
        raw: associationRaw,
        target: { table: associationTable, tableName: metadataTableNames[associationTable], rid: association.rid }
      }
    };
    const stagedRows = [...rows];
    stagedRows.splice(insertionIndex, 0, candidate);
    validateMethodSemanticsRecord(
      this, semantics, methodRid, associationTable, association.rid, stagedRows
    );
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, candidate);
    this.tables.rows.set(24, rows);
    this.tables.counts[24] = rows.length;
    this.tables.valid |= 1n << 24n;
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceMethodSemantics(rid, { methodRid, association, semantics } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(24, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid MethodSemantics row ID ${rid}`);
    }
    const associationTable = association
      ? metadataTableId(association.table)
      : row.Association.target?.table;
    const associationRid = association?.rid ?? row.Association.target?.rid;
    const nextMethodRid = methodRid ?? row.Method.rid;
    const nextSemantics = semantics ?? row.Semantics;
    if (![20, 23].includes(associationTable) || !Number.isInteger(associationRid) ||
        associationRid < 1 || associationRid > (this.tables.counts[associationTable] ?? 0)) {
      throw new RangeError("MethodSemantics association must identify an existing Event or Property row");
    }
    if (!Number.isInteger(nextMethodRid) || nextMethodRid < 1 ||
        nextMethodRid > (this.tables.counts[6] ?? 0)) {
      throw new RangeError("MethodSemantics method must identify an existing MethodDef row");
    }
    const associationRaw = encodeCodedIndex(associationTable, associationRid, "HasSemantics");
    const rows = this.tables.rows.get(24);
    if (rows.some((other) => other.rid !== rid &&
        other.Association.raw === associationRaw && other.Semantics === nextSemantics)) {
      throw new FormatError("MethodSemantics association already has this semantic");
    }
    const candidate = {
      ...row,
      Semantics: nextSemantics,
      Method: { raw: nextMethodRid, table: 6, tableName: metadataTableNames[6], rid: nextMethodRid },
      Association: {
        raw: associationRaw,
        target: { table: associationTable, tableName: metadataTableNames[associationTable], rid: associationRid }
      }
    };
    const stagedRows = rows.map((item) => item.rid === rid ? candidate : item);
    if ((this.tables.sorted & (1n << 24n)) !== 0n &&
        stagedRows.some((item, index) => index > 0 &&
          stagedRows[index - 1].Association.raw > item.Association.raw)) {
      throw new UnsupportedFormatError("MethodSemantics replacement would violate declared Association ordering");
    }
    validateMethodSemanticsRecord(
      this, nextSemantics, nextMethodRid, associationTable, associationRid, stagedRows
    );
    Object.assign(row, candidate);
    this._metadataDirty = true;
    return this;
  }

  removeMethodSemantics(rid) {
    this.#ensureEditable();
    return this.#removeTokenRow(24, rid, "MethodSemantics");
  }

  replacePropertySignature(rid, signature) {
    this.#ensureEditable();
    const row = this.tables.row(23, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid Property row ID ${rid}`);
    }
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
      throw new TypeError("Property signature must be a non-empty Uint8Array");
    }
    const parsed = parseSignature(signature, { counts: this.tables.counts });
    if (parsed.kind !== "property") {
      throw new FormatError("Property signature must use the property signature form");
    }
    const declaringType = this.types.find((type) => type.propertyRids.includes(rid));
    const typeArity = declaringType
      ? getGenericParameterArity(this.genericParams, 2, declaringType.rid)
      : 0;
    validateGenericVariableReferences(parsed, typeArity, this);
    validatePropertyAccessors(this, rid, parsed);
    const currentSignature = this.heaps.getBlob(row.Type);
    if (signature.length === currentSignature.length &&
        signature.every((byte, index) => byte === currentSignature[index])) {
      return this;
    }
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Blob", blob.heap);
    row.Type = blob.index;
    const property = declaringType?.properties.find((item) => item.rid === rid);
    if (property) property.signature = signature.slice();
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  replaceProperty(rid, { name, flags } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(23, rid);
    const property = this.types.flatMap((type) => type.properties)
      .find((item) => item.rid === rid);
    if (!Number.isInteger(rid) || rid < 1 || !row || !property) {
      throw new RangeError(`Invalid Property row ID ${rid}`);
    }
    const nextName = name === undefined ? property.name : name;
    const nextFlags = flags === undefined ? row.Flags : flags;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("Property name must be a non-empty null-free string");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 0xffff) {
      throw new RangeError("Property flags must be an unsigned 16-bit integer");
    }
    if ((this.tables.rows.get(11) ?? []).some((constant) =>
      constant.Parent.target?.table === 23 && constant.Parent.target.rid === rid
    ) && (nextFlags & 0x1000) === 0) {
      throw new FormatError("A Property with a Constant row must retain the HasDefault flag");
    }
    if (nextName === property.name && nextFlags === row.Flags) return this;
    this.#validateAssociatedFlags(23, rid, nextFlags);

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== property.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.Name = stringHeap.index;
    }
    row.Flags = nextFlags;
    property.name = nextName;
    property.flags = nextFlags;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeProperty(rid) {
    return this.#removeOwnedRow(23, 21, 22, rid);
  }

  addProperty({ owner, name, flags = 0, signature }) {
    return this.#writeProperty({ owner, name, flags, signature }, false).rid;
  }

  insertProperty({ owner, name, flags = 0, signature }) {
    return this.#writeProperty({ owner, name, flags, signature }, true);
  }

  #writeProperty({ owner, name, flags = 0, signature }, insertIntoOwner) {
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    const ownerType = this.types[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !ownerType) {
      throw new RangeError("Property owner must identify an existing TypeDef");
    }
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("Property name must be a non-empty null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffff) {
      throw new RangeError("Property flags must be an unsigned 16-bit integer");
    }
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
      throw new TypeError("Property signature must be a non-empty Uint8Array");
    }
    const parsedSignature = parseSignature(signature, { counts: this.tables.counts });
    if (parsedSignature.kind !== "property") {
      throw new FormatError("Property signature must use the property signature form");
    }
    validateGenericVariableReferences(
      parsedSignature,
      getGenericParameterArity(this.genericParams, 2, ownerRid),
      this
    );

    const rows = this.tables.rows.get(23) ?? [];
    const originalRowCount = rows.length;
    const maps = this.tables.rows.get(21) ?? [];
    if (rows.length !== this.tables.counts[23] || rows.length >= 0x00ffffff ||
        maps.length !== this.tables.counts[21]) {
      throw new FormatError("Property or PropertyMap row count is inconsistent with the metadata header");
    }
    const pointerPresent = (this.tables.valid & (1n << 22n)) !== 0n;
    const pointerRows = getBijectivePointerRows(this, 22, 23, "Property");
    if (pointerPresent && !pointerRows) {
      throw new FormatError("PropertyPtr must be a one-to-one mapping to Property rows");
    }
    const listCount = pointerRows?.length ?? rows.length;
    for (let index = 1; index < maps.length; index++) {
      if (maps[index - 1].Parent.rid >= maps[index].Parent.rid) {
        throw new FormatError("PropertyMap rows are not strictly ordered by TypeDef");
      }
    }
    const ownerMap = maps.find((row) => row.Parent.rid === ownerRid);
    const ownerMapIndex = ownerMap ? maps.indexOf(ownerMap) : -1;
    const nextMapIndex = maps.findIndex((row) => row.Parent.rid > ownerRid);
    const mapInsertIndex = ownerMap
      ? ownerMapIndex
      : nextMapIndex < 0 ? maps.length : nextMapIndex;
    if (ownerMap) {
      const endRid = maps[ownerMapIndex + 1]?.PropertyList.rid ?? listCount + 1;
      const ownedRids = pointerRows
        ? pointerRows.slice(ownerMap.PropertyList.rid - 1, endRid - 1)
          .map((pointer) => pointer.Property.rid)
        : Array.from(
          { length: Math.max(0, endRid - ownerMap.PropertyList.rid) },
          (_, index) => ownerMap.PropertyList.rid + index
        );
      if (endRid > listCount + 1 ||
          ownedRids.length !== ownerType.propertyRids.length ||
          ownedRids.some((rid, index) => rid !== ownerType.propertyRids[index])) {
        throw new UnsupportedFormatError("Property insertion requires a valid contiguous owner range");
      }
    } else if (ownerType.propertyRids.length !== 0) {
      throw new FormatError(`TypeDef row ${ownerRid} has properties without a PropertyMap row`);
    }
    if (!insertIntoOwner && ownerMap &&
        (maps[ownerMapIndex + 1]?.PropertyList.rid ?? listCount + 1) !== listCount + 1) {
      throw new UnsupportedFormatError("Property append requires the owner's properties to be contiguous at the end");
    }
    if (!insertIntoOwner && !ownerMap && maps.at(-1)?.Parent.rid >= ownerRid) {
      throw new FormatError("Appending a PropertyMap row would violate TypeDef ordering");
    }
    const endRid = ownerMap
      ? maps[ownerMapIndex + 1]?.PropertyList.rid ?? listCount + 1
      : insertIntoOwner
        ? maps[mapInsertIndex]?.PropertyList.rid ?? listCount + 1
        : listCount + 1;
    const ownedCount = ownerType.propertyRids.length;
    const rid = pointerRows ? rows.length + 1 : endRid;
    const pointerInsertionIndex = pointerRows
      ? ownerMap
        ? ownerMap.PropertyList.rid - 1 + ownedCount
        : insertIntoOwner
          ? endRid - 1
          : pointerRows.length
      : -1;
    const pointerRid = pointerInsertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = pointerRows
      ? { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] }
      : this.#prepareTokenRowInsertion(23, rid, rows.length, "Property");

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Strings", stringHeap.heap);
    heapStreams.set("#Blob", blobHeap.heap);
    const propertyRow = {
      table: 23,
      tableName: metadataTableNames[23],
      rid,
      Flags: flags,
      Name: stringHeap.index,
      Type: blobHeap.index
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(rid - 1, 0, propertyRow);
    this.tables.rows.set(23, rows);
    this.tables.counts[23] = rows.length;
    this.tables.valid |= 1n << 23n;
    if (pointerRows) {
      for (const row of pointerRows) {
        if (row.rid >= pointerRid) row.rid++;
      }
      pointerRows.splice(pointerInsertionIndex, 0, {
        table: 22,
        tableName: metadataTableNames[22],
        rid: pointerRid,
        Property: { raw: rid, table: 23, tableName: metadataTableNames[23], rid }
      });
      this.tables.rows.set(22, pointerRows);
      this.tables.counts[22] = pointerRows.length;
    }
    if (pointerRows && (ownerMap || insertIntoOwner)) {
      const firstFollowingMap = ownerMap ? ownerMapIndex + 1 : mapInsertIndex;
      for (const map of maps.slice(firstFollowingMap)) {
        map.PropertyList.rid++;
        map.PropertyList.raw++;
      }
    } else if (ownerMap && rid > originalRowCount) {
      for (const map of maps.slice(ownerMapIndex + 1)) {
        map.PropertyList.rid++;
        map.PropertyList.raw++;
      }
    }
    for (const type of this.types) {
      if (!pointerRows) {
        type.propertyRids = type.propertyRids.map((propertyRid) =>
          propertyRid >= rid ? propertyRid + 1 : propertyRid
        );
        for (const property of type.properties) {
          if (property.rid >= rid) property.rid++;
        }
      }
    }
    if (!ownerMap) {
      const listTable = pointerRows ? 22 : 23;
      const listRid = pointerRows ? pointerRid : rid;
      const mapRow = {
        table: 21,
        tableName: metadataTableNames[21],
        rid: mapInsertIndex + 1,
        Parent: { raw: ownerRid, table: 2, tableName: metadataTableNames[2], rid: ownerRid },
        PropertyList: {
          raw: listRid,
          table: listTable,
          tableName: metadataTableNames[listTable],
          rid: listRid
        }
      };
      for (const map of maps.slice(mapInsertIndex)) map.rid++;
      maps.splice(mapInsertIndex, 0, mapRow);
      this.tables.rows.set(21, maps);
      this.tables.counts[21] = maps.length;
      this.tables.valid |= 1n << 21n;
    }
    ownerType.propertyRids.push(rid);
    ownerType.properties.push({ rid, flags, name, signature: signature.slice() });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  addEvent({ owner, name, flags = 0, eventType }) {
    return this.#writeEvent({ owner, name, flags, eventType }, false).rid;
  }

  insertEvent({ owner, name, flags = 0, eventType }) {
    return this.#writeEvent({ owner, name, flags, eventType }, true);
  }

  #writeEvent({ owner, name, flags = 0, eventType }, insertIntoOwner) {
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    const ownerType = this.types[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !ownerType) {
      throw new RangeError("Event owner must identify an existing TypeDef");
    }
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("Event name must be a non-empty null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffff) {
      throw new RangeError("Event flags must be an unsigned 16-bit integer");
    }
    const typeTable = metadataTableId(eventType?.table);
    const typeRid = eventType?.rid;
    if (![1, 2, 27].includes(typeTable) || !Number.isInteger(typeRid) ||
        typeRid < 1 || typeRid > (this.tables.counts[typeTable] ?? 0)) {
      throw new RangeError("Event type must identify an existing TypeDef, TypeRef, or TypeSpec row");
    }
    const target = { table: typeTable, tableName: metadataTableNames[typeTable], rid: typeRid };
    if (typeTable === 27) {
      const typeSpec = this.typeSpecs[typeRid - 1];
      if (!typeSpec) throw new FormatError(`Event type references missing TypeSpec row ${typeRid}`);
      validateTypeSpecDefinitions(this, typeSpec.parsedSignature);
      validateTypeSpecGenericContext(
        this,
        typeRid,
        getGenericParameterArity(this.genericParams, 2, ownerRid)
      );
    }

    const rows = this.tables.rows.get(20) ?? [];
    const originalRowCount = rows.length;
    const maps = this.tables.rows.get(18) ?? [];
    if (rows.length !== this.tables.counts[20] || rows.length >= 0x00ffffff ||
        maps.length !== this.tables.counts[18]) {
      throw new FormatError("Event or EventMap row count is inconsistent with the metadata header");
    }
    const pointerPresent = (this.tables.valid & (1n << 19n)) !== 0n;
    const pointerRows = getBijectivePointerRows(this, 19, 20, "Event");
    if (pointerPresent && !pointerRows) {
      throw new FormatError("EventPtr must be a one-to-one mapping to Event rows");
    }
    const listCount = pointerRows?.length ?? rows.length;
    for (let index = 1; index < maps.length; index++) {
      if (maps[index - 1].Parent.rid >= maps[index].Parent.rid) {
        throw new FormatError("EventMap rows are not strictly ordered by TypeDef");
      }
    }
    const ownerMap = maps.find((row) => row.Parent.rid === ownerRid);
    const ownerMapIndex = ownerMap ? maps.indexOf(ownerMap) : -1;
    const nextMapIndex = maps.findIndex((row) => row.Parent.rid > ownerRid);
    const mapInsertIndex = ownerMap
      ? ownerMapIndex
      : nextMapIndex < 0 ? maps.length : nextMapIndex;
    if (ownerMap) {
      const endRid = maps[ownerMapIndex + 1]?.EventList.rid ?? listCount + 1;
      const ownedRids = pointerRows
        ? pointerRows.slice(ownerMap.EventList.rid - 1, endRid - 1)
          .map((pointer) => pointer.Event.rid)
        : Array.from(
          { length: Math.max(0, endRid - ownerMap.EventList.rid) },
          (_, index) => ownerMap.EventList.rid + index
        );
      if (endRid > listCount + 1 ||
          ownedRids.length !== ownerType.eventRids.length ||
          ownedRids.some((rid, index) => rid !== ownerType.eventRids[index])) {
        throw new UnsupportedFormatError("Event insertion requires a valid contiguous owner range");
      }
    } else if (ownerType.eventRids.length !== 0) {
      throw new FormatError(`TypeDef row ${ownerRid} has events without an EventMap row`);
    }
    if (!insertIntoOwner && ownerMap &&
        (maps[ownerMapIndex + 1]?.EventList.rid ?? listCount + 1) !== listCount + 1) {
      throw new UnsupportedFormatError("Event append requires the owner's events to be contiguous at the end");
    }
    if (!insertIntoOwner && !ownerMap && maps.at(-1)?.Parent.rid >= ownerRid) {
      throw new FormatError("Appending an EventMap row would violate TypeDef ordering");
    }
    const endRid = ownerMap
      ? maps[ownerMapIndex + 1]?.EventList.rid ?? listCount + 1
      : insertIntoOwner
        ? maps[mapInsertIndex]?.EventList.rid ?? listCount + 1
        : listCount + 1;
    const ownedCount = ownerType.eventRids.length;
    const rid = pointerRows ? rows.length + 1 : endRid;
    const pointerInsertionIndex = pointerRows
      ? ownerMap
        ? ownerMap.EventList.rid - 1 + ownedCount
        : insertIntoOwner
          ? endRid - 1
          : pointerRows.length
      : -1;
    const pointerRid = pointerInsertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = pointerRows
      ? { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] }
      : this.#prepareTokenRowInsertion(20, rid, rows.length, "Event");

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    heapStreams.set("#Strings", stringHeap.heap);
    const eventRow = {
      table: 20,
      tableName: metadataTableNames[20],
      rid,
      EventFlags: flags,
      Name: stringHeap.index,
      EventType: { raw: encodeCodedIndex(typeTable, typeRid, "TypeDefOrRef"), target }
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(rid - 1, 0, eventRow);
    this.tables.rows.set(20, rows);
    this.tables.counts[20] = rows.length;
    this.tables.valid |= 1n << 20n;
    if (pointerRows) {
      for (const row of pointerRows) {
        if (row.rid >= pointerRid) row.rid++;
      }
      pointerRows.splice(pointerInsertionIndex, 0, {
        table: 19,
        tableName: metadataTableNames[19],
        rid: pointerRid,
        Event: { raw: rid, table: 20, tableName: metadataTableNames[20], rid }
      });
      this.tables.rows.set(19, pointerRows);
      this.tables.counts[19] = pointerRows.length;
    }
    if (pointerRows && (ownerMap || insertIntoOwner)) {
      const firstFollowingMap = ownerMap ? ownerMapIndex + 1 : mapInsertIndex;
      for (const map of maps.slice(firstFollowingMap)) {
        map.EventList.rid++;
        map.EventList.raw++;
      }
    } else if (ownerMap && rid > originalRowCount) {
      for (const map of maps.slice(ownerMapIndex + 1)) {
        map.EventList.rid++;
        map.EventList.raw++;
      }
    }
    for (const type of this.types) {
      if (!pointerRows) {
        type.eventRids = type.eventRids.map((eventRid) =>
          eventRid >= rid ? eventRid + 1 : eventRid
        );
        for (const event of type.events) {
          if (event.rid >= rid) event.rid++;
        }
      }
    }
    if (!ownerMap) {
      const listTable = pointerRows ? 19 : 20;
      const listRid = pointerRows ? pointerRid : rid;
      const mapRow = {
        table: 18,
        tableName: metadataTableNames[18],
        rid: mapInsertIndex + 1,
        Parent: { raw: ownerRid, table: 2, tableName: metadataTableNames[2], rid: ownerRid },
        EventList: {
          raw: listRid,
          table: listTable,
          tableName: metadataTableNames[listTable],
          rid: listRid
        }
      };
      for (const map of maps.slice(mapInsertIndex)) map.rid++;
      maps.splice(mapInsertIndex, 0, mapRow);
      this.tables.rows.set(18, maps);
      this.tables.counts[18] = maps.length;
      this.tables.valid |= 1n << 18n;
    }
    ownerType.eventRids.push(rid);
    ownerType.events.push({ rid, flags, name, eventType: target });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  removeEvent(rid) {
    return this.#removeOwnedRow(20, 18, 19, rid);
  }

  replaceEvent(rid, { name, flags, eventType } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(20, rid);
    const currentEvent = this.types.flatMap((type) => type.events)
      .find((item) => item.rid === rid);
    if (!row || !currentEvent) throw new RangeError(`Invalid Event row ID ${rid}`);
    const declaringType = this.types.find((type) => type.eventRids.includes(rid));
    const nextName = name === undefined ? currentEvent.name : name;
    const nextFlags = flags === undefined ? row.EventFlags : flags;
    const nextType = eventType === undefined
      ? currentEvent.eventType
      : eventType && typeof eventType === "object"
        ? { table: metadataTableId(eventType.table), rid: eventType.rid }
        : null;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("Event name must be a non-empty null-free string");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 0xffff) {
      throw new RangeError("Event flags must be an unsigned 16-bit integer");
    }
    if (!nextType || ![1, 2, 27].includes(nextType.table) ||
        !Number.isInteger(nextType.rid) || nextType.rid < 1 ||
        nextType.rid > (this.tables.counts[nextType.table] ?? 0)) {
      throw new RangeError("Event type must identify an existing TypeDef, TypeRef, or TypeSpec row");
    }
    const typeChanged = nextType.table !== currentEvent.eventType.table ||
      nextType.rid !== currentEvent.eventType.rid;
    if (typeChanged) {
      if (nextType.table === 27) {
        const typeSpec = this.typeSpecs[nextType.rid - 1];
        if (!typeSpec) throw new FormatError(`Event type references missing TypeSpec row ${nextType.rid}`);
        validateTypeSpecDefinitions(this, typeSpec.parsedSignature);
        validateTypeSpecGenericContext(
          this,
          nextType.rid,
          declaringType
            ? getGenericParameterArity(this.genericParams, 2, declaringType.rid)
            : 0
        );
      }
      validateEventAccessors(this, rid, {
        table: nextType.table,
        tableName: metadataTableNames[nextType.table],
        rid: nextType.rid
      });
    }
    if (nextName === currentEvent.name && nextFlags === row.EventFlags && !typeChanged) {
      return this;
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== currentEvent.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.Name = stringHeap.index;
    }
    row.EventFlags = nextFlags;
    const target = {
      table: nextType.table,
      tableName: metadataTableNames[nextType.table],
      rid: nextType.rid
    };
    row.EventType = {
      raw: encodeCodedIndex(target.table, target.rid, "TypeDefOrRef"),
      target
    };
    currentEvent.name = nextName;
    currentEvent.flags = nextFlags;
    currentEvent.eventType = target;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  addInterfaceImplementation({ owner, interfaceType }) {
    return this.#writeInterfaceImplementation({ owner, interfaceType }, false).rid;
  }

  insertInterfaceImplementation({ owner, interfaceType }) {
    return this.#writeInterfaceImplementation({ owner, interfaceType }, true);
  }

  #writeInterfaceImplementation({ owner, interfaceType }, insertSorted) {
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    if (!Number.isInteger(ownerRid) || ownerRid < 1 ||
        ownerRid > (this.tables.counts[2] ?? 0)) {
      throw new RangeError("InterfaceImpl owner must identify an existing TypeDef row");
    }
    const interfaceTable = metadataTableId(interfaceType?.table);
    const interfaceRid = interfaceType?.rid;
    if (![1, 2, 27].includes(interfaceTable) || !Number.isInteger(interfaceRid) ||
        interfaceRid < 1 || interfaceRid > (this.tables.counts[interfaceTable] ?? 0)) {
      throw new RangeError(
        "Interface type must identify an existing TypeDef, TypeRef, or TypeSpec row"
      );
    }
    if (interfaceTable === 27) {
      const typeSpec = this.typeSpecs[interfaceRid - 1];
      if (!typeSpec) {
        throw new FormatError(`Interface type references missing TypeSpec row ${interfaceRid}`);
      }
      validateTypeSpecDefinitions(this, typeSpec.parsedSignature);
      validateTypeSpecGenericContext(
        this,
        interfaceRid,
        getGenericParameterArity(this.genericParams, 2, ownerRid)
      );
    }
    const rows = this.tables.rows.get(9) ?? [];
    if (rows.length !== (this.tables.counts[9] ?? 0) || rows.length >= 0xffffffff) {
      throw new FormatError("InterfaceImpl row count is inconsistent with the metadata header");
    }
    const interfaceValue = encodeCodedIndex(interfaceTable, interfaceRid, "TypeDefOrRef");
    if (rows.some((row) =>
      row.Class.rid === ownerRid && row.Interface.raw === interfaceValue
    )) {
      throw new FormatError("InterfaceImpl row already exists for this TypeDef and interface");
    }
    let insertionIndex = rows.length;
    if (insertSorted) {
      for (let index = 1; index < rows.length; index++) {
        if (rows[index - 1].Class.rid > rows[index].Class.rid) {
          throw new UnsupportedFormatError(
            "Sorted InterfaceImpl insertion requires rows already ordered by Class"
          );
        }
      }
      const laterOwner = rows.findIndex((row) => row.Class.rid > ownerRid);
      if (laterOwner !== -1) insertionIndex = laterOwner;
    } else if ((this.tables.sorted & (1n << 9n)) !== 0n &&
        rows.at(-1)?.Class.rid > ownerRid) {
      throw new FormatError("Appending this InterfaceImpl would violate the table's sorted Class order");
    }
    const rid = insertionIndex + 1;
    if (rid > 0x00ffffff) {
      throw new RangeError("InterfaceImpl token row ID exceeds 24-bit range");
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(9, rid, rows.length, "InterfaceImpl");
    const target = {
      table: interfaceTable,
      tableName: metadataTableNames[interfaceTable],
      rid: interfaceRid
    };
    const newRow = {
      table: 9,
      tableName: metadataTableNames[9],
      rid,
      Class: {
        raw: ownerRid,
        table: 2,
        tableName: metadataTableNames[2],
        rid: ownerRid
      },
      Interface: { raw: interfaceValue, target }
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of rows) {
      if (row.rid >= rid) row.rid++;
    }
    rows.splice(insertionIndex, 0, newRow);
    this.tables.rows.set(9, rows);
    this.tables.counts[9] = rows.length;
    this.tables.valid |= 1n << 9n;
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceInterfaceImplementation(rid, { interfaceType } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(9, rid);
    if (!row) throw new RangeError(`Invalid InterfaceImpl row ID ${rid}`);
    const interfaceTable = metadataTableId(interfaceType?.table);
    const interfaceRid = interfaceType?.rid;
    if (![1, 2, 27].includes(interfaceTable) || !Number.isInteger(interfaceRid) ||
        interfaceRid < 1 || interfaceRid > (this.tables.counts[interfaceTable] ?? 0)) {
      throw new RangeError(
        "Interface type must identify an existing TypeDef, TypeRef, or TypeSpec row"
      );
    }
    const ownerRid = row.Class.rid;
    if (interfaceTable === 27) {
      const typeSpec = this.typeSpecs[interfaceRid - 1];
      if (!typeSpec) {
        throw new FormatError(`Interface type references missing TypeSpec row ${interfaceRid}`);
      }
      validateTypeSpecDefinitions(this, typeSpec.parsedSignature);
      validateTypeSpecGenericContext(
        this,
        interfaceRid,
        getGenericParameterArity(this.genericParams, 2, ownerRid)
      );
    }
    const interfaceValue = encodeCodedIndex(interfaceTable, interfaceRid, "TypeDefOrRef");
    if (interfaceValue === row.Interface.raw) return this;
    if ((this.tables.rows.get(9) ?? []).some((candidate) =>
      candidate.rid !== rid &&
      candidate.Class.rid === ownerRid &&
      candidate.Interface.raw === interfaceValue
    )) {
      throw new FormatError("InterfaceImpl row already exists for this TypeDef and interface");
    }
    const target = {
      table: interfaceTable,
      tableName: metadataTableNames[interfaceTable],
      rid: interfaceRid
    };
    row.Interface = { raw: interfaceValue, target };
    this._metadataDirty = true;
    return this;
  }

  removeInterfaceImplementation(rid) {
    this.#ensureEditable();
    const rows = this.tables.rows.get(9) ?? [];
    if (rows.length !== (this.tables.counts[9] ?? 0)) {
      throw new FormatError("InterfaceImpl row count is inconsistent with the metadata header");
    }
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid InterfaceImpl row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap InterfaceImpl rows with unrecognized metadata stream ${streamName}`
        );
      }
    }
    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      if (!schema) {
        throw new UnsupportedFormatError(
          `Cannot remap InterfaceImpl references in unknown metadata table ${tableId}`
        );
      }
      for (const row of tableRows) {
        for (const [kind, value, name] of schema) {
          if (kind !== "coded") continue;
          const columnName = name ?? value;
          const target = row[columnName]?.target;
          if (target?.table !== 9) continue;
          if (target.rid === rid) {
            throw new FormatError(
              `InterfaceImpl row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
            );
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: {
                raw: encodeCodedIndex(9, remappedTarget.rid, value),
                target: remappedTarget
              }
            });
          }
        }
      }
    }
    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      const parentChanges = new Map(
        rowChanges
          .filter((change) => change.row.table === 12 && change.columnName === "Parent")
          .map((change) => [change.row, change.value.raw])
      );
      const customAttributes = this.tables.rows.get(12) ?? [];
      for (let index = 1; index < customAttributes.length; index++) {
        const previous = parentChanges.get(customAttributes[index - 1]) ??
          customAttributes[index - 1].Parent.raw;
        const current = parentChanges.get(customAttributes[index]) ??
          customAttributes[index].Parent.raw;
        if (previous > current) {
          throw new FormatError(
            "InterfaceImpl row remapping would violate sorted CustomAttribute order"
          );
        }
      }
    }
    const remainingRows = rows.filter((row) => row.rid !== rid);
    const rowMap = new Map(
      Array.from({ length: rows.length - rid }, (_, index) =>
        [rid + index + 1, rid + index]
      )
    );
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.tables.rows.set(9, remainingRows);
    this.tables.counts[9] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 9n);
    this._metadataDirty = true;
    return rowMap;
  }

  setInstructionOperand(methodRid, instructionOffset, value) {
    this.#ensureEditable();
    const body = this.getMethodBody(methodRid);
    if (!body) throw new FormatError("Method has no CIL body");
    const instruction = body.instructions.find((candidate) => candidate.offset === instructionOffset);
    if (!instruction) throw new RangeError(`No instruction begins at IL_${instructionOffset.toString(16)}`);
    if (!instruction.operand) throw new TypeError("Instruction has no operand");

    if (instruction.operand.kind === "branch") {
      this.#validateBranchTarget(body, value);
    } else if (instruction.operand.kind === "switch") {
      if (!Array.isArray(value)) throw new TypeError("Switch operand must be an array of IL target offsets");
      for (const target of value) this.#validateBranchTarget(body, target);
    } else if (instruction.opcode.name === "ldstr") {
      if (!Number.isInteger(value) || (value >>> 24) !== 0x70) {
        throw new TypeError("ldstr operand must be a 0x70-prefixed user-string token");
      }
      this.heaps.getUserString(value);
    } else if (instruction.operand.kind === "token") {
      if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
        throw new RangeError("Metadata token must be an unsigned 32-bit integer");
      }
      const table = value >>> 24;
      const rid = value & 0x00ffffff;
      if (!allowedTokenTables(instruction.opcode.name).includes(table)) {
        throw new FormatError(`Metadata table ${table} is not valid for ${instruction.opcode.name}`);
      }
      if (rid === 0 || rid > (this.tables.counts[table] ?? 0)) {
        throw new RangeError(`${instruction.opcode.name} references missing ${metadataTableNames[table]} row ${rid}`);
      }
      if (table === 43) {
        const methodSpec = this.methodSpecs[rid - 1];
        if (!methodSpec) throw new FormatError(`CIL references missing MethodSpec row ${rid}`);
        validateMethodSpecUseAtCallSite(this, methodRid, methodSpec);
      } else if (instruction.opcode.name === "calli" && table === 17) {
        validateStandAloneSigCallSite(this, methodRid, rid);
      }
    }

    if (instruction.operand.kind === "branch" && instruction.operand.targetOffset === value) return this;
    if (instruction.operand.kind === "switch" &&
        instruction.operand.targetOffsets.length === value.length &&
        instruction.operand.targetOffsets.every((target, index) => target === value[index])) return this;
    if (instruction.operand.kind !== "branch" && instruction.operand.kind !== "switch" &&
        instruction.operand.value === value) return this;

    if (this._structuralBodies.has(methodRid) || this._addedMethodBodies.has(methodRid)) {
      const state = this.#createStructuralState(methodRid);
      const editableInstruction = state.instructions.find((candidate) => candidate.offset === instructionOffset);
      updateStructuralOperand(state, editableInstruction, value);
      this.#commitStructuralState(methodRid, state);
    } else {
      const patches = createOperandPatches(instruction, value);
      for (const patch of patches) this._patches.push(patch);
      instruction.operand = instruction.operand.kind === "branch"
        ? { kind: "branch", targetOffset: value }
        : instruction.operand.kind === "switch"
          ? { kind: "switch", targetOffsets: [...value] }
          : { ...instruction.operand, value };
    }
    return this;
  }

  setInstructionOpcode(methodRid, instructionOffset, opcodeNameOrCode) {
    this.#ensureEditable();
    const body = this.getMethodBody(methodRid);
    if (!body) throw new FormatError("Method has no CIL body");
    const instruction = body.instructions.find((candidate) => candidate.offset === instructionOffset);
    if (!instruction) throw new RangeError(`No instruction begins at IL_${instructionOffset.toString(16)}`);
    const opcode = listOpcodes().find((candidate) =>
      candidate.name === opcodeNameOrCode || candidate.code === opcodeNameOrCode
    );
    if (!opcode) throw new RangeError(`Unknown CIL opcode ${opcodeNameOrCode}`);
    const encoded = encodeOpcode(opcode);
    if (encoded.length !== instruction.opcodeSize || opcode.operand !== instruction.opcode.operand) {
      throw new FormatError("Opcode edit must preserve the opcode and operand widths");
    }
    if (opcode.code === instruction.opcode.code) return this;
    if (this._structuralBodies.has(methodRid) || this._addedMethodBodies.has(methodRid)) {
      const state = this.#createStructuralState(methodRid);
      const editableInstruction = state.instructions.find((candidate) => candidate.offset === instructionOffset);
      editableInstruction.opcode = opcode;
      layoutStructuralState(state);
      this.#commitStructuralState(methodRid, state);
    } else {
      this._patches.push({ offset: instruction.opcodeOffset, bytes: encoded });
      instruction.opcode = opcode;
    }
    return this;
  }

  insertInstruction(methodRid, beforeOffset, opcodeNameOrCode, operand) {
    this.#ensureEditable();
    const opcode = listOpcodes().find((candidate) =>
      candidate.name === opcodeNameOrCode || candidate.code === opcodeNameOrCode
    );
    if (!opcode) throw new RangeError(`Unknown CIL opcode ${opcodeNameOrCode}`);
    const state = this.#createStructuralState(methodRid);
    const instruction = insertStructuralInstruction(state, beforeOffset, opcode, operand);
    this.#commitStructuralState(methodRid, state);
    return instruction;
  }

  removeInstruction(methodRid, instructionOffset) {
    this.#ensureEditable();
    const state = this.#createStructuralState(methodRid);
    const instruction = removeStructuralInstruction(state, instructionOffset);
    this.#commitStructuralState(methodRid, state);
    return instruction;
  }

  setMethodMaxStack(methodRid, maxStack) {
    this.#ensureEditable();
    if (!Number.isInteger(maxStack) || maxStack < 0 || maxStack > 0xffff) {
      throw new RangeError("maxStack must be an unsigned 16-bit integer");
    }
    const state = this.#createStructuralState(methodRid);
    state.maxStack = maxStack;
    layoutStructuralState(state);
    this.#commitStructuralState(methodRid, state);
    return this;
  }

  addMemberRef({ parent, name, signature }) {
    this.#ensureEditable();
    if (!parent || !Number.isInteger(parent.rid) || parent.rid < 1) {
      throw new TypeError("MemberRef parent must identify an existing metadata row");
    }
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("MemberRef name must be a non-empty null-free string");
    }
    if (!(signature instanceof Uint8Array)) throw new TypeError("MemberRef signature must be a Uint8Array");
    if (signature.length === 0) throw new FormatError("MemberRef signature cannot be empty");
    const parsedSignature = parseSignature(signature, { counts: this.tables.counts });
    const parentTable = metadataTableId(parent.table);
    if (parentTable < 0 || parent.rid > (this.tables.counts[parentTable] ?? 0)) {
      throw new RangeError("MemberRef parent references a missing metadata row");
    }
    validateMemberRefGenericContext(this, { table: parentTable, rid: parent.rid }, parsedSignature);
    const classValue = encodeCodedIndex(parentTable, parent.rid, "MemberRefParent");
    const memberRows = this.tables.rows.get(10) ?? [];
    if ((this.tables.sorted & (1n << 10n)) !== 0n && memberRows.length > 0 &&
        memberRows.at(-1).Class.raw > classValue) {
      throw new FormatError("Appending this MemberRef would violate the table's sorted Class order");
    }
    const rid = memberRows.length + 1;
    if (rid > 0x00ffffff) throw new RangeError("MemberRef token row ID exceeds 24-bit range");

    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const stringHeap = appendStringHeap(this._heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const blobHeap = appendBlobHeap(this._heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    this._heapStreams.set("#Strings", stringHeap.heap);
    this._heapStreams.set("#Blob", blobHeap.heap);
    this.#refreshHeaps();

    const row = {
      table: 10,
      tableName: metadataTableNames[10],
      rid,
      Class: { raw: classValue, target: { table: parentTable, tableName: metadataTableNames[parentTable], rid: parent.rid } },
      Name: stringHeap.index,
      Signature: blobHeap.index
    };
    memberRows.push(row);
    this.tables.rows.set(10, memberRows);
    this.tables.valid |= 1n << 10n;
    this.tables.counts[10] = rid;
    this.memberRefs.push({
      rid,
      name,
      parent: row.Class.target,
      signature: signature.slice()
    });
    this._metadataDirty = true;
    return 0x0a000000 + rid;
  }

  replaceMemberRef(rid, { parent, name, signature } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(10, rid);
    const memberRef = this.memberRefs[rid - 1];
    if (!row || !memberRef) throw new RangeError(`Invalid MemberRef row ID ${rid}`);
    const nextName = name === undefined ? memberRef.name : name;
    const nextSignature = signature === undefined ? memberRef.signature : signature;
    const nextParent = parent === undefined
      ? memberRef.parent
      : parent && typeof parent === "object"
        ? { table: metadataTableId(parent.table), rid: parent.rid }
        : null;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("MemberRef name must be a non-empty null-free string");
    }
    if (!(nextSignature instanceof Uint8Array) || nextSignature.length === 0) {
      throw new TypeError("MemberRef signature must be a non-empty Uint8Array");
    }
    if (!nextParent || ![2, 1, 26, 6, 27].includes(nextParent.table) ||
        !Number.isInteger(nextParent.rid) || nextParent.rid < 1 ||
        nextParent.rid > (this.tables.counts[nextParent.table] ?? 0)) {
      throw new RangeError("MemberRef parent references a missing or unsupported metadata row");
    }
    const parsedSignature = parseSignature(nextSignature, { counts: this.tables.counts });
    validateMemberRefGenericContext(this, nextParent, parsedSignature);
    const parentValue = encodeCodedIndex(nextParent.table, nextParent.rid, "MemberRefParent");
    const changed = nextName !== memberRef.name ||
      nextParent.table !== memberRef.parent.table ||
      nextParent.rid !== memberRef.parent.rid ||
      nextSignature.length !== memberRef.signature.length ||
      nextSignature.some((byte, index) => byte !== memberRef.signature[index]);
    if (!changed) return this;
    if (this.customAttributes.some((attribute) =>
      attribute.constructor?.table === 10 && attribute.constructor.rid === rid
    )) {
      throw new UnsupportedFormatError(
        `MemberRef row ${rid} is used as a CustomAttribute constructor and cannot be replaced`
      );
    }
    for (const methodSpec of this.methodSpecs) {
      if (methodSpec.method.table === 10 && methodSpec.method.rid === rid &&
          (parsedSignature.kind !== "method" || !parsedSignature.generic ||
           parsedSignature.genericParameterCount !== methodSpec.parsedInstantiation.arguments.length)) {
        throw new FormatError(
          `MemberRef replacement would invalidate MethodSpec row ${methodSpec.rid}`
        );
      }
    }
    if ((this.tables.sorted & (1n << 10n)) !== 0n) {
      const previous = this.tables.row(10, rid - 1);
      const following = this.tables.row(10, rid + 1);
      if ((previous && previous.Class.raw > parentValue) ||
          (following && parentValue > following.Class.raw)) {
        throw new FormatError("MemberRef replacement would violate the table's sorted Class order");
      }
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== memberRef.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.Name = stringHeap.index;
    }
    if (nextSignature.some((byte, index) => byte !== memberRef.signature[index]) ||
        nextSignature.length !== memberRef.signature.length) {
      const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), nextSignature);
      heapStreams.set("#Blob", blobHeap.heap);
      row.Signature = blobHeap.index;
    }
    const parentTarget = {
      table: nextParent.table,
      tableName: metadataTableNames[nextParent.table],
      rid: nextParent.rid
    };
    row.Class = { raw: parentValue, target: parentTarget };
    memberRef.parent = parentTarget;
    memberRef.name = nextName;
    memberRef.signature = nextSignature.slice();
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeMemberRef(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("MemberRef removal cannot be combined with structural method edits");
    }
    this.#ensureAddedMethodBodiesSafe("MemberRef removal");
    this.#ensureTokenRemappingSafe("MemberRef");
    const rows = this.tables.rows.get(10) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid MemberRef row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap MemberRef tokens with unrecognized metadata stream ${streamName}`
        );
      }
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        const columnName = name ?? value;
        if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId)) {
          for (const row of tableRows) {
            const token = row[columnName];
            if ((token >>> 24) !== 0x0a) continue;
            const targetRid = token & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(
                `MemberRef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (targetRid > rid) {
              rowChanges.push({ row, columnName, value: 0x0a000000 + targetRid - 1 });
            }
          }
          continue;
        }
        if (kind !== "coded") continue;
        for (const row of tableRows) {
          const target = row[columnName]?.target;
          if (target?.table !== 10) continue;
          if (target.rid === rid) {
            throw new FormatError(
              `MemberRef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
            );
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: {
                raw: encodeCodedIndex(10, remappedTarget.rid, value),
                target: remappedTarget
              }
            });
          }
        }
      }
    }
    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      let previous = -1;
      for (const row of this.tables.get(12)) {
        const parent = changesByRow.get(row)?.get("Parent") ?? row.Parent;
        if (parent.raw < previous) {
          throw new FormatError("MemberRef token remapping would violate sorted CustomAttribute order");
        }
        previous = parent.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x0a) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing MemberRef row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`MemberRef row ${rid} is referenced by CIL`);
        if (targetRid > rid) {
          const replacement = 0x0a000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x0a000000 + oldRid, 0x0a000000 + oldRid - 1);
    }
    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingMembers = this.memberRefs.filter((member) => member.rid !== rid);
    if (remainingRows.length !== remainingMembers.length || !this.memberRefs[rid - 1] ||
        this.memberRefs[rid - 1].rid !== rid) {
      throw new FormatError(`MemberRef row ${rid} has no semantic record`);
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
      remainingMembers[index].rid = index + 1;
    });
    this.tables.rows.set(10, remainingRows);
    this.tables.counts[10] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 10n);
    this.memberRefs.splice(0, this.memberRefs.length, ...remainingMembers);
    for (const methodSpec of this.methodSpecs) {
      methodSpec.method = this.tables.row(43, methodSpec.rid).Method.target;
    }
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  insertMemberRefSorted({ parent, name, signature }) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("Sorted MemberRef insertion cannot be combined with structural method edits");
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(`Cannot remap MemberRef tokens with unrecognized metadata stream ${streamName}`);
      }
    }
    if (!parent || !Number.isInteger(parent.rid) || parent.rid < 1) {
      throw new TypeError("MemberRef parent must identify an existing metadata row");
    }
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("MemberRef name must be a non-empty null-free string");
    }
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
      throw new TypeError("MemberRef signature must be a non-empty Uint8Array");
    }
    const parsedSignature = parseSignature(signature, { counts: this.tables.counts });
    const parentTable = metadataTableId(parent.table);
    if (parentTable < 0 || parent.rid > (this.tables.counts[parentTable] ?? 0)) {
      throw new RangeError("MemberRef parent references a missing metadata row");
    }
    validateMemberRefGenericContext(this, { table: parentTable, rid: parent.rid }, parsedSignature);
    const classValue = encodeCodedIndex(parentTable, parent.rid, "MemberRefParent");
    const memberRows = this.tables.rows.get(10) ?? [];
    if (memberRows.length + 1 > 0x00ffffff) {
      throw new RangeError("MemberRef token row ID exceeds 24-bit range");
    }
    const newRow = {
      table: 10,
      tableName: metadataTableNames[10],
      rid: 0,
      Class: {
        raw: classValue,
        target: { table: parentTable, tableName: metadataTableNames[parentTable], rid: parent.rid }
      },
      Name: 0,
      Signature: 0
    };
    const orderedRows = [
      ...memberRows.map((row, index) => ({ row, oldRid: row.rid, order: index })),
      { row: newRow, oldRid: null, order: memberRows.length }
    ].sort((left, right) =>
      left.row.Class.raw - right.row.Class.raw || left.order - right.order
    );
    const remappedRids = new Map(orderedRows.flatMap((item, index) =>
      item.oldRid === null ? [] : [[item.oldRid, index + 1]]
    ));
    const remappedRid = (rid) => remappedRids.get(rid) ?? rid;
    const tokenMap = new Map([...remappedRids].flatMap(([oldRid, newRid]) =>
      oldRid === newRid ? [] : [[0x0a000000 + oldRid, 0x0a000000 + newRid]]
    ));
    if (tokenMap.size > 0) {
      this.#ensureAddedMethodBodiesSafe("MemberRef remapping");
      this.#ensureTokenRemappingSafe("MemberRef");
    }
    const remappedCodedRaw = (column, kind) => {
      const target = column?.target;
      return target?.table === 10
        ? encodeCodedIndex(10, remappedRid(target.rid), kind)
        : column.raw;
    };

    for (const [tableId, columnName, codedKind] of [
      [12, "Parent", "HasCustomAttribute"],
      [43, "Method", "MethodDefOrRef"]
    ]) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = -1;
      for (const row of this.tables.get(tableId)) {
        const key = remappedCodedRaw(row[columnName], codedKind);
        if (key < previous) {
          throw new FormatError(`MemberRef token remapping would violate sorted ${metadataTableNames[tableId]} order`);
        }
        previous = key;
      }
    }

    const rowChanges = [];
    for (const [tableId, rows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      for (const row of rows) {
        for (const [kind, value, name] of schema) {
          const columnName = name ?? value;
          const column = row[columnName];
          if (kind === "coded" && column?.target?.table === 10 &&
              remappedRid(column.target.rid) !== column.target.rid) {
            const target = { ...column.target, rid: remappedRid(column.target.rid) };
            rowChanges.push({
              row,
              columnName,
              value: { raw: encodeCodedIndex(10, target.rid, value), target }
            });
          } else if (kind === "table" && column?.table === 10 &&
              remappedRid(column.rid) !== column.rid) {
            const rid = remappedRid(column.rid);
            rowChanges.push({
              row,
              columnName,
              value: { ...column, rid, raw: rid }
            });
          }
        }
      }
    }

    rowChanges.push(...collectEncTokenRemaps(this.tables, 10, remappedRid));
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x0a) continue;
        const oldRid = token & 0x00ffffff;
        if (oldRid === 0 || oldRid > memberRows.length) {
          throw new FormatError(`CIL references missing MemberRef row ${oldRid}`);
        }
        const newRid = remappedRid(oldRid);
        if (oldRid === newRid) continue;
        const replacement = 0x0a000000 + newRid;
        patches.push(...createOperandPatches(instruction, replacement));
        tokenUpdates.push({ instruction, replacement });
      }
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Strings", stringHeap.heap);
    heapStreams.set("#Blob", blobHeap.heap);

    newRow.Name = stringHeap.index;
    newRow.Signature = blobHeap.index;
    const previousMembersByRid = new Map(this.memberRefs.map((member) => [member.rid, member]));
    const newMember = {
      rid: 0,
      name,
      parent: newRow.Class.target,
      signature: signature.slice()
    };
    const orderedMembers = orderedRows.map((item, index) => {
      if (item.oldRid === null) {
        return newMember;
      }
      const member = previousMembersByRid.get(item.oldRid);
      if (!member) throw new FormatError(`MemberRef row ${item.oldRid} has no semantic record`);
      return member;
    });
    orderedRows.forEach((item, index) => {
      item.row.rid = index + 1;
      orderedMembers[index].rid = index + 1;
    });
    newMember.rid = orderedRows.findIndex((item) => item.oldRid === null) + 1;
    memberRows.splice(0, memberRows.length, ...orderedRows.map((item) => item.row));
    this.tables.rows.set(10, memberRows);
    this.tables.valid |= 1n << 10n;
    this.tables.counts[10] = memberRows.length;
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    this.memberRefs.splice(0, this.memberRefs.length, ...orderedMembers);
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const methodSpec of this.methodSpecs) {
      if (methodSpec.method.table === 10) {
        methodSpec.method.rid = remappedRid(methodSpec.method.rid);
      }
    }
    for (const update of tokenUpdates) {
      update.instruction.operand.value = update.replacement;
    }
    this._patches.push(...patches);
    this._heapStreams = heapStreams;
    this.tables.sorted |= 1n << 10n;
    this._metadataDirty = true;
    return { token: 0x0a000000 + newMember.rid, tokenMap };
  }

  addModuleRef({ name }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("ModuleRef name must be a non-empty null-free string");
    }
    const rows = this.tables.rows.get(26) ?? [];
    if (rows.length >= 0x00ffffff) throw new RangeError("ModuleRef token row ID exceeds 24-bit range");
    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const stringHeap = appendStringHeap(this._heapStreams.get("#Strings") ?? new Uint8Array(), name);
    this._heapStreams.set("#Strings", stringHeap.heap);
    this.#refreshHeaps();
    const rid = rows.length + 1;
    rows.push({
      table: 26,
      tableName: metadataTableNames[26],
      rid,
      Name: stringHeap.index
    });
    this.tables.rows.set(26, rows);
    this.tables.valid |= 1n << 26n;
    this.tables.counts[26] = rid;
    this.moduleRefs.push({ rid, name });
    this._metadataDirty = true;
    return 0x1a000000 + rid;
  }

  insertModuleRef({ beforeRid, name }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("ModuleRef name must be a non-empty null-free string");
    }
    const rows = this.tables.rows.get(26) ?? [];
    if (rows.length !== (this.tables.counts[26] ?? 0) || rows.length !== this.moduleRefs.length) {
      throw new FormatError("ModuleRef row count is inconsistent with parsed ModuleRef records");
    }
    if (!Number.isInteger(beforeRid) || beforeRid < 1 || beforeRid > rows.length + 1) {
      throw new RangeError(`Invalid ModuleRef insertion position ${beforeRid}`);
    }
    if (rows.length >= 0x00ffffff) {
      throw new RangeError("ModuleRef token row ID exceeds 24-bit range");
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(26, beforeRid, rows.length, "ModuleRef");
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    heapStreams.set("#Strings", stringHeap.heap);
    const rid = beforeRid;
    const row = {
      table: 26,
      tableName: metadataTableNames[26],
      rid,
      Name: stringHeap.index
    };

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    rows.splice(rid - 1, 0, row);
    rows.forEach((moduleRefRow, index) => {
      moduleRefRow.rid = index + 1;
    });
    this.tables.rows.set(26, rows);
    this.tables.valid |= 1n << 26n;
    this.tables.counts[26] = rows.length;
    this.moduleRefs.splice(rid - 1, 0, { rid, name });
    this.moduleRefs.forEach((moduleRef, index) => {
      moduleRef.rid = index + 1;
    });
    for (const typeRef of this.typeRefs) {
      typeRef.resolutionScope = this.tables.row(1, typeRef.rid).ResolutionScope.target;
    }
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return { token: 0x1a000000 + rid, tokenMap };
  }

  replaceModuleRef(rid, name) {
    this.#ensureEditable();
    const row = this.tables.row(26, rid);
    if (!row || !this.moduleRefs[rid - 1]) throw new RangeError(`Invalid ModuleRef row ID ${rid}`);
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("ModuleRef name must be a non-empty null-free string");
    }
    if (name === this.moduleRefs[rid - 1].name) return this;
    const heapStreams = this._heapStreams
      ? new Map([...this._heapStreams].map(([streamName, bytes]) => [streamName, bytes.slice()]))
      : new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    heapStreams.set("#Strings", stringHeap.heap);
    row.Name = stringHeap.index;
    this.moduleRefs[rid - 1] = { rid, name };
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeModuleRef(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("ModuleRef removal cannot be combined with structural method edits");
    }
    this.#ensureTokenRemappingSafe("ModuleRef");
    const rows = this.tables.rows.get(26) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid ModuleRef row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(`Cannot remap ModuleRef tokens with unrecognized metadata stream ${streamName}`);
      }
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      for (const row of tableRows) {
        for (const [kind, value, name] of schema) {
          const columnName = name ?? value;
          const column = row[columnName];
          if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId) &&
              (column >>> 24) === 0x1a) {
            const targetRid = column & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(`ModuleRef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (targetRid > rid) {
              rowChanges.push({
                row,
                columnName,
                value: 0x1a000000 + targetRid - 1
              });
            }
            continue;
          }
          const target = kind === "coded" ? column?.target : kind === "table" ? column : null;
          if (target?.table !== 26) continue;
          if (target.rid === rid) {
            throw new FormatError(`ModuleRef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: kind === "coded"
                ? { raw: encodeCodedIndex(26, remappedTarget.rid, value), target: remappedTarget }
                : { ...column, rid: remappedTarget.rid, raw: remappedTarget.rid }
            });
          }
        }
      }
    }

    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    for (const [tableId, columnName] of [[1, "ResolutionScope"], [10, "Class"], [12, "Parent"]]) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = -1;
      for (const row of this.tables.get(tableId)) {
        const key = changesByRow.get(row)?.get(columnName) ?? row[columnName];
        if (key.raw < previous) {
          throw new FormatError(`ModuleRef token remapping would violate sorted ${metadataTableNames[tableId]} order`);
        }
        previous = key.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x1a) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing ModuleRef row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`ModuleRef row ${rid} is referenced by CIL`);
        if (targetRid > rid) {
          const replacement = 0x1a000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x1a000000 + oldRid, 0x1a000000 + oldRid - 1);
    }

    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingRefs = this.moduleRefs.filter((reference) => reference.rid !== rid);
    if (remainingRows.length !== remainingRefs.length || !this.moduleRefs[rid - 1] ||
        this.moduleRefs[rid - 1].rid !== rid) {
      throw new FormatError(`ModuleRef row ${rid} has no semantic record`);
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    remainingRefs.forEach((reference, index) => {
      reference.rid = index + 1;
    });
    this.tables.rows.set(26, remainingRows);
    this.tables.counts[26] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 26n);
    this.moduleRefs.splice(0, this.moduleRefs.length, ...remainingRefs);
    for (const typeRef of this.typeRefs) {
      typeRef.resolutionScope = this.tables.row(1, typeRef.rid).ResolutionScope.target;
    }
    for (const memberRef of this.memberRefs) {
      memberRef.parent = this.tables.row(10, memberRef.rid).Class.target;
    }
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  addTypeRef({ scope = null, name, namespace = "" }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("TypeRef name must be a non-empty null-free string");
    }
    if (typeof namespace !== "string" || namespace.includes("\0")) {
      throw new TypeError("TypeRef namespace must be a null-free string");
    }
    let scopeValue = 0;
    let scopeTarget = null;
    if (scope !== null) {
      if (!Number.isInteger(scope.rid) || scope.rid < 1) {
        throw new TypeError("TypeRef scope must identify an existing metadata row");
      }
      const scopeTable = metadataTableId(scope.table);
      if (scopeTable < 0 || scope.rid > (this.tables.counts[scopeTable] ?? 0)) {
        throw new RangeError("TypeRef scope references a missing metadata row");
      }
      scopeValue = encodeCodedIndex(scopeTable, scope.rid, "ResolutionScope");
      scopeTarget = { table: scopeTable, tableName: metadataTableNames[scopeTable], rid: scope.rid };
    }
    const typeRows = this.tables.rows.get(1) ?? [];
    if ((this.tables.sorted & (1n << 1n)) !== 0n && typeRows.length > 0 &&
        typeRows.at(-1).ResolutionScope.raw > scopeValue) {
      throw new FormatError("Appending this TypeRef would violate the table's sorted ResolutionScope order");
    }
    const rid = typeRows.length + 1;
    if (rid > 0x00ffffff) throw new RangeError("TypeRef token row ID exceeds 24-bit range");

    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const namespaceHeap = appendStringHeap(this._heapStreams.get("#Strings") ?? new Uint8Array(), namespace);
    const nameHeap = appendStringHeap(namespaceHeap.heap, name);
    this._heapStreams.set("#Strings", nameHeap.heap);
    this.#refreshHeaps();

    const row = {
      table: 1,
      tableName: metadataTableNames[1],
      rid,
      ResolutionScope: { raw: scopeValue, target: scopeTarget },
      TypeName: nameHeap.index,
      TypeNamespace: namespaceHeap.index
    };
    typeRows.push(row);
    this.tables.rows.set(1, typeRows);
    this.tables.valid |= 1n << 1n;
    this.tables.counts[1] = rid;
    this.typeRefs.push({
      rid,
      name,
      namespace,
      resolutionScope: scopeTarget
    });
    this._metadataDirty = true;
    return 0x01000000 + rid;
  }

  insertTypeRefSorted({ scope = null, name, namespace = "" }) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("Sorted TypeRef insertion cannot be combined with structural method edits");
    }
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("TypeRef name must be a non-empty null-free string");
    }
    if (typeof namespace !== "string" || namespace.includes("\0")) {
      throw new TypeError("TypeRef namespace must be a null-free string");
    }
    let scopeValue = 0;
    let scopeTarget = null;
    if (scope !== null) {
      if (!Number.isInteger(scope.rid) || scope.rid < 1) {
        throw new TypeError("TypeRef scope must identify an existing metadata row");
      }
      const scopeTable = metadataTableId(scope.table);
      if (scopeTable < 0 || scope.rid > (this.tables.counts[scopeTable] ?? 0)) {
        throw new RangeError("TypeRef scope references a missing metadata row");
      }
      scopeValue = encodeCodedIndex(scopeTable, scope.rid, "ResolutionScope");
      scopeTarget = { table: scopeTable, tableName: metadataTableNames[scopeTable], rid: scope.rid };
    }

    const typeRows = this.tables.rows.get(1) ?? [];
    if (typeRows.length + 1 > 0x00ffffff) {
      throw new RangeError("TypeRef token row ID exceeds 24-bit range");
    }
    const newRow = {
      table: 1,
      tableName: metadataTableNames[1],
      rid: 0,
      ResolutionScope: { raw: scopeValue, target: scopeTarget },
      TypeName: 0,
      TypeNamespace: 0
    };
    const rowItems = [
      ...typeRows.map((row, index) => ({ row, oldRid: row.rid, order: index })),
      { row: newRow, oldRid: null, order: typeRows.length }
    ];
    let orderedRows = [...rowItems].sort((left, right) =>
      left.row.ResolutionScope.raw - right.row.ResolutionScope.raw || left.order - right.order
    );
    const seenOrders = new Set();
    let stableOrderFound = false;
    for (let attempt = 0; attempt <= rowItems.length; attempt++) {
      const state = orderedRows.map((item) => item.oldRid ?? "new").join(",");
      if (seenOrders.has(state)) {
        throw new FormatError("TypeRef insertion cannot establish a stable sorted scope order");
      }
      seenOrders.add(state);
      const currentRids = new Map(orderedRows.flatMap((item, index) =>
        item.oldRid === null ? [] : [[item.oldRid, index + 1]]
      ));
      const scopeRaw = (item) => {
        const target = item.row.ResolutionScope.target;
        return target?.table === 1
          ? encodeCodedIndex(1, currentRids.get(target.rid) ?? target.rid, "ResolutionScope")
          : item.row.ResolutionScope.raw;
      };
      const nextOrder = [...rowItems].sort((left, right) =>
        scopeRaw(left) - scopeRaw(right) || left.order - right.order
      );
      if (nextOrder.every((item, index) => item === orderedRows[index])) {
        orderedRows = nextOrder;
        stableOrderFound = true;
        break;
      }
      orderedRows = nextOrder;
    }
    if (!stableOrderFound) {
      throw new FormatError("TypeRef insertion cannot establish a stable sorted scope order");
    }
    const remappedRids = new Map(orderedRows.flatMap((item, index) =>
      item.oldRid === null ? [] : [[item.oldRid, index + 1]]
    ));
    const remappedRid = (rid) => remappedRids.get(rid) ?? rid;
    const tokenMap = new Map([...remappedRids].flatMap(([oldRid, newRid]) =>
      oldRid === newRid ? [] : [[0x01000000 + oldRid, 0x01000000 + newRid]]
    ));
    if (tokenMap.size > 0) {
      this.#ensureAddedMethodBodiesSafe("TypeRef remapping");
      this.#ensureTokenRemappingSafe("TypeRef");
    }
    if (scopeTarget?.table === 1 && remappedRid(scopeTarget.rid) !== scopeTarget.rid) {
      scopeTarget = { ...scopeTarget, rid: remappedRid(scopeTarget.rid) };
      newRow.ResolutionScope = {
        raw: encodeCodedIndex(1, scopeTarget.rid, "ResolutionScope"),
        target: scopeTarget
      };
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(`Cannot remap TypeRef tokens with unrecognized metadata stream ${streamName}`);
      }
    }

    const rowChanges = [];
    for (const [tableId, rows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      for (const row of rows) {
        for (const [kind, value, name] of schema) {
          const columnName = name ?? value;
          const column = row[columnName];
          if (kind === "coded" && column?.target?.table === 1 &&
              remappedRid(column.target.rid) !== column.target.rid) {
            const target = { ...column.target, rid: remappedRid(column.target.rid) };
            rowChanges.push({
              row,
              columnName,
              value: { raw: encodeCodedIndex(1, target.rid, value), target }
            });
          } else if (tableId === 1 && columnName === "ResolutionScope" &&
              column?.target?.table === 1 &&
              remappedRid(column.target.rid) !== column.target.rid) {
            const target = { ...column.target, rid: remappedRid(column.target.rid) };
            rowChanges.push({
              row,
              columnName,
              value: { raw: encodeCodedIndex(1, target.rid, "ResolutionScope"), target }
            });
          }
        }
      }
    }
    rowChanges.push(...collectEncTokenRemaps(this.tables, 1, remappedRid));
    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    for (const [tableId, columnName, codedKind] of [
      [10, "Class", "MemberRefParent"],
      [12, "Parent", "HasCustomAttribute"]
    ]) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = -1;
      for (const row of this.tables.get(tableId)) {
        const column = changesByRow.get(row)?.get(columnName) ?? row[columnName];
        const key = column?.raw ?? 0;
        if (key < previous) {
          throw new FormatError(`TypeRef token remapping would violate sorted ${metadataTableNames[tableId]} order`);
        }
        previous = key;
      }
    }
    let previousTypeRefScope = -1;
    for (const item of orderedRows) {
      const scopeColumn = item.oldRid === null
        ? newRow.ResolutionScope
        : changesByRow.get(item.row)?.get("ResolutionScope") ?? item.row.ResolutionScope;
      if (scopeColumn.raw < previousTypeRefScope) {
        throw new FormatError("TypeRef token remapping would violate sorted TypeRef scope order");
      }
      previousTypeRefScope = scopeColumn.raw;
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const namespaceHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), namespace);
    const nameHeap = appendStringHeap(namespaceHeap.heap, name);
    heapStreams.set("#Strings", nameHeap.heap);
    newRow.TypeNamespace = namespaceHeap.index;
    newRow.TypeName = nameHeap.index;

    const signatureColumns = new Map([
      [4, "Signature"], [6, "Signature"], [10, "Signature"], [17, "Signature"],
      [23, "Type"], [43, "Instantiation"]
    ]);
    const signatureChanges = [];
    for (const [tableId, columnName] of signatureColumns) {
      for (const row of this.tables.get(tableId)) {
        const bytes = this.heaps.getBlob(row[columnName]);
        const parsed = parseSignature(bytes, { counts: this.tables.counts });
        const remapped = remapTypeReferences(parsed, remappedRid);
        if (JSON.stringify(parsed) === JSON.stringify(remapped)) continue;
        const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), encodeSignature(remapped));
        heapStreams.set("#Blob", blob.heap);
        signatureChanges.push({ row, columnName, index: blob.index });
      }
    }
    for (const row of this.tables.get(27)) {
      const parsed = parseTypeSignature(this.heaps.getBlob(row.Signature), { counts: this.tables.counts });
      const remapped = remapTypeReferences(parsed, remappedRid);
      if (JSON.stringify(parsed) === JSON.stringify(remapped)) continue;
      const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), encodeTypeSignature(remapped));
      heapStreams.set("#Blob", blob.heap);
      signatureChanges.push({ row, columnName: "Signature", index: blob.index });
    }

    const tokenUpdates = [];
    const catchTokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x01) continue;
        const oldRid = token & 0x00ffffff;
        if (oldRid === 0 || oldRid > typeRows.length) {
          throw new FormatError(`CIL references missing TypeRef row ${oldRid}`);
        }
        const newRid = remappedRid(oldRid);
        if (oldRid === newRid) continue;
        const replacement = 0x01000000 + newRid;
        patches.push(...createOperandPatches(instruction, replacement));
        tokenUpdates.push({ instruction, replacement });
      }
      const catchRemaps = collectCatchTokenRemaps(
        body,
        1,
        typeRows.length,
        remappedRid,
        "TypeRef"
      );
      patches.push(...catchRemaps.patches);
      catchTokenUpdates.push(...catchRemaps.updates);
    }

    const previousTypesByRid = new Map(this.typeRefs.map((type) => [type.rid, type]));
    const newType = {
      rid: 0,
      name,
      namespace,
      resolutionScope: scopeTarget
    };
    const orderedTypes = orderedRows.map((item, index) => {
      if (item.oldRid === null) return newType;
      const type = previousTypesByRid.get(item.oldRid);
      if (!type) throw new FormatError(`TypeRef row ${item.oldRid} has no semantic record`);
      return type;
    });
    orderedRows.forEach((item, index) => {
      item.row.rid = index + 1;
      orderedTypes[index].rid = index + 1;
    });
    newType.rid = orderedRows.findIndex((item) => item.oldRid === null) + 1;

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of signatureChanges) change.row[change.columnName] = change.index;
    const reorderedRows = orderedRows.map((item) => item.row);
    this.tables.rows.set(1, reorderedRows);
    this.tables.valid |= 1n << 1n;
    this.tables.counts[1] = reorderedRows.length;
    this.typeRefs.splice(0, this.typeRefs.length, ...orderedTypes);
    this.heaps = new MetadataHeaps(new Map([...heapStreams].map(([streamName, bytes]) =>
      [streamName, { bytes }]
    )));
    for (const type of this.typeRefs) {
      if (type.resolutionScope?.table === 1) type.resolutionScope.rid = remappedRid(type.resolutionScope.rid);
    }
    for (const type of this.types) {
      const row = this.tables.row(2, type.rid);
      type.extends = row.Extends.target;
      for (const field of type.fields) {
        const fieldRow = this.tables.row(4, field.rid);
        field.signature = this.heaps.getBlob(fieldRow.Signature);
      }
    }
    for (const method of this.methods) {
      method.signature = this.heaps.getBlob(method.row.Signature);
    }
    for (const memberRef of this.memberRefs) {
      const row = this.tables.row(10, memberRef.rid);
      memberRef.parent = row.Class.target;
      memberRef.signature = this.heaps.getBlob(row.Signature);
    }
    for (const typeSpec of this.typeSpecs) {
      const row = this.tables.row(27, typeSpec.rid);
      typeSpec.signature = this.heaps.getBlob(row.Signature);
      typeSpec.parsedSignature = parseTypeSignature(typeSpec.signature, { counts: this.tables.counts });
    }
    for (const methodSpec of this.methodSpecs) {
      const row = this.tables.row(43, methodSpec.rid);
      methodSpec.instantiation = this.heaps.getBlob(row.Instantiation);
      methodSpec.parsedInstantiation = parseSignature(methodSpec.instantiation, { counts: this.tables.counts });
    }
    for (const constraint of this.genericParamConstraints) {
      const row = this.tables.row(44, constraint.rid);
      constraint.constraint = row.Constraint.target;
    }
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    for (const update of catchTokenUpdates) {
      update.clause.classTokenOrFilterOffset = update.replacement;
    }
    this._patches.push(...patches);
    this._heapStreams = heapStreams;
    this.tables.sorted |= 1n << 1n;
    this._metadataDirty = true;
    return { token: 0x01000000 + newType.rid, tokenMap };
  }

  replaceTypeRef(rid, { scope, name, namespace } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(1, rid);
    const typeRef = this.typeRefs[rid - 1];
    if (!row || !typeRef) throw new RangeError(`Invalid TypeRef row ID ${rid}`);
    const nextName = name ?? typeRef.name;
    const nextNamespace = namespace ?? typeRef.namespace;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("TypeRef name must be a non-empty null-free string");
    }
    if (typeof nextNamespace !== "string" || nextNamespace.includes("\0")) {
      throw new TypeError("TypeRef namespace must be a null-free string");
    }
    const nextScope = scope === undefined ? typeRef.resolutionScope : scope;
    let scopeValue = 0;
    let scopeTarget = null;
    if (nextScope !== null) {
      if (!Number.isInteger(nextScope.rid) || nextScope.rid < 1) {
        throw new TypeError("TypeRef scope must identify an existing metadata row");
      }
      const scopeTable = metadataTableId(nextScope.table);
      if (scopeTable < 0 || nextScope.rid > (this.tables.counts[scopeTable] ?? 0)) {
        throw new RangeError("TypeRef scope references a missing metadata row");
      }
      if (scopeTable === 1 && nextScope.rid === rid) {
        throw new FormatError("TypeRef cannot be its own resolution scope");
      }
      scopeValue = encodeCodedIndex(scopeTable, nextScope.rid, "ResolutionScope");
      scopeTarget = { table: scopeTable, tableName: metadataTableNames[scopeTable], rid: nextScope.rid };
    }
    if ((this.tables.sorted & (1n << 1n)) !== 0n) {
      const previous = this.tables.row(1, rid - 1)?.ResolutionScope.raw ?? -1;
      const following = this.tables.row(1, rid + 1)?.ResolutionScope.raw ?? Number.MAX_SAFE_INTEGER;
      if (scopeValue < previous || scopeValue > following) {
        throw new FormatError("TypeRef replacement would violate sorted ResolutionScope order");
      }
    }
    if (nextName === typeRef.name && nextNamespace === typeRef.namespace &&
        scopeValue === row.ResolutionScope.raw) {
      return this;
    }
    if (nextName !== typeRef.name) {
      const typeRefOverride = { ...typeRef, rid, name: nextName };
      for (const typeSpec of this.typeSpecs) {
        validateTypeSpecDefinitions(this, typeSpec.parsedSignature, typeRefOverride);
      }
      for (const memberRef of this.memberRefs) {
        if (memberRef.parent.table !== 1 || memberRef.parent.rid !== rid) continue;
        validateMemberRefGenericContext(
          this,
          memberRef.parent,
          parseSignature(memberRef.signature, { counts: this.tables.counts }),
          null,
          typeRefOverride
        );
      }
    }

    const heapStreams = this._heapStreams
      ? new Map([...this._heapStreams].map(([streamName, bytes]) => [streamName, bytes.slice()]))
      : new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    if (nextNamespace !== typeRef.namespace) {
      const namespaceHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextNamespace);
      heapStreams.set("#Strings", namespaceHeap.heap);
      row.TypeNamespace = namespaceHeap.index;
    }
    if (nextName !== typeRef.name) {
      const nameHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", nameHeap.heap);
      row.TypeName = nameHeap.index;
    }
    row.ResolutionScope = { raw: scopeValue, target: scopeTarget };
    typeRef.name = nextName;
    typeRef.namespace = nextNamespace;
    typeRef.resolutionScope = scopeTarget;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeTypeRef(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("TypeRef removal cannot be combined with structural method edits");
    }
    this.#ensureAddedMethodBodiesSafe("TypeRef removal");
    this.#ensureTokenRemappingSafe("TypeRef");
    const rows = this.tables.rows.get(1) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid TypeRef row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap TypeRef tokens with unrecognized metadata stream ${streamName}`
        );
      }
    }
    const remappedRid = (oldRid) => {
      if (oldRid === rid) throw new FormatError(`TypeRef row ${rid} has a live reference`);
      return oldRid > rid ? oldRid - 1 : oldRid;
    };

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        const columnName = name ?? value;
        if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId)) {
          for (const row of tableRows) {
            const token = row[columnName];
            if ((token >>> 24) !== 0x01) continue;
            const targetRid = token & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(`TypeRef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (targetRid > rid) {
              rowChanges.push({ row, columnName, value: 0x01000000 + targetRid - 1 });
            }
          }
          continue;
        }
        if (kind !== "coded") continue;
        for (const row of tableRows) {
          const target = row[columnName]?.target;
          if (target?.table !== 1) continue;
          if (target.rid === rid) {
            throw new FormatError(
              `TypeRef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
            );
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: {
                raw: encodeCodedIndex(1, remappedTarget.rid, value),
                target: remappedTarget
              }
            });
          }
        }
      }
    }

    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    for (const [tableId, columnName] of [[10, "Class"], [12, "Parent"]]) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = -1;
      for (const row of this.tables.get(tableId)) {
        const column = changesByRow.get(row)?.get(columnName) ?? row[columnName];
        if (column.raw < previous) {
          throw new FormatError(
            `TypeRef token remapping would violate sorted ${metadataTableNames[tableId]} order`
          );
        }
        previous = column.raw;
      }
    }
    if ((this.tables.sorted & (1n << 1n)) !== 0n) {
      let previous = -1;
      for (const row of rows) {
        if (row.rid === rid) continue;
        const scope = changesByRow.get(row)?.get("ResolutionScope") ?? row.ResolutionScope;
        if (scope.raw < previous) {
          throw new FormatError("TypeRef token remapping would violate sorted TypeRef scope order");
        }
        previous = scope.raw;
      }
    }

    const tokenMap = new Map();
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x01000000 + oldRid, 0x01000000 + oldRid - 1);
    }
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const signatureColumns = new Map([
      [4, "Signature"], [6, "Signature"], [10, "Signature"], [17, "Signature"],
      [23, "Type"], [43, "Instantiation"]
    ]);
    const signatureChanges = [];
    for (const [tableId, columnName] of signatureColumns) {
      for (const row of this.tables.get(tableId)) {
        const parsed = parseSignature(this.heaps.getBlob(row[columnName]), { counts: this.tables.counts });
        const remapped = remapTypeReferences(parsed, remappedRid);
        if (JSON.stringify(parsed) === JSON.stringify(remapped)) continue;
        const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), encodeSignature(remapped));
        heapStreams.set("#Blob", blob.heap);
        signatureChanges.push({ row, columnName, index: blob.index });
      }
    }
    for (const row of this.tables.get(27)) {
      const parsed = parseTypeSignature(this.heaps.getBlob(row.Signature), { counts: this.tables.counts });
      const remapped = remapTypeReferences(parsed, remappedRid);
      if (JSON.stringify(parsed) === JSON.stringify(remapped)) continue;
      const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), encodeTypeSignature(remapped));
      heapStreams.set("#Blob", blob.heap);
      signatureChanges.push({ row, columnName: "Signature", index: blob.index });
    }

    const tokenUpdates = [];
    const catchTokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x01) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing TypeRef row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`TypeRef row ${rid} is referenced by CIL`);
        if (targetRid > rid) {
          const replacement = 0x01000000 + targetRid - 1;
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
      const catchRemaps = collectCatchTokenRemaps(
        body,
        1,
        rows.length,
        remappedRid,
        "TypeRef",
        rid
      );
      patches.push(...catchRemaps.patches);
      catchTokenUpdates.push(...catchRemaps.updates);
    }
    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingTypes = this.typeRefs.filter((type) => type.rid !== rid);
    if (remainingRows.length !== remainingTypes.length || !this.typeRefs[rid - 1] ||
        this.typeRefs[rid - 1].rid !== rid) {
      throw new FormatError(`TypeRef row ${rid} has no semantic record`);
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of signatureChanges) change.row[change.columnName] = change.index;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
      remainingTypes[index].rid = index + 1;
    });
    this.tables.rows.set(1, remainingRows);
    this.tables.counts[1] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 1n);
    this.typeRefs.splice(0, this.typeRefs.length, ...remainingTypes);
    this.heaps = new MetadataHeaps(new Map([...heapStreams].map(([streamName, bytes]) =>
      [streamName, { bytes }]
    )));
    for (const typeRef of this.typeRefs) {
      if (typeRef.resolutionScope?.table === 1) typeRef.resolutionScope.rid = remappedRid(typeRef.resolutionScope.rid);
    }
    for (const type of this.types) {
      const row = this.tables.row(2, type.rid);
      type.extends = row.Extends.target;
      for (const field of type.fields) {
        field.signature = this.heaps.getBlob(this.tables.row(4, field.rid).Signature);
      }
      for (const event of type.events) {
        event.eventType = this.tables.row(20, event.rid).EventType.target;
      }
      for (const property of type.properties) {
        property.signature = this.heaps.getBlob(this.tables.row(23, property.rid).Type);
      }
    }
    for (const method of this.methods) {
      method.signature = this.heaps.getBlob(method.row.Signature);
    }
    for (const memberRef of this.memberRefs) {
      const row = this.tables.row(10, memberRef.rid);
      memberRef.parent = row.Class.target;
      memberRef.signature = this.heaps.getBlob(row.Signature);
    }
    for (const typeSpec of this.typeSpecs) {
      const row = this.tables.row(27, typeSpec.rid);
      typeSpec.signature = this.heaps.getBlob(row.Signature);
      typeSpec.parsedSignature = parseTypeSignature(typeSpec.signature, { counts: this.tables.counts });
    }
    for (const methodSpec of this.methodSpecs) {
      const row = this.tables.row(43, methodSpec.rid);
      methodSpec.instantiation = this.heaps.getBlob(row.Instantiation);
      methodSpec.parsedInstantiation = parseSignature(methodSpec.instantiation, { counts: this.tables.counts });
    }
    for (const constraint of this.genericParamConstraints) {
      constraint.constraint = this.tables.row(44, constraint.rid).Constraint.target;
    }
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    for (const update of catchTokenUpdates) {
      update.clause.classTokenOrFilterOffset = update.replacement;
    }
    this._patches.push(...patches);
    this._heapStreams = heapStreams;
    this._metadataDirty = true;
    return tokenMap;
  }

  addAssemblyRef({
    name,
    culture = "",
    version = [0, 0, 0, 0],
    flags = 0,
    publicKeyOrToken = new Uint8Array(),
    hashValue = new Uint8Array()
  }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("AssemblyRef name must be a non-empty null-free string");
    }
    if (typeof culture !== "string" || culture.includes("\0")) {
      throw new TypeError("AssemblyRef culture must be a null-free string");
    }
    if (!Array.isArray(version) || version.length !== 4 ||
        version.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffff)) {
      throw new TypeError("AssemblyRef version must contain four unsigned 16-bit integers");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffffffff) {
      throw new TypeError("AssemblyRef flags must be an unsigned 32-bit integer");
    }
    if (!(publicKeyOrToken instanceof Uint8Array) || !(hashValue instanceof Uint8Array)) {
      throw new TypeError("AssemblyRef key and hash values must be Uint8Arrays");
    }
    const referenceRows = this.tables.rows.get(35) ?? [];
    const rid = referenceRows.length + 1;
    if (rid > 0x00ffffff) throw new RangeError("AssemblyRef token row ID exceeds 24-bit range");

    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const nameHeap = appendStringHeap(this._heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const cultureHeap = appendStringHeap(nameHeap.heap, culture);
    const keyHeap = appendBlobHeap(this._heapStreams.get("#Blob") ?? new Uint8Array(), publicKeyOrToken);
    const hashHeap = appendBlobHeap(keyHeap.heap, hashValue);
    this._heapStreams.set("#Strings", cultureHeap.heap);
    this._heapStreams.set("#Blob", hashHeap.heap);
    this.#refreshHeaps();

    referenceRows.push({
      table: 35,
      tableName: metadataTableNames[35],
      rid,
      MajorVersion: version[0],
      MinorVersion: version[1],
      BuildNumber: version[2],
      RevisionNumber: version[3],
      Flags: flags,
      PublicKeyOrToken: keyHeap.index,
      Name: nameHeap.index,
      Culture: cultureHeap.index,
      HashValue: hashHeap.index
    });
    this.tables.rows.set(35, referenceRows);
    this.tables.valid |= 1n << 35n;
    this.tables.counts[35] = rid;
    this.assemblyRefs = Object.freeze([...this.assemblyRefs, {
      rid,
      name,
      culture,
      version: [...version],
      publicKeyOrToken: publicKeyOrToken.slice()
    }]);
    this._metadataDirty = true;
    return 0x23000000 + rid;
  }

  insertAssemblyRef({
    beforeRid,
    name,
    culture = "",
    version = [0, 0, 0, 0],
    flags = 0,
    publicKeyOrToken = new Uint8Array(),
    hashValue = new Uint8Array()
  }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("AssemblyRef name must be a non-empty null-free string");
    }
    if (typeof culture !== "string" || culture.includes("\0")) {
      throw new TypeError("AssemblyRef culture must be a null-free string");
    }
    if (!Array.isArray(version) || version.length !== 4 ||
        version.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffff)) {
      throw new TypeError("AssemblyRef version must contain four unsigned 16-bit integers");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffffffff) {
      throw new TypeError("AssemblyRef flags must be an unsigned 32-bit integer");
    }
    if (!(publicKeyOrToken instanceof Uint8Array) || !(hashValue instanceof Uint8Array)) {
      throw new TypeError("AssemblyRef key and hash values must be Uint8Arrays");
    }
    const rows = this.tables.rows.get(35) ?? [];
    if (rows.length !== (this.tables.counts[35] ?? 0) || rows.length !== this.assemblyRefs.length) {
      throw new FormatError("AssemblyRef row count is inconsistent with parsed AssemblyRef records");
    }
    if (!Number.isInteger(beforeRid) || beforeRid < 1 || beforeRid > rows.length + 1) {
      throw new RangeError(`Invalid AssemblyRef insertion position ${beforeRid}`);
    }
    if (rows.length >= 0x00ffffff) {
      throw new RangeError("AssemblyRef token row ID exceeds 24-bit range");
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(35, beforeRid, rows.length, "AssemblyRef");
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const nameHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const cultureHeap = appendStringHeap(nameHeap.heap, culture);
    const keyHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), publicKeyOrToken);
    const hashHeap = appendBlobHeap(keyHeap.heap, hashValue);
    heapStreams.set("#Strings", cultureHeap.heap);
    heapStreams.set("#Blob", hashHeap.heap);
    const rid = beforeRid;
    const row = {
      table: 35,
      tableName: metadataTableNames[35],
      rid,
      MajorVersion: version[0],
      MinorVersion: version[1],
      BuildNumber: version[2],
      RevisionNumber: version[3],
      Flags: flags,
      PublicKeyOrToken: keyHeap.index,
      Name: nameHeap.index,
      Culture: cultureHeap.index,
      HashValue: hashHeap.index
    };

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    rows.splice(rid - 1, 0, row);
    rows.forEach((referenceRow, index) => {
      referenceRow.rid = index + 1;
    });
    this.tables.rows.set(35, rows);
    this.tables.valid |= 1n << 35n;
    this.tables.counts[35] = rows.length;
    const references = this.assemblyRefs.map((reference) => ({
      ...reference,
      rid: reference.rid >= rid ? reference.rid + 1 : reference.rid
    }));
    references.splice(rid - 1, 0, {
      rid,
      name,
      culture,
      version: [...version],
      publicKeyOrToken: publicKeyOrToken.slice()
    });
    this.assemblyRefs = Object.freeze(references);
    for (const typeRef of this.typeRefs) {
      typeRef.resolutionScope = this.tables.row(1, typeRef.rid).ResolutionScope.target;
    }
    for (const exportedType of this.exportedTypes) {
      exportedType.implementation = this.tables.row(39, exportedType.rid).Implementation.target;
    }
    for (const resource of this.resources) {
      resource.implementation = this.tables.row(40, resource.rid).Implementation.target;
    }
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return { token: 0x23000000 + rid, tokenMap };
  }

  addAssemblyProcessor({ processor }) {
    this.#ensureEditable();
    this.#validateAssemblyPlatformFields(33, { Processor: processor });
    return this.#appendMetadataRow(33, { Processor: processor });
  }

  insertAssemblyProcessor({ beforeRid, processor }) {
    this.#ensureEditable();
    this.#validateAssemblyPlatformFields(33, { Processor: processor });
    return this.#insertAssemblyPlatformRow(33, beforeRid, { Processor: processor });
  }

  replaceAssemblyProcessor(rid, { processor } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(33, rid);
    if (!row) throw new RangeError(`Invalid AssemblyProcessor row ID ${rid}`);
    const nextProcessor = processor === undefined ? row.Processor : processor;
    this.#validateAssemblyPlatformFields(33, { Processor: nextProcessor });
    this.#replaceMetadataRow(33, rid, { Processor: nextProcessor });
    return this;
  }

  removeAssemblyProcessor(rid) {
    this.#ensureEditable();
    return this.#removeMetadataRow(33, rid);
  }

  addAssemblyOS({ platformId, majorVersion, minorVersion }) {
    this.#ensureEditable();
    const values = {
      OSPlatformId: platformId,
      OSMajorVersion: majorVersion,
      OSMinorVersion: minorVersion
    };
    this.#validateAssemblyPlatformFields(34, values);
    return this.#appendMetadataRow(34, values);
  }

  insertAssemblyOS({ beforeRid, platformId, majorVersion, minorVersion }) {
    this.#ensureEditable();
    const values = {
      OSPlatformId: platformId,
      OSMajorVersion: majorVersion,
      OSMinorVersion: minorVersion
    };
    this.#validateAssemblyPlatformFields(34, values);
    return this.#insertAssemblyPlatformRow(34, beforeRid, values);
  }

  replaceAssemblyOS(rid, { platformId, majorVersion, minorVersion } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(34, rid);
    if (!row) throw new RangeError(`Invalid AssemblyOS row ID ${rid}`);
    const values = {
      OSPlatformId: platformId === undefined ? row.OSPlatformId : platformId,
      OSMajorVersion: majorVersion === undefined ? row.OSMajorVersion : majorVersion,
      OSMinorVersion: minorVersion === undefined ? row.OSMinorVersion : minorVersion
    };
    this.#validateAssemblyPlatformFields(34, values);
    this.#replaceMetadataRow(34, rid, values);
    return this;
  }

  removeAssemblyOS(rid) {
    this.#ensureEditable();
    return this.#removeMetadataRow(34, rid);
  }

  addAssemblyRefProcessor({ processor, assemblyRefRid }) {
    this.#ensureEditable();
    this.#validateAssemblyPlatformFields(36, { Processor: processor });
    this.#validateAssemblyRefRid(assemblyRefRid);
    return this.#appendMetadataRow(36, {
      Processor: processor,
      AssemblyRef: { raw: assemblyRefRid, rid: assemblyRefRid, table: 35, tableName: metadataTableNames[35] }
    });
  }

  insertAssemblyRefProcessor({ beforeRid, processor, assemblyRefRid }) {
    this.#ensureEditable();
    this.#validateAssemblyPlatformFields(36, { Processor: processor });
    this.#validateAssemblyRefRid(assemblyRefRid);
    return this.#insertAssemblyPlatformRow(36, beforeRid, {
      Processor: processor,
      AssemblyRef: {
        raw: assemblyRefRid,
        rid: assemblyRefRid,
        table: 35,
        tableName: metadataTableNames[35]
      }
    });
  }

  replaceAssemblyRefProcessor(rid, { processor, assemblyRefRid } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(36, rid);
    if (!row) throw new RangeError(`Invalid AssemblyRefProcessor row ID ${rid}`);
    const nextProcessor = processor === undefined ? row.Processor : processor;
    const nextAssemblyRefRid = assemblyRefRid === undefined ? row.AssemblyRef.rid : assemblyRefRid;
    this.#validateAssemblyPlatformFields(36, { Processor: nextProcessor });
    this.#validateAssemblyRefRid(nextAssemblyRefRid);
    this.#replaceMetadataRow(36, rid, {
      Processor: nextProcessor,
      AssemblyRef: {
        ...row.AssemblyRef,
        raw: nextAssemblyRefRid,
        rid: nextAssemblyRefRid
      }
    });
    return this;
  }

  removeAssemblyRefProcessor(rid) {
    this.#ensureEditable();
    return this.#removeMetadataRow(36, rid);
  }

  addAssemblyRefOS({ platformId, majorVersion, minorVersion, assemblyRefRid }) {
    this.#ensureEditable();
    const values = {
      OSPlatformId: platformId,
      OSMajorVersion: majorVersion,
      OSMinorVersion: minorVersion
    };
    this.#validateAssemblyPlatformFields(37, values);
    this.#validateAssemblyRefRid(assemblyRefRid);
    return this.#appendMetadataRow(37, {
      ...values,
      AssemblyRef: { raw: assemblyRefRid, rid: assemblyRefRid, table: 35, tableName: metadataTableNames[35] }
    });
  }

  insertAssemblyRefOS({ beforeRid, platformId, majorVersion, minorVersion, assemblyRefRid }) {
    this.#ensureEditable();
    const values = {
      OSPlatformId: platformId,
      OSMajorVersion: majorVersion,
      OSMinorVersion: minorVersion
    };
    this.#validateAssemblyPlatformFields(37, values);
    this.#validateAssemblyRefRid(assemblyRefRid);
    return this.#insertAssemblyPlatformRow(37, beforeRid, {
      ...values,
      AssemblyRef: {
        raw: assemblyRefRid,
        rid: assemblyRefRid,
        table: 35,
        tableName: metadataTableNames[35]
      }
    });
  }

  replaceAssemblyRefOS(rid, { platformId, majorVersion, minorVersion, assemblyRefRid } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(37, rid);
    if (!row) throw new RangeError(`Invalid AssemblyRefOS row ID ${rid}`);
    const values = {
      OSPlatformId: platformId === undefined ? row.OSPlatformId : platformId,
      OSMajorVersion: majorVersion === undefined ? row.OSMajorVersion : majorVersion,
      OSMinorVersion: minorVersion === undefined ? row.OSMinorVersion : minorVersion
    };
    const nextAssemblyRefRid = assemblyRefRid === undefined ? row.AssemblyRef.rid : assemblyRefRid;
    this.#validateAssemblyPlatformFields(37, values);
    this.#validateAssemblyRefRid(nextAssemblyRefRid);
    this.#replaceMetadataRow(37, rid, {
      ...values,
      AssemblyRef: {
        ...row.AssemblyRef,
        raw: nextAssemblyRefRid,
        rid: nextAssemblyRefRid
      }
    });
    return this;
  }

  removeAssemblyRefOS(rid) {
    this.#ensureEditable();
    return this.#removeMetadataRow(37, rid);
  }

  replaceAssemblyRef(rid, {
    name,
    culture,
    version,
    flags,
    publicKeyOrToken,
    hashValue
  } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(35, rid);
    const reference = this.assemblyRefs[rid - 1];
    if (!row || !reference) throw new RangeError(`Invalid AssemblyRef row ID ${rid}`);
    const nextName = name === undefined ? reference.name : name;
    const nextCulture = culture === undefined ? reference.culture : culture;
    const nextVersion = version === undefined ? reference.version : version;
    const nextFlags = flags === undefined ? row.Flags : flags;
    const nextKey = publicKeyOrToken === undefined
      ? this.heaps.getBlob(row.PublicKeyOrToken)
      : publicKeyOrToken;
    const nextHash = hashValue === undefined ? this.heaps.getBlob(row.HashValue) : hashValue;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("AssemblyRef name must be a non-empty null-free string");
    }
    if (typeof nextCulture !== "string" || nextCulture.includes("\0")) {
      throw new TypeError("AssemblyRef culture must be a null-free string");
    }
    if (!Array.isArray(nextVersion) || nextVersion.length !== 4 ||
        nextVersion.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffff)) {
      throw new TypeError("AssemblyRef version must contain four unsigned 16-bit integers");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 0xffffffff) {
      throw new TypeError("AssemblyRef flags must be an unsigned 32-bit integer");
    }
    if (!(nextKey instanceof Uint8Array) || !(nextHash instanceof Uint8Array)) {
      throw new TypeError("AssemblyRef key and hash values must be Uint8Arrays");
    }
    const currentKey = this.heaps.getBlob(row.PublicKeyOrToken);
    const currentHash = this.heaps.getBlob(row.HashValue);
    const keyChanged = nextKey.length !== currentKey.length ||
      !nextKey.every((byte, index) => byte === currentKey[index]);
    const hashChanged = nextHash.length !== currentHash.length ||
      !nextHash.every((byte, index) => byte === currentHash[index]);
    const changed = nextName !== reference.name || nextCulture !== reference.culture ||
      nextVersion.some((part, index) => part !== reference.version[index]) ||
      nextFlags !== row.Flags || keyChanged || hashChanged;
    if (!changed) return this;

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== reference.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.Name = stringHeap.index;
    }
    if (nextCulture !== reference.culture) {
      const cultureHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextCulture);
      heapStreams.set("#Strings", cultureHeap.heap);
      row.Culture = cultureHeap.index;
    }
    if (keyChanged) {
      const keyHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), nextKey);
      heapStreams.set("#Blob", keyHeap.heap);
      row.PublicKeyOrToken = keyHeap.index;
    }
    if (hashChanged) {
      const hashHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), nextHash);
      heapStreams.set("#Blob", hashHeap.heap);
      row.HashValue = hashHeap.index;
    }
    [row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber] = nextVersion;
    row.Flags = nextFlags;
    this.assemblyRefs = Object.freeze(this.assemblyRefs.map((item) =>
      item.rid === rid
        ? {
          ...item,
          name: nextName,
          culture: nextCulture,
          version: [...nextVersion],
          publicKeyOrToken: nextKey.slice()
        }
        : item
    ));
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeAssemblyRef(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("AssemblyRef removal cannot be combined with structural method edits");
    }
    this.#ensureTokenRemappingSafe("AssemblyRef");
    const rows = this.tables.rows.get(35) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid AssemblyRef row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(`Cannot remap AssemblyRef tokens with unrecognized metadata stream ${streamName}`);
      }
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      for (const row of tableRows) {
        for (const [kind, value, name] of schema) {
          const columnName = name ?? value;
          const column = row[columnName];
          if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId) &&
              (column >>> 24) === 0x23) {
            const targetRid = column & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(`AssemblyRef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (targetRid > rid) {
              rowChanges.push({
                row,
                columnName,
                value: 0x23000000 + targetRid - 1
              });
            }
            continue;
          }
          const target = kind === "coded" ? column?.target : kind === "table" ? column : null;
          if (target?.table !== 35) continue;
          if (target.rid === rid) {
            throw new FormatError(`AssemblyRef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: kind === "coded"
                ? { raw: encodeCodedIndex(35, remappedTarget.rid, value), target: remappedTarget }
                : { ...column, rid: remappedTarget.rid, raw: remappedTarget.rid }
            });
          }
        }
      }
    }

    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    for (const [tableId, columnName] of [[1, "ResolutionScope"], [12, "Parent"]]) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = -1;
      for (const row of this.tables.get(tableId)) {
        const key = changesByRow.get(row)?.get(columnName) ?? row[columnName];
        if (key.raw < previous) {
          throw new FormatError(`AssemblyRef token remapping would violate sorted ${metadataTableNames[tableId]} order`);
        }
        previous = key.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x23) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing AssemblyRef row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`AssemblyRef row ${rid} is referenced by CIL`);
        if (targetRid > rid) {
          const replacement = 0x23000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x23000000 + oldRid, 0x23000000 + oldRid - 1);
    }

    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingRefs = this.assemblyRefs.filter((reference) => reference.rid !== rid);
    if (remainingRows.length !== remainingRefs.length || !this.assemblyRefs[rid - 1] ||
        this.assemblyRefs[rid - 1].rid !== rid) {
      throw new FormatError(`AssemblyRef row ${rid} has no semantic record`);
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    remainingRefs.forEach((reference, index) => {
      reference.rid = index + 1;
    });
    this.tables.rows.set(35, remainingRows);
    this.tables.counts[35] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 35n);
    this.assemblyRefs = Object.freeze(remainingRefs);
    for (const typeRef of this.typeRefs) {
      typeRef.resolutionScope = this.tables.row(1, typeRef.rid).ResolutionScope.target;
    }
    for (const resource of this.resources) {
      resource.implementation = this.tables.row(40, resource.rid).Implementation.target;
    }
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  addTypeSpec({ signature }) {
    this.#ensureEditable();
    if (!(signature instanceof Uint8Array)) throw new TypeError("TypeSpec signature must be a Uint8Array");
    const parsedSignature = parseTypeSignature(signature, { counts: this.tables.counts });
    validateTypeSpecDefinitions(this, parsedSignature);
    const typeSpecRows = this.tables.rows.get(27) ?? [];
    const rid = typeSpecRows.length + 1;
    if (rid > 0x00ffffff) throw new RangeError("TypeSpec token row ID exceeds 24-bit range");

    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const blobHeap = appendBlobHeap(this._heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    this._heapStreams.set("#Blob", blobHeap.heap);
    this.#refreshHeaps();
    typeSpecRows.push({
      table: 27,
      tableName: metadataTableNames[27],
      rid,
      Signature: blobHeap.index
    });
    this.tables.rows.set(27, typeSpecRows);
    this.tables.valid |= 1n << 27n;
    this.tables.counts[27] = rid;
    this.typeSpecs.push({
      rid,
      signature: signature.slice(),
      parsedSignature
    });
    this._metadataDirty = true;
    return 0x1b000000 + rid;
  }

  insertTypeSpec({ beforeRid, signature }) {
    this.#ensureEditable();
    if (!(signature instanceof Uint8Array)) {
      throw new TypeError("TypeSpec signature must be a Uint8Array");
    }
    const parsedSignature = parseTypeSignature(signature, { counts: this.tables.counts });
    validateTypeSpecDefinitions(this, parsedSignature);
    const rows = this.tables.rows.get(27) ?? [];
    if (rows.length !== (this.tables.counts[27] ?? 0) || rows.length !== this.typeSpecs.length) {
      throw new FormatError("TypeSpec row count is inconsistent with parsed TypeSpec records");
    }
    if (!Number.isInteger(beforeRid) || beforeRid < 1 || beforeRid > rows.length + 1) {
      throw new RangeError(`Invalid TypeSpec insertion position ${beforeRid}`);
    }
    if (rows.length >= 0x00ffffff) {
      throw new RangeError("TypeSpec token row ID exceeds 24-bit range");
    }

    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(27, beforeRid, rows.length, "TypeSpec");
    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    for (const [tableId, columnName] of [[10, "Class"], [12, "Parent"]]) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = -1;
      for (const row of this.tables.get(tableId)) {
        const column = changesByRow.get(row)?.get(columnName) ?? row[columnName];
        if (column.raw < previous) {
          throw new FormatError(
            `TypeSpec token remapping would violate sorted ${metadataTableNames[tableId]} order`
          );
        }
        previous = column.raw;
      }
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const remapTypeSpecRid = (oldRid) => oldRid >= beforeRid ? oldRid + 1 : oldRid;
    const signatureColumns = new Map([
      [4, "Signature"], [6, "Signature"], [10, "Signature"], [17, "Signature"],
      [23, "Type"], [43, "Instantiation"]
    ]);
    const signatureChanges = [];
    for (const [tableId, columnName] of signatureColumns) {
      for (const row of this.tables.get(tableId)) {
        const parsed = parseSignature(this.heaps.getBlob(row[columnName]), {
          counts: this.tables.counts
        });
        if (!rows.slice(beforeRid - 1).some((candidate) =>
          containsMetadataReference(parsed, 27, candidate.rid)
        )) continue;
        const remapped = remapTypeReferences(parsed, remapTypeSpecRid, 27);
        const blob = appendBlobHeap(
          heapStreams.get("#Blob") ?? new Uint8Array(),
          encodeSignature(remapped)
        );
        heapStreams.set("#Blob", blob.heap);
        signatureChanges.push({ row, columnName, index: blob.index });
      }
    }
    for (const row of rows) {
      const parsed = parseTypeSignature(this.heaps.getBlob(row.Signature), {
        counts: this.tables.counts
      });
      if (!rows.slice(beforeRid - 1).some((candidate) =>
        containsMetadataReference(parsed, 27, candidate.rid)
      )) continue;
      const remapped = remapTypeReferences(parsed, remapTypeSpecRid, 27);
      const blob = appendBlobHeap(
        heapStreams.get("#Blob") ?? new Uint8Array(),
        encodeTypeSignature(remapped)
      );
      heapStreams.set("#Blob", blob.heap);
      signatureChanges.push({ row, columnName: "Signature", index: blob.index });
    }
    const remappedNewSignature = remapTypeReferences(parsedSignature, remapTypeSpecRid, 27);
    const newSignatureBytes = encodeTypeSignature(remappedNewSignature);
    const newBlob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), newSignatureBytes);
    heapStreams.set("#Blob", newBlob.heap);

    const catchTokenUpdates = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      const catchRemaps = collectCatchTokenRemaps(
        body,
        27,
        rows.length,
        remapTypeSpecRid,
        "TypeSpec"
      );
      patches.push(...catchRemaps.patches);
      catchTokenUpdates.push(...catchRemaps.updates);
    }

    const rid = beforeRid;
    const newRow = {
      table: 27,
      tableName: metadataTableNames[27],
      rid,
      Signature: newBlob.index
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of signatureChanges) change.row[change.columnName] = change.index;
    rows.splice(rid - 1, 0, newRow);
    rows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.tables.rows.set(27, rows);
    this.tables.valid |= 1n << 27n;
    this.tables.counts[27] = rows.length;
    this.typeSpecs.splice(rid - 1, 0, {
      rid,
      signature: newSignatureBytes,
      parsedSignature: remappedNewSignature
    });
    this.typeSpecs.forEach((typeSpec, index) => {
      typeSpec.rid = index + 1;
    });

    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    for (const type of this.types) {
      type.extends = this.tables.row(2, type.rid).Extends.target;
      for (const field of type.fields) {
        field.signature = this.heaps.getBlob(this.tables.row(4, field.rid).Signature);
      }
      for (const event of type.events) {
        event.eventType = this.tables.row(20, event.rid).EventType.target;
      }
      for (const property of type.properties) {
        property.signature = this.heaps.getBlob(this.tables.row(23, property.rid).Type);
      }
    }
    for (const method of this.methods) {
      method.signature = this.heaps.getBlob(method.row.Signature);
    }
    for (const memberRef of this.memberRefs) {
      const row = this.tables.row(10, memberRef.rid);
      memberRef.parent = row.Class.target;
      memberRef.signature = this.heaps.getBlob(row.Signature);
    }
    for (const constraint of this.genericParamConstraints) {
      constraint.constraint = this.tables.row(44, constraint.rid).Constraint.target;
    }
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    for (const typeSpec of this.typeSpecs) {
      const row = this.tables.row(27, typeSpec.rid);
      typeSpec.signature = this.heaps.getBlob(row.Signature);
      typeSpec.parsedSignature = parseTypeSignature(typeSpec.signature, {
        counts: this.tables.counts
      });
    }
    for (const methodSpec of this.methodSpecs) {
      const row = this.tables.row(43, methodSpec.rid);
      methodSpec.instantiation = this.heaps.getBlob(row.Instantiation);
      methodSpec.parsedInstantiation = parseSignature(methodSpec.instantiation, {
        counts: this.tables.counts
      });
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    for (const update of catchTokenUpdates) {
      update.clause.classTokenOrFilterOffset = update.replacement;
    }
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { token: 0x1b000000 + rid, tokenMap };
  }

  replaceTypeSpecSignature(rid, signature) {
    this.#ensureEditable();
    const row = this.tables.row(27, rid);
    const typeSpec = this.typeSpecs[rid - 1];
    if (!row || !typeSpec) throw new RangeError(`Invalid TypeSpec row ID ${rid}`);
    if (!(signature instanceof Uint8Array)) {
      throw new TypeError("TypeSpec signature must be a Uint8Array");
    }
    const parsedSignature = parseTypeSignature(signature, { counts: this.tables.counts });
    validateTypeSpecDefinitions(
      this,
      parsedSignature,
      null,
      new Set(),
      { ...typeSpec, signature: signature.slice(), parsedSignature }
    );
    validateTypeSpecUseSites(this, {
      ...typeSpec,
      signature: signature.slice(),
      parsedSignature
    });
    if (signature.length === typeSpec.signature.length &&
        signature.every((byte, index) => byte === typeSpec.signature[index])) {
      return this;
    }
    const heapStreams = this._heapStreams
      ? new Map([...this._heapStreams].map(([streamName, bytes]) => [streamName, bytes.slice()]))
      : new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Blob", blobHeap.heap);
    row.Signature = blobHeap.index;
    typeSpec.signature = signature.slice();
    typeSpec.parsedSignature = parsedSignature;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeTypeSpec(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("TypeSpec removal cannot be combined with structural method edits");
    }
    this.#ensureAddedMethodBodiesSafe("TypeSpec removal");
    this.#ensureTokenRemappingSafe("TypeSpec");
    const rows = this.tables.rows.get(27) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid TypeSpec row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap TypeSpec tokens with unrecognized metadata stream ${streamName}`
        );
      }
    }
    const remappedRid = (oldRid) => {
      if (oldRid === rid) throw new FormatError(`TypeSpec row ${rid} has a live reference`);
      return oldRid > rid ? oldRid - 1 : oldRid;
    };

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        const columnName = name ?? value;
        if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId)) {
          for (const row of tableRows) {
            const token = row[columnName];
            if ((token >>> 24) !== 0x1b) continue;
            const targetRid = token & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(`TypeSpec row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (targetRid > rid) {
              rowChanges.push({ row, columnName, value: 0x1b000000 + targetRid - 1 });
            }
          }
          continue;
        }
        if (kind !== "coded") continue;
        for (const row of tableRows) {
          const target = row[columnName]?.target;
          if (target?.table !== 27) continue;
          if (target.rid === rid) {
            throw new FormatError(
              `TypeSpec row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
            );
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: {
                raw: encodeCodedIndex(27, remappedTarget.rid, value),
                target: remappedTarget
              }
            });
          }
        }
      }
    }
    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    for (const [tableId, columnName] of [[10, "Class"], [12, "Parent"]]) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = -1;
      for (const row of this.tables.get(tableId)) {
        const column = changesByRow.get(row)?.get(columnName) ?? row[columnName];
        if (column.raw < previous) {
          throw new FormatError(
            `TypeSpec token remapping would violate sorted ${metadataTableNames[tableId]} order`
          );
        }
        previous = column.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const catchTokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x1b) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing TypeSpec row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`TypeSpec row ${rid} is referenced by CIL`);
        if (targetRid > rid) {
          const replacement = 0x1b000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
      const catchRemaps = collectCatchTokenRemaps(
        body,
        27,
        rows.length,
        (oldRid) => oldRid > rid ? oldRid - 1 : oldRid,
        "TypeSpec",
        rid
      );
      patches.push(...catchRemaps.patches);
      catchTokenUpdates.push(...catchRemaps.updates);
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x1b000000 + oldRid, 0x1b000000 + oldRid - 1);
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const signatureColumns = new Map([
      [4, "Signature"], [6, "Signature"], [10, "Signature"], [17, "Signature"],
      [23, "Type"], [43, "Instantiation"]
    ]);
    const signatureChanges = [];
    for (const [tableId, columnName] of signatureColumns) {
      for (const row of this.tables.get(tableId)) {
        const parsed = parseSignature(this.heaps.getBlob(row[columnName]), { counts: this.tables.counts });
        const remapped = remapTypeReferences(parsed, remappedRid, 27);
        if (JSON.stringify(parsed) === JSON.stringify(remapped)) continue;
        const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), encodeSignature(remapped));
        heapStreams.set("#Blob", blob.heap);
        signatureChanges.push({ row, columnName, index: blob.index });
      }
    }
    for (const row of rows) {
      if (row.rid === rid) continue;
      const parsed = parseTypeSignature(this.heaps.getBlob(row.Signature), { counts: this.tables.counts });
      const remapped = remapTypeReferences(parsed, remappedRid, 27);
      if (JSON.stringify(parsed) === JSON.stringify(remapped)) continue;
      const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), encodeTypeSignature(remapped));
      heapStreams.set("#Blob", blob.heap);
      signatureChanges.push({ row, columnName: "Signature", index: blob.index });
    }
    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingTypeSpecs = this.typeSpecs.filter((typeSpec) => typeSpec.rid !== rid);
    if (remainingRows.length !== remainingTypeSpecs.length || !this.typeSpecs[rid - 1] ||
        this.typeSpecs[rid - 1].rid !== rid) {
      throw new FormatError(`TypeSpec row ${rid} has no semantic record`);
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of signatureChanges) change.row[change.columnName] = change.index;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
      remainingTypeSpecs[index].rid = index + 1;
    });
    this.tables.rows.set(27, remainingRows);
    this.tables.counts[27] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 27n);
    this.typeSpecs.splice(0, this.typeSpecs.length, ...remainingTypeSpecs);
    this.heaps = new MetadataHeaps(new Map([...heapStreams].map(([streamName, bytes]) =>
      [streamName, { bytes }]
    )));
    for (const type of this.types) {
      type.extends = this.tables.row(2, type.rid).Extends.target;
      for (const field of type.fields) {
        field.signature = this.heaps.getBlob(this.tables.row(4, field.rid).Signature);
      }
      for (const event of type.events) {
        event.eventType = this.tables.row(20, event.rid).EventType.target;
      }
      for (const property of type.properties) {
        property.signature = this.heaps.getBlob(this.tables.row(23, property.rid).Type);
      }
    }
    for (const method of this.methods) {
      method.signature = this.heaps.getBlob(method.row.Signature);
    }
    for (const memberRef of this.memberRefs) {
      const row = this.tables.row(10, memberRef.rid);
      memberRef.parent = row.Class.target;
      memberRef.signature = this.heaps.getBlob(row.Signature);
    }
    for (const typeSpec of this.typeSpecs) {
      const row = this.tables.row(27, typeSpec.rid);
      typeSpec.signature = this.heaps.getBlob(row.Signature);
      typeSpec.parsedSignature = parseTypeSignature(typeSpec.signature, { counts: this.tables.counts });
    }
    for (const methodSpec of this.methodSpecs) {
      const row = this.tables.row(43, methodSpec.rid);
      methodSpec.instantiation = this.heaps.getBlob(row.Instantiation);
      methodSpec.parsedInstantiation = parseSignature(methodSpec.instantiation, { counts: this.tables.counts });
    }
    for (const constraint of this.genericParamConstraints) {
      constraint.constraint = this.tables.row(44, constraint.rid).Constraint.target;
    }
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    for (const update of catchTokenUpdates) {
      update.clause.classTokenOrFilterOffset = update.replacement;
    }
    this._patches.push(...patches);
    this._heapStreams = heapStreams;
    this._metadataDirty = true;
    return tokenMap;
  }

  addMethodSpec({ method, instantiation }) {
    this.#ensureEditable();
    if (!method || !Number.isInteger(method.rid) || method.rid < 1) {
      throw new TypeError("MethodSpec method must identify an existing MethodDef or MemberRef");
    }
    const methodTable = metadataTableId(method.table);
    if ((methodTable !== 6 && methodTable !== 10) ||
        method.rid > (this.tables.counts[methodTable] ?? 0)) {
      throw new RangeError("MethodSpec references a missing or invalid method row");
    }
    if (!(instantiation instanceof Uint8Array)) {
      throw new TypeError("MethodSpec instantiation must be a Uint8Array");
    }
    const parsedInstantiation = parseSignature(instantiation, { counts: this.tables.counts });
    if (parsedInstantiation.kind !== "methodInstantiation") {
      throw new FormatError("MethodSpec requires a method-instantiation signature");
    }
    const methodSignatureBytes = methodTable === 6
      ? this.methods[method.rid - 1]?.signature
      : this.memberRefs.find((reference) => reference.rid === method.rid)?.signature;
    if (!methodSignatureBytes) throw new FormatError("MethodSpec target has no available signature");
    const methodSignature = parseSignature(methodSignatureBytes, { counts: this.tables.counts });
    if (methodSignature.kind !== "method" || !methodSignature.generic ||
        methodSignature.genericParameterCount !== parsedInstantiation.arguments.length) {
      throw new FormatError("MethodSpec instantiation does not match its generic method signature");
    }
    const methodValue = encodeCodedIndex(methodTable, method.rid, "MethodDefOrRef");
    const methodSpecRows = this.tables.rows.get(43) ?? [];
    if ((this.tables.sorted & (1n << 43n)) !== 0n && methodSpecRows.length > 0 &&
        methodSpecRows.at(-1).Method.raw > methodValue) {
      throw new FormatError("Appending this MethodSpec would violate the table's sorted Method order");
    }
    const rid = methodSpecRows.length + 1;
    if (rid > 0x00ffffff) throw new RangeError("MethodSpec token row ID exceeds 24-bit range");

    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const blobHeap = appendBlobHeap(this._heapStreams.get("#Blob") ?? new Uint8Array(), instantiation);
    this._heapStreams.set("#Blob", blobHeap.heap);
    this.#refreshHeaps();
    const target = {
      table: methodTable,
      tableName: metadataTableNames[methodTable],
      rid: method.rid
    };
    methodSpecRows.push({
      table: 43,
      tableName: metadataTableNames[43],
      rid,
      Method: { raw: methodValue, target },
      Instantiation: blobHeap.index
    });
    this.tables.rows.set(43, methodSpecRows);
    this.tables.valid |= 1n << 43n;
    this.tables.counts[43] = rid;
    this.methodSpecs.push({
      rid,
      method: target,
      instantiation: instantiation.slice(),
      parsedInstantiation
    });
    this._metadataDirty = true;
    return 0x2b000000 + rid;
  }

  replaceMethodSpecInstantiation(rid, instantiation) {
    this.#ensureEditable();
    const row = this.tables.row(43, rid);
    const methodSpec = this.methodSpecs[rid - 1];
    if (!row || !methodSpec) throw new RangeError(`Invalid MethodSpec row ID ${rid}`);
    if (!(instantiation instanceof Uint8Array)) {
      throw new TypeError("MethodSpec instantiation must be a Uint8Array");
    }
    const parsedInstantiation = parseSignature(instantiation, { counts: this.tables.counts });
    if (parsedInstantiation.kind !== "methodInstantiation") {
      throw new FormatError("MethodSpec requires a method-instantiation signature");
    }
    const methodSignatureBytes = methodSpec.method.table === 6
      ? this.methods[methodSpec.method.rid - 1]?.signature
      : this.memberRefs.find((reference) => reference.rid === methodSpec.method.rid)?.signature;
    if (!methodSignatureBytes) throw new FormatError("MethodSpec target has no available signature");
    const methodSignature = parseSignature(methodSignatureBytes, { counts: this.tables.counts });
    if (methodSignature.kind !== "method" || !methodSignature.generic ||
        methodSignature.genericParameterCount !== parsedInstantiation.arguments.length) {
      throw new FormatError("MethodSpec instantiation does not match its generic method signature");
    }
    validateMethodSpecUseSites(this, rid, null, {
      ...methodSpec,
      instantiation: instantiation.slice(),
      parsedInstantiation
    });
    if (instantiation.length === methodSpec.instantiation.length &&
        instantiation.every((byte, index) => byte === methodSpec.instantiation[index])) {
      return this;
    }
    const heapStreams = this._heapStreams
      ? new Map([...this._heapStreams].map(([streamName, bytes]) => [streamName, bytes.slice()]))
      : new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), instantiation);
    heapStreams.set("#Blob", blobHeap.heap);
    row.Instantiation = blobHeap.index;
    methodSpec.instantiation = instantiation.slice();
    methodSpec.parsedInstantiation = parsedInstantiation;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  addStandAloneSig({ signature }) {
    this.#ensureEditable();
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
      throw new TypeError("StandAloneSig signature must be a non-empty Uint8Array");
    }
    const parsedSignature = parseSignature(signature, { counts: this.tables.counts });
    if (!["method", "locals"].includes(parsedSignature.kind)) {
      throw new FormatError("StandAloneSig must contain a method or local-variable signature");
    }
    const rows = this.tables.rows.get(17) ?? [];
    if (rows.length !== (this.tables.counts[17] ?? 0) || rows.length >= 0x00ffffff) {
      throw new RangeError("StandAloneSig row count is inconsistent or exceeds the metadata token range");
    }
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Blob", blob.heap);
    const rid = rows.length + 1;
    rows.push({
      table: 17,
      tableName: metadataTableNames[17],
      rid,
      Signature: blob.index
    });
    this.tables.rows.set(17, rows);
    this.tables.counts[17] = rid;
    this.tables.valid |= 1n << 17n;
    this.standAloneSigs.push({
      rid,
      signature: signature.slice(),
      parsedSignature
    });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return 0x11000000 + rid;
  }

  insertStandAloneSig({ beforeRid, signature }) {
    this.#ensureEditable();
    const embeddedPdbIndices = this.pe.debugDirectoryEntries.flatMap((entry, index) =>
      entry.embeddedPortablePdb ? [index] : []
    );
    if (embeddedPdbIndices.length > 1) {
      throw new UnsupportedFormatError(
        "StandAloneSig insertion supports only one embedded Portable PDB"
      );
    }
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
      throw new TypeError("StandAloneSig signature must be a non-empty Uint8Array");
    }
    const parsedSignature = parseSignature(signature, { counts: this.tables.counts });
    if (!["method", "locals"].includes(parsedSignature.kind)) {
      throw new FormatError("StandAloneSig must contain a method or local-variable signature");
    }
    const rows = this.tables.rows.get(17) ?? [];
    if (rows.length !== (this.tables.counts[17] ?? 0) || rows.length !== this.standAloneSigs.length) {
      throw new FormatError("StandAloneSig row count is inconsistent with parsed signature records");
    }
    if (!Number.isInteger(beforeRid) || beforeRid < 1 || beforeRid > rows.length + 1) {
      throw new RangeError(`Invalid StandAloneSig insertion position ${beforeRid}`);
    }
    if (rows.length >= 0x00ffffff) {
      throw new RangeError("StandAloneSig token row ID exceeds 24-bit range");
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(
        17,
        beforeRid,
        rows.length,
        "StandAloneSig",
        { allowEmbeddedPortablePdb: embeddedPdbIndices.length === 1 }
      );
    const localSignatureUpdates = [];
    if (beforeRid <= rows.length) {
      for (const method of this.methods) {
        const body = this.getMethodBody(method.rid);
        if (!body) continue;
        const localToken = body.localVarSigToken;
        if (localToken !== 0) {
          const localRid = localToken & 0x00ffffff;
          if ((localToken >>> 24) !== 17 || localRid < 1 || localRid > rows.length) {
            throw new FormatError(`MethodDef row ${method.rid} has an invalid local signature token`);
          }
          if (localRid >= beforeRid) {
            if (body.format !== "fat") {
              throw new FormatError("A tiny method body cannot contain a local signature token");
            }
            const replacement = localToken + 1;
            patches.push({
              offset: body.headerOffset + 8,
              bytes: Uint8Array.of(
                replacement & 0xff,
                (replacement >>> 8) & 0xff,
                (replacement >>> 16) & 0xff,
                (replacement >>> 24) & 0xff
              )
            });
            localSignatureUpdates.push({ body, replacement });
          }
        }
        for (const instruction of body.instructions) {
          const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
          if ((token >>> 24) === 17) {
            const targetRid = token & 0x00ffffff;
            if (targetRid < 1 || targetRid > rows.length) {
              throw new FormatError(`CIL references missing StandAloneSig row ${targetRid}`);
            }
          }
        }
      }
    }
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Blob", blob.heap);
    const rid = beforeRid;
    const newRow = {
      table: 17,
      tableName: metadataTableNames[17],
      rid,
      Signature: blob.index
    };
    let updatedEmbeddedPdb = null;
    let updatedCounts = null;
    if (embeddedPdbIndices.length === 1) {
      updatedCounts = [...this.tables.counts];
      updatedCounts[17]++;
      const debugEntryIndex = embeddedPdbIndices[0];
      const debugEntry = this.pe.debugDirectoryEntries[debugEntryIndex];
      updatedEmbeddedPdb = remapPortablePdbLocalSignatures(
        this.#getPortablePdbForEdit(debugEntryIndex, debugEntry),
        rid,
        this.tables.counts,
        updatedCounts,
        "insert"
      );
      this.#replaceEmbeddedPortablePdb(
        debugEntryIndex,
        updatedEmbeddedPdb,
        updatedCounts
      );
    }

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    rows.splice(rid - 1, 0, newRow);
    rows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.tables.rows.set(17, rows);
    this.tables.counts[17] = rows.length;
    this.tables.valid |= 1n << 17n;
    const signatures = this.standAloneSigs.map((entry) => ({
      ...entry,
      rid: entry.rid >= rid ? entry.rid + 1 : entry.rid
    }));
    signatures.splice(rid - 1, 0, {
      rid,
      signature: signature.slice(),
      parsedSignature
    });
    this.standAloneSigs = signatures;
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    for (const update of localSignatureUpdates) {
      update.body.localVarSigToken = update.replacement;
    }
    this._patches.push(...patches);
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return { token: 0x11000000 + rid, tokenMap };
  }

  replaceStandAloneSig(rid, { signature } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(17, rid);
    const entry = this.standAloneSigs[rid - 1];
    if (!Number.isInteger(rid) || rid < 1 || !row || !entry) {
      throw new RangeError(`Invalid StandAloneSig row ID ${rid}`);
    }
    if (!(signature instanceof Uint8Array) || signature.length === 0) {
      throw new TypeError("StandAloneSig signature must be a non-empty Uint8Array");
    }
    const parsedSignature = parseSignature(signature, { counts: this.tables.counts });
    if (parsedSignature.kind !== entry.parsedSignature.kind) {
      throw new FormatError("StandAloneSig replacement must preserve its method or local-signature kind");
    }
    if (signature.length === entry.signature.length &&
        signature.every((byte, index) => byte === entry.signature[index])) {
      return this;
    }
    const token = 0x11000000 + rid;
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      const localSignatureReference = body.localVarSigToken === token;
      const calliReferences = body.instructions.filter((instruction) =>
        instruction.operand?.kind === "token" && instruction.operand.value === token &&
        instruction.opcode.name === "calli"
      );
      if (!localSignatureReference && calliReferences.length === 0) continue;
      const ownerType = this.types.find((type) => type.methodRids.includes(method.rid));
      const typeArity = ownerType
        ? getGenericParameterArity(this.genericParams, 2, ownerType.rid)
        : 0;
      const methodSignature = parseSignature(method.signature, { counts: this.tables.counts });
      const methodArity = methodSignature.kind === "method" && methodSignature.generic
        ? methodSignature.genericParameterCount
        : 0;
      if (localSignatureReference) {
        if (parsedSignature.kind !== "locals") {
          throw new FormatError("StandAloneSig used by a method header must remain a local-variable signature");
        }
        validateGenericVariableReferences(parsedSignature, typeArity, this, null, methodArity);
      }
      if (calliReferences.length > 0) {
        if (parsedSignature.kind !== "method") {
          throw new FormatError("StandAloneSig used by calli must remain a method signature");
        }
        validateGenericVariableReferences(parsedSignature, typeArity, this, null, methodArity);
      }
    }
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signature);
    heapStreams.set("#Blob", blob.heap);
    row.Signature = blob.index;
    entry.signature = signature.slice();
    entry.parsedSignature = parsedSignature;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeStandAloneSig(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError(
        "StandAloneSig removal cannot be combined with structural method edits"
      );
    }
    this.#ensureAddedMethodBodiesSafe("StandAloneSig removal");
    const embeddedPdbIndices = this.pe.debugDirectoryEntries.flatMap((entry, index) =>
      entry.embeddedPortablePdb ? [index] : []
    );
    if (embeddedPdbIndices.length > 1) {
      throw new UnsupportedFormatError(
        "StandAloneSig removal supports only one embedded Portable PDB"
      );
    }
    this.#ensureTokenRemappingSafe("StandAloneSig", {
      allowEmbeddedPortablePdb: embeddedPdbIndices.length === 1
    });
    const rows = this.tables.rows.get(17) ?? [];
    if (rows.length !== this.tables.counts[17]) {
      throw new FormatError("StandAloneSig row count is inconsistent with the metadata table header");
    }
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid StandAloneSig row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap StandAloneSig rows with unrecognized metadata stream ${streamName}`
        );
      }
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      if (!schema) {
        throw new UnsupportedFormatError(
          `Cannot remap StandAloneSig references in unknown metadata table ${tableId}`
        );
      }
      for (const row of tableRows) {
        for (const [kind, value, name] of schema) {
          const columnName = name ?? value;
          if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId)) {
            const token = row[columnName];
            if ((token >>> 24) !== 0x11) continue;
            const targetRid = token & 0x00ffffff;
            if (targetRid === 0 || targetRid > rows.length) {
              throw new FormatError(
                `${metadataTableNames[tableId]}.${columnName} references a missing StandAloneSig row`
              );
            }
            if (targetRid === rid) {
              throw new FormatError(
                `StandAloneSig row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (targetRid > rid) {
              rowChanges.push({
                row,
                columnName,
                value: 0x11000000 + targetRid - 1
              });
            }
            continue;
          }
          if (kind !== "coded" && kind !== "table") continue;
          const column = row[columnName];
          const target = kind === "coded" ? column?.target : column;
          if (target?.table !== 17) continue;
          if (!Number.isInteger(target.rid) || target.rid < 1 || target.rid > rows.length) {
            throw new FormatError(
              `${metadataTableNames[tableId]}.${columnName} references an invalid StandAloneSig row`
            );
          }
          if (target.rid === rid) {
            throw new FormatError(
              `StandAloneSig row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
            );
          }
          if (target.rid < rid) continue;
          const remappedTarget = { ...target, rid: target.rid - 1 };
          rowChanges.push({
            row,
            columnName,
            value: kind === "coded"
              ? {
                raw: encodeCodedIndex(17, remappedTarget.rid, value),
                target: remappedTarget
              }
              : { ...column, raw: remappedTarget.rid, rid: remappedTarget.rid }
          });
        }
      }
    }

    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      const changesByRow = new Map(rowChanges.map((change) => [
        change.row,
        change.value
      ]));
      let previous = -1;
      for (const row of this.tables.get(12)) {
        const parent = changesByRow.get(row) ?? row.Parent;
        if (parent.raw < previous) {
          throw new FormatError(
            "StandAloneSig token remapping would violate sorted CustomAttribute order"
          );
        }
        previous = parent.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const localSignatureUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      const localToken = body.localVarSigToken;
      if (localToken !== 0) {
        const localTable = localToken >>> 24;
        const localRid = localToken & 0x00ffffff;
        if (localTable !== 0x11 || localRid === 0 || localRid > rows.length) {
          throw new FormatError(`MethodDef row ${method.rid} has an invalid local signature token`);
        }
        if (localRid === rid) {
          throw new FormatError(
            `StandAloneSig row ${rid} is referenced by MethodDef row ${method.rid} local signature`
          );
        }
        if (localRid > rid) {
          if (body.format !== "fat") {
            throw new FormatError("A tiny method body cannot contain a local signature token");
          }
          const replacement = 0x11000000 + localRid - 1;
          patches.push({
            offset: body.headerOffset + 8,
            bytes: Uint8Array.of(
              replacement & 0xff,
              (replacement >>> 8) & 0xff,
              (replacement >>> 16) & 0xff,
              (replacement >>> 24) & 0xff
            )
          });
          localSignatureUpdates.push({ body, replacement });
        }
      }

      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x11) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing StandAloneSig row ${targetRid}`);
        }
        if (targetRid === rid) {
          throw new FormatError(`StandAloneSig row ${rid} is referenced by CIL`);
        }
        if (targetRid > rid) {
          const replacement = 0x11000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x11000000 + oldRid, 0x11000000 + oldRid - 1);
    }

    let updatedEmbeddedPdb = null;
    let updatedCounts = null;
    if (embeddedPdbIndices.length === 1) {
      updatedCounts = [...this.tables.counts];
      updatedCounts[17]--;
      const debugEntryIndex = embeddedPdbIndices[0];
      const debugEntry = this.pe.debugDirectoryEntries[debugEntryIndex];
      updatedEmbeddedPdb = remapPortablePdbLocalSignatures(
        this.#getPortablePdbForEdit(debugEntryIndex, debugEntry),
        rid,
        this.tables.counts,
        updatedCounts,
        "remove"
      );
      this.#replaceEmbeddedPortablePdb(
        debugEntryIndex,
        updatedEmbeddedPdb,
        updatedCounts
      );
    }

    const remainingRows = rows.filter((row) => row.rid !== rid);
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    const remainingSignatures = this.standAloneSigs.filter((signature) => signature.rid !== rid);
    remainingSignatures.forEach((signature, index) => {
      signature.rid = index + 1;
    });
    this.tables.rows.set(17, remainingRows);
    this.tables.counts[17] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 17n);
    this.standAloneSigs = remainingSignatures;
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    for (const update of localSignatureUpdates) {
      update.body.localVarSigToken = update.replacement;
    }
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  insertMethodSpecSorted({ method, instantiation }) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("Sorted MethodSpec insertion cannot be combined with structural method edits");
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(`Cannot remap MethodSpec tokens with unrecognized metadata stream ${streamName}`);
      }
    }
    if (!method || !Number.isInteger(method.rid) || method.rid < 1) {
      throw new TypeError("MethodSpec method must identify an existing MethodDef or MemberRef");
    }
    const methodTable = metadataTableId(method.table);
    if ((methodTable !== 6 && methodTable !== 10) ||
        method.rid > (this.tables.counts[methodTable] ?? 0)) {
      throw new RangeError("MethodSpec references a missing or invalid method row");
    }
    if (!(instantiation instanceof Uint8Array)) {
      throw new TypeError("MethodSpec instantiation must be a Uint8Array");
    }
    const parsedInstantiation = parseSignature(instantiation, { counts: this.tables.counts });
    if (parsedInstantiation.kind !== "methodInstantiation") {
      throw new FormatError("MethodSpec requires a method-instantiation signature");
    }
    const methodSignatureBytes = methodTable === 6
      ? this.methods[method.rid - 1]?.signature
      : this.memberRefs.find((reference) => reference.rid === method.rid)?.signature;
    if (!methodSignatureBytes) throw new FormatError("MethodSpec target has no available signature");
    const methodSignature = parseSignature(methodSignatureBytes, { counts: this.tables.counts });
    if (methodSignature.kind !== "method" || !methodSignature.generic ||
        methodSignature.genericParameterCount !== parsedInstantiation.arguments.length) {
      throw new FormatError("MethodSpec instantiation does not match its generic method signature");
    }

    const methodValue = encodeCodedIndex(methodTable, method.rid, "MethodDefOrRef");
    const methodSpecRows = this.tables.rows.get(43) ?? [];
    if (methodSpecRows.length + 1 > 0x00ffffff) {
      throw new RangeError("MethodSpec token row ID exceeds 24-bit range");
    }
    const newRow = {
      table: 43,
      tableName: metadataTableNames[43],
      rid: 0,
      Method: {
        raw: methodValue,
        target: { table: methodTable, tableName: metadataTableNames[methodTable], rid: method.rid }
      },
      Instantiation: 0
    };
    const orderedRows = [
      ...methodSpecRows.map((row, index) => ({ row, oldRid: row.rid, order: index })),
      { row: newRow, oldRid: null, order: methodSpecRows.length }
    ].sort((left, right) => left.row.Method.raw - right.row.Method.raw || left.order - right.order);
    const remappedRids = new Map(orderedRows.flatMap((item, index) =>
      item.oldRid === null ? [] : [[item.oldRid, index + 1]]
    ));
    const remappedRid = (rid) => remappedRids.get(rid) ?? rid;
    const tokenMap = new Map([...remappedRids].flatMap(([oldRid, newRid]) =>
      oldRid === newRid ? [] : [[0x2b000000 + oldRid, 0x2b000000 + newRid]]
    ));
    if (tokenMap.size > 0) {
      this.#ensureAddedMethodBodiesSafe("MethodSpec remapping");
      this.#ensureTokenRemappingSafe("MethodSpec");
    }

    const rowChanges = [];
    for (const [tableId, rows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        if (kind !== "coded") continue;
        const columnName = name ?? value;
        for (const row of rows) {
          const target = row[columnName]?.target;
          if (target?.table !== 43 || remappedRid(target.rid) === target.rid) continue;
          const remappedTarget = { ...target, rid: remappedRid(target.rid) };
          rowChanges.push({
            row,
            columnName,
            value: {
              raw: encodeCodedIndex(43, remappedTarget.rid, value),
              target: remappedTarget
            }
          });
        }
      }
    }
    rowChanges.push(...collectEncTokenRemaps(this.tables, 43, remappedRid));
    const customAttributeChanges = new Map(
      rowChanges.filter((change) => change.row.table === 12)
        .map((change) => [change.row, change.value])
    );
    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      let previous = -1;
      for (const row of this.tables.get(12)) {
        const key = customAttributeChanges.get(row)?.raw ?? row.Parent.raw;
        if (key < previous) {
          throw new FormatError("MethodSpec token remapping would violate sorted CustomAttribute order");
        }
        previous = key;
      }
    }

    const tokenUpdates = [];
    const patches = [];
    for (const methodDef of this.methods) {
      const body = this.getMethodBody(methodDef.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x2b) continue;
        const oldRid = token & 0x00ffffff;
        if (oldRid === 0 || oldRid > methodSpecRows.length) {
          throw new FormatError(`CIL references missing MethodSpec row ${oldRid}`);
        }
        const newRid = remappedRid(oldRid);
        if (oldRid === newRid) continue;
        const replacement = 0x2b000000 + newRid;
        patches.push(...createOperandPatches(instruction, replacement));
        tokenUpdates.push({ instruction, replacement });
      }
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), instantiation);
    heapStreams.set("#Blob", blobHeap.heap);
    newRow.Instantiation = blobHeap.index;
    const previousMethodSpecs = new Map(this.methodSpecs.map((item) => [item.rid, item]));
    const newMethodSpec = {
      rid: 0,
      method: newRow.Method.target,
      instantiation: instantiation.slice(),
      parsedInstantiation
    };
    const orderedMethodSpecs = orderedRows.map((item) => {
      if (item.oldRid === null) return newMethodSpec;
      const itemSemantic = previousMethodSpecs.get(item.oldRid);
      if (!itemSemantic) throw new FormatError(`MethodSpec row ${item.oldRid} has no semantic record`);
      return itemSemantic;
    });
    orderedRows.forEach((item, index) => {
      item.row.rid = index + 1;
      orderedMethodSpecs[index].rid = index + 1;
    });
    newMethodSpec.rid = orderedRows.findIndex((item) => item.oldRid === null) + 1;

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    methodSpecRows.splice(0, methodSpecRows.length, ...orderedRows.map((item) => item.row));
    this.tables.rows.set(43, methodSpecRows);
    this.tables.valid |= 1n << 43n;
    this.tables.counts[43] = methodSpecRows.length;
    this.methodSpecs.splice(0, this.methodSpecs.length, ...orderedMethodSpecs);
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    this.heaps = new MetadataHeaps(new Map([...heapStreams].map(([streamName, bytes]) =>
      [streamName, { bytes }]
    )));
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._heapStreams = heapStreams;
    this.tables.sorted |= 1n << 43n;
    this._metadataDirty = true;
    return { token: 0x2b000000 + newMethodSpec.rid, tokenMap };
  }

  removeMethodSpec(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("MethodSpec removal cannot be combined with structural method edits");
    }
    this.#ensureAddedMethodBodiesSafe("MethodSpec removal");
    this.#ensureTokenRemappingSafe("MethodSpec");
    const rows = this.tables.rows.get(43) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid MethodSpec row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(`Cannot remap MethodSpec tokens with unrecognized metadata stream ${streamName}`);
      }
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        const columnName = name ?? value;
        if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId)) {
          for (const row of tableRows) {
            const token = row[columnName];
            if ((token >>> 24) !== 0x2b) continue;
            const targetRid = token & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(`MethodSpec row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (targetRid > rid) {
              rowChanges.push({
                row,
                columnName,
                value: 0x2b000000 + targetRid - 1
              });
            }
          }
          continue;
        }
        if (kind !== "coded") continue;
        for (const row of tableRows) {
          const target = row[columnName]?.target;
          if (target?.table !== 43) continue;
          if (target.rid === rid) {
            throw new FormatError(`MethodSpec row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: {
                raw: encodeCodedIndex(43, remappedTarget.rid, value),
                target: remappedTarget
              }
            });
          }
        }
      }
    }

    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      let previous = -1;
      for (const row of this.tables.get(12)) {
        const key = changesByRow.get(row)?.get("Parent") ?? row.Parent;
        if (key.raw < previous) {
          throw new FormatError("MethodSpec token remapping would violate sorted CustomAttribute order");
        }
        previous = key.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x2b) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing MethodSpec row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`MethodSpec row ${rid} is referenced by CIL`);
        if (targetRid > rid) {
          const replacement = 0x2b000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x2b000000 + oldRid, 0x2b000000 + oldRid - 1);
    }

    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingMethodSpecs = this.methodSpecs.filter((item) => item.rid !== rid);
    if (remainingRows.length !== remainingMethodSpecs.length || !this.methodSpecs[rid - 1] ||
        this.methodSpecs[rid - 1].rid !== rid) {
      throw new FormatError(`MethodSpec row ${rid} has no semantic record`);
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    remainingMethodSpecs.forEach((item, index) => {
      item.rid = index + 1;
    });
    this.tables.rows.set(43, remainingRows);
    this.tables.counts[43] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 43n);
    this.methodSpecs.splice(0, this.methodSpecs.length, ...remainingMethodSpecs);
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  addGenericParamConstraint({ ownerRid, constraint }) {
    return this.#writeGenericParamConstraint({ ownerRid, constraint }, false).rid;
  }

  insertGenericParamConstraint({ ownerRid, constraint }) {
    return this.#writeGenericParamConstraint({ ownerRid, constraint }, true);
  }

  #validateSortedRowRemapping(rowChanges, tableName) {
    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    const valueOf = (row, columnName) =>
      changesByRow.get(row)?.get(columnName) ?? row[columnName];
    const sortedKeys = new Map([
      [1, (row) => [valueOf(row, "ResolutionScope").raw]],
      [9, (row) => [valueOf(row, "Class").rid]],
      [10, (row) => [valueOf(row, "Class").raw]],
      [11, (row) => [valueOf(row, "Parent").raw]],
      [12, (row) => [valueOf(row, "Parent").raw]],
      [13, (row) => [valueOf(row, "Parent").raw]],
      [14, (row) => [valueOf(row, "Parent").raw]],
      [15, (row) => [valueOf(row, "Parent").rid]],
      [16, (row) => [valueOf(row, "Field").rid]],
      [18, (row) => [valueOf(row, "Parent").rid]],
      [21, (row) => [valueOf(row, "Parent").rid]],
      [24, (row) => [valueOf(row, "Association").raw]],
      [25, (row) => [valueOf(row, "Class").rid]],
      [28, (row) => [valueOf(row, "MemberForwarded").raw]],
      [29, (row) => [valueOf(row, "Field").rid]],
      [41, (row) => [valueOf(row, "NestedClass").rid]],
      [42, (row) => [valueOf(row, "Owner").raw, row.Number]],
      [43, (row) => [valueOf(row, "Method").raw]],
      [44, (row) => [valueOf(row, "Owner").rid]]
    ]);
    for (const [tableId, keyOf] of sortedKeys) {
      if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
      let previous = null;
      for (const row of this.tables.rows.get(tableId) ?? []) {
        const current = keyOf(row);
        let outOfOrder = false;
        if (previous) {
          for (let index = 0; index < current.length; index++) {
            if (current[index] === previous[index]) continue;
            outOfOrder = current[index] < previous[index];
            break;
          }
        }
        if (outOfOrder) {
          throw new FormatError(
            `${tableName} token remapping would violate sorted ${metadataTableNames[tableId]} order`
          );
        }
        previous = current;
      }
    }
  }

  #prepareTokenRowInsertion(
    tableId,
    insertionRid,
    rowCount,
    tableName,
    { allowEmbeddedPortablePdb = false } = {}
  ) {
    const tokenMap = new Map();
    const rowChanges = [];
    const tokenUpdates = [];
    const patches = [];
    if (insertionRid > rowCount) {
      return { tokenMap, rowChanges, tokenUpdates, patches };
    }
    if (this._structuralBodies.size > 0 || this._addedMethodBodies.size > 0) {
      throw new UnsupportedFormatError(
        `Sorted ${tableName} insertion cannot be combined with method-body edits`
      );
    }
    this.#ensureTokenRemappingSafe(tableName, { allowEmbeddedPortablePdb });
    for (let oldRid = insertionRid; oldRid <= rowCount; oldRid++) {
      tokenMap.set(
        (tableId << 24) + oldRid,
        (tableId << 24) + oldRid + 1
      );
    }
    for (const [sourceTableId, rows] of this.tables.rows) {
      const schema = metadataTableSchemas[sourceTableId];
      if (!schema) {
        throw new UnsupportedFormatError(
          `Cannot remap ${tableName} tokens through unknown table ${sourceTableId}`
        );
      }
      for (const row of rows) {
        for (const [kind, value, name, pointer] of schema) {
          const columnName = name ?? value;
          const column = row[columnName];
          if (kind === "coded" && column?.target?.table === tableId &&
              column.target.rid >= insertionRid) {
            const target = { ...column.target, rid: column.target.rid + 1 };
            rowChanges.push({
              row,
              columnName,
              value: {
                raw: encodeCodedIndex(tableId, target.rid, value),
                target
              }
            });
          } else if (kind === "table") {
            const targetTable = pointer !== undefined &&
              (this.tables.valid & (1n << BigInt(pointer))) !== 0n ? pointer : value;
            if (targetTable === tableId && column?.rid >= insertionRid) {
              rowChanges.push({
                row,
                columnName,
                value: {
                  ...column,
                  raw: column.rid + 1,
                  rid: column.rid + 1
                }
              });
            }
          } else if (kind === "u4" &&
              (sourceTableId === 30 || sourceTableId === 31) &&
              columnName === "Token" && row[columnName] >>> 24 === tableId) {
            const oldToken = row[columnName];
            const targetRid = oldToken & 0x00ffffff;
            if (targetRid >= insertionRid) {
              rowChanges.push({
                row,
                columnName,
                value: (tableId << 24) | (targetRid + 1)
              });
            }
          }
        }
      }
    }
    for (const method of this.methods) {
      for (const instruction of this.getMethodBody(method.rid)?.instructions ?? []) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== tableId || (token & 0x00ffffff) < insertionRid) continue;
        const replacement = token + 1;
        tokenUpdates.push({ instruction, replacement });
        patches.push(...createOperandPatches(instruction, replacement));
      }
    }
    this.#validateSortedRowRemapping(rowChanges, tableName);
    return { tokenMap, rowChanges, tokenUpdates, patches };
  }

  #prepareTokenRowRemoval(tableId, removedRid, rowCount, tableName) {
    if (this._structuralBodies.size > 0 || this._addedMethodBodies.size > 0) {
      throw new UnsupportedFormatError(
        `${tableName} removal cannot be combined with method-body edits`
      );
    }
    this.#ensureTokenRemappingSafe(tableName);
    const tokenMap = new Map();
    const rowChanges = [];
    const tokenUpdates = [];
    const patches = [];
    for (let oldRid = removedRid + 1; oldRid <= rowCount; oldRid++) {
      tokenMap.set((tableId << 24) + oldRid, (tableId << 24) + oldRid - 1);
    }
    for (const [sourceTableId, rows] of this.tables.rows) {
      const schema = metadataTableSchemas[sourceTableId];
      if (!schema) {
        throw new UnsupportedFormatError(
          `Cannot remap ${tableName} tokens through unknown table ${sourceTableId}`
        );
      }
      for (const row of rows) {
        for (const [kind, value, name, pointer] of schema) {
          const columnName = name ?? value;
          const column = row[columnName];
          if (kind === "coded" && column?.target?.table === tableId) {
            const targetRid = column.target.rid;
            if (targetRid === removedRid) {
              throw new FormatError(
                `${tableName} row ${removedRid} is referenced by ${metadataTableNames[sourceTableId]}.${columnName}`
              );
            }
            if (targetRid > removedRid) {
              const target = { ...column.target, rid: targetRid - 1 };
              rowChanges.push({
                row,
                columnName,
                value: { raw: encodeCodedIndex(tableId, target.rid, value), target }
              });
            }
          } else if (kind === "table") {
            const targetTable = pointer !== undefined &&
              (this.tables.valid & (1n << BigInt(pointer))) !== 0n ? pointer : value;
            if (targetTable !== tableId || !Number.isInteger(column?.rid)) continue;
            if (column.rid === removedRid) {
              throw new FormatError(
                `${tableName} row ${removedRid} is referenced by ${metadataTableNames[sourceTableId]}.${columnName}`
              );
            }
            if (column.rid > removedRid) {
              rowChanges.push({
                row,
                columnName,
                value: { ...column, raw: column.rid - 1, rid: column.rid - 1 }
              });
            }
          } else if (kind === "u4" &&
              (sourceTableId === 30 || sourceTableId === 31) &&
              columnName === "Token" && row[columnName] >>> 24 === tableId) {
            const token = row[columnName];
            const targetRid = token & 0x00ffffff;
            if (targetRid === removedRid) {
              throw new FormatError(
                `${tableName} row ${removedRid} is referenced by ${metadataTableNames[sourceTableId]}`
              );
            }
            if (targetRid > removedRid) {
              rowChanges.push({
                row,
                columnName,
                value: (tableId << 24) | (targetRid - 1)
              });
            }
          }
        }
      }
    }
    for (const method of this.methods) {
      for (const instruction of this.getMethodBody(method.rid)?.instructions ?? []) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== tableId) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === removedRid) {
          throw new FormatError(`${tableName} row ${removedRid} is referenced by CIL`);
        }
        if (targetRid > removedRid) {
          const replacement = token - 1;
          tokenUpdates.push({ instruction, replacement });
          patches.push(...createOperandPatches(instruction, replacement));
        }
      }
    }
    this.#validateSortedRowRemapping(rowChanges, tableName);
    return { tokenMap, rowChanges, tokenUpdates, patches };
  }

  #updateMetadataFlags(tableId, rid, { set = 0, clear = 0 } = {}) {
    const row = this.tables.row(tableId, rid);
    let record;
    if (tableId === 2) {
      record = this.types[rid - 1];
    } else if (tableId === 4) {
      record = this.types.flatMap((type) => type.fields)
        .find((field) => field.rid === rid);
    } else if (tableId === 6) {
      record = this.methods[rid - 1];
    } else if (tableId === 8) {
      record = this.methods.flatMap((method) => method.parameters)
        .find((parameter) => parameter.rid === rid);
    } else if (tableId === 23) {
      record = this.types.flatMap((type) => type.properties)
        .find((property) => property.rid === rid);
    }
    if (!row || !record) {
      throw new FormatError(
        `${metadataTableNames[tableId]} row ${rid} has no resolved semantic record`
      );
    }
    row.Flags = (row.Flags | set) & ~clear;
    record.flags = row.Flags;
  }

  #validateAssociatedFlags(tableId, rid, flags) {
    const relations = new Map([
      [2, [{ tableId: 14, column: "Parent", flag: 0x00040000, name: "HasSecurity", row: "DeclSecurity" }]],
      [4, [
        { tableId: 11, column: "Parent", flag: 0x8000, name: "HasDefault", row: "Constant" },
        { tableId: 13, column: "Parent", flag: 0x1000, name: "HasFieldMarshal", row: "FieldMarshal" },
        { tableId: 29, column: "Field", flag: 0x0100, name: "HasFieldRVA", row: "FieldRVA" },
        { tableId: 28, column: "MemberForwarded", flag: 0x2000, name: "PInvokeImpl", row: "ImplMap" }
      ]],
      [6, [
        { tableId: 14, column: "Parent", flag: 0x4000, name: "HasSecurity", row: "DeclSecurity" },
        { tableId: 28, column: "MemberForwarded", flag: 0x2000, name: "PInvokeImpl", row: "ImplMap" }
      ]],
      [8, [
        { tableId: 11, column: "Parent", flag: 0x1000, name: "HasDefault", row: "Constant" },
        { tableId: 13, column: "Parent", flag: 0x2000, name: "HasFieldMarshal", row: "FieldMarshal" }
      ]],
      [23, [{ tableId: 11, column: "Parent", flag: 0x1000, name: "HasDefault", row: "Constant" }]]
    ]);
    for (const relation of relations.get(tableId) ?? []) {
      if ((flags & relation.flag) !== 0) continue;
      const referenced = (this.tables.rows.get(relation.tableId) ?? []).some((candidate) => {
        const reference = candidate[relation.column];
        const target = relation.column === "Field"
          ? { table: 4, rid: reference?.rid }
          : reference?.target;
        return target?.table === tableId && target.rid === rid;
      });
      if (referenced) {
        throw new FormatError(
          `A ${metadataTableNames[tableId]} with a ${relation.row} row must retain the ${relation.name} flag`
        );
      }
    }
  }

  #removeTokenRow(tableId, rid, tableName) {
    const rows = this.tables.rows.get(tableId) ?? [];
    if (rows.length !== (this.tables.counts[tableId] ?? 0) ||
        !Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid ${tableName} row ID ${rid}`);
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowRemoval(tableId, rid, rows.length, tableName);
    const attributeRows = this.customAttributes.map((attribute) => {
      const row = this.tables.row(12, attribute.rid);
      if (!row) throw new FormatError(`CustomAttribute row ${attribute.rid} has no metadata row`);
      return { attribute, row };
    });
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.rows.set(tableId, rows);
    this.tables.counts[tableId] = rows.length;
    if (rows.length === 0) this.tables.valid &= ~(1n << BigInt(tableId));
    for (const { attribute, row } of attributeRows) {
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  #writeGenericParamConstraint({ ownerRid, constraint }, insertSorted) {
    this.#ensureEditable();
    if (!Number.isInteger(ownerRid) || ownerRid < 1 ||
        ownerRid > (this.tables.counts[42] ?? 0)) {
      throw new RangeError("GenericParamConstraint owner references a missing GenericParam row");
    }
    const ownerParameter = this.genericParams[ownerRid - 1];
    if (!ownerParameter || ownerParameter.rid !== ownerRid) {
      throw new FormatError(`GenericParam row ${ownerRid} has no semantic record`);
    }
    if (!constraint || !Number.isInteger(constraint.rid) || constraint.rid < 1) {
      throw new TypeError("GenericParamConstraint type must identify a TypeDef, TypeRef, or TypeSpec row");
    }
    const constraintTable = metadataTableId(constraint.table);
    if (![1, 2, 27].includes(constraintTable) ||
        constraint.rid > (this.tables.counts[constraintTable] ?? 0)) {
      throw new RangeError("GenericParamConstraint references a missing or invalid type row");
    }
    if (constraintTable === 27) {
      const typeSpec = this.typeSpecs[constraint.rid - 1];
      if (!typeSpec) {
        throw new FormatError(`GenericParamConstraint references missing TypeSpec row ${constraint.rid}`);
      }
      const parameter = this.genericParams[ownerRid - 1];
      const { typeArity, methodArity } = getGenericParameterOwnerContext(this, parameter);
      validateTypeSpecDefinitions(this, typeSpec.parsedSignature);
      validateTypeSpecGenericContext(
        this, constraint.rid, typeArity, methodArity
      );
    }
    const constraintValue = encodeCodedIndex(constraintTable, constraint.rid, "TypeDefOrRef");
    const constraintRows = this.tables.rows.get(44) ?? [];
    if (constraintRows.length !== (this.tables.counts[44] ?? 0) ||
        constraintRows.length !== this.genericParamConstraints.length) {
      throw new FormatError("GenericParamConstraint row count is inconsistent with the metadata table header");
    }
    let insertionIndex = constraintRows.length;
    if (insertSorted) {
      for (let index = 1; index < constraintRows.length; index++) {
        if (constraintRows[index - 1].Owner.rid > constraintRows[index].Owner.rid) {
          throw new UnsupportedFormatError(
            "Sorted GenericParamConstraint insertion requires rows already ordered by Owner"
          );
        }
      }
      const laterOwner = constraintRows.findIndex((row) => row.Owner.rid > ownerRid);
      if (laterOwner !== -1) insertionIndex = laterOwner;
    } else if (constraintRows.length > 0 &&
        constraintRows.at(-1).Owner.rid > ownerRid) {
      throw new FormatError("Appending this GenericParamConstraint would violate the table's sorted Owner order");
    }
    const rid = insertionIndex + 1;
    if (rid > 0x00ffffff) {
      throw new RangeError("GenericParamConstraint token row ID exceeds 24-bit range");
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(44, rid, constraintRows.length, "GenericParamConstraint");
    const target = {
      table: constraintTable,
      tableName: metadataTableNames[constraintTable],
      rid: constraint.rid
    };
    const newRow = {
      table: 44,
      tableName: metadataTableNames[44],
      rid,
      Owner: { rid: ownerRid },
      Constraint: { raw: constraintValue, target }
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of constraintRows) {
      if (row.rid >= rid) row.rid++;
    }
    constraintRows.splice(insertionIndex, 0, newRow);
    this.tables.rows.set(44, constraintRows);
    this.tables.valid |= 1n << 44n;
    this.tables.counts[44] = constraintRows.length;
    for (const parameterConstraint of this.genericParamConstraints) {
      if (parameterConstraint.rid >= rid) parameterConstraint.rid++;
    }
    const parameterConstraint = { rid, ownerRid, constraint: target };
    this.genericParamConstraints.splice(insertionIndex, 0, parameterConstraint);
    ownerParameter.constraints ??= [];
    ownerParameter.constraints.push(parameterConstraint);
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid, tokenMap };
  }

  replaceGenericParamConstraint(rid, { constraint } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(44, rid);
    const parameterConstraint = this.genericParamConstraints[rid - 1];
    if (!row || !parameterConstraint) {
      throw new RangeError(`Invalid GenericParamConstraint row ID ${rid}`);
    }
    if (!constraint || !Number.isInteger(constraint.rid) || constraint.rid < 1) {
      throw new TypeError("GenericParamConstraint type must identify a TypeDef, TypeRef, or TypeSpec row");
    }
    const constraintTable = metadataTableId(constraint.table);
    if (![1, 2, 27].includes(constraintTable) ||
        constraint.rid > (this.tables.counts[constraintTable] ?? 0)) {
      throw new RangeError("GenericParamConstraint references a missing or invalid type row");
    }
    if (constraintTable === 27) {
      const typeSpec = this.typeSpecs[constraint.rid - 1];
      if (!typeSpec) {
        throw new FormatError(`GenericParamConstraint references missing TypeSpec row ${constraint.rid}`);
      }
      const parameter = this.genericParams[parameterConstraint.ownerRid - 1];
      const { typeArity, methodArity } = getGenericParameterOwnerContext(this, parameter);
      validateTypeSpecDefinitions(this, typeSpec.parsedSignature);
      validateTypeSpecGenericContext(
        this, constraint.rid, typeArity, methodArity
      );
    }
    const target = {
      table: constraintTable,
      tableName: metadataTableNames[constraintTable],
      rid: constraint.rid
    };
    if (row.Constraint.target.table === target.table && row.Constraint.target.rid === target.rid) {
      return this;
    }
    row.Constraint = {
      raw: encodeCodedIndex(target.table, target.rid, "TypeDefOrRef"),
      target
    };
    parameterConstraint.constraint = target;
    this._metadataDirty = true;
    return this;
  }

  removeGenericParamConstraint(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError(
        "GenericParamConstraint removal cannot be combined with structural method edits"
      );
    }
    this.#ensureTokenRemappingSafe("GenericParamConstraint");
    const rows = this.tables.rows.get(44) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid GenericParamConstraint row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap GenericParamConstraint tokens with unrecognized metadata stream ${streamName}`
        );
      }
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        const columnName = name ?? value;
        if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId)) {
          for (const row of tableRows) {
            const token = row[columnName];
            if ((token >>> 24) !== 0x2c) continue;
            const targetRid = token & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(
                `GenericParamConstraint row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (targetRid > rid) {
              rowChanges.push({
                row,
                columnName,
                value: 0x2c000000 + targetRid - 1
              });
            }
          }
          continue;
        }
        if (kind !== "coded") continue;
        for (const row of tableRows) {
          const target = row[columnName]?.target;
          if (target?.table !== 44) continue;
          if (target.rid === rid) {
            throw new FormatError(
              `GenericParamConstraint row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
            );
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: {
                raw: encodeCodedIndex(44, remappedTarget.rid, value),
                target: remappedTarget
              }
            });
          }
        }
      }
    }

    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      let previous = -1;
      for (const row of this.tables.get(12)) {
        const key = changesByRow.get(row)?.get("Parent") ?? row.Parent;
        if (key.raw < previous) {
          throw new FormatError(
            "GenericParamConstraint token remapping would violate sorted CustomAttribute order"
          );
        }
        previous = key.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x2c) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing GenericParamConstraint row ${targetRid}`);
        }
        if (targetRid === rid) {
          throw new FormatError(`GenericParamConstraint row ${rid} is referenced by CIL`);
        }
        if (targetRid > rid) {
          const replacement = 0x2c000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x2c000000 + oldRid, 0x2c000000 + oldRid - 1);
    }

    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingConstraints = this.genericParamConstraints.filter((item) => item.rid !== rid);
    if (this.genericParamConstraints.length !== rows.length ||
        this.genericParamConstraints.some((item, index) => item.rid !== index + 1)) {
      throw new FormatError("GenericParamConstraint semantic rows do not match the metadata table");
    }
    const attributeUpdates = this.customAttributes.map((attribute) => {
      const row = this.tables.row(12, attribute.rid);
      if (!row) throw new FormatError(`CustomAttribute row ${attribute.rid} has no metadata row`);
      return {
        attribute,
        parent: changesByRow.get(row)?.get("Parent")?.target ?? row.Parent.target,
        constructor: row.Type.target
      };
    });
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    remainingConstraints.forEach((item, index) => {
      item.rid = index + 1;
    });
    this.tables.rows.set(44, remainingRows);
    this.tables.counts[44] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 44n);
    this.genericParamConstraints.splice(0, this.genericParamConstraints.length, ...remainingConstraints);
    for (const { attribute, parent, constructor } of attributeUpdates) {
      attribute.parent = parent;
      attribute.constructor = constructor;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  addGenericParam({ owner, name, number, flags = 0 }) {
    return this.#writeGenericParam({ owner, name, number, flags }, false).token;
  }

  insertGenericParam({ owner, name, number, flags = 0 }) {
    return this.#writeGenericParam({ owner, name, number, flags }, true);
  }

  #writeGenericParam({ owner, name, number, flags }, insertSorted) {
    this.#ensureEditable();
    if (!owner || !Number.isInteger(owner.rid) || owner.rid < 1) {
      throw new TypeError("GenericParam owner must identify a TypeDef or MethodDef row");
    }
    const ownerTable = metadataTableId(owner.table);
    if ((ownerTable !== 2 && ownerTable !== 6) ||
        owner.rid > (this.tables.counts[ownerTable] ?? 0)) {
      throw new RangeError("GenericParam owner references a missing TypeDef or MethodDef row");
    }
    if (typeof name !== "string" || name.includes("\0")) {
      throw new TypeError("GenericParam name must be a null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffff || (flags & ~0x1f) !== 0) {
      throw new RangeError("GenericParam flags contain reserved bits");
    }
    this.#validateGenericParamFlags(ownerTable, owner.rid, flags);

    const ownerValue = encodeCodedIndex(ownerTable, owner.rid, "TypeOrMethodDef");
    const genericParamRows = this.tables.rows.get(42) ?? [];
    const existing = this.genericParams.filter((parameter) =>
      parameter.owner.table === ownerTable && parameter.owner.rid === owner.rid
    );
    const nextNumber = existing.reduce((max, parameter) => Math.max(max, parameter.number), -1) + 1;
    const selectedNumber = number ?? nextNumber;
    if (!Number.isInteger(selectedNumber) || selectedNumber < 0 || selectedNumber > 0xffff) {
      throw new RangeError("GenericParam number must be an unsigned 16-bit integer");
    }
    if (selectedNumber !== nextNumber) {
      throw new FormatError(`GenericParam number must be appended contiguously at ${nextNumber}`);
    }
    if (ownerTable === 6) {
      const method = this.methods[owner.rid - 1];
      const signature = method ? parseSignature(method.signature, { counts: this.tables.counts }) : null;
      if (signature?.kind !== "method" || !signature.generic ||
          selectedNumber >= signature.genericParameterCount) {
        throw new FormatError("GenericParam number exceeds the generic arity declared by its method signature");
      }
    }
    if (existing.some((parameter) => parameter.number === selectedNumber)) {
      throw new FormatError(`GenericParam number ${selectedNumber} already exists for this owner`);
    }
    let insertionIndex = genericParamRows.length;
    if (insertSorted) {
      for (let index = 1; index < genericParamRows.length; index++) {
        const previous = genericParamRows[index - 1];
        const current = genericParamRows[index];
        if (previous.Owner.raw > current.Owner.raw ||
            (previous.Owner.raw === current.Owner.raw && previous.Number > current.Number)) {
          throw new UnsupportedFormatError(
            "Sorted GenericParam insertion requires rows already ordered by Owner/Number"
          );
        }
      }
      const laterParameter = genericParamRows.findIndex((row) =>
        row.Owner.raw > ownerValue ||
        (row.Owner.raw === ownerValue && row.Number > selectedNumber)
      );
      if (laterParameter !== -1) insertionIndex = laterParameter;
    } else {
      const ordered = genericParamRows.every((row, index) => {
        if (index === 0) return true;
        const previous = genericParamRows[index - 1];
        return previous.Owner.raw < row.Owner.raw ||
          (previous.Owner.raw === row.Owner.raw && previous.Number <= row.Number);
      });
      const last = genericParamRows.at(-1);
      if (!ordered || (last &&
          (last.Owner.raw > ownerValue ||
           (last.Owner.raw === ownerValue && last.Number > selectedNumber)))) {
        throw new FormatError("Appending this GenericParam would violate the table's sorted Owner/Number order");
      }
    }
    if (genericParamRows.length + 1 > 0x00ffffff) {
      throw new RangeError("GenericParam token row ID exceeds 24-bit range");
    }

    const rid = insertionIndex + 1;
    const { tokenMap, rowChanges, tokenUpdates, patches } = insertSorted
      ? this.#prepareTokenRowInsertion(42, rid, genericParamRows.length, "GenericParam")
      : { tokenMap: new Map(), rowChanges: [], tokenUpdates: [], patches: [] };
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    heapStreams.set("#Strings", stringHeap.heap);
    const candidate = {
      table: 42,
      tableName: metadataTableNames[42],
      rid,
      Number: selectedNumber,
      Flags: flags,
      Owner: {
        raw: ownerValue,
        target: { table: ownerTable, tableName: metadataTableNames[ownerTable], rid: owner.rid }
      },
      Name: stringHeap.index
    };
    const parameter = {
      rid,
      number: selectedNumber,
      flags,
      owner: { table: ownerTable, tableName: metadataTableNames[ownerTable], rid: owner.rid },
      name
    };
    const attributeRows = this.customAttributes.map((attribute) => {
      const row = this.tables.row(12, attribute.rid);
      if (!row) throw new FormatError(`CustomAttribute row ${attribute.rid} has no metadata row`);
      return { attribute, row };
    });
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const row of genericParamRows) {
      if (row.rid >= rid) row.rid++;
    }
    for (const item of this.genericParams) {
      if (item.rid >= rid) item.rid++;
    }
    for (const constraint of this.genericParamConstraints) {
      if (constraint.ownerRid >= rid) constraint.ownerRid++;
    }
    genericParamRows.splice(insertionIndex, 0, candidate);
    this.genericParams.splice(insertionIndex, 0, parameter);
    for (const { attribute, row } of attributeRows) {
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    this.tables.rows.set(42, genericParamRows);
    this.tables.valid |= 1n << 42n;
    this.tables.sorted |= 1n << 42n;
    this.tables.counts[42] = genericParamRows.length;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    if (ownerTable === 2) {
      const ownerParams = this.types[owner.rid - 1].genericParams;
      if (!ownerParams.includes(parameter)) ownerParams.push(parameter);
    } else {
      const ownerParams = this.methods[owner.rid - 1].genericParams;
      if (!ownerParams.includes(parameter)) ownerParams.push(parameter);
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { token: 0x2a000000 + rid, rid, tokenMap };
  }

  replaceGenericParam(rid, { name, flags } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(42, rid);
    const parameter = this.genericParams[rid - 1];
    if (!row || !parameter) throw new RangeError(`Invalid GenericParam row ID ${rid}`);
    const replacementName = name === undefined ? parameter.name : name;
    const replacementFlags = flags === undefined ? parameter.flags : flags;
    if (typeof replacementName !== "string" || replacementName.includes("\0")) {
      throw new TypeError("GenericParam name must be a null-free string");
    }
    if (!Number.isInteger(replacementFlags) || replacementFlags < 0 ||
        replacementFlags > 0xffff || (replacementFlags & ~0x1f) !== 0) {
      throw new RangeError("GenericParam flags contain reserved bits");
    }
    this.#validateGenericParamFlags(parameter.owner.table, parameter.owner.rid, replacementFlags);
    if (replacementName === parameter.name && replacementFlags === parameter.flags) return this;

    let heapStreams = this._heapStreams;
    let nameIndex = row.Name;
    if (replacementName !== parameter.name) {
      heapStreams = this._heapStreams
        ? new Map([...this._heapStreams].map(([streamName, bytes]) =>
          [streamName, bytes.slice()]
        ))
        : new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
          [streamName, stream.bytes.slice()]
        ));
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), replacementName);
      heapStreams.set("#Strings", stringHeap.heap);
      nameIndex = stringHeap.index;
    }

    row.Flags = replacementFlags;
    row.Name = nameIndex;
    parameter.flags = replacementFlags;
    parameter.name = replacementName;
    if (heapStreams !== this._heapStreams) {
      this._heapStreams = heapStreams;
      this.#refreshHeaps();
    }
    this._metadataDirty = true;
    return this;
  }

  removeGenericParam(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("GenericParam removal cannot be combined with structural method edits");
    }
    this.#ensureTokenRemappingSafe("GenericParam");
    const rows = this.tables.rows.get(42) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid GenericParam row ID ${rid}`);
    }
    const parameter = this.genericParams[rid - 1];
    if (!parameter || parameter.rid !== rid) {
      throw new FormatError(`GenericParam row ${rid} has no semantic record`);
    }
    if (parameter.owner.table !== 6) {
      throw new UnsupportedFormatError("Only method-owned trailing GenericParam rows can be removed safely");
    }
    const method = this.methods[parameter.owner.rid - 1];
    if (!method) throw new FormatError(`GenericParam row ${rid} references a missing MethodDef`);
    const methodSignature = parseSignature(method.signature, { counts: this.tables.counts });
    if (methodSignature.kind !== "method" || !methodSignature.generic ||
        parameter.number !== methodSignature.genericParameterCount - 1) {
      throw new UnsupportedFormatError("Only the trailing method generic parameter can be removed");
    }
    if (this.genericParamConstraints.some((constraint) => constraint.ownerRid === rid)) {
      throw new FormatError(`GenericParam row ${rid} has live GenericParamConstraint rows`);
    }
    if (this.methodSpecs.some((spec) =>
      spec.method.table === 6 && spec.method.rid === parameter.owner.rid
    )) {
      throw new FormatError(`MethodDef row ${parameter.owner.rid} has live MethodSpec instantiations`);
    }
    const declaringType = this.types.find((type) => type.methodRids.includes(method.rid));
    const replacementSignature = {
      ...methodSignature,
      generic: methodSignature.genericParameterCount > 1,
      genericParameterCount: methodSignature.genericParameterCount - 1
    };
    validateGenericVariableReferences(
      replacementSignature,
      declaringType
        ? getGenericParameterArity(this.genericParams, 2, declaringType.rid)
        : 0,
      this
    );
    const signatureBlob = encodeSignature(replacementSignature);

    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap GenericParam tokens with unrecognized metadata stream ${streamName}`
        );
      }
    }
    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, name] of metadataTableSchemas[tableId]) {
        const columnName = name ?? value;
        if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId)) {
          for (const row of tableRows) {
            const token = row[columnName];
            if ((token >>> 24) !== 0x2a) continue;
            const targetRid = token & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(
                `GenericParam row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
              );
            }
            if (targetRid > rid) {
              rowChanges.push({ row, columnName, value: 0x2a000000 + targetRid - 1 });
            }
          }
          continue;
        }
        for (const row of tableRows) {
          const column = row[columnName];
          const target = kind === "coded"
            ? column?.target
            : kind === "table" ? { table: value, rid: column?.rid } : null;
          if (target?.table !== 42) continue;
          if (target.rid === rid) {
            throw new FormatError(
              `GenericParam row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
            );
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: kind === "coded"
                ? { raw: encodeCodedIndex(42, remappedTarget.rid, value), target: remappedTarget }
                : { ...column, rid: remappedTarget.rid, raw: remappedTarget.rid }
            });
          }
        }
      }
    }
    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      let previous = -1;
      for (const row of this.tables.get(12)) {
        const parent = changesByRow.get(row)?.get("Parent") ?? row.Parent;
        if (parent.raw < previous) {
          throw new FormatError("GenericParam token remapping would violate sorted CustomAttribute order");
        }
        previous = parent.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const methodDef of this.methods) {
      const body = this.getMethodBody(methodDef.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x2a) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing GenericParam row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`GenericParam row ${rid} is referenced by CIL`);
        if (targetRid > rid) {
          const replacement = 0x2a000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x2a000000 + oldRid, 0x2a000000 + oldRid - 1);
    }
    const remainingRows = rows.filter((row) => row.rid !== rid);
    const remainingParams = this.genericParams.filter((item) => item.rid !== rid);
    if (remainingRows.length !== remainingParams.length ||
        rows.some((row, index) => row.rid !== index + 1) ||
        this.genericParams.some((item, index) => item.rid !== index + 1) ||
        this.genericParamConstraints.some((constraint, index) => {
          const row = this.tables.row(44, constraint.rid);
          return constraint.rid !== index + 1 || !row ||
            constraint.ownerRid !== row.Owner.rid ||
            !this.genericParams[constraint.ownerRid - 1];
        })) {
      throw new FormatError("GenericParam semantic rows do not match the metadata table");
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), signatureBlob);
    heapStreams.set("#Blob", blob.heap);
    const methodRow = this.tables.row(6, method.rid);
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
      remainingParams[index].rid = index + 1;
    });
    this.tables.rows.set(42, remainingRows);
    this.tables.counts[42] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << 42n);
    this.genericParams.splice(0, this.genericParams.length, ...remainingParams);
    methodRow.Signature = blob.index;
    method.signature = signatureBlob;
    for (const constraint of this.genericParamConstraints) {
      constraint.ownerRid = this.tables.row(44, constraint.rid).Owner.rid;
    }
    for (const type of this.types) {
      type.genericParams = this.genericParams.filter((item) =>
        item.owner.table === 2 && item.owner.rid === type.rid
      );
    }
    for (const methodDef of this.methods) {
      methodDef.genericParams = this.genericParams.filter((item) =>
        item.owner.table === 6 && item.owner.rid === methodDef.rid
      );
    }
    for (const item of this.genericParams) item.constraints = [];
    for (const constraint of this.genericParamConstraints) {
      const owner = this.genericParams[constraint.ownerRid - 1];
      if (!owner) throw new FormatError(`GenericParamConstraint row ${constraint.rid} has a missing owner`);
      owner.constraints.push(constraint);
    }
    for (const attribute of this.customAttributes) {
      const row = this.tables.row(12, attribute.rid);
      attribute.parent = row.Parent.target;
      attribute.constructor = row.Type.target;
    }
    this.heaps = new MetadataHeaps(new Map([...heapStreams].map(([streamName, bytes]) =>
      [streamName, { bytes }]
    )));
    this._patches.push(...patches);
    this._heapStreams = heapStreams;
    this._metadataDirty = true;
    return tokenMap;
  }

  addFile({ name, flags = 0, hashValue = new Uint8Array() }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("File name must be a non-empty null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 1) {
      throw new RangeError("File flags may only specify ContainsNoMetaData");
    }
    if (!(hashValue instanceof Uint8Array)) {
      throw new TypeError("File hash value must be a Uint8Array");
    }
    const rows = this.tables.rows.get(38) ?? [];
    if (rows.length >= 0x00ffffff) throw new RangeError("File token row ID exceeds 24-bit range");
    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const stringHeap = appendStringHeap(this._heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const blobHeap = appendBlobHeap(this._heapStreams.get("#Blob") ?? new Uint8Array(), hashValue);
    this._heapStreams.set("#Strings", stringHeap.heap);
    this._heapStreams.set("#Blob", blobHeap.heap);
    this.#refreshHeaps();
    const rid = rows.length + 1;
    rows.push({
      table: 38,
      tableName: metadataTableNames[38],
      rid,
      Flags: flags,
      Name: stringHeap.index,
      HashValue: blobHeap.index
    });
    this.tables.rows.set(38, rows);
    this.tables.valid |= 1n << 38n;
    this.tables.counts[38] = rid;
    this.files.push({ rid, flags, name, hashValue: hashValue.slice() });
    this._metadataDirty = true;
    return 0x26000000 + rid;
  }

  insertFile({ beforeRid, name, flags = 0, hashValue = new Uint8Array() }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("File name must be a non-empty null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 1) {
      throw new RangeError("File flags may only specify ContainsNoMetaData");
    }
    if (!(hashValue instanceof Uint8Array)) {
      throw new TypeError("File hash value must be a Uint8Array");
    }
    const rows = this.tables.rows.get(38) ?? [];
    if (rows.length !== (this.tables.counts[38] ?? 0) || rows.length !== this.files.length) {
      throw new FormatError("File row count is inconsistent with parsed File records");
    }
    if (!Number.isInteger(beforeRid) || beforeRid < 1 || beforeRid > rows.length + 1) {
      throw new RangeError(`Invalid File insertion position ${beforeRid}`);
    }
    if (rows.length >= 0x00ffffff) throw new RangeError("File token row ID exceeds 24-bit range");

    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(38, beforeRid, rows.length, "File");
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), hashValue);
    heapStreams.set("#Strings", stringHeap.heap);
    heapStreams.set("#Blob", blobHeap.heap);
    const rid = beforeRid;
    const row = {
      table: 38,
      tableName: metadataTableNames[38],
      rid,
      Flags: flags,
      Name: stringHeap.index,
      HashValue: blobHeap.index
    };

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    rows.splice(rid - 1, 0, row);
    rows.forEach((fileRow, index) => {
      fileRow.rid = index + 1;
    });
    this.tables.rows.set(38, rows);
    this.tables.valid |= 1n << 38n;
    this.tables.counts[38] = rows.length;

    const file = { rid, flags, name, hashValue: hashValue.slice() };
    this.files.splice(rid - 1, 0, file);
    this.files.forEach((record, index) => {
      record.rid = index + 1;
    });
    for (const exportedType of this.exportedTypes) {
      if (exportedType.implementation?.table === 38 && exportedType.implementation.rid >= rid) {
        exportedType.implementation.rid++;
      }
    }
    for (const resource of this.resources) {
      if (resource.implementation?.table === 38 && resource.implementation.rid >= rid) {
        resource.implementation.rid++;
      }
    }
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    patches.forEach((patch) => this._patches.push(patch));
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return { token: 0x26000000 + rid, tokenMap };
  }

  addExportedType({ name, namespace = "", flags = 0, typeDefId = 0, implementation }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("ExportedType name must be a non-empty null-free string");
    }
    if (typeof namespace !== "string" || namespace.includes("\0")) {
      throw new TypeError("ExportedType namespace must be a null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffffffff) {
      throw new RangeError("ExportedType flags must be an unsigned 32-bit integer");
    }
    if (!Number.isInteger(typeDefId) || typeDefId < 0 || typeDefId > 0xffffffff) {
      throw new RangeError("ExportedType TypeDefId must be an unsigned 32-bit integer");
    }
    const implementationTable = metadataTableId(implementation?.table);
    if (![35, 38, 39].includes(implementationTable) ||
        !Number.isInteger(implementation.rid) || implementation.rid < 1 ||
        implementation.rid > (this.tables.counts[implementationTable] ?? 0)) {
      throw new RangeError("ExportedType implementation must identify an existing File, AssemblyRef, or ExportedType row");
    }
    const rows = this.tables.rows.get(39) ?? [];
    if (rows.length !== (this.tables.counts[39] ?? 0) || rows.length >= 0x00ffffff) {
      throw new RangeError("ExportedType row count is inconsistent or exceeds the metadata token range");
    }
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const nameHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const namespaceHeap = appendStringHeap(nameHeap.heap, namespace);
    heapStreams.set("#Strings", namespaceHeap.heap);
    const rid = rows.length + 1;
    const implementationTarget = {
      table: implementationTable,
      tableName: metadataTableNames[implementationTable],
      rid: implementation.rid
    };
    rows.push({
      table: 39,
      tableName: metadataTableNames[39],
      rid,
      Flags: flags,
      TypeDefId: typeDefId,
      TypeName: nameHeap.index,
      TypeNamespace: namespaceHeap.index,
      Implementation: {
        raw: encodeCodedIndex(implementationTable, implementation.rid, "Implementation"),
        target: implementationTarget
      }
    });
    this.tables.rows.set(39, rows);
    this.tables.counts[39] = rid;
    this.tables.valid |= 1n << 39n;
    this.exportedTypes.push({
      rid, flags, typeDefId, name, namespace, implementation: implementationTarget
    });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return 0x27000000 + rid;
  }

  insertExportedType({ beforeRid, name, namespace = "", flags = 0, typeDefId = 0, implementation }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("ExportedType name must be a non-empty null-free string");
    }
    if (typeof namespace !== "string" || namespace.includes("\0")) {
      throw new TypeError("ExportedType namespace must be a null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffffffff) {
      throw new TypeError("ExportedType flags must be an unsigned 32-bit integer");
    }
    if (!Number.isInteger(typeDefId) || typeDefId < 0 || typeDefId > 0xffffffff) {
      throw new TypeError("ExportedType TypeDefId must be an unsigned 32-bit integer");
    }
    const implementationTable = metadataTableId(implementation?.table);
    if (![35, 38, 39].includes(implementationTable) ||
        !Number.isInteger(implementation.rid) || implementation.rid < 1 ||
        implementation.rid > (this.tables.counts[implementationTable] ?? 0)) {
      throw new RangeError("ExportedType implementation must identify an existing File, AssemblyRef, or ExportedType row");
    }
    const rows = this.tables.rows.get(39) ?? [];
    if (rows.length !== (this.tables.counts[39] ?? 0) || rows.length !== this.exportedTypes.length) {
      throw new FormatError("ExportedType row count is inconsistent with parsed ExportedType records");
    }
    if (!Number.isInteger(beforeRid) || beforeRid < 1 || beforeRid > rows.length + 1) {
      throw new RangeError(`Invalid ExportedType insertion position ${beforeRid}`);
    }
    if (rows.length >= 0x00ffffff) {
      throw new RangeError("ExportedType token row ID exceeds 24-bit range");
    }

    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(39, beforeRid, rows.length, "ExportedType");
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const nameHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    const namespaceHeap = appendStringHeap(nameHeap.heap, namespace);
    heapStreams.set("#Strings", namespaceHeap.heap);
    const implementationRid = implementationTable === 39 && implementation.rid >= beforeRid
      ? implementation.rid + 1
      : implementation.rid;
    const implementationTarget = {
      table: implementationTable,
      tableName: metadataTableNames[implementationTable],
      rid: implementationRid
    };
    const rid = beforeRid;
    const row = {
      table: 39,
      tableName: metadataTableNames[39],
      rid,
      Flags: flags,
      TypeDefId: typeDefId,
      TypeName: nameHeap.index,
      TypeNamespace: namespaceHeap.index,
      Implementation: {
        raw: encodeCodedIndex(implementationTable, implementationRid, "Implementation"),
        target: implementationTarget
      }
    };

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    rows.splice(rid - 1, 0, row);
    rows.forEach((exportedTypeRow, index) => {
      exportedTypeRow.rid = index + 1;
    });
    this.tables.rows.set(39, rows);
    this.tables.valid |= 1n << 39n;
    this.tables.counts[39] = rows.length;

    this.exportedTypes.splice(rid - 1, 0, {
      rid,
      flags,
      typeDefId,
      name,
      namespace,
      implementation: implementationTarget
    });
    this.exportedTypes.forEach((exportedType, index) => {
      exportedType.rid = index + 1;
      exportedType.implementation = rows[index].Implementation.target;
    });
    for (const resource of this.resources) {
      if (resource.implementation?.table === 39 && resource.implementation.rid >= rid) {
        resource.implementation.rid++;
      }
    }
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    patches.forEach((patch) => this._patches.push(patch));
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return { token: 0x27000000 + rid, tokenMap };
  }

  replaceExportedType(rid, { name, namespace, flags, typeDefId, implementation } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(39, rid);
    const exportedType = this.exportedTypes[rid - 1];
    if (!Number.isInteger(rid) || rid < 1 || !row || !exportedType) {
      throw new RangeError(`Invalid ExportedType row ID ${rid}`);
    }
    const nextName = name ?? exportedType.name;
    const nextNamespace = namespace ?? exportedType.namespace;
    const nextFlags = flags ?? exportedType.flags;
    const nextTypeDefId = typeDefId ?? exportedType.typeDefId;
    const nextImplementation = implementation ?? exportedType.implementation;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("ExportedType name must be a non-empty null-free string");
    }
    if (typeof nextNamespace !== "string" || nextNamespace.includes("\0")) {
      throw new TypeError("ExportedType namespace must be a null-free string");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 0xffffffff) {
      throw new RangeError("ExportedType flags must be an unsigned 32-bit integer");
    }
    if (!Number.isInteger(nextTypeDefId) || nextTypeDefId < 0 || nextTypeDefId > 0xffffffff) {
      throw new RangeError("ExportedType TypeDefId must be an unsigned 32-bit integer");
    }
    const implementationTable = metadataTableId(nextImplementation?.table);
    if (![35, 38, 39].includes(implementationTable) ||
        !Number.isInteger(nextImplementation.rid) || nextImplementation.rid < 1 ||
        nextImplementation.rid > (this.tables.counts[implementationTable] ?? 0)) {
      throw new RangeError("ExportedType implementation must identify an existing File, AssemblyRef, or ExportedType row");
    }
    if (implementationTable === 39) {
      const visited = new Set();
      let currentRid = nextImplementation.rid;
      while (currentRid > 0 && !visited.has(currentRid)) {
        if (currentRid === rid) throw new FormatError("ExportedType implementation cannot create a cycle");
        visited.add(currentRid);
        const target = this.tables.row(39, currentRid)?.Implementation.target;
        if (target?.table !== 39) break;
        currentRid = target.rid;
      }
      if (visited.has(currentRid) && this.tables.row(39, currentRid)?.Implementation.target?.table === 39) {
        throw new FormatError("ExportedType implementation chain contains a cycle");
      }
    }
    const implementationUnchanged =
      exportedType.implementation.table === implementationTable &&
      exportedType.implementation.rid === nextImplementation.rid;
    if (nextName === exportedType.name && nextNamespace === exportedType.namespace &&
        nextFlags === exportedType.flags && nextTypeDefId === exportedType.typeDefId &&
        implementationUnchanged) return this;

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== exportedType.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.TypeName = stringHeap.index;
    }
    if (nextNamespace !== exportedType.namespace) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextNamespace);
      heapStreams.set("#Strings", stringHeap.heap);
      row.TypeNamespace = stringHeap.index;
    }
    const implementationTarget = {
      table: implementationTable,
      tableName: metadataTableNames[implementationTable],
      rid: nextImplementation.rid
    };
    row.Flags = nextFlags;
    row.TypeDefId = nextTypeDefId;
    row.Implementation = {
      raw: encodeCodedIndex(implementationTable, nextImplementation.rid, "Implementation"),
      target: implementationTarget
    };
    Object.assign(exportedType, {
      name: nextName,
      namespace: nextNamespace,
      flags: nextFlags,
      typeDefId: nextTypeDefId,
      implementation: implementationTarget
    });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeExportedType(rid) {
    this.#ensureEditable();
    const rows = this.tables.rows.get(39) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid || !this.exportedTypes[rid - 1]) {
      throw new RangeError(`Invalid ExportedType row ID ${rid}`);
    }
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("ExportedType removal cannot be combined with structural method edits");
    }
    this.#ensureTokenRemappingSafe("ExportedType");
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remove ExportedType rows with unrecognized metadata stream ${streamName}`
        );
      }
    }
    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      for (const [kind, value, columnName] of metadataTableSchemas[tableId]) {
        const name = columnName ?? value;
        for (const other of tableRows) {
          const column = other[name];
          if (kind === "u4" && [30, 31].includes(tableId)) {
            const token = column ?? 0;
            if ((token >>> 24) === 0x27) {
              const targetRid = token & 0x00ffffff;
              if (targetRid === rid) {
                throw new FormatError(
                  `ExportedType row ${rid} is referenced by ${metadataTableNames[tableId]}.${name}`
                );
              }
              if (targetRid > rid) {
                rowChanges.push({ row: other, columnName: name, value: token - 1 });
              }
            }
            continue;
          }
          const target = kind === "coded"
            ? column?.target
            : kind === "table" ? { table: value, rid: column?.rid } : null;
          if (target?.table === 39) {
            if (target.rid === rid) {
              throw new FormatError(
                `ExportedType row ${rid} is referenced by ${metadataTableNames[tableId]}.${name}`
              );
            }
            if (target.rid > rid) {
              const remappedTarget = { ...target, rid: target.rid - 1 };
              rowChanges.push({
                row: other,
                columnName: name,
                value: kind === "coded"
                  ? {
                    raw: encodeCodedIndex(39, remappedTarget.rid, value),
                    target: remappedTarget
                  }
                  : { ...column, raw: remappedTarget.rid, rid: remappedTarget.rid }
              });
            }
          }
        }
      }
    }
    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      let previous = -1;
      for (const row of this.tables.get(12)) {
        const parent = changesByRow.get(row)?.get("Parent") ?? row.Parent;
        if (parent.raw < previous) {
          throw new FormatError("ExportedType token remapping would violate sorted CustomAttribute order");
        }
        previous = parent.raw;
      }
    }
    const tokenMap = new Map();
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x27000000 + oldRid, 0x27000000 + oldRid - 1);
    }
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    rows.splice(rid - 1, 1);
    this.exportedTypes.splice(rid - 1, 1);
    rows.forEach((row, index) => {
      row.rid = index + 1;
      this.exportedTypes[index].rid = index + 1;
    });
    for (const exportedType of this.exportedTypes) {
      exportedType.implementation = rows[exportedType.rid - 1].Implementation.target;
    }
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    this.tables.rows.set(39, rows);
    this.tables.counts[39] = rows.length;
    if (rows.length === 0) this.tables.valid &= ~(1n << 39n);
    this._metadataDirty = true;
    return tokenMap.size > 0 ? tokenMap : this;
  }

  replaceFile(rid, { name, flags, hashValue } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(38, rid);
    const file = this.files[rid - 1];
    if (!row || !file) throw new RangeError(`Invalid File row ID ${rid}`);
    const nextName = name === undefined ? file.name : name;
    const nextFlags = flags === undefined ? file.flags : flags;
    const nextHash = hashValue === undefined ? file.hashValue : hashValue;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("File name must be a non-empty null-free string");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 1) {
      throw new RangeError("File flags may only specify ContainsNoMetaData");
    }
    if (!(nextHash instanceof Uint8Array)) {
      throw new TypeError("File hash value must be a Uint8Array");
    }
    const currentHash = this.heaps.getBlob(row.HashValue);
    const hashChanged = nextHash.length !== currentHash.length ||
      !nextHash.every((byte, index) => byte === currentHash[index]);
    if (nextName === file.name && nextFlags === file.flags && !hashChanged) return this;

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    if (nextName !== file.name) {
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.Name = stringHeap.index;
    }
    if (hashChanged) {
      const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), nextHash);
      heapStreams.set("#Blob", blobHeap.heap);
      row.HashValue = blobHeap.index;
    }
    row.Flags = nextFlags;
    file.name = nextName;
    file.flags = nextFlags;
    file.hashValue = nextHash.slice();
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
  }

  removeFile(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("File removal cannot be combined with structural method edits");
    }
    this.#ensureTokenRemappingSafe("File");
    const rows = this.tables.rows.get(38) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid File row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(`Cannot remap File tokens with unrecognized metadata stream ${streamName}`);
      }
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      for (const row of tableRows) {
        for (const [kind, value, name] of schema) {
          const columnName = name ?? value;
          const column = row[columnName];
          if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId) &&
              (column >>> 24) === 0x26) {
            const targetRid = column & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(`File row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (targetRid > rid) {
              rowChanges.push({
                row,
                columnName,
                value: 0x26000000 + targetRid - 1
              });
            }
            continue;
          }
          const target = kind === "coded" ? column?.target : kind === "table" ? column : null;
          if (target?.table !== 38) continue;
          if (target.rid === rid) {
            throw new FormatError(`File row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: kind === "coded"
                ? { raw: encodeCodedIndex(38, remappedTarget.rid, value), target: remappedTarget }
                : { ...column, rid: remappedTarget.rid, raw: remappedTarget.rid }
            });
          }
        }
      }
    }

    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      let previous = -1;
      for (const row of this.tables.get(12)) {
        const parent = changesByRow.get(row)?.get("Parent") ?? row.Parent;
        if (parent.raw < previous) {
          throw new FormatError("File token remapping would violate sorted CustomAttribute order");
        }
        previous = parent.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x26) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing File row ${targetRid}`);
        }
        if (targetRid === rid) throw new FormatError(`File row ${rid} is referenced by CIL`);
        if (targetRid > rid) {
          const replacement = 0x26000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x26000000 + oldRid, 0x26000000 + oldRid - 1);
    }

    const remainingFiles = this.files.filter((file) => file.rid !== rid);
    const newRows = rows.filter((row) => row.rid !== rid);
    if (remainingFiles.length !== newRows.length || !this.files[rid - 1] ||
        this.files[rid - 1].rid !== rid) {
      throw new FormatError(`File row ${rid} has no semantic record`);
    }

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingFiles.forEach((file, index) => {
      file.rid = index + 1;
    });
    newRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.files.splice(0, this.files.length, ...remainingFiles);
    this.tables.rows.set(38, newRows);
    this.tables.counts[38] = newRows.length;
    if (newRows.length === 0) this.tables.valid &= ~(1n << 38n);
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  addUserString(value) {
    this.#ensureEditable();
    if (typeof value !== "string") throw new TypeError("User strings must be strings");
    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const existingHeap = this._heapStreams.get("#US") ?? new Uint8Array();
    const source = existingHeap.subarray(0, this.heaps.userStringDataEnd);
    const userStringHeap = appendUserStringHeap(source, value);
    this._heapStreams.set("#US", userStringHeap.heap);
    this.#refreshHeaps();
    this._metadataDirty = true;
    return 0x70000000 + userStringHeap.index;
  }

  addManifestResource({ name, flags = 0, implementation = null, data = null }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("Manifest resource name must be a non-empty null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffffffff) {
      throw new RangeError("Manifest resource flags must be an unsigned 32-bit integer");
    }
    if (implementation === null) {
      if (!(data instanceof Uint8Array)) {
        throw new TypeError("Embedded manifest resources require a Uint8Array payload");
      }
    } else {
      if (data !== null) {
        throw new TypeError("Linked manifest resources cannot include an embedded payload");
      }
      const table = metadataTableId(implementation.table);
      if (![35, 38, 39].includes(table) || !Number.isInteger(implementation.rid) ||
          implementation.rid < 1 || implementation.rid > (this.tables.counts[table] ?? 0)) {
        throw new RangeError("Manifest resource implementation must identify an existing File, AssemblyRef, or ExportedType row");
      }
      implementation = {
        table,
        tableName: metadataTableNames[table],
        rid: implementation.rid
      };
    }
    if (data && data.length > 0xffffffff) {
      throw new RangeError("Manifest resource exceeds the CLI size limit");
    }

    const rows = this.tables.rows.get(40) ?? [];
    if (rows.length >= 0xffffffff) throw new RangeError("ManifestResource table row limit reached");
    const implementationRaw = implementation
      ? encodeCodedIndex(implementation.table, implementation.rid, "Implementation")
      : 0;
    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const stringHeap = appendStringHeap(this._heapStreams.get("#Strings") ?? new Uint8Array(), name);
    this._heapStreams.set("#Strings", stringHeap.heap);
    this.#refreshHeaps();

    const rid = rows.length + 1;
    rows.push({
      table: 40,
      tableName: metadataTableNames[40],
      rid,
      Offset: 0,
      Flags: flags,
      Name: stringHeap.index,
      Implementation: { raw: implementationRaw, target: implementation }
    });
    this.tables.rows.set(40, rows);
    this.tables.valid |= 1n << 40n;
    this.tables.counts[40] = rid;
    const resource = {
      rid,
      name,
      flags,
      implementation,
      data: implementation === null ? data.slice() : null
    };
    this.resources.push(resource);
    if (implementation === null) {
      this._resourceEdits.set(rid, data.slice());
      this._clearResourcesDirectory = false;
    }
    this._metadataDirty = true;
    return 0x28000000 + rid;
  }

  insertManifestResource({
    beforeRid,
    name,
    flags = 0,
    implementation = null,
    data = null
  }) {
    this.#ensureEditable();
    if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
      throw new TypeError("Manifest resource name must be a non-empty null-free string");
    }
    if (!Number.isInteger(flags) || flags < 0 || flags > 0xffffffff) {
      throw new TypeError("Manifest resource flags must be an unsigned 32-bit integer");
    }
    if (implementation === null) {
      if (!(data instanceof Uint8Array)) {
        throw new TypeError("Embedded manifest resources require a Uint8Array payload");
      }
    } else {
      if (data !== null) {
        throw new TypeError("Linked manifest resources cannot include an embedded payload");
      }
      const table = metadataTableId(implementation.table);
      if (![35, 38, 39].includes(table) || !Number.isInteger(implementation.rid) ||
          implementation.rid < 1 || implementation.rid > (this.tables.counts[table] ?? 0)) {
        throw new RangeError("Manifest resource implementation must identify an existing File, AssemblyRef, or ExportedType row");
      }
      implementation = {
        table,
        tableName: metadataTableNames[table],
        rid: implementation.rid
      };
    }
    if (data && data.length > 0xffffffff) {
      throw new RangeError("Manifest resource exceeds the CLI size limit");
    }

    const rows = this.tables.rows.get(40) ?? [];
    if (rows.length !== (this.tables.counts[40] ?? 0) || rows.length !== this.resources.length) {
      throw new FormatError("ManifestResource row count is inconsistent with parsed resource records");
    }
    if (!Number.isInteger(beforeRid) || beforeRid < 1 || beforeRid > rows.length + 1) {
      throw new RangeError(`Invalid ManifestResource insertion position ${beforeRid}`);
    }
    if (rows.length >= 0x00ffffff) {
      throw new RangeError("ManifestResource token row ID exceeds 24-bit range");
    }

    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(40, beforeRid, rows.length, "ManifestResource");
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    heapStreams.set("#Strings", stringHeap.heap);
    const implementationRaw = implementation
      ? encodeCodedIndex(implementation.table, implementation.rid, "Implementation")
      : 0;
    const rid = beforeRid;
    const row = {
      table: 40,
      tableName: metadataTableNames[40],
      rid,
      Offset: 0,
      Flags: flags,
      Name: stringHeap.index,
      Implementation: { raw: implementationRaw, target: implementation }
    };

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    rows.splice(rid - 1, 0, row);
    rows.forEach((resourceRow, index) => {
      resourceRow.rid = index + 1;
    });
    this.tables.rows.set(40, rows);
    this.tables.valid |= 1n << 40n;
    this.tables.counts[40] = rows.length;

    const resource = {
      rid,
      name,
      flags,
      implementation,
      data: implementation === null ? data.slice() : null
    };
    this.resources.splice(rid - 1, 0, resource);
    this.resources.forEach((item, index) => {
      item.rid = index + 1;
    });
    const shiftedEdits = new Map();
    for (const [oldRid, editedData] of this._resourceEdits) {
      shiftedEdits.set(oldRid >= rid ? oldRid + 1 : oldRid, editedData);
    }
    this._resourceEdits = shiftedEdits;
    if (implementation === null) {
      this._resourceEdits.set(rid, data.slice());
      this._clearResourcesDirectory = false;
    }
    for (const attribute of this.customAttributes) {
      attribute.parent = this.tables.row(12, attribute.rid).Parent.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    patches.forEach((patch) => this._patches.push(patch));
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return { token: 0x28000000 + rid, tokenMap };
  }

  replaceManifestResource(rid, data) {
    this.#ensureEditable();
    if (!Number.isInteger(rid) || rid < 1 || rid > this.resources.length) {
      throw new RangeError(`Invalid ManifestResource row ID ${rid}`);
    }
    if (!(data instanceof Uint8Array)) {
      throw new TypeError("Manifest resource data must be a Uint8Array");
    }
    const resource = this.resources[rid - 1];
    if (resource.rid !== rid || resource.implementation !== null) {
      throw new UnsupportedFormatError("Only embedded manifest resources can be replaced");
    }
    if (data.length > 0xffffffff) throw new RangeError("Manifest resource exceeds the CLI size limit");
    this._resourceEdits.set(rid, data.slice());
    this._clearResourcesDirectory = false;
    resource.data = data.slice();
    return this;
  }

  replaceLinkedResource(rid, data) {
    this.#ensureEditable();
    if (!Number.isInteger(rid) || rid < 1 || rid > this.resources.length) {
      throw new RangeError(`Invalid ManifestResource row ID ${rid}`);
    }
    if (!(data instanceof Uint8Array)) {
      throw new TypeError("Linked resource data must be a Uint8Array");
    }
    const resource = this.resources[rid - 1];
    if (resource.rid !== rid || resource.implementation?.table !== 38) {
      throw new UnsupportedFormatError("Only resources linked directly to a File row can be replaced");
    }
    const file = this.files[resource.implementation.rid - 1];
    const assemblyRow = this.tables.row(32, 1);
    if (!file || !assemblyRow) {
      throw new FormatError("Linked resource File or containing Assembly row is missing");
    }
    const hashName = getStrongNameHashName(assemblyRow.HashAlgId);
    const hashValue = Uint8Array.from(createHash(hashName).update(data).digest());
    this.replaceFile(file.rid, { hashValue });
    for (const linkedResource of this.resources) {
      if (linkedResource.implementation?.table === 38 &&
          linkedResource.implementation.rid === file.rid) {
        linkedResource.data = data.slice();
      }
    }
    return this;
  }

  replaceManifestResourceMetadata(rid, { name, flags, implementation } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(40, rid);
    const resource = this.resources[rid - 1];
    if (!Number.isInteger(rid) || rid < 1 || !row || !resource) {
      throw new RangeError(`Invalid ManifestResource row ID ${rid}`);
    }
    const nextName = name ?? resource.name;
    const nextFlags = flags ?? resource.flags;
    const nextImplementation = implementation === undefined
      ? resource.implementation
      : implementation;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("Manifest resource name must be a non-empty null-free string");
    }
    if (!Number.isInteger(nextFlags) || nextFlags < 0 || nextFlags > 0xffffffff) {
      throw new RangeError("Manifest resource flags must be an unsigned 32-bit integer");
    }
    let implementationTarget = null;
    if (nextImplementation !== null) {
      const table = metadataTableId(nextImplementation?.table);
      if (![35, 38, 39].includes(table) || !Number.isInteger(nextImplementation.rid) ||
          nextImplementation.rid < 1 || nextImplementation.rid > (this.tables.counts[table] ?? 0)) {
        throw new RangeError("Manifest resource implementation must identify an existing File, AssemblyRef, or ExportedType row");
      }
      implementationTarget = {
        table,
        tableName: metadataTableNames[table],
        rid: nextImplementation.rid
      };
    }
    if ((resource.implementation === null) !== (implementationTarget === null)) {
      throw new UnsupportedFormatError(
        "Manifest resource metadata replacement cannot convert between embedded and linked resources"
      );
    }
    if (resource.name === nextName && resource.flags === nextFlags &&
        resource.implementation?.table === implementationTarget?.table &&
        resource.implementation?.rid === implementationTarget?.rid) return this;

    let heapStreams = null;
    if (nextName !== resource.name) {
      heapStreams = new Map(
        [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
          [streamName, stream.bytes]
        )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
      );
      const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", stringHeap.heap);
      row.Name = stringHeap.index;
    }
    row.Flags = nextFlags;
    row.Implementation = {
      raw: implementationTarget
        ? encodeCodedIndex(implementationTarget.table, implementationTarget.rid, "Implementation")
        : 0,
      target: implementationTarget
    };
    resource.name = nextName;
    resource.flags = nextFlags;
    resource.implementation = implementationTarget;
    if (heapStreams) {
      this._heapStreams = heapStreams;
      this.#refreshHeaps();
    }
    this._metadataDirty = true;
    return this;
  }

  removeManifestResource(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("ManifestResource removal cannot be combined with structural method edits");
    }
    this.#ensureTokenRemappingSafe("ManifestResource");
    const rows = this.tables.rows.get(40) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid ManifestResource row ID ${rid}`);
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(`Cannot remap ManifestResource tokens with unrecognized metadata stream ${streamName}`);
      }
    }

    const rowChanges = [];
    for (const [tableId, tableRows] of this.tables.rows) {
      const schema = metadataTableSchemas[tableId];
      for (const row of tableRows) {
        for (const [kind, value, name] of schema) {
          const columnName = name ?? value;
          const column = row[columnName];
          if (kind === "coded" && column?.target?.table === 40) {
            if (column.target.rid === rid) {
              throw new FormatError(`ManifestResource row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (column.target.rid > rid) {
              const target = { ...column.target, rid: column.target.rid - 1 };
              rowChanges.push({
                row,
                columnName,
                value: {
                  raw: encodeCodedIndex(40, target.rid, value),
                  target
                }
              });
            }
          } else if (kind === "table" && column?.table === 40) {
            if (column.rid === rid) {
              throw new FormatError(`ManifestResource row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (column.rid > rid) {
              const newRid = column.rid - 1;
              rowChanges.push({
                row,
                columnName,
                value: { ...column, rid: newRid, raw: newRid }
              });
            }
          } else if (kind === "u4" && columnName === "Token" && [30, 31].includes(tableId) &&
              (column >>> 24) === 0x28) {
            const targetRid = column & 0x00ffffff;
            if (targetRid === rid) {
              throw new FormatError(`ManifestResource row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            }
            if (targetRid > rid) {
              rowChanges.push({
                row,
                columnName,
                value: 0x28000000 + targetRid - 1
              });
            }
          }
        }
      }
    }

    const changesByRow = new Map();
    for (const change of rowChanges) {
      if (!changesByRow.has(change.row)) changesByRow.set(change.row, new Map());
      changesByRow.get(change.row).set(change.columnName, change.value);
    }
    if ((this.tables.sorted & (1n << 12n)) !== 0n) {
      let previous = -1;
      for (const row of this.tables.get(12)) {
        const parent = changesByRow.get(row)?.get("Parent") ?? row.Parent;
        if (parent.raw < previous) {
          throw new FormatError("ManifestResource token remapping would violate sorted CustomAttribute order");
        }
        previous = parent.raw;
      }
    }

    const tokenMap = new Map();
    const tokenUpdates = [];
    const patches = [];
    for (const method of this.methods) {
      const body = this.getMethodBody(method.rid);
      if (!body) continue;
      for (const instruction of body.instructions) {
        const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
        if ((token >>> 24) !== 0x28) continue;
        const targetRid = token & 0x00ffffff;
        if (targetRid === 0 || targetRid > rows.length) {
          throw new FormatError(`CIL references missing ManifestResource row ${targetRid}`);
        }
        if (targetRid === rid) {
          throw new FormatError(`ManifestResource row ${rid} is referenced by CIL`);
        }
        if (targetRid > rid) {
          const replacement = 0x28000000 + targetRid - 1;
          tokenMap.set(token, replacement);
          patches.push(...createOperandPatches(instruction, replacement));
          tokenUpdates.push({ instruction, replacement });
        }
      }
    }
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set(0x28000000 + oldRid, 0x28000000 + oldRid - 1);
    }

    const resource = this.resources[rid - 1];
    if (!resource || resource.rid !== rid) {
      throw new FormatError(`ManifestResource row ${rid} has no semantic record`);
    }
    const remainingResources = this.resources.filter((item) => item.rid !== rid);
    const remainingEmbedded = remainingResources.filter((item) => item.implementation === null);
    if (resource.implementation === null && remainingEmbedded.some((item) =>
      !(item.data instanceof Uint8Array)
    )) {
      throw new FormatError("A remaining embedded manifest resource has no payload");
    }
    const newRows = rows.filter((row) => row.rid !== rid);

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingResources.forEach((item, index) => {
      item.rid = index + 1;
    });
    newRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.resources.splice(0, this.resources.length, ...remainingResources);
    this.tables.rows.set(40, newRows);
    this.tables.counts[40] = newRows.length;
    if (newRows.length === 0) this.tables.valid &= ~(1n << 40n);
    for (const attribute of this.customAttributes) {
      const attributeRow = this.tables.row(12, attribute.rid);
      attribute.parent = attributeRow.Parent.target;
    }
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);

    if (resource.implementation === null) {
      this._resourceEdits.clear();
      if (remainingEmbedded.length === 0) {
        this._clearResourcesDirectory = true;
      } else {
        this._clearResourcesDirectory = false;
        for (const item of remainingEmbedded) {
          this._resourceEdits.set(item.rid, item.data.slice());
        }
      }
    } else {
      const shiftedEdits = new Map();
      for (const [oldRid, data] of this._resourceEdits) {
        if (oldRid === rid) continue;
        shiftedEdits.set(oldRid > rid ? oldRid - 1 : oldRid, data);
      }
      this._resourceEdits = shiftedEdits;
    }
    this._metadataDirty = true;
    return tokenMap;
  }

  #validateGenericParamFlags(ownerTable, ownerRid, flags) {
    const variance = flags & 0x03;
    if (variance === 0x03) throw new RangeError("GenericParam variance value 3 is reserved");
    if ((flags & 0x18) === 0x18) {
      throw new RangeError("GenericParam cannot require both reference-type and non-nullable value-type constraints");
    }
    if (variance === 0) return;
    if (ownerTable !== 2) throw new FormatError("Generic method parameters cannot declare variance");
    const ownerType = this.types[ownerRid - 1];
    const baseType = ownerType?.extends;
    const baseName = baseType?.table === 1
      ? this.typeRefs[baseType.rid - 1]
      : baseType?.table === 2
        ? this.types[baseType.rid - 1]
        : null;
    if ((ownerType?.flags & 0x20) === 0 &&
        `${baseName?.namespace ?? ""}.${baseName?.name ?? ""}` !== "System.MulticastDelegate") {
      throw new FormatError("Generic parameter variance is only valid on interfaces and delegates");
    }
  }

  #validateBranchTarget(body, target) {
    if (!Number.isInteger(target) || target < 0 || target >= body.codeSize) {
      throw new RangeError("Branch target must point inside the method body");
    }
    if (!body.instructions.some((instruction) => instruction.offset === target)) {
      throw new RangeError(`Branch target IL_${target.toString(16)} is not an instruction boundary`);
    }
  }

  #ensureEditable() {
    if (this.#hasAuthenticodeCertificate) {
      throw new UnsupportedFormatError("Tier 1 refuses edits to Authenticode-signed PE files");
    }
  }

  #validateAssemblyPlatformFields(tableId, values) {
    if ([33, 34].includes(tableId) && (this.tables.counts[32] ?? 0) !== 1) {
      throw new UnsupportedFormatError(`${metadataTableNames[tableId]} requires exactly one Assembly row`);
    }
    for (const [name, value] of Object.entries(values)) {
      if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
        throw new RangeError(`${metadataTableNames[tableId]}.${name} must be an unsigned 32-bit integer`);
      }
    }
  }

  #validateAssemblyRefRid(rid) {
    if (!Number.isInteger(rid) || rid < 1 || rid > (this.tables.counts[35] ?? 0)) {
      throw new RangeError(`Invalid AssemblyRef row ID ${rid}`);
    }
  }

  #appendMetadataRow(tableId, values) {
    const rows = this.tables.rows.get(tableId) ?? [];
    if (rows.length !== (this.tables.counts[tableId] ?? 0)) {
      throw new FormatError(`${metadataTableNames[tableId]} row count is inconsistent with the metadata table header`);
    }
    const rid = rows.length + 1;
    rows.push({ table: tableId, tableName: metadataTableNames[tableId], rid, ...values });
    this.tables.rows.set(tableId, rows);
    this.tables.counts[tableId] = rid;
    this.tables.valid |= 1n << BigInt(tableId);
    this._metadataDirty = true;
    return rid;
  }

  #insertAssemblyPlatformRow(tableId, beforeRid, values) {
    const rows = this.tables.rows.get(tableId) ?? [];
    if (rows.length !== (this.tables.counts[tableId] ?? 0)) {
      throw new FormatError(`${metadataTableNames[tableId]} row count is inconsistent with the metadata table header`);
    }
    if (!Number.isInteger(beforeRid) || beforeRid < 1 || beforeRid > rows.length + 1) {
      throw new RangeError(`Invalid ${metadataTableNames[tableId]} insertion position ${beforeRid}`);
    }
    if (rows.length >= 0x00ffffff) {
      throw new RangeError(`${metadataTableNames[tableId]} token row ID exceeds 24-bit range`);
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowInsertion(tableId, beforeRid, rows.length, metadataTableNames[tableId]);
    const row = {
      table: tableId,
      tableName: metadataTableNames[tableId],
      rid: beforeRid,
      ...values
    };
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    rows.splice(beforeRid - 1, 0, row);
    rows.forEach((currentRow, index) => {
      currentRow.rid = index + 1;
    });
    this.tables.rows.set(tableId, rows);
    this.tables.counts[tableId] = rows.length;
    this.tables.valid |= 1n << BigInt(tableId);
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return { rid: beforeRid, tokenMap };
  }

  #replaceMetadataRow(tableId, rid, values) {
    const row = this.tables.row(tableId, rid);
    if (!row) throw new RangeError(`Invalid ${metadataTableNames[tableId]} row ID ${rid}`);
    Object.assign(row, values);
    this._metadataDirty = true;
  }

  #removeMetadataRow(tableId, rid) {
    if (![33, 34, 36, 37].includes(tableId)) {
      throw new RangeError(`Unsupported metadata row removal for table ${tableId}`);
    }
    const rows = this.tables.rows.get(tableId) ?? [];
    if (rows.length !== (this.tables.counts[tableId] ?? 0)) {
      throw new FormatError(`${metadataTableNames[tableId]} row count is inconsistent with the metadata table header`);
    }
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid ${metadataTableNames[tableId]} row ID ${rid}`);
    }
    const { tokenMap, rowChanges, tokenUpdates, patches } =
      this.#prepareTokenRowRemoval(tableId, rid, rows.length, metadataTableNames[tableId]);
    const remainingRows = rows.filter((row) => row.rid !== rid);
    for (const change of rowChanges) change.row[change.columnName] = change.value;
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.tables.rows.set(tableId, remainingRows);
    this.tables.counts[tableId] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << BigInt(tableId));
    for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
    this._patches.push(...patches);
    this._metadataDirty = true;
    return tokenMap;
  }

  #ensureTokenRemappingSafe(tableName, { allowEmbeddedPortablePdb = false } = {}) {
    if (this.#hasDebugDirectory) {
      const embeddedPdbEntries = this.pe.debugDirectoryEntries
        .map((entry, index) => ({ entry, index }))
        .filter(({ entry }) => entry.embeddedPortablePdb);
      const stagedPdb = embeddedPdbEntries.length === 1
        ? this._embeddedPortablePdbEdits.get(embeddedPdbEntries[0].index)
        : null;
      const portablePdb = stagedPdb
        ? parseEmbeddedPortablePdbData(stagedPdb, 0, stagedPdb.length)
        : embeddedPdbEntries[0]?.entry.embeddedPortablePdb;
      const portablePdbCanPreserveTokenRemapping =
        embeddedPdbEntries.length === 1 &&
        !["MethodDef", "StandAloneSig"].includes(tableName) &&
        canPreservePortablePdbCustomDebugInformation(portablePdb) &&
        this.pe.debugDirectoryEntries.every((entry) => [2, 16, 17, 19].includes(entry.type));
      if ((!allowEmbeddedPortablePdb && !portablePdbCanPreserveTokenRemapping) ||
          embeddedPdbEntries.length !== 1) {
        throw new UnsupportedFormatError(
          `${tableName} token remapping is unsupported while a PE debug directory is present`
        );
      }
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `${tableName} token remapping is unsupported with unrecognized metadata stream ${streamName}`
        );
      }
    }
  }

  #ensureAddedMethodBodiesSafe(operation) {
    if (this._addedMethodBodies.size > 0) {
      throw new UnsupportedFormatError(`${operation} cannot be combined with added method bodies`);
    }
  }

  #removeOwnedRow(tableId, mapTableId, pointerTableId, rid) {
    this.#ensureEditable();
    const tableName = metadataTableNames[tableId];
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError(`${tableName} removal cannot be combined with structural method edits`);
    }
    this.#ensureTokenRemappingSafe(tableName);
    const rows = this.tables.rows.get(tableId) ?? [];
    const maps = this.tables.rows.get(mapTableId) ?? [];
    if (rows.length !== this.tables.counts[tableId] || maps.length !== this.tables.counts[mapTableId]) {
      throw new FormatError(`${tableName} or ${metadataTableNames[mapTableId]} row count is inconsistent`);
    }
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid ${tableName} row ID ${rid}`);
    }
    const pointerColumn = tableId === 23 ? "Property" : "Event";
    const pointerRows = getBijectivePointerRows(
      this, pointerTableId, tableId, pointerColumn
    );
    const pointerRid = pointerRows
      ? pointerRows.findIndex((pointer) => pointer[pointerColumn].rid === rid) + 1
      : 0;
    if (pointerRows && pointerRid === 0) {
      throw new FormatError(
        `${metadataTableNames[pointerTableId]} has no pointer to ${tableName} row ${rid}`
      );
    }
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remap ${tableName} tokens with unrecognized metadata stream ${streamName}`
        );
      }
    }
    const listProperty = tableId === 23 ? "propertyRids" : "eventRids";
    const recordsProperty = tableId === 23 ? "properties" : "events";
    const owners = this.types.filter((type) => type[listProperty].includes(rid));
    const semanticRow = owners[0]?.[recordsProperty].find((item) => item.rid === rid);
    if (owners.length !== 1 || !semanticRow) {
      throw new FormatError(`${tableName} row ${rid} has no unique resolved TypeDef owner`);
    }

    const listColumn = tableId === 23 ? "PropertyList" : "EventList";
    const rowChanges = [];
    for (const [referenceTableId, referenceRows] of this.tables.rows) {
      const schema = metadataTableSchemas[referenceTableId];
      if (!schema) {
        throw new UnsupportedFormatError(
          `Cannot remap ${tableName} references in unknown metadata table ${referenceTableId}`
        );
      }
      for (const row of referenceRows) {
        for (const [kind, value, name] of schema) {
          if (kind !== "coded") continue;
          const columnName = name ?? value;
          const target = row[columnName]?.target;
          if (target?.table !== tableId) continue;
          if (target.rid === rid) {
            throw new FormatError(
              `${tableName} row ${rid} is referenced by ${metadataTableNames[referenceTableId]}.${columnName}`
            );
          }
          if (target.rid > rid) {
            const remappedTarget = { ...target, rid: target.rid - 1 };
            rowChanges.push({
              row,
              columnName,
              value: {
                raw: encodeCodedIndex(tableId, remappedTarget.rid, value),
                target: remappedTarget
              }
            });
          }
        }
      }
    }
    const listChanges = [];
    const listBoundary = pointerRows ? pointerRid : rid;
    for (const row of maps) {
      const list = row[listColumn];
      if (list.rid > listBoundary) {
        listChanges.push({
          row,
          value: { ...list, raw: list.rid - 1, rid: list.rid - 1 }
        });
      }
    }
    const tokenMap = new Map();
    for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
      tokenMap.set((tableId << 24) + oldRid, (tableId << 24) + oldRid - 1);
    }

    for (const change of rowChanges) change.row[change.columnName] = change.value;
    for (const change of listChanges) change.row[listColumn] = change.value;
    if (pointerRows) {
      const remainingPointers = pointerRows.filter((pointer) => pointer.rid !== pointerRid);
      for (const pointer of remainingPointers) {
        const targetRid = pointer[pointerColumn].rid;
        if (targetRid > rid) {
          pointer[pointerColumn] = {
            ...pointer[pointerColumn],
            raw: targetRid - 1,
            rid: targetRid - 1
          };
        }
      }
      remainingPointers.forEach((pointer, index) => {
        pointer.rid = index + 1;
      });
      this.tables.rows.set(pointerTableId, remainingPointers);
      this.tables.counts[pointerTableId] = remainingPointers.length;
      if (remainingPointers.length === 0) {
        this.tables.valid &= ~(1n << BigInt(pointerTableId));
      }
    }
    const remainingRows = rows.filter((row) => row.rid !== rid);
    remainingRows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.tables.rows.set(tableId, remainingRows);
    this.tables.counts[tableId] = remainingRows.length;
    if (remainingRows.length === 0) this.tables.valid &= ~(1n << BigInt(tableId));
    for (const type of this.types) {
      type[listProperty] = type[listProperty]
        .filter((rowRid) => rowRid !== rid)
        .map((rowRid) => rowRid > rid ? rowRid - 1 : rowRid);
      type[recordsProperty] = type[recordsProperty]
        .filter((item) => item.rid !== rid)
        .map((item) => {
          if (item.rid > rid) item.rid--;
          return item;
        });
    }
    this._metadataDirty = true;
    return tokenMap;
  }

  #refreshHeaps() {
    this.heaps = new MetadataHeaps(new Map([...this._heapStreams].map(([streamName, bytes]) =>
      [streamName, { bytes }]
    )));
  }

  formatInstruction(instruction) {
    return formatInstruction(instruction);
  }

  replaceModule({ name, generation } = {}) {
    this.#ensureEditable();
    const moduleRow = this.tables.row(0, 1);
    if (!moduleRow || !this.module) {
      throw new UnsupportedFormatError("Module replacement requires a Module metadata row");
    }
    const nextName = name ?? this.module.name;
    const nextGeneration = generation ?? this.module.generation;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("Module name must be a non-empty null-free string");
    }
    if (!Number.isInteger(nextGeneration) || nextGeneration < 0 || nextGeneration > 0xffff) {
      throw new TypeError("Module generation must be an unsigned 16-bit integer");
    }
    if (nextName === this.module.name && nextGeneration === this.module.generation) return this;

    if (nextName !== this.module.name) {
      const heapStreams = this._heapStreams
        ? new Map([...this._heapStreams].map(([streamName, bytes]) => [streamName, bytes.slice()]))
        : new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
          [streamName, stream.bytes.slice()]
        ));
      const nameHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", nameHeap.heap);
      moduleRow.Name = nameHeap.index;
      this._heapStreams = heapStreams;
      this.#refreshHeaps();
    }
    moduleRow.Generation = nextGeneration;
    this.module = { ...this.module, name: nextName, generation: nextGeneration };
    this._metadataDirty = true;
    return this;
  }

  replaceAssemblyIdentity({ name, culture, version } = {}) {
    this.#ensureEditable();
    const assemblyRow = this.tables.row(32, 1);
    if (!assemblyRow || !this.module.assembly) {
      throw new UnsupportedFormatError("Assembly identity replacement requires an Assembly metadata row");
    }
    const current = this.module.assembly;
    const nextName = name ?? current.name;
    const nextCulture = culture ?? current.culture;
    const nextVersion = version ?? current.version;
    if (typeof nextName !== "string" || nextName.length === 0 || nextName.includes("\0")) {
      throw new TypeError("Assembly name must be a non-empty null-free string");
    }
    if (typeof nextCulture !== "string" || nextCulture.includes("\0")) {
      throw new TypeError("Assembly culture must be a null-free string");
    }
    if (!Array.isArray(nextVersion) || nextVersion.length !== 4 ||
        nextVersion.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffff)) {
      throw new TypeError("Assembly version must contain four unsigned 16-bit integers");
    }
    const identityChanged = nextName !== current.name ||
      nextCulture !== current.culture ||
      nextVersion.some((part, index) => part !== current.version[index]);
    if (!identityChanged) return this;

    const heapStreams = this._heapStreams
      ? new Map([...this._heapStreams].map(([streamName, bytes]) => [streamName, bytes.slice()]))
      : new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    if (nextName !== current.name) {
      const nameHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextName);
      heapStreams.set("#Strings", nameHeap.heap);
      assemblyRow.Name = nameHeap.index;
    }
    if (nextCulture !== current.culture) {
      const cultureHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), nextCulture);
      heapStreams.set("#Strings", cultureHeap.heap);
      assemblyRow.Culture = cultureHeap.index;
    }
    [assemblyRow.MajorVersion, assemblyRow.MinorVersion, assemblyRow.BuildNumber, assemblyRow.RevisionNumber] =
      nextVersion;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this.module.assembly = {
      ...current,
      name: nextName,
      culture: nextCulture,
      version: [...nextVersion]
    };
    this._metadataDirty = true;
    return this;
  }

  replaceStrongNamePublicKey(privateKeyInput, { hashAlgorithm } = {}) {
    this.#ensureEditable();
    assertStrongNamePEProfile(this.pe);
    const privateKey = importStrongNamePrivateKey(privateKeyInput);
    const assemblyRow = this.tables.row(32, 1);
    if (!assemblyRow) {
      throw new UnsupportedFormatError("Strong-name signing requires an Assembly metadata row");
    }
    const selectedHashAlgorithm = hashAlgorithm ?? (assemblyRow.HashAlgId || 0x00008004);
    getStrongNameHashName(selectedHashAlgorithm);
    const publicKey = encodeStrongNamePublicKey(privateKey, selectedHashAlgorithm);
    const signature = this.cli.strongNameSignature;
    if ((signature.rva === 0) !== (signature.size === 0)) {
      throw new FormatError("Strong-name signature directory has only one of RVA and size set");
    }
    if (signature.rva === 0 && (this.cli.flags & 0x08) !== 0) {
      throw new FormatError("Strong-name-signed CLI header has no signature directory");
    }
    const expectedSize = Math.ceil(privateKey.asymmetricKeyDetails.modulusLength / 8);
    const currentPublicKey = this.heaps.getBlob(assemblyRow.PublicKey);
    const keyChanged = !Buffer.from(currentPublicKey).equals(publicKey);
    const identityChanged = keyChanged ||
      assemblyRow.HashAlgId !== selectedHashAlgorithm ||
      (assemblyRow.Flags & 0x01) === 0;
    if (identityChanged) {
      const heapStreams = this._heapStreams
        ? new Map([...this._heapStreams].map(([name, bytes]) => [name, bytes.slice()]))
        : new Map([...this.metadataRoot.streams].map(([name, stream]) =>
          [name, stream.bytes.slice()]
        ));
      if (keyChanged) {
        const blobHeap = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), publicKey);
        heapStreams.set("#Blob", blobHeap.heap);
        assemblyRow.PublicKey = blobHeap.index;
        this._heapStreams = heapStreams;
        this.#refreshHeaps();
      }
      assemblyRow.HashAlgId = selectedHashAlgorithm;
      assemblyRow.Flags |= 0x01;
      this._metadataDirty = true;
    }
    if (signature.rva !== 0 && signature.size !== expectedSize) {
      this.#strongNameSignatureSize = expectedSize;
      this._metadataDirty = true;
    }
    return this.signStrongName(privateKey);
  }

  signStrongName(privateKeyInput) {
    this.#ensureEditable();
    assertStrongNamePEProfile(this.pe);
    const privateKey = importStrongNamePrivateKey(privateKeyInput);
    const assemblyRow = this.tables.row(32, 1);
    if (!assemblyRow) {
      throw new UnsupportedFormatError("Strong-name signing requires an Assembly metadata row");
    }
    if ((assemblyRow.Flags & 0x01) === 0) {
      throw new UnsupportedFormatError("Strong-name signing requires a full Assembly public key");
    }
    const hashAlgorithm = assemblyRow.HashAlgId || 0x00008004;
    getStrongNameHashName(hashAlgorithm);
    const expectedPublicKey = encodeStrongNamePublicKey(privateKey, hashAlgorithm);
    const currentPublicKey = this.heaps.getBlob(assemblyRow.PublicKey);
    if (!Buffer.from(currentPublicKey).equals(expectedPublicKey)) {
      throw new FormatError("Strong-name private key does not match the Assembly public key");
    }
    const signature = this.cli.strongNameSignature;
    const expectedSize = Math.ceil(privateKey.asymmetricKeyDetails.modulusLength / 8);
    if ((signature.rva === 0) !== (signature.size === 0)) {
      throw new FormatError("Strong-name signature directory has only one of RVA and size set");
    }
    if (signature.rva === 0) {
      if ((this.cli.flags & 0x08) !== 0) {
        throw new FormatError("Strong-name-signed CLI header has no signature directory");
      }
      this.#strongNameSignatureSize = expectedSize;
      this._metadataDirty = true;
    } else if (signature.size !== expectedSize) {
      if (this.#strongNameSignatureSize !== expectedSize) {
        throw new FormatError(
          `Strong-name signature slot size ${signature.size} does not match RSA key size ${expectedSize}`
        );
      }
    } else {
      this.pe.rvaToOffset(signature.rva, signature.size);
    }
    this.#strongNamePrivateKey = privateKey;
    this.#strongNameHashAlgorithm = hashAlgorithm;
    return this;
  }

  verifyStrongNameSignature() {
    const assemblyRow = this.tables.row(32, 1);
    if (!assemblyRow) return false;
    return verifyStrongNameImage(
      this.#bytes,
      this.pe,
      this.cli,
      this.heaps.getBlob(assemblyRow.PublicKey),
      assemblyRow.HashAlgId
    );
  }

  serialize() {
    this.#synchronizeEmbeddedPortablePdbRowCounts();
    const structurallyDirty = this._structuralBodies.size > 0 ||
      this._addedMethodBodies.size > 0 || this._metadataDirty ||
      this._resourceEdits.size > 0 || this._clearResourcesDirectory ||
      this._embeddedPortablePdbEdits.size > 0;
    let output = structurallyDirty
      ? serializeStructural(this, {
        preserveStrongName: this.#strongNamePrivateKey !== null,
        strongNameSignatureSize: this.#strongNameSignatureSize
      })
      : applyPatches(this.#bytes, this._patches, this.cli, this.pe, {
        preserveStrongName: this.#strongNamePrivateKey !== null
      });
    if (this.#strongNamePrivateKey !== null) {
      const unsignedAssembly = new Assembly(output);
      output = signStrongNameImage(
        output,
        unsignedAssembly.pe,
        unsignedAssembly.cli,
        this.#strongNamePrivateKey,
        this.#strongNameHashAlgorithm
      );
    }
    if (structurallyDirty || this.#strongNamePrivateKey !== null) {
      new Assembly(output);
    }
    return output;
  }

  toBuffer() {
    return Buffer.from(this.serialize());
  }
}

export function parseAssembly(input) {
  return Assembly.from(input);
}
