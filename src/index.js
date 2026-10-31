import { FormatError, UnsupportedFormatError } from "./binary/errors.js";
import { parsePE, parseCliHeader } from "./pe/headers.js";
import { parseMetadataRoot, MetadataHeaps } from "./metadata/streams.js";
import { parseTablesStream } from "./metadata/tables.js";
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
  encodeStrongNamePublicKey,
  getStrongNameHashName,
  importStrongNamePrivateKey,
  signStrongNameImage,
  verifyStrongNameImage
} from "./metadata/strong-name.js";
import {
  encodeCustomAttribute as encodeCustomAttributeBlob,
  parseCustomAttribute as parseCustomAttributeBlob
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
    return type ? `${type.namespace ? `${type.namespace}.` : ""}${type.name}` : null;
  }
  return null;
}

function resolveEnumElementType(assembly, name) {
  const fullName = name.split(",", 1)[0].trim();
  const definition = assembly.types.find((type) =>
    `${type.namespace ? `${type.namespace}.` : ""}${type.name}` === fullName
  );
  const underlyingField = definition?.fields.find((field) => field.name === "value__");
  if (!underlyingField) {
    throw new UnsupportedFormatError(`Custom-attribute enum ${name} is not defined in this assembly`);
  }
  const signature = parseSignature(underlyingField.signature);
  const elementType = signature.type?.kind === "primitive" ? signature.type.elementType : 0;
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
    if (type.kind === "typeParameter" && type.index >= typeArity) {
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
    visitType(signature.type, 0);
  } else if (signature.kind === "property") {
    visitType(signature.returnType, 0);
    for (const parameter of signature.parameters) visitType(parameter, 0);
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

function validateTypeSpecDefinitions(assembly, type) {
  if (type.kind === "modified") {
    validateTypeSpecDefinitions(assembly, type.type);
  } else if (type.kind === "genericInstance") {
    if (type.genericType.table === 2) {
      const expectedArity = getGenericParameterArity(assembly.genericParams, 2, type.genericType.rid);
      if (type.arguments.length !== expectedArity) {
        throw new FormatError(
          `TypeSpec generic instance has ${type.arguments.length} arguments for TypeDef arity ${expectedArity}`
        );
      }
    }
    for (const argument of type.arguments) validateTypeSpecDefinitions(assembly, argument);
  } else if (["array", "szArray", "pointer", "byRef", "pinned"].includes(type.kind)) {
    validateTypeSpecDefinitions(assembly, type.type);
  } else if (type.kind === "functionPointer") {
    validateTypeSpecDefinitions(assembly, type.signature.returnType);
    for (const parameter of type.signature.parameters) {
      validateTypeSpecDefinitions(assembly, parameter);
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
    if (type.kind === "typeParameter" && type.index >= typeArity) {
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
    const aritySuffix = /`([0-9]+)$/.exec(typeRef.name);
    const typeArity = aritySuffix ? Number(aritySuffix[1]) : 0;
    if (!Number.isSafeInteger(typeArity)) {
      throw new FormatError(`TypeRef row ${parent.rid} has an unsupported generic arity suffix`);
    }
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
  const method = assembly.methods[methodRid - 1];
  if (!method) throw new FormatError(`CIL call site references missing MethodDef row ${methodRid}`);
  const methodSignature = parseSignature(method.signature, { counts: assembly.tables.counts });
  if (methodSignature.kind !== "method") {
    throw new FormatError(`MethodDef row ${methodRid} has an invalid method signature`);
  }
  const declaringType = assembly.types.find((type) => type.methodRids.includes(methodRid));
  const typeArity = declaringType
    ? getGenericParameterArity(assembly.genericParams, 2, declaringType.rid)
    : 0;
  const methodArity = methodSignature.generic ? methodSignature.genericParameterCount : 0;
  validateGenericVariableReferences(
    methodSpec.parsedInstantiation,
    typeArity,
    assembly,
    typeSpecOverride,
    methodArity
  );
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
    validateMethodSpecUsesInBody(
      assembly, method, body, methodSpecRid, typeSpecOverride, methodSpecOverride
    );
  }
}

function validateMethodSpecUsesInBody(
  assembly,
  method,
  body,
  methodSpecRid = null,
  typeSpecOverride = null,
  methodSpecOverride = null
) {
  for (const instruction of body.instructions) {
    const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
    const currentRid = token & 0x00ffffff;
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

function getCustomAttributeConstructor(assembly, attribute, resolveEnum) {
  const constructor = attribute.constructor;
  let method;
  let ownerType;
  if (constructor?.table === 6) {
    method = assembly.methods[constructor.rid - 1];
    ownerType = assembly.types.find((type) => type.methodRids.includes(constructor.rid));
  } else if (constructor?.table === 10) {
    method = assembly.memberRefs.find((reference) => reference.rid === constructor.rid);
    ownerType = method ? getManagedTypeName(assembly, method.parent) : null;
  }
  if (!method || method.name !== ".ctor") {
    throw new FormatError(`CustomAttribute row ${attribute.rid} does not reference a supported constructor`);
  }
  const signature = parseSignature(method.signature);
  if (signature.kind !== "method" || !signature.hasThis || signature.generic) {
    throw new UnsupportedFormatError(`CustomAttribute row ${attribute.rid} has an unsupported constructor signature`);
  }
  if (constructor.table === 6 && !ownerType) {
    throw new FormatError(`CustomAttribute row ${attribute.rid} constructor has no declaring type`);
  }
  return {
    signature,
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
  encodeCustomAttribute,
  parseCustomAttribute
} from "./metadata/custom-attributes.js";
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
    if (this.#hasDebugDirectory && previousBody &&
        (state.instructions.length !== previousBody.instructions.length ||
         state.instructions.some((instruction, index) =>
           instruction.offset !== previousBody.instructions[index]?.offset
         ))) {
      throw new UnsupportedFormatError(
        "Instruction-offset changes cannot be combined with PE debug information because sequence points are not rewritten"
      );
    }
    this._addedMethodBodies.delete(methodRid);
    this._structuralBodies.set(methodRid, state);
    this._bodyCache.set(methodRid, state.body);
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
    validateMethodSpecUsesInBody(this, method, body);
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
    const { fixedTypes } = getCustomAttributeConstructor(this, attribute, enumResolver);
    return parseCustomAttributeBlob(
      attribute.value,
      fixedTypes,
      enumResolver
    );
  }

  replaceCustomAttribute(rid, value, { resolveEnum } = {}) {
    this.#ensureEditable();
    if (!Number.isInteger(rid) || rid < 1 || rid > this.customAttributes.length) {
      throw new RangeError(`Invalid CustomAttribute row ID ${rid}`);
    }
    const attribute = this.customAttributes[rid - 1];
    const enumResolver = getCustomAttributeEnumResolver(this, resolveEnum);
    const { fixedTypes } = getCustomAttributeConstructor(this, attribute, enumResolver);
    const encoded = encodeCustomAttributeBlob(value, fixedTypes);
    const parsed = parseCustomAttributeBlob(encoded, fixedTypes, enumResolver);
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
    if ((this.tables.sorted & (1n << 12n)) !== 0n &&
        customRows.at(-1)?.Parent.raw > parentRaw) {
      throw new FormatError("Appending this CustomAttribute would violate the table's sorted Parent order");
    }

    const enumResolver = getCustomAttributeEnumResolver(this, resolveEnum);
    const newAttribute = {
      rid: customRows.length + 1,
      parent: { table: parentTable, tableName: metadataTableNames[parentTable], rid: parent.rid },
      constructor: {
        table: constructorTable,
        tableName: metadataTableNames[constructorTable],
        rid: constructor.rid
      },
      value: new Uint8Array()
    };
    const { fixedTypes } = getCustomAttributeConstructor(this, newAttribute, enumResolver);
    const encoded = encodeCustomAttributeBlob(value, fixedTypes);
    const parsed = parseCustomAttributeBlob(encoded, fixedTypes, enumResolver);
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), encoded);
    heapStreams.set("#Blob", blob.heap);

    const rid = newAttribute.rid;
    customRows.push({
      table: 12,
      tableName: metadataTableNames[12],
      rid,
      Parent: { raw: parentRaw, target: newAttribute.parent },
      Type: { raw: constructorRaw, target: newAttribute.constructor },
      Value: blob.index
    });
    this.tables.rows.set(12, customRows);
    this.tables.valid |= 1n << 12n;
    this.tables.counts[12] = rid;
    newAttribute.value = encoded.slice();
    newAttribute.parsedValue = parsed;
    this.customAttributes.push(newAttribute);
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return 0x0c000000 + rid;
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
    if (new TextDecoder().decode(encodedPath) !== path) {
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
    codeView.path = path;
    codeView.pathByteLength = encodedPath.length;
    return this;
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
    this.#ensureEditable();
    const rows = this.tables.rows.get(29) ?? [];
    if (rows.length !== this.tables.counts[29] || rows.length >= 0xffffffff) {
      throw new RangeError("FieldRVA row count is inconsistent or exceeds the metadata table limit");
    }
    const field = validateFieldRva(this, fieldRid, rva);
    if (rows.some((row) => row.Field.rid === fieldRid)) {
      throw new FormatError("The FieldRVA table already has a row for this Field");
    }
    if ((this.tables.sorted & (1n << 29n)) !== 0n && rows.at(-1)?.Field.rid > fieldRid) {
      throw new UnsupportedFormatError("FieldRVA append would violate declared Field ordering");
    }
    const rid = rows.length + 1;
    rows.push({ table: 29, tableName: metadataTableNames[29], rid, RVA: rva,
      Field: { rid: fieldRid } });
    this.tables.rows.set(29, rows);
    this.tables.counts[29] = rid;
    this.tables.valid |= 1n << 29n;
    field.rva = rva;
    this._metadataDirty = true;
    return rid;
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
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[29] = rows.length;
    this.tables.rows.set(29, rows);
    field.rva = null;
    this._metadataDirty = true;
    return this;
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
    if (rows.length !== this.tables.counts[11] || rows.length >= 0xffffffff) {
      throw new RangeError("Constant row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) =>
      row.Parent.target?.table === parentTable && row.Parent.target.rid === parent.rid
    )) {
      throw new FormatError("The Constant table already has a value for this parent");
    }
    const encodedParent = encodeCodedIndex(parentTable, parent.rid, "HasConstant");
    if ((this.tables.sorted & (1n << 11n)) !== 0n &&
        rows.at(-1)?.Parent.raw > encodedParent) {
      throw new UnsupportedFormatError(
        "Constant append would violate declared Parent ordering"
      );
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), value);
    heapStreams.set("#Blob", blob.heap);
    const rid = rows.length + 1;
    rows.push({
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
    });
    this.tables.rows.set(11, rows);
    this.tables.counts[11] = rid;
    this.tables.valid |= 1n << 11n;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return 0x0b000000 + rid;
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
    const rows = this.tables.rows.get(11) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid Constant row ID ${rid}`);
    }
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[11] = rows.length;
    this.tables.rows.set(11, rows);
    this._metadataDirty = true;
    return this;
  }

  addFieldMarshal({ parent, nativeType }) {
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
    if (rows.length !== this.tables.counts[13] || rows.length >= 0xffffffff) {
      throw new RangeError("FieldMarshal row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) =>
      row.Parent.target?.table === parentTable && row.Parent.target.rid === parent.rid
    )) {
      throw new FormatError("The FieldMarshal table already has a descriptor for this parent");
    }
    const encodedParent = encodeCodedIndex(parentTable, parent.rid, "HasFieldMarshal");
    if ((this.tables.sorted & (1n << 13n)) !== 0n &&
        rows.at(-1)?.Parent.raw > encodedParent) {
      throw new UnsupportedFormatError(
        "FieldMarshal append would violate declared Parent ordering"
      );
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), nativeType);
    heapStreams.set("#Blob", blob.heap);
    const rid = rows.length + 1;
    rows.push({
      table: 13,
      tableName: metadataTableNames[13],
      rid,
      Parent: {
        raw: encodedParent,
        target: { table: parentTable, tableName: metadataTableNames[parentTable], rid: parent.rid }
      },
      NativeType: blob.index
    });
    this.tables.rows.set(13, rows);
    this.tables.counts[13] = rid;
    this.tables.valid |= 1n << 13n;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return this;
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
    const rows = this.tables.rows.get(13) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid FieldMarshal row ID ${rid}`);
    }
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[13] = rows.length;
    this.tables.rows.set(13, rows);
    this._metadataDirty = true;
    return this;
  }

  addClassLayout({ owner, packingSize = 0, classSize = 0 }) {
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
    if (rows.length !== this.tables.counts[15] || rows.length >= 0xffffffff) {
      throw new RangeError("ClassLayout row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.Parent.rid === ownerRid)) {
      throw new FormatError("The ClassLayout table already has a row for this TypeDef");
    }
    if ((this.tables.sorted & (1n << 15n)) !== 0n && rows.at(-1)?.Parent.rid > ownerRid) {
      throw new UnsupportedFormatError("ClassLayout append would violate declared Parent ordering");
    }
    const rid = rows.length + 1;
    rows.push({ table: 15, tableName: metadataTableNames[15], rid, PackingSize: packingSize,
      ClassSize: classSize, Parent: { rid: ownerRid } });
    this.tables.rows.set(15, rows);
    this.tables.counts[15] = rid;
    this.tables.valid |= 1n << 15n;
    this._metadataDirty = true;
    return rid;
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
    const rows = this.tables.rows.get(15) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid ClassLayout row ID ${rid}`);
    }
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[15] = rows.length;
    this.tables.rows.set(15, rows);
    this._metadataDirty = true;
    return this;
  }

  addFieldLayout({ fieldRid, offset }) {
    this.#ensureEditable();
    if (!Number.isInteger(fieldRid) || fieldRid < 1 || fieldRid > this.tables.counts[4]) {
      throw new RangeError("FieldLayout parent must identify an existing Field row");
    }
    if (!Number.isInteger(offset) || offset < 0 || offset > 0xffffffff) {
      throw new RangeError("FieldLayout offset must be an unsigned 32-bit integer");
    }
    const rows = this.tables.rows.get(16) ?? [];
    if (rows.length !== this.tables.counts[16] || rows.length >= 0xffffffff) {
      throw new RangeError("FieldLayout row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.Field.rid === fieldRid)) {
      throw new FormatError("The FieldLayout table already has a row for this Field");
    }
    if ((this.tables.sorted & (1n << 16n)) !== 0n && rows.at(-1)?.Field.rid > fieldRid) {
      throw new UnsupportedFormatError("FieldLayout append would violate declared Field ordering");
    }
    const rid = rows.length + 1;
    rows.push({ table: 16, tableName: metadataTableNames[16], rid, Offset: offset,
      Field: { rid: fieldRid } });
    this.tables.rows.set(16, rows);
    this.tables.counts[16] = rid;
    this.tables.valid |= 1n << 16n;
    this._metadataDirty = true;
    return rid;
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
    const rows = this.tables.rows.get(16) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid FieldLayout row ID ${rid}`);
    }
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[16] = rows.length;
    this.tables.rows.set(16, rows);
    this._metadataDirty = true;
    return this;
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
    const rows = this.tables.rows.get(41) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid NestedClass row ID ${rid}`);
    }
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[41] = rows.length;
    this.tables.rows.set(41, rows);
    this._metadataDirty = true;
    return this;
  }

  addImplMap({ member, moduleRefRid, importName, mappingFlags = 0 }) {
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
    if (rows.length !== this.tables.counts[28] || rows.length >= 0xffffffff) {
      throw new RangeError("ImplMap row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.MemberForwarded.raw === forwarded.raw)) {
      throw new FormatError("The ImplMap table already has a mapping for this member");
    }
    if ((this.tables.sorted & (1n << 28n)) !== 0n &&
        rows.at(-1)?.MemberForwarded.raw > forwarded.raw) {
      throw new UnsupportedFormatError(
        "ImplMap append would violate declared MemberForwarded ordering"
      );
    }
    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), importName);
    heapStreams.set("#Strings", stringHeap.heap);
    const rid = rows.length + 1;
    rows.push({
      table: 28,
      tableName: metadataTableNames[28],
      rid,
      MappingFlags: mappingFlags,
      MemberForwarded: forwarded,
      ImportName: stringHeap.index,
      ImportScope: { raw: moduleRefRid, table: 26, tableName: metadataTableNames[26], rid: moduleRefRid }
    });
    this.tables.rows.set(28, rows);
    this.tables.counts[28] = rid;
    this.tables.valid |= 1n << 28n;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return rid;
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
    memberRow.Flags &= ~0x2000;
    if (member.table === 4) {
      const field = this.types.flatMap((type) => type.fields)
        .find((item) => item.rid === member.rid);
      if (field) field.flags = memberRow.Flags;
    } else {
      const method = this.methods[member.rid - 1];
      if (method) method.flags = memberRow.Flags;
    }
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[28] = rows.length;
    this.tables.rows.set(28, rows);
    this._metadataDirty = true;
    return this;
  }

  addMethodImpl({ owner, body, declaration }) {
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
    if ((this.tables.sorted & (1n << 25n)) !== 0n && rows.at(-1)?.Class.rid > ownerRid) {
      throw new UnsupportedFormatError("MethodImpl append would violate declared Class ordering");
    }
    const rid = rows.length + 1;
    rows.push({
      table: 25,
      tableName: metadataTableNames[25],
      rid,
      Class: { raw: ownerRid, table: 2, tableName: metadataTableNames[2], rid: ownerRid },
      MethodBody: bodyReference,
      MethodDeclaration: declarationReference
    });
    this.tables.rows.set(25, rows);
    this.tables.counts[25] = rid;
    this.tables.valid |= 1n << 25n;
    this._metadataDirty = true;
    return rid;
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
    const rows = this.tables.rows.get(25) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid MethodImpl row ID ${rid}`);
    }
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[25] = rows.length;
    this.tables.rows.set(25, rows);
    this._metadataDirty = true;
    return this;
  }

  addDeclSecurity({ parent, action, permissionSet }) {
    this.#ensureEditable();
    const parentTable = metadataTableId(parent?.table);
    if (![2, 6, 32].includes(parentTable) || !Number.isInteger(parent.rid) ||
        parent.rid < 1 || parent.rid > (this.tables.counts[parentTable] ?? 0)) {
      throw new RangeError("DeclSecurity parent must identify an existing TypeDef, MethodDef, or Assembly row");
    }
    if (!Number.isInteger(action) || action < 2 || action > 14) {
      throw new RangeError("DeclSecurity action must be a supported CLI security action");
    }
    if (!(permissionSet instanceof Uint8Array) || permissionSet.length === 0) {
      throw new TypeError("PermissionSet must be a non-empty Uint8Array");
    }
    const rows = this.tables.rows.get(14) ?? [];
    if (rows.length !== this.tables.counts[14] || rows.length >= 0xffffffff) {
      throw new RangeError("DeclSecurity row count is inconsistent or exceeds the metadata table limit");
    }
    const encodedParent = encodeCodedIndex(parentTable, parent.rid, "HasDeclSecurity");
    if (rows.some((row) => row.Parent.raw === encodedParent && row.Action === action)) {
      throw new FormatError("Duplicate DeclSecurity action for parent");
    }
    if ((this.tables.sorted & (1n << 14n)) !== 0n &&
        rows.at(-1)?.Parent.raw > encodedParent) {
      throw new UnsupportedFormatError(
        "DeclSecurity append would violate declared Parent ordering"
      );
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const blob = appendBlobHeap(heapStreams.get("#Blob") ?? new Uint8Array(), permissionSet);
    heapStreams.set("#Blob", blob.heap);
    const rid = rows.length + 1;
    rows.push({
      table: 14,
      tableName: metadataTableNames[14],
      rid,
      Action: action,
      Parent: {
        raw: encodedParent,
        target: { table: parentTable, tableName: metadataTableNames[parentTable], rid: parent.rid }
      },
      PermissionSet: blob.index
    });
    this.tables.rows.set(14, rows);
    this.tables.counts[14] = rid;
    this.tables.valid |= 1n << 14n;
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return rid;
  }

  replaceDeclSecurity(rid, { action, permissionSet } = {}) {
    this.#ensureEditable();
    const row = this.tables.row(14, rid);
    if (!Number.isInteger(rid) || rid < 1 || !row) {
      throw new RangeError(`Invalid DeclSecurity row ID ${rid}`);
    }
    const nextAction = action === undefined ? row.Action : action;
    const nextPermissionSet = permissionSet === undefined
      ? null
      : permissionSet;
    if (!Number.isInteger(nextAction) || nextAction < 2 || nextAction > 14) {
      throw new RangeError("DeclSecurity action must be a supported CLI security action");
    }
    if (nextPermissionSet !== null &&
        (!(nextPermissionSet instanceof Uint8Array) || nextPermissionSet.length === 0)) {
      throw new TypeError("PermissionSet must be a non-empty Uint8Array");
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
    const rows = this.tables.rows.get(14) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length ||
        rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid DeclSecurity row ID ${rid}`);
    }
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[14] = rows.length;
    this.tables.rows.set(14, rows);
    this._metadataDirty = true;
    return this;
  }

  addMethod({ owner, name, flags, implFlags = 0, signature, body: bodyBytes }) {
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    const ownerType = this.types[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !ownerType) {
      throw new RangeError("Method owner must identify an existing TypeDef");
    }
    if (ownerType.rid !== this.types.at(-1)?.rid) {
      throw new UnsupportedFormatError("Methods can only be appended to the last TypeDef row");
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
    if (methodRows.length !== this.tables.counts[6] || methodRows.length !== this.methods.length ||
        methodRows.length >= 0x00ffffff) {
      throw new RangeError("MethodDef row count is inconsistent or exceeds the metadata token range");
    }
    const pointerRows = getBijectivePointerRows(this, 5, 6, "Method");
    const parameterRows = this.tables.rows.get(8) ?? [];
    if (parameterRows.length !== this.tables.counts[8]) {
      throw new FormatError("Param row count is inconsistent with the metadata table header");
    }
    const parameterPointerRows = getBijectivePointerRows(this, 7, 8, "Param");
    const rid = methodRows.length + 1;
    if (hasBody) {
      parsedBody = validateNewMethodBody(
        this, bodyBytes, ownerType, rid, parsedSignature.genericParameterCount ?? 0
      );
    }
    const parameterListTable = parameterPointerRows ? 7 : 8;
    const parameterListRid = (parameterPointerRows?.length ?? parameterRows.length) + 1;

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
    methodRows.push(row);
    this.tables.rows.set(6, methodRows);
    this.tables.counts[6] = rid;
    this.tables.valid |= 1n << 6n;
    if (pointerRows) {
      const pointerRid = pointerRows.length + 1;
      pointerRows.push({
        table: 5,
        tableName: metadataTableNames[5],
        rid: pointerRid,
        Method: { raw: rid, table: 6, tableName: metadataTableNames[6], rid }
      });
      this.tables.rows.set(5, pointerRows);
      this.tables.counts[5] = pointerRid;
    }
    this.methods.push(method);
    if (parsedBody) {
      this._addedMethodBodies.set(rid, bodyBytes.slice());
      this._bodyCache.set(rid, parsedBody);
    }
    ownerType.methodRids.push(rid);
    ownerType.methods.push(method);
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return 0x06000000 + rid;
  }

  removeMethod(rid) {
    this.#ensureEditable();
    if (this._structuralBodies.size > 0) {
      throw new UnsupportedFormatError("Method removal cannot be combined with structural method edits");
    }
    this.#ensureTokenRemappingSafe("MethodDef");
    const rows = this.tables.rows.get(6) ?? [];
    if (rows.length !== this.tables.counts[6] || rows.length !== this.methods.length) {
      throw new FormatError("MethodDef row count is inconsistent with the metadata table header");
    }
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid MethodDef row ID ${rid}`);
    }
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
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 6 ? owner.rid : 0;
    const method = this.methods[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !method) {
      throw new RangeError("Param owner must identify an existing MethodDef");
    }
    if (method.rid !== this.methods.at(-1)?.rid) {
      throw new UnsupportedFormatError("Params can only be appended to the last MethodDef row");
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
    const lastSequence = method.parameters.at(-1)?.sequence ?? -1;
    if (sequence <= lastSequence) {
      throw new UnsupportedFormatError("Param append must preserve the method's sequence order");
    }

    const rows = this.tables.rows.get(8) ?? [];
    if (rows.length !== this.tables.counts[8] || rows.length >= 0xffffffff) {
      throw new RangeError("Param row count is inconsistent or exceeds the metadata table limit");
    }
    const pointerPresent = (this.tables.valid & (1n << 7n)) !== 0n;
    const pointerRows = this.tables.rows.get(7) ?? [];
    if (pointerPresent) {
      const pointedRids = pointerRows.map((pointer) => pointer.Param?.rid);
      if (pointerRows.length !== this.tables.counts[7] ||
          pointerRows.length !== rows.length ||
          pointedRids.some((paramRid) => !Number.isInteger(paramRid) || paramRid < 1 ||
            paramRid > rows.length) ||
          new Set(pointedRids).size !== rows.length) {
        throw new UnsupportedFormatError("ParamPtr editing requires a one-to-one ParamPtr table");
      }
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    heapStreams.set("#Strings", stringHeap.heap);
    const rid = rows.length + 1;
    rows.push({
      table: 8,
      tableName: metadataTableNames[8],
      rid,
      Flags: flags,
      Sequence: sequence,
      Name: stringHeap.index
    });
    this.tables.rows.set(8, rows);
    this.tables.counts[8] = rid;
    this.tables.valid |= 1n << 8n;
    if (pointerPresent) {
      const pointerRid = pointerRows.length + 1;
      pointerRows.push({
        table: 7,
        tableName: metadataTableNames[7],
        rid: pointerRid,
        Param: { raw: rid, table: 8, tableName: metadataTableNames[8], rid }
      });
      this.tables.rows.set(7, pointerRows);
      this.tables.counts[7] = pointerRid;
    }
    method.parameterRids.push(rid);
    method.parameters.push({ rid, flags, sequence, name });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return rid;
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
    const assignments = [];
    let offset = 0;
    for (let index = 0; index < definition.owners.length; index++) {
      const owner = definition.owners[index];
      const oldGroup = ownerGroups[index];
      const nextGroup = newRids.slice(offset, offset + oldGroup.length);
      offset += oldGroup.length;
      const oldSet = new Set(oldGroup);
      if (nextGroup.some((rid) => !oldSet.has(rid))) {
        throw new UnsupportedFormatError("Pointer reordering cannot change row ownership");
      }
      const recordsByRid = new Map(owner[definition.records].map((record) => [record.rid, record]));
      const nextRecords = nextGroup.map((rid) => recordsByRid.get(rid));
      if (nextRecords.some((record) => !record)) {
        throw new FormatError(`${metadataTableNames[definition.targetTableId]} ownership has no semantic record`);
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
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    const ownerType = this.types[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !ownerType) {
      throw new RangeError("Field owner must identify an existing TypeDef");
    }
    if (ownerType.rid !== this.types.at(-1)?.rid) {
      throw new UnsupportedFormatError("Fields can only be appended to the last TypeDef row");
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
    if (fieldRows.length !== this.tables.counts[4] ||
        fieldRows.length >= 0x00ffffff) {
      throw new RangeError("Field token row ID exceeds 24-bit range or table counts are inconsistent");
    }
    const pointerPresent = (this.tables.valid & (1n << 3n)) !== 0n;
    const pointerRows = this.tables.rows.get(3) ?? [];
    if (pointerPresent) {
      const pointedRids = pointerRows.map((pointer) => pointer.Field?.rid);
      if (pointerRows.length !== fieldRows.length ||
          pointedRids.some((fieldRid) => !Number.isInteger(fieldRid) || fieldRid < 1 ||
            fieldRid > fieldRows.length) ||
          new Set(pointedRids).size !== fieldRows.length) {
        throw new UnsupportedFormatError("FieldPtr editing requires a one-to-one FieldPtr table");
      }
    }
    const rid = fieldRows.length + 1;
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
    fieldRows.push(fieldRow);
    this.tables.rows.set(4, fieldRows);
    this.tables.valid |= 1n << 4n;
    this.tables.counts[4] = rid;
    if (pointerPresent) {
      const pointerRid = pointerRows.length + 1;
      pointerRows.push({
        table: 3,
        tableName: metadataTableNames[3],
        rid: pointerRid,
        Field: { raw: rid, table: 4, tableName: metadataTableNames[4], rid }
      });
      this.tables.rows.set(3, pointerRows);
      this.tables.counts[3] = pointerRid;
    }
    ownerType.fieldRids.push(rid);
    ownerType.fields.push({ rid, flags, name, signature: signature.slice() });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return 0x04000000 + rid;
  }

  addMethodSemantics({ methodRid, association, semantics }) {
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
    if (rows.length !== (this.tables.counts[24] ?? 0) || rows.length >= 0xffffffff) {
      throw new RangeError("MethodSemantics row count is inconsistent or exceeds the metadata table limit");
    }
    if (rows.some((row) => row.Association.raw === associationRaw && row.Semantics === semantics)) {
      throw new FormatError("MethodSemantics association already has this semantic");
    }
    if ((this.tables.sorted & (1n << 24n)) !== 0n && rows.at(-1)?.Association.raw > associationRaw) {
      throw new UnsupportedFormatError("MethodSemantics append would violate declared Association ordering");
    }
    const rid = rows.length + 1;
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
    const stagedRows = [...rows, candidate];
    validateMethodSemanticsRecord(
      this, semantics, methodRid, associationTable, association.rid, stagedRows
    );
    rows.push(candidate);
    this.tables.rows.set(24, rows);
    this.tables.counts[24] = rid;
    this.tables.valid |= 1n << 24n;
    this._metadataDirty = true;
    return rid;
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
    const rows = this.tables.rows.get(24) ?? [];
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length || rows[rid - 1]?.rid !== rid) {
      throw new RangeError(`Invalid MethodSemantics row ID ${rid}`);
    }
    rows.splice(rid - 1, 1);
    for (let index = rid - 1; index < rows.length; index++) rows[index].rid = index + 1;
    this.tables.counts[24] = rows.length;
    this.tables.rows.set(24, rows);
    if (rows.length === 0) this.tables.valid &= ~(1n << 24n);
    this._metadataDirty = true;
    return this;
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
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    const ownerType = this.types[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !ownerType) {
      throw new RangeError("Property owner must identify an existing TypeDef");
    }
    if (ownerType.rid !== this.types.at(-1)?.rid) {
      throw new UnsupportedFormatError("Properties can only be appended to the last TypeDef row");
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
    const maps = this.tables.rows.get(21) ?? [];
    if (rows.length !== this.tables.counts[23] || rows.length >= 0xffffffff ||
        maps.length !== this.tables.counts[21]) {
      throw new FormatError("Property or PropertyMap row count is inconsistent with the metadata header");
    }
    const pointerRows = getBijectivePointerRows(this, 22, 23, "Property");
    const listCount = pointerRows?.length ?? rows.length;
    for (let index = 1; index < maps.length; index++) {
      if (maps[index - 1].Parent.rid >= maps[index].Parent.rid) {
        throw new FormatError("PropertyMap rows are not strictly ordered by TypeDef");
      }
    }
    const ownerMap = maps.find((row) => row.Parent.rid === ownerRid);
    if (ownerMap) {
      const ownerMapIndex = maps.indexOf(ownerMap);
      const endRid = maps[ownerMapIndex + 1]?.PropertyList.rid ?? listCount + 1;
      const ownedRids = pointerRows
        ? pointerRows.slice(ownerMap.PropertyList.rid - 1, endRid - 1)
          .map((pointer) => pointer.Property.rid)
        : Array.from(
          { length: Math.max(0, endRid - ownerMap.PropertyList.rid) },
          (_, index) => ownerMap.PropertyList.rid + index
        );
      if (endRid !== listCount + 1 ||
          ownedRids.length !== ownerType.propertyRids.length ||
          ownedRids.some((rid, index) => rid !== ownerType.propertyRids[index])) {
        throw new UnsupportedFormatError("Property append requires the last TypeDef's properties to be contiguous at the end");
      }
    } else if (ownerType.propertyRids.length !== 0) {
      throw new FormatError(`TypeDef row ${ownerRid} has properties without a PropertyMap row`);
    }
    if (!ownerMap && maps.at(-1)?.Parent.rid >= ownerRid) {
      throw new FormatError("Appending a PropertyMap row would violate TypeDef ordering");
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
    const rid = rows.length + 1;
    rows.push({
      table: 23,
      tableName: metadataTableNames[23],
      rid,
      Flags: flags,
      Name: stringHeap.index,
      Type: blobHeap.index
    });
    this.tables.rows.set(23, rows);
    this.tables.counts[23] = rid;
    this.tables.valid |= 1n << 23n;
    if (pointerRows) {
      const pointerRid = pointerRows.length + 1;
      pointerRows.push({
        table: 22,
        tableName: metadataTableNames[22],
        rid: pointerRid,
        Property: { raw: rid, table: 23, tableName: metadataTableNames[23], rid }
      });
      this.tables.rows.set(22, pointerRows);
      this.tables.counts[22] = pointerRid;
      this.tables.valid |= 1n << 22n;
    }
    if (!ownerMap) {
      const mapRid = maps.length + 1;
      const listTable = pointerRows ? 22 : 23;
      const listRid = pointerRows?.length ?? rid;
      maps.push({
        table: 21,
        tableName: metadataTableNames[21],
        rid: mapRid,
        Parent: { raw: ownerRid, table: 2, tableName: metadataTableNames[2], rid: ownerRid },
        PropertyList: {
          raw: listRid,
          table: listTable,
          tableName: metadataTableNames[listTable],
          rid: listRid
        }
      });
      this.tables.rows.set(21, maps);
      this.tables.counts[21] = mapRid;
      this.tables.valid |= 1n << 21n;
    }
    ownerType.propertyRids.push(rid);
    ownerType.properties.push({ rid, flags, name, signature: signature.slice() });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return rid;
  }

  addEvent({ owner, name, flags = 0, eventType }) {
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    const ownerType = this.types[ownerRid - 1];
    if (!Number.isInteger(ownerRid) || ownerRid < 1 || !ownerType) {
      throw new RangeError("Event owner must identify an existing TypeDef");
    }
    if (ownerType.rid !== this.types.at(-1)?.rid) {
      throw new UnsupportedFormatError("Events can only be appended to the last TypeDef row");
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
    const maps = this.tables.rows.get(18) ?? [];
    if (rows.length !== this.tables.counts[20] || rows.length >= 0xffffffff ||
        maps.length !== this.tables.counts[18]) {
      throw new FormatError("Event or EventMap row count is inconsistent with the metadata header");
    }
    const pointerRows = getBijectivePointerRows(this, 19, 20, "Event");
    const listCount = pointerRows?.length ?? rows.length;
    for (let index = 1; index < maps.length; index++) {
      if (maps[index - 1].Parent.rid >= maps[index].Parent.rid) {
        throw new FormatError("EventMap rows are not strictly ordered by TypeDef");
      }
    }
    const ownerMap = maps.find((row) => row.Parent.rid === ownerRid);
    if (ownerMap) {
      const ownerMapIndex = maps.indexOf(ownerMap);
      const endRid = maps[ownerMapIndex + 1]?.EventList.rid ?? listCount + 1;
      const ownedRids = pointerRows
        ? pointerRows.slice(ownerMap.EventList.rid - 1, endRid - 1)
          .map((pointer) => pointer.Event.rid)
        : Array.from(
          { length: Math.max(0, endRid - ownerMap.EventList.rid) },
          (_, index) => ownerMap.EventList.rid + index
        );
      if (endRid !== listCount + 1 ||
          ownedRids.length !== ownerType.eventRids.length ||
          ownedRids.some((rid, index) => rid !== ownerType.eventRids[index])) {
        throw new UnsupportedFormatError("Event append requires the last TypeDef's events to be contiguous at the end");
      }
    } else if (ownerType.eventRids.length !== 0) {
      throw new FormatError(`TypeDef row ${ownerRid} has events without an EventMap row`);
    }
    if (!ownerMap && maps.at(-1)?.Parent.rid >= ownerRid) {
      throw new FormatError("Appending an EventMap row would violate TypeDef ordering");
    }

    const heapStreams = new Map(
      [...(this._heapStreams ?? new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes]
      )))].map(([streamName, bytes]) => [streamName, bytes.slice()])
    );
    const stringHeap = appendStringHeap(heapStreams.get("#Strings") ?? new Uint8Array(), name);
    heapStreams.set("#Strings", stringHeap.heap);
    const rid = rows.length + 1;
    rows.push({
      table: 20,
      tableName: metadataTableNames[20],
      rid,
      EventFlags: flags,
      Name: stringHeap.index,
      EventType: { raw: encodeCodedIndex(typeTable, typeRid, "TypeDefOrRef"), target }
    });
    this.tables.rows.set(20, rows);
    this.tables.counts[20] = rid;
    this.tables.valid |= 1n << 20n;
    if (pointerRows) {
      const pointerRid = pointerRows.length + 1;
      pointerRows.push({
        table: 19,
        tableName: metadataTableNames[19],
        rid: pointerRid,
        Event: { raw: rid, table: 20, tableName: metadataTableNames[20], rid }
      });
      this.tables.rows.set(19, pointerRows);
      this.tables.counts[19] = pointerRid;
      this.tables.valid |= 1n << 19n;
    }
    if (!ownerMap) {
      const mapRid = maps.length + 1;
      const listTable = pointerRows ? 19 : 20;
      const listRid = pointerRows?.length ?? rid;
      maps.push({
        table: 18,
        tableName: metadataTableNames[18],
        rid: mapRid,
        Parent: { raw: ownerRid, table: 2, tableName: metadataTableNames[2], rid: ownerRid },
        EventList: {
          raw: listRid,
          table: listTable,
          tableName: metadataTableNames[listTable],
          rid: listRid
        }
      });
      this.tables.rows.set(18, maps);
      this.tables.counts[18] = mapRid;
      this.tables.valid |= 1n << 18n;
    }
    ownerType.eventRids.push(rid);
    ownerType.events.push({ rid, flags, name, eventType: target });
    this._heapStreams = heapStreams;
    this.#refreshHeaps();
    this._metadataDirty = true;
    return rid;
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
    this.#ensureEditable();
    const ownerRid = metadataTableId(owner?.table) === 2 ? owner.rid : 0;
    if (!Number.isInteger(ownerRid) || ownerRid < 1 ||
        ownerRid !== this.types.at(-1)?.rid) {
      throw new UnsupportedFormatError(
        "Interface implementations can only be appended to the last TypeDef row"
      );
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
    if ((this.tables.sorted & (1n << 9n)) !== 0n &&
        rows.at(-1)?.Class.rid > ownerRid) {
      throw new FormatError("Appending this InterfaceImpl would violate the table's sorted Class order");
    }
    const rid = rows.length + 1;
    const target = {
      table: interfaceTable,
      tableName: metadataTableNames[interfaceTable],
      rid: interfaceRid
    };
    rows.push({
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
    });
    this.tables.rows.set(9, rows);
    this.tables.counts[9] = rid;
    this.tables.valid |= 1n << 9n;
    this._metadataDirty = true;
    return rid;
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
      const typeRefOverride = { rid, name: nextName };
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

  addAssemblyProcessor({ processor }) {
    this.#ensureEditable();
    this.#validateAssemblyPlatformFields(33, { Processor: processor });
    return this.#appendMetadataRow(33, { Processor: processor });
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
    this.#removeMetadataRow(33, rid);
    return this;
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
    this.#removeMetadataRow(34, rid);
    return this;
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
    this.#removeMetadataRow(36, rid);
    return this;
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
    this.#removeMetadataRow(37, rid);
    return this;
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

  replaceTypeSpecSignature(rid, signature) {
    this.#ensureEditable();
    const row = this.tables.row(27, rid);
    const typeSpec = this.typeSpecs[rid - 1];
    if (!row || !typeSpec) throw new RangeError(`Invalid TypeSpec row ID ${rid}`);
    if (!(signature instanceof Uint8Array)) {
      throw new TypeError("TypeSpec signature must be a Uint8Array");
    }
    const parsedSignature = parseTypeSignature(signature, { counts: this.tables.counts });
    validateTypeSpecDefinitions(this, parsedSignature);
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
    this.#ensureTokenRemappingSafe("StandAloneSig");
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
    this.#ensureEditable();
    if (!Number.isInteger(ownerRid) || ownerRid < 1 ||
        ownerRid > (this.tables.counts[42] ?? 0)) {
      throw new RangeError("GenericParamConstraint owner references a missing GenericParam row");
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
    if ((this.tables.sorted & (1n << 44n)) !== 0n && constraintRows.length > 0 &&
        constraintRows.at(-1).Owner.rid > ownerRid) {
      throw new FormatError("Appending this GenericParamConstraint would violate the table's sorted Owner order");
    }
    const rid = constraintRows.length + 1;
    if (rid > 0xffffffff) throw new RangeError("GenericParamConstraint row ID exceeds 32-bit range");
    const target = {
      table: constraintTable,
      tableName: metadataTableNames[constraintTable],
      rid: constraint.rid
    };
    constraintRows.push({
      table: 44,
      tableName: metadataTableNames[44],
      rid,
      Owner: { rid: ownerRid },
      Constraint: { raw: constraintValue, target }
    });
    this.tables.rows.set(44, constraintRows);
    this.tables.valid |= 1n << 44n;
    this.tables.counts[44] = rid;
    this.genericParamConstraints.push({ rid, ownerRid, constraint: target });
    this._metadataDirty = true;
    return rid;
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
    if (genericParamRows.length + 1 > 0x00ffffff) {
      throw new RangeError("GenericParam token row ID exceeds 24-bit range");
    }

    const rid = genericParamRows.length + 1;
    if (!this._heapStreams) {
      this._heapStreams = new Map([...this.metadataRoot.streams].map(([streamName, stream]) =>
        [streamName, stream.bytes.slice()]
      ));
    }
    const stringHeap = appendStringHeap(this._heapStreams.get("#Strings") ?? new Uint8Array(), name);
    this._heapStreams.set("#Strings", stringHeap.heap);
    this.#refreshHeaps();
    genericParamRows.push({
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
    });
    this.tables.rows.set(42, genericParamRows);
    this.tables.valid |= 1n << 42n;
    this.tables.sorted |= 1n << 42n;
    this.tables.counts[42] = rid;
    const parameter = {
      rid,
      number: selectedNumber,
      flags,
      owner: { table: ownerTable, tableName: metadataTableNames[ownerTable], rid: owner.rid },
      name
    };
    this.genericParams.push(parameter);
    if (ownerTable === 2) {
      this.types[owner.rid - 1].genericParams.push(parameter);
    } else {
      this.methods[owner.rid - 1].genericParams.push(parameter);
    }
    this._metadataDirty = true;
    return 0x2a000000 + rid;
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
    const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
    for (const streamName of this.metadataRoot.streams.keys()) {
      if (!supportedStreams.has(streamName)) {
        throw new UnsupportedFormatError(
          `Cannot remove ${metadataTableNames[tableId]} rows with unrecognized metadata stream ${streamName}`
        );
      }
    }
    const rows = this.tables.rows.get(tableId) ?? [];
    if (rows.length !== (this.tables.counts[tableId] ?? 0)) {
      throw new FormatError(`${metadataTableNames[tableId]} row count is inconsistent with the metadata table header`);
    }
    if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
      throw new RangeError(`Invalid ${metadataTableNames[tableId]} row ID ${rid}`);
    }
    rows.splice(rid - 1, 1);
    rows.forEach((row, index) => {
      row.rid = index + 1;
    });
    this.tables.rows.set(tableId, rows);
    this.tables.counts[tableId] = rows.length;
    if (rows.length === 0) this.tables.valid &= ~(1n << BigInt(tableId));
    this._metadataDirty = true;
  }

  #ensureTokenRemappingSafe(tableName) {
    if (this.#hasDebugDirectory) {
      throw new UnsupportedFormatError(
        `${tableName} token remapping is unsupported while a PE debug directory is present`
      );
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
    const structurallyDirty = this._structuralBodies.size > 0 ||
      this._addedMethodBodies.size > 0 || this._metadataDirty ||
      this._resourceEdits.size > 0 || this._clearResourcesDirectory;
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
