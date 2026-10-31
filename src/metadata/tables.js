import { BinaryReader } from "../binary/reader.js";
import { FormatError, UnsupportedFormatError } from "../binary/errors.js";

const tableNames = [
  "Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr", "MethodDef", "ParamPtr", "Param",
  "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute", "FieldMarshal", "DeclSecurity", "ClassLayout",
  "FieldLayout", "StandAloneSig", "EventMap", "EventPtr", "Event", "PropertyMap", "PropertyPtr", "Property",
  "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA", "ENCLog", "ENCMap",
  "Assembly", "AssemblyProcessor", "AssemblyOS", "AssemblyRef", "AssemblyRefProcessor", "AssemblyRefOS",
  "File", "ExportedType", "ManifestResource", "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint",
  null, null, null,
  "Document", "MethodDebugInformation", "LocalScope", "LocalVariable", "LocalConstant", "ImportScope",
  "StateMachineMethod", "CustomDebugInformation"
];

const codedIndexes = {
  TypeDefOrRef: { bits: 2, tables: [2, 1, 27] },
  HasConstant: { bits: 2, tables: [4, 8, 23] },
  HasCustomAttribute: { bits: 5, tables: [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43] },
  HasFieldMarshal: { bits: 1, tables: [4, 8] },
  HasDeclSecurity: { bits: 2, tables: [2, 6, 32] },
  MemberRefParent: { bits: 3, tables: [2, 1, 26, 6, 27] },
  HasSemantics: { bits: 1, tables: [20, 23] },
  MethodDefOrRef: { bits: 1, tables: [6, 10] },
  MemberForwarded: { bits: 1, tables: [4, 6] },
  Implementation: { bits: 2, tables: [38, 35, 39] },
  CustomAttributeType: { bits: 3, tables: [null, null, 6, 10, null] },
  ResolutionScope: { bits: 2, tables: [0, 26, 35, 1] },
  TypeOrMethodDef: { bits: 1, tables: [2, 6] },
  HasCustomDebugInformation: {
    bits: 5,
    tables: [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42,
      44, 43, 48, 50, 51, 52, 53]
  }
};

const schemas = [
  [["u2", "Generation"], ["str", "Name"], ["guid", "Mvid"], ["guid", "EncId"], ["guid", "EncBaseId"]],
  [["coded", "ResolutionScope"], ["str", "TypeName"], ["str", "TypeNamespace"]],
  [["u4", "Flags"], ["str", "TypeName"], ["str", "TypeNamespace"], ["coded", "TypeDefOrRef", "Extends"], ["table", 4, "FieldList", 3], ["table", 6, "MethodList", 5]],
  [["table", 4, "Field"]],
  [["u2", "Flags"], ["str", "Name"], ["blob", "Signature"]],
  [["table", 6, "Method"]],
  [["u4", "RVA"], ["u2", "ImplFlags"], ["u2", "Flags"], ["str", "Name"], ["blob", "Signature"], ["table", 8, "ParamList", 7]],
  [["table", 8, "Param"]],
  [["u2", "Flags"], ["u2", "Sequence"], ["str", "Name"]],
  [["table", 2, "Class"], ["coded", "TypeDefOrRef", "Interface"]],
  [["coded", "MemberRefParent", "Class"], ["str", "Name"], ["blob", "Signature"]],
  [["u1", "Type"], ["u1", "Padding"], ["coded", "HasConstant", "Parent"], ["blob", "Value"]],
  [["coded", "HasCustomAttribute", "Parent"], ["coded", "CustomAttributeType", "Type"], ["blob", "Value"]],
  [["coded", "HasFieldMarshal", "Parent"], ["blob", "NativeType"]],
  [["u2", "Action"], ["coded", "HasDeclSecurity", "Parent"], ["blob", "PermissionSet"]],
  [["u2", "PackingSize"], ["u4", "ClassSize"], ["table", 2, "Parent"]],
  [["u4", "Offset"], ["table", 4, "Field"]],
  [["blob", "Signature"]],
  [["table", 2, "Parent"], ["table", 20, "EventList", 19]],
  [["table", 20, "Event"]],
  [["u2", "EventFlags"], ["str", "Name"], ["coded", "TypeDefOrRef", "EventType"]],
  [["table", 2, "Parent"], ["table", 23, "PropertyList", 22]],
  [["table", 23, "Property"]],
  [["u2", "Flags"], ["str", "Name"], ["blob", "Type"]],
  [["u2", "Semantics"], ["table", 6, "Method"], ["coded", "HasSemantics", "Association"]],
  [["table", 2, "Class"], ["coded", "MethodDefOrRef", "MethodBody"], ["coded", "MethodDefOrRef", "MethodDeclaration"]],
  [["str", "Name"]],
  [["blob", "Signature"]],
  [["u2", "MappingFlags"], ["coded", "MemberForwarded", "MemberForwarded"], ["str", "ImportName"], ["table", 26, "ImportScope"]],
  [["u4", "RVA"], ["table", 4, "Field"]],
  [["u4", "Token"], ["u4", "FuncCode"]],
  [["u4", "Token"]],
  [["u4", "HashAlgId"], ["u2", "MajorVersion"], ["u2", "MinorVersion"], ["u2", "BuildNumber"], ["u2", "RevisionNumber"], ["u4", "Flags"], ["blob", "PublicKey"], ["str", "Name"], ["str", "Culture"]],
  [["u4", "Processor"]],
  [["u4", "OSPlatformId"], ["u4", "OSMajorVersion"], ["u4", "OSMinorVersion"]],
  [["u2", "MajorVersion"], ["u2", "MinorVersion"], ["u2", "BuildNumber"], ["u2", "RevisionNumber"], ["u4", "Flags"], ["blob", "PublicKeyOrToken"], ["str", "Name"], ["str", "Culture"], ["blob", "HashValue"]],
  [["u4", "Processor"], ["table", 35, "AssemblyRef"]],
  [["u4", "OSPlatformId"], ["u4", "OSMajorVersion"], ["u4", "OSMinorVersion"], ["table", 35, "AssemblyRef"]],
  [["u4", "Flags"], ["str", "Name"], ["blob", "HashValue"]],
  [["u4", "Flags"], ["u4", "TypeDefId"], ["str", "TypeName"], ["str", "TypeNamespace"], ["coded", "Implementation"]],
  [["u4", "Offset"], ["u4", "Flags"], ["str", "Name"], ["coded", "Implementation"]],
  [["table", 2, "NestedClass"], ["table", 2, "EnclosingClass"]],
  [["u2", "Number"], ["u2", "Flags"], ["coded", "TypeOrMethodDef", "Owner"], ["str", "Name"]],
  [["coded", "MethodDefOrRef", "Method"], ["blob", "Instantiation"]],
  [["table", 42, "Owner"], ["coded", "TypeDefOrRef", "Constraint"]],
  null, null, null,
  [["blob", "Name"], ["guid", "HashAlgorithm"], ["blob", "Hash"], ["guid", "Language"]],
  [["table", 48, "Document"], ["blob", "SequencePoints"]],
  [["table", 6, "Method"], ["table", 53, "ImportScope"], ["table", 51, "VariableList", 51],
    ["table", 52, "ConstantList", 52], ["u4", "StartOffset"], ["u4", "Length"]],
  [["u2", "Attributes"], ["u2", "Index"], ["str", "Name"]],
  [["str", "Name"], ["blob", "Signature"]],
  [["table", 53, "Parent"], ["blob", "Imports"]],
  [["table", 6, "MoveNextMethod"], ["table", 6, "KickoffMethod"]],
  [["coded", "HasCustomDebugInformation", "Parent"], ["guid", "Kind"], ["blob", "Value"]]
];

const tableIdByName = new Map(tableNames.flatMap((name, id) => name === null ? [] : [[name, id]]));
const pointerTables = new Map([[3, 4], [5, 6], [7, 8], [19, 20], [22, 23]]);
const listColumns = new Set([
  "FieldList", "MethodList", "ParamList", "EventList", "PropertyList", "VariableList", "ConstantList"
]);

function fieldWidth(field, counts, heapSizes, present) {
  const [kind, value, , pointer] = field;
  if (kind === "u1") return 1;
  if (kind === "u2") return 2;
  if (kind === "u4") return 4;
  if (kind === "str") return (heapSizes & 1) !== 0 ? 4 : 2;
  if (kind === "guid") return (heapSizes & 2) !== 0 ? 4 : 2;
  if (kind === "blob") return (heapSizes & 4) !== 0 ? 4 : 2;
  if (kind === "table") {
    const table = pointer !== undefined && present.has(pointer) ? pointer : value;
    return tableIndexWidth(counts[table]);
  }
  const definition = codedIndexes[value];
  if (!definition) throw new FormatError(`Unknown coded-index kind ${value}`, { context: "metadata tables" });
  const maxRows = Math.max(0, ...definition.tables.filter((id) => id !== null).map((id) => counts[id] || 0));
  return maxRows < 2 ** (16 - definition.bits) ? 2 : 4;
}

function readIndex(reader, width) {
  if (width === 1) return reader.u1();
  return width === 2 ? reader.u2() : reader.u4();
}

export function decodeCodedIndex(value, kind) {
  const definition = codedIndexes[kind];
  if (!definition) throw new FormatError(`Unknown coded-index kind ${kind}`);
  const mask = (1 << definition.bits) - 1;
  const tag = value & mask;
  const table = definition.tables[tag];
  const rid = value >>> definition.bits;
  if (table === null || table === undefined) {
    throw new FormatError(`Invalid ${kind} tag ${tag}`, { context: "metadata tables" });
  }
  if (rid === 0 && value !== 0) {
    throw new FormatError(`Invalid zero row ID in ${kind}`, { context: "metadata tables" });
  }
  return rid === 0 ? null : { table, tableName: tableNames[table], rid };
}

export function encodeCodedIndex(table, rid, kind) {
  const definition = codedIndexes[kind];
  if (!definition) throw new FormatError(`Unknown coded-index kind ${kind}`);
  const maxRid = Math.floor(0xffffffff / (2 ** definition.bits));
  if (!Number.isInteger(rid) || rid < 0 || rid > maxRid) throw new RangeError("Invalid metadata row ID");
  if (rid === 0) return 0;
  const tag = definition.tables.indexOf(table);
  if (tag < 0) throw new FormatError(`Table ${table} is not valid for ${kind}`);
  return rid * (2 ** definition.bits) + tag;
}

export function codedIndexWidth(kind, counts) {
  const definition = codedIndexes[kind];
  if (!definition) throw new FormatError(`Unknown coded-index kind ${kind}`);
  const maxRows = Math.max(0, ...definition.tables.filter((id) => id !== null).map((id) => counts[id] || 0));
  return maxRows < 2 ** (16 - definition.bits) ? 2 : 4;
}

export function tableIndexWidth(rowCount) {
  if (!Number.isInteger(rowCount) || rowCount < 0 || rowCount > 0xffffffff) {
    throw new RangeError("Invalid metadata table row count");
  }
  return rowCount < 0x10000 ? 2 : 4;
}

export function parseTablesStream(stream, externalCounts = null) {
  const reader = new BinaryReader(stream.bytes, {
    baseOffset: stream.offset,
    context: `${stream.name} tables stream`
  });
  const reserved = reader.u4();
  const majorVersion = reader.u1();
  const minorVersion = reader.u1();
  const heapSizes = reader.u1();
  if ((heapSizes & 0xf8) !== 0) {
    throw new FormatError("Metadata heap-size flags contain reserved bits", {
      offset: reader.absoluteOffset - 1,
      context: `${stream.name} tables stream`
    });
  }
  const reservedByte = reader.u1();
  if (reserved !== 0 || reservedByte !== 1) {
    throw new FormatError("Metadata tables header has invalid reserved fields", {
      offset: reader.absoluteOffset - 8,
      context: `${stream.name} tables stream`
    });
  }
  const valid = reader.u8();
  const sorted = reader.u8();
  const present = new Set();
  const counts = Array.from({ length: 64 }, (_, id) => externalCounts?.[id] ?? 0);
  for (let id = 0; id < 64; id++) {
    if ((valid & (1n << BigInt(id))) === 0n) continue;
    if (id >= schemas.length || !schemas[id]) {
      throw new UnsupportedFormatError(`Metadata table 0x${id.toString(16).padStart(2, "0")} has no supported schema`, {
        offset: reader.absoluteOffset,
        context: `${stream.name} tables stream`
      });
    }
    present.add(id);
    counts[id] = reader.u4();
  }

  const rows = new Map();
  const tableDataOffset = reader.absoluteOffset;
  for (const id of [...present].sort((a, b) => a - b)) {
    const schema = schemas[id];
    const rowCount = counts[id];
    const rowSize = schema.reduce((size, field) => size + fieldWidth(field, counts, heapSizes, present), 0);
    if (rowSize === 0 || rowCount > Math.floor(reader.remaining / rowSize)) {
      throw new FormatError(`Table ${tableNames[id]} row count exceeds the remaining stream`, {
        offset: reader.absoluteOffset,
        context: `${stream.name} tables stream`
      });
    }
    const tableRows = [];
    const previousListIndexes = new Map();
    for (let rid = 1; rid <= rowCount; rid++) {
      const row = { table: id, tableName: tableNames[id], rid };
      for (const field of schema) {
        const [kind, value, name, pointer] = field;
        const width = fieldWidth(field, counts, heapSizes, present);
        const raw = readIndex(reader, width);
        if (kind === "coded") {
          const target = decodeCodedIndex(raw, value);
          if (target && target.rid > counts[target.table]) {
            throw new FormatError(`${value} references missing ${target.tableName} row ${target.rid}`, {
              offset: reader.absoluteOffset - width,
              context: `${stream.name} tables stream`
            });
          }
          row[name ?? value] = { raw, target };
        } else if (kind === "table") {
          const targetTable = pointer !== undefined && present.has(pointer) ? pointer : value;
          const isList = listColumns.has(name);
          const maxRid = counts[targetTable] + (isList ? 1 : 0);
          if (isList && raw === 0) {
            throw new FormatError(`${name} must reference a one-based list position`, {
              offset: reader.absoluteOffset - width,
              context: `${stream.name} tables stream`
            });
          }
          if (raw > maxRid) {
            throw new FormatError(`${name} references missing ${tableNames[targetTable]} row ${raw}`, {
              offset: reader.absoluteOffset - width,
              context: `${stream.name} tables stream`
            });
          }
          const previous = previousListIndexes.get(name);
          if (isList && previous !== undefined && raw < previous) {
            throw new FormatError(`${name} indexes are not ordered`, {
              offset: reader.absoluteOffset - width,
              context: `${stream.name} tables stream`
            });
          }
          if (isList) previousListIndexes.set(name, raw);
          row[name] = { raw, table: targetTable, tableName: tableNames[targetTable], rid: raw };
        } else {
          row[name ?? value] = raw;
        }
      }
      tableRows.push(row);
    }
    rows.set(id, tableRows);
  }

  for (const row of rows.get(42) ?? []) {
    if (!row.Owner.target) {
      throw new FormatError(`GenericParam row ${row.rid} has a nil Owner`, {
        context: `${stream.name} tables stream`
      });
    }
    if ((row.Flags & ~0x1f) !== 0 || (row.Flags & 0x03) === 0x03 ||
        (row.Flags & 0x18) === 0x18) {
      throw new FormatError(`GenericParam row ${row.rid} contains invalid flags`, {
        context: `${stream.name} tables stream`
      });
    }
    if ((row.Flags & 0x03) !== 0 && row.Owner.target.table === 6) {
      throw new FormatError(`GenericParam row ${row.rid} gives variance to a method parameter`, {
        context: `${stream.name} tables stream`
      });
    }
  }
  for (const row of rows.get(44) ?? []) {
    if (row.Owner.rid === 0 || !row.Constraint.target) {
      throw new FormatError(`GenericParamConstraint row ${row.rid} has a nil Owner or Constraint`, {
        context: `${stream.name} tables stream`
      });
    }
  }
  const sortedKeys = new Map([
    [1, (row) => [row.ResolutionScope.raw]],
    [9, (row) => [row.Class.rid]],
    [10, (row) => [row.Class.raw]],
    [11, (row) => [row.Parent.raw]],
    [12, (row) => [row.Parent.raw]],
    [13, (row) => [row.Parent.raw]],
    [14, (row) => [row.Parent.raw]],
    [15, (row) => [row.Parent.rid]],
    [16, (row) => [row.Field.rid]],
    [18, (row) => [row.Parent.rid]],
    [21, (row) => [row.Parent.rid]],
    [24, (row) => [row.Association.raw]],
    [25, (row) => [row.Class.rid]],
    [28, (row) => [row.MemberForwarded.raw]],
    [29, (row) => [row.Field.rid]],
    [41, (row) => [row.NestedClass.rid]],
    [42, (row) => [row.Owner.raw, row.Number]],
    [43, (row) => [row.Method.raw]],
    [44, (row) => [row.Owner.rid]]
  ]);
  const uniqueKeys = new Map([
    [9, (row) => [row.Class.rid, row.Interface.raw]],
    [11, (row) => [row.Parent.raw]],
    [13, (row) => [row.Parent.raw]],
    [14, (row) => [row.Parent.raw, row.Action]],
    [15, (row) => [row.Parent.rid]],
    [16, (row) => [row.Field.rid]],
    [18, (row) => [row.Parent.rid]],
    [21, (row) => [row.Parent.rid]],
    [28, (row) => [row.MemberForwarded.raw]],
    [29, (row) => [row.Field.rid]],
    [41, (row) => [row.NestedClass.rid]],
    [42, (row) => [row.Owner.raw, row.Number]],
    [44, (row) => [row.Owner.rid, row.Constraint.raw]]
  ]);
  for (const [id, keyOf] of uniqueKeys) {
    const seen = new Set();
    for (const row of rows.get(id) ?? []) {
      const key = JSON.stringify(keyOf(row));
      if (seen.has(key)) {
        throw new FormatError(`${tableNames[id]} rows contain a duplicate key`, {
          context: `${stream.name} tables stream`
        });
      }
      seen.add(key);
    }
  }
  for (const [id, keyOf] of sortedKeys) {
    if ((sorted & (1n << BigInt(id))) === 0n) continue;
    let previous = null;
    for (const row of rows.get(id) ?? []) {
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
        throw new FormatError(`${tableNames[id]} rows are not ordered by their sorted key`, {
          context: `${stream.name} tables stream`
        });
      }
      previous = current;
    }
  }

  return {
    majorVersion,
    minorVersion,
    reserved,
    reservedByte,
    heapSizes,
    valid,
    sorted,
    counts,
    rows,
    tableDataOffset,
    row(idOrName, rid) {
      const id = typeof idOrName === "string" ? tableIdByName.get(idOrName) : idOrName;
      if (!Number.isInteger(id) || !Number.isInteger(rid) || rid < 1) return null;
      return rows.get(id)?.[rid - 1] ?? null;
    },
    get(idOrName) {
      const id = typeof idOrName === "string" ? tableIdByName.get(idOrName) : idOrName;
      return Number.isInteger(id) ? rows.get(id) ?? [] : [];
    }
  };
}

export const metadataTableNames = tableNames;
export const metadataTableSchemas = schemas;

export function metadataTableId(nameOrId) {
  if (Number.isInteger(nameOrId)) return nameOrId;
  return tableIdByName.get(nameOrId) ?? -1;
}
