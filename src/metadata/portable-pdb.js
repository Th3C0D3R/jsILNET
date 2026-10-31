import { inflateRawSync } from "node:zlib";
import { BinaryReader, readCompressedInt, readCompressedUInt } from "../binary/reader.js";
import { FormatError, UnsupportedFormatError } from "../binary/errors.js";

const maxEmbeddedSourceSize = 0x10000000;
const embeddedSourceKind = "0e8a571b-6926-466e-b4ad-8ab04611f5fe";
const sourceLinkKind = "cc110556-a091-4d38-9fec-25ab9a351a6a";

export function validatePortablePdbAssemblyReferences(pdb, assemblyRowCounts) {
  if (!pdb || !(pdb.rowCounts instanceof Map) || !Array.isArray(assemblyRowCounts)) {
    throw new TypeError("Portable PDB validation requires parsed PDB data and assembly row counts");
  }
  for (const [table, count] of pdb.rowCounts) {
    if (assemblyRowCounts[table] !== count) {
      throw new FormatError(
        `Portable PDB row count for type-system table ${table} does not match assembly metadata`
      );
    }
  }
  if (pdb.entryPointToken !== 0 &&
      (pdb.entryPointToken & 0x00ffffff) > assemblyRowCounts[6]) {
    throw new FormatError("Portable PDB entry point references a missing MethodDef row");
  }
}

function decodeUtf8(bytes, context) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new FormatError(`Invalid UTF-8 data: ${error.message}`, { context });
  }
}

function formatGuid(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const first = view.getUint32(0, true).toString(16).padStart(8, "0");
  const second = view.getUint16(4, true).toString(16).padStart(4, "0");
  const third = view.getUint16(6, true).toString(16).padStart(4, "0");
  const tail = [...bytes.subarray(8)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${first}-${second}-${third}-${tail.slice(0, 4)}-${tail.slice(4)}`;
}

export function decodePortablePdbCustomDebugInformation(row, heaps) {
  const kindBytes = heaps.getGuid(row.Kind);
  if (!kindBytes) throw new FormatError("Portable PDB custom debug information has a nil Kind");
  const kind = formatGuid(kindBytes);
  const value = heaps.getBlob(row.Value);
  if (kind === embeddedSourceKind) {
    if (row.Parent.target?.table !== 48) {
      throw new FormatError("EmbeddedSource custom debug information must belong to a Document");
    }
    if (value.length < 4) {
      throw new FormatError("EmbeddedSource custom debug information is truncated");
    }
    const format = new DataView(value.buffer, value.byteOffset, 4).getInt32(0, true);
    if (format < 0) {
      throw new UnsupportedFormatError("EmbeddedSource uses a reserved content format");
    }
    const content = value.subarray(4);
    if (format === 0) return { kind, embeddedSource: content.slice() };
    if (format > maxEmbeddedSourceSize) {
      throw new UnsupportedFormatError(
        `EmbeddedSource exceeds the ${maxEmbeddedSourceSize}-byte decompression limit`
      );
    }
    let decompressed;
    try {
      decompressed = inflateRawSync(content, { maxOutputLength: format });
    } catch (error) {
      throw new FormatError(`EmbeddedSource deflate stream is invalid: ${error.message}`);
    }
    if (decompressed.length !== format) {
      throw new FormatError("EmbeddedSource decompressed size does not match its header");
    }
    return { kind, embeddedSource: Uint8Array.from(decompressed) };
  }
  if (kind === sourceLinkKind) {
    if (row.Parent.target?.table !== 0) {
      throw new FormatError("SourceLink custom debug information must belong to the Module");
    }
    let sourceLink;
    try {
      sourceLink = JSON.parse(decodeUtf8(value, "Portable PDB SourceLink"));
    } catch (error) {
      if (error instanceof FormatError) throw error;
      throw new FormatError(`Portable PDB SourceLink JSON is invalid: ${error.message}`);
    }
    if (sourceLink === null || Array.isArray(sourceLink) || typeof sourceLink !== "object") {
      throw new FormatError("Portable PDB SourceLink value must be a JSON object");
    }
    return { kind, sourceLink };
  }
  return { kind };
}

export function decodePortablePdbDocumentName(blob, heaps) {
  if (blob.length < 2) {
    throw new FormatError("Portable PDB document name is truncated", {
      context: "Portable PDB Document.Name"
    });
  }
  const first = blob[0];
  const separatorLength = first < 0x80 ? 1 :
    first >= 0xc2 && first <= 0xdf ? 2 :
      first >= 0xe0 && first <= 0xef ? 3 :
        first >= 0xf0 && first <= 0xf4 ? 4 : 0;
  if (separatorLength === 0 || separatorLength >= blob.length) {
    throw new FormatError("Portable PDB document name has an invalid separator", {
      context: "Portable PDB Document.Name"
    });
  }
  const separator = first === 0 ? "" : decodeUtf8(blob.subarray(0, separatorLength), "Portable PDB document separator");
  const reader = new BinaryReader(blob, {
    start: separatorLength,
    context: "Portable PDB Document.Name"
  });
  const parts = [];
  while (reader.remaining > 0) {
    const index = readCompressedUInt(reader);
    parts.push(index === 0 ? "" : decodeUtf8(heaps.getBlob(index), "Portable PDB document name part"));
  }
  if (parts.length === 0) {
    throw new FormatError("Portable PDB document name has no parts", {
      context: "Portable PDB Document.Name"
    });
  }
  return parts.join(separator);
}

export function decodePortablePdbSequencePoints(blob, { documentRid, documentCount, localSignatureCount }) {
  const reader = new BinaryReader(blob, { context: "Portable PDB sequence points" });
  const localSignatureRid = readCompressedUInt(reader);
  if (localSignatureRid > localSignatureCount) {
    throw new FormatError("Portable PDB sequence points reference a missing StandAloneSig row");
  }
  let currentDocumentRid = documentRid;
  if (currentDocumentRid === 0) currentDocumentRid = readCompressedUInt(reader);
  if (currentDocumentRid === 0 || currentDocumentRid > documentCount) {
    throw new FormatError("Portable PDB sequence points reference a missing Document row");
  }

  const points = [];
  let previousOffset = 0;
  let previousStartLine = null;
  let previousStartColumn = null;
  while (reader.remaining > 0) {
    const deltaOffset = readCompressedUInt(reader);
    if (deltaOffset === 0 && points.length > 0) {
      currentDocumentRid = readCompressedUInt(reader);
      if (currentDocumentRid === 0 || currentDocumentRid > documentCount) {
        throw new FormatError("Portable PDB document record references a missing Document row");
      }
      continue;
    }

    const offset = points.length === 0 ? deltaOffset : previousOffset + deltaOffset;
    if ((points.length > 0 && deltaOffset === 0) || offset >= 0x20000000) {
      throw new FormatError("Portable PDB sequence-point IL offsets are invalid");
    }
    const deltaLines = readCompressedUInt(reader);
    const deltaColumns = deltaLines === 0 ? readCompressedUInt(reader) : readCompressedInt(reader);
    const hidden = deltaLines === 0 && deltaColumns === 0;
    let startLine = 0xfeefee;
    let startColumn = 0;
    let endLine = 0xfeefee;
    let endColumn = 0;
    if (!hidden) {
      const lineDelta = previousStartLine === null ? readCompressedUInt(reader) : readCompressedInt(reader);
      const columnDelta = previousStartColumn === null ? readCompressedUInt(reader) : readCompressedInt(reader);
      startLine = (previousStartLine ?? 0) + lineDelta;
      startColumn = (previousStartColumn ?? 0) + columnDelta;
      endLine = startLine + deltaLines;
      endColumn = startColumn + deltaColumns;
      if (startLine < 0 || startLine >= 0x20000000 || startLine === 0xfeefee ||
          endLine < startLine || endLine >= 0x20000000 || endLine === 0xfeefee ||
          startColumn < 0 || startColumn >= 0x10000 || endColumn < 0 || endColumn >= 0x10000 ||
          (startLine === endLine && endColumn <= startColumn)) {
        throw new FormatError("Portable PDB sequence-point source spans are invalid");
      }
      previousStartLine = startLine;
      previousStartColumn = startColumn;
    }
    points.push({
      offset,
      documentRid: currentDocumentRid,
      hidden,
      startLine,
      startColumn,
      endLine,
      endColumn
    });
    previousOffset = offset;
  }
  return { localSignatureRid, points };
}

function validateLocalScopes(scopes, variables, constants, heaps) {
  const variableOwners = new Set();
  const constantOwners = new Set();
  const nestedScopes = new Map();
  let previous = null;
  for (const scope of scopes) {
    const key = [scope.Method.rid, scope.StartOffset, -scope.Length];
    if (previous && (key[0] < previous[0] ||
        (key[0] === previous[0] && (key[1] < previous[1] ||
          (key[1] === previous[1] && key[2] < previous[2]))))) {
      throw new FormatError("Portable PDB LocalScope rows are not ordered");
    }
    previous = key;
    if (scope.Method.rid === 0) {
      throw new FormatError(`Portable PDB LocalScope row ${scope.rid} has a nil Method`);
    }
    const end = scope.StartOffset + scope.Length;
    if (scope.Length === 0 || scope.StartOffset >= 0x80000000 || end >= 0x80000000) {
      throw new FormatError(`Portable PDB LocalScope row ${scope.rid} has an invalid IL range`);
    }
    const stack = nestedScopes.get(scope.Method.rid) ?? [];
    while (stack.length > 0 && stack.at(-1).end <= scope.StartOffset) stack.pop();
    if (stack.length > 0 && end > stack.at(-1).end) {
      throw new FormatError(`Portable PDB LocalScope row ${scope.rid} partially overlaps another scope`);
    }
    stack.push({ start: scope.StartOffset, end });
    nestedScopes.set(scope.Method.rid, stack);
  }

  const validateList = (column, rows, owners, kind) => {
    if (rows.length === 0) return;
    if (scopes.length === 0 || scopes[0][column].rid !== 1) {
      throw new FormatError(`Portable PDB ${kind} rows are not owned by a LocalScope`);
    }
    for (let index = 0; index < scopes.length; index++) {
      const scope = scopes[index];
      const start = scope[column].rid;
      const end = scopes[index + 1]?.[column].rid ?? rows.length + 1;
      for (let rid = start; rid < end; rid++) {
        const row = rows[rid - 1];
        if (!row || owners.has(rid)) {
          throw new FormatError(`Portable PDB ${kind} ownership ranges are invalid`);
        }
        owners.add(rid);
        if (kind === "LocalVariable") {
          if ((row.Attributes & ~1) !== 0) {
            throw new FormatError(`Portable PDB LocalVariable row ${rid} has invalid attributes`);
          }
          const name = heaps.getString(row.Name);
          const key = `${scope.rid}:${row.Index}`;
          const namedKey = `${scope.rid}:${name}`;
          if (owners.has(key) || owners.has(namedKey)) {
            throw new FormatError(`Portable PDB LocalVariable row ${rid} duplicates a scope variable`);
          }
          owners.add(key);
          owners.add(namedKey);
        } else {
          const name = heaps.getString(row.Name);
          const key = `${scope.rid}:${name}`;
          if (owners.has(key)) {
            throw new FormatError(`Portable PDB LocalConstant row ${rid} duplicates a scope constant`);
          }
          if (heaps.getBlob(row.Signature).length === 0) {
            throw new FormatError(`Portable PDB LocalConstant row ${rid} has an empty signature`);
          }
          owners.add(key);
        }
      }
    }
  };
  validateList("VariableList", variables, variableOwners, "LocalVariable");
  validateList("ConstantList", constants, constantOwners, "LocalConstant");
}

function validateImportScopes(scopes) {
  const states = new Uint8Array(scopes.length + 1);
  for (let rid = 1; rid <= scopes.length; rid++) {
    if (states[rid] === 2) continue;
    const path = [];
    let current = rid;
    while (current !== 0 && states[current] !== 2) {
      if (states[current] === 1) {
        throw new FormatError("Portable PDB ImportScope parent relationships contain a cycle");
      }
      states[current] = 1;
      path.push(current);
      current = scopes[current - 1].Parent.rid;
    }
    for (const item of path) states[item] = 2;
  }
}

export function parsePortablePdbTables(tables, heaps, typeSystemCounts) {
  const documentRows = tables.get(48);
  const documents = [];
  const documentNames = new Set();
  for (const row of documentRows) {
    if (row.Name === 0) {
      throw new FormatError(`Portable PDB Document row ${row.rid} has a nil name`);
    }
    const name = decodePortablePdbDocumentName(heaps.getBlob(row.Name), heaps);
    if (documentNames.has(name)) {
      throw new FormatError("Portable PDB Document table contains duplicate names");
    }
    documentNames.add(name);
    heaps.getGuid(row.HashAlgorithm);
    heaps.getBlob(row.Hash);
    heaps.getGuid(row.Language);
    documents.push({ ...row, name });
  }

  const debugRows = tables.get(49);
  if (debugRows.length !== 0 && debugRows.length !== typeSystemCounts[6]) {
    throw new FormatError("Portable PDB MethodDebugInformation row count must match MethodDef");
  }
  const methodDebugInformation = debugRows.map((row) => {
    if (row.SequencePoints === 0) return { ...row, localSignatureRid: 0, sequencePoints: [] };
    const parsed = decodePortablePdbSequencePoints(heaps.getBlob(row.SequencePoints), {
      documentRid: row.Document.rid,
      documentCount: documentRows.length,
      localSignatureCount: typeSystemCounts[17]
    });
    return { ...row, ...parsed, sequencePoints: parsed.points };
  });
  validateLocalScopes(
    tables.get(50),
    tables.get(51),
    tables.get(52),
    heaps
  );
  const importScopes = tables.get(53);
  validateImportScopes(importScopes);
  for (const row of importScopes) heaps.getBlob(row.Imports);
  const stateMachineMethods = tables.get(54);
  const kickoffMethods = new Set();
  let previousMoveNext = 0;
  for (const row of stateMachineMethods) {
    if (row.MoveNextMethod.rid <= previousMoveNext ||
        kickoffMethods.has(row.KickoffMethod.rid)) {
      throw new FormatError("Portable PDB StateMachineMethod rows are unsorted or duplicated");
    }
    previousMoveNext = row.MoveNextMethod.rid;
    kickoffMethods.add(row.KickoffMethod.rid);
  }
  let previousCustomDebugParent = 0;
  for (const row of tables.get(55)) {
    if (row.Parent.raw < previousCustomDebugParent || row.Kind === 0) {
      throw new FormatError("Portable PDB CustomDebugInformation rows are unsorted or have a nil Kind");
    }
    previousCustomDebugParent = row.Parent.raw;
    heaps.getGuid(row.Kind);
    heaps.getBlob(row.Value);
  }
  const customDebugInformation = tables.get(55).map((row) => ({
    ...row,
    ...decodePortablePdbCustomDebugInformation(row, heaps)
  }));
  return { documents, methodDebugInformation, stateMachineMethods, customDebugInformation };
}
