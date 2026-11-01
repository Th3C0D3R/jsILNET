import { deflateRawSync, inflateRawSync } from "node:zlib";
import { createHash } from "node:crypto";
import { BinaryReader, readCompressedInt, readCompressedUInt } from "../binary/reader.js";
import { FormatError, UnsupportedFormatError } from "../binary/errors.js";
import {
  appendBlobHeap,
  appendCompressedInt,
  appendCompressedUInt,
  serializeTablesStream
} from "./writer.js";
import { serializeMetadataRoot } from "./root-writer.js";
import { encodeCodedIndex } from "./tables.js";

const maxEmbeddedSourceSize = 0x10000000;
const maxEmbeddedPortablePdbSize = 0x10000000;
const documentHashAlgorithms = new Map([
  ["ff1816ec-aa5e-4d10-87f7-6f4963833460", "sha1"],
  ["8829d00f-11b8-4213-878b-770e8597ac16", "sha256"],
  ["d99cfeb1-8c43-444a-8a6c-b61269d2a0bf", "sha384"],
  ["ef2d1afc-6550-46d6-b14b-d70afe9a5566", "sha512"]
]);
const embeddedSourceKind = "0e8a571b-6926-466e-b4ad-8ab04611f5fe";
const sourceLinkKind = "cc110556-a091-4d38-9fec-25ab9a351a6a";
const defaultNamespaceKind = "58b2eab6-209f-4e4e-a22c-b2d0f910c782";
const dynamicLocalVariablesKind = "83c563c4-b4f3-47d5-b824-ba5441477ea8";
const embeddedSourceGuidBytes = Uint8Array.from([
  0x1b, 0x57, 0x8a, 0x0e, 0x26, 0x69, 0x6e, 0x46,
  0xb4, 0xad, 0x8a, 0xb0, 0x46, 0x11, 0xf5, 0xfe
]);
const sourceLinkGuidBytes = Uint8Array.from([
  0x56, 0x05, 0x11, 0xcc, 0x91, 0xa0, 0x38, 0x4d,
  0x9f, 0xec, 0x25, 0xab, 0x9a, 0x35, 0x1a, 0x6a
]);

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

export function updateEmbeddedPortablePdbRowCounts(pdb, assemblyRowCounts) {
  if (!pdb?.metadataRoot?.streams || !(pdb.rowCounts instanceof Map) ||
      !Array.isArray(pdb.tables?.counts) || !Array.isArray(assemblyRowCounts)) {
    throw new TypeError("Portable PDB row-count update requires parsed data and assembly row counts");
  }
  const rowCounts = new Map();
  let changed = false;
  for (const [table, count] of pdb.rowCounts) {
    const updatedCount = assemblyRowCounts[table];
    if (!Number.isInteger(updatedCount) || updatedCount < 0 ||
        (updatedCount < count && (table === 6 || table === 17))) {
      throw new UnsupportedFormatError(
        `Portable PDB row-count update cannot safely change type-system table ${table}`
      );
    }
    rowCounts.set(table, updatedCount);
    changed ||= updatedCount !== count;
  }
  if (!changed) return null;

  const pdbStream = new Uint8Array(32 + rowCounts.size * 4);
  pdbStream.set(pdb.id);
  const pdbView = new DataView(pdbStream.buffer);
  pdbView.setUint32(20, pdb.entryPointToken, true);
  pdbView.setUint32(24, Number(pdb.referencedTypeSystemTables & 0xffffffffn), true);
  pdbView.setUint32(28, Number(pdb.referencedTypeSystemTables >> 32n), true);
  let countOffset = 32;
  for (const [table, count] of [...rowCounts].sort(([left], [right]) => left - right)) {
    pdbView.setUint32(countOffset, count, true);
    countOffset += 4;
  }

  const tableCounts = [...pdb.tables.counts];
  for (let table = 0; table < 45; table++) {
    tableCounts[table] = assemblyRowCounts[table];
  }
  const streams = new Map([...pdb.metadataRoot.streams].map(([name, stream]) =>
    [name, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
  ));
  const metadataPdbStream = streams.get("#Pdb");
  if (!metadataPdbStream) throw new FormatError("Portable PDB is missing its #Pdb stream");
  metadataPdbStream.bytes = pdbStream;
  return serializeEmbeddedPortablePdb({
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams },
    rowCounts,
    tables: { ...pdb.tables, counts: tableCounts }
  });
}

function decodeUtf8(bytes, context) {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
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

export function validatePortablePdbCodeViewIdentity(pdb, codeView, timeDateStamp) {
  if (!pdb || !(pdb.id instanceof Uint8Array) || !codeView) {
    throw new TypeError("Portable PDB identity validation requires parsed PDB and CodeView data");
  }
  if (codeView.format !== "RSDS") return;
  const guid = formatGuid(pdb.id.subarray(0, 16));
  if (codeView.guid !== guid) {
    throw new FormatError("Embedded Portable PDB identity does not match its CodeView GUID");
  }
  if (codeView.age !== 1) {
    throw new FormatError("Embedded Portable PDB CodeView age must be one");
  }
  if (timeDateStamp !== undefined) {
    const idStamp = new DataView(pdb.id.buffer, pdb.id.byteOffset, pdb.id.byteLength)
      .getUint32(16, true);
    if (timeDateStamp !== idStamp) {
      throw new FormatError("Embedded Portable PDB identity does not match its CodeView stamp");
    }
  }
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
    if (sourceLink.documents === null || Array.isArray(sourceLink.documents) ||
        typeof sourceLink.documents !== "object") {
      throw new FormatError("Portable PDB SourceLink documents value must be a JSON object");
    }
    if (Object.values(sourceLink.documents).some((mapping) => typeof mapping !== "string")) {
      throw new FormatError("Portable PDB SourceLink document mappings must be strings");
    }
    return { kind, sourceLink };
  }
  if (kind === defaultNamespaceKind) {
    if (row.Parent.target?.table !== 0) {
      throw new FormatError("DefaultNamespace custom debug information must belong to the Module");
    }
    return {
      kind,
      defaultNamespace: decodeUtf8(value, "Portable PDB DefaultNamespace")
    };
  }
  if (kind === dynamicLocalVariablesKind) {
    if (![51, 52].includes(row.Parent.target?.table)) {
      throw new FormatError(
        "DynamicLocalVariables custom debug information must belong to a LocalVariable or LocalConstant"
      );
    }
    return { kind, dynamicLocalVariables: value.slice() };
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

export function encodePortablePdbDocumentName(separator, partBlobIndices) {
  if (typeof separator !== "string" ||
      (separator !== "" && [...separator].length !== 1) ||
      separator.includes("\0")) {
    throw new TypeError("Portable PDB document-name separator must be empty or one Unicode character");
  }
  if (!Array.isArray(partBlobIndices) || partBlobIndices.length === 0) {
    throw new TypeError("Portable PDB document names require at least one blob index");
  }
  const separatorBytes = new TextEncoder().encode(separator);
  if (new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(separatorBytes) !== separator) {
    throw new TypeError("Portable PDB document-name separator must contain valid Unicode");
  }
  const output = [...(separatorBytes.length === 0 ? [0] : separatorBytes)];
  for (const index of partBlobIndices) {
    if (!Number.isInteger(index) || index < 0 || index >= 0x20000000) {
      throw new RangeError("Portable PDB document-name blob index is out of range");
    }
    output.push(...appendCompressedUInt(index));
  }
  return Uint8Array.from(output);
}

export function appendPortablePdbDocumentName(blobHeap, name, separator) {
  if (!(blobHeap instanceof Uint8Array)) {
    throw new TypeError("Portable PDB document-name encoding requires a Blob heap");
  }
  if (typeof name !== "string") {
    throw new TypeError("Portable PDB document names must be strings");
  }
  if (typeof separator !== "string" ||
      (separator !== "" && [...separator].length !== 1) ||
      separator.includes("\0")) {
    throw new TypeError("Portable PDB document-name separator must be empty or one Unicode character");
  }
  const parts = separator === "" ? [name] : name.split(separator);
  let updatedHeap = Uint8Array.from(blobHeap);
  const partBlobIndices = parts.map((part) => {
    if (part === "") return 0;
    const bytes = new TextEncoder().encode(part);
    if (new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) !== part) {
      throw new TypeError("Portable PDB document-name parts must contain valid Unicode");
    }
    const appended = appendBlobHeap(updatedHeap, bytes);
    updatedHeap = appended.heap;
    return appended.index;
  });
  const blob = encodePortablePdbDocumentName(separator, partBlobIndices);
  const appended = appendBlobHeap(updatedHeap, blob);
  return {
    heap: appended.heap,
    nameBlobIndex: appended.index,
    nameBlob: blob
  };
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

export function encodePortablePdbSequencePoints(
  sequencePoints,
  { documentRid, documentCount, localSignatureCount } = {}
) {
  if (!sequencePoints || !Array.isArray(sequencePoints.points)) {
    throw new TypeError("Portable PDB sequence points require a points array");
  }
  if (![documentRid, documentCount, localSignatureCount].every((value) =>
    Number.isInteger(value) && value >= 0
  )) {
    throw new TypeError("Portable PDB sequence-point context counts must be non-negative integers");
  }
  const { localSignatureRid, points } = sequencePoints;
  if (!Number.isInteger(localSignatureRid) || localSignatureRid < 0 ||
      localSignatureRid > localSignatureCount) {
    throw new RangeError("Portable PDB sequence points reference a missing StandAloneSig row");
  }
  if (documentRid > documentCount) {
    throw new RangeError("Portable PDB sequence points reference a missing Document row");
  }
  const initialDocumentRid = documentRid === 0
    ? points[0]?.documentRid
    : documentRid;
  if (initialDocumentRid === undefined) {
    throw new RangeError("Portable PDB sequence points with a nil Document require an initial document");
  }
  if (!Number.isInteger(initialDocumentRid) || initialDocumentRid < 1 ||
      initialDocumentRid > documentCount) {
    throw new RangeError("Portable PDB sequence points reference a missing Document row");
  }

  const output = [...appendCompressedUInt(localSignatureRid)];
  if (documentRid === 0) output.push(...appendCompressedUInt(initialDocumentRid));
  let currentDocumentRid = initialDocumentRid;
  let previousOffset = 0;
  let previousStartLine = null;
  let previousStartColumn = null;
  for (let index = 0; index < points.length; index++) {
    const point = points[index];
    if (!point || !Number.isInteger(point.documentRid) ||
        point.documentRid < 1 || point.documentRid > documentCount) {
      throw new RangeError("Portable PDB sequence point references a missing Document row");
    }
    if (index === 0 && point.documentRid !== initialDocumentRid) {
      throw new FormatError("First Portable PDB sequence point does not match its initial Document");
    }
    if (index > 0 && point.documentRid !== currentDocumentRid) {
      output.push(0, ...appendCompressedUInt(point.documentRid));
      currentDocumentRid = point.documentRid;
    }
    if (!Number.isInteger(point.offset) || point.offset < 0 || point.offset >= 0x20000000 ||
        (index > 0 && point.offset <= previousOffset)) {
      throw new RangeError("Portable PDB sequence-point IL offsets must be increasing and in range");
    }
    output.push(...appendCompressedUInt(index === 0 ? point.offset : point.offset - previousOffset));
    if (typeof point.hidden !== "boolean") {
      throw new TypeError("Portable PDB sequence points require a hidden flag");
    }
    if (point.hidden) {
      output.push(0, 0);
    } else {
      const { startLine, startColumn, endLine, endColumn } = point;
      if (![startLine, startColumn, endLine, endColumn].every(Number.isInteger) ||
          startLine < 0 || startLine >= 0x20000000 || startLine === 0xfeefee ||
          endLine < startLine || endLine >= 0x20000000 || endLine === 0xfeefee ||
          startColumn < 0 || startColumn >= 0x10000 ||
          endColumn < 0 || endColumn >= 0x10000 ||
          (startLine === endLine && endColumn <= startColumn)) {
        throw new FormatError("Portable PDB sequence-point source spans are invalid");
      }
      const deltaLines = endLine - startLine;
      const deltaColumns = endColumn - startColumn;
      output.push(...appendCompressedUInt(deltaLines));
      output.push(...(deltaLines === 0
        ? appendCompressedUInt(deltaColumns)
        : appendCompressedInt(deltaColumns)));
      output.push(...(previousStartLine === null
        ? appendCompressedUInt(startLine)
        : appendCompressedInt(startLine - previousStartLine)));
      output.push(...(previousStartColumn === null
        ? appendCompressedUInt(startColumn)
        : appendCompressedInt(startColumn - previousStartColumn)));
      previousStartLine = startLine;
      previousStartColumn = startColumn;
    }
    previousOffset = point.offset;
  }
  return Uint8Array.from(output);
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

export function serializeEmbeddedPortablePdb(pdb) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts)) {
    throw new TypeError("Embedded Portable PDB serialization requires parsed PDB data");
  }
  const streams = new Map([...pdb.metadataRoot.streams].map(([name, stream]) =>
    [name, Uint8Array.from(stream.bytes)]
  ));
  const tableStreamName = streams.has("#~") ? "#~" : streams.has("#-") ? "#-" : null;
  if (!tableStreamName || !streams.has("#Pdb")) {
    throw new FormatError("Embedded Portable PDB is missing a required metadata stream");
  }
  streams.set(tableStreamName, serializeTablesStream(pdb.tables, streams));
  const metadata = serializeMetadataRoot(pdb.metadataRoot, streams);
  if (metadata.length === 0 || metadata.length > maxEmbeddedPortablePdbSize ||
      metadata.length > 0xffffffff) {
    throw new UnsupportedFormatError("Serialized Portable PDB metadata exceeds the supported size");
  }
  const compressed = deflateRawSync(metadata);
  if (compressed.length > 0xffffffff - 8) {
    throw new RangeError("Compressed Portable PDB exceeds the container size limit");
  }
  const output = new Uint8Array(8 + compressed.length);
  output.set([0x4d, 0x50, 0x44, 0x42]);
  new DataView(output.buffer).setUint32(4, metadata.length, true);
  output.set(compressed, 8);
  return output;
}

export function refreshEmbeddedPortablePdbId(pdb) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts)) {
    throw new TypeError("Portable PDB ID generation requires parsed PDB data");
  }
  const streams = new Map([...pdb.metadataRoot.streams].map(([name, stream]) =>
    [name, Uint8Array.from(stream.bytes)]
  ));
  const tableStreamName = streams.has("#~") ? "#~" : streams.has("#-") ? "#-" : null;
  const pdbStream = streams.get("#Pdb");
  if (!tableStreamName || !pdbStream || pdbStream.length < 20) {
    throw new FormatError("Portable PDB ID generation requires #Pdb and table streams");
  }
  streams.set(tableStreamName, serializeTablesStream(pdb.tables, streams));
  pdbStream.fill(0, 0, 20);
  const metadata = serializeMetadataRoot(pdb.metadataRoot, streams);
  const hashes = new Map();
  for (const [algorithm, name] of [
    ["SHA256", "sha256"],
    ["SHA384", "sha384"],
    ["SHA512", "sha512"]
  ]) {
    hashes.set(algorithm, Uint8Array.from(createHash(name).update(metadata).digest()));
  }
  const id = hashes.get("SHA256").slice(0, 20);
  pdbStream.set(id);
  const updatedStreams = new Map([...streams].map(([name, bytes]) => [
    name,
    { ...pdb.metadataRoot.streams.get(name), bytes }
  ]));
  const updatedPdb = {
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams: updatedStreams }
  };
  return {
    bytes: serializeEmbeddedPortablePdb(updatedPdb),
    id,
    hashes
  };
}

export function replaceEmbeddedPortablePdbDocumentName(pdb, documentRid, name, separator) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !pdb.heaps?.getBlob ||
      !Array.isArray(pdb.documents)) {
    throw new TypeError("Portable PDB document editing requires parsed PDB data");
  }
  if (!Number.isInteger(documentRid) || documentRid < 1 ||
      documentRid > pdb.documents.length) {
    throw new RangeError(`Invalid Portable PDB Document row ID ${documentRid}`);
  }
  if (typeof name !== "string" || name.length === 0 || name.includes("\0")) {
    throw new TypeError("Portable PDB document names must be nonempty null-free strings");
  }
  const documentRows = pdb.tables.rows.get(48) ?? [];
  const documentRow = documentRows[documentRid - 1];
  if (!documentRow || documentRow.rid !== documentRid) {
    throw new FormatError(`Portable PDB Document row ${documentRid} is missing`);
  }
  const streams = new Map([...pdb.metadataRoot.streams].map(([streamName, stream]) =>
    [streamName, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
  ));
  const blobStream = streams.get("#Blob");
  if (!blobStream) throw new FormatError("Portable PDB metadata is missing its #Blob heap");
  const documentName = appendPortablePdbDocumentName(blobStream.bytes, name, separator);
  blobStream.bytes = documentName.heap;
  for (const document of pdb.documents) {
    if (document.rid !== documentRid && document.name === name) {
      throw new FormatError(`Portable PDB Document name ${JSON.stringify(name)} already exists`);
    }
  }
  const rows = new Map(pdb.tables.rows);
  rows.set(48, documentRows.map((row) =>
    row.rid === documentRid ? { ...row, Name: documentName.nameBlobIndex } : { ...row }
  ));
  return serializeEmbeddedPortablePdb({
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams },
    tables: { ...pdb.tables, rows }
  });
}

export function replaceEmbeddedPortablePdbSequencePoints(pdb, methodRid, sequencePoints) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !(pdb.rowCounts instanceof Map) ||
      !Array.isArray(pdb.methodDebugInformation)) {
    throw new TypeError("Portable PDB sequence-point editing requires parsed PDB data");
  }
  if (!Number.isInteger(methodRid) || methodRid < 1 ||
      methodRid > pdb.methodDebugInformation.length) {
    throw new RangeError(`Invalid Portable PDB MethodDebugInformation row ID ${methodRid}`);
  }
  const rowsForMethods = pdb.tables.rows.get(49) ?? [];
  const row = rowsForMethods[methodRid - 1];
  if (!row || row.rid !== methodRid) {
    throw new FormatError(`Portable PDB MethodDebugInformation row ${methodRid} is missing`);
  }
  const encoded = encodePortablePdbSequencePoints(sequencePoints, {
    documentRid: row.Document.rid,
    documentCount: pdb.tables.counts[48],
    localSignatureCount: pdb.rowCounts.get(17) ?? 0
  });
  const streams = new Map([...pdb.metadataRoot.streams].map(([streamName, stream]) =>
    [streamName, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
  ));
  const blobStream = streams.get("#Blob");
  if (!blobStream) throw new FormatError("Portable PDB metadata is missing its #Blob heap");
  const appended = appendBlobHeap(blobStream.bytes, encoded);
  blobStream.bytes = appended.heap;
  const rows = new Map(pdb.tables.rows);
  rows.set(49, rowsForMethods.map((methodRow) =>
    methodRow.rid === methodRid
      ? { ...methodRow, SequencePoints: appended.index }
      : { ...methodRow }
  ));
  return serializeEmbeddedPortablePdb({
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams },
    tables: { ...pdb.tables, rows }
  });
}

export function replaceEmbeddedPortablePdbMethodOffsets(
  pdb,
  methodRid,
  { sequencePoints = null, localSignatureRid = 0, scopes = [] } = {}
) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !(pdb.rowCounts instanceof Map)) {
    throw new TypeError("Portable PDB method-offset editing requires parsed PDB data");
  }
  if (!Number.isInteger(methodRid) || methodRid < 1 ||
      methodRid > (pdb.rowCounts.get(6) ?? 0)) {
    throw new RangeError(`Invalid Portable PDB MethodDef row ID ${methodRid}`);
  }
  if (!Array.isArray(scopes)) {
    throw new TypeError("Portable PDB local-scope edits must be an array");
  }
  const scopeRows = pdb.tables.rows.get(50) ?? [];
  const scopeUpdates = new Map(scopes.map((scope) => [scope.rid, scope]));
  if (scopeUpdates.size !== scopes.length || scopes.some((scope) =>
    !Number.isInteger(scope.rid) || !Number.isInteger(scope.startOffset) ||
    !Number.isInteger(scope.length) || scope.startOffset < 0 || scope.length < 0 ||
    scope.startOffset + scope.length > 0xffffffff ||
    !scopeRows.some((row) => row.rid === scope.rid && row.Method.rid === methodRid)
  )) {
    throw new FormatError("Portable PDB local-scope edits contain invalid rows or ranges");
  }
  const rows = new Map(pdb.tables.rows);
  const methodRows = pdb.tables.rows.get(49) ?? [];
  if (sequencePoints !== null) {
    const row = methodRows[methodRid - 1];
    if (!row || row.rid !== methodRid) {
      throw new FormatError(
        `Portable PDB MethodDebugInformation row ${methodRid} is missing`
      );
    }
    const encoded = encodePortablePdbSequencePoints({
      localSignatureRid,
      points: sequencePoints
    }, {
      documentRid: row.Document.rid,
      documentCount: pdb.tables.counts[48],
      localSignatureCount: pdb.rowCounts.get(17) ?? 0
    });
    const streams = new Map([...pdb.metadataRoot.streams].map(([name, stream]) =>
      [name, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
    ));
    const blobStream = streams.get("#Blob");
    if (!blobStream) throw new FormatError("Portable PDB metadata is missing its #Blob heap");
    const appended = appendBlobHeap(blobStream.bytes, encoded);
    blobStream.bytes = appended.heap;
    rows.set(49, methodRows.map((methodRow) =>
      methodRow.rid === methodRid
        ? { ...methodRow, SequencePoints: appended.index }
        : { ...methodRow }
    ));
    if (scopes.length > 0) {
      rows.set(50, scopeRows.map((scopeRow) => {
        const update = scopeUpdates.get(scopeRow.rid);
        return update
          ? { ...scopeRow, StartOffset: update.startOffset, Length: update.length }
          : { ...scopeRow };
      }));
    }
    return serializeEmbeddedPortablePdb({
      ...pdb,
      metadataRoot: { ...pdb.metadataRoot, streams },
      tables: { ...pdb.tables, rows }
    });
  }
  if (scopes.length === 0) return serializeEmbeddedPortablePdb(pdb);
  rows.set(50, scopeRows.map((scopeRow) => {
    const update = scopeUpdates.get(scopeRow.rid);
    return update
      ? { ...scopeRow, StartOffset: update.startOffset, Length: update.length }
      : { ...scopeRow };
  }));
  return serializeEmbeddedPortablePdb({
    ...pdb,
    tables: { ...pdb.tables, rows }
  });
}

export function insertEmbeddedPortablePdbMethod(pdb, methodRid, oldCounts, newCounts) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !(pdb.rowCounts instanceof Map)) {
    throw new TypeError("Portable PDB method insertion requires parsed PDB data");
  }
  if (!Array.isArray(oldCounts) || !Array.isArray(newCounts) ||
      oldCounts.length < 45 || newCounts.length < 45 ||
      !Number.isInteger(methodRid) || methodRid < 1 ||
      methodRid > newCounts[6] || newCounts[6] !== oldCounts[6] + 1) {
    throw new UnsupportedFormatError(
      "Portable PDB method insertion requires one valid MethodDef row to be inserted"
    );
  }
  for (const [table, count] of pdb.rowCounts) {
    if (count !== oldCounts[table]) {
      throw new FormatError(
        `Portable PDB row count for type-system table ${table} does not match assembly metadata`
      );
    }
  }

  const entryPointRid = pdb.entryPointToken & 0x00ffffff;
  if (pdb.entryPointToken !== 0 && entryPointRid > oldCounts[6]) {
    throw new FormatError("Portable PDB entry point references a missing MethodDef");
  }
  const entryPointToken = pdb.entryPointToken !== 0 &&
    (pdb.entryPointToken >>> 24) === 6 && entryPointRid >= methodRid
    ? pdb.entryPointToken + 1
    : pdb.entryPointToken;

  const rows = new Map(pdb.tables.rows);
  const methodRows = rows.get(49) ?? [];
  if (methodRows.length !== 0 && methodRows.length !== oldCounts[6]) {
    throw new FormatError("Portable PDB MethodDebugInformation row count is inconsistent");
  }
  if (methodRows.length > 0) {
    if (methodRows.some((row, index) => row.rid !== index + 1)) {
      throw new FormatError("Portable PDB MethodDebugInformation rows are not RID-aligned");
    }
    const remappedMethodRows = methodRows.map((row) => ({
      ...row,
      rid: row.rid >= methodRid ? row.rid + 1 : row.rid
    }));
    remappedMethodRows.splice(methodRid - 1, 0, {
      table: 49,
      tableName: "MethodDebugInformation",
      rid: methodRid,
      Document: { raw: 0, table: 48, tableName: "Document", rid: 0 },
      SequencePoints: 0
    });
    rows.set(49, remappedMethodRows);
  } else {
    rows.delete(49);
  }

  const remapMethodReference = (reference) => reference.rid >= methodRid
    ? { ...reference, raw: reference.rid + 1, rid: reference.rid + 1 }
    : { ...reference };
  const scopeRows = rows.get(50) ?? [];
  if (rows.has(50)) {
    rows.set(50, scopeRows.map((scope) => ({
      ...scope,
      Method: remapMethodReference(scope.Method)
    })));
  }
  const stateMachineRows = rows.get(54) ?? [];
  if (rows.has(54)) {
    rows.set(54, stateMachineRows.map((stateMachine) => ({
      ...stateMachine,
      MoveNextMethod: remapMethodReference(stateMachine.MoveNextMethod),
      KickoffMethod: remapMethodReference(stateMachine.KickoffMethod)
    })));
  }
  const customDebugRows = rows.get(55) ?? [];
  if (customDebugRows.some((record) => record.Parent.target?.table === 6)) {
    throw new UnsupportedFormatError(
      "Portable PDB method remapping cannot update method-scoped CustomDebugInformation"
    );
  }

  const rowCounts = new Map([...pdb.rowCounts].map(([table]) =>
    [table, newCounts[table]]
  ));
  const tableCounts = [...pdb.tables.counts];
  for (let table = 0; table < 45; table++) {
    tableCounts[table] = newCounts[table];
  }
  tableCounts[49] = methodRows.length > 0 ? methodRows.length + 1 : 0;
  const valid = tableCounts[49] === 0
    ? pdb.tables.valid & ~(1n << 49n)
    : pdb.tables.valid | (1n << 49n);

  const pdbStream = new Uint8Array(32 + rowCounts.size * 4);
  pdbStream.set(pdb.id);
  const pdbView = new DataView(pdbStream.buffer);
  pdbView.setUint32(20, entryPointToken, true);
  pdbView.setUint32(24, Number(pdb.referencedTypeSystemTables & 0xffffffffn), true);
  pdbView.setUint32(28, Number(pdb.referencedTypeSystemTables >> 32n), true);
  let countOffset = 32;
  for (const [table, count] of [...rowCounts].sort(([left], [right]) => left - right)) {
    pdbView.setUint32(countOffset, count, true);
    countOffset += 4;
  }

  const streams = new Map([...pdb.metadataRoot.streams].map(([name, stream]) =>
    [name, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
  ));
  const pdbMetadataStream = streams.get("#Pdb");
  if (!pdbMetadataStream) {
    throw new FormatError("Portable PDB is missing its #Pdb stream");
  }
  pdbMetadataStream.bytes = pdbStream;
  return serializeEmbeddedPortablePdb({
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams },
    rowCounts,
    tables: { ...pdb.tables, rows, counts: tableCounts, valid }
  });
}

export function remapEmbeddedPortablePdbLocalSignatures(
  pdb,
  signatureRid,
  oldCounts,
  newCounts,
  operation
) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !(pdb.rowCounts instanceof Map) ||
      !Array.isArray(pdb.methodDebugInformation)) {
    throw new TypeError("Portable PDB local-signature remapping requires parsed PDB data");
  }
  if (!Array.isArray(oldCounts) || !Array.isArray(newCounts) ||
      oldCounts.length < 45 || newCounts.length < 45 ||
      !Number.isInteger(signatureRid) || signatureRid < 1 ||
      !["insert", "remove"].includes(operation) ||
      (operation === "insert" &&
        (signatureRid > newCounts[17] || newCounts[17] !== oldCounts[17] + 1)) ||
      (operation === "remove" &&
        (signatureRid > oldCounts[17] || newCounts[17] !== oldCounts[17] - 1))) {
    throw new UnsupportedFormatError(
      "Portable PDB local-signature remapping requires one valid StandAloneSig edit"
    );
  }
  for (const [table, count] of pdb.rowCounts) {
    if (count !== oldCounts[table]) {
      throw new FormatError(
        `Portable PDB row count for type-system table ${table} does not match assembly metadata`
      );
    }
  }

  const rows = new Map(pdb.tables.rows);
  const methodRows = rows.get(49) ?? [];
  if (methodRows.length !== 0 &&
      (methodRows.length !== oldCounts[6] ||
       pdb.methodDebugInformation.length !== methodRows.length)) {
    throw new FormatError("Portable PDB MethodDebugInformation row count is inconsistent");
  }
  const streams = new Map([...pdb.metadataRoot.streams].map(([name, stream]) =>
    [name, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
  ));
  const blobStream = streams.get("#Blob");
  if (!blobStream) {
    throw new FormatError("Portable PDB metadata is missing its #Blob heap");
  }
  let blobHeap = blobStream.bytes;
  let changed = false;
  const methodRowsWithRemappedSignatures = methodRows.map((row) => {
    if (row.SequencePoints === 0) return { ...row };
    const debugInformation = pdb.methodDebugInformation[row.rid - 1];
    if (!debugInformation || debugInformation.rid !== row.rid) {
      throw new FormatError(
        `Portable PDB MethodDebugInformation row ${row.rid} is missing`
      );
    }
    const localSignatureRid = debugInformation.localSignatureRid;
    if (!Number.isInteger(localSignatureRid) || localSignatureRid < 0 ||
        localSignatureRid > oldCounts[17]) {
      throw new FormatError(
        `Portable PDB MethodDebugInformation row ${row.rid} references a missing StandAloneSig`
      );
    }
    if (operation === "remove" && localSignatureRid === signatureRid) {
      throw new FormatError(
        `StandAloneSig row ${signatureRid} is referenced by Portable PDB MethodDebugInformation row ${row.rid}`
      );
    }
    let remappedLocalSignatureRid = localSignatureRid;
    if (operation === "insert" && localSignatureRid >= signatureRid) {
      remappedLocalSignatureRid++;
    } else if (operation === "remove" && localSignatureRid > signatureRid) {
      remappedLocalSignatureRid--;
    }
    if (remappedLocalSignatureRid === localSignatureRid) return { ...row };
    const encoded = encodePortablePdbSequencePoints({
      localSignatureRid: remappedLocalSignatureRid,
      points: debugInformation.sequencePoints
    }, {
      documentRid: row.Document.rid,
      documentCount: pdb.tables.counts[48],
      localSignatureCount: newCounts[17]
    });
    const appended = appendBlobHeap(blobHeap, encoded);
    blobHeap = appended.heap;
    changed = true;
    return { ...row, SequencePoints: appended.index };
  });

  const rowCounts = new Map([...pdb.rowCounts].map(([table]) =>
    [table, newCounts[table]]
  ));
  const tableCounts = [...pdb.tables.counts];
  for (let table = 0; table < 45; table++) {
    tableCounts[table] = newCounts[table];
  }
  if (methodRows.length > 0) rows.set(49, methodRowsWithRemappedSignatures);
  if (changed) blobStream.bytes = blobHeap;

  const pdbStream = new Uint8Array(32 + rowCounts.size * 4);
  pdbStream.set(pdb.id);
  const pdbView = new DataView(pdbStream.buffer);
  pdbView.setUint32(20, pdb.entryPointToken, true);
  pdbView.setUint32(24, Number(pdb.referencedTypeSystemTables & 0xffffffffn), true);
  pdbView.setUint32(28, Number(pdb.referencedTypeSystemTables >> 32n), true);
  let countOffset = 32;
  for (const [table, count] of [...rowCounts].sort(([left], [right]) => left - right)) {
    pdbView.setUint32(countOffset, count, true);
    countOffset += 4;
  }
  const pdbMetadataStream = streams.get("#Pdb");
  if (!pdbMetadataStream) {
    throw new FormatError("Portable PDB is missing its #Pdb stream");
  }
  pdbMetadataStream.bytes = pdbStream;
  return serializeEmbeddedPortablePdb({
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams },
    rowCounts,
    tables: { ...pdb.tables, rows, counts: tableCounts }
  });
}

export function removeEmbeddedPortablePdbMethod(pdb, methodRid, oldCounts, newCounts) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !(pdb.rowCounts instanceof Map)) {
    throw new TypeError("Portable PDB method removal requires parsed PDB data");
  }
  if (!Array.isArray(oldCounts) || !Array.isArray(newCounts) ||
      oldCounts.length < 45 || newCounts.length < 45 ||
      !Number.isInteger(methodRid) || methodRid < 1 || methodRid > oldCounts[6] ||
      newCounts[6] !== oldCounts[6] - 1) {
    throw new UnsupportedFormatError(
      "Portable PDB method removal requires one valid MethodDef row to be removed"
    );
  }
  for (const [table, count] of pdb.rowCounts) {
    if (count !== oldCounts[table]) {
      throw new FormatError(
        `Portable PDB row count for type-system table ${table} does not match assembly metadata`
      );
    }
  }
  const entryPointRid = pdb.entryPointToken & 0x00ffffff;
  if (pdb.entryPointToken === (0x06000000 | methodRid)) {
    throw new UnsupportedFormatError("Portable PDB entry point cannot be removed");
  }
  if (pdb.entryPointToken !== 0 && entryPointRid > oldCounts[6]) {
    throw new FormatError("Portable PDB entry point references a missing MethodDef");
  }
  const entryPointToken = pdb.entryPointToken !== 0 && entryPointRid > methodRid
    ? pdb.entryPointToken - 1
    : pdb.entryPointToken;
  if (entryPointToken !== 0 && (entryPointToken & 0x00ffffff) > newCounts[6]) {
    throw new FormatError("Portable PDB entry point references a removed MethodDef");
  }

  const rows = new Map(pdb.tables.rows);
  const methodRows = rows.get(49) ?? [];
  if (methodRows.length !== 0 && methodRows.length !== oldCounts[6]) {
    throw new FormatError("Portable PDB MethodDebugInformation row count is inconsistent");
  }
  if (methodRows.length === 0) rows.delete(49);
  if (methodRows.length > 0) {
    if (methodRows.some((row, index) => row.rid !== index + 1)) {
      throw new FormatError("Portable PDB MethodDebugInformation rows are not RID-aligned");
    }
    const remainingMethodRows = methodRows
      .filter((row) => row.rid !== methodRid)
      .map((row) => row.rid > methodRid ? { ...row, rid: row.rid - 1 } : { ...row });
    if (remainingMethodRows.length > 0) rows.set(49, remainingMethodRows);
    else rows.delete(49);
  }
  const scopeRows = rows.get(50) ?? [];
  if (scopeRows.some((scope) => scope.Method.rid === methodRid)) {
    throw new UnsupportedFormatError(
      "Portable PDB method removal cannot discard method-scoped debug records"
    );
  }
  const remapMethodReference = (reference) => reference.rid > methodRid
    ? { ...reference, raw: reference.rid - 1, rid: reference.rid - 1 }
    : { ...reference };
  if (rows.has(50)) {
    rows.set(50, scopeRows.map((scope) => scope.Method.rid > methodRid
      ? { ...scope, Method: remapMethodReference(scope.Method) }
      : { ...scope }
    ));
  }
  const stateMachineRows = rows.get(54) ?? [];
  if (stateMachineRows.some((stateMachine) =>
    stateMachine.MoveNextMethod.rid === methodRid ||
    stateMachine.KickoffMethod.rid === methodRid
  )) {
    throw new UnsupportedFormatError(
      "Portable PDB method removal cannot discard method-scoped debug records"
    );
  }
  if (rows.has(54)) {
    rows.set(54, stateMachineRows.map((stateMachine) => ({
      ...stateMachine,
      MoveNextMethod: remapMethodReference(stateMachine.MoveNextMethod),
      KickoffMethod: remapMethodReference(stateMachine.KickoffMethod)
    })));
  }
  const customDebugRows = rows.get(55) ?? [];
  if (customDebugRows.some((record) =>
    record.Parent.target?.table === 6
  )) {
    throw new UnsupportedFormatError(
      "Portable PDB method remapping cannot update method-scoped CustomDebugInformation"
    );
  }
  const remappedCustomDebugRows = customDebugRows.map((record) => {
    const target = record.Parent.target;
    if (target?.table !== 6 || target.rid < methodRid) return { ...record };
    const rid = target.rid - 1;
    return {
      ...record,
      Parent: {
        raw: encodeCodedIndex(6, rid, "HasCustomDebugInformation"),
        target: { ...target, rid }
      }
    };
  });
  let previousCustomDebugParent = 0;
  for (const record of remappedCustomDebugRows) {
    if (record.Parent.raw < previousCustomDebugParent) {
      throw new UnsupportedFormatError(
        "Portable PDB method remapping would violate CustomDebugInformation order"
      );
    }
    previousCustomDebugParent = record.Parent.raw;
  }
  if (rows.has(55)) rows.set(55, remappedCustomDebugRows);

  const rowCounts = new Map([...pdb.rowCounts].map(([table]) =>
    [table, newCounts[table]]
  ));
  const tableCounts = [...pdb.tables.counts];
  for (let table = 0; table < 45; table++) {
    tableCounts[table] = newCounts[table];
  }
  tableCounts[49] = methodRows.length > 0 ? methodRows.length - 1 : 0;
  const valid = tableCounts[49] === 0
    ? pdb.tables.valid & ~(1n << 49n)
    : pdb.tables.valid;

  const pdbStream = new Uint8Array(32 + rowCounts.size * 4);
  pdbStream.set(pdb.id);
  const pdbView = new DataView(pdbStream.buffer);
  pdbView.setUint32(20, entryPointToken, true);
  pdbView.setUint32(24, Number(pdb.referencedTypeSystemTables & 0xffffffffn), true);
  pdbView.setUint32(28, Number(pdb.referencedTypeSystemTables >> 32n), true);
  let countOffset = 32;
  for (const [table, count] of [...rowCounts].sort(([left], [right]) => left - right)) {
    pdbView.setUint32(countOffset, count, true);
    countOffset += 4;
  }

  const streams = new Map([...pdb.metadataRoot.streams].map(([name, stream]) =>
    [name, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
  ));
  const pdbMetadataStream = streams.get("#Pdb");
  if (!pdbMetadataStream) {
    throw new FormatError("Portable PDB is missing its #Pdb stream");
  }
  pdbMetadataStream.bytes = pdbStream;
  return serializeEmbeddedPortablePdb({
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams },
    rowCounts,
    tables: { ...pdb.tables, rows, counts: tableCounts, valid }
  });
}

export function replaceEmbeddedPortablePdbSource(pdb, documentRid, source, { compress = true } = {}) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !Array.isArray(pdb.customDebugInformation)) {
    throw new TypeError("Portable PDB EmbeddedSource editing requires parsed PDB data");
  }
  if (!Number.isInteger(documentRid) || documentRid < 1 ||
      documentRid > pdb.tables.counts[48]) {
    throw new RangeError(`Invalid Portable PDB Document row ID ${documentRid}`);
  }
  if (!(source instanceof Uint8Array)) {
    throw new TypeError("Portable PDB embedded source must be a Uint8Array");
  }
  if (source.length > maxEmbeddedSourceSize) {
    throw new UnsupportedFormatError(
      `EmbeddedSource exceeds the ${maxEmbeddedSourceSize}-byte size limit`
    );
  }
  if (typeof compress !== "boolean") {
    throw new TypeError("Portable PDB EmbeddedSource compression option must be a boolean");
  }
  const debugInfo = pdb.customDebugInformation.find((row) =>
    row.kind === embeddedSourceKind &&
    row.Parent.target?.table === 48 &&
    row.Parent.target.rid === documentRid
  );
  if (!debugInfo) {
    throw new UnsupportedFormatError(
      `Portable PDB Document row ${documentRid} has no EmbeddedSource record`
    );
  }
  const documentRow = pdb.tables.rows.get(48)?.[documentRid - 1];
  if (!documentRow) {
    throw new FormatError(`Portable PDB Document row ${documentRid} is missing`);
  }
  const hashName = getPortablePdbDocumentHashName(pdb, documentRow);
  const rawSource = Uint8Array.from(source);
  const sourceHash = Uint8Array.from(createHash(hashName).update(rawSource).digest());
  const value = encodeEmbeddedSourceValue(rawSource, compress);

  return replacePortablePdbCustomDebugInformationValue(
    pdb,
    debugInfo,
    value,
    { documentRid, hash: sourceHash }
  );
}

export function addEmbeddedPortablePdbSource(pdb, documentRid, source, { compress = true } = {}) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !Array.isArray(pdb.customDebugInformation)) {
    throw new TypeError("Portable PDB EmbeddedSource editing requires parsed PDB data");
  }
  if (!Number.isInteger(documentRid) || documentRid < 1 ||
      documentRid > pdb.tables.counts[48]) {
    throw new RangeError(`Invalid Portable PDB Document row ID ${documentRid}`);
  }
  if (!(source instanceof Uint8Array)) {
    throw new TypeError("Portable PDB embedded source must be a Uint8Array");
  }
  if (source.length > maxEmbeddedSourceSize) {
    throw new UnsupportedFormatError(
      `EmbeddedSource exceeds the ${maxEmbeddedSourceSize}-byte size limit`
    );
  }
  if (typeof compress !== "boolean") {
    throw new TypeError("Portable PDB EmbeddedSource compression option must be a boolean");
  }
  if (pdb.customDebugInformation.some((row) =>
    row.kind === embeddedSourceKind &&
    row.Parent.target?.table === 48 &&
    row.Parent.target.rid === documentRid
  )) {
    throw new UnsupportedFormatError(
      `Portable PDB Document row ${documentRid} already has an EmbeddedSource record`
    );
  }
  const documentRow = pdb.tables.rows.get(48)?.[documentRid - 1];
  if (!documentRow) {
    throw new FormatError(`Portable PDB Document row ${documentRid} is missing`);
  }
  const hashName = getPortablePdbDocumentHashName(pdb, documentRow);
  const rawSource = Uint8Array.from(source);
  const sourceHash = Uint8Array.from(createHash(hashName).update(rawSource).digest());
  const value = encodeEmbeddedSourceValue(rawSource, compress);
  const streams = new Map([...pdb.metadataRoot.streams].map(([streamName, stream]) =>
    [streamName, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
  ));
  const guidStream = streams.get("#GUID");
  const blobStream = streams.get("#Blob");
  if (!guidStream || !blobStream) {
    throw new FormatError("Portable PDB metadata is missing its GUID or Blob heap");
  }
  if (guidStream.bytes.length % 16 !== 0) {
    throw new FormatError("Portable PDB GUID heap size is not a multiple of 16 bytes");
  }
  const kindIndex = guidStream.bytes.length / 16 + 1;
  const expandedGuidStream = new Uint8Array(guidStream.bytes.length + 16);
  expandedGuidStream.set(guidStream.bytes);
  expandedGuidStream.set(embeddedSourceGuidBytes, guidStream.bytes.length);
  guidStream.bytes = expandedGuidStream;
  const appendedValue = appendBlobHeap(blobStream.bytes, value);
  const appendedHash = appendBlobHeap(appendedValue.heap, sourceHash);
  blobStream.bytes = appendedHash.heap;

  const parent = {
    raw: encodeCodedIndex(48, documentRid, "HasCustomDebugInformation"),
    target: { table: 48, tableName: "Document", rid: documentRid }
  };
  const rows = new Map(pdb.tables.rows);
  rows.set(48, (pdb.tables.rows.get(48) ?? []).map((row) =>
    row.rid === documentRid ? { ...row, Hash: appendedHash.index } : { ...row }
  ));
  const debugRows = [...(pdb.tables.rows.get(55) ?? []), {
    table: 55,
    tableName: "CustomDebugInformation",
    rid: 0,
    Parent: parent,
    Kind: kindIndex,
    Value: appendedValue.index
  }].sort((left, right) => left.Parent.raw - right.Parent.raw)
    .map((row, index) => ({ ...row, rid: index + 1 }));
  rows.set(55, debugRows);
  const counts = [...pdb.tables.counts];
  counts[55] = debugRows.length;
  return serializeEmbeddedPortablePdb({
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams },
    tables: {
      ...pdb.tables,
      valid: debugRows.length > 0
        ? pdb.tables.valid | (1n << 55n)
        : pdb.tables.valid & ~(1n << 55n),
      counts,
      rows
    }
  });
}

function getPortablePdbDocumentHashName(pdb, documentRow) {
  const hashAlgorithmBytes = pdb.heaps.getGuid(documentRow.HashAlgorithm);
  const hashAlgorithm = hashAlgorithmBytes ? formatGuid(hashAlgorithmBytes) : null;
  const hashName = documentHashAlgorithms.get(hashAlgorithm);
  if (!hashName) {
    throw new UnsupportedFormatError(
      `Portable PDB Document hash algorithm ${hashAlgorithm ?? "(nil)"} is unsupported`
    );
  }
  return hashName;
}

function encodeEmbeddedSourceValue(source, compress) {
  const compressed = compress && source.length > 0
    ? Uint8Array.from(deflateRawSync(source))
    : null;
  const useCompressed = compressed !== null && compressed.length < source.length;
  const payload = useCompressed ? compressed : source;
  const value = new Uint8Array(4 + payload.length);
  new DataView(value.buffer).setUint32(0, useCompressed ? source.length : 0, true);
  value.set(payload, 4);
  return value;
}

function replacePortablePdbCustomDebugInformationValue(
  pdb,
  debugInfo,
  value,
  documentHashUpdate = null
) {
  const streams = new Map([...pdb.metadataRoot.streams].map(([streamName, stream]) =>
    [streamName, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
  ));
  const blobStream = streams.get("#Blob");
  if (!blobStream) throw new FormatError("Portable PDB metadata is missing its #Blob heap");
  const appended = appendBlobHeap(blobStream.bytes, value);
  blobStream.bytes = appended.heap;
  const rows = new Map(pdb.tables.rows);
  const debugRows = pdb.tables.rows.get(55) ?? [];
  rows.set(55, debugRows.map((row) =>
    row.rid === debugInfo.rid ? { ...row, Value: appended.index } : { ...row }
  ));
  if (documentHashUpdate) {
    const documentRows = pdb.tables.rows.get(48) ?? [];
    const appendedHash = appendBlobHeap(blobStream.bytes, documentHashUpdate.hash);
    blobStream.bytes = appendedHash.heap;
    rows.set(48, documentRows.map((row) =>
      row.rid === documentHashUpdate.documentRid
        ? { ...row, Hash: appendedHash.index }
        : { ...row }
    ));
  }
  return serializeEmbeddedPortablePdb({
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams },
    tables: { ...pdb.tables, rows }
  });
}

function encodeSourceLinkValue(sourceLink) {
  if (sourceLink === null || Array.isArray(sourceLink) || typeof sourceLink !== "object" ||
      sourceLink.documents === null || Array.isArray(sourceLink.documents) ||
      typeof sourceLink.documents !== "object" ||
      Object.values(sourceLink.documents).some((mapping) => typeof mapping !== "string")) {
    throw new TypeError("SourceLink requires a documents object with string mappings");
  }
  const json = JSON.stringify(sourceLink);
  if (typeof json !== "string") {
    throw new TypeError("SourceLink value could not be serialized as JSON");
  }
  const encoded = new TextEncoder().encode(json);
  if (decodeUtf8(encoded, "Portable PDB SourceLink") !== json) {
    throw new TypeError("SourceLink JSON must contain valid Unicode text");
  }
  return encoded;
}

export function addEmbeddedPortablePdbSourceLink(pdb, sourceLink) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !Array.isArray(pdb.customDebugInformation)) {
    throw new TypeError("Portable PDB SourceLink editing requires parsed PDB data");
  }
  if (pdb.customDebugInformation.some((row) =>
    row.kind === sourceLinkKind && row.Parent.target?.table === 0
  )) {
    throw new UnsupportedFormatError("Portable PDB already has a module-scoped SourceLink record");
  }
  const value = encodeSourceLinkValue(sourceLink);
  const streams = new Map([...pdb.metadataRoot.streams].map(([streamName, stream]) =>
    [streamName, { ...stream, bytes: Uint8Array.from(stream.bytes) }]
  ));
  const guidStream = streams.get("#GUID");
  const blobStream = streams.get("#Blob");
  if (!guidStream || !blobStream) {
    throw new FormatError("Portable PDB metadata is missing its GUID or Blob heap");
  }
  if (guidStream.bytes.length % 16 !== 0) {
    throw new FormatError("Portable PDB GUID heap size is not a multiple of 16 bytes");
  }
  const kindIndex = guidStream.bytes.length / 16 + 1;
  const expandedGuidStream = new Uint8Array(guidStream.bytes.length + 16);
  expandedGuidStream.set(guidStream.bytes);
  expandedGuidStream.set(sourceLinkGuidBytes, guidStream.bytes.length);
  guidStream.bytes = expandedGuidStream;
  const appendedValue = appendBlobHeap(blobStream.bytes, value);
  blobStream.bytes = appendedValue.heap;

  const parent = {
    raw: encodeCodedIndex(0, 1, "HasCustomDebugInformation"),
    target: { table: 0, tableName: "Module", rid: 1 }
  };
  const rows = new Map(pdb.tables.rows);
  const debugRows = [...(pdb.tables.rows.get(55) ?? []), {
    table: 55,
    tableName: "CustomDebugInformation",
    rid: 0,
    Parent: parent,
    Kind: kindIndex,
    Value: appendedValue.index
  }].sort((left, right) => left.Parent.raw - right.Parent.raw)
    .map((row, index) => ({ ...row, rid: index + 1 }));
  rows.set(55, debugRows);
  const counts = [...pdb.tables.counts];
  counts[55] = debugRows.length;
  return serializeEmbeddedPortablePdb({
    ...pdb,
    metadataRoot: { ...pdb.metadataRoot, streams },
    tables: {
      ...pdb.tables,
      valid: debugRows.length > 0
        ? pdb.tables.valid | (1n << 55n)
        : pdb.tables.valid & ~(1n << 55n),
      counts,
      rows
    }
  });
}

export function replaceEmbeddedPortablePdbSourceLink(pdb, sourceLink) {
  if (!pdb?.metadataRoot?.streams || !(pdb.tables?.rows instanceof Map) ||
      !Array.isArray(pdb.tables.counts) || !Array.isArray(pdb.customDebugInformation)) {
    throw new TypeError("Portable PDB SourceLink editing requires parsed PDB data");
  }
  const encoded = encodeSourceLinkValue(sourceLink);
  const debugInfo = pdb.customDebugInformation.find((row) =>
    row.kind === sourceLinkKind && row.Parent.target?.table === 0
  );
  if (!debugInfo) {
    throw new UnsupportedFormatError("Portable PDB has no module-scoped SourceLink record");
  }
  return replacePortablePdbCustomDebugInformationValue(
    pdb,
    debugInfo,
    encoded
  );
}
