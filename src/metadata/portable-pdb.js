import { BinaryReader, readCompressedInt, readCompressedUInt } from "../binary/reader.js";
import { FormatError } from "../binary/errors.js";

function decodeUtf8(bytes, context) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new FormatError(`Invalid UTF-8 data: ${error.message}`, { context });
  }
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
  return { documents, methodDebugInformation };
}
