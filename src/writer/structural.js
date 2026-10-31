import { FormatError } from "../binary/errors.js";
import { serializeMetadataRoot } from "../metadata/root-writer.js";
import { serializeTablesStream } from "../metadata/writer.js";
import { encodeMethodBody } from "../il/rewrite.js";
import { appendPeSection, getNextSectionVirtualAddress } from "./pe.js";
import { applyPatches } from "./patch.js";

function align(value, alignment) {
  return Math.ceil(value / alignment) * alignment;
}

function writeDebugDirectory(payload, tableOffset, assembly, replacements) {
  const entries = assembly.pe.debugDirectoryEntries;
  const tableSize = entries.length * 28;
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const preservedEntries = [];
  const relocatedEntries = [];
  let dataOffset = align(tableOffset + tableSize, 4);
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index];
    const entryOffset = tableOffset + index * 28;
    const replacementValue = replacements.get(index);
    const replacement = replacementValue?.bytes ?? replacementValue;
    view.setUint32(entryOffset, entry.characteristics, true);
    view.setUint32(
      entryOffset + 4,
      replacementValue?.timeDateStamp ?? entry.timeDateStamp,
      true
    );
    view.setUint16(entryOffset + 8, entry.majorVersion, true);
    view.setUint16(entryOffset + 10, entry.minorVersion, true);
    view.setUint32(entryOffset + 12, entry.type, true);
    if (replacement) {
      view.setUint32(entryOffset + 16, replacement.length, true);
      relocatedEntries.push({
        entryOffset,
        dataOffset,
        size: replacement.length
      });
      payload.set(replacement, dataOffset);
      dataOffset = align(dataOffset + replacement.length, 4);
    } else {
      view.setUint32(entryOffset + 16, entry.sizeOfData, true);
      view.setUint32(entryOffset + 20, entry.addressOfRawData, true);
      view.setUint32(entryOffset + 24, entry.pointerToRawData, true);
      if (entry.pointerToRawData !== 0) {
        preservedEntries.push({
          pointerOffset: entryOffset + 24,
          pointer: entry.pointerToRawData
        });
      }
    }
  }
  return {
    size: tableSize,
    preservedEntries,
    relocatedEntries,
    endOffset: dataOffset
  };
}

function cloneTables(tables) {
  const rows = new Map();
  for (const [id, tableRows] of tables.rows) {
    rows.set(id, tableRows.map((row) => {
      const copy = { ...row };
      for (const [key, value] of Object.entries(copy)) {
        if (value && typeof value === "object") {
          copy[key] = value.target !== undefined
            ? { ...value, target: value.target ? { ...value.target } : null }
            : { ...value };
        }
      }
      return copy;
    }));
  }
  return { ...tables, rows, counts: [...tables.counts] };
}

function getHeapStreams(assembly) {
  if (assembly._heapStreams) {
    return new Map([...assembly._heapStreams].map(([name, bytes]) => [name, bytes.slice()]));
  }
  return new Map([...assembly.metadataRoot.streams].map(([name, stream]) => [name, stream.bytes.slice()]));
}

function buildMetadata(assembly, tables, heapStreams, tableStreamName) {
  const streams = new Map(heapStreams);
  streams.set(tableStreamName, serializeTablesStream(tables, heapStreams));
  return serializeMetadataRoot(assembly.metadataRoot, streams);
}

function buildResourcePayload(assembly, tables) {
  if (assembly._resourceEdits.size === 0) return null;
  const rows = tables.rows.get(40) ?? [];
  const entries = [];
  let size = 0;
  for (const resource of assembly.resources) {
    if (resource.implementation !== null) continue;
    const data = assembly._resourceEdits.get(resource.rid) ?? resource.data;
    if (!(data instanceof Uint8Array)) {
      throw new FormatError(`Embedded ManifestResource row ${resource.rid} has no payload`);
    }
    const offset = align(size, 8);
    if (offset > 0xffffffff) throw new RangeError("Manifest resource offset exceeds 32-bit range");
    const row = rows[resource.rid - 1];
    if (!row || row.rid !== resource.rid) {
      throw new FormatError(`ManifestResource row ${resource.rid} is missing from the metadata tables`);
    }
    row.Offset = offset;
    if (data.length > 0xffffffff) throw new RangeError("Manifest resource exceeds the CLI size limit");
    entries.push({ offset, data });
    size = offset + 4 + data.length;
    if (size > 0xffffffff) throw new RangeError("CLI resources directory exceeds 32-bit range");
  }
  if (entries.length === 0) throw new FormatError("No embedded resources are available for replacement");
  const output = new Uint8Array(size);
  const view = new DataView(output.buffer);
  for (const entry of entries) {
    view.setUint32(entry.offset, entry.data.length, true);
    output.set(entry.data, entry.offset + 4);
  }
  return output;
}

export function serializeStructural(
  assembly,
  { preserveStrongName = false, strongNameSignatureSize = 0 } = {}
) {
  const source = applyPatches(assembly.bytes, assembly._patches, assembly.cli, assembly.pe, {
    preserveStrongName
  });
  const tables = cloneTables(assembly.tables);
  const heapStreams = getHeapStreams(assembly);
  const tableStreamName = assembly.metadataRoot.streams.has("#~") ? "#~" : "#-";
  let metadata = buildMetadata(assembly, tables, heapStreams, tableStreamName);
  const virtualAddress = getNextSectionVirtualAddress(assembly.pe);
  let bodyOffset = align(metadata.length, 4);
  const encodedBodies = [];
  const bodies = new Map(assembly._addedMethodBodies ?? []);
  for (const [methodRid, state] of assembly._structuralBodies) bodies.set(methodRid, state);
  for (const [methodRid, state] of [...bodies].sort(([left], [right]) => left - right)) {
    const methodRow = tables.rows.get(6)?.[methodRid - 1];
    if (!methodRow) throw new FormatError(`MethodDef row ${methodRid} is missing from the metadata tables`);
    const methodRva = virtualAddress + bodyOffset;
    if (methodRva > 0xffffffff) throw new RangeError("Rewritten method RVA exceeds 32-bit range");
    const bytes = state instanceof Uint8Array
      ? state
      : encodeMethodBody(state, methodRva);
    methodRow.RVA = methodRva;
    encodedBodies.push({ offset: bodyOffset, bytes });
    bodyOffset = align(bodyOffset + bytes.length, 4);
  }
  const resourcePayload = buildResourcePayload(assembly, tables);
  const resourceOffset = resourcePayload ? align(bodyOffset, 8) : 0;
  const resourceEnd = resourcePayload ? resourceOffset + resourcePayload.length : bodyOffset;
  const signatureOffset = strongNameSignatureSize > 0 ? align(resourceEnd, 4) : 0;
  const signatureEnd = strongNameSignatureSize > 0
    ? signatureOffset + strongNameSignatureSize
    : resourceEnd;
  const hasDebugEdits = (assembly._embeddedPortablePdbEdits?.size ?? 0) > 0;
  const debugTableOffset = hasDebugEdits ? align(signatureEnd, 4) : 0;
  const debugTableSize = hasDebugEdits
    ? assembly.pe.debugDirectoryEntries.length * 28
    : 0;
  const debugDataStart = hasDebugEdits
    ? align(debugTableOffset + debugTableSize, 4)
    : 0;
  const debugRecordEdits = new Map(assembly._embeddedPortablePdbEdits ?? []);
  for (const [index, edit] of assembly._debugRecordEdits ?? []) {
    debugRecordEdits.set(index, edit);
  }
  let finalPayloadSize = hasDebugEdits ? debugDataStart : signatureEnd;
  if (hasDebugEdits) {
    for (const [index, replacementValue] of [...debugRecordEdits].sort(
      ([left], [right]) => left - right
    )) {
      if (!assembly.pe.debugDirectoryEntries[index]) {
        throw new FormatError(`Debug-directory entry ${index} is missing`);
      }
      const replacement = replacementValue?.bytes ?? replacementValue;
      finalPayloadSize = align(finalPayloadSize, 4) + replacement.length;
    }
  }
  const rewrittenMetadata = buildMetadata(assembly, tables, heapStreams, tableStreamName);
  if (rewrittenMetadata.length !== metadata.length) {
    throw new FormatError("Metadata size changed while assigning method RVAs");
  }
  metadata = rewrittenMetadata;

  const payload = new Uint8Array(finalPayloadSize);
  payload.set(metadata);
  for (const body of encodedBodies) payload.set(body.bytes, body.offset);
  if (resourcePayload) payload.set(resourcePayload, resourceOffset);
  let debugDirectoryPayload = null;
  if (hasDebugEdits) {
    debugDirectoryPayload = writeDebugDirectory(
      payload,
      debugTableOffset,
      assembly,
      debugRecordEdits
    );
  }
  const resourcesDirectory = resourcePayload
    ? { rva: virtualAddress + resourceOffset, size: resourcePayload.length }
    : assembly._clearResourcesDirectory
      ? { rva: 0, size: 0 }
      : null;
  const appended = appendPeSection(
    source,
    assembly.pe,
    assembly.cli,
    payload,
    0,
    metadata.length,
    resourcesDirectory,
    preserveStrongName,
    hasDebugEdits
      ? {
        tableOffset: debugTableOffset,
        size: debugDirectoryPayload.size,
        preservedEntries: debugDirectoryPayload.preservedEntries,
        relocatedEntries: debugDirectoryPayload.relocatedEntries
      }
      : null
  );
  if (strongNameSignatureSize > 0) {
    const signatureRva = virtualAddress + signatureOffset;
    if (signatureRva > 0xffffffff) throw new RangeError("Strong-name signature RVA exceeds 32-bit range");
    const view = new DataView(
      appended.bytes.buffer,
      appended.bytes.byteOffset,
      appended.bytes.byteLength
    );
    const directoryOffset = appended.cliOffset +
      assembly.cli.strongNameDirectoryOffset - assembly.cli.offset;
    view.setUint32(directoryOffset, signatureRva, true);
    view.setUint32(directoryOffset + 4, strongNameSignatureSize, true);
  }
  return appended.bytes;
}
