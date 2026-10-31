import { FormatError, UnsupportedFormatError } from "../binary/errors.js";

function align(value, alignment) {
  if (!Number.isInteger(alignment) || alignment < 1 || (alignment & (alignment - 1)) !== 0) {
    throw new UnsupportedFormatError(`Unsupported PE alignment ${alignment}`);
  }
  return Math.ceil(value / alignment) * alignment;
}

function writeU16(view, offset, value, label) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new RangeError(`${label} exceeds 16-bit range`);
  view.setUint16(offset, value, true);
}

function writeU32(view, offset, value, label) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError(`${label} exceeds 32-bit range`);
  view.setUint32(offset, value, true);
}

export function getNextSectionVirtualAddress(pe) {
  let maxVirtualEnd = pe.sizeOfImage;
  for (const section of pe.sections) {
    maxVirtualEnd = Math.max(maxVirtualEnd, section.virtualAddress + Math.max(section.virtualSize, section.rawSize));
  }
  return align(maxVirtualEnd, pe.sectionAlignment);
}

function expandHeaderForSection(input, pe) {
  const firstRawPointer = Math.min(
    ...pe.sections.filter((section) => section.rawSize > 0).map((section) => section.rawPointer),
    pe.sizeOfHeaders
  );
  const sectionHeaderOffset = pe.sectionOffset + pe.sectionCount * 40;
  const newHeaderEnd = sectionHeaderOffset + 40;
  if (sectionHeaderOffset > firstRawPointer) {
    throw new UnsupportedFormatError("PE section headers overlap section data");
  }
  const required = newHeaderEnd - Math.min(pe.sizeOfHeaders, firstRawPointer);
  const delta = required > 0 ? align(required, pe.fileAlignment) : 0;
  const insertionOffset = firstRawPointer;
  const output = new Uint8Array(input.length + delta);
  output.set(input.subarray(0, insertionOffset));
  output.set(input.subarray(insertionOffset), insertionOffset + delta);
  const view = new DataView(output.buffer);

  if (delta > 0) {
    for (let index = 0; index < pe.sections.length; index++) {
      const header = pe.sectionOffset + index * 40;
      for (const fieldOffset of [20, 24, 28]) {
        const pointer = view.getUint32(header + fieldOffset, true);
        if (pointer >= insertionOffset && pointer !== 0) view.setUint32(header + fieldOffset, pointer + delta, true);
      }
    }
    if (pe.symbolTablePointer >= insertionOffset && pe.symbolTablePointer !== 0) {
      view.setUint32(pe.peOffset + 12, pe.symbolTablePointer + delta, true);
    }
    view.setUint32(pe.optionalHeaderOffset + 60, pe.sizeOfHeaders + delta, true);
    const debugDirectory = pe.directories[6];
    if (debugDirectory?.rva && debugDirectory.size > 0) {
      if (debugDirectory.size % 28 !== 0) {
        throw new UnsupportedFormatError("Debug directory size is not a multiple of IMAGE_DEBUG_DIRECTORY");
      }
      const originalOffset = pe.rvaToOffset(debugDirectory.rva, debugDirectory.size);
      if (originalOffset < insertionOffset && originalOffset + debugDirectory.size > insertionOffset) {
        throw new UnsupportedFormatError("Debug directory crosses the PE header expansion boundary");
      }
      const debugOffset = originalOffset >= insertionOffset ? originalOffset + delta : originalOffset;
      for (let offset = debugOffset; offset < debugOffset + debugDirectory.size; offset += 28) {
        const pointer = view.getUint32(offset + 24, true);
        if (pointer >= insertionOffset && pointer !== 0) view.setUint32(offset + 24, pointer + delta, true);
      }
    }
  }
  return { bytes: output, delta, insertionOffset, sectionHeaderOffset, firstRawPointer: firstRawPointer + delta };
}

export function appendPeSection(
  input,
  pe,
  cli,
  payload,
  metadataOffset,
  metadataSize,
  resourcesDirectory = null,
  preserveStrongName = false,
  debugDirectoryPayload = null
) {
  if (payload.length === 0) throw new RangeError("Cannot add an empty PE section");
  if (pe.sectionCount >= 0xffff) throw new UnsupportedFormatError("PE section-count limit reached");
  const fileAlignment = pe.fileAlignment;
  const sectionAlignment = pe.sectionAlignment;
  const expanded = expandHeaderForSection(input, pe);
  const rawPointer = align(expanded.bytes.length, fileAlignment);
  const rawSize = align(payload.length, fileAlignment);
  const sectionHeaderOffset = expanded.sectionHeaderOffset;
  if (sectionHeaderOffset + 40 > pe.sizeOfHeaders + expanded.delta ||
      sectionHeaderOffset + 40 > expanded.firstRawPointer) {
    throw new UnsupportedFormatError("PE headers have no room for an additional section header");
  }
  const virtualAddress = getNextSectionVirtualAddress(pe);
  const imageSize = align(virtualAddress + payload.length, sectionAlignment);
  if (rawPointer + rawSize > 0xffffffff || imageSize > 0xffffffff) {
    throw new RangeError("Rewritten PE exceeds 32-bit image limits");
  }

  const output = new Uint8Array(rawPointer + rawSize);
  output.set(expanded.bytes);
  output.set(payload, rawPointer);
  const view = new DataView(output.buffer);
  view.setUint16(pe.peOffset + 6, pe.sectionCount + 1, true);
  writeU32(view, pe.optionalHeaderOffset + 4, pe.sizeOfCode + rawSize, "SizeOfCode");
  writeU32(view, pe.optionalHeaderOffset + 56, imageSize, "SizeOfImage");
  view.setUint32(pe.checksumOffset, 0, true);

  output.set(new TextEncoder().encode(".jsilnet"), sectionHeaderOffset);
  writeU32(view, sectionHeaderOffset + 8, payload.length, "section virtual size");
  writeU32(view, sectionHeaderOffset + 12, virtualAddress, "section virtual address");
  writeU32(view, sectionHeaderOffset + 16, rawSize, "section raw size");
  writeU32(view, sectionHeaderOffset + 20, rawPointer, "section raw pointer");
  writeU32(view, sectionHeaderOffset + 24, 0, "section relocation pointer");
  writeU32(view, sectionHeaderOffset + 28, 0, "section line-number pointer");
  writeU16(view, sectionHeaderOffset + 32, 0, "section relocation count");
  writeU16(view, sectionHeaderOffset + 34, 0, "section line-number count");
  writeU32(view, sectionHeaderOffset + 36, 0x60000020, "section characteristics");

  const shiftedCliOffset = cli.offset >= expanded.insertionOffset ? cli.offset + expanded.delta : cli.offset;
  if (metadataOffset !== null) {
    const newMetadataRva = virtualAddress + metadataOffset;
    writeU32(view, shiftedCliOffset + 8, newMetadataRva, "CLI metadata RVA");
    writeU32(view, shiftedCliOffset + 12, metadataSize, "CLI metadata size");
  }
  if (resourcesDirectory) {
    writeU32(view, shiftedCliOffset + 24, resourcesDirectory.rva, "CLI resources RVA");
    writeU32(view, shiftedCliOffset + 28, resourcesDirectory.size, "CLI resources size");
  }
  if (!preserveStrongName && (cli.flags & 0x08) !== 0) {
    const signature = cli.strongNameSignature;
    if (signature.rva !== 0 && signature.size !== 0) {
      const oldOffset = pe.rvaToOffset(signature.rva, signature.size);
      const signatureOffset = oldOffset >= expanded.insertionOffset ? oldOffset + expanded.delta : oldOffset;
      output.fill(0, signatureOffset, signatureOffset + signature.size);
    }
    writeU32(view, shiftedCliOffset + 16, cli.flags & ~0x08, "CLI flags");
    writeU32(view, shiftedCliOffset + 32, 0, "strong-name RVA");
    writeU32(view, shiftedCliOffset + 36, 0, "strong-name size");
  }
  if (debugDirectoryPayload) {
    const directoryBase = pe.optionalHeaderOffset +
      (pe.optionalHeaderMagic === 0x10b ? 96 : 112);
    const directoryField = directoryBase + 6 * 8;
    if (directoryField + 8 > pe.optionalHeaderOffset + pe.optionalHeaderSize) {
      throw new UnsupportedFormatError("PE optional header has no debug data-directory slot");
    }
    writeU32(
      view,
      directoryField,
      virtualAddress + debugDirectoryPayload.tableOffset,
      "debug directory RVA"
    );
    writeU32(view, directoryField + 4, debugDirectoryPayload.size, "debug directory size");
    for (const entry of debugDirectoryPayload.preservedEntries) {
      const pointer = entry.pointer >= expanded.insertionOffset && entry.pointer !== 0
        ? entry.pointer + expanded.delta
        : entry.pointer;
      writeU32(view, rawPointer + entry.pointerOffset, pointer, "debug record raw pointer");
    }
    for (const entry of debugDirectoryPayload.relocatedEntries) {
      writeU32(
        view,
        rawPointer + entry.entryOffset + 16,
        entry.size,
        "debug record data size"
      );
      writeU32(
        view,
        rawPointer + entry.entryOffset + 20,
        virtualAddress + entry.dataOffset,
        "debug record data RVA"
      );
      writeU32(
        view,
        rawPointer + entry.entryOffset + 24,
        rawPointer + entry.dataOffset,
        "debug record raw pointer"
      );
    }
  }
  return {
    bytes: output,
    virtualAddress,
    rawPointer,
    rawSize,
    headerExpansion: expanded.delta,
    cliOffset: shiftedCliOffset
  };
}
