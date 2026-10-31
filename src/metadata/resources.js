import { FormatError } from "../binary/errors.js";

export function parseManifestResources(bytes, directory, rows, heaps, rvaToOffset) {
  const embeddedRows = rows.filter((row) => row.Implementation.target === null);
  let directoryOffset = 0;
  if (embeddedRows.length > 0) {
    if (!directory || directory.rva === 0 || directory.size === 0) {
      throw new FormatError("Embedded manifest resources have no CLI resources directory");
    }
    directoryOffset = rvaToOffset(directory.rva, directory.size);
  }

  return rows.map((row) => {
    const implementation = row.Implementation.target;
    let data = null;
    if (implementation === null) {
      if (!Number.isInteger(row.Offset) || row.Offset < 0 ||
          row.Offset > directory.size - 4) {
        throw new FormatError(`ManifestResource row ${row.rid} offset is outside the CLI resources directory`);
      }
      const lengthOffset = directoryOffset + row.Offset;
      const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
        .getUint32(lengthOffset, true);
      if (length > directory.size - row.Offset - 4) {
        throw new FormatError(`ManifestResource row ${row.rid} payload exceeds the CLI resources directory`);
      }
      data = bytes.slice(lengthOffset + 4, lengthOffset + 4 + length);
    }
    return {
      rid: row.rid,
      name: heaps.getString(row.Name),
      flags: row.Flags,
      implementation,
      data
    };
  });
}
