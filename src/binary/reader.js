import { FormatError } from "./errors.js";

export class BinaryReader {
  constructor(input, { start = 0, length, baseOffset = 0, context } = {}) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    const available = bytes.byteLength - start;
    const size = length ?? available;
    if (!Number.isInteger(start) || !Number.isInteger(size) || start < 0 || size < 0 || size > available) {
      throw new RangeError("Invalid binary reader range");
    }
    this.bytes = bytes.subarray(start, start + size);
    this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
    this.baseOffset = baseOffset;
    this.context = context;
    this.position = 0;
  }

  get remaining() {
    return this.bytes.length - this.position;
  }

  get absoluteOffset() {
    return this.baseOffset + this.position;
  }

  ensure(size) {
    if (!Number.isInteger(size) || size < 0 || size > this.remaining) {
      throw new FormatError(`Read of ${size} byte(s) exceeds the available ${this.remaining}`, {
        offset: this.absoluteOffset,
        context: this.context
      });
    }
  }

  seek(position) {
    if (!Number.isInteger(position) || position < 0 || position > this.bytes.length) {
      throw new FormatError(`Invalid seek position ${position}`, {
        offset: this.baseOffset + Math.max(0, position || 0),
        context: this.context
      });
    }
    this.position = position;
  }

  skip(size) {
    this.ensure(size);
    this.position += size;
  }

  align(alignment) {
    if (!Number.isInteger(alignment) || alignment < 1 || (alignment & (alignment - 1)) !== 0) {
      throw new RangeError("Alignment must be a positive power of two");
    }
    this.skip((-this.position) & (alignment - 1));
  }

  u1() {
    this.ensure(1);
    return this.view.getUint8(this.position++);
  }

  i1() {
    this.ensure(1);
    return this.view.getInt8(this.position++);
  }

  u2() {
    this.ensure(2);
    const value = this.view.getUint16(this.position, true);
    this.position += 2;
    return value;
  }

  i2() {
    this.ensure(2);
    const value = this.view.getInt16(this.position, true);
    this.position += 2;
    return value;
  }

  u4() {
    this.ensure(4);
    const value = this.view.getUint32(this.position, true);
    this.position += 4;
    return value;
  }

  i4() {
    this.ensure(4);
    const value = this.view.getInt32(this.position, true);
    this.position += 4;
    return value;
  }

  u8() {
    this.ensure(8);
    const value = this.view.getBigUint64(this.position, true);
    this.position += 8;
    return value;
  }

  f4() {
    this.ensure(4);
    const value = this.view.getFloat32(this.position, true);
    this.position += 4;
    return value;
  }

  f8() {
    this.ensure(8);
    const value = this.view.getFloat64(this.position, true);
    this.position += 8;
    return value;
  }

  take(size) {
    this.ensure(size);
    const result = this.bytes.subarray(this.position, this.position + size);
    this.position += size;
    return result;
  }

  slice(size, context = this.context) {
    const start = this.position;
    this.ensure(size);
    this.position += size;
    return new BinaryReader(this.bytes, {
      start,
      length: size,
      baseOffset: this.baseOffset + start,
      context
    });
  }
}

export function readCompressedUInt(reader) {
  const first = reader.u1();
  if ((first & 0x80) === 0) return first;
  if ((first & 0xc0) === 0x80) return ((first & 0x3f) << 8) | reader.u1();
  if ((first & 0xe0) === 0xc0) {
    return ((first & 0x1f) * 0x1000000) +
      (reader.u1() << 16) +
      (reader.u1() << 8) +
      reader.u1();
  }
  throw new FormatError("Invalid compressed unsigned integer prefix", {
    offset: reader.absoluteOffset - 1,
    context: reader.context
  });
}

export function readCompressedInt(reader) {
  const first = reader.u1();
  let encoded;
  let signOffset;
  if ((first & 0x80) === 0) {
    encoded = first;
    signOffset = 0x40;
  } else if ((first & 0xc0) === 0x80) {
    encoded = ((first & 0x3f) << 8) | reader.u1();
    signOffset = 0x2000;
  } else if ((first & 0xe0) === 0xc0) {
    encoded = (first & 0x1f) * 0x1000000 +
      reader.u1() * 0x10000 +
      reader.u1() * 0x100 +
      reader.u1();
    signOffset = 0x10000000;
  } else {
    throw new FormatError("Invalid compressed signed integer prefix", {
      offset: reader.absoluteOffset - 1,
      context: reader.context
    });
  }
  const value = Math.floor(encoded / 2);
  return (encoded & 1) === 0 ? value : value - signOffset;
}
