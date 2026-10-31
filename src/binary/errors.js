export class FormatError extends Error {
  constructor(message, { offset, context } = {}) {
    const location = Number.isInteger(offset) ? ` at file offset 0x${offset.toString(16)}` : "";
    const scope = context ? ` (${context})` : "";
    super(`${message}${location}${scope}`);
    this.name = "FormatError";
    this.offset = offset;
    this.context = context;
  }
}

export class UnsupportedFormatError extends FormatError {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "UnsupportedFormatError";
  }
}
