export class FormatError extends Error {
    constructor(message: any, { offset, context }?: {});
    offset: any;
    context: any;
}
export class UnsupportedFormatError extends FormatError {
}
