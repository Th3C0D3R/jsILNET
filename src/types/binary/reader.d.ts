export function readCompressedUInt(reader: any): any;
export function readCompressedInt(reader: any): number;
export class BinaryReader {
    constructor(input: any, { start, length, baseOffset, context }?: {
        start?: number;
        baseOffset?: number;
    });
    bytes: Uint8Array<any>;
    view: DataView<any>;
    baseOffset: number;
    context: any;
    position: number;
    get remaining(): number;
    get absoluteOffset(): number;
    ensure(size: any): void;
    seek(position: any): void;
    skip(size: any): void;
    align(alignment: any): void;
    u1(): number;
    i1(): number;
    u2(): number;
    i2(): number;
    u4(): number;
    i4(): number;
    u8(): bigint;
    f4(): number;
    f8(): number;
    take(size: any): Uint8Array<any>;
    slice(size: any, context?: any): BinaryReader;
}
