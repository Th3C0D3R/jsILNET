export function parseMetadataRoot(input: any, offset: any, size: any): {
    offset: any;
    size: any;
    majorVersion: number;
    minorVersion: number;
    version: string;
    versionLength: number;
    versionBytes: Uint8Array<any>;
    flags: number;
    streams: Map<any, any>;
};
export class MetadataHeaps {
    constructor(streams: any);
    strings: any;
    userStrings: any;
    guids: any;
    blobs: any;
    userStringDataEnd: any;
    blobEntryOffsets: Set<number>;
    userStringEntryOffsets: Set<number>;
    getString(index: any): string;
    getBlob(index: any): Uint8Array<ArrayBuffer>;
    getGuid(index: any): any;
    getUserString(tokenOrOffset: any): string;
    #private;
}
