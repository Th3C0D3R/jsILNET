export function parseEmbeddedPortablePdbData(bytes: any, offset: any, size: any): {
    id: Uint8Array<ArrayBuffer>;
    entryPointToken: number;
    referencedTypeSystemTables: bigint;
    rowCounts: Map<any, any>;
    documents: any[];
    methodDebugInformation: any;
    stateMachineMethods: any;
    customDebugInformation: any;
    uncompressedSize: number;
    bytes: Uint8Array<ArrayBuffer>;
    metadataRoot: {
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
    tables: {
        majorVersion: number;
        minorVersion: number;
        reserved: number;
        reservedByte: number;
        heapSizes: number;
        valid: bigint;
        sorted: bigint;
        counts: any[];
        rows: Map<any, any>;
        tableDataOffset: number;
        row(idOrName: any, rid: any): any;
        get(idOrName: any): any;
    };
    heaps: MetadataHeaps;
};
export function parsePE(input: any): {
    bytes: Uint8Array<any>;
    peOffset: number;
    machine: number;
    sectionCount: number;
    symbolTablePointer: number;
    symbolCount: number;
    characteristics: number;
    optionalHeaderOffset: number;
    optionalHeaderSize: number;
    optionalHeaderMagic: number;
    sectionOffset: number;
    sizeOfCode: number;
    sizeOfInitializedData: number;
    sectionAlignment: number;
    fileAlignment: number;
    sizeOfImage: number;
    sizeOfHeaders: number;
    checksumOffset: number;
    directories: {
        rva: number;
        size: number;
    }[];
    debugDirectoryEntries: {
        characteristics: number;
        timeDateStamp: number;
        majorVersion: number;
        minorVersion: number;
        type: number;
        sizeOfData: number;
        addressOfRawData: number;
        pointerToRawData: number;
        codeView: {
            format: string;
            signature: string;
        } | {
            path: string;
            pathOffset: number;
            pathByteLength: any;
            guid: string;
            age: number;
            format: string;
            signature?: undefined;
        } | {
            path: string;
            pathOffset: number;
            pathByteLength: any;
            offset: number;
            timeDateStamp: number;
            age: number;
            format: string;
            signature?: undefined;
        };
        embeddedPortablePdb: {
            id: Uint8Array<ArrayBuffer>;
            entryPointToken: number;
            referencedTypeSystemTables: bigint;
            rowCounts: Map<any, any>;
            documents: any[];
            methodDebugInformation: any;
            stateMachineMethods: any;
            customDebugInformation: any;
            uncompressedSize: number;
            bytes: Uint8Array<ArrayBuffer>;
            metadataRoot: {
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
            tables: {
                majorVersion: number;
                minorVersion: number;
                reserved: number;
                reservedByte: number;
                heapSizes: number;
                valid: bigint;
                sorted: bigint;
                counts: any[];
                rows: Map<any, any>;
                tableDataOffset: number;
                row(idOrName: any, rid: any): any;
                get(idOrName: any): any;
            };
            heaps: MetadataHeaps;
        };
    }[];
    sections: {
        name: string;
        virtualSize: number;
        virtualAddress: number;
        rawSize: number;
        rawPointer: number;
    }[];
    rvaToOffset: (rva: any, size?: number) => any;
};
export function parseCliHeader(pe: any): {
    offset: any;
    headerSize: number;
    majorRuntimeVersion: number;
    minorRuntimeVersion: number;
    metadataRva: number;
    metadataSize: number;
    flags: number;
    entryPointToken: number;
    resources: {
        rva: number;
        size: number;
    };
    strongNameSignature: {
        rva: number;
        size: number;
    };
    strongNameFlagOffset: any;
    strongNameDirectoryOffset: any;
};
import { MetadataHeaps } from "../metadata/streams.js";
