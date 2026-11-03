export function getNextSectionVirtualAddress(pe: any): number;
export function appendPeSection(input: any, pe: any, cli: any, payload: any, metadataOffset: any, metadataSize: any, resourcesDirectory?: any, preserveStrongName?: boolean, debugDirectoryPayload?: any): {
    bytes: Uint8Array<ArrayBuffer>;
    virtualAddress: number;
    rawPointer: number;
    rawSize: number;
    headerExpansion: number;
    cliOffset: any;
};
