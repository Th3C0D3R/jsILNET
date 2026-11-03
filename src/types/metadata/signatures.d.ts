export function parseSignature(input: any, { counts }?: {}): any;
export function parseTypeSignature(input: any, { counts }?: {}): any;
export function encodeSignature(signature: any): Uint8Array<ArrayBuffer>;
export function encodeTypeSignature(signature: any): Uint8Array<ArrayBuffer>;
export function remapTypeReferences(signature: any, remapRid: any, tableId?: number): any;
