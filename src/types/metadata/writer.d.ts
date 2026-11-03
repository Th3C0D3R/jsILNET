export function serializeTablesStream(tables: any, heapStreams: any): Uint8Array<ArrayBuffer>;
export function appendCompressedUInt(value: any): Uint8Array<ArrayBuffer>;
export function appendCompressedInt(value: any): Uint8Array<ArrayBuffer>;
export function appendStringHeap(heap: any, value: any): {
    heap: Uint8Array<any>;
    index: any;
};
export function appendBlobHeap(heap: any, value: any): {
    heap: Uint8Array<any>;
    index: any;
};
export function appendUserStringHeap(heap: any, value: any): {
    heap: Uint8Array<any>;
    index: any;
};
export function tableName(id: any): string;
