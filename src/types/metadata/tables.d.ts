export function decodeCodedIndex(value: any, kind: any): {
    table: any;
    tableName: string;
    rid: number;
};
export function encodeCodedIndex(table: any, rid: any, kind: any): any;
export function codedIndexWidth(kind: any, counts: any): 2 | 4;
export function tableIndexWidth(rowCount: any): 2 | 4;
export function parseTablesStream(stream: any, externalCounts?: any): {
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
export function metadataTableId(nameOrId: any): any;
export const metadataTableNames: string[];
export const metadataTableSchemas: (string | number)[][][];
