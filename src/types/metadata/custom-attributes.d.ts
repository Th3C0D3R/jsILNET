export function parseCustomAttribute(bytes: any, fixedTypes: any, resolveEnum?: () => never): {
    fixedArguments: any;
    namedArguments: {
        kind: string;
        type: any;
        name: string;
        value: any;
    }[];
};
export function parsePermissionSet(bytes: any, resolveEnum?: () => never): {
    format: string;
    xml: string;
    attributes?: undefined;
} | {
    format: string;
    attributes: {
        typeName: string;
        namedArguments: {
            kind: string;
            type: any;
            name: string;
            value: any;
        }[];
    }[];
    xml?: undefined;
};
export function encodePermissionSet(value: any): Uint8Array<ArrayBuffer>;
export function encodeCustomAttribute(value: any, fixedTypes: any): Uint8Array<ArrayBuffer>;
