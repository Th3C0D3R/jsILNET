export function serializeStructural(assembly: any, { preserveStrongName, strongNameSignatureSize }?: {
    preserveStrongName?: boolean;
    strongNameSignatureSize?: number;
}): Uint8Array<ArrayBuffer>;
