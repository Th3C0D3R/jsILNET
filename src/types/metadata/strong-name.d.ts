export function getStrongNameHashName(algorithm: any): string;
export function importStrongNamePrivateKey(input: any): any;
export function encodeStrongNamePublicKey(key: any, hashAlgorithm: any): any;
export function decodeStrongNamePublicKey(bytes: any): {
    publicKey: any;
    hashAlgorithm: number;
    signatureSize: number;
};
export function assertStrongNamePEProfile(pe: any): 96 | 112;
export function signStrongNameImage(bytes: any, pe: any, cli: any, privateKey: any, hashAlgorithm: any): Uint8Array<ArrayBuffer>;
export function verifyStrongNameImage(bytes: any, pe: any, cli: any, publicKeyBytes: any, hashAlgorithm: any): any;
