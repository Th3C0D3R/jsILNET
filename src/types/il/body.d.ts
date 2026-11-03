export function parseMethodBody(input: any, fileOffset: any, methodRva?: any): {
    format: string;
    flags: number;
    maxStack: number;
    codeSize: number;
    localVarSigToken: number;
    headerOffset: any;
    headerSize: number;
    codeOffset: any;
    endOffset: any;
    instructions: {
        opcode: any;
        offset: number;
        size: number;
        opcodeOffset: number;
        opcodeSize: number;
        operandOffset: number;
        patchOffsets: any[];
        operand: {
            kind: string;
            targetOffset: number;
            targetOffsets?: undefined;
            value?: undefined;
        } | {
            kind: string;
            targetOffsets: number[];
            targetOffset?: undefined;
            value?: undefined;
        } | {
            kind: any;
            value: any;
            targetOffset?: undefined;
            targetOffsets?: undefined;
        };
    }[];
    sections: {
        offset: any;
        rva: any;
        size: number;
        fat: boolean;
        moreSections: boolean;
        clauses: {
            flags: number;
            tryOffset: number;
            tryLength: number;
            handlerOffset: number;
            handlerLength: number;
            classTokenOrFilterOffset: number;
        }[];
    }[];
};
