export function decodeInstructions(input: any, { baseOffset, ilOffset }?: {
    baseOffset?: number;
    ilOffset?: number;
}): {
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
export function encodeOpcode(opcode: any): Uint8Array<ArrayBuffer>;
export function getInstructionSize(opcode: any, operand: any): any;
export function encodeInstruction(instruction: any): Uint8Array<any>;
export function formatInstruction(instruction: any): string;
export function encodeOperand(instruction: any, value: any): Uint8Array<any>;
