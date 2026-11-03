export function createStructuralState(body: any): {
    body: any;
    instructions: any;
    branchTargets: Map<any, any>;
    clauses: any[];
    maxStack: any;
};
export function layoutStructuralState(state: any): any;
export function insertInstruction(state: any, beforeOffset: any, opcode: any, value: any): {
    opcode: any;
    operand: {
        kind: string;
        targetOffset: any;
        targetOffsets?: undefined;
        value?: undefined;
    } | {
        kind: string;
        targetOffsets: any[];
        targetOffset?: undefined;
        value?: undefined;
    } | {
        kind: any;
        value: any;
        targetOffset?: undefined;
        targetOffsets?: undefined;
    };
    offset: number;
    size: any;
    opcodeSize: number;
    opcodeOffset: any;
    operandOffset: any;
    patchOffsets: any[];
    originalOffset: any;
    isNew: boolean;
};
export function removeInstruction(state: any, offset: any): any;
export function updateStructuralOperand(state: any, instruction: any, value: any): void;
export function encodeMethodBody(state: any, methodRva: any): Uint8Array<ArrayBuffer>;
