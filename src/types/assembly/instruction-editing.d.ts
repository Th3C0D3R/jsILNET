export function createInstructionEditor(assembly: any, hooks: any): {
    setInstructionOperand(methodRid: any, instructionOffset: any, value: any): any;
    setInstructionOpcode(methodRid: any, instructionOffset: any, opcodeNameOrCode: any): any;
    insertInstruction(methodRid: any, beforeOffset: any, opcodeNameOrCode: any, operand: any): {
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
    removeInstruction(methodRid: any, instructionOffset: any): any;
    setMethodMaxStack(methodRid: any, maxStack: any): any;
};
