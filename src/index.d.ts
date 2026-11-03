export interface AssemblyIdentity {
  name: string;
  culture: string;
  version: [number, number, number, number] | number[];
}

export interface ModuleMetadata {
  generation: number;
  name: string;
  mvid: Uint8Array;
  assembly: AssemblyIdentity | null;
}

export interface MethodParameter {
  rid: number;
  flags: number;
  sequence: number;
  name: string;
}

export interface MethodDefinition {
  rid: number;
  rva: number;
  flags: number;
  implFlags: number;
  name: string;
  signature: Uint8Array;
  parameterRids: number[];
  parameters: MethodParameter[];
}

export interface TypeDefinition {
  rid: number;
  flags: number;
  name: string;
  namespace: string;
  extends: MetadataReference | null;
  fieldRids: number[];
  methodRids: number[];
  eventRids: number[];
  propertyRids: number[];
}

export interface MetadataReference {
  table: number;
  rid: number;
}

export interface Opcode {
  code: number;
  name: string;
  operand: string;
}

export type InstructionOperand =
  | { kind: "branch"; targetOffset: number }
  | { kind: "switch"; targetOffsets: number[] }
  | {
      kind: "u1" | "i1" | "u2" | "i4" | "i8" | "f4" | "f8" | "token";
      value: number | bigint;
    };

export interface Instruction {
  opcode: Opcode;
  offset: number;
  size: number;
  opcodeOffset: number;
  opcodeSize: number;
  operandOffset: number;
  patchOffsets: number[];
  operand: InstructionOperand | null;
}

export interface ExceptionClause {
  flags: number;
  tryOffset: number;
  tryLength: number;
  handlerOffset: number;
  handlerLength: number;
  classTokenOrFilterOffset: number;
}

export interface MethodDataSection {
  offset: number;
  rva: number;
  size: number;
  fat: boolean;
  moreSections: boolean;
  clauses: ExceptionClause[];
}

export interface MethodBody {
  format: "tiny" | "fat";
  headerOffset: number;
  headerSize: number;
  codeOffset: number;
  codeSize: number;
  maxStack: number;
  localVarSigToken: number;
  flags: number;
  instructions: Instruction[];
  sections: MethodDataSection[];
  endOffset: number;
}

export interface ParseErrorOptions {
  offset?: number;
  context?: string;
}

export class FormatError extends Error {
  offset?: number;
  context?: string;
  constructor(message: string, options?: ParseErrorOptions);
}

export class UnsupportedFormatError extends FormatError {
  constructor(message: string, options?: ParseErrorOptions);
}

export class Assembly {
  constructor(input: Uint8Array | ArrayBuffer);
  static from(input: Uint8Array | ArrayBuffer): Assembly;
  readonly bytes: Uint8Array;
  readonly modified: boolean;
  readonly module: ModuleMetadata | null;
  readonly types: TypeDefinition[];
  readonly methods: MethodDefinition[];

  getMethodBody(methodRid: number): MethodBody | null;
  getInstructions(methodRid: number): Instruction[];
  setInstructionOperand(
    methodRid: number,
    instructionOffset: number,
    value: number | bigint | number[]
  ): this;
  setInstructionOpcode(
    methodRid: number,
    instructionOffset: number,
    opcodeNameOrCode: string | number
  ): this;
  insertInstruction(
    methodRid: number,
    beforeOffset: number,
    opcodeNameOrCode: string | number,
    operand?: number | bigint | number[]
  ): Instruction;
  removeInstruction(methodRid: number, instructionOffset: number): Instruction;
  setMethodMaxStack(methodRid: number, maxStack: number): this;
  serialize(): Uint8Array;
  toBuffer(): Uint8Array;
}

export function parseAssembly(input: Uint8Array | ArrayBuffer): Assembly;
export function decodeInstructions(
  input: Uint8Array | ArrayBuffer,
  options?: { baseOffset?: number; ilOffset?: number }
): Instruction[];
export function encodeInstruction(instruction: Instruction): Uint8Array;
export function encodeOpcode(opcode: Opcode): Uint8Array;
export function formatInstruction(instruction: Instruction): string;
export function encodeOperand(
  instruction: Instruction,
  value: number | bigint | number[]
): Uint8Array;
export function getInstructionSize(
  opcode: Opcode,
  operand?: { targetOffsets?: number[] } | null
): number;

import type { Assembly as InferredAssembly } from "./types/index.js";

type PublicAssemblySurface = {
  [K in keyof InferredAssembly as K extends `_${string}` ? never : K]:
    InferredAssembly[K];
};

export interface Assembly extends Omit<
  PublicAssemblySurface,
  | "bytes"
  | "modified"
  | "module"
  | "types"
  | "methods"
  | "getMethodBody"
  | "getInstructions"
  | "setInstructionOperand"
  | "setInstructionOpcode"
  | "insertInstruction"
  | "removeInstruction"
  | "setMethodMaxStack"
  | "serialize"
  | "toBuffer"
> {}

export {
  BinaryReader,
  readCompressedInt,
  readCompressedUInt,
  parseMethodBody,
  codedIndexWidth,
  decodeCodedIndex,
  encodeCodedIndex,
  metadataTableNames,
  parseTablesStream,
  tableIndexWidth,
  MetadataHeaps,
  parseMetadataRoot,
  parseClassicPdb,
  insertClassicPdbFileChecksum,
  insertClassicPdbConstantSymbol,
  insertClassicPdbDataSymbol,
  insertClassicPdbLineBlock,
  insertClassicPdbPublicSymbol,
  insertClassicPdbThreadDataSymbol,
  removeClassicPdbFileChecksum,
  removeClassicPdbLineBlock,
  removeClassicPdbSymbol,
  replaceClassicPdbFileChecksum,
  replaceClassicPdbConstantSymbol,
  replaceClassicPdbDataSymbol,
  replaceClassicPdbLineBlock,
  replaceClassicPdbLineInfo,
  replaceClassicPdbModuleNames,
  replaceClassicPdbPublicSymbol,
  replaceClassicPdbStringTableName,
  replaceClassicPdbThreadDataSymbol,
  replaceClassicPdbSymbolName,
  encodeCustomAttribute,
  encodePermissionSet,
  parseCustomAttribute,
  parsePermissionSet,
  appendPortablePdbDocumentName,
  decodePortablePdbDocumentName,
  decodePortablePdbSequencePoints,
  encodePortablePdbDocumentName,
  encodePortablePdbSequencePoints,
  addEmbeddedPortablePdbDocument,
  insertEmbeddedPortablePdbDocument,
  addEmbeddedPortablePdbTypeDefinitionDocuments,
  removeEmbeddedPortablePdbDocument,
  replaceEmbeddedPortablePdbDocumentMetadata,
  replaceEmbeddedPortablePdbTypeDefinitionDocuments,
  replaceEmbeddedPortablePdbDocumentName,
  replaceEmbeddedPortablePdbLocalScope,
  replaceEmbeddedPortablePdbLocalVariable,
  replaceEmbeddedPortablePdbLocalConstant,
  replaceEmbeddedPortablePdbCustomDebugInformation,
  replaceEmbeddedPortablePdbMethodDocument,
  replaceEmbeddedPortablePdbImportScope,
  replaceEmbeddedPortablePdbSequencePoints,
  addEmbeddedPortablePdbSource,
  removeEmbeddedPortablePdbSource,
  removeEmbeddedPortablePdbSourceLink,
  removeEmbeddedPortablePdbCustomDebugInformation,
  replaceEmbeddedPortablePdbSource,
  addEmbeddedPortablePdbSourceLink,
  replaceEmbeddedPortablePdbSourceLink,
  serializeEmbeddedPortablePdb,
  encodeSignature,
  encodeTypeSignature,
  parseSignature,
  parseTypeSignature,
  remapTypeReferences,
  parseCliHeader,
  parsePE
} from "./types/index.js";
