export function validatePortablePdbAssemblyReferences(pdb: any, assemblyRowCounts: any): void;
export function updateEmbeddedPortablePdbRowCounts(pdb: any, assemblyRowCounts: any): Uint8Array<any>;
export function validatePortablePdbCodeViewIdentity(pdb: any, codeView: any, timeDateStamp: any): void;
export function decodePortablePdbCustomDebugInformation(row: any, heaps: any, documentCount?: number, methodCount?: number): {
    kind: string;
    embeddedSource: any;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    sourceLink: any;
    embeddedSource?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    defaultNamespace: string;
    embeddedSource?: undefined;
    sourceLink?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    dynamicLocalVariables: any;
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    compilationOptions: {
        name: string;
        value: string;
    }[];
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    compilationMetadataReferences: {
        fileName: string;
        aliases: string;
        flags: any;
        timeStamp: number;
        fileSize: number;
        mvid: any;
    }[];
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    typeDefinitionDocuments: any[];
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    asyncMethodSteppingInformation: {
        catchHandlerOffset: number;
        steps: {
            yieldOffset: number;
            resumeOffset: number;
            methodRid: any;
        }[];
    };
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    stateMachineHoistedLocalScopes: {
        startOffset: number;
        length: number;
    }[];
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    editAndContinueStateMachineStateMap: {
        stateNumber: number;
        syntaxOffset: any;
    }[];
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    editAndContinueLocalSlotMap: {
        syntaxOffsetBaseline: number;
        slots: {
            kind: number;
            syntaxOffset: any;
            ordinal: any;
        }[];
    };
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
} | {
    kind: string;
    editAndContinueLambdaAndClosureMap: {
        methodOrdinal: any;
        syntaxOffsetBaseline: any;
        closures: any[];
        lambdas: {
            syntaxOffset: any;
            closureOrdinal: any;
        }[];
    };
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
} | {
    kind: string;
    embeddedSource?: undefined;
    sourceLink?: undefined;
    defaultNamespace?: undefined;
    dynamicLocalVariables?: undefined;
    compilationOptions?: undefined;
    compilationMetadataReferences?: undefined;
    typeDefinitionDocuments?: undefined;
    asyncMethodSteppingInformation?: undefined;
    stateMachineHoistedLocalScopes?: undefined;
    editAndContinueStateMachineStateMap?: undefined;
    editAndContinueLocalSlotMap?: undefined;
    editAndContinueLambdaAndClosureMap?: undefined;
};
export function decodePortablePdbDocumentName(blob: any, heaps: any): string;
export function encodePortablePdbDocumentName(separator: any, partBlobIndices: any): Uint8Array<ArrayBuffer>;
export function appendPortablePdbDocumentName(blobHeap: any, name: any, separator: any): {
    heap: Uint8Array<any>;
    nameBlobIndex: any;
    nameBlob: Uint8Array<ArrayBuffer>;
};
export function decodePortablePdbSequencePoints(blob: any, { documentRid, documentCount, localSignatureCount }: {
    documentRid: any;
    documentCount: any;
    localSignatureCount: any;
}): {
    localSignatureRid: any;
    points: {
        offset: any;
        documentRid: any;
        hidden: boolean;
        startLine: number;
        startColumn: number;
        endLine: number;
        endColumn: number;
    }[];
};
export function encodePortablePdbSequencePoints(sequencePoints: any, { documentRid, documentCount, localSignatureCount }?: {}): Uint8Array<ArrayBuffer>;
export function parsePortablePdbTables(tables: any, heaps: any, typeSystemCounts: any): {
    documents: any[];
    methodDebugInformation: any;
    stateMachineMethods: any;
    customDebugInformation: any;
};
export function serializeEmbeddedPortablePdb(pdb: any): Uint8Array<any>;
export function refreshEmbeddedPortablePdbId(pdb: any): {
    bytes: Uint8Array<any>;
    id: any;
    hashes: Map<any, any>;
};
export function replaceEmbeddedPortablePdbDocumentName(pdb: any, documentRid: any, name: any, separator: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbDocumentMetadata(pdb: any, documentRid: any, options: any): Uint8Array<any>;
export function addEmbeddedPortablePdbDocument(pdb: any, name: any, options: any): Uint8Array<any>;
export function insertEmbeddedPortablePdbDocument(pdb: any, options?: {}): Uint8Array<any>;
export function addEmbeddedPortablePdbTypeDefinitionDocuments(pdb: any, typeRid: any, documentRids: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbTypeDefinitionDocuments(pdb: any, typeRid: any, documentRids: any): Uint8Array<any>;
export function removeEmbeddedPortablePdbDocument(pdb: any, documentRid: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbSequencePoints(pdb: any, methodRid: any, sequencePoints: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbMethodDocument(pdb: any, methodRid: any, documentRid: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbCustomDebugInformation(pdb: any, customDebugInformationRid: any, value: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbLocalScope(pdb: any, localScopeRid: any, options: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbLocalVariable(pdb: any, localVariableRid: any, options: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbLocalConstant(pdb: any, localConstantRid: any, options: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbImportScope(pdb: any, importScopeRid: any, options: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbMethodOffsets(pdb: any, methodRid: any, { sequencePoints, localSignatureRid, scopes, stateMachineHoistedLocalScopes, asyncMethodSteppingInformation }?: {
    sequencePoints?: any;
    localSignatureRid?: number;
    scopes?: any[];
    stateMachineHoistedLocalScopes?: any[];
    asyncMethodSteppingInformation?: any[];
}): Uint8Array<any>;
export function insertEmbeddedPortablePdbMethod(pdb: any, methodRid: any, oldCounts: any, newCounts: any): Uint8Array<any>;
export function remapEmbeddedPortablePdbLocalSignatures(pdb: any, signatureRid: any, oldCounts: any, newCounts: any, operation: any): Uint8Array<any>;
export function remapEmbeddedPortablePdbTypeDefinitions(pdb: any, typeRid: any, oldCounts: any, newCounts: any, operation: any): Uint8Array<any>;
export function removeEmbeddedPortablePdbMethod(pdb: any, methodRid: any, oldCounts: any, newCounts: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbSource(pdb: any, documentRid: any, source: any, { compress }?: {
    compress?: boolean;
}): Uint8Array<any>;
export function addEmbeddedPortablePdbSource(pdb: any, documentRid: any, source: any, { compress }?: {
    compress?: boolean;
}): Uint8Array<any>;
export function removeEmbeddedPortablePdbSource(pdb: any, documentRid: any): Uint8Array<any>;
export function removeEmbeddedPortablePdbCustomDebugInformation(pdb: any, recordRid: any): Uint8Array<any>;
export function addEmbeddedPortablePdbSourceLink(pdb: any, sourceLink: any): Uint8Array<any>;
export function replaceEmbeddedPortablePdbSourceLink(pdb: any, sourceLink: any): Uint8Array<any>;
export function removeEmbeddedPortablePdbSourceLink(pdb: any): Uint8Array<any>;
