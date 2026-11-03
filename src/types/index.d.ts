export function parseAssembly(input: any): Assembly;
export { parseMethodBody } from "./il/body.js";
export class Assembly {
    static from(input: any): Assembly;
    constructor(input: any);
    pe: Readonly<{
        bytes: Uint8Array<any>;
        peOffset: number;
        machine: number;
        sectionCount: number;
        symbolTablePointer: number;
        symbolCount: number;
        characteristics: number;
        optionalHeaderOffset: number;
        optionalHeaderSize: number;
        optionalHeaderMagic: number;
        sectionOffset: number;
        sizeOfCode: number;
        sizeOfInitializedData: number;
        sectionAlignment: number;
        fileAlignment: number;
        sizeOfImage: number;
        sizeOfHeaders: number;
        checksumOffset: number;
        directories: {
            rva: number;
            size: number;
        }[];
        debugDirectoryEntries: {
            characteristics: number;
            timeDateStamp: number;
            majorVersion: number;
            minorVersion: number;
            type: number;
            sizeOfData: number;
            addressOfRawData: number;
            pointerToRawData: number;
            codeView: {
                format: string;
                signature: string;
            } | {
                path: string;
                pathOffset: number;
                pathByteLength: any;
                guid: string;
                age: number;
                format: string;
                signature?: undefined;
            } | {
                path: string;
                pathOffset: number;
                pathByteLength: any;
                offset: number;
                timeDateStamp: number;
                age: number;
                format: string;
                signature?: undefined;
            };
            embeddedPortablePdb: {
                id: Uint8Array<ArrayBuffer>;
                entryPointToken: number;
                referencedTypeSystemTables: bigint;
                rowCounts: Map<any, any>;
                documents: any[];
                methodDebugInformation: any;
                stateMachineMethods: any;
                customDebugInformation: any;
                uncompressedSize: number;
                bytes: Uint8Array<ArrayBuffer>;
                metadataRoot: {
                    offset: any;
                    size: any;
                    majorVersion: number;
                    minorVersion: number;
                    version: string;
                    versionLength: number;
                    versionBytes: Uint8Array<any>;
                    flags: number;
                    streams: Map<any, any>;
                };
                tables: {
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
                heaps: MetadataHeaps;
            };
        }[];
        sections: {
            name: string;
            virtualSize: number;
            virtualAddress: number;
            rawSize: number;
            rawPointer: number;
        }[];
        rvaToOffset: (rva: any, size?: number) => any;
    }>;
    cli: Readonly<{
        strongNameSignature: Readonly<{
            rva: number;
            size: number;
        }>;
        offset: any;
        headerSize: number;
        majorRuntimeVersion: number;
        minorRuntimeVersion: number;
        metadataRva: number;
        metadataSize: number;
        flags: number;
        entryPointToken: number;
        resources: {
            rva: number;
            size: number;
        };
        strongNameFlagOffset: any;
        strongNameDirectoryOffset: any;
    }>;
    metadataRoot: {
        offset: any;
        size: any;
        majorVersion: number;
        minorVersion: number;
        version: string;
        versionLength: number;
        versionBytes: Uint8Array<any>;
        flags: number;
        streams: Map<any, any>;
    };
    tables: {
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
    heaps: MetadataHeaps;
    methods: any;
    typeRefs: any;
    typeSpecs: any;
    standAloneSigs: any;
    methodSpecs: any;
    genericParams: any;
    genericParamConstraints: any;
    memberRefs: any;
    assemblyRefs: any;
    moduleRefs: any;
    files: any;
    exportedTypes: any;
    resources: any;
    types: {
        rid: any;
        flags: any;
        name: any;
        namespace: any;
        extends: any;
        fieldRids: any;
        methodRids: any;
        eventRids: any[];
        propertyRids: any[];
    }[];
    module: {
        generation: any;
        name: string;
        mvid: any;
        assembly: {
            name: string;
            culture: string;
            version: any[];
        };
    };
    customAttributes: any;
    _bodyCache: Map<any, any>;
    _patches: any[];
    _structuralBodies: Map<any, any>;
    _addedMethodBodies: Map<any, any>;
    _metadataDirty: boolean;
    _heapStreams: any;
    _resourceEdits: Map<any, any>;
    _embeddedPortablePdbEdits: Map<any, any>;
    _debugRecordEdits: Map<any, any>;
    _portablePdbOffsetBaselines: Map<any, any>;
    _clearResourcesDirectory: boolean;
    get modified(): boolean;
    get bytes(): Uint8Array<ArrayBuffer>;
    getMethodBody(methodRid: any): any;
    getInstructions(methodRid: any): any;
    parseCustomAttribute(rid: any, { resolveEnum, resolveType }?: {}): {
        fixedArguments: any;
        namedArguments: {
            kind: string;
            type: any;
            name: string;
            value: any;
        }[];
    };
    parseDeclSecurity(rid: any, { resolveEnum, resolveType }?: {}): {
        rid: any;
        action: any;
        parent: any;
        permissionSet: {
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
    };
    replaceCustomAttribute(rid: any, value: any, { resolveEnum, resolveType }?: {}): this;
    addCustomAttribute({ parent, constructor, value, resolveEnum, resolveType }: {
        parent: any;
        constructor: any;
        value: any;
        resolveEnum: any;
        resolveType: any;
    }): any;
    insertCustomAttribute({ parent, constructor, value, resolveEnum, resolveType }: {
        parent: any;
        constructor: any;
        value: any;
        resolveEnum: any;
        resolveType: any;
    }): {
        token: any;
        rid: any;
        tokenMap: Map<any, any>;
    };
    removeCustomAttribute(rid: any): Map<any, any>;
    replaceMethodSignature(rid: any, signature: any): this;
    replaceMethod(rid: any, { name, flags, implFlags }?: {}): this;
    addTypeDef({ name, namespace, flags, extends: baseType }: {
        name: any;
        namespace?: string;
        flags?: number;
        extends?: any;
    }): any;
    insertTypeDef({ beforeRid, name, namespace, flags, extends: baseType }: {
        beforeRid: any;
        name: any;
        namespace?: string;
        flags?: number;
        extends?: any;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    replaceTypeDef(rid: any, { name, namespace, flags, extends: baseType }?: {}): this;
    removeTypeDef(rid: any): Map<any, any> | this;
    replaceCodeViewPath(debugEntryIndex: any, path: any): this;
    replaceEmbeddedPortablePdb(debugEntryIndex: any, data: any): this;
    addEmbeddedPortablePdbDocument(debugEntryIndex: any, name: any, options: any): any;
    insertEmbeddedPortablePdbDocument(debugEntryIndex: any, options: any): any;
    addEmbeddedPortablePdbTypeDefinitionDocuments(debugEntryIndex: any, typeRid: any, documentRids: any): any;
    removeEmbeddedPortablePdbDocument(debugEntryIndex: any, documentRid: any): any;
    replaceEmbeddedPortablePdbTypeDefinitionDocuments(debugEntryIndex: any, typeRid: any, documentRids: any): any;
    replaceEmbeddedPortablePdbDocumentMetadata(debugEntryIndex: any, documentRid: any, options: any): any;
    replaceEmbeddedPortablePdbDocumentName(debugEntryIndex: any, documentRid: any, name: any, separator: any): any;
    replaceEmbeddedPortablePdbSequencePoints(debugEntryIndex: any, methodRid: any, sequencePoints: any): any;
    replaceEmbeddedPortablePdbMethodDocument(debugEntryIndex: any, methodRid: any, documentRid: any): any;
    replaceEmbeddedPortablePdbImportScope(debugEntryIndex: any, importScopeRid: any, options: any): any;
    replaceEmbeddedPortablePdbLocalScope(debugEntryIndex: any, localScopeRid: any, options: any): any;
    replaceEmbeddedPortablePdbLocalVariable(debugEntryIndex: any, localVariableRid: any, options: any): any;
    replaceEmbeddedPortablePdbLocalConstant(debugEntryIndex: any, localConstantRid: any, options: any): any;
    replaceEmbeddedPortablePdbCustomDebugInformation(debugEntryIndex: any, customDebugInformationRid: any, value: any): any;
    replaceEmbeddedPortablePdbSource(debugEntryIndex: any, documentRid: any, source: any, options: any): any;
    addEmbeddedPortablePdbSource(debugEntryIndex: any, documentRid: any, source: any, options: any): any;
    removeEmbeddedPortablePdbSource(debugEntryIndex: any, documentRid: any): any;
    removeEmbeddedPortablePdbCustomDebugInformation(debugEntryIndex: any, recordRid: any): any;
    replaceEmbeddedPortablePdbSourceLink(debugEntryIndex: any, sourceLink: any): any;
    removeEmbeddedPortablePdbSourceLink(debugEntryIndex: any): any;
    addEmbeddedPortablePdbSourceLink(debugEntryIndex: any, sourceLink: any): any;
    replaceFieldSignature(rid: any, signature: any): this;
    replaceField(rid: any, { name, flags }?: {}): this;
    addFieldRva(fieldRid: any, rva: any): any;
    insertFieldRva(fieldRid: any, rva: any): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceFieldRva(rid: any, rva: any): this;
    removeFieldRva(rid: any): Map<any, any>;
    removeField(rid: any): Map<any, any>;
    addConstant({ parent, type, value }: {
        parent: any;
        type: any;
        value: any;
    }): any;
    insertConstant({ parent, type, value }: {
        parent: any;
        type: any;
        value: any;
    }): {
        token: any;
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceConstant(rid: any, { type, value }?: {}): this;
    removeConstant(rid: any): Map<any, any>;
    addFieldMarshal({ parent, nativeType }: {
        parent: any;
        nativeType: any;
    }): this;
    insertFieldMarshal({ parent, nativeType }: {
        parent: any;
        nativeType: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceFieldMarshal(rid: any, nativeType: any): this;
    removeFieldMarshal(rid: any): Map<any, any>;
    addClassLayout({ owner, packingSize, classSize }: {
        owner: any;
        packingSize?: number;
        classSize?: number;
    }): any;
    insertClassLayout({ owner, packingSize, classSize }: {
        owner: any;
        packingSize?: number;
        classSize?: number;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceClassLayout(rid: any, { packingSize, classSize }?: {}): this;
    removeClassLayout(rid: any): Map<any, any>;
    addFieldLayout({ fieldRid, offset }: {
        fieldRid: any;
        offset: any;
    }): any;
    insertFieldLayout({ fieldRid, offset }: {
        fieldRid: any;
        offset: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceFieldLayout(rid: any, offset: any): this;
    removeFieldLayout(rid: any): Map<any, any>;
    addNestedClass({ nestedType, enclosingType }: {
        nestedType: any;
        enclosingType: any;
    }): any;
    insertNestedClass({ nestedType, enclosingType }: {
        nestedType: any;
        enclosingType: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceNestedClass(rid: any, { enclosingType }?: {}): this;
    removeNestedClass(rid: any): Map<any, any>;
    addImplMap({ member, moduleRefRid, importName, mappingFlags }: {
        member: any;
        moduleRefRid: any;
        importName: any;
        mappingFlags?: number;
    }): any;
    insertImplMap({ member, moduleRefRid, importName, mappingFlags }: {
        member: any;
        moduleRefRid: any;
        importName: any;
        mappingFlags?: number;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceImplMap(rid: any, { moduleRefRid, importName, mappingFlags }?: {}): this;
    removeImplMap(rid: any): Map<any, any>;
    addMethodImpl({ owner, body, declaration }: {
        owner: any;
        body: any;
        declaration: any;
    }): any;
    insertMethodImpl({ owner, body, declaration }: {
        owner: any;
        body: any;
        declaration: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceMethodImpl(rid: any, { body, declaration }?: {}): this;
    removeMethodImpl(rid: any): Map<any, any>;
    addDeclSecurity({ parent, action, permissionSet, resolveEnum, resolveType }: {
        parent: any;
        action: any;
        permissionSet: any;
        resolveEnum: any;
        resolveType: any;
    }): any;
    insertDeclSecurity({ parent, action, permissionSet, resolveEnum, resolveType }: {
        parent: any;
        action: any;
        permissionSet: any;
        resolveEnum: any;
        resolveType: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceDeclSecurity(rid: any, { action, permissionSet, resolveEnum, resolveType }?: {}): this;
    removeDeclSecurity(rid: any): Map<any, any>;
    addMethod({ owner, name, flags, implFlags, signature, body: bodyBytes }: {
        owner: any;
        name: any;
        flags: any;
        implFlags?: number;
        signature: any;
        body: any;
    }): any;
    insertMethod({ owner, name, flags, implFlags, signature, body: bodyBytes }: {
        owner: any;
        name: any;
        flags: any;
        implFlags?: number;
        signature: any;
        body: any;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    _cliEntryPointToken: any;
    removeMethod(rid: any): any;
    addParam({ owner, name, sequence, flags }: {
        owner: any;
        name?: string;
        sequence: any;
        flags?: number;
    }): any;
    insertParam({ owner, name, sequence, flags }: {
        owner: any;
        name?: string;
        sequence: any;
        flags?: number;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceParam(rid: any, { name, flags }?: {}): this;
    removeParam(rid: any): Map<any, any>;
    reorderPointerTable(pointerTable: any, targetRids: any): any;
    addField({ owner, name, flags, signature }: {
        owner: any;
        name: any;
        flags?: number;
        signature: any;
    }): any;
    insertField({ owner, name, flags, signature }: {
        owner: any;
        name: any;
        flags?: number;
        signature: any;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    addMethodSemantics({ methodRid, association, semantics }: {
        methodRid: any;
        association: any;
        semantics: any;
    }): any;
    insertMethodSemantics({ methodRid, association, semantics }: {
        methodRid: any;
        association: any;
        semantics: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceMethodSemantics(rid: any, { methodRid, association, semantics }?: {}): this;
    removeMethodSemantics(rid: any): Map<any, any>;
    replacePropertySignature(rid: any, signature: any): this;
    replaceProperty(rid: any, { name, flags }?: {}): this;
    removeProperty(rid: any): Map<any, any>;
    addProperty({ owner, name, flags, signature }: {
        owner: any;
        name: any;
        flags?: number;
        signature: any;
    }): any;
    insertProperty({ owner, name, flags, signature }: {
        owner: any;
        name: any;
        flags?: number;
        signature: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    addEvent({ owner, name, flags, eventType }: {
        owner: any;
        name: any;
        flags?: number;
        eventType: any;
    }): any;
    insertEvent({ owner, name, flags, eventType }: {
        owner: any;
        name: any;
        flags?: number;
        eventType: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    removeEvent(rid: any): Map<any, any>;
    replaceEvent(rid: any, { name, flags, eventType }?: {}): this;
    addInterfaceImplementation({ owner, interfaceType }: {
        owner: any;
        interfaceType: any;
    }): any;
    insertInterfaceImplementation({ owner, interfaceType }: {
        owner: any;
        interfaceType: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceInterfaceImplementation(rid: any, { interfaceType }?: {}): this;
    removeInterfaceImplementation(rid: any): Map<any, any>;
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
    addMemberRef({ parent, name, signature }: {
        parent: any;
        name: any;
        signature: any;
    }): any;
    replaceMemberRef(rid: any, { parent, name, signature }?: {}): this;
    removeMemberRef(rid: any): Map<any, any>;
    insertMemberRefSorted({ parent, name, signature }: {
        parent: any;
        name: any;
        signature: any;
    }): {
        token: number;
        tokenMap: Map<any, number>;
    };
    addModuleRef({ name }: {
        name: any;
    }): any;
    insertModuleRef({ beforeRid, name }: {
        beforeRid: any;
        name: any;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    replaceModuleRef(rid: any, name: any): this;
    removeModuleRef(rid: any): Map<any, any>;
    addTypeRef({ scope, name, namespace }: {
        scope?: any;
        name: any;
        namespace?: string;
    }): any;
    insertTypeRefSorted({ scope, name, namespace }: {
        scope?: any;
        name: any;
        namespace?: string;
    }): {
        token: number;
        tokenMap: Map<any, number>;
    };
    replaceTypeRef(rid: any, { scope, name, namespace }?: {}): this;
    removeTypeRef(rid: any): Map<any, any>;
    addAssemblyRef({ name, culture, version, flags, publicKeyOrToken, hashValue }: {
        name: any;
        culture?: string;
        version?: number[];
        flags?: number;
        publicKeyOrToken?: Uint8Array<ArrayBuffer>;
        hashValue?: Uint8Array<ArrayBuffer>;
    }): any;
    insertAssemblyRef({ beforeRid, name, culture, version, flags, publicKeyOrToken, hashValue }: {
        beforeRid: any;
        name: any;
        culture?: string;
        version?: number[];
        flags?: number;
        publicKeyOrToken?: Uint8Array<ArrayBuffer>;
        hashValue?: Uint8Array<ArrayBuffer>;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    addAssemblyProcessor({ processor }: {
        processor: any;
    }): any;
    insertAssemblyProcessor({ beforeRid, processor }: {
        beforeRid: any;
        processor: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceAssemblyProcessor(rid: any, { processor }?: {}): this;
    removeAssemblyProcessor(rid: any): Map<any, any>;
    addAssemblyOS({ platformId, majorVersion, minorVersion }: {
        platformId: any;
        majorVersion: any;
        minorVersion: any;
    }): any;
    insertAssemblyOS({ beforeRid, platformId, majorVersion, minorVersion }: {
        beforeRid: any;
        platformId: any;
        majorVersion: any;
        minorVersion: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceAssemblyOS(rid: any, { platformId, majorVersion, minorVersion }?: {}): this;
    removeAssemblyOS(rid: any): Map<any, any>;
    addAssemblyRefProcessor({ processor, assemblyRefRid }: {
        processor: any;
        assemblyRefRid: any;
    }): any;
    insertAssemblyRefProcessor({ beforeRid, processor, assemblyRefRid }: {
        beforeRid: any;
        processor: any;
        assemblyRefRid: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceAssemblyRefProcessor(rid: any, { processor, assemblyRefRid }?: {}): this;
    removeAssemblyRefProcessor(rid: any): Map<any, any>;
    addAssemblyRefOS({ platformId, majorVersion, minorVersion, assemblyRefRid }: {
        platformId: any;
        majorVersion: any;
        minorVersion: any;
        assemblyRefRid: any;
    }): any;
    insertAssemblyRefOS({ beforeRid, platformId, majorVersion, minorVersion, assemblyRefRid }: {
        beforeRid: any;
        platformId: any;
        majorVersion: any;
        minorVersion: any;
        assemblyRefRid: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceAssemblyRefOS(rid: any, { platformId, majorVersion, minorVersion, assemblyRefRid }?: {}): this;
    removeAssemblyRefOS(rid: any): Map<any, any>;
    replaceAssemblyRef(rid: any, { name, culture, version, flags, publicKeyOrToken, hashValue }?: {}): this;
    removeAssemblyRef(rid: any): Map<any, any>;
    addTypeSpec({ signature }: {
        signature: any;
    }): any;
    insertTypeSpec({ beforeRid, signature }: {
        beforeRid: any;
        signature: any;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    replaceTypeSpecSignature(rid: any, signature: any): this;
    removeTypeSpec(rid: any): Map<any, any>;
    addMethodSpec({ method, instantiation }: {
        method: any;
        instantiation: any;
    }): any;
    replaceMethodSpecInstantiation(rid: any, instantiation: any): this;
    addStandAloneSig({ signature }: {
        signature: any;
    }): any;
    insertStandAloneSig({ beforeRid, signature }: {
        beforeRid: any;
        signature: any;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    replaceStandAloneSig(rid: any, { signature }?: {}): this;
    removeStandAloneSig(rid: any): Map<any, any>;
    insertMethodSpecSorted({ method, instantiation }: {
        method: any;
        instantiation: any;
    }): {
        token: number;
        tokenMap: Map<any, number>;
    };
    removeMethodSpec(rid: any): Map<any, any>;
    addGenericParamConstraint({ ownerRid, constraint }: {
        ownerRid: any;
        constraint: any;
    }): any;
    insertGenericParamConstraint({ ownerRid, constraint }: {
        ownerRid: any;
        constraint: any;
    }): {
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceGenericParamConstraint(rid: any, { constraint }?: {}): this;
    removeGenericParamConstraint(rid: any): Map<any, any>;
    addGenericParam({ owner, name, number, flags }: {
        owner: any;
        name: any;
        number: any;
        flags?: number;
    }): any;
    insertGenericParam({ owner, name, number, flags }: {
        owner: any;
        name: any;
        number: any;
        flags?: number;
    }): {
        token: any;
        rid: any;
        tokenMap: Map<any, any>;
    };
    replaceGenericParam(rid: any, { name, flags }?: {}): this;
    removeGenericParam(rid: any): Map<any, any>;
    addFile({ name, flags, hashValue }: {
        name: any;
        flags?: number;
        hashValue?: Uint8Array<ArrayBuffer>;
    }): any;
    insertFile({ beforeRid, name, flags, hashValue }: {
        beforeRid: any;
        name: any;
        flags?: number;
        hashValue?: Uint8Array<ArrayBuffer>;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    addExportedType({ name, namespace, flags, typeDefId, implementation }: {
        name: any;
        namespace?: string;
        flags?: number;
        typeDefId?: number;
        implementation: any;
    }): any;
    insertExportedType({ beforeRid, name, namespace, flags, typeDefId, implementation }: {
        beforeRid: any;
        name: any;
        namespace?: string;
        flags?: number;
        typeDefId?: number;
        implementation: any;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    replaceExportedType(rid: any, { name, namespace, flags, typeDefId, implementation }?: {}): this;
    removeExportedType(rid: any): Map<any, any> | this;
    replaceFile(rid: any, { name, flags, hashValue }?: {}): this;
    removeFile(rid: any): Map<any, any>;
    addUserString(value: any): any;
    addManifestResource({ name, flags, implementation, data }: {
        name: any;
        flags?: number;
        implementation?: any;
        data?: any;
    }): any;
    insertManifestResource({ beforeRid, name, flags, implementation, data }: {
        beforeRid: any;
        name: any;
        flags?: number;
        implementation?: any;
        data?: any;
    }): {
        token: any;
        tokenMap: Map<any, any>;
    };
    replaceManifestResource(rid: any, data: any): this;
    replaceLinkedResource(rid: any, data: any): this;
    replaceManifestResourceMetadata(rid: any, { name, flags, implementation }?: {}): this;
    removeManifestResource(rid: any): Map<any, any>;
    formatInstruction(instruction: any): string;
    replaceModule({ name, generation }?: {}): this;
    replaceAssemblyIdentity({ name, culture, version }?: {}): this;
    replaceStrongNamePublicKey(privateKeyInput: any, { hashAlgorithm }?: {}): this;
    signStrongName(privateKeyInput: any): this;
    verifyStrongNameSignature(): any;
    serialize(): Uint8Array<ArrayBuffer>;
    toBuffer(): any;
    #private;
}
import { parseClassicPdb as parseClassicPdbFile } from "./metadata/classic-pdb.js";
import { insertClassicPdbFileChecksum as insertClassicPdbFileChecksumFile } from "./metadata/classic-pdb.js";
import { insertClassicPdbConstantSymbol as insertClassicPdbConstantSymbolFile } from "./metadata/classic-pdb.js";
import { insertClassicPdbDataSymbol as insertClassicPdbDataSymbolFile } from "./metadata/classic-pdb.js";
import { insertClassicPdbLineBlock as insertClassicPdbLineBlockFile } from "./metadata/classic-pdb.js";
import { insertClassicPdbPublicSymbol as insertClassicPdbPublicSymbolFile } from "./metadata/classic-pdb.js";
import { insertClassicPdbThreadDataSymbol as insertClassicPdbThreadDataSymbolFile } from "./metadata/classic-pdb.js";
import { removeClassicPdbFileChecksum as removeClassicPdbFileChecksumFile } from "./metadata/classic-pdb.js";
import { removeClassicPdbLineBlock as removeClassicPdbLineBlockFile } from "./metadata/classic-pdb.js";
import { removeClassicPdbSymbol as removeClassicPdbSymbolFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbFileChecksum as replaceClassicPdbFileChecksumFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbConstantSymbol as replaceClassicPdbConstantSymbolFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbDataSymbol as replaceClassicPdbDataSymbolFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbLineBlock as replaceClassicPdbLineBlockFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbLineInfo as replaceClassicPdbLineInfoFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbModuleNames as replaceClassicPdbModuleNamesFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbPublicSymbol as replaceClassicPdbPublicSymbolFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbStringTableName as replaceClassicPdbStringTableNameFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbThreadDataSymbol as replaceClassicPdbThreadDataSymbolFile } from "./metadata/classic-pdb.js";
import { replaceClassicPdbSymbolName as replaceClassicPdbSymbolNameFile } from "./metadata/classic-pdb.js";
export { parseClassicPdbFile as parseClassicPdb, insertClassicPdbFileChecksumFile as insertClassicPdbFileChecksum, insertClassicPdbConstantSymbolFile as insertClassicPdbConstantSymbol, insertClassicPdbDataSymbolFile as insertClassicPdbDataSymbol, insertClassicPdbLineBlockFile as insertClassicPdbLineBlock, insertClassicPdbPublicSymbolFile as insertClassicPdbPublicSymbol, insertClassicPdbThreadDataSymbolFile as insertClassicPdbThreadDataSymbol, removeClassicPdbFileChecksumFile as removeClassicPdbFileChecksum, removeClassicPdbLineBlockFile as removeClassicPdbLineBlock, removeClassicPdbSymbolFile as removeClassicPdbSymbol, replaceClassicPdbFileChecksumFile as replaceClassicPdbFileChecksum, replaceClassicPdbConstantSymbolFile as replaceClassicPdbConstantSymbol, replaceClassicPdbDataSymbolFile as replaceClassicPdbDataSymbol, replaceClassicPdbLineBlockFile as replaceClassicPdbLineBlock, replaceClassicPdbLineInfoFile as replaceClassicPdbLineInfo, replaceClassicPdbModuleNamesFile as replaceClassicPdbModuleNames, replaceClassicPdbPublicSymbolFile as replaceClassicPdbPublicSymbol, replaceClassicPdbStringTableNameFile as replaceClassicPdbStringTableName, replaceClassicPdbThreadDataSymbolFile as replaceClassicPdbThreadDataSymbol, replaceClassicPdbSymbolNameFile as replaceClassicPdbSymbolName };
export { FormatError, UnsupportedFormatError } from "./binary/errors.js";
export { BinaryReader, readCompressedInt, readCompressedUInt } from "./binary/reader.js";
export { decodeInstructions, encodeInstruction, encodeOpcode, formatInstruction, encodeOperand, getInstructionSize } from "./il/instructions.js";
export { codedIndexWidth, decodeCodedIndex, encodeCodedIndex, metadataTableNames, parseTablesStream, tableIndexWidth } from "./metadata/tables.js";
export { MetadataHeaps, parseMetadataRoot } from "./metadata/streams.js";
export { encodeCustomAttribute, encodePermissionSet, parseCustomAttribute, parsePermissionSet } from "./metadata/custom-attributes.js";
export { appendPortablePdbDocumentName, decodePortablePdbDocumentName, decodePortablePdbSequencePoints, encodePortablePdbDocumentName, encodePortablePdbSequencePoints, addEmbeddedPortablePdbDocument, insertEmbeddedPortablePdbDocument, addEmbeddedPortablePdbTypeDefinitionDocuments, removeEmbeddedPortablePdbDocument, replaceEmbeddedPortablePdbDocumentMetadata, replaceEmbeddedPortablePdbTypeDefinitionDocuments, replaceEmbeddedPortablePdbDocumentName, replaceEmbeddedPortablePdbLocalScope, replaceEmbeddedPortablePdbLocalVariable, replaceEmbeddedPortablePdbLocalConstant, replaceEmbeddedPortablePdbCustomDebugInformation, replaceEmbeddedPortablePdbMethodDocument, replaceEmbeddedPortablePdbImportScope, replaceEmbeddedPortablePdbSequencePoints, addEmbeddedPortablePdbSource, removeEmbeddedPortablePdbSource, removeEmbeddedPortablePdbSourceLink, removeEmbeddedPortablePdbCustomDebugInformation, replaceEmbeddedPortablePdbSource, addEmbeddedPortablePdbSourceLink, replaceEmbeddedPortablePdbSourceLink, serializeEmbeddedPortablePdb } from "./metadata/portable-pdb.js";
export { encodeSignature, encodeTypeSignature, parseSignature, parseTypeSignature, remapTypeReferences } from "./metadata/signatures.js";
export { parseCliHeader, parsePE } from "./pe/headers.js";
