# jsILNET

`jsILNET` is a dependency-free JavaScript library for reading, modifying, and rewriting .NET assemblies. It parses PE/CLI binary formats directly; the library does not use a .NET runtime or .NET code compiled to WebAssembly.

This is an early-stage library, not a dnlib-equivalent rewriter. The implementation covers Tier 1 and a focused subset of Tier 2 in [ARCHITECTURE.md](ARCHITECTURE.md).

## Requirements

- Node.js 20 or later
- ECMAScript modules
- No runtime package dependencies

## Current capabilities

- Parse PE32/PE32+ headers, sections, RVA mappings, and the CLI header.
- Validate PE section/file alignment relationships and reject out-of-file, overlapping, or overflowing section ranges.
- Validate ordering for ECMA-defined sorted metadata tables and reject duplicate keys in metadata tables with unique keys.
- Parse and bounds-check debug-directory entries, adjusting their raw pointers if section-header growth shifts file data.
- Replace RSDS/NB10 CodeView PDB paths in place when the encoded path length is unchanged.
- Read the metadata root, `#~`/`#-` table streams, and the `#Strings`, `#US`, `#GUID`, and `#Blob` heaps.
- Decode ECMA-335 metadata tables and expose core module, type, field, method, member-reference, and assembly-reference data.
- Parse and encode method, field, local, property, method-instantiation, and type signatures, including array shapes, generic instances, modifiers, and compressed signed integers.
- Read embedded manifest-resource payloads with bounds checks and expose linked-resource implementation references.
- Add embedded or linked manifest-resource rows and replace embedded payloads while updating offsets and relocating the CLI resources directory.
- Parse and replace custom-attribute blobs for supported primitive, string, array, boxed, and enum argument types; an optional resolver callback supplies external enum underlying types.
- Decode CIL instructions, including `0xFE`-prefixed opcodes, branch and switch operands, tiny/fat method headers, and exception-handler sections.
- Patch fixed-width instruction operands using existing heap entries and validated metadata tokens, or replace an opcode when its encoded width and operand layout remain unchanged.
- Insert/remove CIL instructions, resolve branch and switch targets, promote out-of-range short branches, and update supported exception-handler regions.
- Re-encode tiny/fat method bodies, including max-stack changes, and relocate rewritten bodies and rebuilt metadata into an appended PE section.
- Append `TypeRef`, `MemberRef`, and `AssemblyRef` rows and required string/blob heap entries while recalculating metadata index widths and rebuilding metadata streams.
- Append fields to the last TypeDef and replace field names/flags without changing their tokens; `#-` append is supported when FieldPtr is one-to-one with Field.
- Append validated concrete IL method bodies or bodyless abstract virtual methods to the last TypeDef, including one-to-one `#-` MethodPtr layouts; generic methods are supported when their matching GenericParam rows are added.
- Append parameter rows to the last MethodDef, with signature-sequence checks and support for one-to-one ParamPtr metadata.
- Append properties and events to the last TypeDef and remove unreferenced rows; `#-` PropertyPtr/EventPtr layouts are supported when each pointer table is a one-to-one mapping to its target rows.
- Append `TypeSpec` rows after validating type references and locally known generic-instance arities.
- Append `MethodSpec` rows with validated generic instantiation signatures.
- Append `GenericParam` rows with validated owner ordering, variance, and special-constraint flags; update existing parameter names and flags without changing their row identities.
- Insert sorted `MemberRef` rows while remapping their supported metadata and CIL references; the API returns old-to-new tokens.
- Insert sorted `TypeRef` rows while remapping known metadata references, signature blobs, and CIL operands.
- Insert sorted `MethodSpec` rows while remapping custom-attribute references and CIL operands.
- Append UTF-16LE user strings to `#US` and use their tokens in `ldstr` edits.
- Preserve unchanged input byte-for-byte; reparse rewritten output and maintain existing metadata token RIDs when appending supported rows.

## API surface

The package exports `parseAssembly` and `Assembly`, plus lower-level PE, metadata, heap, signature, binary-reader, coded-index, CIL-instruction, and method-body parsing utilities.

An `Assembly` exposes parsed PE/CLI metadata, `module`, `types`, `typeRefs`, `typeSpecs`, `methods`, `memberRefs`, `moduleRefs`, `methodSpecs`, `genericParams`, `genericParamConstraints`, `customAttributes`, `assemblyRefs`, `files`, and `resources`. Type records include their fields, methods, events, properties, and generic parameters; method records include their parameter rows. Method bodies are loaded with `getMethodBody` or `getInstructions`. Editing methods include `setInstructionOperand`, `setInstructionOpcode`, `insertInstruction`, `removeInstruction`, `setMethodMaxStack`, `replaceMethodSignature`, `replaceCodeViewPath`, `replaceModule`, `replaceField`, `replaceFieldSignature`, `addField`, `removeField`, `addFieldRva`, `replaceFieldRva`, `removeFieldRva`, `addMethod`, `addConstant`, `replaceConstant`, `addParam`, `replaceParam`, `removeParam`, `addProperty`, `removeProperty`, `addEvent`, `removeEvent`, `addMethodSemantics`, `replaceMethodSemantics`, `removeMethodSemantics`, `replaceAssemblyIdentity`, `signStrongName`, `replaceStrongNamePublicKey`, `verifyStrongNameSignature`, `parseCustomAttribute`, `replaceCustomAttribute`, `addCustomAttribute`, `removeCustomAttribute`, `addManifestResource`, `replaceManifestResource`, `removeManifestResource`, `addTypeRef`, `insertTypeRefSorted`, `removeTypeRef`, `addModuleRef`, `replaceModuleRef`, `removeModuleRef`, `addTypeSpec`, `replaceTypeSpecSignature`, `removeStandAloneSig`, `addMemberRef`, `insertMemberRefSorted`, `addMethodSpec`, `replaceMethodSpecInstantiation`, `insertMethodSpecSorted`, `removeMethodSpec`, `addGenericParam`, `replaceGenericParam`, `removeGenericParam`, `addGenericParamConstraint`, `insertGenericParamConstraint`, `replaceGenericParamConstraint`, `removeGenericParamConstraint`, `addAssemblyRef`, `removeAssemblyRef`, `addAssemblyProcessor`, `replaceAssemblyProcessor`, `removeAssemblyProcessor`, `addAssemblyOS`, `replaceAssemblyOS`, `removeAssemblyOS`, `addAssemblyRefProcessor`, `replaceAssemblyRefProcessor`, `removeAssemblyRefProcessor`, `addAssemblyRefOS`, `replaceAssemblyRefOS`, `removeAssemblyRefOS`, `addFile`, `removeFile`, and `addUserString`; sorted insertion and removal methods return a token map when existing token RIDs change. `addConstant` and `replaceConstant` accept the ECMA element type and its raw encoded value bytes; adding requires an existing Field, Param, or Property parent and rejects duplicate parents or an append that violates declared table ordering. `replaceModule({ name, generation })` updates the module name or unsigned 16-bit generation while preserving its MVID. `signStrongName(privateKey)` accepts an RSA PEM or Node.js private `KeyObject` and signs during serialization; the key must match the assembly's existing full public key, and a correctly sized signature slot is reused or allocated in a new PE section. `replaceStrongNamePublicKey(privateKey, { hashAlgorithm })` explicitly changes the full Assembly public key/hash ID to match the supplied private key, then requests signing; the Assembly name, version, and culture remain unchanged. `replaceAssemblyIdentity({ name, culture, version })` changes those three manifest identity fields. `verifyStrongNameSignature()` verifies signatures using the embedded RSA public key. Signing supports the standard PE optional header with exactly 16 data directories and SHA-1, SHA-256, SHA-384, or SHA-512 assembly hash IDs; nonstandard directory-count profiles are refused. `parseCustomAttribute` and `replaceCustomAttribute` accept an optional `{ resolveEnum(name) }` option; `addCustomAttribute` accepts the same resolver as an input property, allowing callers to resolve external enum definitions. `addCustomAttribute` appends only when the declared parent ordering remains valid. `insertGenericParamConstraint({ ownerRid, constraint })` inserts into an already Owner-ordered GenericParamConstraint table and returns `{ rid, tokenMap }`. `Resource, File, TypeRef, ModuleRef, AssemblyRef, StandAloneSig, MethodSpec, GenericParamConstraint, GenericParam, Property, Event, and CustomAttribute removal rejects rows with live references and remaps surviving references. `serialize` returns a `Uint8Array`, and `toBuffer` returns a Node.js `Buffer`.

Invalid or unsupported structures and edits raise `FormatError` or `UnsupportedFormatError`; they are not silently skipped.

`addInterfaceImplementation` appends an InterfaceImpl row to any existing TypeDef when table ordering permits, with duplicate, sort-order, and TypeSpec-context checks. `replaceInterfaceImplementation` changes the interface type without changing its row ID and rejects duplicates or invalid TypeSpec contexts. `removeInterfaceImplementation` rejects live CustomAttribute references, compacts later row references, and returns a row-RID map.
`insertInterfaceImplementation` inserts by Class into an already Class-ordered InterfaceImpl table and returns `{ rid, tokenMap }`, remapping affected CustomAttribute, CIL, and ENC references.

`replaceTypeRef` updates a TypeRef name, namespace, or resolution scope without changing its token; `removeTypeRef` rejects live references and remaps surviving metadata, signature, and CIL references.

`removeMemberRef` rejects live metadata/CIL references and remaps surviving MemberRef tokens.

`replaceMemberRef` updates a MemberRef's name, parent, or signature without changing its token; it validates generic context (including arity inferred from a direct TypeRef parent's backtick suffix) and sorted-row order, preserves MethodSpec arity, and refuses edits to rows used as custom-attribute constructors.

`removeTypeSpec` rejects live references and remaps surviving TypeDefOrRef metadata indexes, signature references, and CIL tokens.

`replaceAssemblyRef` updates version, flags, identity strings, public-key/token bytes, or hash bytes without changing the AssemblyRef token. `replaceFile` updates a File row's name, flags, or hash without changing its token or breaking linked ManifestResource references. `addAssemblyProcessor`/`replaceAssemblyProcessor`/`removeAssemblyProcessor`, the corresponding `AssemblyOS` methods, and `AssemblyRefProcessor`/`AssemblyRefOS` methods provide validated platform-table CRUD. Processor/platform fields are checked as unsigned 32-bit values, AssemblyRef links must resolve, and removal is refused when unknown metadata streams could contain references.

`replaceManifestResourceMetadata` updates a resource's name and flags, or changes the implementation target of a linked resource; it preserves embedded payloads and refuses conversions between embedded and linked resources.

`addExportedType` appends an ExportedType row whose implementation is an existing File, AssemblyRef, or ExportedType row and returns its metadata token. `replaceExportedType` updates its name, namespace, flags, TypeDefId, or implementation without changing its token; cyclic nested-type forwarding is rejected. `removeExportedType` only removes a trailing unreferenced row and refuses debug data or unknown metadata streams.

`replaceField` updates a Field row's name and flags without changing its token; `addField` appends a validated field to the last TypeDef and supports one-to-one FieldPtr metadata. `removeField` rejects live metadata/CIL references, remaps surviving Field tokens, and updates TypeDef list ownership for optimized and supported `#-` metadata.

`addFieldRva`, `replaceFieldRva`, and `removeFieldRva` edit FieldRVA rows; exposed Field records include their RVA or `null`. RVA edits validate static fixed-width primitive fields and require the complete value range to be backed by PE file data. Changing a Field with FieldRVA cannot make it non-static or variable-sized.

`addParam` appends a validated Param row to the last MethodDef. Its sequence must fit the current method signature and preserve existing parameter-row order; `#-` is supported when ParamPtr has a one-to-one mapping. `replaceParam` updates a Param row's name or flags without changing its row identity. `removeParam` rejects live references and remaps surviving Param row IDs and MethodDef list boundaries.

`removeStandAloneSig` rejects rows referenced by metadata, CIL operands, or fat method headers; it remaps surviving StandAloneSig tokens, including local-variable signature tokens, and refuses edits when debug data or unknown metadata streams make remapping unsafe.

`addStandAloneSig({ signature })` appends a parsed method or local-variable signature and returns its stable StandAloneSig token. `replaceStandAloneSig` replaces the blob in place while preserving signature kind; signatures are exposed in `assembly.standAloneSigs`.

`addMethod({ owner, name, flags, signature, body })` can append a concrete managed IL method to the last TypeDef when `body` is a complete, validated tiny/fat method-body byte sequence; body token operands, local signatures, and generic variable contexts are checked against the assembly. It can also append a bodyless abstract virtual method to an abstract class or interface. Both forms support generic signatures when the matching GenericParam rows are added, and one-to-one `#-` MethodPtr/ParamPtr layouts. `removeMethod` removes unreferenced methods and their owned Param/GenericParam rows when those ranges are contiguous and have no live references. MethodDef, Param, and GenericParam references are remapped together; non-trailing token remapping is refused when debug data, unknown streams, or added method bodies make it unsafe.

`addConstant` and `replaceConstant` operate on raw ECMA element-type/value-byte pairs for existing Field, Param, or Property parents; `addConstant` rejects duplicate parents and declared Parent-order violations. `removeConstant` removes a Constant row without changing metadata tokens.

`replaceMethod` updates a MethodDef name, flags, and implementation flags in place without changing its RID.

`replaceTypeDef` updates TypeDef names, namespaces, flags, and base-type references in place; it preserves the required `<Module>` row and validates base-type references and known TypeSpec generic contexts.

`addTypeDef` appends a TypeDef with a validated optional base type and stable token, initializing optimized or pointer-table ownership boundaries so fields and supported methods can subsequently be appended to it. `removeTypeDef` removes an unreferenced empty non-module type at any RID, remapping later TypeDef references in metadata, signatures, CIL operands, and catch clauses. TypeRef sorted insertion and TypeRef/TypeSpec removal also remap or reject catch-clause tokens when their RIDs change. These operations refuse live references, debug data, unknown streams, sorted-key changes, and unsupported combinations with added method bodies; non-trailing TypeDef removal returns the resulting token map.

`addFieldMarshal`, `replaceFieldMarshal`, and `removeFieldMarshal` edit raw native-type descriptor blobs for Field and Param parents; duplicate parents and declared Parent-order violations are rejected on append.

ClassLayout and FieldLayout rows can be added, updated, and removed through `addClassLayout`, `replaceClassLayout`, `removeClassLayout`, `addFieldLayout`, `replaceFieldLayout`, and `removeFieldLayout`; parent uniqueness, layout values, and declared row ordering are validated.

Nested TypeDef relationships can be added, changed, and removed with `addNestedClass`, `replaceNestedClass`, and `removeNestedClass`; duplicate nested owners, invalid TypeDef references, declared sort order, and relationship cycles are checked.

DeclSecurity rows can be added or removed, and their action or raw PermissionSet bytes can be replaced, with parent/action uniqueness and declared Parent ordering enforced. PermissionSet blobs are treated as opaque bytes.

MethodImpl override mappings can be added, replaced, and removed with `addMethodImpl`, `replaceMethodImpl`, and `removeMethodImpl`; references must resolve to method-signature MethodDef/MemberRef rows, and MethodDef bodies must belong to the owning TypeDef.

MethodSemantics rows can be added, replaced, and removed with `addMethodSemantics`, `replaceMethodSemantics`, and `removeMethodSemantics`; accessor semantics are restricted by association kind, methods must belong to the associated TypeDef, and getter/setter/add/remove signatures are validated.

P/Invoke mappings can be added, updated, and removed with `addImplMap`, `replaceImplMap`, and `removeImplMap`; members must carry the PInvokeImpl flag, scopes must be existing ModuleRef rows, and removing a mapping clears that member flag.

`replacePropertySignature` validates generic variable bounds and requires associated getter/setter signatures to remain compatible; update accessors with `replaceMethodSignature` before changing the property signature.

`replaceProperty` updates a property's name and flags without changing its row identity; a property with a Constant row must retain `HasDefault`.

`replaceEvent` updates event names, flags, and types in place; a changed event type must remain compatible with associated add/remove accessors.

The PE reader accepts power-of-two section/file alignments, enforces the PE low-alignment and standard file-alignment rules, and rejects misaligned header/section ranges, overlapping ranges, and ranges outside file/RVA bounds.

## Boundaries and signature behavior

Structural rewriting is deliberately limited. Metadata additions support appending `MethodDef` bodies or bodyless abstract methods, `Param`, `Field`, `Property`, `Event`, `TypeRef`, `ModuleRef`, `TypeSpec`, `MemberRef`, `MethodSpec`, `GenericParam`, `GenericParamConstraint`, `AssemblyRef`, and `File` rows when declared sorted-table ordering is preserved, plus appending `#US` entries. Field, Property, Event, and MethodDef additions target the last TypeDef. `#-` pointer-table operations are supported for the corresponding ownership edits only when each pointer table is a one-to-one mapping to its target table; `reorderPointerTable` permits only within-owner permutations of a complete bijective map and rejects cross-owner or non-bijective layouts. Property/Event, TypeDef, and ExportedType rows can be removed when no metadata rows reference them; surviving metadata references, pointer rows, and ownership-list boundaries are compacted, and token maps are returned when RIDs change. TypeDef, TypeRef, TypeSpec, and ExportedType token remapping updates supported metadata references and, where applicable, signature, CIL, catch-clause, and ENC token references, while refusing unsupported debug/stream layouts, live references to removed rows, and sorted-key changes. TypeSpec signatures, MethodSpec instantiations, and ModuleRef names can be replaced in place after validation. Field, Property, Event, CustomAttribute, File, ModuleRef, AssemblyRef, StandAloneSig, MethodSpec, GenericParamConstraint, and method-owned GenericParam rows can be removed with reference checks and surviving-token remapping; removing a method generic parameter also reduces its method signature arity and rejects live constraints or instantiations. Method removal deletes owned GenericParamConstraint rows when safe and rejects external constraint references. StandAloneSig removal also remaps CIL token operands and fat method-header local-signature tokens. Sorted-key violations are rejected instead of resorting other tables. Existing `GenericParam` names/flags and `GenericParamConstraint` type references can be updated in place without changing row identities. Sorted `MemberRef`, `TypeRef`, and `MethodSpec` insertion remaps known metadata/ENC references and method-body operands (and signatures for TypeRef changes); it refuses combinations it cannot safely remap. Generalized insertion/removal and arbitrary table sorting remain unsupported. Edits at ambiguous exception-handler boundaries, removal of branch/EH targets, unsupported method-body layouts, and Authenticode-signed images are rejected.

Modified strong-name-signed assemblies have the signature cleared by default; call `signStrongName` before serialization to request re-signing when the private key matches the existing full assembly public key. A missing signature slot is allocated in a new PE section. `replaceStrongNamePublicKey` explicitly updates the Assembly public key and hash algorithm and re-signs; `replaceAssemblyIdentity` can change the name, version, and culture. Signing supports the standard PE optional header with exactly 16 data directories and SHA-1, SHA-256, SHA-384, or SHA-512 assembly hash IDs; nonstandard directory-count profiles are refused. `verifyStrongNameSignature` verifies signatures using the embedded RSA public key. Authenticode-signed PE files can be read unchanged, but edits are refused. Generic metadata/signatures are partially supported: local generic-instance arities and MemberRef signatures on TypeSpec parents are validated, MethodSpec generic variables are checked against caller arities when method bodies are loaded, and trailing method-owned GenericParam rows can be removed with signature-arity and token remapping; wider contextual validation remains incomplete. Adding/removing manifest-resource rows, replacing embedded payloads, and remapping surviving references are supported, while editing existing linked resources is not. Custom attributes can be parsed/replaced, appended in valid parent order, and removed for supported primitive, string, array, boxed, and enum argument types; callers can supply an enum resolver for definitions unavailable in the current assembly. Attribute-constructor/member discovery beyond the current metadata is unsupported. PE CodeView records in RSDS and NB10 forms are parsed for their PDB identity and path; paths that fit within the existing record slot can be replaced while preserving record size and PDB identity. PDB contents and sequence points are not parsed or rewritten; instruction-offset-changing edits and metadata edits that remap token RIDs are refused when a PE debug directory is present, while fixed-width edits preserve its references. Broad malformed/obfuscated-input hardening remains incomplete.

PE32 and PE32+ CLI assemblies are covered, including PE32+ structural metadata rewriting and output reparsing. The parser requires one Module row, at most one Assembly row, and the special `<Module>` TypeDef first; it also rejects invalid metadata-root stream directories, table-header reserved values, malformed heap entries (including unreferenced entries), and malformed sentinels. Unknown metadata streams are retained byte-for-byte on no-op round trips; operations that remap metadata tokens refuse unknown streams. Supported Field, MethodDef, Param, Property, and Event ownership edits handle `#-` pointer tables only when each table is a bijection to its target table. The implementation otherwise assumes well-formed assemblies from standard compilers; broader malformed/obfuscated-input hardening remains incomplete. Unsupported table/stream layouts and invalid bounds or references encountered during parsing produce explicit errors.

The `#-` reader resolves TypeDef field/method/event/property ownership and MethodDef parameter lists through their pointer tables. Supported ownership edits require one-to-one pointer-to-target mappings; non-bijective layouts are explicitly rejected.

Generic TypeSpec variables referenced by TypeDef base types, interface implementations, events, generic constraints, method/field/property signatures, and MemberRefs are checked against their known owner context. Direct-TypeDef and TypeSpec-parent MemberRefs use metadata arity; direct-TypeRef MemberRefs infer arity from a trailing backtick-number name suffix, and TypeRef renames revalidate their dependent MemberRefs. TypeSpec replacement also revalidates nested references and TypeSpec arguments at CIL MethodSpec call sites; adding a MethodSpec token to an instruction and replacing a used MethodSpec instantiation validate that call site's generic context. Broader parser-time validation of all caller contexts remains incomplete.

## Tests

The test suite uses Node.js's built-in test runner and includes a compiler-produced DLL fixture. It covers byte-identical no-op round trips, fixed-size edits, PE32+ structural metadata rewriting, metadata index-width boundaries, CIL and EH decoding, strong-name signing and verification, and malformed-input bounds.

Run the suite with `npm test`; run the package syntax check with `npm run check`.
