# Architecture: Pure JavaScript/TypeScript .NET Assembly Library

## Purpose and constraints

This document proposes a native JavaScript/TypeScript library for reading, editing, and rewriting PE files containing CLI metadata and CIL method bodies, as defined by ECMA-335. The library implements the binary formats directly: it does not depend on a .NET runtime, invoke .NET for parsing or writing, or use .NET code compiled to WebAssembly.

The design deliberately separates binary parsing from semantic resolution. The raw PE, metadata, and IL layers should be useful before a complete object model exists. The work is staged so a useful read-and-fixed-size-patch release can ship before structural rewriting.

## Scope by tier

### Tier 1 — Minimal reader and fixed-size writer

- Parse DOS and PE/COFF headers, the optional header and data directories, section headers, RVA/file-offset mappings, and the CLI header and metadata directory.
- Parse the metadata root and discover `#~` or `#-`, `#Strings`, `#US`, `#GUID`, and `#Blob` streams.
- Read the core tables `Module`, `TypeDef`, `TypeRef`, `MethodDef`, `Field`, `MemberRef`, `Assembly`, and `AssemblyRef`.
- Read the row counts and schema information needed to size indices even when a referenced table is not exposed as a semantic API. References to unsupported tables remain explicit raw indices or produce an unsupported-layout diagnostic.
- Decode tiny and fat method bodies and present decoded CIL as an ordered instruction list.
- Permit only edits that preserve encoded width and all enclosing layouts, such as changing a numeric operand in place or changing an `ldstr` operand to reference an existing `#US` entry.
- Write the modified bytes without changing method-body length, metadata row counts, heap sizes, stream offsets, or PE layout. Prefer patching original byte ranges and retaining untouched bytes verbatim.
- Preserve unchanged input exactly when the supported layout allows it.

Tier 1 does **not** insert or remove instructions, add metadata rows, add heap entries, resize a body, rebuild tables, or move PE data. Reject an edit if it cannot be represented as a same-width patch.

### Tier 2 — Structural rewriting

- Insert/remove instructions; recalculate instruction offsets, branch displacements, and switch targets.
- Promote short branches to long forms when needed, repeating layout until instruction sizes and targets converge.
- Update exception-handler (EH) region offsets and lengths with the instruction layout.
- Select tiny or fat method-body encoding based on code size, locals signature, max stack, init-locals flags, and EH sections. Tiny bodies are limited to code sizes below 64 bytes, max stack 8, no locals signature, and no extra sections.
- Add metadata rows and heap values, including new `MemberRef` rows and required strings/blobs.
- Recalculate row counts, heap-size flags, simple-index and coded-index widths, tokens/references, stream headers and offsets, and final PE layout.
- Enforce required table sort order. Insertions into sorted tables may require order-preserving placement and updates to affected references; do not assume arbitrary row insertion preserves tokens.

Tier 2 heap writing initially appends values and does not deduplicate. This is simpler and correct when indices are updated, though it may produce larger, non-canonical heaps.

### Tier 3 — Full-parity target (stretch)

- Generics and their metadata/signature forms, including `TypeSpec`, `MethodSpec`, generic parameters, constraints, and variance.
- Custom attributes, including constructor resolution and serialized attribute values.
- PDB and sequence-point preservation.
- Strong-name re-signing, in addition to the earlier tiers' strip-on-modification policy.
- Resources and manifest handling.
- Tolerance and recovery for malformed or obfuscated inputs, including out-of-range tokens, duplicate rows, overlapping or nonstandard heaps, and other noncanonical structures.

Tier 3 is a parity target, not a promise of compatibility with every behavior of dnlib or de4dot.

## Implementation status

The current implementation includes the Tier 1 reader and fixed-size patch writer, plus structural method-body rewriting and a limited metadata writer. PE32 and PE32+ CLI paths are both covered, including a minimal PE32+ managed-image round trip and a PE32+ structural metadata rewrite with a reparsed appended section. CLI metadata requires exactly one Module row, at most one Assembly row, and a first TypeDef named `<Module>` in the empty namespace. Metadata-root parsing validates the version terminator, reserved field, ASCII stream names, stream alignment, directory bounds, and overlap; metadata tables validate reserved header values, ordering for all ECMA-defined sorted tables, and duplicate keys for tables with unique-key constraints; heaps validate their sentinels, complete entries (including unreferenced entries), UTF encodings, and GUID entry sizing. Unknown streams are retained on no-op round trips but prevent token-remapping edits. `#-` pointer-table list resolution is supported for TypeDef field/method/event/property ownership and MethodDef parameter ownership. All five pointer tables require one-to-one target mappings; `reorderPointerTable` supports validated cross-owner FieldPtr, ParamPtr, MethodPtr, PropertyPtr, and EventPtr moves with table-specific generic-context, signature-sequence, abstract-method, and accessor/MethodImpl checks, while non-bijective mappings are rejected. Appending a user string discards only validated trailing `#US` alignment padding before writing a new entry. Structural IL edits preserve branch targets by instruction identity, promote short branches until layout stabilizes, update supported EH regions, and move rewritten bodies into a new PE section. When a PE debug directory is present, edits that change IL instruction offsets and metadata edits that remap token RIDs are refused because external/embedded sequence points and token references are not rewritten; same-width edits and body relocations that preserve offsets retain debug references. Metadata writing currently appends `Constant`, `Param`, `Field`, `TypeRef`, `ModuleRef`, `TypeSpec`, `MemberRef`, `MethodSpec`, `GenericParam`, `GenericParamConstraint`, `AssemblyRef`, `File`, `ManifestResource`, and `CustomAttribute` rows, supports appending `#US` entries, and can insert sorted `MemberRef`, `TypeRef`, and `MethodSpec` rows while remapping known table/signature/IL/ENC references. `Constant` values are added or replaced as raw ECMA element-type/byte pairs for existing Field, Param, and Property parents; duplicate parents and declared Parent-order violations are rejected. TypeSpec signatures, MethodSpec instantiations, and ModuleRef names can be replaced in place after validation. File rows can back linked manifest resources and can be removed with reference checks and surviving-token remapping; ModuleRef rows can be removed with scope/token remapping and sorted-key checks; AssemblyRef rows can be removed with reference checks and remapping of scopes, linked resources, metadata tokens, and CIL operands; unreferenced MethodSpec and GenericParamConstraint rows can be removed with metadata/CIL token remapping and live-reference checks. Method and field signatures can be replaced with validated method-/field-form blobs, including bounds checks for generic variable indices; parsed method, field, property, and direct-TypeDef MemberRef signatures also validate generic variables against owner arities. Direct-TypeRef MemberRef signatures infer arity from a trailing backtick-number name suffix, and TypeRef renames revalidate dependent MemberRefs. Method generic arity changes must remain compatible with existing `GenericParam` rows. Embedded and linked manifest resources can be read and added; embedded payload replacement and row removal rebuild the CLI resources directory and remap surviving references. For existing linked resources that target a File row, payload replacement updates the File hash and exposes pending bytes in the resource record; callers remain responsible for writing the external file. Custom attributes can be parsed, replaced, and appended when their constructors and serialized argument types are supported (primitive/string, arrays, boxed values, and enums); appends must preserve the declared parent order, and callers can provide an enum resolver for definitions unavailable in the current assembly. Generic parameter rows can be appended and existing names/variance/special-constraint flags updated in place, and constraint type references can be replaced in place; GenericParam positions must be contiguous from zero per owner and method generic arity must match its GenericParam rows. TypeSpec generic variables are checked in known metadata use contexts, including nested signature references and MethodSpec CIL call sites during relevant edits; parser-time validation of all caller contexts remains incomplete. Removing a trailing method-owned GenericParam is supported when it has no constraints or MethodSpec instantiations; the method signature arity is reduced and surviving GenericParam references are remapped. Heap values are appended without deduplication, and operations whose references or sorted-table constraints cannot be safely preserved are rejected.

Field rows can be appended to an owner whose FieldList reaches the end of the list, including when later TypeDefs have empty ranges, or inserted at the end of any valid owner range; optimized insertion remaps shifted Field tokens and one-to-one FieldPtr insertion preserves target tokens while advancing later list boundaries. Field names and flags can be replaced in place. Unreferenced fields can be removed with metadata/CIL reference rejection, token remapping, and TypeDef list-boundary updates.
`reorderPointerTable("FieldPtr", ...)` may move fields across TypeDefs after validating each field signature against its new owner's generic arity. `ParamPtr` may move parameters across methods after checking that each new method accepts the parameter sequences without duplicates; MethodPtr, EventPtr, and PropertyPtr remain restricted to within-owner permutations.
Param rows can be appended to a MethodDef whose ParamList reaches the end of the list or inserted by sequence into any valid owner range. Optimized insertion remaps shifted Param tokens; one-to-one ParamPtr insertion preserves target tokens and advances later list boundaries. Parameter sequences must fit the method signature and remain ordered. Existing Param names and flags can be updated in place; unreferenced Param rows can be removed while remapping metadata references and MethodDef list boundaries.
StandAloneSig rows can be inserted before existing rows or removed when unreferenced. Insert/remove remaps metadata, CIL, ENC, and fat method-header local-signature tokens; both refuse debug-bearing images, unknown metadata streams, and incompatible method-body edits.
Property and Event rows can be appended to an owner whose PropertyMap/EventMap range reaches the end of the corresponding list, including when later owners have empty ranges, or inserted at the end of an existing owner's range; optimized insertion remaps shifted tokens, while bijective PropertyPtr/EventPtr insertion preserves target tokens and advances later list boundaries. Type references and signatures are validated, and map rows are created in sorted owner order when possible. Property names/flags and Event names/flags/types can be replaced in place, with associated accessor and Constant-row invariants preserved. Insertions require an existing owner map; appends can create map rows in sorted owner order. Append, insertion, and removal support #- pointer layouts only when the pointer table is bijective with its target table. Unreferenced rows can be removed with metadata-reference, pointer-row, and ownership-list remapping; row token changes are refused when debug data is present.
InterfaceImpl rows can be appended to any existing TypeDef when table ordering permits, with duplicate and TypeSpec-context checks; replacement also checks duplicates and TypeSpec context, while removal rejects live CustomAttribute references and remaps surviving InterfaceImpl row references.
`insertInterfaceImplementation` inserts by Class into an already Class-ordered table and remaps later InterfaceImpl references in metadata, custom attributes, CIL operands, and ENC tokens.

TypeRef rows can be removed with live-reference checks and surviving metadata, signature, and CIL token remapping.
MemberRef rows can be removed with the same live-reference and surviving-token safeguards across metadata and CIL.
MethodDef rows can be appended to a TypeDef whose MethodList reaches the end of the list, including when later TypeDefs have empty ranges, or inserted at the end of any valid owner range. Optimized insertion remaps existing MethodDef references in metadata and IL, generic parameter owners, and new-body operands; bijective MethodPtr insertion preserves existing method tokens. New methods accept a complete validated tiny/fat managed IL body or can be bodyless abstract virtual methods on abstract types/interfaces. Generic signatures and method generic-variable contexts are validated; callers add matching GenericParam rows separately. Param rows can be appended to a MethodDef whose ParamList reaches the end of that list, advancing later empty method ranges, or inserted by sequence into any valid owner range. MethodPtr and ParamPtr tables are supported when each is bijective with its target table.

MethodDef removal is supported when no live metadata or CIL references remain. Owned Param and method-owned GenericParam rows can be removed with the method when their row ranges are contiguous; surviving Param and GenericParam references and tokens are remapped. Non-trailing RID remapping is refused when debug data, unknown streams, or added method bodies make it unsafe. Bijective MethodPtr/ParamPtr ownership and TypeDef list boundaries are updated.
GenericParamConstraint rows owned by a removed method's GenericParam rows are removed with them when no metadata, CIL, or ENC references target those constraints; surviving constraint owners and tokens are remapped.
`insertGenericParamConstraint` inserts by Owner into an already Owner-ordered table, remapping later constraint references in metadata, custom attributes, CIL operands, and ENC tokens; it returns the inserted RID and token map.
`insertCustomAttribute` inserts by Parent into an already Parent-ordered table and remaps shifted CustomAttribute tokens in CIL operands and ENC records.
`insertDeclSecurity` inserts by Parent into an already Parent-ordered table and remaps shifted DeclSecurity references in metadata, custom attributes, CIL operands, and ENC records.
`insertNestedClass` inserts by NestedClass into an already ordered table and remaps shifted row tokens in ENC records.
`insertMethodImpl` inserts by Class into an already Class-ordered table and remaps shifted MethodImpl tokens in ENC records.
`insertConstant` inserts by Parent into an already Parent-ordered table and remaps shifted Constant tokens in metadata, CIL operands, and ENC records.
`insertFieldMarshal` inserts by Parent into an already Parent-ordered table and remaps shifted FieldMarshal tokens in ENC records.
`insertMethodSemantics` inserts by Association into an already Association-ordered table and remaps shifted MethodSemantics tokens in ENC records.
`insertClassLayout` inserts by Parent into an already Parent-ordered table and remaps shifted ClassLayout tokens in ENC records.
`insertFieldLayout` inserts by Field into an already Field-ordered table and remaps shifted FieldLayout tokens in ENC records.
`insertImplMap` inserts by MemberForwarded into an already ordered table and remaps shifted ImplMap tokens in ENC records.
`insertFieldRva` inserts by Field into an already Field-ordered table and remaps shifted FieldRVA tokens in ENC records.
`insertGenericParam` inserts by Owner/Number into an already ordered table and remaps shifted GenericParam references and ENC tokens.

MethodDef names, flags, and implementation flags can be replaced without changing row identity.

TypeDef names, namespaces, flags, and base-type references can be replaced without changing row identity; the required `<Module>` identity is preserved, and TypeSpec base signatures are checked against known generic context.

Constant rows can be appended, replaced, and removed for Field, Param, and Property parents. Values are supplied as raw ECMA element-type/byte pairs; duplicate parents and append operations that violate declared Parent ordering are rejected. Sorted insertion and removal remap surviving token references and return token maps.

FieldMarshal rows can be appended, replaced, and removed for Field and Param parents using raw native-type descriptor blobs, with duplicate-parent and sorted-order checks on append. Sorted insertion and removal remap surviving token references and return token maps.

ClassLayout and FieldLayout rows support add/replace/remove operations with TypeDef/Field parent validation, unique-parent checks, bounds validation, and sorted-key checks on append. Sorted insertion and removal remap surviving token references and return token maps.

FieldRVA rows support add/replace/remove for static fixed-width primitive fields. RVA ranges must map to file-backed PE data, and Field metadata changes preserve static status and the supported storage width while an RVA row exists. Sorted insertion and removal remap surviving token references and return token maps.

NestedClass relationships support add/replace/remove with valid TypeDef references, unique nested owners, sorted-key checks, and cycle rejection. Sorted insertion and removal remap surviving token references and return token maps.

DeclSecurity rows support append, action/raw-or-structured PermissionSet replacement, and removal with valid TypeDef/MethodDef/Assembly parents, unique parent/action pairs, and sorted-key checks. `parseDeclSecurity` decodes binary CLI PermissionSet attributes and typed named arguments; UTF-8 XML payloads are exposed as text without XML entity expansion or structural interpretation. The exported `encodePermissionSet` serializes decoded binary PermissionSets and XML text. Sorted insertion and removal remap surviving token references and return token maps.

MethodImpl rows support append/replace/remove with valid owner and method references, owner checks for MethodDef bodies, duplicate rejection, and sorted Class-key checks. Sorted insertion and removal remap surviving token references and return token maps.

MethodSemantics rows support append/replace/remove with association-kind semantics validation, same-TypeDef accessor checks, accessor signature validation, duplicate rejection, and declared Association-order checks. Sorted insertion and removal remap surviving token references and return token maps.

ImplMap rows support append/replace/remove with valid Field/MethodDef and ModuleRef references, duplicate and sorted-key checks; row removal clears the associated PInvokeImpl member flag. Sorted insertion and removal remap surviving token references and return token maps.
TypeDef rows can be appended or inserted before an existing row with validated optional base references and computed FieldList/MethodList boundaries for optimized or pointer-table metadata; inserted rows remap TypeDef references through metadata, supported signatures, CIL operands, and EH catch-clause tokens. Their stable tokens can then be used by supported field/method additions. An unreferenced empty non-module TypeDef can be removed at any RID with the corresponding remapping. TypeRef sorted insertion and TypeRef/TypeSpec removal likewise remap or reject affected EH catch-clause tokens. These operations refuse live references, debug data, unknown streams, sorted-key reordering, and unsupported combinations with added method bodies.

TypeDef removal requires no fields, methods, events, properties, or generic parameters on the removed owner; references to that TypeDef are rejected rather than removed implicitly.

ExportedType rows can be appended with existing File, AssemblyRef, or parent ExportedType implementation references and replaced in place; cyclic implementation chains are rejected. Any unreferenced row can be removed with later ExportedType references remapped in supported metadata and ENC token rows; CustomAttribute sort order is revalidated. Removal is refused with debug data or unknown streams.

ManifestResource metadata supports identity/flags replacement, linked implementation retargeting, and beforeRid insertion while preserving embedded data and refusing embedded/linked conversions. Insertion remaps ManifestResource tokens in metadata, IL, and ENC records; embedded insertions rebuild the resource directory with existing edited payloads preserved.

StandAloneSig method/local signatures can be appended or inserted before an existing row, replaced in place without changing kind, and removed with reference checking/remapping of metadata, CIL, ENC, and fat method-header local-signature tokens.
Lazy method-body parsing validates local-variable and `calli` signatures against the caller's type and method generic arities, along with MethodSpec instantiations.

Module name and generation can be replaced while preserving the MVID.
ModuleRef rows can be inserted before existing rows with ModuleRef token and TypeRef scope remapping.
MemberRef names, parents, and signatures can be replaced in place when sorted ordering, generic context, and dependent MethodSpec/custom-attribute references remain valid.
TypeSpec rows can be inserted or removed with live-reference checks and supported metadata, signature, CIL, and EH catch-token remapping.
AssemblyRef and File rows can be updated in place while preserving their tokens and linked metadata references. AssemblyRef, File, and ExportedType rows can also be inserted before an existing row; insertion remaps tokens in metadata, IL, and ENC records and synchronizes TypeRef scopes, linked resource/ExportedType references, CustomAttribute records, and AssemblyRef platform rows as applicable. AssemblyProcessor, AssemblyOS, AssemblyRefProcessor, and AssemblyRefOS rows support validated append, insertion, replacement, and removal; shifted token references and ENC tokens are remapped, and debug data or unknown streams block unsafe RID changes.
Property signatures can be updated after generic-bound checks when getter/setter signatures remain compatible.
Event names and flags can be updated in place; event-type changes validate associated add/remove accessor signatures.

Strong-name signing is opt-in and normally requires an existing matching full RSA public key. Modified signed images are still stripped by default, while `signStrongName` signs serialized output and `verifyStrongNameSignature` checks the loaded image. A missing or differently sized signature slot is allocated in the appended PE section. `replaceStrongNamePublicKey` explicitly replaces the full public key and hash algorithm before signing, and `replaceAssemblyIdentity` can change the Assembly name, version, and culture.

CustomAttribute rows can be removed with live-reference checks and surviving token remapping; edits that would remap tokens remain blocked when debug data or unknown metadata streams are present. Binary CLI PermissionSet blobs can be decoded and encoded as typed named arguments using the same primitive, array, boxed, and enum codecs as custom attributes; UTF-8 XML permission-set blobs are returned or emitted as text without parsing or entity expansion.

PE CodeView records in RSDS and NB10 forms are parsed into PDB identity/path metadata; any path that fits within the existing record slot can be replaced in place by zero-padding, preserving record size and PDB identity. Embedded Portable PDB (`MPDB`) records are decompressed with a fixed output-size limit; their metadata root, `#Pdb` identity/entry point/referenced-table counts, Portable PDB tables (Document through CustomDebugInformation), document names, sequence points, EmbeddedSource, SourceLink, and metadata heaps are exposed. Referenced type-system row counts and entry points are validated against the containing assembly, and embedded PDB GUID/age is checked against its RSDS CodeView record. `appendPortablePdbDocumentName` can append path components to a Blob heap, and the standalone document-name and sequence-point blobs can be encoded; embedded metadata/heaps are not rewritten. Classic PDB MSF 7.0 containers expose validated stream directories, information-stream identity, named streams, feature signatures, DBI headers, module descriptors, source-file lists, bounded module symbol records, and C13 line/column records with source paths resolved through the PDB string table. Public/data/procedure, managed-procedure, local, and register-relative symbols decode names and locations; managed procedures also expose method tokens. Classic symbol-name edits can resize records only in modules without scoped or unknown symbols and only when the allocated MSF block count remains unchanged; `/names` path edits preserve UTF-8 byte length. Full PDB rebuilding and Portable PDB rewriting remain unsupported, so unsafe debug-data edits are refused when a debug directory is present.

Tier 2 structural rewriting is **complete for the documented supported input profile**, not a full-parity rewriter. Method, field, local, property, method-instantiation, and type signatures can be parsed and encoded, and metadata-token remapping updates schema-described table references, recognized signature blobs, CIL operands, ENC tokens, catch clauses, and fat-header local-signature tokens. Table-specific additions, replacements, removals, sorted insertion, and owner-aware edits validate row ordering and references. `insertMethod`, `insertParam`, `insertField`, `insertProperty`, and `insertEvent` support valid non-trailing owner ranges in optimized metadata and bijective pointer-table layouts; Property/Event insertion also creates missing owner maps in TypeDef order. `reorderPointerTable` supports validated cross-owner moves in all five pointer tables, with distinct safety checks for FieldPtr, MethodPtr, ParamPtr, PropertyPtr, and EventPtr. Sorted-key validity is checked after shared token-row remapping. Structural serialization covers PE32/PE32+, section/header expansion, overlay preservation, metadata-width changes, method-body relocation, and output reparsing. The 223-test suite includes an optional .NET smoke test that loads and invokes inserted methods through optimized MethodDef rows and a `#-` MethodPtr layout. Unknown metadata streams, non-bijective pointer layouts, debug data that would require PDB rewriting, Authenticode-signed images, and other unsupported reference/layout cases are explicitly refused. Generic full-parity, PDB rewriting, malformed-input recovery, and other Tier 3 boundaries remain outside Tier 2.

## Layered module structure

```text
src/
  binary/
    reader.ts                 bounded little-endian reads and alignment
    writer.ts                 bounded little-endian writes and patch ranges
    errors.ts                 diagnostics with file offset and format context
  pe/
    headers.ts                DOS, COFF, optional header, directories, sections
    rva.ts                    checked RVA <-> file-offset mapping
    cli.ts                    CLR header and CLI data-directory parsing
  metadata/
    root.ts                   BSJB root, version, stream directory
    streams.ts                stream slices and heap accessors
    tables.ts                 schemas, row decoding, index widths, coded indices
    signatures.ts             compressed integers and signature grammar
  il/
    opcodes.ts                opcode definitions and operand categories
    instructions.ts           instruction decode/encode and offset model
    body.ts                   tiny/fat method body and EH section parsing
  resolution/
    module.ts                 semantic module facade
    types.ts                  TypeDef/TypeRef and member relationships
    methods.ts                MethodDef and decoded-body facade
  writer/
    patch.ts                  Tier 1 fixed-range patch writer
    metadata.ts               Tier 2 heap/table/stream reconstruction
    methods.ts                method-body layout and EH serialization
    pe.ts                     final section/layout and directory updates
  index.ts                    public API
```

The names are illustrative; implementation can consolidate files while preserving the boundaries.

### Layer responsibilities

- **`binary/`** provides bounded reads/writes, little-endian primitives, alignment, and source-location-aware errors. No layer should read beyond a containing slice or silently substitute default values for invalid offsets.
- **`pe/`** validates PE structures and maps RVAs through section ranges. It locates the CLI header and metadata without assuming that an RVA equals a file offset.
- **`metadata/`** treats streams and tables as binary structures. It owns heap encodings, table schemas, index-width rules, and signature parsing, but does not require a semantic object graph.
- **`il/`** handles opcode and method-body formats independently of metadata semantics. Token operands can remain numeric tokens until a resolver is available.
- **`resolution/`** builds optional navigable relationships over raw rows and heap references. This layer must not be required for Tier 1 parsing or writing.
- **`writer/`** has separate strategies for fixed-range patching and structural rebuilding. Structural writing is not a hidden fallback for a Tier 1 edit.

## Binary and semantic data model

### PE and CLI

Retain the original file bytes as an immutable source buffer and represent parsed structures as validated ranges into it. Header models include machine/optional-header information, data directories, sections, and the CLI header fields. RVA mapping must account for each section's virtual address, raw-data range, and file bounds. The metadata root and method bodies are found via the CLI metadata directory and method RVAs, respectively.

### Metadata root and streams

The root parser validates the `BSJB` signature, version string and alignment, flags, stream count, and each stream's offset, size, and padded name. Support `#~` and `#-` table streams and the four standard heaps. Keep stream slices distinct from the original PE buffer and validate that each declared range is inside the containing file.

Heap accessors return typed references rather than bare numbers:

- `StringIndex` addresses a null-terminated UTF-8 byte sequence in `#Strings`; index zero represents the empty string.
- `UserStringToken` addresses a `#US` entry. `ldstr` carries a four-byte metadata token with the `0x70` token prefix, not a generic `#Blob` index. A `#US` entry has a compressed byte length, UTF-16LE payload, and trailing special-character indicator.
- `GuidIndex` is one-based and selects a 16-byte GUID; zero represents no GUID.
- `BlobIndex` addresses a compressed-length-prefixed byte sequence in `#Blob`; index zero represents an empty blob.

Tier 1 resolves existing entries only. Tier 2 appends new entries, returning new typed indices; deduplication is deferred. Compressed unsigned integers use the ECMA-335 1-, 2-, or 4-byte encodings and must reject reserved/invalid prefixes.

### Metadata tables and index encoding

Represent a row as `{ table, rid, columns }`, with each column retaining its ECMA type (fixed integer, heap index, simple table index, or coded index). Use one declarative schema registry to decode rows, calculate row sizes, and encode rows. Coded-index definitions contain their tag-bit count and target-table ordering; do not duplicate this knowledge in readers and writers.

Core Tier 1 row schemas:

| Table | Columns in order |
|---|---|
| `Module` | `Generation: u2`, `Name: StringIndex`, `Mvid: GuidIndex`, `EncId: GuidIndex`, `EncBaseId: GuidIndex` |
| `TypeRef` | `ResolutionScope: ResolutionScope`, `TypeName: StringIndex`, `TypeNamespace: StringIndex` |
| `TypeDef` | `Flags: u4`, `TypeName: StringIndex`, `TypeNamespace: StringIndex`, `Extends: TypeDefOrRef`, `FieldList: Field index`, `MethodList: MethodDef index` |
| `Field` | `Flags: u2`, `Name: StringIndex`, `Signature: BlobIndex` |
| `MethodDef` | `RVA: u4`, `ImplFlags: u2`, `Flags: u2`, `Name: StringIndex`, `Signature: BlobIndex`, `ParamList: Param index` |
| `MemberRef` | `Class: MemberRefParent`, `Name: StringIndex`, `Signature: BlobIndex` |
| `Assembly` | `HashAlgId: u4`, `MajorVersion: u2`, `MinorVersion: u2`, `BuildNumber: u2`, `RevisionNumber: u2`, `Flags: u4`, `PublicKey: BlobIndex`, `Name: StringIndex`, `Culture: StringIndex` |
| `AssemblyRef` | `MajorVersion: u2`, `MinorVersion: u2`, `BuildNumber: u2`, `RevisionNumber: u2`, `Flags: u4`, `PublicKeyOrToken: BlobIndex`, `Name: StringIndex`, `Culture: StringIndex`, `HashValue: BlobIndex` |

The table stream's `Valid` bitmap identifies present tables and is followed by each present table's row count. Row widths are computed from the current file:

- A simple table index is 2 bytes while the target table has fewer than 65,536 rows, otherwise 4 bytes.
- A coded index is 2 bytes only when the largest target-table row count fits in the remaining bits after its tag bits; otherwise it is 4 bytes. For `n` tag bits, the 2-byte limit is fewer than `2^(16-n)` rows.
- Heap indices use the table-stream heap-size flags for string, GUID, and blob index width.
- Coded-index definitions needed by the core rows include `ResolutionScope` (Module, ModuleRef, AssemblyRef, TypeRef), `TypeDefOrRef` (TypeDef, TypeRef, TypeSpec), and `MemberRefParent` (TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec).

`MethodDef.ParamList` refers to `Param`, which is outside the Tier 1 semantic table set. The parser must still account for its row count and correct index width, and must preserve or explicitly reject layouts it cannot safely rewrite. The same principle applies to coded-index targets not otherwise exposed by Tier 1. For `#-`, pointer tables can alter list-column semantics; Tier 1 must either implement the applicable pointer-table layouts or reject such a layout explicitly rather than interpreting it as optimized `#~` data.

The `Sorted` bitmap is relevant to tables that require ordering. The writer must preserve and validate sorted-table constraints; Tier 2 insertions into tables such as `CustomAttribute` and `InterfaceImpl` must be ordered by their specified keys. Row IDs are one-based. A metadata token combines a table identifier and row ID; adding or reordering rows can invalidate tokens held by method bodies, signatures, custom attributes, and other tables.

### Signatures

Signatures are structured compressed binary values inside `#Blob`, not opaque arbitrary byte sequences once semantic editing is requested. The signature module should parse element types, calling conventions, parameter counts, return/parameter types, custom modifiers, sentinels, generic arity/parameters, and local-variable signatures as applicable. Tier 1 may retain unedited signature blobs byte-for-byte; it must not claim to understand or rewrite forms it does not parse. Broader generic and modifier support is staged with Tier 3.

### CIL instructions

Use an opcode registry keyed by either a one-byte opcode or a two-byte opcode beginning with `0xFE`. Each descriptor includes mnemonic, operand category, and short/long branch partner where one exists. Decode `0xFE` using a second opcode lookup; do not treat the table as a single 256-entry set.

An instruction model should include:

```text
Instruction {
  opcode: Opcode
  operand: Operand
  originalOffset: number
  encodedSize: number
}
```

Operands are a tagged union: no operand, signed/unsigned integer, floating-point, variable index, metadata token, relative branch target, or switch target list. Branch and switch operands should be represented as resolved instruction references (or stable labels) after decode, while retaining their original relative values for diagnostics/unchanged output. `switch` is variable-length: a 4-byte count followed by that many 4-byte relative displacements. It cannot be decoded using a fixed operand width.

The encoder computes instruction sizes from opcode and operand representation, then emits relative offsets from the end of the relevant instruction. Tier 1 only accepts operand updates that keep the encoded width identical. Tier 2 promotes short branches (`br.s`, `brtrue.s`, and related forms with signed 8-bit displacement) when a target is outside -128..127, then repeats layout and promotion until stable because each promotion can move other targets.

### Method bodies and exception handlers

`body.ts` distinguishes tiny and fat headers. Tiny format encodes the code size in the header and implies max stack 8, no locals signature, and no extra sections; code size must be less than 64 bytes. Fat format carries flags/header size, max stack, code size, and local-signature token and may be followed by aligned extra sections.

Parse and write EH sections separately from the instruction stream. Support small and fat EH clause encodings when structural rewriting is implemented; clauses carry flags, try offset/length, handler offset/length, and (for catch clauses) a class token or (for filter clauses) a filter offset. Region boundaries must map to instruction boundaries and be recomputed in lockstep with shifted instructions. Tiny-to-fat conversion is mandatory when any tiny constraint is violated; fat-to-tiny conversion is only safe if all tiny constraints hold and no extra sections are present.

## Writer architecture and invariants

### Tier 1 patch writer

Track dirty fields and their original byte ranges. For each edit, prove before writing that the encoded value fits the original range and that no dependent length, index width, token, or offset changes. Patch only the target range; copy all other bytes unchanged. Refuse an edit if these invariants cannot be established. For a no-op input, preserve the original bytes instead of normalizing layout.

When a modified assembly is strong-name signed, the default policy is to clear the signature and signed flag rather than emit a known-invalid signature. Callers may opt into re-signing with `signStrongName(privateKey)` when the RSA key matches the existing full assembly public key, or explicitly change the key/hash identity with `replaceStrongNamePublicKey(privateKey, options)`. `replaceAssemblyIdentity` updates the manifest name/version/culture. A correctly sized slot is reused, or a new slot is allocated in the appended PE section. The signer hashes the standard 16-slot PE optional header when 15 or 16 data directories are declared, plus section data, excluding the signature slot and zeroing the PE checksum and certificate-directory entry, then emits the reversed RSA PKCS#1 signature bytes. Unsupported optional-header directory counts, key formats, hash algorithms, and key mismatches fail explicitly.

Tier 1 refuses edits when the PE security directory indicates an Authenticode certificate. Certificate stripping is not implemented, so the writer must not silently leave a stale Authenticode signature after a patch.

### Tier 2 structural writer

Use an explicit rebuild pipeline:

1. Apply semantic edits and assign stable temporary row identities.
2. Append required heap values and collect all references.
3. Determine row ordering and final row IDs for sorted/renumbered tables.
4. Remap metadata tokens and table references across metadata, signatures, and IL operands.
5. Recompute row counts, heap-size flags, simple-index and coded-index widths; encode all tables.
6. Re-encode method bodies, iterating instruction layout and branch promotions to a fixed point; update EH sections and method RVAs.
7. Rebuild metadata streams and root headers with correct offsets/alignment.
8. Rebuild PE section data and update affected sizes, RVAs, and CLI metadata directory; preserve the original image overlay before the appended section.
9. Apply the strong-name strip policy unless signing is explicitly available.
10. Validate the output by reparsing it before returning bytes.

Each phase should produce diagnostics and validate its preconditions. Avoid silent fallback to original values or partially serialized output.

## Explicit edge-case disposition

| Edge case | Design response |
|---|---|
| Coded-index width ambiguity | Compute per file from target row counts and tag bits; re-evaluate after Tier 2 row changes. |
| String/blob heap deduplication | Tier 1 uses existing entries only. Tier 2 appends without deduplication initially; deduplication can be added later without changing the typed-index API. |
| Token stability and sorted tables | Keep temporary row identity separate from final RID/token; sort constrained tables and remap every known reference before encoding. Reject unsupported remapping cases. |
| Short-branch promotion | Recalculate all offsets and promote out-of-range short forms until no size changes occur; then encode displacements. |
| EH regions | Model region boundaries independently and update them alongside instruction offsets; validate boundaries before write. |
| Tiny/fat method header | Validate all tiny constraints; promote to fat when any constraint is violated and align/serialize extra sections correctly. |
| `0xFE` multi-byte opcodes | Decode prefix and second byte through a two-stage registry; reject unknown/truncated opcode sequences with an offset diagnostic. |
| `switch` operand | Parse count and N signed 32-bit displacements; validate length and resolve all targets; recalculate all target offsets after edits. |
| Signature blobs | Parse using a dedicated compressed-integer/element-type grammar; preserve untouched bytes, and reject semantic rewrites of unsupported forms. |
| Assembly identity / strong-name signature | Name/version/culture and full public-key/hash updates are explicit; clear signed flag and signature by default, while opt-in signing supports matching RSA full keys and signature-slot reuse/allocation. |
| Malformed/adversarial input | Tier 1/2 accept well-formed standard-compiler inputs. Validate bounds and structural invariants, reject unsupported or malformed data with explicit diagnostics, and defer obfuscation tolerance/recovery to Tier 3. |

## Tier 1 assumptions and limitations

The initial implementation should document and enforce a supported-input profile rather than silently misparse unfamiliar data:

- PE32/PE32+ section layouts must use valid power-of-two alignments, aligned header/section ranges, bounded non-overlapping raw/virtual ranges, and bounded CLI metadata/method-body ranges; unsupported native/CLI combinations are rejected.
- The optional header must contain every data directory it declares. Data-directory declarations are not silently truncated to the available header bytes.
- Metadata root and stream ranges must be in bounds, non-overlapping where required, and use recognized stream layouts. Unknown streams may be retained only if their ranges can be safely preserved without moving them.
- Tier 1 supports the listed core tables and enough table-count/schema information to decode their index widths. Unsupported table schemas or pointer-table layouts that affect interpretation are rejected for edits; they must never be treated as absent.
- Table heap references must be in bounds and well-formed; list columns must use ordered, one-based positions. Invalid compressed integers, unterminated strings, invalid `#US` payloads, and truncated blobs produce explicit errors.
- CIL opcodes and operands must be valid and fully contained in the method body. Unknown, truncated, or unsupported prefixes are rejected rather than skipped.
- Only fixed-size edits are supported. Any request that changes instruction length, row count, heap size, index width, token mapping, method size, EH layout, or PE layout is rejected in Tier 1.
- Input is assumed to come from standard compilers and to be structurally well-formed. Duplicate rows, out-of-range tokens, overlapping heaps, nonstandard heap ordering, and obfuscator-specific tricks are not a Tier 1/2 compatibility goal.
- A modified strong-name-signed assembly loses its signature and signed flag by default. Call `signStrongName` before serialization to request signing with a matching full public key, or use `replaceStrongNamePublicKey` to change it; `replaceAssemblyIdentity` changes name/version/culture. A slot is reused or allocated in a new section.
- Authenticode-signed PE files can be parsed and round-tripped unchanged, but Tier 1 edits are rejected until certificate stripping is supported.
- No guarantee of PDB or sequence-point preservation is made. Embedded resource replacement and a subset of custom-attribute parsing/replacement are supported; unimplemented manifest/resource and attribute forms remain explicit limitations. Unknown data that cannot safely be relocated must cause a clear refusal rather than being dropped silently.

## Testing strategy

- **Round trip:** use a real compiler-produced DLL (for example, trivial Hello World output). Parse and serialize unchanged, requiring byte-for-byte equality for the supported no-op path. Also load/run the rewritten result in a .NET test harness where available; the harness is validation only and is not a library dependency.
- **Golden files:** keep representative metadata rows and heap entries for each supported table/encoding, plus IL test bodies covering every operand category, one-byte and `0xFE` opcodes, switch, tiny/fat headers, and EH sections.
- **Width properties/fuzzing:** generate row counts around simple-index and coded-index thresholds; verify widths, round trips, and boundary/error behavior.
- **Offset properties/fuzzing:** generate instruction streams and target layouts around short-branch limits, cascading promotions, switch target updates, and EH boundaries; verify encode/decode offsets and stable layout.
- **Negative tests:** ensure truncated headers/heaps/bodies, invalid indices, unsupported table layouts, and malformed compressed integers fail with contextual diagnostics and never produce success-shaped partial output.
- **Tiered acceptance:** maintain tests that assert Tier 1 rejects length-changing edits and row/heap growth, while the corresponding structural cases are enabled only in Tier 2.

## Staged roadmap

1. **Foundation:** bounded binary primitives, diagnostics, PE/CLI parsing, metadata-root/stream discovery, and the declarative table/index schema.
2. **Tier 1 reader:** heap readers, core table decoding, CIL opcode registry and body decoding, and optional semantic facade.
3. **Tier 1 fixed-size writer:** dirty-range patching, existing-`#US` operand updates, same-width numeric edits, strong-name stripping, and no-op round-trip validation.
4. **Tier 2 metadata rewriting:** supported table-specific additions, replacements, removals, heap growth, index-width changes, metadata stream rebuilding, sorted insertion, and schema-driven token remapping are implemented for the documented input profile; unknown streams and references without safe remappers are refused.
5. **Tier 2 IL/PE rewriting:** instruction editing, branch/switch/EH fixups, body-format changes, method RVA relocation, PE32/PE32+ section relayout, overlay preservation, and output reparse validation are implemented for the documented input profile; unsupported layouts are explicitly rejected.
6. **Tier 3 parity:** generic signatures/metadata, custom attributes, PDBs, signing, resources/manifests, and malformed/obfuscated-input hardening. Generic, attribute, embedded-resource, and strong-name signing support is partial; remaining boundaries are documented above.

## Open questions before implementation

- Which JavaScript/TypeScript baseline, module format, and runtime targets must be supported (for example, Node.js only versus browsers as well)?
- Is byte-identical no-op serialization required for every supported input, or is it sufficient for an explicitly bounded input profile with semantic equivalence elsewhere?
- May integration tests rely on an installed .NET SDK/compiler and runtime, or must compiler-produced fixtures be checked in so tests run without .NET installed?
- What exact PE variants, metadata streams, and `#-` pointer-table layouts belong in the first supported-input profile?
- Strong-name signing requires callers to supply the matching private key; no private key material is stored in the assembly or repository.
