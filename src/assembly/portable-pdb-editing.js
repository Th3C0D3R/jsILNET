import { FormatError, UnsupportedFormatError } from "../binary/errors.js";
import { parseEmbeddedPortablePdbData } from "../pe/headers.js";
import {
  addEmbeddedPortablePdbDocument as addPortablePdbDocument,
  insertEmbeddedPortablePdbDocument as insertPortablePdbDocument,
  addEmbeddedPortablePdbTypeDefinitionDocuments as addPortablePdbTypeDefinitionDocuments,
  removeEmbeddedPortablePdbDocument as removePortablePdbDocument,
  replaceEmbeddedPortablePdbTypeDefinitionDocuments as replacePortablePdbTypeDefinitionDocuments,
  replaceEmbeddedPortablePdbDocumentMetadata as replacePortablePdbDocumentMetadata,
  replaceEmbeddedPortablePdbDocumentName as replacePortablePdbDocumentName,
  replaceEmbeddedPortablePdbSequencePoints as replacePortablePdbSequencePoints,
  replaceEmbeddedPortablePdbMethodDocument as replacePortablePdbMethodDocument,
  replaceEmbeddedPortablePdbImportScope as replacePortablePdbImportScope,
  replaceEmbeddedPortablePdbLocalScope as replacePortablePdbLocalScope,
  replaceEmbeddedPortablePdbLocalVariable as replacePortablePdbLocalVariable,
  replaceEmbeddedPortablePdbLocalConstant as replacePortablePdbLocalConstant,
  replaceEmbeddedPortablePdbCustomDebugInformation as replacePortablePdbCustomDebugInformation,
  replaceEmbeddedPortablePdbSource as replacePortablePdbSource,
  addEmbeddedPortablePdbSource as addPortablePdbSource,
  removeEmbeddedPortablePdbSource as removePortablePdbSource,
  removeEmbeddedPortablePdbCustomDebugInformation as removePortablePdbCustomDebugInformation,
  replaceEmbeddedPortablePdbSourceLink as replacePortablePdbSourceLink,
  removeEmbeddedPortablePdbSourceLink as removePortablePdbSourceLink,
  addEmbeddedPortablePdbSourceLink as addPortablePdbSourceLink
} from "../metadata/portable-pdb.js";

export function createPortablePdbEditor(hooks) {
  return {
    addEmbeddedPortablePdbDocument(debugEntryIndex, name, options) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = addPortablePdbDocument(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        name,
        options
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    insertEmbeddedPortablePdbDocument(debugEntryIndex, options) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = insertPortablePdbDocument(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        options
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    addEmbeddedPortablePdbTypeDefinitionDocuments(
      debugEntryIndex,
      typeRid,
      documentRids
    ) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = addPortablePdbTypeDefinitionDocuments(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        typeRid,
        documentRids
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    removeEmbeddedPortablePdbDocument(debugEntryIndex, documentRid) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = removePortablePdbDocument(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        documentRid
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbTypeDefinitionDocuments(
      debugEntryIndex,
      typeRid,
      documentRids
    ) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbTypeDefinitionDocuments(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        typeRid,
        documentRids
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbDocumentMetadata(debugEntryIndex, documentRid, options) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbDocumentMetadata(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        documentRid,
        options
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbDocumentName(debugEntryIndex, documentRid, name, separator) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbDocumentName(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        documentRid,
        name,
        separator
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbSequencePoints(debugEntryIndex, methodRid, sequencePoints) {
      hooks.ensureEditable();
      if (this._portablePdbOffsetBaselines.has(methodRid)) {
        throw new UnsupportedFormatError(
          "Portable PDB sequence points cannot be replaced after IL offset remapping has been staged"
        );
      }
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbSequencePoints(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        methodRid,
        sequencePoints
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbMethodDocument(debugEntryIndex, methodRid, documentRid) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbMethodDocument(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        methodRid,
        documentRid
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbImportScope(debugEntryIndex, importScopeRid, options) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbImportScope(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        importScopeRid,
        options
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbLocalScope(debugEntryIndex, localScopeRid, options) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const pdb = hooks.getPortablePdbForEdit(debugEntryIndex, entry);
      const localScope = pdb.tables.rows.get(50)?.[localScopeRid - 1];
      if (!localScope || localScope.rid !== localScopeRid) {
        throw new RangeError(`Invalid Portable PDB LocalScope row ID ${localScopeRid}`);
      }
      if (this._portablePdbOffsetBaselines.has(localScope.Method.rid)) {
        throw new UnsupportedFormatError(
          "Portable PDB LocalScope offsets cannot be replaced after IL offset remapping has been staged"
        );
      }
      const data = replacePortablePdbLocalScope(pdb, localScopeRid, options);
      const updatedPdb = parseEmbeddedPortablePdbData(data, 0, data.length);
      const updatedScope = updatedPdb.tables.rows.get(50)?.[localScopeRid - 1];
      const body = this.getMethodBody(localScope.Method.rid);
      if (!updatedScope || !body) {
        throw new FormatError(
          `Portable PDB LocalScope row ${localScopeRid} does not resolve to a method body`
        );
      }
      const isBoundary = (offset) => offset === body.codeSize ||
        body.instructions.some((instruction) => instruction.offset === offset);
      const endOffset = updatedScope.StartOffset + updatedScope.Length;
      if (!isBoundary(updatedScope.StartOffset) || !isBoundary(endOffset)) {
        throw new FormatError(
          `Portable PDB LocalScope row ${localScopeRid} does not align with MethodDef ${localScope.Method.rid} instruction boundaries`
        );
      }
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbLocalVariable(debugEntryIndex, localVariableRid, options) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbLocalVariable(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        localVariableRid,
        options
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbLocalConstant(debugEntryIndex, localConstantRid, options) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbLocalConstant(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        localConstantRid,
        options
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbCustomDebugInformation(
      debugEntryIndex,
      customDebugInformationRid,
      value
    ) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbCustomDebugInformation(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        customDebugInformationRid,
        value
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbSource(debugEntryIndex, documentRid, source, options) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbSource(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        documentRid,
        source,
        options
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    addEmbeddedPortablePdbSource(debugEntryIndex, documentRid, source, options) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = addPortablePdbSource(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        documentRid,
        source,
        options
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    removeEmbeddedPortablePdbSource(debugEntryIndex, documentRid) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = removePortablePdbSource(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        documentRid
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    removeEmbeddedPortablePdbCustomDebugInformation(debugEntryIndex, recordRid) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = removePortablePdbCustomDebugInformation(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        recordRid
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    replaceEmbeddedPortablePdbSourceLink(debugEntryIndex, sourceLink) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = replacePortablePdbSourceLink(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        sourceLink
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    removeEmbeddedPortablePdbSourceLink(debugEntryIndex) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = removePortablePdbSourceLink(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry)
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    },

    addEmbeddedPortablePdbSourceLink(debugEntryIndex, sourceLink) {
      hooks.ensureEditable();
      if (!Number.isInteger(debugEntryIndex) || debugEntryIndex < 0 ||
          debugEntryIndex >= this.pe.debugDirectoryEntries.length) {
        throw new RangeError(`Invalid debug-directory entry index ${debugEntryIndex}`);
      }
      const entry = this.pe.debugDirectoryEntries[debugEntryIndex];
      if (entry.type !== 17 || !entry.embeddedPortablePdb) {
        throw new UnsupportedFormatError("Debug-directory entry is not an embedded Portable PDB");
      }
      const data = addPortablePdbSourceLink(
        hooks.getPortablePdbForEdit(debugEntryIndex, entry),
        sourceLink
      );
      return this.replaceEmbeddedPortablePdb(debugEntryIndex, data);
    }
  };
}
