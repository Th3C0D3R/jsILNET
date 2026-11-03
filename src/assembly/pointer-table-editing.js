import { FormatError, UnsupportedFormatError } from "../binary/errors.js";
import { parseSignature } from "../metadata/signatures.js";
import { metadataTableId, metadataTableNames } from "../metadata/tables.js";

export function createPointerTableEditor(hooks) {
  const {
    getBijectivePointerRows,
    validateGenericVariableReferences,
    getGenericParameterArity,
    validateTypeSpecDefinitions,
    validateTypeSpecGenericContext
  } = hooks;

  return {
    reorderPointerTable(pointerTable, targetRids) {
      hooks.ensureEditable();

      const pointerTableId = metadataTableId(pointerTable);

      const definitions = new Map([

        [3, { targetTableId: 4, column: "Field", owners: this.types, list: "fieldRids", records: "fields" }],

        [5, { targetTableId: 6, column: "Method", owners: this.types, list: "methodRids", records: "methods" }],

        [7, {

          targetTableId: 8,

          column: "Param",

          owners: this.methods,

          list: "parameterRids",

          records: "parameters"

        }],

        [19, { targetTableId: 20, column: "Event", owners: this.types, list: "eventRids", records: "events" }],

        [22, {

          targetTableId: 23,

          column: "Property",

          owners: this.types,

          list: "propertyRids",

          records: "properties"

        }]

      ]);

      const definition = definitions.get(pointerTableId);

      if (!definition) {

        throw new TypeError("Pointer table must be FieldPtr, MethodPtr, ParamPtr, EventPtr, or PropertyPtr");

      }

      const allowsCrossOwnerFields = pointerTableId === 3;

      const allowsCrossOwnerMethods = pointerTableId === 5;

      const allowsCrossOwnerParameters = pointerTableId === 7;

      const allowsCrossOwnerEvents = pointerTableId === 19;

      const allowsCrossOwnerProperties = pointerTableId === 22;

      if ((this.tables.valid & (1n << BigInt(pointerTableId))) === 0n) {

        throw new UnsupportedFormatError(`${metadataTableNames[pointerTableId]} is not present`);

      }

      const pointerRows = getBijectivePointerRows(

        this,

        pointerTableId,

        definition.targetTableId,

        definition.column

      );

      if (!pointerRows) {

        throw new FormatError(

          `${metadataTableNames[pointerTableId]} must be a one-to-one mapping to ${metadataTableNames[definition.targetTableId]}`

        );

      }

      const targetCount = this.tables.counts[definition.targetTableId] ?? 0;

      if (!Array.isArray(targetRids) || targetRids.length !== targetCount) {

        throw new RangeError("Pointer table order must contain every target row exactly once");

      }

      const newRids = [...targetRids];

      const uniqueRids = new Set(newRids);

      if (uniqueRids.size !== targetCount ||

          newRids.some((rid) => !Number.isInteger(rid) || rid < 1 || rid > targetCount)) {

        throw new RangeError("Pointer table order must contain every target row exactly once");

      }

      const ownerGroups = definition.owners.map((owner) => owner[definition.list]);

      const currentOwnerRids = ownerGroups.flat();

      if (currentOwnerRids.length !== targetCount ||

          new Set(currentOwnerRids).size !== targetCount) {

        throw new FormatError(

          `${metadataTableNames[definition.targetTableId]} ownership does not cover every row exactly once`

        );

      }

      const currentOwnerByRid = new Map();

      for (let index = 0; index < ownerGroups.length; index++) {

        for (const rid of ownerGroups[index]) {

          currentOwnerByRid.set(rid, definition.owners[index].rid);

        }

      }

      const assignments = [];

      let offset = 0;

      const recordsByRid = new Map(

        definition.owners.flatMap((owner) =>

          owner[definition.records].map((record) => [record.rid, record])

        )

      );

      for (let index = 0; index < definition.owners.length; index++) {

        const owner = definition.owners[index];

        const oldGroup = ownerGroups[index];

        const nextGroup = newRids.slice(offset, offset + oldGroup.length);

        offset += oldGroup.length;

        const oldSet = new Set(oldGroup);

        const movesRowsAcrossOwners = nextGroup.some((rid) => !oldSet.has(rid));

        const allowsCrossOwnerRows = allowsCrossOwnerFields || allowsCrossOwnerMethods ||

          allowsCrossOwnerParameters || allowsCrossOwnerEvents || allowsCrossOwnerProperties;

        if (!allowsCrossOwnerRows && movesRowsAcrossOwners) {

          throw new UnsupportedFormatError("Pointer reordering cannot change row ownership");

        }

        const nextRecords = nextGroup.map((rid) => recordsByRid.get(rid));

        if (nextRecords.some((record) => !record)) {

          throw new FormatError(`${metadataTableNames[definition.targetTableId]} ownership has no semantic record`);

        }

        const movedRecords = nextRecords.filter((record) =>

          currentOwnerByRid.get(record.rid) !== owner.rid

        );

        if (allowsCrossOwnerFields) {

          for (const record of movedRecords) {

            const parsed = parseSignature(record.signature, { counts: this.tables.counts });

            if (parsed.kind !== "field") {

              throw new FormatError(`Field row ${record.rid} has a non-field signature`);

            }

            validateGenericVariableReferences(

              parsed,

              getGenericParameterArity(this.genericParams, 2, owner.rid),

              this

            );

            if ((this.tables.rows.get(16) ?? []).some((layout) =>

              layout.Field.rid === record.rid

            ) && (owner.flags & 0x0018) !== 0x0010) {

              throw new UnsupportedFormatError(

                `Field row ${record.rid} has an explicit offset and requires an explicit-layout owner`

              );

            }

          }

        }

        if (allowsCrossOwnerParameters && movesRowsAcrossOwners) {

          const signature = parseSignature(owner.signature, { counts: this.tables.counts });

          if (signature.kind !== "method") {

            throw new FormatError(`MethodDef row ${owner.rid} has a non-method signature`);

          }

          const sequences = new Set();

          for (const record of nextRecords) {

            if (!Number.isInteger(record.sequence) || record.sequence < 0 ||

                record.sequence > signature.parameters.length) {

              throw new FormatError(

                `Param row ${record.rid} sequence exceeds MethodDef row ${owner.rid}'s signature`

              );

            }

            if (sequences.has(record.sequence)) {

              throw new FormatError(

                `MethodDef row ${owner.rid} would have duplicate Param sequence ${record.sequence}`

              );

            }

            sequences.add(record.sequence);

          }

        }

        if (allowsCrossOwnerMethods && movesRowsAcrossOwners) {

          if ((owner.flags & (0x0080 | 0x0020)) === 0) {

            throw new UnsupportedFormatError(

              "Pointer reordering cannot move abstract methods to a non-abstract TypeDef"

            );

          }

          for (const record of movedRecords) {

            if (record.rva !== 0 || (record.flags & 0x0440) !== 0x0440 ||

                record.genericParams.length > 0) {

              throw new UnsupportedFormatError(

                "Cross-owner MethodPtr reordering supports only bodyless, non-generic abstract virtual methods"

              );

            }

            const signature = parseSignature(record.signature, { counts: this.tables.counts });

            if (signature.kind !== "method") {

              throw new FormatError(`MethodDef row ${record.rid} has a non-method signature`);

            }

            if ((signature.genericParameterCount ?? 0) > 0) {

              throw new UnsupportedFormatError(

                "Cross-owner MethodPtr reordering does not support generic methods"

              );

            }

            validateGenericVariableReferences(

              signature,

              getGenericParameterArity(this.genericParams, 2, owner.rid),

              this,

              null,

              signature.genericParameterCount ?? 0

            );

            const hasMethodSemantics = (this.tables.rows.get(24) ?? []).some((row) =>

              row.Method.rid === record.rid

            );

            const hasMethodImpl = (this.tables.rows.get(25) ?? []).some((row) =>

              row.MethodBody.target?.table === 6 && row.MethodBody.target.rid === record.rid ||

              row.MethodDeclaration.target?.table === 6 && row.MethodDeclaration.target.rid === record.rid

            );

            if (hasMethodSemantics || hasMethodImpl) {

              throw new UnsupportedFormatError(

                "Pointer reordering cannot change row ownership for methods with semantics or MethodImpl rows"

              );

            }

          }

        }

        if (allowsCrossOwnerEvents && movesRowsAcrossOwners) {

          for (const record of movedRecords) {

            const hasSemantics = (this.tables.rows.get(24) ?? []).some((row) =>

              row.Association.target?.table === 20 && row.Association.target.rid === record.rid

            );

            if (hasSemantics) {

              throw new UnsupportedFormatError(

                "Pointer reordering cannot change row ownership for events with MethodSemantics rows"

              );

            }

            if (record.eventType.table === 27) {

              const typeArity = getGenericParameterArity(this.genericParams, 2, owner.rid);

              const typeSpec = this.typeSpecs[record.eventType.rid - 1];

              if (!typeSpec) {

                throw new FormatError(`Event row ${record.rid} references missing TypeSpec row ${record.eventType.rid}`);

              }

              validateTypeSpecDefinitions(this, typeSpec.parsedSignature);

              validateTypeSpecGenericContext(this, record.eventType.rid, typeArity);

            }

          }

        }

        if (allowsCrossOwnerProperties && movesRowsAcrossOwners) {

          for (const record of movedRecords) {

            const hasSemantics = (this.tables.rows.get(24) ?? []).some((row) =>

              row.Association.target?.table === 23 && row.Association.target.rid === record.rid

            );

            if (hasSemantics) {

              throw new UnsupportedFormatError(

                "Pointer reordering cannot change row ownership for properties with MethodSemantics rows"

              );

            }

            const signature = parseSignature(record.signature, { counts: this.tables.counts });

            if (signature.kind !== "property") {

              throw new FormatError(`Property row ${record.rid} has a non-property signature`);

            }

            validateGenericVariableReferences(

              signature,

              getGenericParameterArity(this.genericParams, 2, owner.rid),

              this

            );

          }

        }

        assignments.push({ owner, nextGroup, nextRecords });

      }

      if (offset !== targetCount) {

        throw new FormatError(

          `${metadataTableNames[definition.targetTableId]} ownership does not cover every row exactly once`

        );

      }

      const nextPointerRows = newRids.map((rid, index) => ({

        ...pointerRows[index],

        rid: index + 1,

        [definition.column]: {

          raw: rid,

          table: definition.targetTableId,

          tableName: metadataTableNames[definition.targetTableId],

          rid

        }

      }));

      this.tables.rows.set(pointerTableId, nextPointerRows);

      for (const assignment of assignments) {

        assignment.owner[definition.list] = assignment.nextGroup;

        assignment.owner[definition.records] = assignment.nextRecords;

      }

      this._metadataDirty = true;

      return this;

  }
  };
}
