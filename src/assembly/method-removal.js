import { FormatError, UnsupportedFormatError } from "../binary/errors.js";
import { metadataTableSchemas, metadataTableNames } from "../metadata/tables.js";
import { encodeCodedIndex } from "../metadata/tables.js";
import { createOperandPatches } from "../writer/patch.js";
import { removeEmbeddedPortablePdbMethod as removePortablePdbMethod } from "../metadata/portable-pdb.js";

export function createMethodRemovalEditor(hooks) {
  const { getBijectivePointerRows } = hooks;
  return {
    removeMethod(rid) {
      hooks.ensureEditable();
      if (this._structuralBodies.size > 0) {
        throw new UnsupportedFormatError("Method removal cannot be combined with structural method edits");
      }
      const embeddedPdbIndices = this.pe.debugDirectoryEntries.flatMap((entry, index) =>
        entry.embeddedPortablePdb ? [index] : []
      );
      hooks.ensureTokenRemappingSafe("MethodDef", {
        allowEmbeddedPortablePdb: embeddedPdbIndices.length === 1
      });
      const rows = this.tables.rows.get(6) ?? [];
      if (rows.length !== this.tables.counts[6] || rows.length !== this.methods.length) {
        throw new FormatError("MethodDef row count is inconsistent with the metadata table header");
      }
      if (!Number.isInteger(rid) || rid < 1 || rid > rows.length) {
        throw new RangeError(`Invalid MethodDef row ID ${rid}`);
      }
      const cliEntryPointToken = this._cliEntryPointToken ?? this.cli.entryPointToken;
      const isManagedMethodEntryPoint =
        (this.cli.flags & 0x10) === 0 &&
        (cliEntryPointToken >>> 24) === 6;
      const cliEntryPointRid = cliEntryPointToken & 0x00ffffff;
      if (isManagedMethodEntryPoint &&
          (cliEntryPointRid === 0 || cliEntryPointRid > rows.length)) {
        throw new FormatError("CLI entry point references a missing MethodDef");
      }
      if (isManagedMethodEntryPoint && cliEntryPointRid === rid) {
        throw new FormatError(`MethodDef row ${rid} is the CLI entry point`);
      }
      const remappedCliEntryPointToken = isManagedMethodEntryPoint &&
        cliEntryPointRid > rid
        ? cliEntryPointToken - 1
        : cliEntryPointToken;
      const shiftsMethodRids = rid < rows.length;
      if (shiftsMethodRids && this._addedMethodBodies.size > 0) {
        throw new UnsupportedFormatError(
          "MethodDef RID remapping cannot be combined with added method bodies"
        );
      }
      const method = this.methods[rid - 1];
      if (method?.rid !== rid) throw new FormatError(`MethodDef row ${rid} has inconsistent semantic records`);
      const genericParamRows = this.tables.rows.get(42) ?? [];
      if (genericParamRows.length !== (this.tables.counts[42] ?? 0)) {
        throw new FormatError("GenericParam row count is inconsistent with the metadata table header");
      }
      const genericParamRids = new Set(method.genericParams.map((parameter) => parameter.rid));
      if (genericParamRids.size !== method.genericParams.length ||
          method.genericParams.length !== this.genericParams.filter(
            (parameter) => parameter.owner.table === 6 && parameter.owner.rid === rid
          ).length) {
        throw new FormatError(`MethodDef row ${rid} has inconsistent GenericParam ownership`);
      }
      if (genericParamRids.size > 0) {
        const sortedGenericParamRids = [...genericParamRids].sort((a, b) => a - b);
        const firstGenericParamRid = sortedGenericParamRids[0];
        if (firstGenericParamRid < 1 ||
            sortedGenericParamRids.some((parameterRid, index) =>
              parameterRid !== firstGenericParamRid + index
            ) || sortedGenericParamRids.at(-1) > genericParamRows.length) {
          throw new UnsupportedFormatError(
            "MethodDef removal requires its GenericParam rows to form a contiguous table range"
          );
        }
      }
      const genericParamConstraintRows = this.tables.rows.get(44) ?? [];
      if (genericParamConstraintRows.length !== (this.tables.counts[44] ?? 0) ||
          genericParamConstraintRows.length !== this.genericParamConstraints.length) {
        throw new FormatError("GenericParamConstraint row count is inconsistent with the metadata table header");
      }
      const genericParamConstraintRids = new Set(
        this.genericParamConstraints
          .filter((constraint) => genericParamRids.has(constraint.ownerRid))
          .map((constraint) => constraint.rid)
      );
      if (genericParamConstraintRids.size > 0) {
        for (const [tableId, tableRows] of this.tables.rows) {
          const schema = metadataTableSchemas[tableId];
          if (!schema) {
            throw new UnsupportedFormatError(
              `Cannot remove MethodDef row ${rid} with unknown metadata table ${tableId}`
            );
          }
          for (const row of tableRows) {
            if (tableId === 44 && genericParamConstraintRids.has(row.rid)) continue;
            for (const [kind, value, name] of schema) {
              const columnName = name ?? value;
              const column = row[columnName];
              const target = kind === "coded"
                ? column?.target
                : kind === "table" ? { table: value, rid: column?.rid } : null;
              if (target?.table === 44 && genericParamConstraintRids.has(target.rid)) {
                throw new FormatError(
                  `GenericParamConstraint row ${target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                  columnName === "Token" && row[columnName] >>> 24 === 44 &&
                  genericParamConstraintRids.has(row[columnName] & 0x00ffffff)) {
                throw new FormatError(
                  `GenericParamConstraint row ${row[columnName] & 0x00ffffff} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
            }
          }
        }
        for (const candidate of this.methods) {
          for (const instruction of this.getMethodBody(candidate.rid)?.instructions ?? []) {
            const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
            if ((token >>> 24) === 44 && genericParamConstraintRids.has(token & 0x00ffffff)) {
              throw new FormatError(
                `GenericParamConstraint row ${token & 0x00ffffff} is referenced by CIL in MethodDef row ${candidate.rid}`
              );
            }
          }
        }
      }
      const parameterRows = this.tables.rows.get(8) ?? [];
      if (parameterRows.length !== (this.tables.counts[8] ?? 0)) {
        throw new FormatError("Param row count is inconsistent with the metadata table header");
      }
      const parameterRids = new Set(method.parameterRids);
      if (method.parameterRids.length !== method.parameters.length ||
          parameterRids.size !== method.parameterRids.length) {
        throw new FormatError(`MethodDef row ${rid} has inconsistent Param ownership`);
      }
      if (parameterRids.size > 0) {
        const sortedParameterRids = [...parameterRids].sort((a, b) => a - b);
        const firstParameterRid = sortedParameterRids[0];
        if (firstParameterRid < 1 ||
            sortedParameterRids.some((parameterRid, index) => parameterRid !== firstParameterRid + index) ||
            sortedParameterRids.at(-1) > parameterRows.length) {
          throw new UnsupportedFormatError(
            "MethodDef removal requires its Param rows to form a contiguous table range"
          );
        }
      }
      const owners = this.types.filter((type) => type.methodRids.includes(rid));
      if (owners.length !== 1 || !owners[0].methods.some((candidate) => candidate.rid === rid)) {
        throw new FormatError(`MethodDef row ${rid} has no unique resolved TypeDef owner`);
      }
      const supportedStreams = new Set(["#~", "#-", "#Strings", "#US", "#GUID", "#Blob"]);
      for (const streamName of this.metadataRoot.streams.keys()) {
        if (!supportedStreams.has(streamName)) {
          throw new UnsupportedFormatError(
            `Cannot remove MethodDef row ${rid} with unrecognized metadata stream ${streamName}`
          );
        }
      }

      const paramPointerRows = parameterRids.size > 0
        ? getBijectivePointerRows(this, 7, 8, "Param")
        : null;
      if (parameterRids.size > 0 && (this.tables.valid & (1n << 7n)) !== 0n) {
        const pointerRids = paramPointerRows
          .filter((pointer) => parameterRids.has(pointer.Param.rid))
          .map((pointer) => pointer.rid);
        const firstPointerRid = Math.min(...pointerRids);
        if (pointerRids.length !== parameterRids.size ||
            [...pointerRids].sort((a, b) => a - b)
              .some((pointerRid, index) => pointerRid !== firstPointerRid + index)) {
          throw new UnsupportedFormatError(
            "MethodDef removal requires its ParamPtr rows to form a contiguous pointer range"
          );
        }
      }
      if (parameterRids.size > 0) {
        for (const [tableId, tableRows] of this.tables.rows) {
          const schema = metadataTableSchemas[tableId];
          if (!schema) {
            throw new UnsupportedFormatError(
              `Cannot remove MethodDef row ${rid} with unknown metadata table ${tableId}`
            );
          }
          for (const row of tableRows) {
            for (const [kind, value, name, pointer] of schema) {
              const columnName = name ?? value;
              if (kind === "coded" && row[columnName]?.target?.table === 8 &&
                  parameterRids.has(row[columnName].target.rid)) {
                throw new FormatError(
                  `Param row ${row[columnName].target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              if (kind === "table") {
                const targetTable = pointer !== undefined &&
                  (this.tables.valid & (1n << BigInt(pointer))) !== 0n ? pointer : value;
                if (targetTable !== 8 || (tableId === 6 && columnName === "ParamList") ||
                    (tableId === 7 && columnName === "Param")) continue;
                if (parameterRids.has(row[columnName]?.rid)) {
                  throw new FormatError(
                    `Param row ${row[columnName].rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                  );
                }
              }
              if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                  columnName === "Token" && row[columnName] >>> 24 === 8 &&
                  parameterRids.has(row[columnName] & 0x00ffffff)) {
                throw new FormatError(
                  `Param row ${row[columnName] & 0x00ffffff} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
            }
          }
        }
      }
      if (genericParamRids.size > 0) {
        for (const [tableId, tableRows] of this.tables.rows) {
          const schema = metadataTableSchemas[tableId];
          if (!schema) {
            throw new UnsupportedFormatError(
              `Cannot remove MethodDef row ${rid} with unknown metadata table ${tableId}`
            );
          }
          for (const row of tableRows) {
            if (tableId === 44 && genericParamConstraintRids.has(row.rid)) continue;
            for (const [kind, value, name] of schema) {
              const columnName = name ?? value;
              const column = row[columnName];
              const target = kind === "coded"
                ? column?.target
                : kind === "table" ? { table: value, rid: column?.rid } : null;
              if (target?.table === 42 && genericParamRids.has(target.rid)) {
                throw new FormatError(
                  `GenericParam row ${target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                  columnName === "Token" && row[columnName] >>> 24 === 42 &&
                  genericParamRids.has(row[columnName] & 0x00ffffff)) {
                throw new FormatError(
                  `GenericParam row ${row[columnName] & 0x00ffffff} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
            }
          }
        }
      }

      const pointerRows = getBijectivePointerRows(this, 5, 6, "Method");
      const pointerRid = pointerRows
        ? pointerRows.findIndex((pointer) => pointer.Method.rid === rid) + 1
        : 0;
      if (pointerRows && pointerRid === 0) {
        throw new FormatError(`MethodPtr has no pointer to MethodDef row ${rid}`);
      }
      const tokenMap = new Map();
      for (let oldRid = rid + 1; oldRid <= rows.length; oldRid++) {
        tokenMap.set(0x06000000 + oldRid, 0x06000000 + oldRid - 1);
      }
      const lastParameterRid = parameterRids.size > 0
        ? Math.max(...parameterRids)
        : 0;
      const remapParameterRid = (oldRid) =>
        oldRid > lastParameterRid ? oldRid - parameterRids.size : oldRid;
      if (parameterRids.size > 0) {
        for (let oldRid = lastParameterRid + 1; oldRid <= parameterRows.length; oldRid++) {
          tokenMap.set(0x08000000 + oldRid, 0x08000000 + remapParameterRid(oldRid));
        }
      }
      const lastGenericParamRid = genericParamRids.size > 0
        ? Math.max(...genericParamRids)
        : 0;
      const remapGenericParamRid = (oldRid) =>
        oldRid > lastGenericParamRid ? oldRid - genericParamRids.size : oldRid;
      if (genericParamRids.size > 0) {
        for (let oldRid = lastGenericParamRid + 1; oldRid <= genericParamRows.length; oldRid++) {
          tokenMap.set(0x2a000000 + oldRid, 0x2a000000 + remapGenericParamRid(oldRid));
        }
      }
      const remapGenericParamConstraintRid = (oldRid) => oldRid -
        [...genericParamConstraintRids].filter((constraintRid) => constraintRid < oldRid).length;
      if (genericParamConstraintRids.size > 0) {
        for (let oldRid = 1; oldRid <= genericParamConstraintRows.length; oldRid++) {
          if (genericParamConstraintRids.has(oldRid)) continue;
          tokenMap.set(
            0x2c000000 + oldRid,
            0x2c000000 + remapGenericParamConstraintRid(oldRid)
          );
        }
      }
      const rowChanges = [];
      for (const [tableId, tableRows] of this.tables.rows) {
        const schema = metadataTableSchemas[tableId];
        if (!schema) {
          throw new UnsupportedFormatError(
            `Cannot remove MethodDef row ${rid} with unknown metadata table ${tableId}`
          );
        }
        for (const row of tableRows) {
          if (tableId === 44 && genericParamConstraintRids.has(row.rid)) continue;
          for (const [kind, value, name, pointer] of schema) {
            const columnName = name ?? value;
            if (kind === "coded") {
              const target = row[columnName]?.target;
              if (target?.table === 44) {
                if (genericParamConstraintRids.has(target.rid)) {
                  throw new FormatError(
                    `GenericParamConstraint row ${target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                  );
                }
                const remappedRid = remapGenericParamConstraintRid(target.rid);
                if (remappedRid !== target.rid) {
                  const remappedTarget = { ...target, rid: remappedRid };
                  rowChanges.push({
                    row,
                    columnName,
                    value: {
                      raw: encodeCodedIndex(44, remappedRid, value),
                      target: remappedTarget
                    }
                  });
                }
                continue;
              }
              if (target?.table === 8 || target?.table === 42) {
                const removedRids = target.table === 8 ? parameterRids : genericParamRids;
                if (removedRids.has(target.rid)) {
                  throw new FormatError(
                    `${metadataTableNames[target.table]} row ${target.rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                  );
                }
                const remappedRid = target.table === 8
                  ? remapParameterRid(target.rid)
                  : remapGenericParamRid(target.rid);
                if (remappedRid !== target.rid) {
                  const remappedTarget = { ...target, rid: remappedRid };
                  rowChanges.push({
                    row,
                    columnName,
                    value: {
                      raw: encodeCodedIndex(target.table, remappedRid, value),
                      target: remappedTarget
                    }
                  });
                }
                continue;
              }
              if (target?.table !== 6) continue;
              if (tableId === 42 && columnName === "Owner" &&
                  genericParamRids.has(row.rid)) continue;
              if (target.rid === rid) {
                throw new FormatError(`MethodDef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
              }
              if (target.rid > rid) {
                const remappedTarget = { ...target, rid: target.rid - 1 };
                rowChanges.push({
                  row,
                  columnName,
                  value: {
                    raw: encodeCodedIndex(6, remappedTarget.rid, value),
                    target: remappedTarget
                  }
                });
              }
            } else if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                columnName === "Token" && [8, 42].includes(row[columnName] >>> 24)) {
              const tokenTable = row[columnName] >>> 24;
              const targetRid = row[columnName] & 0x00ffffff;
              const removedRids = tokenTable === 8 ? parameterRids : genericParamRids;
              if (removedRids.has(targetRid)) {
                throw new FormatError(
                  `${metadataTableNames[tokenTable]} row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              const remappedRid = tokenTable === 8
                ? remapParameterRid(targetRid)
                : remapGenericParamRid(targetRid);
              if (remappedRid !== targetRid) {
                rowChanges.push({
                  row,
                  columnName,
                  value: (tokenTable << 24) | remappedRid
                });
              }
            } else if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                columnName === "Token" && row[columnName] >>> 24 === 44) {
              const targetRid = row[columnName] & 0x00ffffff;
              if (genericParamConstraintRids.has(targetRid)) {
                throw new FormatError(
                  `GenericParamConstraint row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                );
              }
              const remappedRid = remapGenericParamConstraintRid(targetRid);
              if (remappedRid !== targetRid) {
                rowChanges.push({
                  row,
                  columnName,
                  value: 0x2c000000 | remappedRid
                });
              }
            } else if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                columnName === "Token" && row[columnName] >>> 24 === 6 &&
                (row[columnName] & 0x00ffffff) === rid) {
              throw new FormatError(`MethodDef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
            } else if (kind === "u4" && (tableId === 30 || tableId === 31) &&
                columnName === "Token" && row[columnName] >>> 24 === 6 &&
                (row[columnName] & 0x00ffffff) > rid) {
              const oldToken = row[columnName];
              rowChanges.push({ row, columnName, value: oldToken - 1 });
            } else if (kind === "table") {
              if (tableId === 2 && columnName === "MethodList") continue;
              const targetTable = pointer !== undefined &&
                (this.tables.valid & (1n << BigInt(pointer))) !== 0n ? pointer : value;
              const targetRid = row[columnName]?.rid;
              if (targetTable === 8) {
                if ((tableId === 6 && columnName === "ParamList") ||
                    (tableId === 7 && columnName === "Param")) continue;
                if (parameterRids.has(targetRid)) {
                  throw new FormatError(
                    `Param row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                  );
                }
                const remappedRid = remapParameterRid(targetRid);
                if (remappedRid !== targetRid) {
                  rowChanges.push({
                    row,
                    columnName,
                    value: { ...row[columnName], raw: remappedRid, rid: remappedRid }
                  });
                }
                continue;
              }
              if (targetTable === 42) {
                if (genericParamRids.has(targetRid)) {
                  throw new FormatError(
                    `GenericParam row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                  );
                }
                const remappedRid = remapGenericParamRid(targetRid);
                if (remappedRid !== targetRid) {
                  rowChanges.push({
                    row,
                    columnName,
                    value: { ...row[columnName], raw: remappedRid, rid: remappedRid }
                  });
                }
                continue;
              }
              if (targetTable === 44) {
                if (genericParamConstraintRids.has(targetRid)) {
                  throw new FormatError(
                    `GenericParamConstraint row ${targetRid} is referenced by ${metadataTableNames[tableId]}.${columnName}`
                  );
                }
                const remappedRid = remapGenericParamConstraintRid(targetRid);
                if (remappedRid !== targetRid) {
                  rowChanges.push({
                    row,
                    columnName,
                    value: { ...row[columnName], raw: remappedRid, rid: remappedRid }
                  });
                }
                continue;
              }
              if (targetTable !== 6) continue;
              if (tableId === 5 && columnName === "Method") {
                if (row.rid === pointerRid) continue;
                if (targetRid === rid) {
                  throw new FormatError(`MethodDef row ${rid} is referenced by MethodPtr.Method`);
                }
                continue;
              }
              if (targetRid === rid) {
                throw new FormatError(`MethodDef row ${rid} is referenced by ${metadataTableNames[tableId]}.${columnName}`);
              }
              if (targetRid > rid) {
                rowChanges.push({
                  row,
                  columnName,
                  value: { ...row[columnName], raw: targetRid - 1, rid: targetRid - 1 }
                });
              }
            }
          }
        }
      }
      const tokenUpdates = [];
      const patches = [];
      for (const candidate of this.methods) {
        if (candidate.rid === rid) continue;
        const body = this.getMethodBody(candidate.rid);
        for (const instruction of body?.instructions ?? []) {
          const token = instruction.operand?.kind === "token" ? instruction.operand.value : 0;
          if ((token >>> 24) !== 6) continue;
          const targetRid = token & 0x00ffffff;
          if (targetRid === rid) {
            throw new FormatError(`MethodDef row ${rid} is referenced by CIL in MethodDef row ${candidate.rid}`);
          }
          if (targetRid > rid) {
            const replacement = token - 1;
            tokenUpdates.push({ instruction, replacement });
            patches.push(...createOperandPatches(instruction, replacement));
          }
        }
      }
      const sortedKeyColumns = new Map([
        [10, "Class"], [11, "Parent"], [12, "Parent"], [13, "Parent"], [14, "Parent"],
        [28, "MemberForwarded"], [42, "Owner"], [43, "Method"]
      ]);
      const changedSortedKeys = new Map(rowChanges
        .filter((change) => [...sortedKeyColumns.values()].includes(change.columnName))
        .map((change) => [change.row, change.value]));
      for (const [tableId, keyOf] of [
        [10, (row) => [row.Class.raw]],
        [11, (row) => [row.Parent.raw]],
        [12, (row) => [row.Parent.raw]],
        [13, (row) => [row.Parent.raw]],
        [14, (row) => [row.Parent.raw, row.Action]],
        [28, (row) => [row.MemberForwarded.raw]],
        [42, (row) => [row.Owner.raw, row.Number]],
        [43, (row) => [row.Method.raw]]
      ]) {
        if ((this.tables.sorted & (1n << BigInt(tableId))) === 0n) continue;
        let previous = null;
        for (const row of this.tables.get(tableId)) {
          const changedKey = changedSortedKeys.get(row);
          const current = keyOf(row);
          if (changedKey) current[0] = changedKey.raw ?? changedKey;
          let outOfOrder = false;
          if (previous) {
            for (let index = 0; index < current.length; index++) {
              if (current[index] === previous[index]) continue;
              outOfOrder = current[index] < previous[index];
              break;
            }
          }
          if (outOfOrder) {
            throw new FormatError(
              `MethodDef token remapping would violate sorted ${metadataTableNames[tableId]} order`
            );
          }
          previous = current;
        }
      }

      const methodPointerPresent = pointerRows !== null;
      if (embeddedPdbIndices.length === 1) {
        const updatedCounts = [...this.tables.counts];
        updatedCounts[6]--;
        if (methodPointerPresent) updatedCounts[5]--;
        if (parameterRids.size > 0) {
          updatedCounts[8] -= parameterRids.size;
          if (paramPointerRows) updatedCounts[7] -= parameterRids.size;
        }
        if (genericParamRids.size > 0) updatedCounts[42] -= genericParamRids.size;
        if (genericParamConstraintRids.size > 0) {
          updatedCounts[44] -= genericParamConstraintRids.size;
        }
        const debugEntryIndex = embeddedPdbIndices[0];
        const debugEntry = this.pe.debugDirectoryEntries[debugEntryIndex];
        const pdb = hooks.getPortablePdbForEdit(debugEntryIndex, debugEntry);
        const updatedPdb = removePortablePdbMethod(
          pdb,
          rid,
          this.tables.counts,
          updatedCounts
        );
        hooks.replaceEmbeddedPortablePdb(debugEntryIndex, updatedPdb, updatedCounts);
      }
      if (remappedCliEntryPointToken !== cliEntryPointToken) {
        const entryPointBytes = new Uint8Array(4);
        new DataView(entryPointBytes.buffer).setUint32(0, remappedCliEntryPointToken, true);
        patches.push({
          offset: this.cli.offset + 20,
          bytes: entryPointBytes
        });
        this._cliEntryPointToken = remappedCliEntryPointToken;
      }
      if (methodPointerPresent) {
        const remainingPointers = pointerRows.filter((pointer) => pointer.rid !== pointerRid);
        remainingPointers.forEach((pointer, index) => {
          pointer.rid = index + 1;
          if (pointer.Method.rid > rid) {
            pointer.Method = {
              ...pointer.Method,
              raw: pointer.Method.rid - 1,
              rid: pointer.Method.rid - 1
            };
          }
        });
        this.tables.rows.set(5, remainingPointers);
        this.tables.counts[5] = remainingPointers.length;
        if (remainingPointers.length === 0) this.tables.valid &= ~(1n << 5n);
      }
      const listBoundary = methodPointerPresent ? pointerRid : rid;
      const listChanges = [];
      for (const typeRow of this.tables.rows.get(2) ?? []) {
        if (typeRow.MethodList.rid > listBoundary) {
          listChanges.push({
            row: typeRow,
            value: {
              ...typeRow.MethodList,
              raw: typeRow.MethodList.rid - 1,
              rid: typeRow.MethodList.rid - 1
            }
          });
        }
      }
      const removedParamListPositions = paramPointerRows
        ? paramPointerRows.filter((pointer) => parameterRids.has(pointer.Param.rid))
          .map((pointer) => pointer.rid)
        : [...parameterRids];
      const paramListChanges = [];
      if (removedParamListPositions.length > 0) {
        for (const methodRow of this.tables.get(6)) {
          const oldBoundary = methodRow.ParamList.rid;
          const newBoundary = oldBoundary -
            removedParamListPositions.filter((position) => position < oldBoundary).length;
          if (newBoundary === oldBoundary) continue;
          paramListChanges.push({
            row: methodRow,
            value: {
              ...methodRow.ParamList,
              raw: newBoundary,
              rid: newBoundary
            }
          });
        }
      }
      for (const change of rowChanges) change.row[change.columnName] = change.value;
      for (const change of listChanges) change.row.MethodList = change.value;
      for (const change of paramListChanges) change.row.ParamList = change.value;
      for (const update of tokenUpdates) update.instruction.operand.value = update.replacement;
      this._patches.push(...patches);
      if (parameterRids.size > 0) {
        const remainingParams = parameterRows.filter((parameter) => !parameterRids.has(parameter.rid));
        remainingParams.forEach((parameter) => {
          parameter.rid = remapParameterRid(parameter.rid);
        });
        this.tables.rows.set(8, remainingParams);
        this.tables.counts[8] = remainingParams.length;
        if (remainingParams.length === 0) this.tables.valid &= ~(1n << 8n);
        if (paramPointerRows) {
          const remainingParamPointers = paramPointerRows.filter((pointer) =>
            !parameterRids.has(pointer.Param.rid)
          );
          remainingParamPointers.forEach((pointer, index) => {
            pointer.rid = index + 1;
            const remappedRid = remapParameterRid(pointer.Param.rid);
            if (remappedRid !== pointer.Param.rid) {
              pointer.Param = {
                ...pointer.Param,
                raw: remappedRid,
                rid: remappedRid
              };
            }
          });
          this.tables.rows.set(7, remainingParamPointers);
          this.tables.counts[7] = remainingParamPointers.length;
          if (remainingParamPointers.length === 0) this.tables.valid &= ~(1n << 7n);
        }
        for (const candidate of this.methods) {
          candidate.parameterRids = candidate.parameterRids
            .filter((parameterRid) => !parameterRids.has(parameterRid))
            .map(remapParameterRid);
          candidate.parameters = candidate.parameters
            .filter((parameter) => !parameterRids.has(parameter.rid))
            .map((parameter) => {
              parameter.rid = remapParameterRid(parameter.rid);
              return parameter;
            });
        }
      }
      if (genericParamRids.size > 0) {
        const remainingGenericParams = genericParamRows.filter((parameter) =>
          !genericParamRids.has(parameter.rid)
        );
        remainingGenericParams.forEach((parameter) => {
          parameter.rid = remapGenericParamRid(parameter.rid);
        });
        this.tables.rows.set(42, remainingGenericParams);
        this.tables.counts[42] = remainingGenericParams.length;
        if (remainingGenericParams.length === 0) this.tables.valid &= ~(1n << 42n);
        this.genericParams = this.genericParams.filter((parameter) =>
          !genericParamRids.has(parameter.rid)
        );
        for (const parameter of this.genericParams) {
          parameter.rid = remapGenericParamRid(parameter.rid);
        }
        for (const constraint of this.genericParamConstraints) {
          constraint.ownerRid = remapGenericParamRid(constraint.ownerRid);
        }
      }
      if (genericParamConstraintRids.size > 0) {
        const remainingConstraints = this.genericParamConstraints.filter((constraint) =>
          !genericParamConstraintRids.has(constraint.rid)
        );
        remainingConstraints.forEach((constraint) => {
          constraint.rid = remapGenericParamConstraintRid(constraint.rid);
        });
        this.genericParamConstraints.splice(
          0,
          this.genericParamConstraints.length,
          ...remainingConstraints
        );
        const remainingConstraintRows = genericParamConstraintRows.filter((constraint) =>
          !genericParamConstraintRids.has(constraint.rid)
        );
        remainingConstraintRows.forEach((constraint) => {
          constraint.rid = remapGenericParamConstraintRid(constraint.rid);
        });
        this.tables.rows.set(44, remainingConstraintRows);
        this.tables.counts[44] = remainingConstraintRows.length;
        if (remainingConstraintRows.length === 0) this.tables.valid &= ~(1n << 44n);
      }
      if (parameterRids.size > 0 || genericParamRids.size > 0) {
        for (const attribute of this.customAttributes) {
          if (attribute.parent?.table === 8 && !parameterRids.has(attribute.parent.rid)) {
            attribute.parent = {
              ...attribute.parent,
              rid: remapParameterRid(attribute.parent.rid)
            };
          } else if (attribute.parent?.table === 42 &&
              !genericParamRids.has(attribute.parent.rid)) {
            attribute.parent = {
              ...attribute.parent,
              rid: remapGenericParamRid(attribute.parent.rid)
            };
          } else if (attribute.parent?.table === 44 &&
              !genericParamConstraintRids.has(attribute.parent.rid)) {
            attribute.parent = {
              ...attribute.parent,
              rid: remapGenericParamConstraintRid(attribute.parent.rid)
            };
          }
        }
      }
      const remainingRows = rows.filter((row) => row.rid !== rid);
      remainingRows.forEach((row, index) => {
        row.rid = index + 1;
      });
      this.tables.rows.set(6, remainingRows);
      this.tables.counts[6] = remainingRows.length;
      if (remainingRows.length === 0) this.tables.valid &= ~(1n << 6n);
      for (const type of this.types) {
        type.methodRids = type.methodRids
          .filter((methodRid) => methodRid !== rid)
          .map((methodRid) => methodRid > rid ? methodRid - 1 : methodRid);
        type.methods = type.methods.filter((candidate) => candidate.rid !== rid);
        for (const candidate of type.methods) {
          if (candidate.rid > rid) candidate.rid--;
        }
      }
      this.methods.splice(rid - 1, 1);
      this.methods.forEach((candidate, index) => {
        candidate.rid = index + 1;
      });
      for (const parameter of this.genericParams) {
        if (parameter.owner.table === 6 && parameter.owner.rid > rid) {
          parameter.owner = { ...parameter.owner, rid: parameter.owner.rid - 1 };
        }
      }
      for (const memberRef of this.memberRefs) {
        if (memberRef.parent?.table === 6 && memberRef.parent.rid > rid) {
          memberRef.parent = { ...memberRef.parent, rid: memberRef.parent.rid - 1 };
        }
      }
      for (const methodSpec of this.methodSpecs) {
        if (methodSpec.method?.table === 6 && methodSpec.method.rid > rid) {
          methodSpec.method = { ...methodSpec.method, rid: methodSpec.method.rid - 1 };
        }
      }
      for (const attribute of this.customAttributes) {
        if (attribute.parent?.table === 6 && attribute.parent.rid > rid) {
          attribute.parent = { ...attribute.parent, rid: attribute.parent.rid - 1 };
        }
      }
      const remappedBodyCache = new Map();
      for (const [methodRid, body] of this._bodyCache) {
        if (methodRid === rid) continue;
        remappedBodyCache.set(methodRid > rid ? methodRid - 1 : methodRid, body);
      }
      this._bodyCache = remappedBodyCache;
      this._addedMethodBodies.delete(rid);
      this._bodyCache.delete(rid);
      this._metadataDirty = true;
      return tokenMap;
  }
  };
}
