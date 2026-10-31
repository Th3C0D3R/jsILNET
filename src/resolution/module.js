import { FormatError } from "../binary/errors.js";

function listRids(tables, startRef, endRef, table, pointerTable) {
  const start = startRef?.rid ?? 0;
  const indexTable = startRef?.table === pointerTable ? pointerTable : table;
  const end = endRef?.rid ?? tables.counts[indexTable] + 1;
  if (start <= 0 || end < start) return [];
  if (startRef?.table === pointerTable) {
    const pointerRows = tables.get(pointerTable);
    return pointerRows.slice(start - 1, end - 1).map((row) => row[table === 4 ? "Field" :
      table === 6 ? "Method" : table === 8 ? "Param" : table === 20 ? "Event" : "Property"].rid);
  }
  return Array.from({ length: end - start }, (_, index) => start + index);
}

export function resolveTypes(metadata, heaps) {
  const typeDefs = metadata.get("TypeDef");
  const types = [];
  for (let index = 0; index < typeDefs.length; index++) {
    const row = typeDefs[index];
    const next = typeDefs[index + 1];
    types.push({
      rid: row.rid,
      flags: row.Flags,
      name: heaps.getString(row.TypeName),
      namespace: heaps.getString(row.TypeNamespace),
      extends: row.Extends.target,
      fieldRids: listRids(metadata, row.FieldList, next?.FieldList, 4, 3),
      methodRids: listRids(metadata, row.MethodList, next?.MethodList, 6, 5),
      eventRids: [],
      propertyRids: []
    });
  }
  const eventMaps = metadata.get("EventMap");
  const eventOwners = new Set();
  for (let index = 0; index < eventMaps.length; index++) {
    const row = eventMaps[index];
    const next = eventMaps[index + 1];
    const type = types[row.Parent.rid - 1];
    if (!type) throw new FormatError(`EventMap row ${row.rid} references a missing TypeDef`);
    if (eventOwners.has(type.rid)) throw new FormatError(`TypeDef row ${type.rid} has multiple EventMap rows`);
    eventOwners.add(type.rid);
    type.eventRids = listRids(metadata, row.EventList, next?.EventList, 20, 19);
  }
  const propertyMaps = metadata.get("PropertyMap");
  const propertyOwners = new Set();
  for (let index = 0; index < propertyMaps.length; index++) {
    const row = propertyMaps[index];
    const next = propertyMaps[index + 1];
    const type = types[row.Parent.rid - 1];
    if (!type) throw new FormatError(`PropertyMap row ${row.rid} references a missing TypeDef`);
    if (propertyOwners.has(type.rid)) throw new FormatError(`TypeDef row ${type.rid} has multiple PropertyMap rows`);
    propertyOwners.add(type.rid);
    type.propertyRids = listRids(metadata, row.PropertyList, next?.PropertyList, 23, 22);
  }
  return types;
}

export function resolveMethodParameters(metadata) {
  const methods = metadata.get("MethodDef");
  return methods.map((row, index) =>
    listRids(metadata, row.ParamList, methods[index + 1]?.ParamList, 8, 7)
  );
}
