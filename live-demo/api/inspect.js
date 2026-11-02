import {
  errorResponse,
  jsonResponse,
  parseUploadedAssembly,
  readAssemblyRequest
} from "../lib/request.js";

const maxListedTypes = 200;
const maxScannedMethods = 200;

export async function POST(request) {
  try {
    const bytes = await readAssemblyRequest(request);
    const assembly = parseUploadedAssembly(bytes);
    const typeByMethodRid = new Map();
    for (const type of assembly.types) {
      const fullName = type.namespace ? `${type.namespace}.${type.name}` : type.name;
      for (const methodRid of type.methodRids) typeByMethodRid.set(methodRid, fullName);
    }

    const methods = assembly.methods.slice(0, maxScannedMethods);
    const editCandidates = [];
    for (const method of methods) {
      if (method.rva === 0) continue;
      const instruction = assembly
        .getInstructions(method.rid)
        .find((item) => item.opcode.name === "ldc.i4.s");
      if (!instruction || !Number.isInteger(instruction.operand?.value)) continue;
      editCandidates.push({
        methodRid: method.rid,
        methodName: method.name,
        declaringType: typeByMethodRid.get(method.rid) ?? "(unknown type)",
        instructionOffset: instruction.offset,
        currentValue: instruction.operand.value
      });
    }

    return jsonResponse({
      module: assembly.module
        ? {
            name: assembly.module.name,
            assemblyName: assembly.module.assembly?.name ?? null,
            version: assembly.module.assembly?.version?.join(".") ?? null
          }
        : null,
      counts: {
        types: assembly.types.length,
        methods: assembly.methods.length
      },
      types: assembly.types
        .filter((type) => type.name !== "<Module>")
        .slice(0, maxListedTypes)
        .map((type) => ({
          rid: type.rid,
          name: type.name,
          namespace: type.namespace
        })),
      editCandidates,
      scannedMethods: methods.length,
      truncatedMethods: assembly.methods.length > methods.length
    });
  } catch (error) {
    return errorResponse(error);
  }
}
