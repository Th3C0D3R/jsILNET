import {
  DemoRequestError,
  errorResponse,
  parseUploadedAssembly,
  readAssemblyRequest
} from "../lib/request.js";

function parseInteger(value, name, minimum, maximum) {
  if (typeof value !== "string" || !/^-?\d+$/.test(value)) {
    throw new DemoRequestError(400, `${name} must be an integer.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new DemoRequestError(400, `${name} must be between ${minimum} and ${maximum}.`);
  }
  return parsed;
}

export async function POST(request) {
  try {
    const url = new URL(request.url);
    const methodRid = parseInteger(url.searchParams.get("methodRid"), "methodRid", 1, 0x00ffffff);
    const instructionOffset = parseInteger(
      url.searchParams.get("offset"),
      "offset",
      0,
      Number.MAX_SAFE_INTEGER
    );
    const value = parseInteger(url.searchParams.get("value"), "value", -128, 127);
    const bytes = await readAssemblyRequest(request);
    const assembly = parseUploadedAssembly(bytes);
    const method = assembly.methods.find((item) => item.rid === methodRid);
    if (!method) throw new DemoRequestError(400, "The selected method does not exist.");

    const instruction = assembly
      .getInstructions(methodRid)
      .find((item) => item.offset === instructionOffset);
    if (instruction?.opcode.name !== "ldc.i4.s") {
      throw new DemoRequestError(422, "The selected instruction is not an editable ldc.i4.s.");
    }

    try {
      assembly.setInstructionOperand(methodRid, instructionOffset, value);
    } catch (error) {
      if (error instanceof Error) throw new DemoRequestError(422, error.message);
      throw error;
    }

    const output = assembly.serialize();
    const reparsed = parseUploadedAssembly(output);
    const updated = reparsed
      .getInstructions(methodRid)
      .find((item) => item.offset === instructionOffset);
    if (updated?.opcode.name !== "ldc.i4.s" || updated.operand?.value !== value) {
      throw new Error("The edited operand did not survive serialization and reparsing.");
    }

    return new Response(output, {
      headers: {
        "content-type": "application/octet-stream",
        "content-disposition": 'attachment; filename="edited-assembly.dll"',
        "cache-control": "no-store"
      }
    });
  } catch (error) {
    return errorResponse(error);
  }
}
