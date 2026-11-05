import { parseAssembly } from "jsilnet/browser";

const maxFileSize = 3 * 1024 * 1024;
const maxMethodsToScan = 200;
const maxCandidatesToDisplay = 100;

const fileInput = document.querySelector("#assembly-file");
const inspectButton = document.querySelector("#inspect-button");
const statusMessage = document.querySelector("#status");
const results = document.querySelector("#results");
const assemblySummary = document.querySelector("#assembly-summary");
const typeList = document.querySelector("#type-list");
const methodNote = document.querySelector("#method-note");
const candidateSelect = document.querySelector("#candidate-select");
const operandValue = document.querySelector("#operand-value");
const editForm = document.querySelector("#edit-form");

let currentAssembly = null;
let currentFile = null;
let candidates = [];

function setStatus(message) {
  statusMessage.textContent = message;
}

function disposeCurrentAssembly() {
  currentAssembly?.dispose();
  currentAssembly = null;
}

function formatCandidate(candidate) {
  return `${candidate.methodName} — IL_${candidate.offset.toString(16).padStart(4, "0")} ldc.i4.s ${candidate.currentValue}`;
}

function formatTypeName(type) {
  if (type.fullName) return type.fullName;
  return `${type.namespace ? `${type.namespace}.` : ""}${type.name ?? "Unknown type"}`;
}

function updateCandidateOptions() {
  candidateSelect.replaceChildren();

  for (const [index, candidate] of candidates.entries()) {
    const option = document.createElement("option");
    option.value = String(index);
    option.textContent = formatCandidate(candidate);
    candidateSelect.append(option);
  }

  if (candidates.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No editable constants found";
    candidateSelect.append(option);
  }

  editForm.hidden = candidates.length === 0;
  candidateSelect.disabled = candidates.length === 0;
  editForm.querySelector("button[type=submit]").disabled = candidates.length === 0;

  if (candidates.length > 0) {
    const candidate = candidates[0];
    operandValue.value = String(candidate.currentValue === 127 ? 126 : candidate.currentValue + 1);
  }
}

function renderAssembly(state, scannedMethodCount) {
  const moduleName = state.module?.assembly?.name ?? state.module?.name ?? "Unknown assembly";
  const version = state.module?.assembly?.version?.join(".") ?? "Unknown";
  const types = state.types ?? [];

  assemblySummary.replaceChildren();
  for (const [label, value] of [
    ["Name", moduleName],
    ["Version", version],
    ["Types", String(types.length)],
    ["Methods", String(state.methods?.length ?? 0)],
    ["Methods scanned", String(scannedMethodCount)],
  ]) {
    const item = document.createElement("div");
    const heading = document.createElement("span");
    const description = document.createElement("strong");
    heading.textContent = label;
    description.textContent = value;
    item.append(heading, description);
    assemblySummary.append(item);
  }

  typeList.replaceChildren();
  for (const type of types.slice(0, 100)) {
    const item = document.createElement("li");
    item.textContent = formatTypeName(type);
    typeList.append(item);
  }
  if (types.length > 100) {
    const item = document.createElement("li");
    item.textContent = `…and ${types.length - 100} more`;
    typeList.append(item);
  }

  methodNote.textContent =
    `Scanned up to the first ${maxMethodsToScan} methods; showing up to ${maxCandidatesToDisplay} editable instructions.`;
  results.hidden = false;
}

async function collectCandidates(assembly, state) {
  const methodNames = new Map();
  for (const type of state.types ?? []) {
    for (const methodRid of type.methodRids ?? []) {
      methodNames.set(methodRid, `${formatTypeName(type)}::`);
    }
  }

  const methods = (state.methods ?? []).slice(0, maxMethodsToScan);
  const found = [];
  let scannedMethodCount = 0;
  for (const method of methods) {
    scannedMethodCount++;
    if (!method.rva) continue;

    const instructions = await assembly.getInstructions(method.rid);
    for (const instruction of instructions) {
      if (instruction.opcode?.name !== "ldc.i4.s") continue;
      const value = instruction.operand?.value;
      if (!Number.isInteger(value) || value < -128 || value > 127) continue;

      found.push({
        methodRid: method.rid,
        methodName: `${methodNames.get(method.rid) ?? ""}${method.name}`,
        offset: instruction.offset,
        currentValue: value,
      });
      if (found.length >= maxCandidatesToDisplay) return { found, scannedMethodCount };
    }
  }

  return { found, scannedMethodCount };
}

fileInput.addEventListener("change", () => {
  disposeCurrentAssembly();
  currentFile = fileInput.files?.[0] ?? null;
  candidates = [];
  results.hidden = true;
  inspectButton.disabled = !currentFile;
  setStatus(currentFile ? "Ready to inspect locally in your browser." : "Choose an assembly to begin.");
});

inspectButton.addEventListener("click", async () => {
  const file = currentFile;
  if (!file) return;
  if (file.size > maxFileSize) {
    setStatus("The selected file is larger than the 3 MiB demo limit.");
    return;
  }

  disposeCurrentAssembly();
  candidates = [];
  inspectButton.disabled = true;
  fileInput.disabled = true;
  setStatus("Inspecting assembly in a background browser worker…");

  try {
    const assembly = await parseAssembly(file);
    currentAssembly = assembly;
    const state = await assembly.getState();
    const result = await collectCandidates(assembly, state);
    candidates = result.found;
    renderAssembly(state, result.scannedMethodCount);
    updateCandidateOptions();
    setStatus(
      `${file.name} was inspected locally. Found ${candidates.length} editable instruction${candidates.length === 1 ? "" : "s"}.`,
    );
  } catch (error) {
    disposeCurrentAssembly();
    results.hidden = true;
    setStatus(`Inspection failed: ${error.message}`);
  } finally {
    inspectButton.disabled = !currentFile;
    fileInput.disabled = false;
  }
});

candidateSelect.addEventListener("change", () => {
  const candidate = candidates[Number(candidateSelect.value)];
  if (!candidate) return;
  operandValue.value = String(candidate.currentValue === 127 ? 126 : candidate.currentValue + 1);
});

editForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const candidate = candidates[Number(candidateSelect.value)];
  const value = Number(operandValue.value);
  if (!currentAssembly || !currentFile || !candidate) {
    setStatus("Inspect an assembly and select an instruction before editing.");
    return;
  }
  if (!Number.isInteger(value) || value < -128 || value > 127) {
    setStatus("Enter a signed-byte value between -128 and 127.");
    return;
  }

  const submitButton = editForm.querySelector("button[type=submit]");
  submitButton.disabled = true;
  candidateSelect.disabled = true;
  operandValue.disabled = true;
  fileInput.disabled = true;
  setStatus("Editing and verifying the assembly in browser workers…");

  try {
    await currentAssembly.setInstructionOperand(candidate.methodRid, candidate.offset, value);
    const output = await currentAssembly.serialize();
    const verification = await parseAssembly(output);
    try {
      const instructions = await verification.getInstructions(candidate.methodRid);
      const editedInstruction = instructions.find((instruction) => instruction.offset === candidate.offset);
      if (editedInstruction?.operand?.value !== value) {
        throw new Error("The rewritten instruction did not contain the requested value.");
      }
    } finally {
      verification.dispose();
    }

    const url = URL.createObjectURL(new Blob([output], { type: "application/octet-stream" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `edited-${currentFile.name}`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);

    candidate.currentValue = value;
    const option = candidateSelect.options[Number(candidateSelect.value)];
    if (option) option.textContent = formatCandidate(candidate);
    setStatus(`Downloaded verified output for ${currentFile.name}. Processing stayed in your browser.`);
  } catch (error) {
    setStatus(`Edit failed: ${error.message}`);
  } finally {
    submitButton.disabled = candidates.length === 0;
    candidateSelect.disabled = candidates.length === 0;
    operandValue.disabled = false;
    fileInput.disabled = false;
  }
});
