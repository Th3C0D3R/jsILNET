const maxAssemblyBytes = 3 * 1024 * 1024;
const fileInput = document.querySelector("#assembly-file");
const inspectButton = document.querySelector("#inspect-button");
const status = document.querySelector("#status");
const results = document.querySelector("#results");
const summary = document.querySelector("#assembly-summary");
const typeCount = document.querySelector("#type-count");
const typeList = document.querySelector("#type-list");
const candidateSelect = document.querySelector("#candidate-select");
const editForm = document.querySelector("#edit-form");
const operandValue = document.querySelector("#operand-value");
const downloadButton = document.querySelector("#download-button");
const methodNote = document.querySelector("#method-note");

let candidates = [];

function setStatus(message, isError = false) {
  status.textContent = message;
  status.classList.toggle("error", isError);
}

function createSummaryItem(label, value) {
  const item = document.createElement("div");
  const heading = document.createElement("span");
  const content = document.createElement("strong");
  heading.textContent = label;
  content.textContent = value;
  item.append(heading, content);
  return item;
}

function selectedCandidate() {
  const index = Number(candidateSelect.value);
  return Number.isInteger(index) ? candidates[index] : null;
}

function updateSelectedCandidate() {
  const candidate = selectedCandidate();
  editForm.hidden = !candidate;
  if (!candidate) return;
  operandValue.value = String(candidate.currentValue === 127
    ? 126
    : candidate.currentValue + 1);
}

fileInput.addEventListener("change", () => {
  inspectButton.disabled = !fileInput.files?.length;
  results.hidden = true;
  candidates = [];
  editForm.hidden = true;
  setStatus(fileInput.files?.length ? "Ready to inspect." : "Choose a file to begin.");
});

inspectButton.addEventListener("click", async () => {
  const file = fileInput.files?.[0];
  if (!file) return;
  if (file.size === 0) {
    setStatus("Choose a non-empty assembly file.", true);
    return;
  }
  if (file.size > maxAssemblyBytes) {
    setStatus("Assemblies must be 3 MiB or smaller.", true);
    return;
  }

  inspectButton.disabled = true;
  fileInput.disabled = true;
  setStatus("Inspecting assembly...");
  try {
    const response = await fetch("/api/inspect", {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: file
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error ?? "Inspection failed.");
    renderAssembly(data);
    setStatus("Inspection complete.");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Inspection failed.", true);
  } finally {
    inspectButton.disabled = false;
    fileInput.disabled = false;
  }
});

function renderAssembly(data) {
  const module = data.module;
  summary.replaceChildren(
    createSummaryItem("Assembly", module?.assemblyName ?? module?.name ?? "Unknown"),
    createSummaryItem("Version", module?.version ?? "Not specified"),
    createSummaryItem("Types", String(data.counts.types)),
    createSummaryItem("Methods", String(data.counts.methods))
  );

  typeCount.textContent = data.counts.types > data.types.length
    ? `Showing ${data.types.length} of ${data.counts.types} types.`
    : `${data.types.length} types`;
  typeList.replaceChildren();
  for (const type of data.types) {
    const item = document.createElement("li");
    item.textContent = type.namespace ? `${type.namespace}.${type.name}` : type.name;
    typeList.append(item);
  }

  candidates = data.editCandidates;
  candidateSelect.replaceChildren();
  if (candidates.length === 0) {
    candidateSelect.add(new Option("No editable constants found", ""));
    candidateSelect.disabled = true;
    methodNote.textContent = "Try an assembly with an existing ldc.i4.s instruction.";
    editForm.hidden = true;
  } else {
    for (const [index, candidate] of candidates.entries()) {
      const label = `${candidate.declaringType}.${candidate.methodName} ` +
        `(RID ${candidate.methodRid}, IL_${candidate.instructionOffset.toString(16).padStart(4, "0")}, ` +
        `current value ${candidate.currentValue})`;
      candidateSelect.add(new Option(label, String(index)));
    }
    candidateSelect.disabled = false;
    methodNote.textContent = `Found ${candidates.length} editable method(s).`;
    candidateSelect.value = "0";
    updateSelectedCandidate();
  }

  if (data.truncatedMethods) {
    methodNote.textContent += ` Only the first ${data.scannedMethods} methods were scanned for edits.`;
  }
  results.hidden = false;
}

candidateSelect.addEventListener("change", updateSelectedCandidate);

editForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = fileInput.files?.[0];
  const candidate = selectedCandidate();
  const value = Number(operandValue.value);
  if (!file || !candidate || !Number.isInteger(value) || value < -128 || value > 127) {
    setStatus("Select a method and enter an integer from -128 to 127.", true);
    return;
  }

  const query = new URLSearchParams({
    methodRid: String(candidate.methodRid),
    offset: String(candidate.instructionOffset),
    value: String(value)
  });
  downloadButton.disabled = true;
  inspectButton.disabled = true;
  fileInput.disabled = true;
  candidateSelect.disabled = true;
  operandValue.disabled = true;
  setStatus("Patching and validating the assembly...");
  try {
    const response = await fetch(`/api/edit?${query}`, {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: file
    });
    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.error ?? "The assembly could not be edited.");
    }

    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = "edited-assembly.dll";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setStatus(`Patched ${candidate.methodName} to ${value}; the edited assembly was downloaded.`);
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "The assembly could not be edited.", true);
  } finally {
    downloadButton.disabled = false;
    inspectButton.disabled = false;
    fileInput.disabled = false;
    candidateSelect.disabled = false;
    operandValue.disabled = false;
  }
});
