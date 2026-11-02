import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { POST as inspectHandler } from "../api/inspect.js";
import { POST as editHandler } from "../api/edit.js";

const fixture = new Uint8Array(
  await readFile(new URL("../../test/fixtures/Fixture.dll", import.meta.url))
);

function post(url, bytes, headers = {}) {
  return new Request(url, {
    method: "POST",
    headers: {
      "content-type": "application/octet-stream",
      ...headers
    },
    body: bytes
  });
}

test("inspect reports assembly metadata and editable signed-byte constants", async () => {
  const response = await inspectHandler(post("http://localhost/api/inspect", fixture));
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.module.assemblyName, "Fixture");
  assert.ok(result.counts.types > 0);
  assert.ok(result.counts.methods > 0);
  assert.ok(result.types.some((type) =>
    type.name === "Sample`1" && type.namespace === "JsILNET.Fixture"
  ));
  assert.ok(result.editCandidates.some((candidate) => candidate.methodName === "Answer"));
});

test("inspect rejects malformed assemblies with a client error", async () => {
  const response = await inspectHandler(
    post("http://localhost/api/inspect", Uint8Array.of(1, 2, 3))
  );
  assert.equal(response.status, 422);
  assert.match((await response.json()).error, /Could not parse/);
});

test("inspect enforces the upload-size limit from the content length", async () => {
  const response = await inspectHandler(
    post("http://localhost/api/inspect", Uint8Array.of(1), {
      "content-length": String(3 * 1024 * 1024 + 1)
    })
  );
  assert.equal(response.status, 413);
});

test("inspect enforces the upload-size limit while reading a streamed request", async () => {
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(3 * 1024 * 1024 + 1));
      controller.close();
    }
  });
  const request = new Request("http://localhost/api/inspect", {
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
    body,
    duplex: "half"
  });
  const response = await inspectHandler(request);
  assert.equal(response.status, 413);
});

test("edit changes the selected ldc.i4.s operand and returns a reparsable assembly", async () => {
  const inspectResponse = await inspectHandler(post("http://localhost/api/inspect", fixture));
  const { editCandidates } = await inspectResponse.json();
  const candidate = editCandidates.find((item) => item.methodName === "Answer");
  assert.ok(candidate);

  const url = new URL("http://localhost/api/edit");
  url.searchParams.set("methodRid", String(candidate.methodRid));
  url.searchParams.set("offset", String(candidate.instructionOffset));
  url.searchParams.set("value", "43");
  const response = await editHandler(post(url, fixture));
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-disposition"), /edited-assembly\.dll/);

  const output = new Uint8Array(await response.arrayBuffer());
  const verification = await inspectHandler(post("http://localhost/api/inspect", output));
  assert.equal(verification.status, 200);
  const result = await verification.json();
  assert.ok(result.editCandidates.some((item) =>
    item.methodName === "Answer" && item.currentValue === 43
  ));
});

test("edit rejects values outside the signed-byte range", async () => {
  const response = await editHandler(
    post("http://localhost/api/edit?methodRid=1&offset=0&value=128", fixture)
  );
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /between -128 and 127/);
});
