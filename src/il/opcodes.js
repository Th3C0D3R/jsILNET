function descriptor(code, name, operand = "none", shortBranch = null, longBranch = null) {
  return { code, name, operand, shortBranch, longBranch };
}

const opcodes = new Map();
const add = (...args) => {
  const entry = descriptor(...args);
  opcodes.set(entry.code, entry);
};

add(0x00, "nop");
add(0x01, "break");
for (let i = 0; i < 4; i++) {
  add(0x02 + i, `ldarg.${i}`);
  add(0x06 + i, `ldloc.${i}`);
  add(0x0a + i, `stloc.${i}`);
}
add(0x0e, "ldarg.s", "u1");
add(0x0f, "ldarga.s", "u1");
add(0x10, "starg.s", "u1");
add(0x11, "ldloc.s", "u1");
add(0x12, "ldloca.s", "u1");
add(0x13, "stloc.s", "u1");
add(0x14, "ldnull");
add(0x15, "ldc.i4.m1");
for (let i = 0; i <= 8; i++) add(0x16 + i, `ldc.i4.${i}`);
add(0x1f, "ldc.i4.s", "i1");
add(0x20, "ldc.i4", "i4");
add(0x21, "ldc.i8", "i8");
add(0x22, "ldc.r4", "f4");
add(0x23, "ldc.r8", "f8");
add(0x25, "dup");
add(0x26, "pop");
add(0x27, "jmp", "token");
add(0x28, "call", "token");
add(0x29, "calli", "token");
add(0x2a, "ret");

const branchNames = ["br", "brfalse", "brtrue", "beq", "bge", "bgt", "ble", "blt", "bne.un", "bge.un", "bgt.un", "ble.un", "blt.un"];
for (let i = 0; i < branchNames.length; i++) {
  add(0x2b + i, `${branchNames[i]}.s`, "branch1", null, 0x38 + i);
  add(0x38 + i, branchNames[i], "branch4", 0x2b + i);
}
add(0x45, "switch", "switch");

const simpleNames = [
  "ldind.i1", "ldind.u1", "ldind.i2", "ldind.u2", "ldind.i4", "ldind.u4", "ldind.i8", "ldind.i",
  "ldind.r4", "ldind.r8", "ldind.ref", "stind.ref", "stind.i1", "stind.i2", "stind.i4", "stind.i8",
  "stind.r4", "stind.r8", "add", "sub", "mul", "div", "div.un", "rem", "rem.un", "and", "or", "xor",
  "shl", "shr", "shr.un", "neg", "not", "conv.i1", "conv.i2", "conv.i4", "conv.i8", "conv.r4",
  "conv.r8", "conv.u4", "conv.u8"
];
for (let i = 0; i < simpleNames.length; i++) add(0x46 + i, simpleNames[i]);

[
  [0x6f, "callvirt", "token"], [0x70, "cpobj", "token"], [0x71, "ldobj", "token"],
  [0x72, "ldstr", "token"], [0x73, "newobj", "token"], [0x74, "castclass", "token"],
  [0x75, "isinst", "token"], [0x76, "conv.r.un"], [0x79, "unbox", "token"],
  [0x7a, "throw"], [0x7b, "ldfld", "token"], [0x7c, "ldflda", "token"],
  [0x7d, "stfld", "token"], [0x7e, "ldsfld", "token"], [0x7f, "ldsflda", "token"],
  [0x80, "stsfld", "token"], [0x81, "stobj", "token"], [0x8c, "box", "token"],
  [0x8d, "newarr", "token"], [0x8e, "ldlen"], [0x8f, "ldelema", "token"],
  [0xa3, "ldelem", "token"], [0xa4, "stelem", "token"], [0xa5, "unbox.any", "token"],
  [0xc2, "refanyval", "token"], [0xc3, "ckfinite"], [0xc6, "mkrefany", "token"],
  [0xd0, "ldtoken", "token"], [0xdc, "endfinally"], [0xdd, "leave", "branch4", 0xde],
  [0xde, "leave.s", "branch1", null, 0xdd], [0xdf, "stind.i"], [0xe0, "conv.u"]
].forEach((item) => add(...item));

const conversionNames = [
  "conv.ovf.i1.un", "conv.ovf.i2.un", "conv.ovf.i4.un", "conv.ovf.i8.un", "conv.ovf.u1.un",
  "conv.ovf.u2.un", "conv.ovf.u4.un", "conv.ovf.u8.un", "conv.ovf.i.un", "conv.ovf.u.un"
];
for (let i = 0; i < conversionNames.length; i++) add(0x82 + i, conversionNames[i]);
for (let i = 0; i < 11; i++) add(0x90 + i, `ldelem.${["i1", "u1", "i2", "u2", "i4", "u4", "i8", "i", "r4", "r8", "ref"][i]}`);
for (let i = 0; i < 7; i++) add(0x9b + i, `stelem.${["i", "i1", "i2", "i4", "i8", "r4", "r8"][i]}`);
add(0xa2, "stelem.ref");
for (const [code, name] of [
  [0xb3, "conv.ovf.i1"], [0xb4, "conv.ovf.u1"], [0xb5, "conv.ovf.i2"], [0xb6, "conv.ovf.u2"],
  [0xb7, "conv.ovf.i4"], [0xb8, "conv.ovf.u4"], [0xb9, "conv.ovf.i8"], [0xba, "conv.ovf.u8"],
  [0xd1, "conv.i"], [0xd2, "conv.ovf.i"],
  [0xd3, "conv.ovf.u"], [0xd4, "add.ovf"], [0xd5, "add.ovf.un"], [0xd6, "mul.ovf"],
  [0xd7, "mul.ovf.un"], [0xd8, "sub.ovf"], [0xd9, "sub.ovf.un"]
]) add(code, name);

for (const [code, name, operand] of [
  [0xfe00, "arglist"], [0xfe01, "ceq"], [0xfe02, "cgt"], [0xfe03, "cgt.un"],
  [0xfe04, "clt"], [0xfe05, "clt.un"], [0xfe06, "ldftn", "token"], [0xfe07, "ldvirtftn", "token"],
  [0xfe09, "ldarg", "u2"], [0xfe0a, "ldarga", "u2"], [0xfe0b, "starg", "u2"],
  [0xfe0c, "ldloc", "u2"], [0xfe0d, "ldloca", "u2"], [0xfe0e, "stloc", "u2"],
  [0xfe0f, "localloc"], [0xfe11, "endfilter"], [0xfe12, "unaligned.", "u1"],
  [0xfe13, "volatile."], [0xfe14, "tail."], [0xfe15, "initobj", "token"],
  [0xfe16, "constrained.", "token"], [0xfe17, "cpblk"], [0xfe18, "initblk"],
  [0xfe1a, "rethrow"], [0xfe1c, "sizeof", "token"], [0xfe1d, "refanytype"], [0xfe1e, "readonly."]
]) add(code, name, operand ?? "none");

export function getOpcode(code) {
  return opcodes.get(code) ?? null;
}

export function listOpcodes() {
  return [...opcodes.values()];
}
