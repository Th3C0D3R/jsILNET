import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const sourcePath = fileURLToPath(new URL("../src/index.js", import.meta.url));
const consumerPath = fileURLToPath(new URL("../type-tests/core-api.ts", import.meta.url));
const sourceText = readFileSync(sourcePath, "utf8");
const sourceFile = ts.createSourceFile(
  sourcePath,
  sourceText,
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.JS
);
const expectedExports = new Set();
let assemblyDeclaration;

for (const statement of sourceFile.statements) {
  if (ts.isExportDeclaration(statement) &&
      statement.exportClause &&
      ts.isNamedExports(statement.exportClause)) {
    for (const element of statement.exportClause.elements) {
      expectedExports.add(element.name.text);
    }
  } else if (statement.modifiers?.some((modifier) =>
    modifier.kind === ts.SyntaxKind.ExportKeyword
  )) {
    if (statement.name) expectedExports.add(statement.name.text);
    if (ts.isClassDeclaration(statement) && statement.name?.text === "Assembly") {
      assemblyDeclaration = statement;
    }
  }
}

if (!assemblyDeclaration) throw new Error("Could not find exported Assembly class");

const program = ts.createProgram([consumerPath], {
  module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
  strict: true,
  skipLibCheck: true,
  noEmit: true
});
const checker = program.getTypeChecker();
const consumer = program.getSourceFile(consumerPath);
const namespaceImport = consumer?.statements
  .filter(ts.isImportDeclaration)
  .find((declaration) =>
    ts.isStringLiteral(declaration.moduleSpecifier) &&
    declaration.moduleSpecifier.text === "jsilnet" &&
    declaration.importClause?.namedBindings &&
    ts.isNamespaceImport(declaration.importClause.namedBindings)
  )?.importClause?.namedBindings;

if (!namespaceImport || !ts.isNamespaceImport(namespaceImport)) {
  throw new Error('Type test must include `import * as api from "jsilnet"`');
}

const namespaceSymbol = checker.getSymbolAtLocation(namespaceImport.name);
const moduleSymbol = namespaceSymbol && checker.getAliasedSymbol(namespaceSymbol);
if (!moduleSymbol) throw new Error("Could not resolve the jsilnet declaration module");

const declaredExports = new Set(
  checker.getExportsOfModule(moduleSymbol).map((symbol) => symbol.name)
);
const missingExports = [...expectedExports].filter((name) => !declaredExports.has(name));
const assemblySymbol = checker.getExportsOfModule(moduleSymbol)
  .find((symbol) => symbol.name === "Assembly");
if (!assemblySymbol) missingExports.push("Assembly");

if (assemblySymbol) {
  const instanceType = checker.getDeclaredTypeOfSymbol(assemblySymbol);
  const declaredMethods = new Set(
    checker.getPropertiesOfType(instanceType).map((symbol) => symbol.name)
  );
  const missingMethods = [];
  for (const member of assemblyDeclaration.members) {
    if (!ts.isMethodDeclaration(member) || !member.name) continue;
    const name = member.name.getText(sourceFile);
    if (name.startsWith("#")) continue;
    const isStatic = member.modifiers?.some((modifier) =>
      modifier.kind === ts.SyntaxKind.StaticKeyword
    );
    if (isStatic) {
      const constructorType = checker.getTypeOfSymbolAtLocation(
        assemblySymbol,
        namespaceImport.name
      );
      if (!checker.getPropertyOfType(constructorType, name)) missingMethods.push(name);
    } else if (!declaredMethods.has(name)) {
      missingMethods.push(name);
    }
  }
  if (missingMethods.length > 0) {
    throw new Error(`Missing Assembly declarations: ${missingMethods.join(", ")}`);
  }
  const constructorType = checker.getTypeOfSymbolAtLocation(assemblySymbol, namespaceImport.name);
  if (checker.getSignaturesOfType(constructorType, ts.SignatureKind.Construct).length === 0) {
    throw new Error("Missing Assembly constructor declaration");
  }
}

if (missingExports.length > 0) {
  throw new Error(`Missing package declarations: ${missingExports.join(", ")}`);
}

console.log(
  `Type declarations cover ${expectedExports.size} package exports and all public Assembly methods.`
);
