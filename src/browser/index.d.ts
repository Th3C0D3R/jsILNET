import type { Assembly as NodeAssembly } from "../index.js";

type Browserify<T> = T extends NodeAssembly
  ? BrowserAssembly
  : T extends (...args: infer Args) => infer Result
    ? (...args: { [K in keyof Args]: Browserify<Args[K]> }) =>
      Browserify<Result> | Promise<Browserify<Result>>
    : T extends readonly unknown[]
      ? { [K in keyof T]: Browserify<T[K]> }
      : T extends object
        ? { [K in keyof T]: Browserify<T[K]> }
        : T;

type AsyncMethods<T> = {
  [K in keyof T as T[K] extends (...args: infer _Args) => unknown ? K : never]:
    T[K] extends (...args: infer Args) => infer Result
      ? (...args: { [I in keyof Args]: Browserify<Args[I]> }) => Promise<Browserify<Result>>
      : never;
};

type ResolverMethodName =
  | "parseCustomAttribute"
  | "parseDeclSecurity"
  | "replaceCustomAttribute"
  | "addCustomAttribute"
  | "insertCustomAttribute"
  | "addDeclSecurity"
  | "insertDeclSecurity"
  | "replaceDeclSecurity";

type MethodResult<K extends keyof NodeAssembly> =
  NodeAssembly[K] extends (...args: any[]) => infer Result
    ? Result extends NodeAssembly ? BrowserAssembly : Result
    : unknown;

export interface BrowserTypeResolverContext {
  assembly: BrowserAssembly;
  reference: { table: number; rid: number } | null;
  assemblyReference: unknown;
  assemblyIdentity: string | null;
}

export interface BrowserResolverOptions {
  resolveEnum?: (name: string) => number | undefined | Promise<number | undefined>;
  resolveType?: (
    name: string,
    context: BrowserTypeResolverContext
  ) =>
    | { assembly: BrowserAssembly; rid: number }
    | null
    | undefined
    | Promise<{ assembly: BrowserAssembly; rid: number } | null | undefined>;
}

export interface BrowserAssemblyState extends Readonly<Record<string, unknown>> {
  bytes: Uint8Array;
  modified: boolean;
}

export type BrowserAssembly = Omit<AsyncMethods<NodeAssembly>, ResolverMethodName> & {
  parseCustomAttribute(
    rid: number,
    options?: BrowserResolverOptions
  ): Promise<MethodResult<"parseCustomAttribute">>;
  parseDeclSecurity(
    rid: number,
    options?: BrowserResolverOptions
  ): Promise<MethodResult<"parseDeclSecurity">>;
  replaceCustomAttribute(
    rid: number,
    value: unknown,
    options?: BrowserResolverOptions
  ): Promise<MethodResult<"replaceCustomAttribute">>;
  addCustomAttribute(value: {
    parent: unknown;
    constructor: unknown;
    value: unknown;
  } & BrowserResolverOptions): Promise<MethodResult<"addCustomAttribute">>;
  insertCustomAttribute(value: {
    parent: unknown;
    constructor: unknown;
    value: unknown;
  } & BrowserResolverOptions): Promise<MethodResult<"insertCustomAttribute">>;
  addDeclSecurity(value: {
    parent: unknown;
    action: number;
    permissionSet: unknown;
  } & BrowserResolverOptions): Promise<MethodResult<"addDeclSecurity">>;
  insertDeclSecurity(value: {
    parent: unknown;
    action: number;
    permissionSet: unknown;
  } & BrowserResolverOptions): Promise<MethodResult<"insertDeclSecurity">>;
  replaceDeclSecurity(
    rid: number,
    value?: {
      action?: number;
      permissionSet?: unknown;
    } & BrowserResolverOptions
  ): Promise<MethodResult<"replaceDeclSecurity">>;
  getState(): Promise<BrowserAssemblyState>;
  callUtility(name: string, ...args: unknown[]): Promise<unknown>;
  dispose(): void;
};

export type Assembly = BrowserAssembly;

export declare const BrowserAssembly: {
  from(
    input: Uint8Array | ArrayBuffer | Blob,
    options?: { workerFactory?: () => Worker; transferInput?: boolean }
  ): Promise<BrowserAssembly>;
};

export declare const Assembly: typeof BrowserAssembly;

export declare function parseAssembly(
  input: Uint8Array | ArrayBuffer | Blob,
  options?: { workerFactory?: () => Worker; transferInput?: boolean }
): Promise<BrowserAssembly>;

export declare function callUtility(name: string, ...args: unknown[]): Promise<unknown>;
export { FormatError, UnsupportedFormatError } from "../index.js";
