import { Assembly, parseAssembly } from "../src/browser/index.js";
import type { BrowserAssembly } from "../src/browser/index.js";

async function checkBrowserApi(input: Uint8Array): Promise<BrowserAssembly> {
  const assembly = await parseAssembly(input);
  const sameAssembly: BrowserAssembly = await assembly.setInstructionOperand(1, 0, 1);
  const state = await sameAssembly.getState();
  state.modified satisfies boolean;
  await sameAssembly.parseCustomAttribute(7, {
    resolveEnum: async () => 0x08,
    resolveType: async (_name, context) => {
      await context.assembly.getState();
      return { assembly: sameAssembly, rid: 1 };
    }
  });
  await sameAssembly.serialize();
  sameAssembly.dispose();
  return Assembly.from(input);
}

void checkBrowserApi;
