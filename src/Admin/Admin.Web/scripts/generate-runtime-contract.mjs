import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath, URL } from 'node:url';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const contract = JSON.parse(await readFile(`${root}docs/api/runtime-wire-codes.json`, 'utf8'));
const kinds = ['status', 'health', 'approval', 'role', 'scope', 'auditAction', 'auditOutcome', 'reason'];
for (const kind of kinds) {
  if (!Array.isArray(contract[kind]) || contract[kind].some(value => typeof value !== 'string')) throw new Error(`Invalid runtime contract kind: ${kind}`);
  if (new Set(contract[kind]).size !== contract[kind].length) throw new Error(`Duplicate runtime contract code: ${kind}`);
}
const output = `// Generated from docs/api/runtime-wire-codes.json. Do not edit.\nexport const runtimeWireCodes = ${JSON.stringify(contract, null, 2)} as const;\n\nexport type RuntimeValueKind = keyof typeof runtimeWireCodes;\n`;
await writeFile(new URL('../src/i18n/runtimeContract.generated.ts', import.meta.url), output, 'utf8');
