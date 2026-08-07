import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, URL } from 'node:url';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const contractPath = `${root}docs/api/runtime-wire-codes.json`;
const contract = JSON.parse(await readFile(contractPath, 'utf8'));
const backendFiles = [];
async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await collect(path);
    else if (entry.isFile() && entry.name.endsWith('.cs')) backendFiles.push(path);
  }
}
await collect(`${root}src/Gateway`);
const backend = (await Promise.all(backendFiles.sort().map(path => readFile(path, 'utf8')))).join('\n');
const reasons = new Set([...backend.matchAll(/["'](BGW-[A-Z0-9-]+)["']/g)].map(match => match[1]));
const auditPrefixes = new Set(['admin', 'application', 'connector', 'grant', 'installation', 'operation', 'runtime', 'tenant']);
const actions = new Set([...backend.matchAll(/["']([a-z]+(?:\.[a-z]+)+)["']/g)].map(match => match[1]).filter(value => auditPrefixes.has(value.split('.')[0])));
contract.reason = [...reasons].sort();
contract.auditAction = [...actions].sort();
const kinds = ['status', 'health', 'approval', 'role', 'scope', 'auditAction', 'auditOutcome', 'reason'];
for (const kind of kinds) {
  if (!Array.isArray(contract[kind]) || contract[kind].some(value => typeof value !== 'string')) throw new Error(`Invalid runtime contract kind: ${kind}`);
  if (new Set(contract[kind]).size !== contract[kind].length) throw new Error(`Duplicate runtime contract code: ${kind}`);
}
await writeFile(contractPath, `${JSON.stringify(contract, null, 2)}\n`, 'utf8');
const output = `// Generated from backend-emitted codes through docs/api/runtime-wire-codes.json. Do not edit.\nexport const runtimeWireCodes = ${JSON.stringify(contract, null, 2)} as const;\n\nexport type RuntimeValueKind = keyof typeof runtimeWireCodes;\n`;
await writeFile(new URL('../src/i18n/runtimeContract.generated.ts', import.meta.url), output, 'utf8');
