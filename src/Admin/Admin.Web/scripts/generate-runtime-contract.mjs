import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, URL } from 'node:url';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const authoritativePath = `${root}src/Gateway/Gateway.Application/RuntimeWireCodes.cs`;
const contractPath = `${root}docs/api/runtime-wire-codes.json`;
const kinds = ['status', 'health', 'approval', 'role', 'scope', 'auditAction', 'auditOutcome', 'reason'];
const kindNames = Object.fromEntries(kinds.map(kind => [kind[0].toUpperCase() + kind.slice(1), kind]));

const authoritative = await readFile(authoritativePath, 'utf8');
const publishedBlock = authoritative.match(/\/\/ <runtime-wire:published>([\s\S]*?)\/\/ <\/runtime-wire:published>/)?.[1];
const reservedBlock = authoritative.match(/\/\/ <runtime-wire:reserved>([\s\S]*?)\/\/ <\/runtime-wire:reserved>/)?.[1];
if (!publishedBlock || !reservedBlock) throw new Error('Authoritative runtime wire catalog markers are missing.');

function parseEntries(block) {
  return [...block.matchAll(/new\(RuntimeWireCodeKind\.(\w+),\s*"([^"]+)"\)/g)].map(([, rawKind, value]) => {
    const kind = kindNames[rawKind];
    if (!kind) throw new Error(`Unknown authoritative runtime kind: ${rawKind}`);
    return { kind, value };
  });
}

const published = parseEntries(publishedBlock);
const reserved = parseEntries(reservedBlock);
const keys = values => new Set(values.map(value => `${value.kind}:${value.value}`));
const publishedKeys = keys(published);
if (publishedKeys.size !== published.length) throw new Error('Duplicate authoritative published runtime wire code.');
for (const entry of reserved) if (publishedKeys.has(`${entry.kind}:${entry.value}`)) throw new Error(`Reserved runtime wire code is also published: ${entry.value}`);

const backendFiles = [];
async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await collect(path);
    else if (entry.isFile() && entry.name.endsWith('.cs') && entry.name !== 'RuntimeWireCodes.cs') backendFiles.push(path);
  }
}
await collect(`${root}src/Gateway`);
const backend = (await Promise.all(backendFiles.sort().map(path => readFile(path, 'utf8')))).join('\n');

// Emission discovery is validation only. It never adds values to the authoritative catalog.
const emittedReasons = new Set([...backend.matchAll(/["'](BGW-[A-Z0-9-]+)["']/g)].map(match => match[1]));
const auditPrefixes = new Set(['admin', 'application', 'connector', 'grant', 'installation', 'operation', 'runtime', 'tenant']);
const emittedActions = new Set([...backend.matchAll(/["']([a-z]+(?:\.[a-z]+)+)["']/g)].map(match => match[1]).filter(value => auditPrefixes.has(value.split('.')[0])));
if (process.env.RUNTIME_WIRE_SYNTHETIC_BACKEND_CODE) emittedReasons.add(process.env.RUNTIME_WIRE_SYNTHETIC_BACKEND_CODE);

function assertExact(kind, emitted) {
  const expected = new Set(published.filter(value => value.kind === kind).map(value => value.value));
  const missing = [...emitted].filter(value => !expected.has(value));
  const stale = [...expected].filter(value => !emitted.has(value));
  if (missing.length || stale.length) throw new Error(`Runtime ${kind} catalog mismatch; unmapped emitted=[${missing.join(',')}], cataloged-not-emitted=[${stale.join(',')}]`);
}
assertExact('reason', emittedReasons);
assertExact('auditAction', emittedActions);

const contract = Object.fromEntries(kinds.map(kind => [kind, published.filter(value => value.kind === kind).map(value => value.value)]));
for (const kind of kinds) if (new Set(contract[kind]).size !== contract[kind].length) throw new Error(`Duplicate runtime contract code: ${kind}`);

const runtimeValues = await readFile(new URL('../src/i18n/runtimeValues.ts', import.meta.url), 'utf8');
const explicitWireValues = new Set([...runtimeValues.matchAll(/["']((?:BGW-[A-Z0-9-]+)|(?:[a-z]+(?:\.[a-z]+)+))["']\s*:/g)].map(match => match[1]));
const allPublishedValues = new Set(published.map(value => value.value));
const staleMappings = [...explicitWireValues].filter(value => !allPublishedValues.has(value));
if (staleMappings.length) throw new Error(`Frontend runtime mapping is not backend-cataloged: ${staleMappings.join(',')}`);

const translationKeys = new Set([...runtimeValues.matchAll(/:\s*["'](runtime\.[A-Za-z0-9]+)["']/g)].map(match => match[1]));
for (const language of ['en', 'it']) {
  const source = await readFile(new URL(`../src/i18n/${language}.ts`, import.meta.url), 'utf8');
  const available = new Set([...source.matchAll(/["'](runtime\.[A-Za-z0-9]+)["']\s*:/g)].map(match => match[1]));
  const missing = [...translationKeys].filter(key => !available.has(key));
  if (missing.length) throw new Error(`Missing ${language.toUpperCase()} runtime translations: ${missing.join(',')}`);
}

await writeFile(contractPath, `${JSON.stringify(contract, null, 2)}\n`, 'utf8');
const output = `// Generated from BackendRuntimeWireCodes. Do not edit.\nexport const runtimeWireCodes = ${JSON.stringify(contract, null, 2)} as const;\n\nexport type RuntimeValueKind = keyof typeof runtimeWireCodes;\n`;
await writeFile(new URL('../src/i18n/runtimeContract.generated.ts', import.meta.url), output, 'utf8');
