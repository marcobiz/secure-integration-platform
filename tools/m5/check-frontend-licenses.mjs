import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'src', 'Admin', 'Admin.Web');
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
const allowed = new Set(['0BSD', 'Apache-2.0', 'BlueOak-1.0.0', 'BSD-2-Clause', 'BSD-3-Clause', 'CC-BY-4.0', 'CC0-1.0', 'ISC', 'MIT', 'MIT-0', 'MPL-2.0', 'Python-2.0']);
const failures = [];
for (const [path, entry] of Object.entries(lock.packages ?? {})) {
  if (!path || !path.startsWith('node_modules/')) continue;
  const manifestPath = join(root, path, 'package.json');
  const manifest = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : {};
  const license = String(entry.license ?? manifest.license ?? 'MISSING');
  const alternatives = license.replace(/[()]/g, '').split(/\s+OR\s+/);
  if (!alternatives.every(value => allowed.has(value))) failures.push(`${manifest.name ?? path}: ${license}`);
}
if (failures.length) {
  process.stderr.write(`Disallowed or missing frontend licenses:\n${failures.sort().join('\n')}\n`);
  process.exit(1);
}
process.stdout.write(`Frontend license scan passed for ${Object.keys(lock.packages).length - 1} locked packages.\n`);
