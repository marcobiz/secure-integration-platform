/* global console, process, URL */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const result = spawnSync(process.execPath, [fileURLToPath(new URL('./generate-runtime-contract.mjs', import.meta.url))], {
  cwd: process.cwd(),
  encoding: 'utf8',
  env: { ...process.env, RUNTIME_WIRE_SYNTHETIC_BACKEND_CODE: 'BGW-SYNTHETIC-UNMAPPED' }
});
if (result.status === 0 || !`${result.stderr}${result.stdout}`.includes('BGW-SYNTHETIC-UNMAPPED')) {
  throw new Error('Runtime contract negative control did not reject an unmapped backend code.');
}
console.log('RUNTIME_WIRE_NEGATIVE_CONTROL_PASS');
