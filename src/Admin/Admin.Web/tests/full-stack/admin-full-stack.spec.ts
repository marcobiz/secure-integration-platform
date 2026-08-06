import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { execFile } from 'node:child_process';
import { createHash, createPrivateKey, randomBytes, randomUUID, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { promisify } from 'node:util';

type ApiResult<T> = { status: number; body: T; etag: string | null };
const execFileAsync = promisify(execFile);

async function login(context: BrowserContext, user: 'editor' | 'approver' | 'operator' | 'security-admin'): Promise<Page> {
  const baseUrl = process.env.M5_FULLSTACK_BASE_URL ?? 'https://localhost:8443/admin/';
  const csrfResponse = await context.request.get(new URL('auth/csrf', baseUrl).toString(), { headers: { Accept: 'application/json' } });
  expect(csrfResponse.status()).toBe(200);
  const csrf = await csrfResponse.json() as { token: string };
  const loginResponse = await context.request.post(new URL('auth/development/login', baseUrl).toString(), {
    headers: { Accept: 'application/json', 'X-CSRF-TOKEN': csrf.token },
    data: { userName: user }
  });
  expect(loginResponse.status()).toBe(200);
  const page = await context.newPage();
  await page.goto(baseUrl);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  return page;
}

async function api<T>(page: Page, path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}): Promise<ApiResult<T>> {
  return page.evaluate(async ({ path, method, body, headers }) => {
    const mutation = !['GET', 'HEAD', 'OPTIONS'].includes(method);
    if (mutation) {
      const csrfResponse = await fetch('/admin/auth/csrf', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      if (!csrfResponse.ok) throw new Error(`CSRF_${csrfResponse.status}`);
      const csrf = await csrfResponse.json() as { token: string };
      headers['X-CSRF-TOKEN'] = csrf.token;
    }
    const response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null, etag: response.headers.get('etag') };
  }, { path, method, body, headers });
}

async function invokeRuntime(connectorId: string, operationId: string, correlationId: string) {
  const target = `/v1/connectors/${encodeURIComponent(connectorId)}/operations/${encodeURIComponent(operationId)}:invoke`;
  const body = JSON.stringify({ protocolVersion: '1.0', payload: { contentType: 'application/json', encoding: 'base64', data: Buffer.from('{"synthetic":true}').toString('base64') }, correlationId });
  const timestamp = new Date().toISOString();
  const nonce = randomBytes(16).toString('base64url');
  const digest = createHash('sha256').update(body).digest('base64url');
  const privateKey = createPrivateKey(readFileSync(process.env.M5_FULLSTACK_CLIENT_KEY ?? '/m3-fixture/certificates/security-driver.key'));
  const signature = sign('sha256', Buffer.from(['BGW1', 'POST', target, timestamp, nonce, digest].join('\n')), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  const traceparent = `00-${correlationId.replaceAll('-', '')}-${randomBytes(8).toString('hex')}-01`;
  const baseUrl = process.env.M5_FULLSTACK_BASE_URL ?? 'https://localhost:8443/admin/';
  const response = await execFileAsync('curl', [
    '--silent', '--show-error', '--cacert', process.env.M5_FULLSTACK_CA_CERT ?? '/m3-fixture/certificates/ca.crt',
    '--cert', process.env.M5_FULLSTACK_CLIENT_CERT ?? '/m3-fixture/certificates/security-driver.crt',
    '--key', process.env.M5_FULLSTACK_CLIENT_KEY ?? '/m3-fixture/certificates/security-driver.key',
    '--request', 'POST', '--header', 'Content-Type: application/json', '--header', `X-BG-Timestamp: ${timestamp}`,
    '--header', `X-BG-Nonce: ${nonce}`, '--header', `X-BG-Content-SHA256: ${digest}`, '--header', `X-BG-Signature: ${signature}`,
    '--header', `traceparent: ${traceparent}`,
    '--data-binary', body, '--write-out', '\n%{http_code}', new URL(target, baseUrl).toString()
  ], { maxBuffer: 2 * 1024 * 1024 });
  const separator = response.stdout.lastIndexOf('\n');
  const text = response.stdout.slice(0, separator);
  return { status: Number(response.stdout.slice(separator + 1)), body: text ? JSON.parse(text) as Record<string, unknown> : {} };
}

test('FULLSTACK-01 production Admin build persists and governs the connector lifecycle', async ({ browser }) => {
  const editorContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const approverContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const securityContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const operatorContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const editor = await login(editorContext, 'editor');
  const approver = await login(approverContext, 'approver');
  const security = await login(securityContext, 'security-admin');
  const operator = await login(operatorContext, 'operator');
  const browserEvidence: { console: string[]; network: string[] } = { console: [], network: [] };
  for (const observed of [editor, approver, security, operator]) {
    observed.on('console', message => browserEvidence.console.push(message.text()));
    observed.on('response', async response => {
      const pathname = new URL(response.url()).pathname;
      if ((pathname.startsWith('/admin/api/') || pathname.startsWith('/v1/')) && browserEvidence.network.length < 500) browserEvidence.network.push(await response.text().catch(() => ''));
    });
  }

  const sample = await api<Record<string, unknown>>(editor, '/admin/api/v1/connectors/sample');
  expect(sample.status).toBe(200);
  const definition = structuredClone(sample.body);
  definition.version = '2.0.0';

  const validation = await api<{ valid: boolean; checksumSha256: string }>(editor, '/admin/api/v1/connectors:validate', 'POST', { definition });
  expect(validation.status).toBe(200);
  expect(validation.body.valid).toBe(true);
  const imported = await api<{ connectorId: string; version: string; rowVersion: number; state: string }>(editor, '/admin/api/v1/connectors:import', 'POST', { definition, expectedChecksumSha256: validation.body.checksumSha256 });
  expect(imported.status).toBe(201);
  expect(imported.body.state).toBe('Draft');
  const validated = await api<typeof imported.body>(editor, `/admin/api/v1/connectors/sample-secure-service/versions/2.0.0:validate`, 'POST', undefined, { 'If-Match': `"${imported.body.rowVersion}"` });
  expect(validated.status).toBe(200);
  expect(validated.body.state).toBe('Validated');

  const tenants = await api<{ items: Array<{ id: string }> }>(security, '/admin/api/v1/tenants?offset=0&limit=50');
  let tenantId: string | undefined;
  let enrolled: { id: string; status: string; environmentId: string } | undefined;
  for (const tenant of tenants.body.items) {
    const installations = await api<{ items: Array<{ id: string; status: string; environmentId: string }> }>(security, `/admin/api/v1/installations?tenantId=${tenant.id}&offset=0&limit=50`);
    const grants = await api<{ items: Array<{ installationId: string; connectorId: string; operationId: string }> }>(security, `/admin/api/v1/grants?tenantId=${tenant.id}&offset=0&limit=50`);
    for (const active of installations.body.items.filter(value => value.status === 'Active')) {
      const alreadyGranted = grants.body.items.some(value => value.installationId === active.id && value.connectorId === 'sample-secure-service' && value.operationId === 'submit');
      if (!alreadyGranted) {
        enrolled = active;
        tenantId = tenant.id;
        break;
      }
    }
    if (enrolled) break;
  }
  expect(tenantId, 'quick-start tenant containing an Active installation without the target grant must exist').toBeTruthy();
  expect(enrolled, 'quick-start challenge/PoP enrollment must persist an Active installation available for grant mutation').toBeTruthy();
  const environmentId = enrolled!.environmentId;
  expect(environmentId).toBeTruthy();
  const binding = await api<{ revision: number }>(security, '/admin/api/v1/connectors/sample-secure-service/bindings', 'PUT', {
    environmentId,
    connectorVersion: '2.0.0',
    endpoints: { 'sample-vendor-endpoint': 'https://vendor.m3.test:8443/' },
    secretReferences: { 'sample-vendor-api-key': 'synthetic-vault://vault.m3.test/vendor-api-key' },
    certificateReferences: { 'sample-vendor-client-certificate': 'synthetic-vault://vault.m3.test/vendor-client-certificate' }
  });
  expect(binding.status).toBe(200);
  expect(binding.body.revision).toBe(1);

  const requested = await api<{ id: string; status: string; bindingDigestSha256: string }>(editor, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0/approval-requests', 'POST');
  expect(requested.status).toBe(200);
  const review = await api<{ digestSha256: string; canonicalJson: string; artifact: { operations: Array<{ endpoint: { hostname: string; port: number; path: string; allowedMethods: string[] }; secretBindings: Array<{ providerId: string; resourceLogicalId: string }> }> } }>(approver, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0/approval-review');
  expect(review.status).toBe(200);
  expect(review.body.digestSha256).toBe(requested.body.bindingDigestSha256);
  expect(review.body.artifact.operations[0]).toMatchObject({ endpoint: { hostname: 'vendor.m3.test', port: 8443, path: '/vendor/orders', allowedMethods: ['POST'] }, secretBindings: [{ providerId: 'vault.m3.test', resourceLogicalId: 'vendor-api-key' }] });
  expect(review.body.canonicalJson).not.toMatch(/secretValue|privateKey|clientSecret|passwordValue|connectionString|SYNTHETIC-CANARY/i);
  const approvalBody = { approvalRequestId: requested.body.id, expectedDigestSha256: review.body.digestSha256 };
  const selfApproval = await api<{ code: string }>(editor, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0/approvals', 'POST', approvalBody);
  expect(selfApproval.status).toBe(403);
  expect(selfApproval.body.code).toMatch(/^BGW-/);
  const approved = await api<{ status: string }>(approver, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0/approvals', 'POST', approvalBody);
  expect(approved.status).toBe(200);

  const connectors = await api<{ items: Array<{ connectorId: string; publicationRevision: number }> }>(approver, '/admin/api/v1/connectors?offset=0&limit=50');
  const summary = connectors.body.items.find(value => value.connectorId === 'sample-secure-service');
  expect(summary).toBeTruthy();
  const published = await api<typeof validated.body>(approver, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0:publish', 'POST', { expectedRowVersion: validated.body.rowVersion, expectedPublicationRevision: summary!.publicationRevision }, { 'If-Match': `"${validated.body.rowVersion}"` });
  expect(published.status).toBe(200);
  expect(published.body.state).toBe('Published');

  const controlledTest = await api<{ status: string; connectorVersion: string }>(operator, '/admin/api/v1/connectors/sample-secure-service:test', 'POST', { environmentId, operationId: 'submit' });
  expect(controlledTest.status).toBe(200);
  expect(controlledTest.body).toMatchObject({ status: 'valid', connectorVersion: '2.0.0' });

  const grant = await api<Record<string, unknown>>(security, '/admin/api/v1/grants', 'POST', { tenantId, installationId: enrolled!.id, connectorId: 'sample-secure-service', operationId: 'submit' });
  expect(grant.status).toBe(201);

  const correlationId = randomUUID();
  const invoked = await invokeRuntime('sample-secure-service', 'submit', correlationId);
  expect(invoked.status, `runtime invoke failed with ${JSON.stringify(invoked.body)}`).toBe(200);
  expect(invoked.body.connectorVersion).toBe('2.0.0');
  const sanitized = JSON.stringify(invoked.body);
  expect(sanitized).not.toMatch(/api.?key|certificate|secret|synthetic-vault/i);

  const v2 = await api<typeof published.body>(security, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0');
  const retired = await api<typeof published.body>(security, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0:retire', 'POST', undefined, { 'If-Match': `"${v2.body.rowVersion}"` });
  expect(retired.status).toBe(200);
  expect(retired.body.state).toBe('Retired');
  const deniedAfterRetire = await invokeRuntime('sample-secure-service', 'submit', randomUUID());
  expect(deniedAfterRetire.status).not.toBe(200);
  const audit = await api<{ total: number; items: Array<{ correlationId: string; action: string }> }>(security, `/admin/api/v1/audit?tenantId=${tenantId}&offset=0&limit=100`);
  expect(audit.status).toBe(200);
  expect(audit.body.total).toBeGreaterThan(0);
  expect(audit.body.items).toContainEqual(expect.objectContaining({ correlationId, action: 'operation.invoke' }));

  await security.goto('./connectors');
  await expect(security.getByRole('heading', { name: 'Connectors' })).toBeVisible();
  const accessibility = await new AxeBuilder({ page: security }).analyze();
  expect(accessibility.violations.filter(value => ['critical', 'serious'].includes(value.impact ?? ''))).toEqual([]);

  const replayCookies = await editorContext.cookies();
  const logout = await api<{ status: string }>(editor, '/admin/auth/logout', 'POST');
  expect(logout.status).toBe(200);
  const replayContext = await browser.newContext({ ignoreHTTPSErrors: true });
  await replayContext.addCookies(replayCookies);
  const replay = await replayContext.request.get(new URL('/admin/auth/me', editor.url()).toString(), { headers: { Accept: 'application/json' }, maxRedirects: 0 });
  expect(replay.status()).toBe(401);

  writeFileSync('test-results/browser-redaction-surfaces.json', JSON.stringify({
    dom: await Promise.all([editor, approver, security, operator].map(value => value.locator('body').innerText())),
    console: browserEvidence.console,
    network: browserEvidence.network
  }));

  await Promise.all([editorContext.close(), approverContext.close(), securityContext.close(), operatorContext.close(), replayContext.close()]);
});
