import type { components } from './schema';

export type AdminSession = components['schemas']['AdminSession'];
export type Dashboard = components['schemas']['Dashboard'];
export type Tenant = components['schemas']['Tenant'];
type Page<T> = { items: T[]; offset: number; limit: number; total: number };
export type TenantPage = Page<Tenant>;
export type Application = components['schemas']['Application'];
export type ApplicationPage = Page<Application>;
export type EnvironmentPage = Page<components['schemas']['Environment']>;
export type InstallationPage = Page<components['schemas']['Installation']>;
export type GrantPage = Page<components['schemas']['Grant']>;
export type AuditPage = Page<components['schemas']['AuditEvent']>;
export type ConnectorSummary = components['schemas']['ConnectorSummary'];

export class ApiProblem extends Error {
  constructor(public readonly status: number, public readonly code: string, public readonly correlationId?: string) {
    super(code);
  }
}

let csrfToken: string | undefined;

async function parse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { code?: string; correlationId?: string };
    throw new ApiProblem(response.status, body.code ?? 'BGW-ADMIN-UNEXPECTED', body.correlationId);
  }
  return response.status === 204 ? undefined as T : await response.json() as T;
}

export async function csrf(): Promise<string> {
  const response = await fetch('/admin/auth/csrf', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  csrfToken = (await parse<{ token: string }>(response)).token;
  return csrfToken;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const mutation = !['GET', 'HEAD', 'OPTIONS'].includes(method);
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body) headers.set('Content-Type', 'application/json');
  if (mutation) headers.set('X-CSRF-TOKEN', csrfToken ?? await csrf());
  return parse<T>(await fetch(path, { ...init, headers, credentials: 'same-origin' }));
}

export const adminApi = {
  session: () => api<AdminSession>('/admin/auth/me'),
  dashboard: () => api<Dashboard>('/admin/api/v1/dashboard'),
  tenants: () => api<TenantPage>('/admin/api/v1/tenants'),
  applications: () => api<ApplicationPage>('/admin/api/v1/applications'),
  environments: () => api<EnvironmentPage>('/admin/api/v1/environments'),
  installations: (tenantId: string) => api<InstallationPage>(`/admin/api/v1/installations?tenantId=${encodeURIComponent(tenantId)}`),
  grants: (tenantId: string) => api<GrantPage>(`/admin/api/v1/grants?tenantId=${encodeURIComponent(tenantId)}`),
  audit: (tenantId: string) => api<AuditPage>(`/admin/api/v1/audit?tenantId=${encodeURIComponent(tenantId)}`),
  connectors: () => api<ConnectorSummary[]>('/admin/api/v1/connectors'),
  createTenant: (value: { code: string; displayName: string }) => api<Tenant>('/admin/api/v1/tenants', { method: 'POST', body: JSON.stringify(value) }),
  createApplication: (value: { code: string; displayName: string; minimumBrokerVersion: string }) => api<Application>('/admin/api/v1/applications', { method: 'POST', body: JSON.stringify(value) }),
  validateConnector: (definition: object) => api<{ valid: boolean; checksumSha256: string; errors: Array<{ code: string; path: string }> }>('/admin/api/v1/connectors:validate', { method: 'POST', body: JSON.stringify({ definition }) }),
  importConnector: (definition: object, expectedChecksumSha256: string) => api<Record<string, unknown>>('/admin/api/v1/connectors:import', { method: 'POST', body: JSON.stringify({ definition, expectedChecksumSha256 }) }),
  requestApproval: (id: string, version: string) => api<Record<string, unknown>>(`/admin/api/v1/connectors/${encodeURIComponent(id)}/versions/${encodeURIComponent(version)}/approval-requests`, { method: 'POST' }),
  approve: (id: string, version: string) => api<Record<string, unknown>>(`/admin/api/v1/connectors/${encodeURIComponent(id)}/versions/${encodeURIComponent(version)}/approvals`, { method: 'POST' }),
  logout: () => api<{ status: string }>('/admin/auth/logout', { method: 'POST' }),
  developmentLogin: (userName: string) => api<{ status: string }>('/admin/auth/development/login', { method: 'POST', body: JSON.stringify({ userName }) })
};
