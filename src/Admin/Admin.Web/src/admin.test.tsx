import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { ApiProblem, adminApi, api, csrf, type AdminSession } from './api/client';
import { hasRole } from './auth/SessionContext';
import { DataTable } from './components/DataTable';
import { ErrorState } from './components/AsyncState';
import i18n from './i18n';
import { hasTenantSecurityAdministratorRole, SafeFailureDiagnosticsCell } from './features/operations/TenantDataPage';

const session: AdminSession = { id: '00000000-0000-0000-0000-000000000001', displayName: 'Editor', roles: [{ role: 'ConnectorEditor', tenantId: null }] };

describe('Admin UI security and presentation behavior', () => {
  beforeEach(async () => { vi.restoreAllMocks(); localStorage.clear(); await i18n.changeLanguage('en'); });

  it('renders accessible table headings and data', () => {
    render(<DataTable rows={[{ name: 'Alpha' }]} label="Tenants" columns={[{ key: 'name', label: 'Name', render: row => row.name }]} />);
    expect(screen.getByRole('table', { name: 'Tenants' })).toBeInTheDocument(); expect(screen.getByRole('columnheader', { name: 'Name' })).toBeInTheDocument();
  });
  it('renders the empty state', () => { render(<DataTable rows={[]} label="Empty" columns={[]} />); expect(screen.getByText('No records found.')).toBeInTheDocument(); });
  it('enforces permission guards from server roles', () => { expect(hasRole(session, 'ConnectorEditor')).toBe(true); expect(hasRole(session, 'SecurityAdministrator')).toBe(false); });
  it('maps forbidden errors without internal details', () => { render(<ErrorState error={new ApiProblem(403, 'BGW-ADMIN-AUTHORIZATION', 'c-1')} />); expect(screen.getByText(/not authorized/i)).toBeInTheDocument(); expect(screen.getByText(/c-1/)).toBeInTheDocument(); });
  it('maps concurrency conflict errors', () => { render(<ErrorState error={new ApiProblem(409, 'BGW-CONCURRENCY', 'c-2')} />); expect(screen.getByText(/resource changed/i)).toBeInTheDocument(); });
  it('persists language as non-sensitive preference', async () => { await i18n.changeLanguage('it'); expect(i18n.t('save')).toBe('Salva'); });
  it('fetches and caches CSRF tokens', async () => { vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ token: 'synthetic-csrf' }), { status: 200, headers: { 'Content-Type': 'application/json' } }))); expect(await csrf()).toBe('synthetic-csrf'); });
  it('adds CSRF to mutating requests', async () => { const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ token: 't' }), { status: 200, headers: { 'Content-Type': 'application/json' } })).mockResolvedValueOnce(new Response(JSON.stringify({ token: 't' }), { status: 200, headers: { 'Content-Type': 'application/json' } })).mockResolvedValueOnce(new Response(JSON.stringify({ status: 'ok' }), { status: 200, headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetchMock); await csrf(); await api('/test', { method: 'POST', body: '{}' }); const headers = fetchMock.mock.calls[1][1].headers as Headers; expect(headers.get('X-CSRF-TOKEN')).toBe('t'); });
  it('never requests activation code when listing installations', async () => { const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], offset: 0, limit: 50, total: 0 }), { status: 200, headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetchMock); await adminApi.installations('tenant'); expect(String(fetchMock.mock.calls[0][0])).not.toContain('activation'); });
  it('sends ETag preconditions for connector transitions', async () => { const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({}), { status: 200, headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetchMock); await adminApi.retire('sample', { connectorId: 'sample', version: '1.0.0', schemaVersion: '1.0', state: 'Published', checksumSha256: 'A'.repeat(64), rowVersion: 7, createdAt: '2026-08-05T00:00:00Z' }); const headers = fetchMock.mock.calls.at(-1)?.[1].headers as Headers; expect(headers.get('If-Match')).toBe('"7"'); });
  it('controlled test accepts identifiers only and no arbitrary URL', async () => { const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ status: 'valid', connectorId: 'sample', operationId: 'submit', connectorVersion: '1.0.0' }), { status: 200, headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetchMock); await adminApi.testConnector('sample', '00000000-0000-0000-0000-000000000001', 'submit'); expect(String(fetchMock.mock.calls.at(-1)?.[1].body)).not.toContain('url'); });
  it('supports observable retry action', () => { const retry = vi.fn(); render(<ErrorState error={new Error('offline')} retry={retry} />); fireEvent.click(screen.getByRole('button', { name: 'Retry' })); expect(retry).toHaveBeenCalledOnce(); });
  it('renders only bounded safe failure diagnostics with Gateway and upstream status separated', () => {
    const { container } = render(<SafeFailureDiagnosticsCell gatewayStatus="BGW-EGRESS-UPSTREAM-REJECTED" diagnostics={{ failurePhase: 'LOCAL_RESPONSE_MAPPING_FAILURE', upstreamStatus: 200, statusCategory: 'SUCCESS', safeUpstreamCode: null, localSafeCode: 'FSE2_RESPONSE_INVALID' }} />);
    expect(screen.getByRole('region', { name: 'Safe failure diagnostics' })).toBeInTheDocument();
    expect(screen.getByText(/Gateway status: BGW-EGRESS-UPSTREAM-REJECTED/)).toBeInTheDocument();
    expect(screen.getByText(/Upstream status: 200/)).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/raw|header|token|certificate|exception|stack|retry|replay/i);
  });
  it('shows safe diagnostics only for a SecurityAdministrator authorized for the selected tenant', () => {
    const tenant = '00000000-0000-0000-0000-000000000042';
    expect(hasTenantSecurityAdministratorRole({ ...session, roles: [{ role: 'SecurityAdministrator', tenantId: null }] }, tenant)).toBe(true);
    expect(hasTenantSecurityAdministratorRole({ ...session, roles: [{ role: 'SecurityAdministrator', tenantId: tenant }] }, tenant)).toBe(true);
    expect(hasTenantSecurityAdministratorRole({ ...session, roles: [{ role: 'SecurityAdministrator', tenantId: '00000000-0000-0000-0000-000000000043' }] }, tenant)).toBe(false);
    expect(hasTenantSecurityAdministratorRole(session, tenant)).toBe(false);
  });
});
