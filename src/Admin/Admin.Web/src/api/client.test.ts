import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, clearCsrf, csrf, setUnauthorizedHandler } from './client';

describe('administrative API authentication failures', () => {
  afterEach(() => {
    clearCsrf();
    setUnauthorizedHandler(undefined);
    vi.restoreAllMocks();
  });

  it('clears CSRF state and invalidates the authenticated UI on any 401', async () => {
    const unauthorized = vi.fn();
    setUnauthorizedHandler(unauthorized);
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ token: 'first-csrf' }))
      .mockResolvedValueOnce(json({ code: 'BGW-ADMIN-SESSION' }, 401))
      .mockResolvedValueOnce(json({ token: 'second-csrf' }))
      .mockResolvedValueOnce(json({ status: 'ok' }));

    expect(await csrf()).toBe('first-csrf');
    await expect(api('/admin/api/v1/dashboard')).rejects.toMatchObject({ status: 401, code: 'BGW-ADMIN-SESSION' });
    expect(unauthorized).toHaveBeenCalledOnce();
    await api('/admin/api/v1/test', { method: 'POST', body: '{}' });

    expect(fetchMock.mock.calls[2]?.[0]).toBe('/admin/auth/csrf');
    const mutationHeaders = new Headers((fetchMock.mock.calls[3]?.[1] as RequestInit).headers);
    expect(mutationHeaders.get('X-CSRF-TOKEN')).toBe('second-csrf');
  });

  it('keeps service outages distinct from unauthenticated responses', async () => {
    const unauthorized = vi.fn();
    setUnauthorizedHandler(unauthorized);
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ code: 'BGW-DEPENDENCY-UNAVAILABLE' }, 503));

    await expect(api('/admin/auth/me')).rejects.toEqual(expect.objectContaining({ status: 503, code: 'BGW-DEPENDENCY-UNAVAILABLE' }));
    expect(unauthorized).not.toHaveBeenCalled();
  });
});

function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
