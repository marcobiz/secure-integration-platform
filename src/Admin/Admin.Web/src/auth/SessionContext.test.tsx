import { cleanup, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { setUnauthorizedHandler } from '../api/client';
import { SessionProvider } from './SessionContext';

afterEach(() => {
  cleanup();
  setUnauthorizedHandler(undefined);
  vi.restoreAllMocks();
});

it('shows login after an unauthenticated session check without leaving a pending query', async () => {
  window.history.replaceState(null, '', '/admin/login');
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  cache.setQueryData(['dashboard'], { private: true });
  const request = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 401 }));

  render(<QueryClientProvider client={cache}><SessionProvider fallback={<div>Login required</div>}><div>Authenticated content</div></SessionProvider></QueryClientProvider>);

  expect(await screen.findByText('Login required')).toBeInTheDocument();
  expect(screen.queryByText('Authenticated content')).not.toBeInTheDocument();
  expect(cache.getQueryData(['dashboard'])).toBeUndefined();
  expect(request).toHaveBeenCalledOnce();
});
