import { createContext, useContext, useEffect, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { adminApi, ApiProblem, clearCsrf, setUnauthorizedHandler, type AdminSession } from '../api/client';
import { ErrorState, LoadingState } from '../components/AsyncState';

const SessionContext = createContext<AdminSession | null>(null);
export function SessionProvider({ children, fallback }: { children: ReactNode; fallback: ReactNode }) {
  const cache = useQueryClient();
  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearCsrf();
      cache.clear();
      if (!window.location.pathname.startsWith('/admin/login')) window.location.assign('/admin/login');
    });
    return () => setUnauthorizedHandler(undefined);
  }, [cache]);
  const query = useQuery({ queryKey: ['session'], queryFn: adminApi.session, retry: (count, error) => !(error instanceof ApiProblem && error.status === 401) && count < 2, staleTime: 30_000 });
  if (query.isPending) return <LoadingState />;
  if (query.error instanceof ApiProblem && query.error.status === 401) return fallback;
  if (query.error) return <ErrorState error={query.error} retry={() => void query.refetch()} />;
  if (!query.data) return <LoadingState />;
  return <SessionContext.Provider value={query.data}>{children}</SessionContext.Provider>;
}
export const useSession = () => { const value = useContext(SessionContext); if (!value) throw new Error('Session unavailable'); return value; };
export const hasRole = (session: AdminSession, ...roles: string[]) => session.roles.some(value => roles.includes(value.role));
