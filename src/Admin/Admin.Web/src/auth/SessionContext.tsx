import { createContext, useContext, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { adminApi, type AdminSession } from '../api/client';
import { LoadingState } from '../components/AsyncState';

const SessionContext = createContext<AdminSession | null>(null);
export function SessionProvider({ children, fallback }: { children: ReactNode; fallback: ReactNode }) {
  const query = useQuery({ queryKey: ['session'], queryFn: adminApi.session, retry: false, staleTime: 30_000 });
  if (query.isPending) return <LoadingState />;
  if (!query.data) return fallback;
  return <SessionContext.Provider value={query.data}>{children}</SessionContext.Provider>;
}
export const useSession = () => { const value = useContext(SessionContext); if (!value) throw new Error('Session unavailable'); return value; };
export const hasRole = (session: AdminSession, ...roles: string[]) => session.roles.some(value => roles.includes(value.role));
