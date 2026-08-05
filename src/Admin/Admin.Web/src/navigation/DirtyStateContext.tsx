import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

interface DirtyStateValue {
  dirty: boolean;
  setDirty: (dirty: boolean) => void;
  navigate: (path: string) => void;
}

const DirtyStateContext = createContext<DirtyStateValue | undefined>(undefined);

export function DirtyStateProvider({ children }: { children: ReactNode }) {
  const history = useHistory();
  const { t } = useTranslation();
  const [dirty, setDirty] = useState(false);
  const [pendingPath, setPendingPath] = useState<string>();
  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => { if (dirty) event.preventDefault(); };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);
  useEffect(() => history.block((location, action) => {
    if (!dirty || action !== 'POP') return undefined;
    setPendingPath(`${location.pathname}${location.search}${location.hash}`);
    return false;
  }), [dirty, history]);
  const navigate = useCallback((path: string) => { if (dirty) setPendingPath(path); else history.push(path); }, [dirty, history]);
  const value = useMemo(() => ({ dirty, setDirty, navigate }), [dirty, navigate]);
  return <DirtyStateContext.Provider value={value}>{children}<Dialog open={Boolean(pendingPath)} onClose={() => setPendingPath(undefined)} aria-labelledby="unsaved-title"><DialogTitle id="unsaved-title">{t('unsavedTitle')}</DialogTitle><DialogContent>{t('unsavedQuestion')}</DialogContent><DialogActions><Button onClick={() => setPendingPath(undefined)} autoFocus>{t('stay')}</Button><Button color="error" onClick={() => { const path = pendingPath; setPendingPath(undefined); setDirty(false); if (path) history.push(path); }}>{t('discard')}</Button></DialogActions></Dialog></DirtyStateContext.Provider>;
}

export function useDirtyState() {
  const context = useContext(DirtyStateContext);
  if (!context) throw new Error('Dirty state unavailable');
  return context;
}

export function useFormDirty(dirty: boolean) {
  const { setDirty } = useDirtyState();
  useEffect(() => { setDirty(dirty); return () => setDirty(false); }, [dirty, setDirty]);
}
