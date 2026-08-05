import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';
import { createTheme, CssBaseline, ThemeProvider } from '@mui/material';

export type ThemeChoice = 'light' | 'dark' | 'system';
const ThemeChoiceContext = createContext<{ choice: ThemeChoice; setChoice: (value: ThemeChoice) => void }>({ choice: 'system', setChoice: () => undefined });

export function AppTheme({ children }: { children: ReactNode }) {
  const initial = localStorage.getItem('sip.theme');
  const [choice, update] = useState<ThemeChoice>(initial === 'light' || initial === 'dark' ? initial : 'system');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const mode = choice === 'system' ? (prefersDark ? 'dark' : 'light') : choice;
  const theme = useMemo(() => createTheme({
    palette: { mode, primary: { main: mode === 'dark' ? '#7dd3fc' : '#075985' }, secondary: { main: '#0f766e' }, background: { default: mode === 'dark' ? '#07131f' : '#f4f7fa', paper: mode === 'dark' ? '#0d1c2b' : '#ffffff' } },
    typography: { fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', h1: { fontSize: '1.75rem', fontWeight: 700 }, h2: { fontSize: '1.2rem', fontWeight: 650 } },
    shape: { borderRadius: 10 },
    components: { MuiButton: { defaultProps: { disableElevation: true } }, MuiCard: { styleOverrides: { root: { border: '1px solid', borderColor: mode === 'dark' ? '#1f3548' : '#dbe5ec' } } } }
  }), [mode]);
  const setChoice = (value: ThemeChoice) => { localStorage.setItem('sip.theme', value); update(value); };
  return <ThemeChoiceContext.Provider value={{ choice, setChoice }}><ThemeProvider theme={theme}><CssBaseline />{children}</ThemeProvider></ThemeChoiceContext.Provider>;
}
export const useThemeChoice = () => useContext(ThemeChoiceContext);
