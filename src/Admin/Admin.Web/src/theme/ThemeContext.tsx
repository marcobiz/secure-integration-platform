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
    palette: {
      mode,
      primary: { main: mode === 'dark' ? '#7dd3fc' : '#075985' },
      secondary: { main: '#0f766e' },
      text: { primary: mode === 'dark' ? '#e5edf5' : '#192b3c', secondary: mode === 'dark' ? '#b8c7d3' : '#506274' },
      divider: mode === 'dark' ? '#2b3c4f' : '#dce3ea',
      background: { default: mode === 'dark' ? '#0b131d' : '#f5f7fa', paper: mode === 'dark' ? '#121f2c' : '#ffffff' }
    },
    typography: {
      fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      fontSize: 14,
      h1: { fontSize: '1.75rem', fontWeight: 650, letterSpacing: '-0.035em' },
      h2: { fontSize: '1.15rem', fontWeight: 650, letterSpacing: '-0.015em' },
      h3: { fontSize: '1rem', fontWeight: 650, letterSpacing: '-0.01em' },
      body1: { fontSize: '0.875rem', lineHeight: 1.6 },
      body2: { fontSize: '0.8125rem', lineHeight: 1.5 },
      button: { textTransform: 'none', fontWeight: 600 },
      overline: { fontSize: '0.625rem', fontWeight: 600, letterSpacing: '0.1em' }
    },
    shape: { borderRadius: 8 },
    components: {
      MuiButton: { defaultProps: { disableElevation: true }, styleOverrides: { root: { minHeight: 36, whiteSpace: 'nowrap' } } },
      MuiTextField: { defaultProps: { size: 'small' } },
      MuiFormControl: { defaultProps: { size: 'small' } },
      MuiOutlinedInput: { styleOverrides: { root: { minHeight: 40, fontSize: '0.875rem' } } },
      MuiCard: { defaultProps: { elevation: 0 }, styleOverrides: { root: { minWidth: 0, border: '1px solid', borderColor: mode === 'dark' ? '#2b3c4f' : '#dce3ea' } } },
      MuiChip: { styleOverrides: { root: { maxWidth: '100%', height: 'auto', minHeight: 28 }, label: { whiteSpace: 'normal', paddingTop: 4, paddingBottom: 4, overflowWrap: 'anywhere' } } },
      MuiTableCell: { styleOverrides: {
        head: { backgroundColor: mode === 'dark' ? '#192838' : '#f8fafc', color: mode === 'dark' ? '#bdcedf' : '#506274', fontSize: '0.75rem', fontWeight: 600, whiteSpace: 'nowrap' },
        body: { fontSize: '0.8125rem', paddingTop: 14, paddingBottom: 14, overflowWrap: 'break-word' }
      } },
      MuiTableRow: { styleOverrides: { root: { '&:last-child td': { borderBottom: 0 } } } },
      MuiFormLabel: { styleOverrides: { root: { color: mode === 'dark' ? '#c7d4de' : '#303030' } } },
      MuiFormHelperText: { styleOverrides: { root: { color: mode === 'dark' ? '#c7d4de' : '#303030' } } }
    }
  }), [mode]);
  const setChoice = (value: ThemeChoice) => { localStorage.setItem('sip.theme', value); update(value); };
  return <ThemeChoiceContext.Provider value={{ choice, setChoice }}><ThemeProvider theme={theme}><CssBaseline />{children}</ThemeProvider></ThemeChoiceContext.Provider>;
}
export const useThemeChoice = () => useContext(ThemeChoiceContext);
