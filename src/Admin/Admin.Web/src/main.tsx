import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CacheProvider } from '@emotion/react';
import createCache from '@emotion/cache';
import './i18n';
import { App } from './app/App';
import { AppTheme } from './theme/ThemeContext';

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: (count, error) => count < 1 && !(error instanceof Error && error.message.includes('403')), staleTime: 10_000 } } });
const root = document.getElementById('root');
if (!root) throw new Error('Root element missing');
const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content;
const emotionCache = createCache({ key: 'sip', nonce });
createRoot(root).render(<StrictMode><CacheProvider value={emotionCache}><QueryClientProvider client={queryClient}><AppTheme><App /></AppTheme></QueryClientProvider></CacheProvider></StrictMode>);
