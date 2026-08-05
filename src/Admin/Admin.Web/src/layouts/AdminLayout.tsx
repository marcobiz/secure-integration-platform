import { useState, type ReactNode } from 'react';
import { AppBar, Box, Button, Divider, Drawer, IconButton, List, ListItemButton, ListItemIcon, ListItemText, MenuItem, Select, Toolbar, Typography } from '@mui/material';
import { Activity, AppWindow, Cable, CheckCheck, FileClock, Gauge, KeyRound, LogOut, Menu, Network, Server, ShieldCheck, Users } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { adminApi } from '../api/client';
import { useSession } from '../auth/SessionContext';
import { useThemeChoice, type ThemeChoice } from '../theme/ThemeContext';

const width = 260;
const groups = [
  { label: 'resources', items: [['tenants', '/tenants', Users], ['applications', '/applications', AppWindow], ['installations', '/installations', Server]] },
  { label: 'integration', items: [['connectors', '/connectors', Cable], ['bindings', '/bindings', Network], ['grants', '/grants', KeyRound], ['approvals', '/approvals', CheckCheck]] },
  { label: 'operations', items: [['access', '/access', ShieldCheck], ['audit', '/audit', FileClock], ['health', '/health', Activity]] }
] as const;

export function AdminLayout({ children }: { children: ReactNode }) {
  const { t, i18n } = useTranslation(); const session = useSession(); const currentPath = window.location.pathname.replace(/^\/admin/, '') || '/'; const [mobile, setMobile] = useState(false); const theme = useThemeChoice();
  const navigation = <Box component="nav" aria-label={t('menu')}><Toolbar><ShieldCheck aria-hidden /><Typography variant="subtitle1" sx={{ ml: 1, fontWeight: 700 }}>{t('product')}</Typography></Toolbar><Divider /><List component="div"><ListItemButton component="a" href="/admin/" selected={currentPath === '/'}><ListItemIcon><Gauge /></ListItemIcon><ListItemText primary={t('dashboard')} /></ListItemButton>{groups.map(group => <Box key={group.label}><Typography variant="overline" sx={{ display: 'block', px: 2, pt: 2, color: 'text.secondary' }}>{t(group.label)}</Typography>{group.items.map(([label, path, Icon]) => <ListItemButton key={path} component="a" href={`/admin${path}`} selected={currentPath.startsWith(path)}><ListItemIcon><Icon size={20} /></ListItemIcon><ListItemText primary={t(label)} /></ListItemButton>)}</Box>)}</List></Box>;
  const logout = async () => { await adminApi.logout(); window.location.assign('/admin/login'); };
  const language = (value: string) => { localStorage.setItem('sip.language', value); void i18n.changeLanguage(value); };
  return <Box sx={{ display: 'flex' }}><Button component="a" href="#main-content" sx={{ position: 'fixed', top: -100, '&:focus': { top: 8 }, zIndex: 2000 }}>{t('skip')}</Button><AppBar position="fixed" sx={{ ml: { md: `${width}px` }, width: { md: `calc(100% - ${width}px)` }, bgcolor: 'background.paper', color: 'text.primary', borderBottom: 1, borderColor: 'divider', boxShadow: 'none' }}><Toolbar><IconButton aria-label={t('menu')} onClick={() => setMobile(true)} sx={{ display: { md: 'none' } }}><Menu /></IconButton><Box sx={{ flexGrow: 1 }} /><Select size="small" value={i18n.language.startsWith('it') ? 'it' : 'en'} onChange={event => language(event.target.value)} aria-label={t('language')} sx={{ mr: 1 }}><MenuItem value="en">EN</MenuItem><MenuItem value="it">IT</MenuItem></Select><Select size="small" value={theme.choice} onChange={event => theme.setChoice(event.target.value as ThemeChoice)} aria-label={t('theme')} sx={{ mr: 2 }}><MenuItem value="system">{t('themeSystem')}</MenuItem><MenuItem value="light">{t('themeLight')}</MenuItem><MenuItem value="dark">{t('themeDark')}</MenuItem></Select><Typography variant="body2" sx={{ display: { xs: 'none', sm: 'block' }, mr: 2 }}>{session.displayName}</Typography><IconButton aria-label={t('logout')} onClick={() => void logout()}><LogOut /></IconButton></Toolbar></AppBar><Drawer variant="permanent" sx={{ display: { xs: 'none', md: 'block' }, width, '& .MuiDrawer-paper': { width } }}>{navigation}</Drawer><Drawer open={mobile} onClose={() => setMobile(false)} sx={{ display: { md: 'none' }, '& .MuiDrawer-paper': { width } }}>{navigation}</Drawer><Box component="main" id="main-content" tabIndex={-1} sx={{ flexGrow: 1, minWidth: 0, p: { xs: 2, md: 4 }, mt: 8, ml: { md: `${width}px` } }}>{children}</Box></Box>;
}
