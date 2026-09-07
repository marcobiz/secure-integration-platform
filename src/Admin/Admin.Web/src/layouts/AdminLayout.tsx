import { useState, type ReactNode } from 'react';
import { AppBar, Box, Button, Divider, Drawer, IconButton, List, ListItemButton, ListItemIcon, ListItemText, MenuItem, Select, Toolbar, Typography } from '@mui/material';
import { Activity, AppWindow, BookOpen, Cable, CheckCheck, FileClock, Gauge, KeyRound, LogOut, Menu, Network, Server, ShieldCheck, Users } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import { adminApi } from '../api/client';
import { hasRole, useSession } from '../auth/SessionContext';
import { useThemeChoice, type ThemeChoice } from '../theme/ThemeContext';
import { useDirtyState } from '../navigation/DirtyStateContext';

const width = 248;
const groups = [
  { label: 'resources', items: [['tenants', '/tenants', Users], ['applications', '/applications', AppWindow], ['installations', '/installations', Server]] },
  { label: 'integration', items: [['guidedOnboarding', '/onboarding', Cable], ['connectors', '/connectors', Cable], ['bindings', '/bindings', Network], ['grants', '/grants', KeyRound], ['approvals', '/approvals', CheckCheck]] },
  { label: 'operations', items: [['access', '/access', ShieldCheck], ['audit', '/audit', FileClock], ['health', '/health', Activity], ['documentation', '/documentation', BookOpen]] }
] as const;

export function AdminLayout({ children }: { children: ReactNode }) {
  const { t, i18n } = useTranslation(); const session = useSession(); const currentPath = useLocation().pathname || '/'; const [mobile, setMobile] = useState(false); const theme = useThemeChoice(); const dirty = useDirtyState();
  const go = (path: string) => { setMobile(false); dirty.navigate(path); };
  const section = groups.find(group => group.items.some(([, path]) => currentPath.startsWith(path)));
  const navigation = <Box component="nav" aria-label={t('menu')} sx={{ color: '#dbe5ef', bgcolor: '#101e2d', minHeight: '100%', pb: 2,
    '& .MuiListItemButton-root': { mx: 1.5, my: 0.25, px: 1.5, borderRadius: 1, minHeight: 40, '&:hover': { bgcolor: '#1b3043' }, '&.Mui-selected': { bgcolor: '#243d52', color: '#ffffff', '&:hover': { bgcolor: '#2b465e' } } },
    '& .MuiListItemIcon-root': { minWidth: 32, color: 'inherit', opacity: 0.85 },
    '& .MuiListItemText-primary': { fontSize: '0.8125rem', fontWeight: 500 }
  }}>
    <Toolbar sx={{ gap: 1.5, minHeight: '64px !important', px: '24px !important' }}><ShieldCheck size={24} aria-hidden style={{ flexShrink: 0 }} /><Typography sx={{ fontSize: '0.875rem', fontWeight: 650, lineHeight: 1.4, color: '#ffffff' }}>{t('product')}</Typography></Toolbar>
    <Divider sx={{ borderColor: '#2b3c4f' }} />
    <List component="div" sx={{ pt: 2 }}>
      <ListItemButton component={RouterLink} to="/" onClick={event => { event.preventDefault(); go('/'); }} selected={currentPath === '/'} aria-current={currentPath === '/' ? 'page' : undefined}><ListItemIcon><Gauge size={18} /></ListItemIcon><ListItemText primary={t('dashboard')} /></ListItemButton>
      {groups.map(group => <Box key={group.label}>
        <Typography variant="overline" sx={{ display: 'block', px: 3, pt: 2.5, pb: 0.75, color: '#9eb1c5' }}>{t(group.label)}</Typography>
        {group.items.filter(([label]) => label !== 'access' || hasRole(session, 'SecurityAdministrator')).map(([label, path, Icon]) => <ListItemButton key={path} component={RouterLink} to={path} onClick={event => { event.preventDefault(); go(path); }} selected={currentPath.startsWith(path)} aria-current={currentPath.startsWith(path) ? 'page' : undefined}><ListItemIcon><Icon size={18} /></ListItemIcon><ListItemText primary={t(label)} /></ListItemButton>)}
      </Box>)}
    </List>
  </Box>;
  const logout = async () => { await adminApi.logout(); window.location.assign('/admin/login'); };
  const language = (value: string) => { localStorage.setItem('sip.language', value); void i18n.changeLanguage(value); };
  return <Box sx={{ display: 'flex', minHeight: '100dvh' }}>
    <Button component="a" href="#main-content" sx={{ position: 'fixed', top: -100, '&:focus': { top: 8 }, zIndex: 2000 }}>{t('skip')}</Button>
    <AppBar position="fixed" sx={{ width: { md: `calc(100% - ${width}px)` }, bgcolor: 'background.paper', color: 'text.primary', borderBottom: 1, borderColor: 'divider', boxShadow: 'none' }}>
      <Toolbar sx={{ gap: 1, minHeight: '64px !important' }}>
        <IconButton aria-label={t('menu')} onClick={() => setMobile(true)} sx={{ display: { md: 'none' } }}><Menu size={20} /></IconButton>
        <Typography variant="body2" color="text.secondary" sx={{ display: { xs: 'none', sm: 'block' } }}>{t(section?.label ?? 'dashboard')}</Typography>
        <Box sx={{ flexGrow: 1 }} />
        <Select size="small" value={i18n.language.startsWith('it') ? 'it' : 'en'} onChange={event => language(event.target.value)} aria-label={t('language')}><MenuItem value="en">EN</MenuItem><MenuItem value="it">IT</MenuItem></Select>
        <Select size="small" value={theme.choice} onChange={event => theme.setChoice(event.target.value as ThemeChoice)} aria-label={t('theme')}><MenuItem value="system">{t('themeSystem')}</MenuItem><MenuItem value="light">{t('themeLight')}</MenuItem><MenuItem value="dark">{t('themeDark')}</MenuItem></Select>
        <Typography variant="body2" sx={{ display: { xs: 'none', sm: 'block' }, ml: 1, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={session.displayName}>{session.displayName}</Typography>
        <IconButton aria-label={t('logout')} onClick={() => void logout()}><LogOut size={18} /></IconButton>
      </Toolbar>
    </AppBar>
    <Drawer variant="permanent" sx={{ display: { xs: 'none', md: 'block' }, width, flexShrink: 0, '& .MuiDrawer-paper': { width, boxSizing: 'border-box' } }}>{navigation}</Drawer>
    <Drawer open={mobile} onClose={() => setMobile(false)} sx={{ display: { md: 'none' }, '& .MuiDrawer-paper': { width } }}>{navigation}</Drawer>
    <Box component="main" id="main-content" tabIndex={-1} sx={{ flexGrow: 1, minWidth: 0, p: { xs: 2, sm: 3, lg: 4 }, mt: '64px' }}>{children}</Box>
  </Box>;
}
