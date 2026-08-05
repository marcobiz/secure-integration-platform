import { Box, Button, Card, CardContent, Stack, Typography } from '@mui/material';
import { ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { adminApi } from '../api/client';

export function LoginPage() {
  const { t } = useTranslation();
  const login = async (user: string) => { await adminApi.developmentLogin(user); window.location.assign('/admin/'); };
  return <Box component="main" sx={{ minHeight: '100vh', display: 'grid', placeItems: 'center', p: 2, background: 'linear-gradient(145deg, #071f32, #0d3a4d)' }}><Card sx={{ width: 'min(520px, 100%)' }}><CardContent sx={{ p: 4 }}><ShieldCheck size={42} aria-hidden /><Typography variant="h1" sx={{ mt: 2 }}>{t('loginTitle')}</Typography><Typography color="text.secondary" sx={{ my: 2 }}>{t('loginHelp')}</Typography><Button fullWidth variant="contained" href="/admin/auth/login" sx={{ mb: 3 }}>{t('oidcLogin')}</Button><Stack direction="row" useFlexGap spacing={1} sx={{ flexWrap: 'wrap' }}>{[['viewer','viewer'],['editor','editor'],['approver','approver'],['operator','operator'],['security-admin','securityAdmin']].map(([user,key]) => <Button key={user} variant="outlined" onClick={() => void login(user)}>{t(key)}</Button>)}</Stack></CardContent></Card></Box>;
}
