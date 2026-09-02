import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, Typography } from '@mui/material';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ProvisionedActivation } from '../api/client';

export function ActivationHandoffDialog({ activation, onClose }: { activation?: ProvisionedActivation; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const [copied, setCopied] = useState<'id' | 'code'>();
  const copy = async (kind: 'id' | 'code', value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(kind);
  };
  return <Dialog open={Boolean(activation)} onClose={onClose} fullWidth maxWidth="sm">
    <DialogTitle>{t('activationCodeTitle')}</DialogTitle>
    <DialogContent>
      <Alert severity="warning" sx={{ mb: 2 }}>{t('activationCodeOnce')}</Alert>
      <Typography color="text.secondary" sx={{ mb: 2 }}>{t('activationHandoffHelp')}</Typography>
      <Stack spacing={2}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ alignItems: { sm: 'flex-start' } }}>
          <TextField fullWidth label={t('activationCodeId')} value={activation?.activationCodeId ?? ''} slotProps={{ htmlInput: { readOnly: true, autoComplete: 'off' } }} />
          <Button variant="outlined" onClick={() => activation && copy('id', activation.activationCodeId)}>{t('copyActivationCodeId')}</Button>
        </Stack>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ alignItems: { sm: 'flex-start' } }}>
          <TextField fullWidth label={t('activationCode')} value={activation?.activationCode ?? ''} slotProps={{ htmlInput: { readOnly: true, autoComplete: 'off' } }} />
          <Button variant="outlined" onClick={() => activation && copy('code', activation.activationCode)}>{t('copyActivationCode')}</Button>
        </Stack>
        {copied && <Typography role="status" color="success.main">{t(copied === 'id' ? 'activationCodeIdCopied' : 'activationCodeCopied')}</Typography>}
        <TextField fullWidth label={t('expires')} value={activation ? new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'long' }).format(new Date(activation.expiresAt)) : ''} slotProps={{ htmlInput: { readOnly: true } }} />
      </Stack>
    </DialogContent>
    <DialogActions><Button onClick={onClose}>{t('close')}</Button></DialogActions>
  </Dialog>;
}
