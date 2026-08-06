import { Chip, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';

export interface ConflictField { label: string; localValue: string; serverValue: string }

export function ConflictComparison({ fields, localRowVersion, serverRowVersion }: { fields: ConflictField[]; localRowVersion: number; serverRowVersion: number }) {
  const { t } = useTranslation();
  return <Stack spacing={1} sx={{ mt: 1 }}>
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
      <Typography variant="body2">{`${t('localEtag')}: "${localRowVersion}"`}</Typography>
      <Typography variant="body2">{`${t('serverEtag')}: "${serverRowVersion}"`}</Typography>
    </Stack>
    <Table size="small" aria-label={t('concurrencyConflict')}>
      <TableHead><TableRow><TableCell>{t('conflictField')}</TableCell><TableCell>{t('conflictLocal')}</TableCell><TableCell>{t('conflictServer')}</TableCell><TableCell>{t('conflictState')}</TableCell></TableRow></TableHead>
      <TableBody>{fields.map(field => { const changed = field.localValue !== field.serverValue; return <TableRow key={field.label}><TableCell component="th" scope="row">{field.label}</TableCell><TableCell>{field.localValue || '—'}</TableCell><TableCell>{field.serverValue || '—'}</TableCell><TableCell><Chip size="small" color={changed ? 'warning' : 'default'} label={changed ? t('conflictChanged') : t('conflictUnchanged')} /></TableCell></TableRow>; })}</TableBody>
    </Table>
  </Stack>;
}
