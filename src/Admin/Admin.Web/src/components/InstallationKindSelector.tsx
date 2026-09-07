import { FormControl, FormHelperText, InputLabel, MenuItem, Select } from '@mui/material';
import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import type { Installation } from '../api/client';

export function InstallationKindSelector({ value, onChange, disabled = false }: {
  value: Installation['installationKind'];
  onChange: (value: Installation['installationKind']) => void;
  disabled?: boolean;
}) {
  const { t } = useTranslation();
  const id = useId();
  return <FormControl fullWidth disabled={disabled} sx={{ minWidth: 0 }}>
    <InputLabel id={`${id}-label`}>{t('installationType')}</InputLabel>
    <Select labelId={`${id}-label`} id={id} label={t('installationType')} value={value}
      inputProps={{ 'aria-describedby': `${id}-help` }} onChange={event => onChange(event.target.value)}>
      <MenuItem value="Direct">{t('directInstallation')}</MenuItem>
      <MenuItem value="Broker">{t('brokerInstallation')}</MenuItem>
    </Select>
    <FormHelperText id={`${id}-help`}>{t(value === 'Direct' ? 'directInstallationHelp' : 'brokerInstallationHelp')}</FormHelperText>
  </FormControl>;
}
