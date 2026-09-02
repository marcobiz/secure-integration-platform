import { Button, FormControl, InputLabel, MenuItem, Select, Stack, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Page } from '../api/client';

export function PagedSelector<T>({ id, label, value, page, onChange, onOffset, itemLabel, itemValue }: {
  id: string;
  label: string;
  value: string;
  page: Page<T>;
  onChange: (value: string) => void;
  onOffset: (offset: number) => void;
  itemLabel: (item: T) => string;
  itemValue?: (item: T) => string;
}) {
  const { t } = useTranslation();
  const optionValue = (item: T) => itemValue ? itemValue(item) : (item as { id: string }).id;
  return <Stack spacing={0.5} sx={{ minWidth: 240 }}>
    <FormControl><InputLabel id={`${id}-label`}>{label}</InputLabel><Select labelId={`${id}-label`} label={label} value={page.items.some(item => optionValue(item) === value) ? value : ''} onChange={event => onChange(event.target.value)}>
      {page.items.map(item => { const itemId = optionValue(item); return <MenuItem key={itemId} value={itemId}>{itemLabel(item)}</MenuItem>; })}
    </Select></FormControl>
    <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }} role="group" aria-label={t('selectorPageControls')} data-testid={`${id}-pagination`}>
      <Button size="small" disabled={page.offset === 0} onClick={() => onOffset(Math.max(0, page.offset - page.limit))}>{t('previousPage')}</Button>
      <Typography component="span" variant="caption" aria-live="polite">{page.total === 0 ? '0' : `${page.offset + 1}-${Math.min(page.offset + page.limit, page.total)}`} / {page.total}</Typography>
      <Button size="small" disabled={page.offset + page.limit >= page.total} onClick={() => onOffset(page.offset + page.limit)}>{t('nextPage')}</Button>
    </Stack>
  </Stack>;
}
