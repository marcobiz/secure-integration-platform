import { Box, Button, Typography } from '@mui/material';
import type { Page } from '../api/client';
import { useTranslation } from 'react-i18next';

export function PaginationControls<T>({ page, onOffset }: { page: Page<T>; onOffset: (offset: number) => void }) {
  const { t } = useTranslation();
  const start = page.total === 0 ? 0 : page.offset + 1;
  const end = Math.min(page.total, page.offset + page.items.length);
  return <Box sx={{ mt: 2, display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 2 }} aria-label={t('pagination')}>
    <Button disabled={page.offset === 0} onClick={() => onOffset(Math.max(0, page.offset - page.limit))}>{t('previousPage')}</Button>
    <Typography aria-live="polite">{start}–{end} / {page.total}</Typography>
    <Button disabled={page.offset + page.limit >= page.total} onClick={() => onOffset(page.offset + page.limit)}>{t('nextPage')}</Button>
  </Box>;
}
