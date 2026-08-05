import { Alert, Box, Button, CircularProgress, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import { ApiProblem } from '../api/client';

export function LoadingState() { const { t } = useTranslation(); return <Box role="status" sx={{ p: 4, textAlign: 'center' }}><CircularProgress aria-label={t('loading')} /><Typography sx={{ mt: 2 }}>{t('loading')}</Typography></Box>; }
export function EmptyState() { const { t } = useTranslation(); return <Box sx={{ p: 4, textAlign: 'center' }}><Typography color="text.secondary">{t('empty')}</Typography></Box>; }
export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const { t } = useTranslation(); const problem = error instanceof ApiProblem ? error : undefined;
  const message = problem?.status === 403 ? t('forbidden') : problem?.status === 409 ? t('conflict') : problem?.status === 503 ? t('unavailable') : t('unexpected');
  return <Alert severity="error" action={retry && <Button color="inherit" onClick={retry}>{t('retry')}</Button>}><Typography>{message}</Typography>{problem?.correlationId && <Typography variant="caption">{t('correlation')}: {problem.correlationId}</Typography>}</Alert>;
}
