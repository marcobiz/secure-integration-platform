import { Card, CardContent, Chip, Grid, Stack, Typography } from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { adminApi } from '../../api/client';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { PageTitle } from '../../components/PageTitle';
import { runtimeLabel } from '../../i18n/runtimeValues';

export function DashboardPage() {
  const { t, i18n } = useTranslation(); const query = useQuery({ queryKey: ['dashboard'], queryFn: adminApi.dashboard, refetchInterval: 30_000 });
  if (query.isPending) return <LoadingState />; if (query.error) return <ErrorState error={query.error} retry={() => void query.refetch()} />;
  const data = query.data;
  return <><PageTitle title={t('dashboard')} description={t('healthDescription')} /><Grid container spacing={2}>{[[t('tenants'), data.tenants], [t('applications'), data.applications]].map(([label, value]) => <Grid key={String(label)} size={{ xs: 12, sm: 6, lg: 3 }}><Card><CardContent><Typography color="text.secondary">{label}</Typography><Typography variant="h1">{value}</Typography></CardContent></Card></Grid>)}{[[t('database'), data.database], [t('provider'), data.provider]].map(([label, value]) => <Grid key={String(label)} size={{ xs: 12, sm: 6, lg: 3 }}><Card><CardContent><Typography color="text.secondary">{label}</Typography><Chip color={value === 'healthy' ? 'success' : 'error'} label={runtimeLabel(t, 'health', value)} sx={{ mt: 1 }} /></CardContent></Card></Grid>)}</Grid><Stack direction="row" spacing={1} sx={{ mt: 3 }}><Typography variant="caption" color="text.secondary">{t('lastUpdated')}:</Typography><Typography variant="caption">{new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'long', timeZone: 'UTC' }).format(new Date(data.generatedAtUtc))} {t('utc')}</Typography></Stack></>;
}
