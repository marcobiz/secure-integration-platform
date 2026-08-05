import { FormControl, InputLabel, MenuItem, Select } from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi } from '../../api/client';
import { DataTable } from '../../components/DataTable'; import { ErrorState, LoadingState } from '../../components/AsyncState'; import { PageTitle } from '../../components/PageTitle';

interface InstallationRow { id: string; status: string; applicationId: string; environmentId: string; brokerVersion?: string | null; lastSeenAt?: string | null }
export function InstallationsPage() {
  const { t, i18n } = useTranslation(); const tenants = useQuery({ queryKey: ['tenants'], queryFn: adminApi.tenants }); const [tenant, setTenant] = useState('');
  const installations = useQuery({ queryKey: ['installations', tenant], queryFn: () => adminApi.installations(tenant), enabled: Boolean(tenant) });
  if (tenants.isPending) return <LoadingState />; if (tenants.error) return <ErrorState error={tenants.error} retry={() => void tenants.refetch()} />;
  const rows = (installations.data?.items ?? []) as InstallationRow[];
  return <><PageTitle title={t('installations')} /><FormControl sx={{ minWidth: 280, mb: 3 }}><InputLabel id="tenant-installations-label">{t('selectTenant')}</InputLabel><Select labelId="tenant-installations-label" label={t('selectTenant')} value={tenant} onChange={event => setTenant(event.target.value)}>{(tenants.data.items ?? []).map(value => <MenuItem key={value.id} value={value.id}>{value.displayName}</MenuItem>)}</Select></FormControl>{installations.isPending && tenant ? <LoadingState /> : installations.error ? <ErrorState error={installations.error} retry={() => void installations.refetch()} /> : <DataTable rows={rows} label={t('installations')} columns={[{ key: 'id', label: t('id'), render: row => row.id }, { key: 'status', label: t('status'), render: row => row.status }, { key: 'app', label: t('application'), render: row => row.applicationId }, { key: 'env', label: t('environment'), render: row => row.environmentId }, { key: 'version', label: t('brokerVersion'), render: row => row.brokerVersion ?? '—' }, { key: 'seen', label: t('lastSeen'), render: row => row.lastSeenAt ? new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }).format(new Date(row.lastSeenAt)) : '—' }]} />}</>;
}
