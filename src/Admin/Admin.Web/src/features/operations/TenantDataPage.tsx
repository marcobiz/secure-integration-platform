import { FormControl, InputLabel, MenuItem, Select } from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi } from '../../api/client';
import { DataTable } from '../../components/DataTable'; import { ErrorState, LoadingState } from '../../components/AsyncState'; import { PageTitle } from '../../components/PageTitle';

export function TenantDataPage({ kind }: { kind: 'grants' | 'audit' }) {
  const { t, i18n } = useTranslation(); const [tenant, setTenant] = useState(''); const tenants = useQuery({ queryKey: ['tenants'], queryFn: () => adminApi.tenants() });
  const query = useQuery<{ items: Array<Record<string, unknown>> }>({ queryKey: [kind, tenant], queryFn: async () => { const result = kind === 'grants' ? await adminApi.grants(tenant) : await adminApi.audit(tenant); return { items: result.items as Array<Record<string, unknown>> }; }, enabled: Boolean(tenant) });
  if (tenants.isPending) return <LoadingState />;
  const rows = (query.data?.items ?? []) as Array<Record<string, unknown>>;
  const columns = kind === 'grants' ? [{ key: 'installation', label: t('installation'), render: (row: Record<string, unknown>) => String(row.installationId) }, { key: 'connector', label: t('connectors'), render: (row: Record<string, unknown>) => String(row.connectorId) }, { key: 'operation', label: t('operation'), render: (row: Record<string, unknown>) => String(row.operationId) }, { key: 'from', label: t('validFrom'), render: (row: Record<string, unknown>) => new Intl.DateTimeFormat(i18n.language).format(new Date(String(row.validFrom))) }] : [{ key: 'action', label: t('action'), render: (row: Record<string, unknown>) => String(row.action) }, { key: 'target', label: t('target'), render: (row: Record<string, unknown>) => `${String(row.targetType)} · ${String(row.targetId)}` }, { key: 'outcome', label: t('outcome'), render: (row: Record<string, unknown>) => String(row.outcome) }, { key: 'reason', label: t('reason'), render: (row: Record<string, unknown>) => String(row.reasonCode) }];
  return <><PageTitle title={t(kind)} /><FormControl sx={{ minWidth: 280, mb: 3 }}><InputLabel id={`${kind}-tenant-label`}>{t('selectTenant')}</InputLabel><Select labelId={`${kind}-tenant-label`} label={t('selectTenant')} value={tenant} onChange={event => setTenant(event.target.value)}>{(tenants.data?.items ?? []).map(value => <MenuItem key={value.id} value={value.id}>{value.displayName}</MenuItem>)}</Select></FormControl>{query.isPending && tenant ? <LoadingState /> : query.error ? <ErrorState error={query.error} retry={() => void query.refetch()} /> : <DataTable rows={rows} columns={columns} label={t(kind)} />}</>;
}
