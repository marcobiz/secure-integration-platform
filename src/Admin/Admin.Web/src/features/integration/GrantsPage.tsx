import { Button, Card, CardContent, FormControl, InputLabel, MenuItem, Select, Stack, TextField, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';

export function GrantsPage() {
  const { t, i18n } = useTranslation();
  const session = useSession();
  const cache = useQueryClient();
  const [tenant, setTenant] = useState('');
  const [installationId, setInstallation] = useState('');
  const [connectorId, setConnector] = useState('');
  const [operationId, setOperation] = useState('');
  const [offset, setOffset] = useState(0);
  const tenants = useQuery({ queryKey: ['tenants'], queryFn: () => adminApi.tenants() });
  const installations = useQuery({ queryKey: ['installations', tenant], queryFn: () => adminApi.installations(tenant), enabled: Boolean(tenant) });
  const query = useQuery({ queryKey: ['grants', tenant, offset], queryFn: () => adminApi.grants(tenant, offset), enabled: Boolean(tenant) });
  const create = useMutation({ mutationFn: () => adminApi.createGrant({ tenantId: tenant, installationId, connectorId, operationId }), onSuccess: async () => { setConnector(''); setOperation(''); await cache.invalidateQueries({ queryKey: ['grants', tenant] }); } });
  if (tenants.isPending) return <LoadingState />;
  if (tenants.error) return <ErrorState error={tenants.error} />;
  const canAdmin = hasRole(session, 'SecurityAdministrator');
  return <>
    <PageTitle title={t('grants')} />
    <FormControl sx={{ minWidth: 280, mb: 3 }}><InputLabel id="grants-tenant-label">{t('selectTenant')}</InputLabel><Select labelId="grants-tenant-label" label={t('selectTenant')} value={tenant} onChange={event => { setTenant(event.target.value); setInstallation(''); setOffset(0); }}>{(tenants.data?.items ?? []).map(value => <MenuItem key={value.id} value={value.id}>{value.displayName}</MenuItem>)}</Select></FormControl>
    {canAdmin && tenant && <Card sx={{ mb: 3 }}><CardContent><Typography variant="h2" sx={{ mb: 2 }}>{t('addGrant')}</Typography><Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><FormControl sx={{ minWidth: 220 }}><InputLabel id="grant-installation-label">{t('installation')}</InputLabel><Select labelId="grant-installation-label" label={t('installation')} value={installationId} onChange={event => setInstallation(event.target.value)}>{(installations.data?.items ?? []).map(value => <MenuItem key={value.id} value={value.id}>{value.id}</MenuItem>)}</Select></FormControl><TextField label={t('connectors')} value={connectorId} onChange={event => setConnector(event.target.value)} /><TextField label={t('operation')} value={operationId} onChange={event => setOperation(event.target.value)} /><Button variant="contained" disabled={!installationId || !connectorId || !operationId} onClick={() => create.mutate()}>{t('create')}</Button></Stack></CardContent></Card>}
    {query.isPending && tenant ? <LoadingState /> : query.error ? <ErrorState error={query.error} retry={() => void query.refetch()} /> : <><DataTable rows={query.data?.items ?? []} label={t('grants')} columns={[{ key: 'installation', label: t('installation'), render: row => row.installationId }, { key: 'connector', label: t('connectors'), render: row => row.connectorId }, { key: 'operation', label: t('operation'), render: row => row.operationId }, { key: 'from', label: t('validFrom'), render: row => new Intl.DateTimeFormat(i18n.language).format(new Date(row.validFrom)) }]} />{query.data && <PaginationControls page={query.data} onOffset={setOffset} />}</>}
    {create.error && <ErrorState error={create.error} />}
  </>;
}
