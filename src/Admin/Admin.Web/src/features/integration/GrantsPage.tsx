import { Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';
import { PagedSelector } from '../../components/PagedSelector';
import { useFormDirty } from '../../navigation/DirtyStateContext';

export function GrantsPage() {
  const { t, i18n } = useTranslation();
  const session = useSession();
  const cache = useQueryClient();
  const [tenant, setTenant] = useState('');
  const [installationId, setInstallation] = useState('');
  const [connectorId, setConnector] = useState('');
  const [operationId, setOperation] = useState('');
  const [offset, setOffset] = useState(0);
  const [tenantOffset, setTenantOffset] = useState(0);
  const [installationOffset, setInstallationOffset] = useState(0);
  const tenants = useQuery({ queryKey: ['tenants', 'selector', tenantOffset], queryFn: () => adminApi.tenants(tenantOffset) });
  const installations = useQuery({ queryKey: ['installations', tenant, 'selector', installationOffset], queryFn: () => adminApi.installations(tenant, installationOffset), enabled: Boolean(tenant) });
  const query = useQuery({ queryKey: ['grants', tenant, offset], queryFn: () => adminApi.grants(tenant, offset), enabled: Boolean(tenant) });
  useFormDirty(Boolean(installationId || connectorId || operationId));
  const create = useMutation({ mutationFn: () => adminApi.createGrant({ tenantId: tenant, installationId, connectorId, operationId }), onSuccess: async () => { setInstallation(''); setConnector(''); setOperation(''); await cache.invalidateQueries({ queryKey: ['grants', tenant] }); } });
  if (tenants.isPending) return <LoadingState />;
  if (tenants.error) return <ErrorState error={tenants.error} />;
  const canAdmin = hasRole(session, 'SecurityAdministrator');
  return <>
    <PageTitle title={t('grants')} />
    <PagedSelector id="grants-tenant" label={t('selectTenant')} value={tenant} page={tenants.data!} onChange={value => { setTenant(value); setInstallation(''); setInstallationOffset(0); setOffset(0); }} onOffset={setTenantOffset} itemLabel={value => value.displayName} />
    {canAdmin && tenant && installations.data && <Card sx={{ my: 3 }}><CardContent><Typography variant="h2" sx={{ mb: 2 }}>{t('addGrant')}</Typography><Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><PagedSelector id="grant-installation" label={t('installation')} value={installationId} page={installations.data} onChange={setInstallation} onOffset={setInstallationOffset} itemLabel={value => value.id} /><TextField label={t('connectors')} value={connectorId} onChange={event => setConnector(event.target.value)} /><TextField label={t('operation')} value={operationId} onChange={event => setOperation(event.target.value)} /><Button variant="contained" disabled={!installationId || !connectorId || !operationId} onClick={() => create.mutate()}>{t('create')}</Button></Stack></CardContent></Card>}
    {query.isPending && tenant ? <LoadingState /> : query.error ? <ErrorState error={query.error} retry={() => void query.refetch()} /> : <><DataTable rows={query.data?.items ?? []} label={t('grants')} columns={[{ key: 'installation', label: t('installation'), render: row => row.installationId }, { key: 'connector', label: t('connectors'), render: row => row.connectorId }, { key: 'operation', label: t('operation'), render: row => row.operationId }, { key: 'from', label: t('validFrom'), render: row => new Intl.DateTimeFormat(i18n.language).format(new Date(row.validFrom)) }]} />{query.data && <PaginationControls page={query.data} onOffset={setOffset} />}</>}
    {create.error && <ErrorState error={create.error} />}
  </>;
}
