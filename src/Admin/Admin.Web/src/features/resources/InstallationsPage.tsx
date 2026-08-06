import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi, type Installation, type ProvisionedActivation } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';
import { PagedSelector } from '../../components/PagedSelector';
import { runtimeLabel } from '../../i18n/runtimeValues';

export function InstallationsPage() {
  const { t, i18n } = useTranslation();
  const session = useSession();
  const cache = useQueryClient();
  const [tenant, setTenant] = useState('');
  const [applicationId, setApplication] = useState('');
  const [environmentId, setEnvironment] = useState('');
  const [activation, setActivation] = useState<ProvisionedActivation>();
  const [reason, setReason] = useState('administrative-revocation');
  const [offset, setOffset] = useState(0);
  const [tenantOffset, setTenantOffset] = useState(0);
  const [applicationOffset, setApplicationOffset] = useState(0);
  const [environmentOffset, setEnvironmentOffset] = useState(0);
  const tenants = useQuery({ queryKey: ['tenants', 'selector', tenantOffset], queryFn: () => adminApi.tenants(tenantOffset) });
  const applications = useQuery({ queryKey: ['applications', 'selector', applicationOffset], queryFn: () => adminApi.applications(applicationOffset) });
  const environments = useQuery({ queryKey: ['environments', 'selector', environmentOffset], queryFn: () => adminApi.environments(environmentOffset) });
  const installations = useQuery({ queryKey: ['installations', tenant, offset], queryFn: () => adminApi.installations(tenant, offset), enabled: Boolean(tenant) });
  const create = useMutation({ mutationFn: () => adminApi.createInstallation({ tenantId: tenant, applicationId, environmentId }), onSuccess: async value => { setActivation(value); await cache.invalidateQueries({ queryKey: ['installations', tenant] }); } });
  const revoke = useMutation({ mutationFn: (id: string) => adminApi.revokeInstallation(tenant, id, reason), onSuccess: async () => cache.invalidateQueries({ queryKey: ['installations', tenant] }) });
  if (tenants.isPending || applications.isPending || environments.isPending) return <LoadingState />;
  const bootstrapError = tenants.error ?? applications.error ?? environments.error;
  if (bootstrapError) return <ErrorState error={bootstrapError} />;
  const rows = installations.data?.items ?? [];
  const canAdmin = hasRole(session, 'SecurityAdministrator');
  return <>
    <PageTitle title={t('installations')} />
    <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 3 }}>
      <PagedSelector id="tenant-installations" label={t('selectTenant')} value={tenant} page={tenants.data!} onChange={value => { setTenant(value); setOffset(0); }} onOffset={setTenantOffset} itemLabel={value => value.displayName} />
      {canAdmin && <><PagedSelector id="application-installations" label={t('application')} value={applicationId} page={applications.data!} onChange={setApplication} onOffset={setApplicationOffset} itemLabel={value => value.displayName} /><PagedSelector id="environment-installations" label={t('environment')} value={environmentId} page={environments.data!} onChange={setEnvironment} onOffset={setEnvironmentOffset} itemLabel={value => value.displayName} /><Button variant="contained" disabled={!tenant || !applicationId || !environmentId || create.isPending} onClick={() => create.mutate()}>{t('createInstallation')}</Button></>}
    </Stack>
    {installations.isPending && tenant ? <LoadingState /> : installations.error ? <ErrorState error={installations.error} retry={() => void installations.refetch()} /> : <><DataTable rows={rows} label={t('installations')} columns={[{ key: 'id', label: t('id'), render: (row: Installation) => row.id }, { key: 'status', label: t('status'), render: row => runtimeLabel(t, 'status', row.status) }, { key: 'app', label: t('application'), render: row => row.applicationId }, { key: 'env', label: t('environment'), render: row => row.environmentId }, { key: 'seen', label: t('lastSeen'), render: row => row.lastSeenAt ? new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }).format(new Date(row.lastSeenAt)) : '—' }, { key: 'action', label: t('action'), render: row => canAdmin && row.status !== 'Revoked' ? <Button color="error" size="small" onClick={() => revoke.mutate(row.id)}>{t('revoke')}</Button> : null }]} />{installations.data && <PaginationControls page={installations.data} onOffset={setOffset} />}</>}
    {(create.error || revoke.error) && <ErrorState error={create.error ?? revoke.error} />}
    <Dialog open={Boolean(activation)} onClose={() => setActivation(undefined)}><DialogTitle>{t('activationCodeTitle')}</DialogTitle><DialogContent><Alert severity="warning" sx={{ mb: 2 }}>{t('activationCodeOnce')}</Alert><TextField fullWidth label={t('activationCode')} value={activation?.activationCode ?? ''} slotProps={{ input: { readOnly: true } }} /><TextField fullWidth sx={{ mt: 2 }} label={t('expires')} value={activation ? new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'long' }).format(new Date(activation.expiresAt)) : ''} slotProps={{ input: { readOnly: true } }} /></DialogContent><DialogActions><Button onClick={() => setActivation(undefined)}>{t('close')}</Button></DialogActions></Dialog>
    <TextField sx={{ display: 'none' }} aria-hidden label={t('reason')} value={reason} onChange={event => setReason(event.target.value)} />
  </>;
}
