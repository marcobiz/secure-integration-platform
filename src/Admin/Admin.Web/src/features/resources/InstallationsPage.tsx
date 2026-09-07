import { Box, Button, FormControl, InputLabel, MenuItem, Paper, Select, TextField, Typography } from '@mui/material';
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
import { ActivationHandoffDialog } from '../../components/ActivationHandoffDialog';
import { runtimeLabel } from '../../i18n/runtimeValues';
import { formatDateTime } from '../../i18n/dateTime';

export function InstallationsPage() {
  const { t } = useTranslation();
  const session = useSession();
  const cache = useQueryClient();
  const [tenant, setTenant] = useState('');
  const [applicationId, setApplication] = useState('');
  const [environmentId, setEnvironment] = useState('');
  const [installationKind, setInstallationKind] = useState<'Broker' | 'Direct'>('Broker');
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
  const create = useMutation({ mutationFn: () => adminApi.createInstallation({ tenantId: tenant, applicationId, environmentId, installationKind }), onSuccess: async value => { setActivation(value); await cache.invalidateQueries({ queryKey: ['installations', tenant] }); } });
  const revoke = useMutation({ mutationFn: (id: string) => adminApi.revokeInstallation(tenant, id, reason), onSuccess: async () => cache.invalidateQueries({ queryKey: ['installations', tenant] }) });
  if (tenants.isPending || applications.isPending || environments.isPending) return <LoadingState />;
  const bootstrapError = tenants.error ?? applications.error ?? environments.error;
  if (bootstrapError) return <ErrorState error={bootstrapError} />;
  const rows = installations.data?.items ?? [];
  const canAdmin = hasRole(session, 'SecurityAdministrator');
  return <>
    <PageTitle title={t('installations')} description={t('installationsDescription')} action={canAdmin && <Button variant="contained" disabled={!tenant || !applicationId || !environmentId || create.isPending} onClick={() => create.mutate()}>{t('createInstallation')}</Button>} />
    <Paper variant="outlined" sx={{ p: { xs: 2, sm: 2.5 }, mb: 3 }}>
    <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: 'minmax(0, 1fr)', sm: 'repeat(2, minmax(0, 1fr))', lg: canAdmin ? 'repeat(3, minmax(0, 1fr)) minmax(150px, 0.65fr)' : 'minmax(0, 320px)' } }}>
      <PagedSelector id="tenant-installations" label={t('selectTenant')} value={tenant} page={tenants.data!} onChange={value => { setTenant(value); setOffset(0); }} onOffset={setTenantOffset} itemLabel={value => value.displayName} />
      {canAdmin && <><PagedSelector id="application-installations" label={t('application')} value={applicationId} page={applications.data!} onChange={setApplication} onOffset={setApplicationOffset} itemLabel={value => value.displayName} /><PagedSelector id="environment-installations" label={t('environment')} value={environmentId} page={environments.data!} onChange={setEnvironment} onOffset={setEnvironmentOffset} itemLabel={value => value.displayName} /><FormControl sx={{ minWidth: 0 }}><InputLabel id="installation-kind-label">{t('installationType')}</InputLabel><Select labelId="installation-kind-label" id="installation-kind" label={t('installationType')} value={installationKind} onChange={event => setInstallationKind(event.target.value)}><MenuItem value="Broker">{t('brokerInstallation')}</MenuItem><MenuItem value="Direct">{t('directInstallation')}</MenuItem></Select></FormControl></>}
    </Box>
    </Paper>
    {!tenant ? <Paper variant="outlined" sx={{ px: 3, py: 7, textAlign: 'center' }}><Typography variant="h2" sx={{ mb: 1 }}>{t('selectTenant')}</Typography><Typography color="text.secondary">{t('installationsSelectTenantHelp')}</Typography></Paper> : installations.isPending ? <LoadingState /> : installations.error ? <ErrorState error={installations.error} retry={() => void installations.refetch()} /> : <><DataTable rows={rows} label={t('installations')} columns={[{ key: 'id', label: t('id'), render: (row: Installation) => row.id }, { key: 'kind', label: t('installationType'), render: row => row.installationKind === 'Direct' ? t('directInstallation') : t('brokerInstallation') }, { key: 'status', label: t('status'), render: row => runtimeLabel(t, 'status', row.status) }, { key: 'app', label: t('application'), render: row => applications.data!.items.find(application => application.id === row.applicationId)?.displayName ?? row.applicationId }, { key: 'version', label: t('clientVersion'), render: row => row.clientVersion ?? row.brokerVersion ?? '—' }, { key: 'credential', label: t('publicKeyFingerprint'), render: row => <Box component="code" sx={{ display: 'block', width: 190, overflowWrap: 'anywhere' }}>{row.credential?.spkiSha256 ?? '—'}</Box> }, { key: 'created', label: t('created'), render: row => <Box component="time" dateTime={row.createdAt} sx={{ whiteSpace: 'nowrap' }}>{formatDateTime(row.createdAt)}</Box> }, { key: 'seen', label: t('lastSeen'), render: row => <Box component="span" sx={{ whiteSpace: 'nowrap' }}>{formatDateTime(row.lastSeenAt)}</Box> }, { key: 'action', label: t('action'), render: row => canAdmin && row.status !== 'Revoked' ? <Button color="error" size="small" onClick={() => revoke.mutate(row.id)}>{t('revoke')}</Button> : null }]} />{installations.data && <PaginationControls page={installations.data} onOffset={setOffset} />}</>}
    {(create.error || revoke.error) && <ErrorState error={create.error ?? revoke.error} />}
    <ActivationHandoffDialog activation={activation} onClose={() => setActivation(undefined)} />
    <TextField sx={{ display: 'none' }} aria-hidden label={t('reason')} value={reason} onChange={event => setReason(event.target.value)} />
  </>;
}
