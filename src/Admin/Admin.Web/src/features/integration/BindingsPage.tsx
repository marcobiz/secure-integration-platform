import { Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { adminApi, type ConnectorBinding } from '../../api/client';
import { ErrorState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';

interface BindingForm { connectorId: string; connectorVersion: string; environmentId: string; endpointId: string; endpoint: string; secretId: string; secretReference: string; certificateId: string; certificateReference: string }

export function BindingsPage() {
  const { t } = useTranslation();
  const cache = useQueryClient();
  const form = useForm<BindingForm>();
  const [connectorId = '', connectorVersion = '', environmentId = ''] = useWatch({ control: form.control, name: ['connectorId', 'connectorVersion', 'environmentId'] });
  const [offset, setOffset] = useState(0);
  const history = useQuery({ queryKey: ['bindings', connectorId, connectorVersion, environmentId, offset], queryFn: () => adminApi.bindings(connectorId, connectorVersion, environmentId, offset), enabled: Boolean(connectorId && connectorVersion) });
  const currentRevision = history.data?.items[0]?.revision;
  const save = useMutation({
    mutationFn: (value: BindingForm) => adminApi.putBindings(value.connectorId, {
      environmentId: value.environmentId,
      connectorVersion: value.connectorVersion,
      endpoints: { [value.endpointId]: value.endpoint },
      secretReferences: { [value.secretId]: value.secretReference },
      certificateReferences: { [value.certificateId]: value.certificateReference },
    }, currentRevision),
    onSuccess: async () => cache.invalidateQueries({ queryKey: ['bindings', connectorId, connectorVersion] }),
  });
  return <>
    <PageTitle title={t('bindings')} />
    <Card><CardContent><Typography color="text.secondary" sx={{ mb: 2 }}>{t('bindingsHelp')}</Typography><form onSubmit={form.handleSubmit(value => save.mutate(value))}><Stack spacing={2}><TextField label={t('connectors')} {...form.register('connectorId', { required: true })} /><TextField label={t('version')} {...form.register('connectorVersion', { required: true })} /><TextField label={t('environment')} {...form.register('environmentId', { required: true })} /><TextField label={t('endpointBinding')} {...form.register('endpointId', { required: true })} /><TextField label={t('endpoint')} type="url" {...form.register('endpoint', { required: true })} /><TextField label={t('secretBinding')} {...form.register('secretId', { required: true })} /><TextField label={t('secretReference')} helperText={t('secretNeverShown')} {...form.register('secretReference', { required: true })} /><TextField label="Certificate binding" {...form.register('certificateId', { required: true })} /><TextField label="Certificate reference" helperText={t('secretNeverShown')} {...form.register('certificateReference', { required: true })} /><Button type="submit" variant="contained">{t('save')}</Button></Stack></form>{save.isSuccess && <Typography role="status" color="success.main" sx={{ mt: 2 }}>{t('saved')}</Typography>}{save.error && <ErrorState error={save.error} />}</CardContent></Card>
    {history.data && <Card sx={{ mt: 3 }}><CardContent><DataTable rows={history.data.items} label={t('bindings')} columns={[{ key: 'revision', label: t('revision'), render: (value: ConnectorBinding) => value.revision }, { key: 'state', label: t('status'), render: value => value.state }, { key: 'checksum', label: t('checksum'), render: value => value.checksumSha256.slice(0, 12) }]} /><PaginationControls page={history.data} onOffset={setOffset} /></CardContent></Card>}
    {history.error && <ErrorState error={history.error} />}
  </>;
}
