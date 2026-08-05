import { Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material';
import { useMutation } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { api } from '../../api/client';
import { ErrorState } from '../../components/AsyncState'; import { PageTitle } from '../../components/PageTitle';

interface BindingForm { connectorId: string; environmentId: string; endpointId: string; endpoint: string; secretId: string; secretReference: string }
export function BindingsPage() {
  const { t } = useTranslation(); const form = useForm<BindingForm>(); const save = useMutation({ mutationFn: (value: BindingForm) => api(`/admin/api/v1/connectors/${encodeURIComponent(value.connectorId)}/bindings`, { method: 'PUT', body: JSON.stringify({ environmentId: value.environmentId, endpoints: { [value.endpointId]: value.endpoint }, secretReferences: { [value.secretId]: value.secretReference } }) }) });
  return <><PageTitle title={t('bindings')} /><Card><CardContent><Typography color="text.secondary" sx={{ mb: 2 }}>{t('bindingsHelp')}</Typography><form onSubmit={form.handleSubmit(value => save.mutate(value))}><Stack spacing={2}><TextField label={t('connectors')} {...form.register('connectorId', { required: true })} /><TextField label={t('environment')} {...form.register('environmentId', { required: true })} /><TextField label={t('endpointBinding')} {...form.register('endpointId', { required: true })} /><TextField label={t('endpoint')} type="url" {...form.register('endpoint', { required: true })} /><TextField label={t('secretBinding')} {...form.register('secretId', { required: true })} /><TextField label={t('secretReference')} helperText={t('secretNeverShown')} {...form.register('secretReference', { required: true })} /><Button type="submit" variant="contained">{t('save')}</Button></Stack></form>{save.isSuccess && <Typography role="status" color="success.main" sx={{ mt: 2 }}>{t('saved')}</Typography>}{save.error && <ErrorState error={save.error} />}</CardContent></Card></>;
}
