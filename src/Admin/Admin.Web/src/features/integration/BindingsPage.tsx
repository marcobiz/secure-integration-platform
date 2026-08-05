import { Alert, Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { adminApi, type ConnectorBinding, type ConnectorBindingRequest } from '../../api/client';
import { ErrorState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';
import { useFormDirty } from '../../navigation/DirtyStateContext';

export interface BindingForm { connectorId: string; connectorVersion: string; environmentId: string; endpointsJson: string; secretReferencesJson: string; certificateReferencesJson: string }
const defaults: BindingForm = { connectorId: '', connectorVersion: '', environmentId: '', endpointsJson: '{}', secretReferencesJson: '{}', certificateReferencesJson: '{}' };

export function parseBindingMap(value: string, field: string): Record<string, string> {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error(`${field} must be valid JSON.`); }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error(`${field} must be a JSON object.`);
  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.length === 0) return {};
  if (entries.some(([key, item]) => !key.trim() || typeof item !== 'string' || !item.trim())) throw new Error(`${field} must map non-empty logical names to non-empty strings.`);
  return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right, 'en'))) as Record<string, string>;
}

export function buildBindingRequest(value: BindingForm): ConnectorBindingRequest {
  return { environmentId: value.environmentId, connectorVersion: value.connectorVersion, endpoints: parseBindingMap(value.endpointsJson, 'Endpoints'), secretReferences: parseBindingMap(value.secretReferencesJson, 'Secret references'), certificateReferences: parseBindingMap(value.certificateReferencesJson, 'Certificate references') };
}

export function BindingsPage() {
  const { t } = useTranslation();
  const cache = useQueryClient();
  const form = useForm<BindingForm>({ defaultValues: defaults });
  const [connectorId = '', connectorVersion = '', environmentId = ''] = useWatch({ control: form.control, name: ['connectorId', 'connectorVersion', 'environmentId'] });
  const [offset, setOffset] = useState(0);
  const summary = useRef<HTMLDivElement>(null);
  useFormDirty(form.formState.isDirty);
  const history = useQuery({ queryKey: ['bindings', connectorId, connectorVersion, environmentId, offset], queryFn: () => adminApi.bindings(connectorId, connectorVersion, environmentId, offset), enabled: Boolean(connectorId && connectorVersion && environmentId) });
  const currentRevision = history.data?.items[0]?.revision;
  const save = useMutation({
    mutationFn: (value: BindingForm) => adminApi.putBindings(value.connectorId, buildBindingRequest(value), currentRevision),
    onSuccess: async (_result, value) => { form.reset(value); await cache.invalidateQueries({ queryKey: ['bindings', connectorId, connectorVersion] }); },
  });
  useEffect(() => { if (save.error) summary.current?.focus(); }, [save.error]);
  const errorCount = Object.keys(form.formState.errors).length;
  useEffect(() => { if (form.formState.submitCount > 0 && errorCount > 0) summary.current?.focus(); }, [errorCount, form.formState.submitCount]);
  return <>
    <PageTitle title={t('bindings')} />
    <Card><CardContent><Typography id="binding-help" color="text.secondary" sx={{ mb: 2 }}>{t('bindingsHelp')} {t('bindingCompleteHelp')}</Typography><form onSubmit={form.handleSubmit(value => save.mutate(value))} noValidate><Stack spacing={2}>
      <TextField label={t('connectors')} slotProps={{ htmlInput: { 'aria-describedby': 'binding-help' } }} {...form.register('connectorId', { required: true })} error={Boolean(form.formState.errors.connectorId)} helperText={form.formState.errors.connectorId ? t('connectorRequired') : undefined} />
      <TextField label={t('version')} {...form.register('connectorVersion', { required: true })} error={Boolean(form.formState.errors.connectorVersion)} helperText={form.formState.errors.connectorVersion ? t('versionRequired') : undefined} />
      <TextField label={t('environment')} {...form.register('environmentId', { required: true })} error={Boolean(form.formState.errors.environmentId)} helperText={form.formState.errors.environmentId ? t('environmentRequired') : undefined} />
      <TextField multiline minRows={3} label={t('endpointsJsonLabel')} {...form.register('endpointsJson', { required: true, validate: value => { try { parseBindingMap(value, 'Endpoints'); return true; } catch (error) { return (error as Error).message; } } })} error={Boolean(form.formState.errors.endpointsJson)} helperText={form.formState.errors.endpointsJson?.message ?? t('endpointsExample')} />
      <TextField multiline minRows={3} label={t('secretReferencesJsonLabel')} {...form.register('secretReferencesJson', { required: true, validate: value => { try { parseBindingMap(value, 'Secret references'); return true; } catch (error) { return (error as Error).message; } } })} error={Boolean(form.formState.errors.secretReferencesJson)} helperText={form.formState.errors.secretReferencesJson?.message ?? t('secretReferencesHelp')} />
      <TextField multiline minRows={3} label={t('certificateReferencesJsonLabel')} {...form.register('certificateReferencesJson', { required: true, validate: value => { try { parseBindingMap(value, 'Certificate references'); return true; } catch (error) { return (error as Error).message; } } })} error={Boolean(form.formState.errors.certificateReferencesJson)} helperText={form.formState.errors.certificateReferencesJson?.message ?? t('certificateReferencesHelp')} />
      <Button type="submit" variant="contained">{t('save')}</Button>
    </Stack></form>
    {(Object.keys(form.formState.errors).length > 0 || save.error) && <Alert ref={summary} tabIndex={-1} severity="error" role="alert" aria-live="assertive" sx={{ mt: 2 }}>{t('bindingSaveFailed')}{save.error && <ErrorState error={save.error} />}</Alert>}
    {save.isSuccess && <Typography role="status" color="success.main" sx={{ mt: 2 }}>{t('saved')}</Typography>}</CardContent></Card>
    {history.data && <Card sx={{ mt: 3 }}><CardContent><DataTable rows={history.data.items} label={t('bindings')} columns={[{ key: 'revision', label: t('revision'), render: (value: ConnectorBinding) => value.revision }, { key: 'state', label: t('status'), render: value => value.state }, { key: 'checksum', label: t('checksum'), render: value => value.checksumSha256.slice(0, 12) }]} /><PaginationControls page={history.data} onOffset={setOffset} /></CardContent></Card>}
    {history.error && <ErrorState error={history.error} />}
  </>;
}
