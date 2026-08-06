import { Alert, Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { adminApi, type ConnectorBinding, type ConnectorBindingRequest, type ProviderResourceCatalog } from '../../api/client';
import { ErrorState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';
import { useFormDirty } from '../../navigation/DirtyStateContext';
import { runtimeLabel } from '../../i18n/runtimeValues';

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

type ProviderResourceSelection = { providerId: string; resourceId: string; resourceType: 'Secret' | 'ClientCertificate'; version?: string | null; publicMetadataRevision?: number | null };

export function parseResourceMap(value: string, field: string, expectedType: ProviderResourceSelection['resourceType']): Record<string, ProviderResourceSelection> {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error(`${field} must be valid JSON.`); }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error(`${field} must be a JSON object.`);
  const entries = Object.entries(parsed as Record<string, unknown>);
  const result: Record<string, ProviderResourceSelection> = {};
  for (const [logicalId, candidate] of entries.sort(([left], [right]) => left.localeCompare(right, 'en'))) {
    if (!logicalId.trim() || !candidate || Array.isArray(candidate) || typeof candidate !== 'object') throw new Error(`${field} must select catalog resources.`);
    const resource = candidate as Record<string, unknown>;
    const allowed = new Set(['providerId', 'resourceId', 'resourceType', 'version', 'publicMetadataRevision']);
    if (Object.keys(resource).some(key => !allowed.has(key)) || typeof resource.providerId !== 'string' || typeof resource.resourceId !== 'string' || resource.resourceType !== expectedType) throw new Error(`${field} must select catalog resources.`);
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(resource.providerId) || !/^[A-Za-z0-9_.-]{1,128}$/.test(resource.resourceId)) throw new Error(`${field} contains an invalid logical identifier.`);
    result[logicalId] = { providerId: resource.providerId, resourceId: resource.resourceId, resourceType: expectedType, version: typeof resource.version === 'string' ? resource.version : null, publicMetadataRevision: typeof resource.publicMetadataRevision === 'number' ? resource.publicMetadataRevision : null };
  }
  return result;
}

export function buildBindingRequest(value: BindingForm): ConnectorBindingRequest {
  return { environmentId: value.environmentId, connectorVersion: value.connectorVersion, endpoints: parseBindingMap(value.endpointsJson, 'Endpoints'), secretResources: parseResourceMap(value.secretReferencesJson, 'Secret resources', 'Secret'), certificateResources: parseResourceMap(value.certificateReferencesJson, 'Certificate resources', 'ClientCertificate') };
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
  const resources = useQuery({ queryKey: ['provider-resources', environmentId], queryFn: () => adminApi.providerResources(environmentId), enabled: Boolean(environmentId) });
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
      {resources.data && <DataTable rows={resources.data.items} label={t('catalogResources')} columns={[
        { key: 'provider', label: t('provider'), render: (value: ProviderResourceCatalog) => value.providerId },
        { key: 'resource', label: t('resourceLogicalId'), render: value => value.resourceId },
        { key: 'type', label: t('type'), render: value => value.resourceType },
        { key: 'revision', label: t('revision'), render: value => value.revision }
      ]} />}
      <TextField multiline minRows={3} label={t('endpointsJsonLabel')} {...form.register('endpointsJson', { required: true, validate: value => { try { parseBindingMap(value, 'Endpoints'); return true; } catch (error) { return (error as Error).message; } } })} error={Boolean(form.formState.errors.endpointsJson)} helperText={form.formState.errors.endpointsJson?.message ?? t('endpointsExample')} />
      <TextField multiline minRows={3} label={t('secretReferencesJsonLabel')} {...form.register('secretReferencesJson', { required: true, validate: value => { try { parseResourceMap(value, 'Secret resources', 'Secret'); return true; } catch (error) { return (error as Error).message; } } })} error={Boolean(form.formState.errors.secretReferencesJson)} helperText={form.formState.errors.secretReferencesJson?.message ?? t('secretReferencesHelp')} />
      <TextField multiline minRows={3} label={t('certificateReferencesJsonLabel')} {...form.register('certificateReferencesJson', { required: true, validate: value => { try { parseResourceMap(value, 'Certificate resources', 'ClientCertificate'); return true; } catch (error) { return (error as Error).message; } } })} error={Boolean(form.formState.errors.certificateReferencesJson)} helperText={form.formState.errors.certificateReferencesJson?.message ?? t('certificateReferencesHelp')} />
      <Button type="submit" variant="contained">{t('save')}</Button>
    </Stack></form>
    {(Object.keys(form.formState.errors).length > 0 || save.error) && <Alert ref={summary} tabIndex={-1} severity="error" role="alert" aria-live="assertive" sx={{ mt: 2 }}>{t('bindingSaveFailed')}{save.error && <ErrorState error={save.error} />}</Alert>}
    {save.isSuccess && <Typography role="status" color="success.main" sx={{ mt: 2 }}>{t('saved')}</Typography>}</CardContent></Card>
    {history.data && <Card sx={{ mt: 3 }}><CardContent><DataTable rows={history.data.items} label={t('bindings')} columns={[{ key: 'revision', label: t('revision'), render: (value: ConnectorBinding) => value.revision }, { key: 'state', label: t('status'), render: value => runtimeLabel(t, 'status', value.state) }, { key: 'checksum', label: t('checksum'), render: value => value.checksumSha256.slice(0, 12) }]} /><PaginationControls page={history.data} onOffset={setOffset} /></CardContent></Card>}
    {history.error && <ErrorState error={history.error} />}
    {resources.error && <ErrorState error={resources.error} />}
  </>;
}
