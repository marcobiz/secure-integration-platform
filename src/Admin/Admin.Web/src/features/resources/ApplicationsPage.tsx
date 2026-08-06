import { useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { adminApi, ApiProblem, type Application } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { DataTable } from '../../components/DataTable'; import { ErrorState, LoadingState } from '../../components/AsyncState'; import { PageTitle } from '../../components/PageTitle';
import { ConflictComparison } from '../../components/ConflictComparison';
import { runtimeLabel } from '../../i18n/runtimeValues';
import { PaginationControls } from '../../components/PaginationControls'; import { useFormDirty } from '../../navigation/DirtyStateContext';

type ApplicationForm = { code: string; displayName: string; minimumBrokerVersion: string; maximumBrokerVersion?: string };

export function ApplicationsPage() {
  const { t } = useTranslation(); const session = useSession(); const cache = useQueryClient(); const [mode, setMode] = useState<'closed' | 'create' | 'edit'>('closed'); const [selected, setSelected] = useState<Application>(); const [current, setCurrent] = useState<Application>(); const [offset, setOffset] = useState(0);
  const form = useForm<ApplicationForm>({ defaultValues: { minimumBrokerVersion: '3.0.0' } }); useFormDirty(mode !== 'closed' && form.formState.isDirty);
  const query = useQuery({ queryKey: ['applications', offset], queryFn: () => adminApi.applications(offset) });
  const invalidate = async () => { setMode('closed'); setSelected(undefined); setCurrent(undefined); form.reset(); await cache.invalidateQueries({ queryKey: ['applications'] }); };
  const captureConflict = async (error: Error, row: Application) => { if (error instanceof ApiProblem && (error.status === 409 || error.status === 412)) setCurrent(await adminApi.application(row.id)); };
  const create = useMutation({ mutationFn: adminApi.createApplication, onSuccess: invalidate });
  const update = useMutation({ mutationFn: (value: ApplicationForm) => adminApi.updateApplication(selected!.id, { displayName: value.displayName, minimumBrokerVersion: value.minimumBrokerVersion, maximumBrokerVersion: value.maximumBrokerVersion || null }, selected!.rowVersion), onSuccess: invalidate, onError: error => captureConflict(error, selected!) });
  const disable = useMutation({ mutationFn: (row: Application) => adminApi.disableApplication(row.id, row.rowVersion), onSuccess: invalidate, onError: (error, row) => captureConflict(error, row) });
  if (query.isPending) return <LoadingState />; if (query.error) return <ErrorState error={query.error} retry={() => void query.refetch()} />;
  const beginCreate = () => { form.reset({ code: '', displayName: '', minimumBrokerVersion: '3.0.0', maximumBrokerVersion: '' }); setMode('create'); };
  const beginEdit = (row: Application) => { setSelected(row); setCurrent(undefined); form.reset({ code: row.code, displayName: row.displayName, minimumBrokerVersion: row.minimumBrokerVersion, maximumBrokerVersion: row.maximumBrokerVersion ?? '' }); setMode('edit'); };
  const columns = [{ key: 'code', label: t('code'), render: (row: Application) => row.code }, { key: 'name', label: t('name'), render: (row: Application) => row.displayName }, { key: 'version', label: t('minimumBrokerVersion'), render: (row: Application) => row.minimumBrokerVersion }, { key: 'status', label: t('status'), render: (row: Application) => runtimeLabel(t, 'status', row.status) }, ...(hasRole(session, 'SecurityAdministrator') ? [{ key: 'actions', label: t('action'), render: (row: Application) => <Stack direction="row"><Button onClick={() => beginEdit(row)}>{t('edit')}</Button><Button color="error" disabled={row.status !== 'Active'} onClick={() => disable.mutate(row)}>{t('disable')}</Button></Stack> }] : [])];
  return <><PageTitle title={t('applications')} action={hasRole(session, 'SecurityAdministrator') ? <Button variant="contained" onClick={beginCreate}>{t('addApplication')}</Button> : undefined} /><DataTable rows={query.data.items ?? []} columns={columns} label={t('applications')} /><PaginationControls page={query.data} onOffset={setOffset} />
    <Dialog open={mode !== 'closed'} onClose={() => setMode('closed')}><form onSubmit={form.handleSubmit(value => mode === 'create' ? create.mutate(value) : update.mutate(value))} noValidate><DialogTitle>{mode === 'create' ? t('addApplication') : t('editApplication')}</DialogTitle><DialogContent><Stack spacing={2} sx={{ mt: 1 }}>
      {current && selected && <Alert severity="warning" action={<Button onClick={() => beginEdit(current)}>{t('reloadCurrent')}</Button>}><Typography>{t('concurrencyConflict')}</Typography><ConflictComparison localRowVersion={selected.rowVersion} serverRowVersion={current.rowVersion} fields={[
        { label: t('name'), localValue: form.getValues('displayName'), serverValue: current.displayName },
        { label: t('minimumBrokerVersion'), localValue: form.getValues('minimumBrokerVersion'), serverValue: current.minimumBrokerVersion },
        { label: t('maximumBrokerVersion'), localValue: form.getValues('maximumBrokerVersion') ?? '', serverValue: current.maximumBrokerVersion ?? '' }
      ]} /></Alert>}
      <TextField label={t('code')} disabled={mode === 'edit'} {...form.register('code', { required: true })} error={Boolean(form.formState.errors.code)} helperText={form.formState.errors.code ? t('applicationCodeRequired') : t('applicationCodeHelp')} />
      <TextField label={t('name')} {...form.register('displayName', { required: true })} error={Boolean(form.formState.errors.displayName)} helperText={form.formState.errors.displayName ? t('displayNameRequired') : t('applicationNameHelp')} />
      <TextField label={t('minimumBrokerVersion')} {...form.register('minimumBrokerVersion', { required: true, pattern: /^\d+\.\d+\.\d+$/ })} error={Boolean(form.formState.errors.minimumBrokerVersion)} helperText={form.formState.errors.minimumBrokerVersion ? t('brokerVersionInvalid') : t('minimumBrokerVersionHelp')} />
      <TextField label={t('maximumBrokerVersion')} {...form.register('maximumBrokerVersion', { pattern: /^$|^\d+\.\d+\.\d+$/ })} error={Boolean(form.formState.errors.maximumBrokerVersion)} helperText={form.formState.errors.maximumBrokerVersion ? t('brokerVersionInvalid') : t('maximumBrokerVersionHelp')} />
    </Stack>{Object.keys(form.formState.errors).length > 0 && <Alert severity="error" tabIndex={-1} sx={{ mt: 2 }}>{t('applicationSaveFailed')}</Alert>}{(create.error || update.error) && !current && <ErrorState error={create.error ?? update.error} />}</DialogContent><DialogActions><Button onClick={() => { form.reset(); setMode('closed'); }}>{t('cancel')}</Button><Button type="submit" variant="contained" disabled={Boolean(current)}>{mode === 'create' ? t('create') : t('save')}</Button></DialogActions></form></Dialog></>;
}
