import { useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { adminApi, ApiProblem, type Tenant } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { DataTable } from '../../components/DataTable';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';
import { useFormDirty } from '../../navigation/DirtyStateContext';

type TenantForm = { code: string; displayName: string };

export function TenantsPage() {
  const { t, i18n } = useTranslation(); const session = useSession(); const client = useQueryClient();
  const [mode, setMode] = useState<'closed' | 'create' | 'edit'>('closed'); const [selected, setSelected] = useState<Tenant>(); const [current, setCurrent] = useState<Tenant>(); const [offset, setOffset] = useState(0);
  const form = useForm<TenantForm>(); useFormDirty(mode !== 'closed' && form.formState.isDirty);
  const query = useQuery({ queryKey: ['tenants', offset], queryFn: () => adminApi.tenants(offset) });
  const invalidate = async () => { setMode('closed'); setSelected(undefined); setCurrent(undefined); form.reset(); await client.invalidateQueries({ queryKey: ['tenants'] }); };
  const captureConflict = async (error: Error, row: Tenant) => { if (error instanceof ApiProblem && (error.status === 409 || error.status === 412)) setCurrent(await adminApi.tenant(row.id)); };
  const create = useMutation({ mutationFn: adminApi.createTenant, onSuccess: invalidate });
  const update = useMutation({ mutationFn: async (value: TenantForm) => adminApi.updateTenant(selected!.id, { displayName: value.displayName }, selected!.rowVersion), onSuccess: invalidate, onError: error => captureConflict(error, selected!) });
  const disable = useMutation({ mutationFn: (row: Tenant) => adminApi.disableTenant(row.id, row.rowVersion), onSuccess: invalidate, onError: (error, row) => captureConflict(error, row) });
  if (query.isPending) return <LoadingState />; if (query.error) return <ErrorState error={query.error} retry={() => void query.refetch()} />;
  const beginCreate = () => { form.reset({ code: '', displayName: '' }); setMode('create'); };
  const beginEdit = (row: Tenant) => { setSelected(row); setCurrent(undefined); form.reset({ code: row.code, displayName: row.displayName }); setMode('edit'); };
  const columns = [
    { key: 'code', label: t('code'), render: (row: Tenant) => row.code }, { key: 'name', label: t('name'), render: (row: Tenant) => row.displayName },
    { key: 'status', label: t('status'), render: (row: Tenant) => row.status }, { key: 'created', label: t('created'), render: (row: Tenant) => new Intl.DateTimeFormat(i18n.language).format(new Date(row.createdAt)) },
    ...(hasRole(session, 'SecurityAdministrator') ? [{ key: 'actions', label: t('action'), render: (row: Tenant) => <Stack direction="row"><Button onClick={() => beginEdit(row)}>{t('edit')}</Button><Button color="error" disabled={row.status !== 'Active'} onClick={() => disable.mutate(row)}>{t('disable')}</Button></Stack> }] : [])
  ];
  return <><PageTitle title={t('tenants')} action={hasRole(session, 'SecurityAdministrator') ? <Button variant="contained" onClick={beginCreate}>{t('addTenant')}</Button> : undefined} />
    <DataTable rows={query.data.items ?? []} columns={columns} label={t('tenants')} /><PaginationControls page={query.data} onOffset={setOffset} />
    <Dialog open={mode !== 'closed'} onClose={() => setMode('closed')}><form onSubmit={form.handleSubmit(value => mode === 'create' ? create.mutate(value) : update.mutate(value))} noValidate>
      <DialogTitle>{mode === 'create' ? t('addTenant') : t('editTenant')}</DialogTitle><DialogContent><Stack spacing={2} sx={{ mt: 1 }}>
        {current && selected && <Alert severity="warning" action={<Button onClick={() => beginEdit(current)}>{t('reloadCurrent')}</Button>}>
          <Typography>{t('concurrencyConflict')}</Typography><Typography>{t('yourValue')}: {form.getValues('displayName')}</Typography><Typography>{t('currentValue')}: {current.displayName}</Typography>
        </Alert>}
        <TextField label={t('code')} disabled={mode === 'edit'} {...form.register('code', { required: true, maxLength: 64, pattern: /^[A-Za-z0-9_.-]+$/ })} error={Boolean(form.formState.errors.code)} helperText={form.formState.errors.code ? t('tenantCodeInvalid') : t('tenantCodeHelp')} />
        <TextField label={t('name')} {...form.register('displayName', { required: true, maxLength: 256 })} error={Boolean(form.formState.errors.displayName)} helperText={form.formState.errors.displayName ? t('displayNameRequired') : t('tenantNameHelp')} />
      </Stack>{Object.keys(form.formState.errors).length > 0 && <Alert severity="error" tabIndex={-1} sx={{ mt: 2 }}>{t('tenantSaveFailed')}</Alert>}{(create.error || update.error) && !current && <ErrorState error={create.error ?? update.error} />}</DialogContent>
      <DialogActions><Button onClick={() => { form.reset(); setMode('closed'); }}>{t('cancel')}</Button><Button type="submit" variant="contained">{mode === 'create' ? t('create') : t('save')}</Button></DialogActions>
    </form></Dialog></>;
}
