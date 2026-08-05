import { useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { adminApi, type Tenant } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { DataTable } from '../../components/DataTable';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';
import { useFormDirty } from '../../navigation/DirtyStateContext';

export function TenantsPage() {
  const { t, i18n } = useTranslation(); const session = useSession(); const client = useQueryClient(); const [open, setOpen] = useState(false); const [offset, setOffset] = useState(0); const form = useForm<{ code: string; displayName: string }>();
  useFormDirty(open && form.formState.isDirty);
  const query = useQuery({ queryKey: ['tenants', offset], queryFn: () => adminApi.tenants(offset) }); const create = useMutation({ mutationFn: adminApi.createTenant, onSuccess: async () => { setOpen(false); form.reset(); await client.invalidateQueries({ queryKey: ['tenants'] }); } });
  if (query.isPending) return <LoadingState />; if (query.error) return <ErrorState error={query.error} retry={() => void query.refetch()} />;
  const columns = [{ key: 'code', label: t('code'), render: (row: Tenant) => row.code }, { key: 'name', label: t('name'), render: (row: Tenant) => row.displayName }, { key: 'status', label: t('status'), render: (row: Tenant) => row.status }, { key: 'created', label: t('created'), render: (row: Tenant) => new Intl.DateTimeFormat(i18n.language).format(new Date(row.createdAt)) }];
  return <><PageTitle title={t('tenants')} action={hasRole(session, 'SecurityAdministrator') ? <Button variant="contained" onClick={() => setOpen(true)}>{t('addTenant')}</Button> : undefined} /><DataTable rows={query.data.items ?? []} columns={columns} label={t('tenants')} /><PaginationControls page={query.data} onOffset={setOffset} /><Dialog open={open} onClose={() => setOpen(false)}><form onSubmit={form.handleSubmit(value => create.mutate(value))} noValidate><DialogTitle>{t('addTenant')}</DialogTitle><DialogContent><Stack spacing={2} sx={{ mt: 1 }}><TextField label={t('code')} {...form.register('code', { required: true, maxLength: 64, pattern: /^[A-Za-z0-9_.-]+$/ })} error={Boolean(form.formState.errors.code)} helperText={form.formState.errors.code ? 'Use 1–64 letters, digits, dot, dash or underscore.' : 'Stable tenant code.'} /><TextField label={t('name')} {...form.register('displayName', { required: true, maxLength: 256 })} error={Boolean(form.formState.errors.displayName)} helperText={form.formState.errors.displayName ? 'Display name is required.' : 'Human-readable tenant name.'} /></Stack>{Object.keys(form.formState.errors).length > 0 && <Alert severity="error" tabIndex={-1} sx={{ mt: 2 }}>Tenant was not created. Correct the identified fields.</Alert>}{create.error && <ErrorState error={create.error} />}</DialogContent><DialogActions><Button onClick={() => { form.reset(); setOpen(false); }}>{t('cancel')}</Button><Button type="submit" variant="contained">{t('create')}</Button></DialogActions></form></Dialog></>;
}
