import { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { adminApi, type Tenant } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { DataTable } from '../../components/DataTable';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { PageTitle } from '../../components/PageTitle';

export function TenantsPage() {
  const { t, i18n } = useTranslation(); const session = useSession(); const client = useQueryClient(); const [open, setOpen] = useState(false); const form = useForm<{ code: string; displayName: string }>();
  const query = useQuery({ queryKey: ['tenants'], queryFn: () => adminApi.tenants() }); const create = useMutation({ mutationFn: adminApi.createTenant, onSuccess: async () => { setOpen(false); form.reset(); await client.invalidateQueries({ queryKey: ['tenants'] }); } });
  if (query.isPending) return <LoadingState />; if (query.error) return <ErrorState error={query.error} retry={() => void query.refetch()} />;
  const columns = [{ key: 'code', label: t('code'), render: (row: Tenant) => row.code }, { key: 'name', label: t('name'), render: (row: Tenant) => row.displayName }, { key: 'status', label: t('status'), render: (row: Tenant) => row.status }, { key: 'created', label: t('created'), render: (row: Tenant) => new Intl.DateTimeFormat(i18n.language).format(new Date(row.createdAt)) }];
  return <><PageTitle title={t('tenants')} action={hasRole(session, 'SecurityAdministrator') ? <Button variant="contained" onClick={() => setOpen(true)}>{t('addTenant')}</Button> : undefined} /><DataTable rows={query.data.items ?? []} columns={columns} label={t('tenants')} /><Dialog open={open} onClose={() => setOpen(false)}><form onSubmit={form.handleSubmit(value => create.mutate(value))}><DialogTitle>{t('addTenant')}</DialogTitle><DialogContent><Stack spacing={2} sx={{ mt: 1 }}><TextField label={t('code')} {...form.register('code', { required: true, maxLength: 64, pattern: /^[A-Za-z0-9_.-]+$/ })} error={Boolean(form.formState.errors.code)} /><TextField label={t('name')} {...form.register('displayName', { required: true, maxLength: 256 })} error={Boolean(form.formState.errors.displayName)} /></Stack>{create.error && <ErrorState error={create.error} />}</DialogContent><DialogActions><Button onClick={() => setOpen(false)}>{t('cancel')}</Button><Button type="submit" variant="contained">{t('create')}</Button></DialogActions></form></Dialog></>;
}
