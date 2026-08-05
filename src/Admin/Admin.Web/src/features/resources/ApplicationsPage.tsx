import { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { adminApi, type Application } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { DataTable } from '../../components/DataTable'; import { ErrorState, LoadingState } from '../../components/AsyncState'; import { PageTitle } from '../../components/PageTitle';

export function ApplicationsPage() {
  const { t } = useTranslation(); const session = useSession(); const cache = useQueryClient(); const [open, setOpen] = useState(false); const form = useForm<{ code: string; displayName: string; minimumBrokerVersion: string }>({ defaultValues: { minimumBrokerVersion: '3.0.0' } });
  const query = useQuery({ queryKey: ['applications'], queryFn: adminApi.applications }); const create = useMutation({ mutationFn: adminApi.createApplication, onSuccess: async () => { setOpen(false); form.reset(); await cache.invalidateQueries({ queryKey: ['applications'] }); } });
  if (query.isPending) return <LoadingState />; if (query.error) return <ErrorState error={query.error} retry={() => void query.refetch()} />;
  const columns = [{ key: 'code', label: t('code'), render: (row: Application) => row.code }, { key: 'name', label: t('name'), render: (row: Application) => row.displayName }, { key: 'version', label: t('minimumBrokerVersion'), render: (row: Application) => row.minimumBrokerVersion }, { key: 'status', label: t('status'), render: (row: Application) => row.status }];
  return <><PageTitle title={t('applications')} action={hasRole(session, 'SecurityAdministrator') ? <Button variant="contained" onClick={() => setOpen(true)}>{t('addApplication')}</Button> : undefined} /><DataTable rows={query.data.items ?? []} columns={columns} label={t('applications')} /><Dialog open={open} onClose={() => setOpen(false)}><form onSubmit={form.handleSubmit(value => create.mutate(value))}><DialogTitle>{t('addApplication')}</DialogTitle><DialogContent><Stack spacing={2} sx={{ mt: 1 }}><TextField label={t('code')} {...form.register('code', { required: true })} /><TextField label={t('name')} {...form.register('displayName', { required: true })} /><TextField label={t('minimumBrokerVersion')} {...form.register('minimumBrokerVersion', { required: true, pattern: /^\d+\.\d+\.\d+$/ })} /></Stack>{create.error && <ErrorState error={create.error} />}</DialogContent><DialogActions><Button onClick={() => setOpen(false)}>{t('cancel')}</Button><Button type="submit" variant="contained">{t('create')}</Button></DialogActions></form></Dialog></>;
}
