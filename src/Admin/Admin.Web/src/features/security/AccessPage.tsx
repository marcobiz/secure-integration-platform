import { Alert, Button, Card, CardContent, FormControl, InputLabel, MenuItem, Select, Stack, TextField } from '@mui/material';
import { useMutation } from '@tanstack/react-query';
import { useForm, useWatch } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { adminApi } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { ErrorState } from '../../components/AsyncState';
import { PageTitle } from '../../components/PageTitle';

type Form = { issuer: string; subject: string; displayName: string; role: string; tenantId: string };
const roles = ['Viewer', 'ConnectorEditor', 'ConnectorApprover', 'Operator', 'SecurityAdministrator'] as const;

export function AccessPage() {
  const { t } = useTranslation(); const session = useSession(); const form = useForm<Form>({ defaultValues: { issuer: '', subject: '', displayName: '', role: 'Viewer', tenantId: '' } });
  const selectedRole = useWatch({ control: form.control, name: 'role' });
  const assign = useMutation({ mutationFn: (value: Form) => adminApi.assignRole({ principal: { issuer: value.issuer, subject: value.subject, displayName: value.displayName }, role: value.role, tenantId: value.tenantId || null }) });
  if (!hasRole(session, 'SecurityAdministrator')) return <><PageTitle title={t('access')} /><Alert severity="error">{t('forbidden')}</Alert></>;
  return <><PageTitle title={t('access')} /><Card><CardContent><form onSubmit={form.handleSubmit(value => assign.mutate(value))}><Stack spacing={2}><TextField label={t('issuer')} {...form.register('issuer', { required: true, pattern: /^https:\/\//, maxLength: 512 })} error={Boolean(form.formState.errors.issuer)} /><TextField label={t('subject')} {...form.register('subject', { required: true, maxLength: 256 })} error={Boolean(form.formState.errors.subject)} /><TextField label={t('name')} {...form.register('displayName', { required: true, maxLength: 256 })} error={Boolean(form.formState.errors.displayName)} /><FormControl><InputLabel id="admin-role">{t('role')}</InputLabel><Select labelId="admin-role" label={t('role')} value={selectedRole} onChange={event => form.setValue('role', event.target.value)}>{roles.map(role => <MenuItem key={role} value={role}>{role}</MenuItem>)}</Select></FormControl><TextField label={t('optionalTenantScope')} {...form.register('tenantId')} /><Button type="submit" variant="contained">{t('assignRole')}</Button>{assign.isSuccess && <span role="status">{t('saved')}</span>}{assign.error && <ErrorState error={assign.error} />}</Stack></form></CardContent></Card></>;
}
