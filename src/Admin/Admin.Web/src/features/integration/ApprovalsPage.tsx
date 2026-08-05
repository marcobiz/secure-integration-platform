import { Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi, api } from '../../api/client';
import { ErrorState } from '../../components/AsyncState';
import { PageTitle } from '../../components/PageTitle';

export function ApprovalsPage() {
  const { t } = useTranslation(); const [connectorId, setConnector] = useState(''); const [version, setVersion] = useState(''); const [comment, setComment] = useState('');
  const query = useQuery({ queryKey: ['approvals', connectorId, version], queryFn: () => api<Array<Record<string, unknown>>>(`/admin/api/v1/connectors/${encodeURIComponent(connectorId)}/versions/${encodeURIComponent(version)}/approvals`), enabled: Boolean(connectorId && version) });
  const request = useMutation({ mutationFn: () => adminApi.requestApproval(connectorId, version), onSuccess: () => query.refetch() });
  const approve = useMutation({ mutationFn: () => adminApi.approve(connectorId, version), onSuccess: () => query.refetch() });
  const reject = useMutation({ mutationFn: () => adminApi.reject(connectorId, version, comment), onSuccess: () => query.refetch() });
  const error = query.error ?? request.error ?? approve.error ?? reject.error;
  return <><PageTitle title={t('approvals')} /><Card><CardContent><Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}><TextField label={t('connectors')} value={connectorId} onChange={event => setConnector(event.target.value)} /><TextField label={t('version')} value={version} onChange={event => setVersion(event.target.value)} /><TextField label={t('decisionComment')} value={comment} slotProps={{ htmlInput: { maxLength: 500 } }} onChange={event => setComment(event.target.value)} /><Button variant="outlined" disabled={!connectorId || !version} onClick={() => request.mutate()}>{t('requestApproval')}</Button><Button variant="contained" disabled={!connectorId || !version} onClick={() => approve.mutate()}>{t('approve')}</Button><Button color="error" disabled={!connectorId || !version} onClick={() => reject.mutate()}>{t('reject')}</Button></Stack>{query.data?.map(value => <Typography key={String(value.id)} sx={{ mt: 2 }}>{String(value.status)} · {String(value.checksumSha256)}</Typography>)}{error && <ErrorState error={error} />}</CardContent></Card></>;
}
