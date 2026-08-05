import { Button, Card, CardContent, Stack, TextField } from '@mui/material';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi, type Approval } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { ErrorState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';

export function ApprovalsPage() {
  const { t } = useTranslation();
  const session = useSession();
  const [connectorId, setConnector] = useState('');
  const [version, setVersion] = useState('');
  const [comment, setComment] = useState('');
  const [offset, setOffset] = useState(0);
  const query = useQuery({ queryKey: ['approvals', connectorId, version, offset], queryFn: () => adminApi.approvals(connectorId, version, offset), enabled: Boolean(connectorId && version) });
  const request = useMutation({ mutationFn: () => adminApi.requestApproval(connectorId, version), onSuccess: () => query.refetch() });
  const approve = useMutation({ mutationFn: () => adminApi.approve(connectorId, version), onSuccess: () => query.refetch() });
  const reject = useMutation({ mutationFn: () => adminApi.reject(connectorId, version, comment), onSuccess: () => query.refetch() });
  const error = query.error ?? request.error ?? approve.error ?? reject.error;
  const canRequest = hasRole(session, 'ConnectorEditor', 'SecurityAdministrator');
  const canDecide = hasRole(session, 'ConnectorApprover', 'SecurityAdministrator');
  return <>
    <PageTitle title={t('approvals')} />
    <Card><CardContent>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}><TextField label={t('connectors')} value={connectorId} onChange={event => { setConnector(event.target.value); setOffset(0); }} /><TextField label={t('version')} value={version} onChange={event => { setVersion(event.target.value); setOffset(0); }} />{canDecide && <TextField label={t('decisionComment')} value={comment} slotProps={{ htmlInput: { maxLength: 500 } }} onChange={event => setComment(event.target.value)} />}{canRequest && <Button variant="outlined" disabled={!connectorId || !version} onClick={() => request.mutate()}>{t('requestApproval')}</Button>}{canDecide && <Button variant="contained" disabled={!connectorId || !version} onClick={() => approve.mutate()}>{t('approve')}</Button>}{canDecide && <Button color="error" disabled={!connectorId || !version} onClick={() => reject.mutate()}>{t('reject')}</Button>}</Stack>
      {query.data && <><DataTable rows={query.data.items} label={t('approvals')} columns={[{ key: 'status', label: t('status'), render: (value: Approval) => value.status }, { key: 'checksum', label: t('checksum'), render: value => value.checksumSha256.slice(0, 12) }, { key: 'requested', label: t('requestedBy'), render: value => value.requestedBy }]} /><PaginationControls page={query.data} onOffset={setOffset} /></>}
      {error && <ErrorState error={error} />}
    </CardContent></Card>
  </>;
}
