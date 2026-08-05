import { Button, Card, CardContent, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from '@mui/material';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi, type Approval, type ConnectorBinding } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { ErrorState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';
import { diffCanonicalJson } from '../connectors/canonicalJsonDiff';

export function ApprovalsPage() {
  const { t } = useTranslation();
  const session = useSession();
  const [connectorId, setConnector] = useState('');
  const [version, setVersion] = useState('');
  const [comment, setComment] = useState('');
  const [offset, setOffset] = useState(0);
  const enabled = Boolean(connectorId && version);
  const query = useQuery({ queryKey: ['approvals', connectorId, version, offset], queryFn: () => adminApi.approvals(connectorId, version, offset), enabled });
  const versions = useQuery({ queryKey: ['approval-versions', connectorId], queryFn: () => adminApi.connectorVersions(connectorId, 0, 100), enabled: Boolean(connectorId) });
  const targetDefinition = useQuery({ queryKey: ['approval-definition', connectorId, version], queryFn: () => adminApi.connectorDefinition(connectorId, version), enabled });
  const targetBindings = useQuery({ queryKey: ['approval-bindings', connectorId, version], queryFn: () => adminApi.bindings(connectorId, version, '', 0, 100), enabled });
  const publishedVersion = versions.data?.items.find(item => item.state === 'Published' && item.version !== version)?.version ?? '';
  const baseDefinition = useQuery({ queryKey: ['approval-definition', connectorId, publishedVersion], queryFn: () => adminApi.connectorDefinition(connectorId, publishedVersion), enabled: Boolean(publishedVersion) });
  const baseBindings = useQuery({ queryKey: ['approval-bindings', connectorId, publishedVersion], queryFn: () => adminApi.bindings(connectorId, publishedVersion, '', 0, 100), enabled: Boolean(publishedVersion) });
  const displayedApproval = useMemo(() => query.data?.items.find(item => item.status === 'Requested') ?? query.data?.items[0], [query.data]);
  const request = useMutation({ mutationFn: () => adminApi.requestApproval(connectorId, version), onSuccess: () => query.refetch() });
  const approve = useMutation({ mutationFn: () => {
    if (!displayedApproval) throw new Error('approval-digest-unavailable');
    return adminApi.approve(connectorId, version, displayedApproval.bindingDigestSha256);
  }, onSuccess: () => query.refetch() });
  const reject = useMutation({ mutationFn: () => adminApi.reject(connectorId, version, comment), onSuccess: () => query.refetch() });
  const error = query.error ?? versions.error ?? targetDefinition.error ?? targetBindings.error ?? baseDefinition.error ?? baseBindings.error ?? request.error ?? approve.error ?? reject.error;
  const canRequest = hasRole(session, 'ConnectorEditor', 'SecurityAdministrator');
  const canDecide = hasRole(session, 'ConnectorApprover', 'SecurityAdministrator');
  const definitionDiff = targetDefinition.data ? diffCanonicalJson(baseDefinition.data ?? {}, targetDefinition.data) : [];
  const bindingRows = bindingDiffRows(baseBindings.data?.items ?? [], targetBindings.data?.items ?? []);

  return <>
    <PageTitle title={t('approvals')} />
    <Card><CardContent>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
        <TextField label={t('connectors')} value={connectorId} onChange={event => { setConnector(event.target.value); setOffset(0); }} />
        <TextField label={t('version')} value={version} onChange={event => { setVersion(event.target.value); setOffset(0); }} />
        {canDecide && <TextField label={t('decisionComment')} value={comment} slotProps={{ htmlInput: { maxLength: 500 } }} onChange={event => setComment(event.target.value)} />}
        {canRequest && <Button variant="outlined" disabled={!enabled} onClick={() => request.mutate()}>{t('requestApproval')}</Button>}
        {canDecide && <Button variant="contained" disabled={!displayedApproval || displayedApproval.status !== 'Requested'} onClick={() => approve.mutate()}>{t('approve')}</Button>}
        {canDecide && <Button color="error" disabled={!enabled} onClick={() => reject.mutate()}>{t('reject')}</Button>}
      </Stack>
      {displayedApproval && <section aria-labelledby="approval-artifacts-title">
        <Typography id="approval-artifacts-title" variant="h2" sx={{ mt: 3 }}>{t('approvalArtifacts')}</Typography>
        <Typography><strong>{t('connectorChecksum')}:</strong> <code>{displayedApproval.checksumSha256}</code></Typography>
        <Typography><strong>{t('publicationDigest')}:</strong> <code data-testid="approval-publication-digest">{displayedApproval.bindingDigestSha256}</code></Typography>
        <Table size="small" aria-label={t('canonicalDiff')} sx={{ mt: 2 }}><TableHead><TableRow><TableCell>{t('change')}</TableCell><TableCell>{t('jsonPath')}</TableCell><TableCell>{t('oldValue')}</TableCell><TableCell>{t('newValue')}</TableCell></TableRow></TableHead><TableBody>
          {[...definitionDiff, ...bindingRows].map((change, index) => <TableRow key={`${change.kind}-${change.path}-${index}`}><TableCell>{t(change.kind)}</TableCell><TableCell><code>{change.path}</code></TableCell><TableCell><code>{change.oldValue ?? '—'}</code></TableCell><TableCell><code>{change.newValue ?? '—'}</code></TableCell></TableRow>)}
        </TableBody></Table>
      </section>}
      {query.data && <><DataTable rows={query.data.items} label={t('approvals')} columns={[{ key: 'status', label: t('status'), render: (value: Approval) => value.status }, { key: 'checksum', label: t('checksum'), render: value => value.checksumSha256.slice(0, 12) }, { key: 'requested', label: t('requestedBy'), render: value => value.requestedBy }]} /><PaginationControls page={query.data} onOffset={setOffset} /></>}
      {error && <ErrorState error={error} />}
    </CardContent></Card>
  </>;
}

function bindingDiffRows(base: ConnectorBinding[], target: ConnectorBinding[]) {
  const before = new Map(base.map(value => [value.environmentId, value]));
  const after = new Map(target.map(value => [value.environmentId, value]));
  const rows: Array<{ kind: 'added' | 'removed' | 'changed'; path: string; oldValue?: string; newValue?: string }> = [];
  for (const environmentId of [...new Set([...before.keys(), ...after.keys()])].sort()) {
    const oldBinding = before.get(environmentId);
    const newBinding = after.get(environmentId);
    const parts = [
      ['endpoints', oldBinding?.endpoints, newBinding?.endpoints, oldBinding?.endpointChecksumSha256, newBinding?.endpointChecksumSha256],
      ['secrets', oldBinding?.secretReferences, newBinding?.secretReferences, oldBinding?.secretChecksumSha256, newBinding?.secretChecksumSha256],
      ['certificates', oldBinding?.certificateReferences, newBinding?.certificateReferences, oldBinding?.certificateChecksumSha256, newBinding?.certificateChecksumSha256],
    ] as const;
    for (const [part, oldValues, newValues, oldChecksum, newChecksum] of parts) {
      for (const name of [...new Set([...Object.keys(oldValues ?? {}), ...Object.keys(newValues ?? {})])].sort()) {
        const existed = Object.hasOwn(oldValues ?? {}, name);
        const exists = Object.hasOwn(newValues ?? {}, name);
        if (existed && exists && oldChecksum === newChecksum && oldBinding?.revision === newBinding?.revision) continue;
        const redacted = (binding: ConnectorBinding | undefined, checksum: string | undefined) => binding ? `[REDACTED] (revision ${binding.revision}, checksum ${checksum})` : undefined;
        rows.push({ kind: !existed ? 'added' : !exists ? 'removed' : 'changed', path: `/bindings/${environmentId}/${part}/${name}`, oldValue: redacted(oldBinding, oldChecksum), newValue: redacted(newBinding, newChecksum) });
      }
    }
  }
  return rows;
}
