import { Alert, Button, Card, CardContent, Chip, Divider, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi, type Approval } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { ErrorState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';
import { runtimeLabel } from '../../i18n/runtimeValues';

function endpointDestination(endpoint: { scheme: string; hostname: string; port: number; path: string; query: string }): string {
  return `${endpoint.scheme}://${endpoint.hostname}:${endpoint.port}${endpoint.path}${endpoint.query}`;
}

export function ApprovalsPage() {
  const { t } = useTranslation();
  const session = useSession();
  const client = useQueryClient();
  const [connectorId, setConnector] = useState('');
  const [version, setVersion] = useState('');
  const [comment, setComment] = useState('');
  const [offset, setOffset] = useState(0);
  const enabled = Boolean(connectorId && version);
  const query = useQuery({ queryKey: ['approvals', connectorId, version, offset], queryFn: () => adminApi.approvals(connectorId, version, offset), enabled });
  const review = useQuery({ queryKey: ['approval-review', connectorId, version], queryFn: () => adminApi.approvalReview(connectorId, version), enabled });
  const displayedApproval = useMemo(() => query.data?.items.find(item => item.status === 'Requested') ?? query.data?.items[0], [query.data]);
  const refresh = async () => {
    await Promise.all([
      client.invalidateQueries({ queryKey: ['approvals', connectorId, version] }),
      client.invalidateQueries({ queryKey: ['approval-review', connectorId, version] })
    ]);
  };
  const request = useMutation({ mutationFn: () => adminApi.requestApproval(connectorId, version), onSuccess: refresh });
  const approve = useMutation({ mutationFn: () => {
    if (!displayedApproval || !review.data) throw new Error('approval-digest-unavailable');
    return adminApi.approve(connectorId, version, displayedApproval.id, review.data.digestSha256, comment);
  }, onSuccess: refresh });
  const reject = useMutation({ mutationFn: () => adminApi.reject(connectorId, version, comment), onSuccess: refresh });
  const error = query.error ?? review.error ?? request.error ?? approve.error ?? reject.error;
  const canRequest = hasRole(session, 'ConnectorEditor', 'SecurityAdministrator');
  const canDecide = hasRole(session, 'ConnectorApprover', 'SecurityAdministrator');

  return <>
    <PageTitle title={t('approvals')} />
    <Card><CardContent>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
        <TextField label={t('connectors')} value={connectorId} onChange={event => { setConnector(event.target.value); setOffset(0); }} />
        <TextField label={t('version')} value={version} onChange={event => { setVersion(event.target.value); setOffset(0); }} />
        {canDecide && <TextField label={t('decisionComment')} value={comment} slotProps={{ htmlInput: { maxLength: 500 } }} onChange={event => setComment(event.target.value)} />}
        {canRequest && <Button variant="outlined" disabled={!enabled} onClick={() => request.mutate()}>{t('requestApproval')}</Button>}
        {canDecide && <Button variant="contained" disabled={!displayedApproval || displayedApproval.status !== 'Requested' || !review.data} onClick={() => approve.mutate()}>{t('approve')}</Button>}
        {canDecide && <Button color="error" disabled={!enabled} onClick={() => reject.mutate()}>{t('reject')}</Button>}
      </Stack>
      {review.data && <section aria-labelledby="approval-artifacts-title">
        <Typography id="approval-artifacts-title" variant="h2" sx={{ mt: 3 }}>{t('approvalArtifacts')}</Typography>
        <Typography><strong>{t('connector')}:</strong> {review.data.artifact.connector.displayName} ({review.data.artifact.connector.connectorId})</Typography>
        <Typography><strong>{t('version')}:</strong> {review.data.artifact.connector.version}</Typography>
        <Typography><strong>{t('connectorChecksum')}:</strong> <code>{review.data.artifact.connector.canonicalDefinitionChecksumSha256}</code></Typography>
        <Typography><strong>{t('publicationDigest')}:</strong> <code data-testid="approval-publication-digest">{review.data.digestSha256}</code></Typography>
        <Stack spacing={2} sx={{ mt: 2 }}>
          {review.data.riskIndicators.map(risk => <Alert key={`${risk.code}-${risk.path}`} severity={risk.severity === 'high' ? 'error' : 'warning'}>
            <strong>{t(`risk.${risk.code}`)}:</strong> <code>{risk.path}</code>
          </Alert>)}
          {review.data.artifact.operations.map(operation => {
            const destination = endpointDestination(operation.endpoint);
            const credential = operation.secretBindings[0];
            return <Card variant="outlined" key={`${operation.environment}-${operation.operationId}`} data-testid="approval-operation-review"><CardContent>
              <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}><Chip label={`${t('operation')}: ${operation.operationId}`} /><Chip label={`${t('environment')}: ${operation.environment}`} /><Chip label={t(`destination.${operation.endpoint.destinationClassification}`)} /></Stack>
              <Typography sx={{ mt: 1 }}><strong>{t('effectiveDestination')}:</strong> {destination}</Typography>
              <Typography><strong>{t('allowedMethods')}:</strong> {operation.endpoint.allowedMethods.join(', ')}</Typography>
              <Typography><strong>{t('redirectPolicy')}:</strong> {operation.endpoint.redirectPolicy}; <strong>{t('tlsPolicy')}:</strong> {operation.endpoint.tlsPolicy}</Typography>
              {credential && <Typography data-testid="approval-semantic-sentence">{t('approvalSemanticSentence', { credential: credential.logicalBindingId, destination, method: operation.endpoint.allowedMethods.join(', ') })}</Typography>}
              {operation.authorityEndpoints.map(authority => {
                const authorityDestination = endpointDestination(authority.endpoint);
                return <Card variant="outlined" key={`${authority.role}-${authority.endpoint.logicalBindingId}`} sx={{ mt: 2 }} data-testid="approval-authority-endpoint-review"><CardContent>
                  <Typography variant="h3">{t('authorityEndpoint')}: {t(`authorityRole.${authority.role}`)}</Typography>
                  <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: 'wrap' }}><Chip label={t(`destination.${authority.endpoint.destinationClassification}`)} /><Chip label={`${t('allowedMethods')}: ${authority.endpoint.allowedMethods.join(', ')}`} /></Stack>
                  <Typography><strong>{t('logicalEndpoint')}:</strong> {authority.endpoint.logicalBindingId}</Typography>
                  <Typography><strong>{t('effectiveDestination')}:</strong> {authorityDestination}</Typography>
                  <Typography><strong>{t('hostname')}:</strong> {authority.endpoint.hostname}; <strong>{t('port')}:</strong> {authority.endpoint.port}</Typography>
                  <Typography><strong>{t('path')}:</strong> {authority.endpoint.path}; <strong>{t('query')}:</strong> {authority.endpoint.query || t('none')}</Typography>
                  <Typography><strong>{t('redirectPolicy')}:</strong> {authority.endpoint.redirectPolicy}; <strong>{t('tlsPolicy')}:</strong> {authority.endpoint.tlsPolicy}</Typography>
                  <Typography><strong>{t('bindingRevision')}:</strong> {authority.endpoint.bindingRevision}; <strong>{t('endpointChecksum')}:</strong> <code>{authority.endpoint.endpointChecksumSha256}</code>; <strong>{t('bindingChecksum')}:</strong> <code>{authority.endpoint.bindingChecksumSha256}</code></Typography>
                </CardContent></Card>;
              })}
              {operation.secretBindings.map(secret => <Stack key={secret.logicalBindingId} sx={{ mt: 1 }}>
                <Typography><strong>{t('logicalCredential')}:</strong> {secret.logicalBindingId}</Typography>
                <Typography><strong>{t('provider')}:</strong> {secret.providerDisplayName} ({secret.providerType}:{secret.providerId})</Typography>
                <Typography><strong>{t('logicalResource')}:</strong> {secret.resourceLogicalId} ({secret.resourceType})</Typography>
                <Typography><strong>{t('resourceVersion')}:</strong> {secret.resourceVersion ?? '—'}; <strong>{t('catalogRevision')}:</strong> {secret.catalogRevision}; <strong>{t('publicMetadataRevision')}:</strong> {secret.publicMetadataRevision ?? '—'}</Typography>
                <Typography><strong>{t('bindingRevision')}:</strong> {secret.bindingRevision}; <strong>{t('environment')}:</strong> {secret.environment}</Typography>
                <Typography><strong>{t('scope')}:</strong> {secret.connectorScope}/{secret.operationScope}</Typography>
                <Typography><strong>{t('catalogChecksum')}:</strong> <code>{secret.catalogChecksumSha256}</code></Typography>
                <Typography><strong>{t('resourceBindingChecksum')}:</strong> <code>{secret.resourceBindingChecksumSha256}</code></Typography>
                <Typography><strong>{t('bindingChecksum')}:</strong> <code>{secret.bindingChecksumSha256}</code></Typography>
              </Stack>)}
              {operation.certificateBindings.map(certificate => <Stack key={certificate.logicalBindingId} sx={{ mt: 1 }}>
                <Typography><strong>{t('certificate')}:</strong> {certificate.certificateLogicalId} ({certificate.resourceType})</Typography>
                <Typography><strong>{t('provider')}:</strong> {certificate.providerDisplayName} ({certificate.providerType}:{certificate.providerId})</Typography>
                <Typography><strong>{t('resourceVersion')}:</strong> {certificate.resourceVersion ?? '—'}; <strong>{t('certificateVersion')}:</strong> {certificate.certificateVersion}</Typography>
                <Typography><strong>{t('catalogRevision')}:</strong> {certificate.catalogRevision}; <strong>{t('publicMetadataRevision')}:</strong> {certificate.publicMetadataRevision}; <strong>{t('bindingRevision')}:</strong> {certificate.bindingRevision}</Typography>
                <Typography><strong>{t('fingerprint')}:</strong> <code>{certificate.publicFingerprintSha256}</code></Typography>
                <Typography><strong>{t('certificateSubject')}:</strong> {certificate.publicSubject}; <strong>{t('certificateIssuer')}:</strong> {certificate.publicIssuer}</Typography>
                <Typography><strong>{t('certificateValidity')}:</strong> {certificate.notBefore} – {certificate.expiresAt}; <strong>{t('publicKey')}:</strong> {certificate.keyAlgorithm} {certificate.publicKeySize}</Typography>
                <Typography><strong>{t('catalogChecksum')}:</strong> <code>{certificate.catalogChecksumSha256}</code></Typography>
                <Typography><strong>{t('resourceBindingChecksum')}:</strong> <code>{certificate.resourceBindingChecksumSha256}</code></Typography>
                <Typography><strong>{t('bindingChecksum')}:</strong> <code>{certificate.bindingChecksumSha256}</code></Typography>
              </Stack>)}
              <Divider sx={{ my: 1 }} />
              <Typography><strong>{t('bindingRevision')}:</strong> {operation.endpoint.bindingRevision}; <strong>{t('endpointChecksum')}:</strong> <code>{operation.endpoint.endpointChecksumSha256}</code>; <strong>{t('bindingChecksum')}:</strong> <code>{operation.endpoint.bindingChecksumSha256}</code></Typography>
            </CardContent></Card>;
          })}
        </Stack>
        <Typography variant="h3" sx={{ mt: 3 }}>{t('canonicalDiff')}</Typography>
        <Table size="small" aria-label={t('canonicalDiff')}><TableHead><TableRow><TableCell>{t('change')}</TableCell><TableCell>{t('jsonPath')}</TableCell><TableCell>{t('oldValue')}</TableCell><TableCell>{t('newValue')}</TableCell></TableRow></TableHead><TableBody>
          {review.data.diff.map((change, index) => <TableRow key={`${change.change}-${change.path}-${index}`}><TableCell>{t(change.change)}</TableCell><TableCell><code>{change.path}</code></TableCell><TableCell><code>{change.previousValue ?? '—'}</code></TableCell><TableCell><code>{change.currentValue ?? '—'}</code></TableCell></TableRow>)}
        </TableBody></Table>
      </section>}
      {query.data && <><DataTable rows={query.data.items} label={t('approvals')} columns={[{ key: 'status', label: t('status'), render: (value: Approval) => runtimeLabel(t, 'approval', value.status) }, { key: 'checksum', label: t('checksum'), render: value => value.checksumSha256.slice(0, 12) }, { key: 'requested', label: t('requestedBy'), render: value => value.requestedBy }]} /><PaginationControls page={query.data} onOffset={setOffset} /></>}
      {error && <ErrorState error={error} />}
    </CardContent></Card>
  </>;
}
