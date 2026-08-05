import { lazy, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, Chip, FormControl, InputLabel, MenuItem, Select, Stack, TextField, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { adminApi, type ConnectorSummary, type ConnectorVersion } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { DataTable } from '../../components/DataTable';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { PageTitle } from '../../components/PageTitle';
import { validateConnectorDefinition, type ConnectorValidationIssue } from './connectorDefinitionValidation';

const CodeMirror = lazy(() => import('@uiw/react-codemirror'));

function VersionComparison({ connectorId, versions }: { connectorId: string; versions: ConnectorVersion[] }) {
  const { t } = useTranslation();
  const [base, setBase] = useState('');
  const [target, setTarget] = useState('');
  const baseDefinition = useQuery({ queryKey: ['connector-definition', connectorId, base], queryFn: () => adminApi.connectorDefinition(connectorId, base), enabled: Boolean(base) });
  const targetDefinition = useQuery({ queryKey: ['connector-definition', connectorId, target], queryFn: () => adminApi.connectorDefinition(connectorId, target), enabled: Boolean(target) });

  return <Box sx={{ mt: 3 }}>
    <Typography variant="h3">{t('compareVersions')}</Typography>
    <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mt: 1 }}>
      <FormControl fullWidth><InputLabel id="base-version">{t('baseVersion')}</InputLabel><Select labelId="base-version" label={t('baseVersion')} value={base} onChange={event => setBase(event.target.value)}>{versions.map(value => <MenuItem key={value.version} value={value.version}>{value.version}</MenuItem>)}</Select></FormControl>
      <FormControl fullWidth><InputLabel id="target-version">{t('targetVersion')}</InputLabel><Select labelId="target-version" label={t('targetVersion')} value={target} onChange={event => setTarget(event.target.value)}>{versions.map(value => <MenuItem key={value.version} value={value.version}>{value.version}</MenuItem>)}</Select></FormControl>
    </Stack>
    {baseDefinition.data && targetDefinition.data && <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2} sx={{ mt: 2 }}>
      <Box component="pre" aria-label={t('baseVersion')} sx={{ flex: 1, overflow: 'auto', p: 2, bgcolor: 'action.hover' }}>{JSON.stringify(baseDefinition.data, null, 2)}</Box>
      <Box component="pre" aria-label={t('targetVersion')} sx={{ flex: 1, overflow: 'auto', p: 2, bgcolor: 'action.hover' }}>{JSON.stringify(targetDefinition.data, null, 2)}</Box>
    </Stack>}
    {(baseDefinition.error || targetDefinition.error) && <ErrorState error={baseDefinition.error ?? targetDefinition.error} />}
  </Box>;
}

export function ConnectorsPage() {
  const { t } = useTranslation();
  const session = useSession();
  const cache = useQueryClient();
  const [json, setJson] = useState('');
  const [editorChanged, setEditorChanged] = useState(false);
  const [selected, setSelected] = useState('');
  const [environmentId, setEnvironment] = useState('');
  const [operationId, setOperation] = useState('');
  const [testResult, setTestResult] = useState('');
  const [clientIssues, setClientIssues] = useState<ConnectorValidationIssue[]>([]);
  const [validation, setValidation] = useState<{ valid: boolean; checksumSha256: string | null; issues: ConnectorValidationIssue[] }>();

  const query = useQuery({ queryKey: ['connectors'], queryFn: adminApi.connectors });
  const versions = useQuery({ queryKey: ['connector-versions', selected], queryFn: () => adminApi.connectorVersions(selected), enabled: Boolean(selected) });
  const environments = useQuery({ queryKey: ['environments'], queryFn: () => adminApi.environments() });
  const schema = useQuery({ queryKey: ['connector-schema'], queryFn: adminApi.connectorSchema });
  const sample = useQuery({ queryKey: ['connector-sample'], queryFn: adminApi.connectorSample });

  const editorJson = editorChanged ? json : sample.data ? JSON.stringify(sample.data, null, 2) : '';

  const refresh = async () => {
    await Promise.all([cache.invalidateQueries({ queryKey: ['connectors'] }), cache.invalidateQueries({ queryKey: ['connector-versions', selected] })]);
  };
  const validate = useMutation({
    mutationFn: async () => {
      const parsed: unknown = JSON.parse(editorJson);
      if (!schema.data) throw new Error('connector-schema-unavailable');
      const issues = validateConnectorDefinition(schema.data, parsed);
      setClientIssues(issues);
      if (issues.length > 0) return { valid: false, checksumSha256: null, issues };
      return adminApi.validateConnector(parsed as object);
    },
    onSuccess: setValidation,
  });
  const importDraft = useMutation({
    mutationFn: async () => {
      if (!validation?.valid || !validation.checksumSha256) throw new Error('validation-required');
      return adminApi.importConnector(JSON.parse(editorJson) as object, validation.checksumSha256);
    },
    onSuccess: refresh,
  });
  const transition = useMutation({
    mutationFn: async ({ action, version }: { action: 'validate' | 'publish' | 'retire' | 'rollback'; version: ConnectorVersion }) => {
      if (action === 'validate') return adminApi.validateStored(selected, version);
      if (action === 'publish') {
        const connector = query.data?.find(value => value.connectorId === selected);
        if (!connector) throw new Error('connector-required');
        return adminApi.publish(selected, version, connector.publicationRevision);
      }
      if (action === 'rollback') {
        const active = versions.data?.find(value => value.state === 'Published');
        if (!active) throw new Error('published-version-required');
        return adminApi.rollback(selected, version.version, active.rowVersion);
      }
      return adminApi.retire(selected, version);
    },
    onSuccess: refresh,
  });
  const controlledTest = useMutation({ mutationFn: () => adminApi.testConnector(selected, environmentId, operationId), onSuccess: value => setTestResult(`${value.connectorId} · ${value.operationId} · ${value.connectorVersion}`) });

  if (query.isPending) return <LoadingState />;
  if (query.error) return <ErrorState error={query.error} retry={() => void query.refetch()} />;
  const canEdit = hasRole(session, 'ConnectorEditor', 'SecurityAdministrator');
  const canPublish = hasRole(session, 'ConnectorApprover', 'SecurityAdministrator');
  const canRetire = hasRole(session, 'SecurityAdministrator');
  const canTest = hasRole(session, 'Operator', 'SecurityAdministrator');
  const error = schema.error ?? sample.error ?? validate.error ?? importDraft.error ?? transition.error ?? controlledTest.error;

  return <>
    <PageTitle title={t('connectors')} />
    <DataTable rows={query.data} label={t('connectors')} columns={[
      { key: 'id', label: t('code'), render: (row: ConnectorSummary) => <Button onClick={() => setSelected(row.connectorId)}>{row.connectorId}</Button> },
      { key: 'name', label: t('name'), render: row => row.displayName },
      { key: 'version', label: t('published'), render: row => row.publishedVersion ?? '—' },
      { key: 'total', label: t('total'), render: row => row.versions },
    ]} />
    {selected && <Card sx={{ mt: 3 }}><CardContent>
      <Typography variant="h2">{t('versionTimeline')}: {selected}</Typography>
      {versions.isPending ? <LoadingState /> : versions.error ? <ErrorState error={versions.error} /> : <>
        <DataTable rows={versions.data ?? []} label={t('versionTimeline')} columns={[
          { key: 'version', label: t('version'), render: value => value.version },
          { key: 'state', label: t('status'), render: value => <Chip label={value.state} size="small" /> },
          { key: 'checksum', label: t('checksum'), render: value => value.checksumSha256.slice(0, 12) },
          { key: 'row', label: t('revision'), render: value => value.rowVersion },
          { key: 'actions', label: t('action'), render: value => <Stack direction="row" spacing={1}>
            {canEdit && value.state === 'Draft' && <Button size="small" onClick={() => transition.mutate({ action: 'validate', version: value })}>{t('validate')}</Button>}
            {canPublish && value.state === 'Validated' && <Button size="small" onClick={() => transition.mutate({ action: 'publish', version: value })}>{t('publish')}</Button>}
            {canPublish && value.state === 'Superseded' && <Button size="small" onClick={() => transition.mutate({ action: 'rollback', version: value })}>{t('rollback')}</Button>}
            {canRetire && value.state !== 'Retired' && <Button size="small" color="error" onClick={() => transition.mutate({ action: 'retire', version: value })}>{t('retire')}</Button>}
          </Stack> },
        ]} />
        <VersionComparison connectorId={selected} versions={versions.data ?? []} />
      </>}
      {canTest && <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mt: 3 }}>
        <FormControl sx={{ minWidth: 220 }}><InputLabel id="connector-test-environment">{t('environment')}</InputLabel><Select labelId="connector-test-environment" label={t('environment')} value={environmentId} onChange={event => setEnvironment(event.target.value)}>{(environments.data?.items ?? []).map(value => <MenuItem key={value.id} value={value.id}>{value.displayName}</MenuItem>)}</Select></FormControl>
        <TextField label={t('operation')} value={operationId} onChange={event => setOperation(event.target.value)} />
        <Button variant="outlined" disabled={!environmentId || !operationId} onClick={() => controlledTest.mutate()}>{t('testConnector')}</Button>
        {testResult && <Alert severity="success">{testResult}</Alert>}
      </Stack>}
    </CardContent></Card>}
    {canEdit && <Card sx={{ mt: 3 }}><CardContent>
      <Typography variant="h2" sx={{ mb: 2 }}>{t('connectorJson')}</Typography>
      <Box sx={{ border: 1, borderColor: 'divider' }}><CodeMirror value={editorJson} height="360px" onChange={value => { setJson(value); setEditorChanged(true); setValidation(undefined); }} aria-label={t('connectorJson')} /></Box>
      <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
        <Button variant="outlined" disabled={!schema.data || !editorJson} onClick={() => validate.mutate()}>{t('validate')}</Button>
        <Button variant="contained" disabled={!validation?.valid} onClick={() => importDraft.mutate()}>{t('importDraft')}</Button>
      </Stack>
      {validation && <Alert severity={validation.valid ? 'success' : 'error'} sx={{ mt: 2 }}>
        {t(validation.valid ? 'validationPassed' : 'validationFailed')} {validation.valid && <Chip size="small" label={`${t('checksum')}: ${validation.checksumSha256}`} />}
        {!validation.valid && <Box component="ul">{(validation.issues.length ? validation.issues : clientIssues).map((issue, index) => <li key={`${issue.code}-${issue.location}-${index}`}><code>{issue.code}</code> <code>{issue.location}</code></li>)}</Box>}
      </Alert>}
    </CardContent></Card>}
    {error && <Box sx={{ mt: 2 }}><ErrorState error={error} /></Box>}
  </>;
}
