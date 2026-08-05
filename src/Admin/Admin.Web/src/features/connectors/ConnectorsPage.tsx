import { lazy, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, Chip, Stack, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { adminApi, type ConnectorSummary } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { DataTable } from '../../components/DataTable'; import { ErrorState, LoadingState } from '../../components/AsyncState'; import { PageTitle } from '../../components/PageTitle';

const localEnvelopeSchema = { type: 'object', required: ['schemaVersion', 'connector'], properties: { schemaVersion: { const: '1.0' }, connector: { type: 'object' } }, additionalProperties: true } as const;
const CodeMirror = lazy(() => import('@uiw/react-codemirror'));
const initial = JSON.stringify({ schemaVersion: '1.0', connector: { id: 'sample-secure-service', displayName: 'Sample secure service', version: '1.0.0' }, endpointBindings: [], secretBindings: [], operations: [] }, null, 2);

export function ConnectorsPage() {
  const { t } = useTranslation(); const session = useSession(); const cache = useQueryClient(); const [json, setJson] = useState(initial); const [validation, setValidation] = useState<{ valid: boolean; checksumSha256: string; errors: Array<{ code: string; path: string }> }>();
  const query = useQuery({ queryKey: ['connectors'], queryFn: adminApi.connectors });
  const validate = useMutation({ mutationFn: async () => { const parsed: unknown = JSON.parse(json); const { default: Ajv2020 } = await import('ajv/dist/2020'); if (!new Ajv2020().validate(localEnvelopeSchema, parsed)) throw new Error('local-json-validation'); return adminApi.validateConnector(parsed as object); }, onSuccess: setValidation });
  const importDraft = useMutation({ mutationFn: async () => { if (!validation?.valid) throw new Error('validation-required'); return adminApi.importConnector(JSON.parse(json) as object, validation.checksumSha256); }, onSuccess: async () => { await cache.invalidateQueries({ queryKey: ['connectors'] }); } });
  if (query.isPending) return <LoadingState />; if (query.error) return <ErrorState error={query.error} retry={() => void query.refetch()} />;
  const canEdit = hasRole(session, 'ConnectorEditor', 'SecurityAdministrator');
  return <><PageTitle title={t('connectors')} /><DataTable rows={query.data} label={t('connectors')} columns={[{ key: 'id', label: t('code'), render: (row: ConnectorSummary) => row.connectorId }, { key: 'name', label: t('name'), render: row => row.displayName }, { key: 'version', label: t('published'), render: row => row.publishedVersion ?? '—' }, { key: 'total', label: t('total'), render: row => row.versions }]} />{canEdit && <Card sx={{ mt: 3 }}><CardContent><Typography variant="h2" sx={{ mb: 2 }}>{t('connectorJson')}</Typography><Box sx={{ border: 1, borderColor: 'divider' }}><CodeMirror value={json} height="360px" onChange={setJson} aria-label={t('connectorJson')} /></Box><Stack direction="row" spacing={1} sx={{ mt: 2 }}><Button variant="outlined" onClick={() => validate.mutate()}>{t('validate')}</Button><Button variant="contained" disabled={!validation?.valid} onClick={() => importDraft.mutate()}>{t('importDraft')}</Button></Stack>{validation && <Alert severity={validation.valid ? 'success' : 'error'} sx={{ mt: 2 }}>{t(validation.valid ? 'validationPassed' : 'validationFailed')} {validation.valid && <Chip size="small" label={`${t('checksum')}: ${validation.checksumSha256}`} />}</Alert>}{(validate.error || importDraft.error) && <Box sx={{ mt: 2 }}><ErrorState error={validate.error ?? importDraft.error} /></Box>}</CardContent></Card>}</>;
}
