import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { adminApi, type Page } from '../../api/client';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { DataTable } from '../../components/DataTable';
import { PageTitle } from '../../components/PageTitle';
import { PaginationControls } from '../../components/PaginationControls';
import { PagedSelector } from '../../components/PagedSelector';

export function TenantDataPage({ kind }: { kind: 'grants' | 'audit' }) {
  const { t, i18n } = useTranslation();
  const [tenant, setTenant] = useState('');
  const [offset, setOffset] = useState(0);
  const [tenantOffset, setTenantOffset] = useState(0);
  const tenants = useQuery({ queryKey: ['tenants', 'selector', tenantOffset], queryFn: () => adminApi.tenants(tenantOffset) });
  const query = useQuery<Page<Record<string, unknown>>>({
    queryKey: [kind, tenant, offset],
    queryFn: async () => {
      const result = kind === 'grants' ? await adminApi.grants(tenant, offset) : await adminApi.audit(tenant, offset);
      return { ...result, items: result.items as Array<Record<string, unknown>> };
    },
    enabled: Boolean(tenant),
  });
  if (tenants.isPending) return <LoadingState />;
  const rows = query.data?.items ?? [];
  const columns = kind === 'grants'
    ? [{ key: 'installation', label: t('installation'), render: (row: Record<string, unknown>) => String(row.installationId) }, { key: 'connector', label: t('connectors'), render: (row: Record<string, unknown>) => String(row.connectorId) }, { key: 'operation', label: t('operation'), render: (row: Record<string, unknown>) => String(row.operationId) }, { key: 'from', label: t('validFrom'), render: (row: Record<string, unknown>) => new Intl.DateTimeFormat(i18n.language).format(new Date(String(row.validFrom))) }]
    : [{ key: 'action', label: t('action'), render: (row: Record<string, unknown>) => String(row.action) }, { key: 'target', label: t('target'), render: (row: Record<string, unknown>) => `${String(row.targetType)} · ${String(row.targetId)}` }, { key: 'outcome', label: t('outcome'), render: (row: Record<string, unknown>) => String(row.outcome) }, { key: 'reason', label: t('reason'), render: (row: Record<string, unknown>) => String(row.reasonCode) }];
  return <>
    <PageTitle title={t(kind)} />
    <PagedSelector id={`${kind}-tenant`} label={t('selectTenant')} value={tenant} page={tenants.data!} onChange={value => { setTenant(value); setOffset(0); }} onOffset={setTenantOffset} itemLabel={value => value.displayName} />
    {query.isPending && tenant ? <LoadingState /> : query.error ? <ErrorState error={query.error} retry={() => void query.refetch()} /> : <><DataTable rows={rows} columns={columns} label={t(kind)} />{query.data && <PaginationControls page={query.data} onOffset={setOffset} />}</>}
  </>;
}
