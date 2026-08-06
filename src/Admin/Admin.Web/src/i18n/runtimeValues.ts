import type { TFunction } from 'i18next';

export type RuntimeValueKind = 'status' | 'health' | 'approval' | 'role' | 'scope' | 'auditAction' | 'auditOutcome' | 'reason';

const labels: Record<RuntimeValueKind, Readonly<Record<string, string>>> = {
  status: {
    Active: 'runtime.active', Disabled: 'runtime.disabled', Suspended: 'runtime.suspended', Retired: 'runtime.retired', Pending: 'runtime.pending', Revoked: 'runtime.revoked',
    Overlap: 'runtime.overlap', Expired: 'runtime.expired', Draft: 'runtime.draft', Validated: 'runtime.validated', Published: 'runtime.published', Superseded: 'runtime.superseded'
  },
  health: { healthy: 'runtime.healthy', Healthy: 'runtime.healthy', degraded: 'runtime.degraded', Degraded: 'runtime.degraded', unhealthy: 'runtime.unhealthy', Unhealthy: 'runtime.unhealthy', unknown: 'runtime.unknown', Unknown: 'runtime.unknown' },
  approval: { Pending: 'runtime.pending', Requested: 'runtime.pending', Approved: 'runtime.approved', Rejected: 'runtime.rejected', Obsolete: 'runtime.obsolete', Invalidated: 'runtime.obsolete' },
  role: { Viewer: 'runtime.roleViewer', ConnectorEditor: 'runtime.roleConnectorEditor', ConnectorApprover: 'runtime.roleConnectorApprover', Operator: 'runtime.roleOperator', SecurityAdministrator: 'runtime.roleSecurityAdministrator' },
  scope: { global: 'runtime.scopeGlobal', tenant: 'runtime.scopeTenant' },
  auditAction: {
    'tenant.create': 'runtime.actionTenantCreate', 'tenant.update': 'runtime.actionTenantUpdate', 'tenant.disable': 'runtime.actionTenantDisable',
    'application.create': 'runtime.actionApplicationCreate', 'application.update': 'runtime.actionApplicationUpdate', 'application.disable': 'runtime.actionApplicationDisable',
    'connector.approval.request': 'runtime.actionApprovalRequest', 'connector.approval.approve': 'runtime.actionApprovalApprove', 'connector.approval.reject': 'runtime.actionApprovalReject',
    'connector.publish': 'runtime.actionConnectorPublish', 'connector.bindings.update': 'runtime.actionBindingUpdate', 'admin.access.denied': 'runtime.actionAccessDenied'
  },
  auditOutcome: { success: 'runtime.outcomeSuccess', denied: 'runtime.outcomeDenied', failure: 'runtime.outcomeFailure', conflict: 'runtime.outcomeConflict' },
  reason: {
    'BGW-ADMIN-APPROVAL-APPROVED': 'runtime.reasonApprovalApproved', 'BGW-ADMIN-APPROVAL-REJECTED': 'runtime.reasonApprovalRejected',
    'BGW-ADMIN-APPROVAL-STALE': 'runtime.reasonApprovalStale', 'BGW-CONCURRENCY-CONFLICT': 'runtime.reasonConcurrencyConflict',
    'BGW-CONCURRENCY-PRECONDITION': 'runtime.reasonConcurrencyPrecondition', 'BGW-ADMIN-AUTHORIZATION': 'runtime.reasonAuthorizationDenied',
    'BGW-PROVIDER-RESOURCE-NOT-FOUND': 'runtime.reasonResourceNotFound', 'BGW-PROVIDER-RESOURCE-SCOPE': 'runtime.reasonResourceScope',
    'BGW-PROVIDER-RESOURCE-REVISION-STALE': 'runtime.reasonResourceStale'
  }
};

/** Maps stable wire codes to localized labels while preserving the wire value for sorting and filtering. */
export function runtimeLabel(t: TFunction, kind: RuntimeValueKind, wireValue: unknown): string {
  const wire = String(wireValue ?? 'Unknown');
  const key = labels[kind][wire];
  if (key) return t(key);
  const safe = /^[A-Za-z0-9_.:-]{1,64}$/.test(wire) ? wire : 'invalid';
  return t('runtime.unknownValue', { value: safe });
}

export const knownRuntimeValues = labels;
