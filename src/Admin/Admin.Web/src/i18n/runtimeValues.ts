import type { TFunction } from 'i18next';
import { runtimeWireCodes, type RuntimeValueKind } from './runtimeContract.generated';

export type { RuntimeValueKind } from './runtimeContract.generated';

const explicitLabels: Readonly<Partial<Record<RuntimeValueKind, Readonly<Record<string, string>>>>> = {
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
    'connector.publish': 'runtime.actionConnectorPublish', 'connector.bindings.update': 'runtime.actionBindingUpdate', 'admin.request.denied': 'runtime.actionAccessDenied',
    'installation.create': 'runtime.actionInstallationCreate', 'installation.revoke': 'runtime.actionInstallationRevoke', 'grant.create': 'runtime.actionGrantCreate',
    'runtime.authenticate': 'runtime.actionRuntimeAuthenticate', 'operation.invoke': 'runtime.actionOperationInvoke'
  },
  auditOutcome: { success: 'runtime.outcomeSuccess', denied: 'runtime.outcomeDenied', failure: 'runtime.outcomeFailure', conflict: 'runtime.outcomeConflict' },
  reason: {
    'BGW-ADMIN-ACTION': 'runtime.reasonAdminAction', 'BGW-INSTALLATION-CREATED': 'runtime.reasonInstallationCreated', 'BGW-OPERATION-OK': 'runtime.reasonOperationOk',
    'BGW-ADMIN-APPROVAL-APPROVED': 'runtime.reasonApprovalApproved', 'BGW-ADMIN-APPROVAL-REJECTED': 'runtime.reasonApprovalRejected',
    'BGW-ADMIN-APPROVAL-STALE': 'runtime.reasonApprovalStale', 'BGW-CONCURRENCY-CONFLICT': 'runtime.reasonConcurrencyConflict',
    'BGW-CONCURRENCY-PRECONDITION': 'runtime.reasonConcurrencyPrecondition', 'BGW-ADMIN-AUTHORIZATION': 'runtime.reasonAuthorizationDenied',
    'BGW-PROVIDER-RESOURCE-NOT-FOUND': 'runtime.reasonResourceNotFound', 'BGW-PROVIDER-RESOURCE-SCOPE': 'runtime.reasonResourceScope',
    'BGW-PROVIDER-RESOURCE-REVISION-STALE': 'runtime.reasonResourceStale', 'BGW-AUTH-SIGNING-SLOT-DENIED': 'runtime.reasonSigningSlotDenied',
    'BGW-CONNECTOR-SIGNING-MODE-AMBIGUOUS': 'runtime.reasonSigningModeAmbiguous', 'BGW-CONNECTOR-SIGNING-SLOT-DUPLICATE': 'runtime.reasonSigningSlotDuplicate',
    'BGW-CONNECTOR-SIGNING-PROFILE-DUPLICATE': 'runtime.reasonSigningProfileDuplicate', 'BGW-CONNECTOR-SIGNING-AUTHORIZATION-DUPLICATE': 'runtime.reasonSigningAuthorizationDuplicate',
    'BGW-CONNECTOR-SIGNING-HEADER-FORBIDDEN': 'runtime.reasonSigningHeaderForbidden', 'BGW-CONNECTOR-SIGNING-HEADER-DUPLICATE': 'runtime.reasonSigningHeaderDuplicate'
  }
};

const generatedLabels = Object.fromEntries(Object.entries(runtimeWireCodes).map(([kind, values]) => [kind,
  Object.fromEntries(values.map(wire => [wire, explicitLabels[kind as RuntimeValueKind]?.[wire]
    ?? (kind === 'auditAction' ? 'runtime.knownAction' : kind === 'reason' ? 'runtime.knownReason' : 'runtime.knownValue')]))
])) as Record<RuntimeValueKind, Readonly<Record<string, string>>>;

/** Maps every backend-contract wire code to localized copy while preserving wire values for sorting/filtering. */
export function runtimeLabel(t: TFunction, kind: RuntimeValueKind, wireValue: unknown): string {
  const wire = String(wireValue ?? 'Unknown');
  const key = generatedLabels[kind][wire];
  if (key) return t(key, { value: wire });
  const safe = /^[A-Za-z0-9_.:-]{1,64}$/.test(wire) ? wire : 'invalid';
  return t('runtime.unknownValue', { value: safe });
}

export const knownRuntimeValues = generatedLabels;
