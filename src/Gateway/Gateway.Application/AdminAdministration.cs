using System.Security.Claims;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>Provider-neutral administrative roles.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<AdminRole>))]
public enum AdminRole
{
    /// <summary>Read-only metadata and health access.</summary>
    Viewer,
    /// <summary>Draft, validation and binding administration.</summary>
    ConnectorEditor,
    /// <summary>Distinct approval, publication and rollback authority.</summary>
    ConnectorApprover,
    /// <summary>Installation lifecycle and controlled test authority.</summary>
    Operator,
    /// <summary>Principal, role, bootstrap and security policy authority.</summary>
    SecurityAdministrator
}

/// <summary>External identity key. Email is deliberately not part of the key.</summary>
public sealed record AdminExternalIdentity(string Issuer, string Subject, string DisplayName, string? Email);

/// <summary>Persisted administrative principal.</summary>
public sealed record AdminPrincipalRecord(Guid Id, string Issuer, string Subject, string DisplayName, string? Email, bool Active, DateTimeOffset CreatedAt);

/// <summary>Role assignment optionally restricted to one tenant.</summary>
public sealed record AdminRoleAssignmentRecord(Guid Id, Guid PrincipalId, AdminRole Role, Guid? TenantId, Guid GrantedBy, DateTimeOffset GrantedAt);

/// <summary>Role assignment request identifying the target by immutable external identity.</summary>
public sealed record AdminRoleAssignmentRequest(AdminExternalIdentity Principal, AdminRole Role, Guid? TenantId);

/// <summary>Bounded administrative result page.</summary>
public sealed record AdminPage<T>(IReadOnlyList<T> Items, int Offset, int Limit, int Total);

/// <summary>Provider-neutral, read-only administrative catalogue. Secret values are absent by design.</summary>
public interface IAdminDirectoryStore
{
    /// <summary>Lists tenants in a bounded page.</summary>
    Task<AdminPage<TenantRecord>> ListTenantsAsync(int offset, int limit, CancellationToken cancellationToken);
    /// <summary>Lists applications in a bounded page.</summary>
    Task<AdminPage<ApplicationRecord>> ListApplicationsAsync(int offset, int limit, CancellationToken cancellationToken);
    /// <summary>Lists deployment environments in a bounded page.</summary>
    Task<AdminPage<GatewayEnvironmentRecord>> ListEnvironmentsAsync(int offset, int limit, CancellationToken cancellationToken);
    /// <summary>Lists installations inside one authorized tenant.</summary>
    Task<AdminPage<InstallationRecord>> ListInstallationsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken);
    /// <summary>Gets one installation inside one authorized tenant.</summary>
    Task<InstallationRecord?> GetInstallationAsync(Guid tenantId, Guid installationId, CancellationToken cancellationToken);
    /// <summary>Lists operation grants inside one authorized tenant.</summary>
    Task<AdminPage<InstallationGrantRecord>> ListGrantsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken);
    /// <summary>Lists metadata-only audit events inside one authorized tenant.</summary>
    Task<AdminPage<GatewayAuditEvent>> ListAuditAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken);
}

/// <summary>Resolved principal and immutable assignments for one request.</summary>
public sealed record AdminAccessContext(AdminPrincipalRecord Principal, IReadOnlyList<AdminRoleAssignmentRecord> Assignments)
{
    /// <summary>Stable metadata-only actor identifier.</summary>
    public string ActorId => Principal.Id.ToString("D");
}

/// <summary>Approval lifecycle independent from Connector version state.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ConnectorApprovalStatus>))]
public enum ConnectorApprovalStatus
{
    /// <summary>Awaiting a distinct approver.</summary>
    Requested,
    /// <summary>Approved for the exact checksum.</summary>
    Approved,
    /// <summary>Explicitly rejected by a distinct approver.</summary>
    Rejected,
    /// <summary>No longer usable after mutation or replacement.</summary>
    Invalidated
}

/// <summary>Checksum-specific four-eyes approval record.</summary>
public sealed record ConnectorApprovalRecord(
    Guid Id,
    Guid ConnectorVersionId,
    string ChecksumSha256,
    Guid RequestedBy,
    Guid? ApprovedBy,
    Guid? RejectedBy,
    ConnectorApprovalStatus Status,
    DateTimeOffset RequestedAt,
    DateTimeOffset? ApprovedAt,
    DateTimeOffset? RejectedAt,
    string? DecisionComment,
    DateTimeOffset? InvalidatedAt);

/// <summary>Redacted approval decision input.</summary>
public sealed record ConnectorApprovalDecisionRequest(string? Comment);

/// <summary>Minimal persistence contract for identities, roles and four-eyes records.</summary>
public interface IAdminSecurityStore
{
    /// <summary>Ensures an authenticated external identity has a non-privileged local principal.</summary>
    Task<AdminPrincipalRecord> EnsurePrincipalAsync(AdminExternalIdentity identity, CancellationToken cancellationToken);
    /// <summary>Gets active role assignments for one principal.</summary>
    Task<IReadOnlyList<AdminRoleAssignmentRecord>> GetAssignmentsAsync(Guid principalId, CancellationToken cancellationToken);
    /// <summary>Atomically claims the one-time Security Administrator bootstrap.</summary>
    Task<bool> TryBootstrapSecurityAdministratorAsync(Guid principalId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Assigns a role through an audited Security Administrator action.</summary>
    Task<AdminRoleAssignmentRecord> AssignRoleAsync(Guid principalId, AdminRole role, Guid? tenantId, Guid grantedBy, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Creates or replaces a request for the exact version checksum.</summary>
    Task<ConnectorApprovalRecord> RequestApprovalAsync(ConnectorVersionRecord version, Guid requester, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Approves the current request when approver and editor identities are distinct.</summary>
    Task<ConnectorApprovalRecord> ApproveAsync(Guid connectorVersionId, byte[] checksumSha256, string createdBy, Guid approver, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Rejects the current exact-checksum request as a distinct approver.</summary>
    Task<ConnectorApprovalRecord> RejectAsync(Guid connectorVersionId, byte[] checksumSha256, string createdBy, Guid rejector, string? comment, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Checks for a current approval by a distinct principal.</summary>
    Task<bool> HasValidApprovalAsync(Guid connectorVersionId, byte[] checksumSha256, string actor, CancellationToken cancellationToken);
    /// <summary>Invalidates current approvals after an approval-relevant mutation.</summary>
    Task InvalidateApprovalsAsync(Guid connectorVersionId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Lists redacted approval metadata for a Connector version.</summary>
    Task<IReadOnlyList<ConnectorApprovalRecord>> ListApprovalsAsync(Guid connectorVersionId, CancellationToken cancellationToken);
}

/// <summary>Policy hook applied inside the Connector service, not only at the HTTP endpoint.</summary>
public interface IConnectorApprovalPolicy
{
    /// <summary>Rejects publication unless the exact checksum has a distinct valid approval.</summary>
    Task EnsurePublishApprovedAsync(ConnectorVersionRecord version, string actor, CancellationToken cancellationToken);
}

/// <summary>Default production four-eyes policy.</summary>
public sealed class FourEyesConnectorApprovalPolicy(IAdminSecurityStore store) : IConnectorApprovalPolicy
{
    /// <inheritdoc />
    public async Task EnsurePublishApprovedAsync(ConnectorVersionRecord version, string actor, CancellationToken cancellationToken)
    {
        if (!await store.HasValidApprovalAsync(version.Id, version.ChecksumSha256, actor, cancellationToken).ConfigureAwait(false))
            throw new GatewayException("BGW-ADMIN-APPROVAL-REQUIRED", 409);
    }
}

/// <summary>Resolves claims and enforces provider-neutral RBAC with optional tenant scope.</summary>
public sealed class AdminAccessService(IAdminSecurityStore store)
{
    /// <summary>Resolves the authenticated identity using issuer and subject only.</summary>
    public async Task<AdminAccessContext> ResolveAsync(ClaimsPrincipal claimsPrincipal, CancellationToken cancellationToken)
    {
        if (claimsPrincipal.Identity?.IsAuthenticated != true) throw new GatewayException("BGW-ADMIN-AUTHENTICATION", 401);
        string issuer = claimsPrincipal.FindFirst("iss")?.Value ?? claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Issuer ?? string.Empty;
        string subject = claimsPrincipal.FindFirst("sub")?.Value ?? claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? issuerUri) || issuerUri.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(subject) || subject.Length > 256)
            throw new GatewayException("BGW-ADMIN-IDENTITY", 401);
        string displayName = claimsPrincipal.FindFirst("name")?.Value ?? subject;
        if (displayName.Length > 256) displayName = displayName[..256];
        string? email = claimsPrincipal.FindFirst("email")?.Value;
        if (email?.Length > 320) email = null;
        AdminPrincipalRecord principal = await store.EnsurePrincipalAsync(new(issuer, subject, displayName, email), cancellationToken).ConfigureAwait(false);
        if (!principal.Active) throw new GatewayException("BGW-ADMIN-PRINCIPAL-DISABLED", 403);
        return new(principal, await store.GetAssignmentsAsync(principal.Id, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Requires one of the supplied roles, respecting tenant scope.</summary>
    public static void Require(AdminAccessContext context, Guid? tenantId, params AdminRole[] roles)
    {
        bool allowed = context.Assignments.Any(assignment => roles.Contains(assignment.Role) && (assignment.TenantId is null || assignment.TenantId == tenantId));
        if (!allowed) throw new GatewayException("BGW-ADMIN-AUTHORIZATION", 403);
    }
}

/// <summary>Four-eyes request and approval application service.</summary>
public sealed class ConnectorApprovalService(IAdminSecurityStore store, IConnectorConfigurationStore connectors, IGatewayClock clock)
{
    /// <summary>Requests approval for the current Validated checksum.</summary>
    public async Task<ConnectorApprovalRecord> RequestAsync(string connectorId, string version, AdminAccessContext actor, CancellationToken cancellationToken)
    {
        AdminAccessService.Require(actor, null, AdminRole.ConnectorEditor, AdminRole.SecurityAdministrator);
        ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        if (current.State != ConnectorVersionState.Validated) throw new GatewayException("BGW-CONNECTOR-STATE", 409);
        return await store.RequestApprovalAsync(current, actor.Principal.Id, clock.UtcNow, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Approves only as a distinct ConnectorApprover or SecurityAdministrator.</summary>
    public async Task<ConnectorApprovalRecord> ApproveAsync(string connectorId, string version, AdminAccessContext actor, CancellationToken cancellationToken)
    {
        AdminAccessService.Require(actor, null, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
        ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        return await store.ApproveAsync(current.Id, current.ChecksumSha256, current.CreatedBy, actor.Principal.Id, clock.UtcNow, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Rejects only as a distinct ConnectorApprover or SecurityAdministrator.</summary>
    public async Task<ConnectorApprovalRecord> RejectAsync(string connectorId, string version, string? comment, AdminAccessContext actor, CancellationToken cancellationToken)
    {
        AdminAccessService.Require(actor, null, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
        ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        string? redactedComment = string.IsNullOrWhiteSpace(comment) ? null : comment.Trim();
        if (redactedComment?.Length > 500) throw new GatewayException("BGW-ADMIN-APPROVAL-COMMENT", 400);
        return await store.RejectAsync(current.Id, current.ChecksumSha256, current.CreatedBy, actor.Principal.Id, redactedComment, clock.UtcNow, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Lists approval metadata.</summary>
    public Task<IReadOnlyList<ConnectorApprovalRecord>> ListAsync(string connectorId, string version, AdminAccessContext actor, CancellationToken cancellationToken)
    {
        AdminAccessService.Require(actor, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
        return ListCoreAsync(connectorId, version, cancellationToken);
    }

    private async Task<IReadOnlyList<ConnectorApprovalRecord>> ListCoreAsync(string connectorId, string version, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        return await store.ListApprovalsAsync(current.Id, cancellationToken).ConfigureAwait(false);
    }
}
