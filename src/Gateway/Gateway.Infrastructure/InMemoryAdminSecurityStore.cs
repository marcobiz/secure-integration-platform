using System.Collections.Concurrent;
using System.Security.Cryptography;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Thread-safe Development/Testing Admin security store.</summary>
public sealed class InMemoryAdminSecurityStore(IGatewayRegistry? auditRegistry = null) : IAdminSecurityStore
{
    private readonly object sync = new();
    private readonly Dictionary<(string Issuer, string Subject), AdminPrincipalRecord> principals = new();
    private readonly List<AdminRoleAssignmentRecord> assignments = [];
    private readonly List<ConnectorApprovalRecord> approvals = [];
    private Guid? bootstrapPrincipal;
    internal event Action<Guid, DateTimeOffset>? PrincipalPrivilegesChanged;

    /// <inheritdoc />
    public Task<AdminPrincipalRecord> EnsurePrincipalAsync(AdminExternalIdentity identity, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateIdentity(identity);
        lock (sync)
        {
            (string, string) key = (identity.Issuer, identity.Subject);
            if (!principals.TryGetValue(key, out AdminPrincipalRecord? principal))
            {
                principal = new(Guid.NewGuid(), identity.Issuer, identity.Subject, identity.DisplayName, identity.Email, true, DateTimeOffset.UtcNow);
                principals.Add(key, principal);
            }
            return Task.FromResult(principal);
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<AdminRoleAssignmentRecord>> GetAssignmentsAsync(Guid principalId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync) return Task.FromResult<IReadOnlyList<AdminRoleAssignmentRecord>>(assignments.Where(value => value.PrincipalId == principalId).ToArray());
    }

    /// <inheritdoc />
    public Task<AdminPage<AdminRoleAssignmentRecord>> ListAssignmentsAsync(int offset, int limit, Guid? principalId, Guid? tenantId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            AdminRoleAssignmentRecord[] values = assignments.Where(value => (principalId is null || value.PrincipalId == principalId) && (tenantId is null || value.TenantId == tenantId)).OrderBy(value => value.Role).ThenBy(value => value.PrincipalId).ToArray();
            return Task.FromResult(new AdminPage<AdminRoleAssignmentRecord>(values.Skip(offset).Take(limit).ToArray(), offset, limit, values.Length));
        }
    }

    /// <inheritdoc />
    public Task<bool> TryBootstrapSecurityAdministratorAsync(Guid principalId, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            if (bootstrapPrincipal is not null) return Task.FromResult(false);
            if (!principals.Values.Any(value => value.Id == principalId && value.Active)) return Task.FromResult(false);
            bootstrapPrincipal = principalId;
            assignments.Add(new(Guid.NewGuid(), principalId, AdminRole.SecurityAdministrator, null, principalId, now));
            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    public async Task<AdminRoleAssignmentRecord> AssignRoleAsync(Guid principalId, AdminRole role, Guid? tenantId, Guid grantedBy, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        AdminRoleAssignmentRecord result;
        bool privilegesChanged = false;
        lock (sync)
        {
            if (!principals.Values.Any(value => value.Id == principalId && value.Active)) throw new GatewayException("BGW-ADMIN-PRINCIPAL-NOT-FOUND", 404);
            AdminRoleAssignmentRecord? existing = assignments.SingleOrDefault(value => value.PrincipalId == principalId && value.Role == role && value.TenantId == tenantId);
            if (existing is not null) result = existing;
            else
            {
                result = new(Guid.NewGuid(), principalId, role, tenantId, grantedBy, now);
                assignments.Add(result);
                privilegesChanged = true;
            }
        }
        if (privilegesChanged && auditRegistry is not null)
            await auditRegistry.AppendAuditAsync(new(Guid.NewGuid(), now, tenantId, "administrator", grantedBy.ToString("D"), "admin.role.assign", "admin_principal", principalId.ToString("D"), correlationId, "success", "BGW-ADMIN-ROLE-ASSIGNED", new Dictionary<string, string>()), cancellationToken).ConfigureAwait(false);
        if (privilegesChanged) PrincipalPrivilegesChanged?.Invoke(principalId, now);
        return result;
    }

    /// <inheritdoc />
    public Task<bool> RevokeRoleAsync(Guid assignmentId, Guid revokedBy, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Guid? principalId = null;
        lock (sync)
        {
            int index = assignments.FindIndex(value => value.Id == assignmentId);
            if (index < 0) return Task.FromResult(false);
            principalId = assignments[index].PrincipalId;
            assignments.RemoveAt(index);
        }
        PrincipalPrivilegesChanged?.Invoke(principalId.Value, now);
        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public Task<ConnectorApprovalRecord> RequestApprovalAsync(ConnectorVersionRecord version, byte[] bindingDigestSha256, Guid requester, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            InvalidateCore(version.Id, now);
            ConnectorApprovalRecord created = new(Guid.NewGuid(), version.Id, Convert.ToHexString(version.ChecksumSha256), Convert.ToHexString(bindingDigestSha256), requester, null, null, ConnectorApprovalStatus.Requested, now, null, null, null, null);
            approvals.Add(created);
            return Task.FromResult(created);
        }
    }

    /// <inheritdoc />
    public Task<ConnectorApprovalRecord> ApproveAsync(Guid approvalRequestId, Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string createdBy, Guid approver, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            int index = approvals.FindIndex(value => value.Id == approvalRequestId && value.ConnectorVersionId == connectorVersionId && value.Status == ConnectorApprovalStatus.Requested && FixedChecksum(value.ChecksumSha256, checksumSha256) && FixedChecksum(value.BindingDigestSha256, bindingDigestSha256));
            if (index < 0) throw new GatewayException("BGW-ADMIN-APPROVAL-NOT-FOUND", 409);
            ConnectorApprovalRecord current = approvals[index];
            if (current.RequestedBy == approver || (Guid.TryParse(createdBy, out Guid creator) && creator == approver)) throw new GatewayException("BGW-ADMIN-FOUR-EYES", 403);
            ConnectorApprovalRecord approved = current with { ApprovedBy = approver, Status = ConnectorApprovalStatus.Approved, ApprovedAt = now, DecisionComment = comment };
            approvals[index] = approved;
            return Task.FromResult(approved);
        }
    }

    /// <inheritdoc />
    public Task<ConnectorApprovalRecord> RejectAsync(Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string createdBy, Guid rejector, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            int index = approvals.FindIndex(value => value.ConnectorVersionId == connectorVersionId && value.Status == ConnectorApprovalStatus.Requested && FixedChecksum(value.ChecksumSha256, checksumSha256) && FixedChecksum(value.BindingDigestSha256, bindingDigestSha256));
            if (index < 0) throw new GatewayException("BGW-ADMIN-APPROVAL-NOT-FOUND", 409);
            ConnectorApprovalRecord current = approvals[index];
            if (current.RequestedBy == rejector || (Guid.TryParse(createdBy, out Guid creator) && creator == rejector)) throw new GatewayException("BGW-ADMIN-FOUR-EYES", 403);
            ConnectorApprovalRecord rejected = current with { RejectedBy = rejector, Status = ConnectorApprovalStatus.Rejected, RejectedAt = now, DecisionComment = comment };
            approvals[index] = rejected;
            return Task.FromResult(rejected);
        }
    }

    /// <inheritdoc />
    public Task<bool> HasValidApprovalAsync(Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string actor, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!Guid.TryParseExact(actor, "D", out Guid publisher)) return Task.FromResult(false);
        lock (sync) return Task.FromResult(approvals.Any(value => value.ConnectorVersionId == connectorVersionId && value.Status == ConnectorApprovalStatus.Approved && value.ApprovedBy == publisher && value.ApprovedBy != value.RequestedBy && FixedChecksum(value.ChecksumSha256, checksumSha256) && FixedChecksum(value.BindingDigestSha256, bindingDigestSha256)));
    }

    /// <inheritdoc />
    public Task InvalidateApprovalsAsync(Guid connectorVersionId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync) InvalidateCore(connectorVersionId, now);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<ConnectorApprovalRecord>> ListApprovalsAsync(Guid connectorVersionId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync) return Task.FromResult<IReadOnlyList<ConnectorApprovalRecord>>(approvals.Where(value => value.ConnectorVersionId == connectorVersionId).OrderByDescending(value => value.RequestedAt).ToArray());
    }

    /// <inheritdoc />
    public Task<AdminPage<ConnectorApprovalRecord>> ListApprovalsPageAsync(Guid connectorVersionId, int offset, int limit, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            ConnectorApprovalRecord[] values = approvals.Where(value => value.ConnectorVersionId == connectorVersionId).OrderByDescending(value => value.RequestedAt).ToArray();
            return Task.FromResult(new AdminPage<ConnectorApprovalRecord>(values.Skip(offset).Take(limit).ToArray(), offset, limit, values.Length));
        }
    }

    private void InvalidateCore(Guid connectorVersionId, DateTimeOffset now)
    {
        for (int index = 0; index < approvals.Count; index++)
            if (approvals[index].ConnectorVersionId == connectorVersionId && approvals[index].Status is ConnectorApprovalStatus.Requested or ConnectorApprovalStatus.Approved)
                approvals[index] = approvals[index] with { Status = ConnectorApprovalStatus.Invalidated, InvalidatedAt = now };
    }

    private static bool FixedChecksum(string expectedHex, byte[] actual)
    {
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(expectedHex), actual); }
        catch (FormatException) { return false; }
    }

    private static void ValidateIdentity(AdminExternalIdentity identity)
    {
        if (!Uri.TryCreate(identity.Issuer, UriKind.Absolute, out Uri? issuer) || issuer.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(identity.Subject) || identity.Subject.Length > 256 || string.IsNullOrWhiteSpace(identity.DisplayName) || identity.DisplayName.Length > 256)
            throw new GatewayException("BGW-ADMIN-IDENTITY", 401);
    }
}
