using System.Security.Claims;
using System.Security.Cryptography;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class AdminSecurityTests
{
    [Fact]
    public void M5_UT_Runtime_wire_contract_exports_all_stable_admin_audit_values()
    {
        RuntimeWireCodeCatalog catalog = RuntimeWireCodeCatalog.Current;
        Assert.Equal(Enum.GetNames<AdminRole>().Order(), catalog.Role.Order());
        Assert.Contains("installation.create", catalog.AuditAction);
        Assert.Contains("installation.revoke", catalog.AuditAction);
        Assert.Contains("grant.create", catalog.AuditAction);
        Assert.Contains("runtime.authenticate", catalog.AuditAction);
        Assert.Contains("operation.invoke", catalog.AuditAction);
        Assert.Contains("admin.request.denied", catalog.AuditAction);
        Assert.Contains("BGW-INSTALLATION-CREATED", catalog.Reason);
        Assert.Contains("BGW-OPERATION-OK", catalog.Reason);
        Assert.Contains("BGW-ADMIN-ACTION", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-BINDING-SCOPE", catalog.Reason);
        Assert.Contains("BGW-ADMIN-FOUR-EYES", catalog.Reason);
        Assert.Contains("BGW-ADMIN-BOOTSTRAP-DENIED", catalog.Reason);
        Assert.Contains("BGW-PROVIDER-LOCATOR-DENIED", catalog.Reason);
        Assert.Contains("BGW-INSTALLATION-CLIENT-VERSION", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-OAUTH-REDIRECT-URI-INVALID", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SESSION-HEADER-FORMAT-INVALID", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SOAP-ACTION-INVALID", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SOAP-CONTENT-TYPE-INVALID", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SOAP-METHOD-INVALID", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-TYPED-HANDSHAKE-METHOD", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-TYPED-HANDSHAKE-AUTH", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-TYPED-HANDSHAKE-CONTENT-TYPE", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-TYPED-COMPOSED-METHOD", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-TYPED-COMPOSED-AUTH", catalog.Reason);
        Assert.Contains("BGW-AUTH-VERTICAL-AUTHORITY-STALE", catalog.Reason);
        Assert.Contains("BGW-AUTH-SIGNING-SLOT-DENIED", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SERVER-INPUT-BINDING-INVALID", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-CAPABILITY-SIGNING-BINDING-INVALID", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SIGNING-MODE-AMBIGUOUS", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SIGNING-SLOT-DUPLICATE", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SIGNING-PROFILE-DUPLICATE", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SIGNING-AUTHORIZATION-DUPLICATE", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SIGNING-HEADER-FORBIDDEN", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-SIGNING-HEADER-DUPLICATE", catalog.Reason);
        Assert.Contains("BGW-AUTH-RESTRICTED-BODY-MODE-DENIED", catalog.Reason);
        Assert.Contains("BGW-AUTH-RESTRICTED-PATH-DENIED", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-PATH-TEMPLATE-CAPABILITY-REQUIRED", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-PATH-TEMPLATE-INVALID", catalog.Reason);
        Assert.Contains("BGW-CONNECTOR-RESTRICTED-BODY-NONE-METHOD", catalog.Reason);
        Assert.Contains("BGW-PROVIDER-PUBLIC-MATERIAL-INVALID", catalog.Reason);
        Assert.Equal(173, catalog.Reason.Count);
        Assert.DoesNotContain("grant.revoke", catalog.AuditAction);
        Assert.DoesNotContain("BGW-GRANT-REVOKED", catalog.Reason);
        Assert.Contains(BackendRuntimeWireCodes.Reserved, value => value == new RuntimeWireCode(RuntimeWireCodeKind.AuditAction, "grant.revoke"));
        Assert.Contains(BackendRuntimeWireCodes.Reserved, value => value == new RuntimeWireCode(RuntimeWireCodeKind.Reason, "BGW-GRANT-REVOKED"));
        Assert.Equal(BackendRuntimeWireCodes.Published.Count, catalog.Status.Count + catalog.Health.Count + catalog.Approval.Count + catalog.Role.Count + catalog.Scope.Count + catalog.AuditAction.Count + catalog.AuditOutcome.Count + catalog.Reason.Count);
        Assert.Equal(catalog.Reason.Count, catalog.Reason.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(catalog.AuditAction.Count, catalog.AuditAction.Distinct(StringComparer.Ordinal).Count());
        Assert.All(catalog.AuditAction.Concat(catalog.Reason), value => Assert.DoesNotContain('<', value));
    }

    private static readonly DateTimeOffset Now = new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] BindingDigest = SHA256.HashData("binding-bundle"u8);

    [Fact]
    public async Task M5_UT_Admin_identity_is_issuer_and_subject_not_email()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord first = await store.EnsurePrincipalAsync(new("https://issuer-a.example.invalid", "subject", "First", "same@example.invalid"), TestContext.Current.CancellationToken);
        AdminPrincipalRecord second = await store.EnsurePrincipalAsync(new("https://issuer-b.example.invalid", "subject", "Second", "same@example.invalid"), TestContext.Current.CancellationToken);
        AdminPrincipalRecord renamed = await store.EnsurePrincipalAsync(new("https://issuer-a.example.invalid", "subject", "Renamed", "changed@example.invalid"), TestContext.Current.CancellationToken);

        Assert.NotEqual(first.Id, second.Id);
        Assert.Equal(first.Id, renamed.Id);
    }

    [Fact]
    public async Task M5_UT_Bootstrap_is_atomic_and_cannot_be_claimed_twice()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord first = await PrincipalAsync(store, "first");
        AdminPrincipalRecord second = await PrincipalAsync(store, "second");

        bool[] results = await Task.WhenAll(
            store.TryBootstrapSecurityAdministratorAsync(first.Id, Guid.NewGuid(), Now, TestContext.Current.CancellationToken),
            store.TryBootstrapSecurityAdministratorAsync(second.Id, Guid.NewGuid(), Now, TestContext.Current.CancellationToken));

        _ = Assert.Single(results, value => value);
        int administrators = (await store.GetAssignmentsAsync(first.Id, TestContext.Current.CancellationToken)).Count(value => value.Role == AdminRole.SecurityAdministrator)
            + (await store.GetAssignmentsAsync(second.Id, TestContext.Current.CancellationToken)).Count(value => value.Role == AdminRole.SecurityAdministrator);
        Assert.Equal(1, administrators);
    }

    [Fact]
    public async Task M5_UT_RBAC_honors_global_and_tenant_scoped_roles()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord principal = await PrincipalAsync(store, "viewer");
        Guid tenant = Guid.NewGuid();
        await store.AssignRoleAsync(principal.Id, AdminRole.Viewer, tenant, principal.Id, Guid.NewGuid(), Now, TestContext.Current.CancellationToken);
        AdminAccessContext context = new(principal, await store.GetAssignmentsAsync(principal.Id, TestContext.Current.CancellationToken));

        AdminAccessService.Require(context, tenant, AdminRole.Viewer);
        GatewayException denied = Assert.Throws<GatewayException>(() => AdminAccessService.Require(context, Guid.NewGuid(), AdminRole.Viewer));
        Assert.Equal("BGW-ADMIN-AUTHORIZATION", denied.Code);
    }

    [Fact]
    public async Task M5_UT_Editor_or_requester_cannot_approve_own_checksum()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord editor = await PrincipalAsync(store, "editor");
        ConnectorVersionRecord version = Version(editor.Id);
        ConnectorApprovalRecord request = await store.RequestApprovalAsync(version, BindingDigest, editor.Id, Guid.NewGuid(), Now, TestContext.Current.CancellationToken);

        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => store.ApproveAsync(request.Id, version.Id, version.ChecksumSha256, BindingDigest, version.CreatedBy, editor.Id, null, Guid.NewGuid(), Now.AddMinutes(1), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-ADMIN-FOUR-EYES", denied.Code);
    }

    [Fact]
    public async Task M5_UT_Distinct_approval_is_checksum_specific_and_enables_policy()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord editor = await PrincipalAsync(store, "editor");
        AdminPrincipalRecord approver = await PrincipalAsync(store, "approver");
        ConnectorVersionRecord version = Version(editor.Id);
        ConnectorApprovalRecord request = await store.RequestApprovalAsync(version, BindingDigest, editor.Id, Guid.NewGuid(), Now, TestContext.Current.CancellationToken);
        ConnectorApprovalRecord approval = await store.ApproveAsync(request.Id, version.Id, version.ChecksumSha256, BindingDigest, version.CreatedBy, approver.Id, null, Guid.NewGuid(), Now.AddMinutes(1), TestContext.Current.CancellationToken);

        Assert.Equal(ConnectorApprovalStatus.Approved, approval.Status);
        Assert.True(await store.HasValidApprovalAsync(version.Id, version.ChecksumSha256, BindingDigest, editor.Id.ToString("D"), TestContext.Current.CancellationToken));
        Assert.False(await store.HasValidApprovalAsync(version.Id, SHA256.HashData("other"u8), BindingDigest, editor.Id.ToString("D"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_UT_Distinct_approver_can_reject_with_bounded_redacted_comment()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord editor = await PrincipalAsync(store, "editor-reject");
        AdminPrincipalRecord approver = await PrincipalAsync(store, "approver-reject");
        ConnectorVersionRecord version = Version(editor.Id);
        await store.RequestApprovalAsync(version, BindingDigest, editor.Id, Guid.NewGuid(), Now, TestContext.Current.CancellationToken);

        ConnectorApprovalRecord rejection = await store.RejectAsync(version.Id, version.ChecksumSha256, BindingDigest, version.CreatedBy, approver.Id, "schema requires revision", Guid.NewGuid(), Now.AddMinutes(1), TestContext.Current.CancellationToken);

        Assert.Equal(ConnectorApprovalStatus.Rejected, rejection.Status);
        Assert.Equal(approver.Id, rejection.RejectedBy);
        Assert.Equal("schema requires revision", rejection.DecisionComment);
        Assert.False(await store.HasValidApprovalAsync(version.Id, version.ChecksumSha256, BindingDigest, editor.Id.ToString("D"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_UT_Modification_invalidation_revokes_previous_approval()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord editor = await PrincipalAsync(store, "editor");
        AdminPrincipalRecord approver = await PrincipalAsync(store, "approver");
        ConnectorVersionRecord version = Version(editor.Id);
        ConnectorApprovalRecord request = await store.RequestApprovalAsync(version, BindingDigest, editor.Id, Guid.NewGuid(), Now, TestContext.Current.CancellationToken);
        await store.ApproveAsync(request.Id, version.Id, version.ChecksumSha256, BindingDigest, version.CreatedBy, approver.Id, null, Guid.NewGuid(), Now.AddMinutes(1), TestContext.Current.CancellationToken);

        await store.InvalidateApprovalsAsync(version.Id, Now.AddMinutes(2), TestContext.Current.CancellationToken);

        Assert.False(await store.HasValidApprovalAsync(version.Id, version.ChecksumSha256, BindingDigest, editor.Id.ToString("D"), TestContext.Current.CancellationToken));
        Assert.Equal(ConnectorApprovalStatus.Invalidated, Assert.Single(await store.ListApprovalsAsync(version.Id, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task M5_UT_Approval_is_bound_to_exact_connector_and_binding_bundle_digest()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord editor = await PrincipalAsync(store, "digest-editor");
        AdminPrincipalRecord approver = await PrincipalAsync(store, "digest-approver");
        ConnectorVersionRecord version = Version(editor.Id);
        ConnectorApprovalRecord request = await store.RequestApprovalAsync(version, BindingDigest, editor.Id, Guid.NewGuid(), Now, TestContext.Current.CancellationToken);
        await store.ApproveAsync(request.Id, version.Id, version.ChecksumSha256, BindingDigest, version.CreatedBy, approver.Id, null, Guid.NewGuid(), Now.AddMinutes(1), TestContext.Current.CancellationToken);

        byte[] changedBindingDigest = SHA256.HashData("changed-binding-bundle"u8);
        Assert.False(await store.HasValidApprovalAsync(version.Id, version.ChecksumSha256, changedBindingDigest, approver.Id.ToString("D"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_UT_Admin_claim_resolution_rejects_missing_server_session()
    {
        InMemoryAdminSecurityStore store = new();
        AdminAccessService service = new(store, new InMemoryAdminSessionStore(store), new FixedClock());
        ClaimsIdentity identity = new([new Claim("iss", "http://issuer.invalid"), new Claim("sub", "subject")], "test");
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => service.ResolveAsync(new ClaimsPrincipal(identity), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-ADMIN-SESSION", denied.Code);
    }

    [Fact]
    public async Task M5_UT_Server_sessions_are_opaque_unique_revocable_and_idle_bounded_by_absolute_expiry()
    {
        InMemoryAdminSecurityStore security = new();
        InMemoryAdminSessionStore sessions = new(security);
        AdminExternalIdentity identity = new("https://issuer.example.invalid", "session-user", "Session user", null);

        (string firstHandle, AdminSessionRecord first) = await sessions.CreateAsync(identity, Now, TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        (string secondHandle, _) = await sessions.CreateAsync(identity, Now, TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);

        Assert.NotEqual(firstHandle, secondHandle);
        Assert.Equal(64, firstHandle.Length);
        Assert.DoesNotContain(identity.Subject, firstHandle, StringComparison.Ordinal);
        Assert.NotNull(await sessions.ValidateAsync(firstHandle, Now.AddMinutes(15), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
        Assert.NotNull(await sessions.ValidateAsync(firstHandle, Now.AddMinutes(30), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
        AdminSessionRecord touched = Assert.IsType<AdminSessionRecord>(await sessions.ValidateAsync(firstHandle, Now.AddMinutes(45), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
        Assert.Equal(first.AbsoluteExpiresAt, touched.IdleExpiresAt);
        Assert.Null(await sessions.ValidateAsync(firstHandle, first.AbsoluteExpiresAt, TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));

        await sessions.RevokeAsync(secondHandle, Now.AddMinutes(1), TestContext.Current.CancellationToken);
        Assert.Null(await sessions.ValidateAsync(secondHandle, Now.AddMinutes(2), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_UT_Server_session_idle_expiry_and_principal_revocation_are_fail_closed()
    {
        InMemoryAdminSecurityStore security = new();
        InMemoryAdminSessionStore sessions = new(security);
        AdminExternalIdentity identity = new("https://issuer.example.invalid", "idle-user", "Idle user", null);
        (string idleHandle, AdminSessionRecord idleSession) = await sessions.CreateAsync(identity, Now, TimeSpan.FromHours(8), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        Assert.Null(await sessions.ValidateAsync(idleHandle, idleSession.IdleExpiresAt, TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));

        (string revokedHandle, AdminSessionRecord revokedSession) = await sessions.CreateAsync(identity, Now, TimeSpan.FromHours(8), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        await sessions.RevokePrincipalAsync(revokedSession.Principal.Id, Now.AddMinutes(1), TestContext.Current.CancellationToken);
        Assert.Null(await sessions.ValidateAsync(revokedHandle, Now.AddMinutes(2), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_UT_Disabled_principal_is_rejected_before_role_resolution()
    {
        DisabledPrincipalStore store = new();
        AdminAccessService service = new(store, new DisabledSessionStore(), new FixedClock());
        ClaimsIdentity identity = new([new Claim("sid", "opaque")], "test");

        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => service.ResolveAsync(new ClaimsPrincipal(identity), TestContext.Current.CancellationToken));

        Assert.Equal("BGW-ADMIN-PRINCIPAL-DISABLED", denied.Code);
    }

    private static Task<AdminPrincipalRecord> PrincipalAsync(InMemoryAdminSecurityStore store, string subject) =>
        store.EnsurePrincipalAsync(new("https://issuer.example.invalid", subject, subject, subject + "@example.invalid"), TestContext.Current.CancellationToken);

    private static ConnectorVersionRecord Version(Guid editor) => new(
        Guid.NewGuid(), Guid.NewGuid(), "sample", "1.0.0", "1.0", ConnectorVersionState.Validated,
        "{}", SHA256.HashData("canonical"u8), editor.ToString("D"), Now, 2, Now, null, null);

    private sealed class FixedClock : IGatewayClock { public DateTimeOffset UtcNow => Now; }

    private sealed class DisabledSessionStore : IAdminSessionStore
    {
        public Task<(string Handle, AdminSessionRecord Session)> CreateAsync(AdminExternalIdentity identity, DateTimeOffset now, TimeSpan absoluteLifetime, TimeSpan idleLifetime, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<AdminSessionRecord?> ValidateAsync(string handle, DateTimeOffset now, TimeSpan idleLifetime, CancellationToken cancellationToken) => Task.FromResult<AdminSessionRecord?>(new(Guid.NewGuid(), new(Guid.NewGuid(), "https://issuer.example.invalid", "disabled", "disabled", null, false, Now), Now, Now.AddHours(1), Now.AddMinutes(20), Now, null));
        public Task RevokeAsync(string handle, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task RevokePrincipalAsync(Guid principalId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class DisabledPrincipalStore : IAdminSecurityStore
    {
        public Task<AdminPrincipalRecord> EnsurePrincipalAsync(AdminExternalIdentity identity, CancellationToken cancellationToken) =>
            Task.FromResult(new AdminPrincipalRecord(Guid.NewGuid(), identity.Issuer, identity.Subject, identity.DisplayName, identity.Email, false, Now));
        public Task<IReadOnlyList<AdminRoleAssignmentRecord>> GetAssignmentsAsync(Guid principalId, CancellationToken cancellationToken) => throw new InvalidOperationException("Role resolution must not run for disabled principals.");
        public Task<AdminPage<AdminRoleAssignmentRecord>> ListAssignmentsAsync(int offset, int limit, Guid? principalId, Guid? tenantId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<bool> TryBootstrapSecurityAdministratorAsync(Guid principalId, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<AdminRoleAssignmentRecord> AssignRoleAsync(Guid principalId, AdminRole role, Guid? tenantId, Guid grantedBy, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<bool> RevokeRoleAsync(Guid assignmentId, Guid revokedBy, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ConnectorApprovalRecord> RequestApprovalAsync(ConnectorVersionRecord version, byte[] bindingDigestSha256, Guid requester, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ConnectorApprovalRecord> ApproveAsync(Guid approvalRequestId, Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string createdBy, Guid approver, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ConnectorApprovalRecord> RejectAsync(Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string createdBy, Guid rejector, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<bool> HasValidApprovalAsync(Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string actor, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task InvalidateApprovalsAsync(Guid connectorVersionId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyList<ConnectorApprovalRecord>> ListApprovalsAsync(Guid connectorVersionId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<AdminPage<ConnectorApprovalRecord>> ListApprovalsPageAsync(Guid connectorVersionId, int offset, int limit, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
