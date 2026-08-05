using System.Security.Claims;
using System.Security.Cryptography;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class AdminSecurityTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

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
            store.TryBootstrapSecurityAdministratorAsync(first.Id, Now, TestContext.Current.CancellationToken),
            store.TryBootstrapSecurityAdministratorAsync(second.Id, Now, TestContext.Current.CancellationToken));

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
        await store.AssignRoleAsync(principal.Id, AdminRole.Viewer, tenant, principal.Id, Now, TestContext.Current.CancellationToken);
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
        await store.RequestApprovalAsync(version, editor.Id, Now, TestContext.Current.CancellationToken);

        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => store.ApproveAsync(version.Id, version.ChecksumSha256, version.CreatedBy, editor.Id, Now.AddMinutes(1), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-ADMIN-FOUR-EYES", denied.Code);
    }

    [Fact]
    public async Task M5_UT_Distinct_approval_is_checksum_specific_and_enables_policy()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord editor = await PrincipalAsync(store, "editor");
        AdminPrincipalRecord approver = await PrincipalAsync(store, "approver");
        ConnectorVersionRecord version = Version(editor.Id);
        await store.RequestApprovalAsync(version, editor.Id, Now, TestContext.Current.CancellationToken);
        ConnectorApprovalRecord approval = await store.ApproveAsync(version.Id, version.ChecksumSha256, version.CreatedBy, approver.Id, Now.AddMinutes(1), TestContext.Current.CancellationToken);

        Assert.Equal(ConnectorApprovalStatus.Approved, approval.Status);
        await new FourEyesConnectorApprovalPolicy(store).EnsurePublishApprovedAsync(version, editor.Id.ToString("D"), TestContext.Current.CancellationToken);
        Assert.False(await store.HasValidApprovalAsync(version.Id, SHA256.HashData("other"u8), editor.Id.ToString("D"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_UT_Distinct_approver_can_reject_with_bounded_redacted_comment()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord editor = await PrincipalAsync(store, "editor-reject");
        AdminPrincipalRecord approver = await PrincipalAsync(store, "approver-reject");
        ConnectorVersionRecord version = Version(editor.Id);
        await store.RequestApprovalAsync(version, editor.Id, Now, TestContext.Current.CancellationToken);

        ConnectorApprovalRecord rejection = await store.RejectAsync(version.Id, version.ChecksumSha256, version.CreatedBy, approver.Id, "schema requires revision", Now.AddMinutes(1), TestContext.Current.CancellationToken);

        Assert.Equal(ConnectorApprovalStatus.Rejected, rejection.Status);
        Assert.Equal(approver.Id, rejection.RejectedBy);
        Assert.Equal("schema requires revision", rejection.DecisionComment);
        Assert.False(await store.HasValidApprovalAsync(version.Id, version.ChecksumSha256, editor.Id.ToString("D"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_UT_Modification_invalidation_revokes_previous_approval()
    {
        InMemoryAdminSecurityStore store = new();
        AdminPrincipalRecord editor = await PrincipalAsync(store, "editor");
        AdminPrincipalRecord approver = await PrincipalAsync(store, "approver");
        ConnectorVersionRecord version = Version(editor.Id);
        await store.RequestApprovalAsync(version, editor.Id, Now, TestContext.Current.CancellationToken);
        await store.ApproveAsync(version.Id, version.ChecksumSha256, version.CreatedBy, approver.Id, Now.AddMinutes(1), TestContext.Current.CancellationToken);

        await store.InvalidateApprovalsAsync(version.Id, Now.AddMinutes(2), TestContext.Current.CancellationToken);

        Assert.False(await store.HasValidApprovalAsync(version.Id, version.ChecksumSha256, editor.Id.ToString("D"), TestContext.Current.CancellationToken));
        Assert.Equal(ConnectorApprovalStatus.Invalidated, Assert.Single(await store.ListApprovalsAsync(version.Id, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task M5_UT_Admin_claim_resolution_rejects_non_https_issuer()
    {
        AdminAccessService service = new(new InMemoryAdminSecurityStore());
        ClaimsIdentity identity = new([new Claim("iss", "http://issuer.invalid"), new Claim("sub", "subject")], "test");
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => service.ResolveAsync(new ClaimsPrincipal(identity), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-ADMIN-IDENTITY", denied.Code);
    }

    [Fact]
    public async Task M5_UT_Disabled_principal_is_rejected_before_role_resolution()
    {
        AdminAccessService service = new(new DisabledPrincipalStore());
        ClaimsIdentity identity = new([new Claim("iss", "https://issuer.example.invalid"), new Claim("sub", "disabled")], "test");

        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => service.ResolveAsync(new ClaimsPrincipal(identity), TestContext.Current.CancellationToken));

        Assert.Equal("BGW-ADMIN-PRINCIPAL-DISABLED", denied.Code);
    }

    private static Task<AdminPrincipalRecord> PrincipalAsync(InMemoryAdminSecurityStore store, string subject) =>
        store.EnsurePrincipalAsync(new("https://issuer.example.invalid", subject, subject, subject + "@example.invalid"), TestContext.Current.CancellationToken);

    private static ConnectorVersionRecord Version(Guid editor) => new(
        Guid.NewGuid(), Guid.NewGuid(), "sample", "1.0.0", "1.0", ConnectorVersionState.Validated,
        "{}", SHA256.HashData("canonical"u8), editor.ToString("D"), Now, 2, Now, null, null);

    private sealed class DisabledPrincipalStore : IAdminSecurityStore
    {
        public Task<AdminPrincipalRecord> EnsurePrincipalAsync(AdminExternalIdentity identity, CancellationToken cancellationToken) =>
            Task.FromResult(new AdminPrincipalRecord(Guid.NewGuid(), identity.Issuer, identity.Subject, identity.DisplayName, identity.Email, false, Now));
        public Task<IReadOnlyList<AdminRoleAssignmentRecord>> GetAssignmentsAsync(Guid principalId, CancellationToken cancellationToken) => throw new InvalidOperationException("Role resolution must not run for disabled principals.");
        public Task<bool> TryBootstrapSecurityAdministratorAsync(Guid principalId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<AdminRoleAssignmentRecord> AssignRoleAsync(Guid principalId, AdminRole role, Guid? tenantId, Guid grantedBy, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ConnectorApprovalRecord> RequestApprovalAsync(ConnectorVersionRecord version, Guid requester, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ConnectorApprovalRecord> ApproveAsync(Guid connectorVersionId, byte[] checksumSha256, string createdBy, Guid approver, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ConnectorApprovalRecord> RejectAsync(Guid connectorVersionId, byte[] checksumSha256, string createdBy, Guid rejector, string? comment, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<bool> HasValidApprovalAsync(Guid connectorVersionId, byte[] checksumSha256, string actor, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task InvalidateApprovalsAsync(Guid connectorVersionId, DateTimeOffset now, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyList<ConnectorApprovalRecord>> ListApprovalsAsync(Guid connectorVersionId, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
