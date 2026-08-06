using System.Net;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>UTC clock seam used by expiry, replay and certificate checks.</summary>
public interface IGatewayClock
{
    /// <summary>Current UTC time.</summary>
    DateTimeOffset UtcNow { get; }
}

/// <summary>Test-only failpoint seam used to prove transactional rollback at named boundaries.</summary>
public interface IAdminTransactionFaultInjector
{
    /// <summary>Throws when a configured transaction boundary is reached.</summary>
    void Check(string boundary);
}

/// <summary>Gateway persistence boundary.</summary>
public interface IGatewayRegistry
{
    /// <summary>Adds a Tenant.</summary>
    Task AddTenantAsync(TenantRecord tenant, CancellationToken cancellationToken);
    /// <summary>Adds a Tenant and its administrative audit event atomically.</summary>
    Task AddTenantWithAuditAsync(TenantRecord tenant, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Updates Tenant metadata and audit atomically.</summary>
    Task<TenantRecord> UpdateTenantWithAuditAsync(Guid tenantId, string displayName, long expectedRowVersion, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Disables a Tenant and appends its audit atomically.</summary>
    Task<TenantRecord> DisableTenantWithAuditAsync(Guid tenantId, long expectedRowVersion, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Adds an Application.</summary>
    Task AddApplicationAsync(ApplicationRecord application, CancellationToken cancellationToken);
    /// <summary>Adds an Application and its administrative audit event atomically.</summary>
    Task AddApplicationWithAuditAsync(ApplicationRecord application, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Updates Application metadata and audit atomically.</summary>
    Task<ApplicationRecord> UpdateApplicationWithAuditAsync(Guid applicationId, string displayName, string minimumBrokerVersion, string? maximumBrokerVersion, long expectedRowVersion, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Disables an Application and appends its audit atomically.</summary>
    Task<ApplicationRecord> DisableApplicationWithAuditAsync(Guid applicationId, long expectedRowVersion, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Adds an Environment.</summary>
    Task AddEnvironmentAsync(GatewayEnvironmentRecord environment, CancellationToken cancellationToken);
    /// <summary>Adds a tenant-bound Installation.</summary>
    Task AddInstallationAsync(InstallationRecord installation, CancellationToken cancellationToken);
    /// <summary>Adds a one-time activation record.</summary>
    Task AddActivationCodeAsync(ActivationCodeRecord activationCode, CancellationToken cancellationToken);
    /// <summary>Persists a pending Installation, its HMAC-only activation and audit event in one transaction.</summary>
    Task AddInstallationActivationWithAuditAsync(InstallationRecord installation, ActivationCodeRecord activationCode, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Adds an operation grant.</summary>
    Task AddGrantAsync(InstallationGrantRecord grant, CancellationToken cancellationToken);
    /// <summary>Persists a grant and its audit event atomically.</summary>
    Task AddGrantWithAuditAsync(InstallationGrantRecord grant, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Finds activation metadata by its opaque identifier.</summary>
    Task<ActivationCodeRecord?> FindActivationCodeAsync(Guid activationCodeId, CancellationToken cancellationToken);
    /// <summary>Records a denied activation attempt.</summary>
    Task RecordActivationFailureAsync(Guid activationCodeId, CancellationToken cancellationToken);
    /// <summary>Atomically consumes activation material and registers a credential.</summary>
    Task<bool> ActivateAsync(Guid activationCodeId, byte[] expectedCodeHmac, InstallationCredentialRecord credential, string brokerVersion, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Resolves identity from an exact certificate digest.</summary>
    Task<RegisteredInstallationIdentity?> FindIdentityByCertificateAsync(byte[] certificateSha256, CancellationToken cancellationToken);
    /// <summary>Atomically replaces the active credential with a bounded overlap.</summary>
    Task<bool> RenewCredentialAsync(Guid installationId, Guid currentCredentialId, InstallationCredentialRecord replacement, DateTimeOffset overlapEndsAt, CancellationToken cancellationToken);
    /// <summary>Revokes an Installation and its usable credentials.</summary>
    Task<bool> RevokeInstallationAsync(Guid installationId, string reason, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Revokes an Installation and appends its audit event atomically.</summary>
    Task<bool> RevokeInstallationWithAuditAsync(Guid installationId, string reason, DateTimeOffset now, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Checks an operation grant in the authenticated tenant scope.</summary>
    Task<bool> IsGrantedAsync(Guid installationId, Guid tenantId, string connectorId, string operationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Stores a replay digest if it has not been seen.</summary>
    Task<bool> TryStoreNonceAsync(Guid installationId, byte[] nonceSha256, DateTimeOffset expiresAt, CancellationToken cancellationToken);
    /// <summary>Appends a metadata-only audit event.</summary>
    Task AppendAuditAsync(GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Checks persistence readiness.</summary>
    Task<bool> IsReadyAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Administrative registry boundary. Implementations use the separately configured
/// non-superuser admin data source and must never be resolved by runtime request paths.
/// </summary>
public interface IAdminGatewayRegistry : IGatewayRegistry;

/// <summary>Short-lived enrollment challenge storage. Challenges are never persisted with secret values.</summary>
public interface IEnrollmentChallengeStore
{
    /// <summary>Creates a short-lived challenge.</summary>
    EnrollmentChallenge Create(Guid activationCodeId, byte[] publicKeySpki, DateTimeOffset now, TimeSpan lifetime);
    /// <summary>Consumes an unexpired challenge once.</summary>
    EnrollmentChallenge? Consume(Guid challengeId, DateTimeOffset now);
}

/// <summary>DNS seam for deterministic SSRF tests.</summary>
public interface IHostResolver
{
    /// <summary>Resolves every address for a host.</summary>
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

/// <summary>Optional, narrowly scoped M3 test-network exception for one synthetic host.</summary>
public interface IPrivateDestinationAllowance
{
    /// <summary>Returns true only for the configured synthetic host and network.</summary>
    bool IsAllowed(string host, IPAddress address);
}

/// <summary>Restricted HTTP transport. Implementations must not follow redirects or use ambient proxy settings.</summary>
public interface IRestrictedTransport
{
    /// <summary>Sends a bounded request without redirects or ambient proxy use.</summary>
    Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken);
}

/// <summary>Read-only catalogue of server-owned outbound operations.</summary>
public interface IGatewayOperationCatalog
{
    /// <summary>Gets one Published, Environment-bound operation or rejects it.</summary>
    Task<GatewayOperationDefinition> GetRequiredAsync(string connectorId, string operationId, Guid environmentId, CancellationToken cancellationToken);
    /// <summary>Invalidates local cache entries after an administrative lifecycle change.</summary>
    void Invalidate(string connectorId);
}

/// <summary>Provider-neutral persistence boundary for Connector lifecycle and logical bindings.</summary>
public interface IConnectorConfigurationStore
{
    /// <summary>Registers an immutable provider resource catalog revision from protected server configuration.</summary>
    Task<ProviderResourceCatalogRecord> RegisterProviderResourceAsync(ProviderResourceCatalogRecord resource, CancellationToken cancellationToken);
    /// <summary>Resolves and authorizes one structured logical resource reference against the server-owned catalog.</summary>
    Task<ProviderResourceCatalogRecord> ResolveProviderResourceAsync(ProviderResourceReference reference, Guid environmentId, string connectorId, IReadOnlyCollection<string> operationIds, CancellationToken cancellationToken);
    /// <summary>Lists only non-secret catalog metadata for administration selectors.</summary>
    Task<AdminPage<ProviderResourceCatalogRecord>> ListProviderResourcesPageAsync(int offset, int limit, Guid? environmentId, ProviderResourceType? resourceType, CancellationToken cancellationToken);
    /// <summary>Fails closed when a binding references a catalog revision that is no longer current and active.</summary>
    Task ValidateBindingResourcesAsync(Guid connectorVersionId, CancellationToken cancellationToken);
    /// <summary>Creates a new Draft; Connector/version pairs are unique.</summary>
    Task<ConnectorVersionRecord> CreateDraftAsync(ConnectorVersionRecord draft, CancellationToken cancellationToken);
    /// <summary>Creates a Draft and its audit event in one persistence transaction.</summary>
    Task<ConnectorVersionRecord> CreateDraftWithAuditAsync(ConnectorVersionRecord draft, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Gets a version by Connector and semantic version.</summary>
    Task<ConnectorVersionRecord?> GetVersionAsync(string connectorId, string version, CancellationToken cancellationToken);
    /// <summary>Lists all known Connectors.</summary>
    Task<IReadOnlyList<ConnectorSummary>> ListConnectorsAsync(CancellationToken cancellationToken);
    /// <summary>Lists a stable bounded Connector page with optional server-side text filter.</summary>
    async Task<AdminPage<ConnectorSummary>> ListConnectorsPageAsync(int offset, int limit, string? filter, CancellationToken cancellationToken)
    {
        IReadOnlyList<ConnectorSummary> all = await ListConnectorsAsync(cancellationToken).ConfigureAwait(false);
        IEnumerable<ConnectorSummary> filtered = string.IsNullOrWhiteSpace(filter) ? all : all.Where(value => value.ConnectorId.Contains(filter, StringComparison.OrdinalIgnoreCase) || value.DisplayName.Contains(filter, StringComparison.OrdinalIgnoreCase));
        ConnectorSummary[] values = filtered.ToArray();
        return new(values.Skip(offset).Take(limit).ToArray(), offset, limit, values.Length);
    }
    /// <summary>Lists versions newest first.</summary>
    Task<IReadOnlyList<ConnectorVersionRecord>> ListVersionsAsync(string connectorId, CancellationToken cancellationToken);
    /// <summary>Lists a stable bounded version timeline.</summary>
    async Task<AdminPage<ConnectorVersionRecord>> ListVersionsPageAsync(string connectorId, int offset, int limit, string? filter, CancellationToken cancellationToken)
    {
        IReadOnlyList<ConnectorVersionRecord> all = await ListVersionsAsync(connectorId, cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord[] values = (string.IsNullOrWhiteSpace(filter) ? all : all.Where(value => value.Version.Contains(filter, StringComparison.OrdinalIgnoreCase))).ToArray();
        return new(values.Skip(offset).Take(limit).ToArray(), offset, limit, values.Length);
    }
    /// <summary>Transitions Draft to Validated using optimistic concurrency.</summary>
    Task<ConnectorVersionRecord> MarkValidatedAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Marks a Draft validated and appends its audit event atomically.</summary>
    Task<ConnectorVersionRecord> MarkValidatedWithAuditAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Publishes a Validated version and supersedes the current one atomically.</summary>
    Task<ConnectorVersionRecord> PublishAsync(Guid versionId, long expectedRowVersion, long expectedPublicationRevision, string actor, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Publishes only after locking and verifying the exact approved connector/binding digest, and appends audit in the same transaction.</summary>
    Task<ConnectorVersionRecord> PublishApprovedAsync(Guid versionId, byte[] expectedBindingDigestSha256, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Reactivates a previously Published, now Superseded version atomically.</summary>
    Task<ConnectorVersionRecord> RollbackAsync(string connectorId, string targetVersion, long expectedActiveRowVersion, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Retires a version and clears runtime activation if necessary.</summary>
    Task<ConnectorVersionRecord> RetireAsync(Guid versionId, long expectedRowVersion, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Creates/replaces server-side logical bindings for one Environment.</summary>
    Task<ConnectorBindingSet> PutBindingsAsync(ConnectorBindingSet bindings, long? expectedRevision, Guid correlationId, CancellationToken cancellationToken);
    /// <summary>Lists immutable binding revisions for one Connector version.</summary>
    Task<AdminPage<ConnectorBindingSet>> ListBindingsPageAsync(Guid connectorVersionId, int offset, int limit, Guid? environmentId, CancellationToken cancellationToken);
    /// <summary>Computes the approval digest over the Connector checksum and all current immutable binding revisions.</summary>
    Task<byte[]> GetBindingBundleDigestAsync(Guid connectorVersionId, CancellationToken cancellationToken);
    /// <summary>Locks approval, Connector, binding and catalog revisions and recalculates the canonical digest in the approval transaction.</summary>
    Task<ConnectorApprovalRecord> ApproveCanonicalAsync(IAdminSecurityStore fallbackStore, Guid approvalRequestId, Guid connectorVersionId, string expectedDigestSha256, string createdBy, Guid approver, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Returns the active stamp, or null when no version is Published.</summary>
    Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken);
    /// <summary>Returns the Published definition with bindings, or null.</summary>
    Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken);
}

/// <summary>Immutable enrollment challenge.</summary>
public sealed record EnrollmentChallenge(Guid Id, Guid ActivationCodeId, byte[] Challenge, byte[] PublicKeySpki, DateTimeOffset ExpiresAt);

/// <summary>Bounded external response returned to the operation pipeline.</summary>
public sealed record ExternalResponse(int StatusCode, string ContentType, byte[] Body);
