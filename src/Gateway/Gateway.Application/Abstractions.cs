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

/// <summary>Gateway persistence boundary.</summary>
public interface IGatewayRegistry
{
    /// <summary>Adds a Tenant.</summary>
    Task AddTenantAsync(TenantRecord tenant, CancellationToken cancellationToken);
    /// <summary>Adds an Application.</summary>
    Task AddApplicationAsync(ApplicationRecord application, CancellationToken cancellationToken);
    /// <summary>Adds an Environment.</summary>
    Task AddEnvironmentAsync(GatewayEnvironmentRecord environment, CancellationToken cancellationToken);
    /// <summary>Adds a tenant-bound Installation.</summary>
    Task AddInstallationAsync(InstallationRecord installation, CancellationToken cancellationToken);
    /// <summary>Adds a one-time activation record.</summary>
    Task AddActivationCodeAsync(ActivationCodeRecord activationCode, CancellationToken cancellationToken);
    /// <summary>Adds an operation grant.</summary>
    Task AddGrantAsync(InstallationGrantRecord grant, CancellationToken cancellationToken);
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
    /// <summary>Checks an operation grant in the authenticated tenant scope.</summary>
    Task<bool> IsGrantedAsync(Guid installationId, Guid tenantId, string connectorId, string operationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Stores a replay digest if it has not been seen.</summary>
    Task<bool> TryStoreNonceAsync(Guid installationId, byte[] nonceSha256, DateTimeOffset expiresAt, CancellationToken cancellationToken);
    /// <summary>Appends a metadata-only audit event.</summary>
    Task AppendAuditAsync(GatewayAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Checks persistence readiness.</summary>
    Task<bool> IsReadyAsync(CancellationToken cancellationToken);
}

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
    /// <summary>Creates a new Draft; Connector/version pairs are unique.</summary>
    Task<ConnectorVersionRecord> CreateDraftAsync(ConnectorVersionRecord draft, CancellationToken cancellationToken);
    /// <summary>Gets a version by Connector and semantic version.</summary>
    Task<ConnectorVersionRecord?> GetVersionAsync(string connectorId, string version, CancellationToken cancellationToken);
    /// <summary>Lists all known Connectors.</summary>
    Task<IReadOnlyList<ConnectorSummary>> ListConnectorsAsync(CancellationToken cancellationToken);
    /// <summary>Lists versions newest first.</summary>
    Task<IReadOnlyList<ConnectorVersionRecord>> ListVersionsAsync(string connectorId, CancellationToken cancellationToken);
    /// <summary>Transitions Draft to Validated using optimistic concurrency.</summary>
    Task<ConnectorVersionRecord> MarkValidatedAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Publishes a Validated version and supersedes the current one atomically.</summary>
    Task<ConnectorVersionRecord> PublishAsync(Guid versionId, long expectedRowVersion, long expectedPublicationRevision, string actor, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Reactivates a previously Published, now Superseded version atomically.</summary>
    Task<ConnectorVersionRecord> RollbackAsync(string connectorId, string targetVersion, long expectedActiveRowVersion, string actor, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Retires a version and clears runtime activation if necessary.</summary>
    Task<ConnectorVersionRecord> RetireAsync(Guid versionId, long expectedRowVersion, string actor, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Creates/replaces server-side logical bindings for one Environment.</summary>
    Task<ConnectorBindingSet> PutBindingsAsync(ConnectorBindingSet bindings, long? expectedRevision, CancellationToken cancellationToken);
    /// <summary>Returns the active stamp, or null when no version is Published.</summary>
    Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken);
    /// <summary>Returns the Published definition with bindings, or null.</summary>
    Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken);
}

/// <summary>Immutable enrollment challenge.</summary>
public sealed record EnrollmentChallenge(Guid Id, Guid ActivationCodeId, byte[] Challenge, byte[] PublicKeySpki, DateTimeOffset ExpiresAt);

/// <summary>Bounded external response returned to the operation pipeline.</summary>
public sealed record ExternalResponse(int StatusCode, string ContentType, byte[] Body);
