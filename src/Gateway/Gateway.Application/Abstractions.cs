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

/// <summary>Central secret provider. Values are usable only by Gateway runtime code.</summary>
public interface ISecretProvider
{
    /// <summary>Gets a secret for internal request construction.</summary>
    Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken);
    /// <summary>Gets an outbound client certificate.</summary>
    Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken);
    /// <summary>Checks secret-provider readiness.</summary>
    Task<bool> IsReadyAsync(CancellationToken cancellationToken);
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
    /// <summary>Gets one configured operation or rejects the identifier.</summary>
    GatewayOperationDefinition GetRequired(string connectorId, string operationId);
}

/// <summary>Immutable enrollment challenge.</summary>
public sealed record EnrollmentChallenge(Guid Id, Guid ActivationCodeId, byte[] Challenge, byte[] PublicKeySpki, DateTimeOffset ExpiresAt);

/// <summary>Bounded external response returned to the operation pipeline.</summary>
public sealed record ExternalResponse(int StatusCode, string ContentType, byte[] Body);
