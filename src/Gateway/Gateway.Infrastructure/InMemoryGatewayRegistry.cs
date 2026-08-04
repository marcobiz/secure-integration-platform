using System.Collections.Concurrent;
using System.Security.Cryptography;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Deterministic registry for unit/API tests and Development only.</summary>
public sealed class InMemoryGatewayRegistry : IGatewayRegistry
{
    private readonly object gate = new();
    private readonly Dictionary<Guid, TenantRecord> tenants = [];
    private readonly Dictionary<Guid, ApplicationRecord> applications = [];
    private readonly Dictionary<Guid, GatewayEnvironmentRecord> environments = [];
    private readonly Dictionary<Guid, InstallationRecord> installations = [];
    private readonly Dictionary<Guid, ActivationCodeRecord> activationCodes = [];
    private readonly Dictionary<Guid, InstallationCredentialRecord> credentials = [];
    private readonly Dictionary<Guid, InstallationGrantRecord> grants = [];
    private readonly Dictionary<string, DateTimeOffset> nonces = new(StringComparer.Ordinal);
    private readonly List<GatewayAuditEvent> auditEvents = [];

    /// <summary>Returns a stable audit snapshot for tests.</summary>
    public IReadOnlyList<GatewayAuditEvent> SnapshotAuditEvents()
    {
        lock (gate) return auditEvents.ToArray();
    }

    /// <inheritdoc />
    public Task AddTenantAsync(TenantRecord tenant, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (tenants.Values.Any(item => string.Equals(item.Code, tenant.Code, StringComparison.OrdinalIgnoreCase)) || !tenants.TryAdd(tenant.Id, tenant)) throw new GatewayException("BGW-VALIDATION-TENANT-DUPLICATE", 409);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task AddApplicationAsync(ApplicationRecord application, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (applications.Values.Any(item => string.Equals(item.Code, application.Code, StringComparison.OrdinalIgnoreCase)) || !applications.TryAdd(application.Id, application)) throw new GatewayException("BGW-VALIDATION-APPLICATION-DUPLICATE", 409);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task AddEnvironmentAsync(GatewayEnvironmentRecord environment, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (environments.Values.Any(item => string.Equals(item.Code, environment.Code, StringComparison.OrdinalIgnoreCase)) || !environments.TryAdd(environment.Id, environment)) throw new GatewayException("BGW-VALIDATION-ENVIRONMENT-DUPLICATE", 409);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task AddInstallationAsync(InstallationRecord installation, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!tenants.ContainsKey(installation.TenantId) || !applications.ContainsKey(installation.ApplicationId) || !environments.ContainsKey(installation.EnvironmentId)) throw new GatewayException("BGW-VALIDATION-REGISTRY-REFERENCE", 400);
            if (!installations.TryAdd(installation.Id, installation)) throw new GatewayException("BGW-VALIDATION-INSTALLATION-DUPLICATE", 409);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task AddActivationCodeAsync(ActivationCodeRecord activationCode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!installations.TryGetValue(activationCode.InstallationId, out InstallationRecord? installation) || installation.Status != InstallationStatus.Pending) throw new GatewayException("BGW-INSTALLATION-NOT-PENDING", 409);
            if (activationCodes.Values.Any(item => CryptographicOperations.FixedTimeEquals(item.CodeHmac, activationCode.CodeHmac)) || !activationCodes.TryAdd(activationCode.Id, Clone(activationCode))) throw new GatewayException("BGW-AUTHN-ACTIVATION-DUPLICATE", 409);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task AddGrantAsync(InstallationGrantRecord grant, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!installations.TryGetValue(grant.InstallationId, out InstallationRecord? installation) || installation.TenantId != grant.TenantId) throw new GatewayException("BGW-AUTHZ-CROSS-TENANT-GRANT", 403);
            if (grants.Values.Any(item => item.InstallationId == grant.InstallationId && item.ConnectorId == grant.ConnectorId && item.OperationId == grant.OperationId) || !grants.TryAdd(grant.Id, grant)) throw new GatewayException("BGW-AUTHZ-GRANT-DUPLICATE", 409);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<ActivationCodeRecord?> FindActivationCodeAsync(Guid activationCodeId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate) return Task.FromResult(activationCodes.TryGetValue(activationCodeId, out ActivationCodeRecord? value) ? Clone(value) : null);
    }

    /// <inheritdoc />
    public Task RecordActivationFailureAsync(Guid activationCodeId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (activationCodes.TryGetValue(activationCodeId, out ActivationCodeRecord? value)) activationCodes[activationCodeId] = value with { AttemptCount = checked((short)Math.Min(5, value.AttemptCount + 1)) };
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> ActivateAsync(Guid activationCodeId, byte[] expectedCodeHmac, InstallationCredentialRecord credential, string brokerVersion, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!activationCodes.TryGetValue(activationCodeId, out ActivationCodeRecord? activation) || activation.UsedAt is not null || activation.ExpiresAt <= now || activation.AttemptCount >= 5 || !CryptographicOperations.FixedTimeEquals(activation.CodeHmac, expectedCodeHmac)) return Task.FromResult(false);
            if (!installations.TryGetValue(activation.InstallationId, out InstallationRecord? installation) || installation.Status != InstallationStatus.Pending || credential.InstallationId != installation.Id) return Task.FromResult(false);
            ApplicationRecord application = applications[installation.ApplicationId];
            if (!IsVersionAllowed(brokerVersion, application.MinimumBrokerVersion, application.MaximumBrokerVersion)) throw new GatewayException("BGW-INSTALLATION-BROKER-INCOMPATIBLE", 409);
            if (credentials.Values.Any(item => CryptographicOperations.FixedTimeEquals(item.CertificateSha256, credential.CertificateSha256) || CryptographicOperations.FixedTimeEquals(item.SpkiSha256, credential.SpkiSha256))) return Task.FromResult(false);
            activationCodes[activationCodeId] = activation with { UsedAt = now };
            installations[installation.Id] = installation with { Status = InstallationStatus.Active, BrokerVersion = brokerVersion, LastSeenAt = now };
            credentials.Add(credential.Id, Clone(credential));
            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    public Task<RegisteredInstallationIdentity?> FindIdentityByCertificateAsync(byte[] certificateSha256, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            InstallationCredentialRecord? credential = credentials.Values.FirstOrDefault(item => CryptographicOperations.FixedTimeEquals(item.CertificateSha256, certificateSha256));
            if (credential is null || !installations.TryGetValue(credential.InstallationId, out InstallationRecord? installation) || !applications.TryGetValue(installation.ApplicationId, out ApplicationRecord? application)) return Task.FromResult<RegisteredInstallationIdentity?>(null);
            TenantRecord tenant = tenants[installation.TenantId];
            return Task.FromResult<RegisteredInstallationIdentity?>(new RegisteredInstallationIdentity(installation.Id, installation.TenantId, installation.ApplicationId, installation.EnvironmentId, tenant.Status, application.Status, installation.Status, credential.Id, credential.Status, credential.CertificateDer.ToArray(), credential.NotBefore, credential.NotAfter, application.MinimumBrokerVersion, application.MaximumBrokerVersion));
        }
    }

    /// <inheritdoc />
    public Task<bool> RenewCredentialAsync(Guid installationId, Guid currentCredentialId, InstallationCredentialRecord replacement, DateTimeOffset overlapEndsAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!installations.TryGetValue(installationId, out InstallationRecord? installation) || installation.Status != InstallationStatus.Active || !credentials.TryGetValue(currentCredentialId, out InstallationCredentialRecord? current) || current.InstallationId != installationId || current.Status != CredentialStatus.Active || replacement.InstallationId != installationId) return Task.FromResult(false);
            if (credentials.Values.Any(item => CryptographicOperations.FixedTimeEquals(item.CertificateSha256, replacement.CertificateSha256) || CryptographicOperations.FixedTimeEquals(item.SpkiSha256, replacement.SpkiSha256))) return Task.FromResult(false);
            credentials[currentCredentialId] = current with { Status = CredentialStatus.Overlap, NotAfter = current.NotAfter < overlapEndsAt ? current.NotAfter : overlapEndsAt, ReplacedById = replacement.Id };
            credentials.Add(replacement.Id, Clone(replacement));
            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    public Task<bool> RevokeInstallationAsync(Guid installationId, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!installations.TryGetValue(installationId, out InstallationRecord? installation) || installation.Status is InstallationStatus.Revoked or InstallationStatus.Retired) return Task.FromResult(false);
            installations[installationId] = installation with { Status = InstallationStatus.Revoked, RevokedAt = now, RevocationReason = reason };
            foreach (Guid credentialId in credentials.Values.Where(item => item.InstallationId == installationId && item.Status is CredentialStatus.Active or CredentialStatus.Overlap).Select(item => item.Id).ToArray()) credentials[credentialId] = credentials[credentialId] with { Status = CredentialStatus.Revoked, RevokedAt = now };
            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    public Task<bool> IsGrantedAsync(Guid installationId, Guid tenantId, string connectorId, string operationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate) return Task.FromResult(grants.Values.Any(item => item.InstallationId == installationId && item.TenantId == tenantId && item.Enabled && item.ConnectorId == connectorId && item.OperationId == operationId && item.ValidFrom <= now && (item.ValidUntil is null || item.ValidUntil > now)));
    }

    /// <inheritdoc />
    public Task<bool> TryStoreNonceAsync(Guid installationId, byte[] nonceSha256, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            foreach (string expired in nonces.Where(item => item.Value <= DateTimeOffset.UtcNow).Select(item => item.Key).ToArray()) nonces.Remove(expired);
            return Task.FromResult(nonces.TryAdd(installationId.ToString("N") + ':' + Convert.ToHexString(nonceSha256), expiresAt));
        }
    }

    /// <inheritdoc />
    public Task AppendAuditAsync(GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate) auditEvents.Add(auditEvent);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(true);
    }

    private static ActivationCodeRecord Clone(ActivationCodeRecord value) => value with { CodeHmac = value.CodeHmac.ToArray() };
    private static InstallationCredentialRecord Clone(InstallationCredentialRecord value) => value with { CertificateSha256 = value.CertificateSha256.ToArray(), SpkiSha256 = value.SpkiSha256.ToArray(), CertificateDer = value.CertificateDer.ToArray() };
    private static bool IsVersionAllowed(string value, string minimum, string? maximum) => Version.TryParse(value, out Version? parsed) && Version.TryParse(minimum, out Version? min) && parsed >= min && (maximum is null || (Version.TryParse(maximum, out Version? max) && parsed <= max));
}
