using System.Security.Cryptography;
using System.Text;

namespace SecureIntegration.Broker.Core;

/// <summary>Implements the minimal Local Broker use cases without exposing secret plaintext.</summary>
public sealed class BrokerApplicationService
{
    private const int MaxLocalValueBytes = 524_288;
    private readonly ILocalSecretRepository secrets;
    private readonly ILocalProtectionProvider localProtection;
    private readonly AeadDataProtector aead;
    private readonly IGatewayInvoker? gateway;
    private readonly IBrokerAuditSink audit;
    private readonly byte[] entropy;

    /// <summary>Whether a fixed central Gateway invoker is configured.</summary>
    public bool GatewayConfigured => gateway is not null;

    /// <summary>Creates the application service.</summary>
    public BrokerApplicationService(ILocalSecretRepository secrets, ILocalProtectionProvider localProtection, AeadDataProtector aead, IBrokerAuditSink audit, string installationId, IGatewayInvoker? gateway = null)
    {
        this.secrets = secrets ?? throw new ArgumentNullException(nameof(secrets));
        this.localProtection = localProtection ?? throw new ArgumentNullException(nameof(localProtection));
        this.aead = aead ?? throw new ArgumentNullException(nameof(aead));
        this.audit = audit ?? throw new ArgumentNullException(nameof(audit));
        this.gateway = gateway;
        entropy = SHA256.HashData(Encoding.UTF8.GetBytes("broker-local-secret-v1\n" + installationId));
    }

    /// <summary>Stores a Tenant or Session secret and returns an opaque reference.</summary>
    public async Task<string> PutLocalSecretAsync(string applicationId, string logicalName, string secretClass, IReadOnlyCollection<string> allowedOperations, byte[] value, Guid correlationId, CancellationToken cancellationToken)
    {
        ValidateIdentifier(applicationId, nameof(applicationId));
        ValidateIdentifier(logicalName, nameof(logicalName));
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length is 0 or > MaxLocalValueBytes)
        {
            throw new BrokerException("invalid_secret_size", "validation");
        }

        if (!Enum.TryParse(secretClass, true, out LocalSecretClass parsedClass))
        {
            throw new BrokerException("secret_class_not_permitted", "authorization");
        }

        HashSet<string> operations = new(allowedOperations ?? Array.Empty<string>(), StringComparer.Ordinal);
        if (operations.Any(static operation => operation != "ComputeHmac"))
        {
            throw new BrokerException("secret_operation_not_permitted", "authorization");
        }

        string secretRef = "lsr_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        byte[] protectedValue = localProtection.Protect(value, entropy);
        try
        {
            await secrets.SaveAsync(new LocalSecretRecord(secretRef, applicationId, logicalName, parsedClass, operations, protectedValue), cancellationToken).ConfigureAwait(false);
            await audit.WriteAsync("PutLocalSecret", applicationId, correlationId, true, null, cancellationToken).ConfigureAwait(false);
            return secretRef;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedValue);
        }
    }

    /// <summary>Deletes an owned local secret.</summary>
    public async Task DeleteLocalSecretAsync(string applicationId, string secretRef, Guid correlationId, CancellationToken cancellationToken)
    {
        ValidateIdentifier(applicationId, nameof(applicationId));
        ValidateIdentifier(secretRef, nameof(secretRef));
        LocalSecretRecord? record = await secrets.FindAsync(secretRef, cancellationToken).ConfigureAwait(false);
        if (record is null)
        {
            await audit.WriteAsync("DeleteLocalSecret", applicationId, correlationId, true, null, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (!string.Equals(record.OwnerApplicationId, applicationId, StringComparison.Ordinal)) throw new BrokerException("secret_not_found", "not_found");
        _ = await secrets.DeleteAsync(secretRef, cancellationToken).ConfigureAwait(false);

        await audit.WriteAsync("DeleteLocalSecret", applicationId, correlationId, true, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Protects application data using the active Installation key.</summary>
    public Task<byte[]> ProtectDataAsync(string applicationId, string purpose, string contentType, byte[] plaintext, CancellationToken cancellationToken) =>
        aead.ProtectAsync(applicationId, purpose, contentType, plaintext, cancellationToken);

    /// <summary>Unprotects application data after authenticating its context.</summary>
    public Task<byte[]> UnprotectDataAsync(string applicationId, string purpose, string contentType, byte[] envelope, CancellationToken cancellationToken) =>
        aead.UnprotectAsync(applicationId, purpose, contentType, envelope, cancellationToken);

    /// <summary>Computes an HMAC without returning its local key.</summary>
    public async Task<byte[]> ComputeHmacAsync(string applicationId, string secretRef, byte[] message, Guid correlationId, CancellationToken cancellationToken)
    {
        LocalSecretRecord record = await OwnedSecretAsync(applicationId, secretRef, cancellationToken).ConfigureAwait(false);
        if (!record.AllowedOperations.Contains("ComputeHmac"))
        {
            throw new BrokerException("operation_not_granted", "authorization");
        }

        byte[] key = localProtection.Unprotect(record.ProtectedValue, entropy);
        try
        {
            byte[] digest = HMACSHA256.HashData(key, message);
            await audit.WriteAsync("ComputeHmac", applicationId, correlationId, true, null, cancellationToken).ConfigureAwait(false);
            return digest;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Invokes one Gateway operation selected only by Connector and operation IDs.</summary>
    public Task<GatewayInvocationResult> InvokeGatewayAsync(string applicationId, string connectorId, string operationId, string contentType, byte[] payload, Guid correlationId, CancellationToken cancellationToken)
    {
        if (gateway is null)
        {
            throw new BrokerException("gateway_not_configured", "configuration");
        }

        ValidateIdentifier(connectorId, nameof(connectorId));
        ValidateIdentifier(operationId, nameof(operationId));
        return gateway.InvokeAsync(applicationId, connectorId, operationId, contentType, payload, correlationId, cancellationToken);
    }

    private async Task<LocalSecretRecord> OwnedSecretAsync(string applicationId, string secretRef, CancellationToken cancellationToken)
    {
        ValidateIdentifier(applicationId, nameof(applicationId));
        ValidateIdentifier(secretRef, nameof(secretRef));
        LocalSecretRecord? record = await secrets.FindAsync(secretRef, cancellationToken).ConfigureAwait(false);
        if (record is null || !string.Equals(record.OwnerApplicationId, applicationId, StringComparison.Ordinal))
        {
            throw new BrokerException("secret_not_found", "not_found");
        }

        return record;
    }

    private static void ValidateIdentifier(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128)
        {
            throw new BrokerException("invalid_" + name, "validation");
        }
    }
}
