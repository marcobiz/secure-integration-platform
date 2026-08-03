namespace SecureIntegration.Broker.Core;

/// <summary>Classes of secret permitted in local Broker persistence.</summary>
public enum LocalSecretClass
{
    /// <summary>Tenant-owned secret.</summary>
    Tenant,
    /// <summary>Short-lived session secret.</summary>
    Session,
}

/// <summary>A protected local-secret record. Its value is never plaintext.</summary>
public sealed record LocalSecretRecord(
    string SecretRef,
    string OwnerApplicationId,
    string LogicalName,
    LocalSecretClass SecretClass,
    IReadOnlySet<string> AllowedOperations,
    byte[] ProtectedValue);

/// <summary>A versioned Installation data key.</summary>
public sealed record DataKey(uint Version, byte[] Value);

/// <summary>Persists protected local-secret records.</summary>
public interface ILocalSecretRepository
{
    /// <summary>Saves a record atomically.</summary>
    Task SaveAsync(LocalSecretRecord record, CancellationToken cancellationToken);
    /// <summary>Finds a record by opaque reference.</summary>
    Task<LocalSecretRecord?> FindAsync(string secretRef, CancellationToken cancellationToken);
    /// <summary>Deletes a record.</summary>
    Task<bool> DeleteAsync(string secretRef, CancellationToken cancellationToken);
}

/// <summary>Provides versioned Installation-scoped data keys.</summary>
public interface IDataKeyRepository
{
    /// <summary>Gets or creates the active key.</summary>
    Task<DataKey> GetActiveAsync(CancellationToken cancellationToken);
    /// <summary>Gets a historical key used to decrypt an envelope.</summary>
    Task<DataKey?> GetAsync(uint version, CancellationToken cancellationToken);
}

/// <summary>Protects bytes under the Windows service identity.</summary>
public interface ILocalProtectionProvider
{
    /// <summary>Protects plaintext.</summary>
    byte[] Protect(byte[] plaintext, byte[] entropy);
    /// <summary>Unprotects ciphertext.</summary>
    byte[] Unprotect(byte[] protectedData, byte[] entropy);
}

/// <summary>Invokes the configured central Gateway without exposing endpoints or bindings.</summary>
public interface IGatewayInvoker
{
    /// <summary>Invokes one pre-authorized Connector operation.</summary>
    Task<GatewayInvocationResult> InvokeAsync(
        string applicationId,
        string connectorId,
        string operationId,
        string contentType,
        byte[] payload,
        Guid correlationId,
        CancellationToken cancellationToken);
}

/// <summary>Gateway response visible to the client.</summary>
public sealed record GatewayInvocationResult(string ContentType, byte[] Payload, string ConnectorVersion);

/// <summary>Receives metadata-only Broker audit events.</summary>
public interface IBrokerAuditSink
{
    /// <summary>Writes an event that must not include request or secret payloads.</summary>
    Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken);
}

/// <summary>Stable Broker failure safe to map to the wire protocol.</summary>
public sealed class BrokerException : Exception
{
    /// <summary>Creates a redacted Broker failure.</summary>
    public BrokerException(string code, string category, bool retryable = false, Exception? innerException = null)
        : base(code, innerException)
    {
        Code = code;
        Category = category;
        Retryable = retryable;
    }

    /// <summary>Machine-readable error code.</summary>
    public string Code { get; }
    /// <summary>Error category.</summary>
    public string Category { get; }
    /// <summary>Whether retry can be considered.</summary>
    public bool Retryable { get; }
}
