using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Api;

/// <summary>Gateway host configuration containing references and policy, not secret values in files.</summary>
public sealed class GatewayHostOptions
{
    /// <summary>Azure Key Vault HTTPS endpoint.</summary>
    public string? KeyVaultUri { get; init; }
    /// <summary>Optional user-assigned Managed Identity client identifier.</summary>
    public string? ManagedIdentityClientId { get; init; }
    /// <summary>Base64 activation HMAC key supplied by a protected configuration provider.</summary>
    public string? ActivationHmacKeyBase64 { get; init; }
    /// <summary>Azure Key Vault logical reference for the production activation HMAC key.</summary>
    public string? ActivationHmacSecretReference { get; init; }
    /// <summary>HTTPS endpoint for the deterministic M3 synthetic Vault; rejected outside M3Testing.</summary>
    public string? SyntheticVaultUri { get; init; }
    /// <summary>Environment variable containing the per-run synthetic Vault access token.</summary>
    public string SyntheticVaultTokenEnvironmentVariable { get; init; } = "M3_SYNTHETIC_VAULT_TOKEN";
    /// <summary>Exact synthetic vendor host allowed on a private M3 test network.</summary>
    public string? M3PrivateMockHost { get; init; }
    /// <summary>Private CIDR containing only the synthetic vendor fixture.</summary>
    public string? M3PrivateMockCidr { get; init; }
    /// <summary>Trust App Service's X-ARR-ClientCert boundary; valid only inside Azure App Service.</summary>
    public bool TrustAzureAppServiceClientCertificateForwarding { get; init; }
    /// <summary>Server-owned operation allowlist.</summary>
    public List<GatewayOperationConfiguration> Operations { get; init; } = [];
}

/// <summary>Configuration representation of one immutable outbound operation.</summary>
public sealed class GatewayOperationConfiguration
{
    /// <summary>Connector identifier.</summary>
    public required string ConnectorId { get; init; }
    /// <summary>Operation identifier.</summary>
    public required string OperationId { get; init; }
    /// <summary>Operation configuration version.</summary>
    public required string Version { get; init; }
    /// <summary>Fixed HTTPS destination.</summary>
    public required string Endpoint { get; init; }
    /// <summary>Fixed HTTP method.</summary>
    public string Method { get; init; } = "POST";
    /// <summary>Fixed outbound content type.</summary>
    public string RequestContentType { get; init; } = "application/octet-stream";
    /// <summary>Server-side authentication mode.</summary>
    public GatewayAuthenticationKind Authentication { get; init; }
    /// <summary>Basic username secret reference.</summary>
    public string? UsernameSecretReference { get; init; }
    /// <summary>Basic password secret reference.</summary>
    public string? PasswordSecretReference { get; init; }
    /// <summary>API key secret reference.</summary>
    public string? ApiKeySecretReference { get; init; }
    /// <summary>Fixed API key header name.</summary>
    public string? ApiKeyHeaderName { get; init; }
    /// <summary>Outbound client certificate secret reference.</summary>
    public string? ClientCertificateReference { get; init; }
    /// <summary>End-to-end operation timeout.</summary>
    public int TimeoutMilliseconds { get; init; } = 30_000;
    /// <summary>Maximum decoded request bytes.</summary>
    public long MaximumRequestBytes { get; init; } = 16 * 1024 * 1024;
    /// <summary>Maximum buffered response bytes.</summary>
    public long MaximumResponseBytes { get; init; } = 16 * 1024 * 1024;
    /// <summary>Whether retry is safe for the operation.</summary>
    public bool Idempotent { get; init; }
    /// <summary>Maximum retry count for transient transport failures.</summary>
    public int MaximumRetries { get; init; }

    /// <summary>Creates the validated application definition.</summary>
    public GatewayOperationDefinition ToDefinition() => new(
        ConnectorId, OperationId, Version, new Uri(Endpoint, UriKind.Absolute), new HttpMethod(Method), RequestContentType,
        Authentication, UsernameSecretReference, PasswordSecretReference, ApiKeySecretReference, ApiKeyHeaderName,
        ClientCertificateReference, TimeoutMilliseconds, MaximumRequestBytes, MaximumResponseBytes, Idempotent, MaximumRetries);
}
