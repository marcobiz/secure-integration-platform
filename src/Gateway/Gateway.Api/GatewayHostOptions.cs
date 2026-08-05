using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Api;

/// <summary>Gateway host configuration containing references and policy, not secret values in files.</summary>
public sealed class GatewayHostOptions
{
    /// <summary>Base64 activation HMAC key supplied by a protected configuration provider.</summary>
    public string? ActivationHmacKeyBase64 { get; init; }
    /// <summary>Logical provider reference for the production activation HMAC key.</summary>
    public string? ActivationHmacSecretReference { get; init; }
    /// <summary>Provider-neutral deployment pack configuration.</summary>
    public GatewayProviderOptions Provider { get; init; } = new();
    /// <summary>Exact synthetic vendor host allowed on a private M3 test network.</summary>
    public string? M3PrivateMockHost { get; init; }
    /// <summary>Private CIDR containing only the synthetic vendor fixture.</summary>
    public string? M3PrivateMockCidr { get; init; }
    /// <summary>Trust a deployment platform's explicitly configured client-certificate forwarding boundary.</summary>
    public bool TrustPlatformClientCertificateForwarding { get; init; }
    /// <summary>Server-owned operation allowlist.</summary>
    public List<GatewayOperationConfiguration> Operations { get; init; } = [];
    /// <summary>Published Connector cache TTL. A store stamp is still checked on every invocation.</summary>
    public int ConnectorCacheTtlSeconds { get; init; } = 30;
    /// <summary>Authentication configuration for the provider-neutral Admin API.</summary>
    public GatewayAdminOptions Admin { get; init; } = new();
}

/// <summary>Provider-neutral composition settings. Provider-specific values remain owned by the pack.</summary>
public sealed class GatewayProviderOptions
{
    /// <summary>Disabled, InMemory, Synthetic or ExternalPack.</summary>
    public string Kind { get; init; } = "Disabled";
    /// <summary>Fixed HTTPS endpoint owned by the selected provider pack.</summary>
    public string? Endpoint { get; init; }
    /// <summary>Optional deployment identity identifier interpreted only by the pack.</summary>
    public string? ClientIdentity { get; init; }
    /// <summary>Absolute assembly path for an optional deployment pack.</summary>
    public string? AssemblyPath { get; init; }
    /// <summary>Full factory type name implementing the provider pack contract.</summary>
    public string? FactoryType { get; init; }
    /// <summary>Environment variable containing a synthetic provider access token.</summary>
    public string AccessTokenEnvironmentVariable { get; init; } = "M3_SYNTHETIC_VAULT_TOKEN";
    /// <summary>Opaque non-secret provider settings. Secrets are references or process environment values.</summary>
    public Dictionary<string, string> Settings { get; init; } = new(StringComparer.Ordinal);
}

/// <summary>Admin API authentication. DevelopmentApiKey is rejected outside Development/Testing.</summary>
public sealed class GatewayAdminOptions
{
    /// <summary>Disabled, Oidc, DevelopmentAuth or the M4Testing-only DevelopmentApiKey compatibility mode.</summary>
    public string Mode { get; init; } = "Disabled";
    /// <summary>Process environment variable containing the development-only API key.</summary>
    public string ApiKeyEnvironmentVariable { get; init; } = "GATEWAY_ADMIN_API_KEY";
    /// <summary>Environment variable containing the one-time bootstrap token.</summary>
    public string BootstrapTokenEnvironmentVariable { get; init; } = "GATEWAY_ADMIN_BOOTSTRAP_TOKEN";
    /// <summary>Requires checksum-specific approval by a distinct principal before publication.</summary>
    public bool RequireFourEyes { get; init; } = true;
    /// <summary>Explicit proxy IP addresses allowed to supply forwarded headers.</summary>
    public List<string> TrustedProxies { get; init; } = [];
    /// <summary>Provider-neutral OIDC client configuration.</summary>
    public GatewayOidcOptions Oidc { get; init; } = new();
}

/// <summary>Standard confidential OIDC client settings.</summary>
public sealed class GatewayOidcOptions
{
    /// <summary>HTTPS issuer/authority.</summary>
    public string? Authority { get; init; }
    /// <summary>OIDC client identifier.</summary>
    public string? ClientId { get; init; }
    /// <summary>Process environment variable containing the confidential client secret.</summary>
    public string ClientSecretEnvironmentVariable { get; init; } = "GATEWAY_ADMIN_OIDC_CLIENT_SECRET";
    /// <summary>OIDC callback path registered with the provider.</summary>
    public string CallbackPath { get; init; } = "/admin/auth/callback";
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
