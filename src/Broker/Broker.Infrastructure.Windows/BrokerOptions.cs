namespace SecureIntegration.Broker.Infrastructure.Windows;

/// <summary>Windows Local Broker runtime settings.</summary>
public sealed class BrokerOptions
{
    /// <summary>Administrator-installed Windows service name, also used as the Event Log source.</summary>
    public string ServiceName { get; set; } = "SecureIntegrationBroker";
    /// <summary>Named Pipe name without the Windows prefix.</summary>
    public string PipeName { get; set; } = "SecureIntegration.Broker.v1";
    /// <summary>Stable Installation identifier.</summary>
    public string InstallationId { get; set; } = string.Empty;
    /// <summary>Broker-owned ProgramData directory.</summary>
    public string DataDirectory { get; set; } = string.Empty;
    /// <summary>Explicit first-install provisioning only; disable after initialization. Never repairs partial or lost state.</summary>
    public bool InitializeDataKeys { get; set; }
    /// <summary>Registered applications.</summary>
    public List<ApplicationPolicy> Applications { get; set; } = [];
    /// <summary>Production Gateway installation-authentication settings.</summary>
    public GatewayInstallationOptions Gateway { get; set; } = new();
}

/// <summary>Fixed central Gateway and Installation credential settings.</summary>
public sealed class GatewayInstallationOptions
{
    /// <summary>Enables the production authenticated Gateway client.</summary>
    public bool Enabled { get; set; }
    /// <summary>Fixed HTTPS Gateway origin. Paths are always constructed by the Broker.</summary>
    public string BaseAddress { get; set; } = string.Empty;
    /// <summary>Opaque one-time activation record identifier provisioned out of band.</summary>
    public string ActivationCodeId { get; set; } = string.Empty;
    /// <summary>Name of the process environment variable containing the one-time code.</summary>
    public string ActivationCodeEnvironmentVariable { get; set; } = "BROKER_GATEWAY_ACTIVATION_CODE";
    /// <summary>Persisted CNG key name. The key is created non-exportable under the service identity.</summary>
    public string CngKeyName { get; set; } = "SecureIntegration.Broker.Installation.v1";
    /// <summary>Broker semantic version sent during enrollment.</summary>
    public string BrokerVersion { get; set; } = "1.0.0";
    /// <summary>Bounded request timeout.</summary>
    public int TimeoutSeconds { get; set; } = 30;
}

/// <summary>Deny-by-default policy for one local application.</summary>
public sealed class ApplicationPolicy
{
    /// <summary>Opaque application registration ID sent in the handshake.</summary>
    public string RegistrationId { get; set; } = string.Empty;
    /// <summary>Allowed Windows user SIDs.</summary>
    public List<string> AllowedUserSids { get; set; } = [];
    /// <summary>Allowed absolute executable paths.</summary>
    public List<string> ExecutablePaths { get; set; } = [];
    /// <summary>Allowed SHA-256 executable hashes; at least one path is always required.</summary>
    public List<string> ExecutableSha256 { get; set; } = [];
    /// <summary>Allowed trusted Authenticode leaf-certificate thumbprints.</summary>
    public List<string> AllowedPublisherThumbprints { get; set; } = [];
    /// <summary>Allowed Broker operations.</summary>
    public List<string> AllowedOperations { get; set; } = [];
    /// <summary>Exact allowed purpose/content-type pairs for local ProtectData and UnprotectData. Empty denies both.</summary>
    public List<DataProtectionContext> AllowedDataProtectionContexts { get; set; } = [];
    /// <summary>Allowed Gateway Connector/operation pairs formatted as connector:operation.</summary>
    public List<string> GatewayGrants { get; set; } = [];
}

/// <summary>One administrator-authorized local data context.</summary>
public sealed class DataProtectionContext
{
    /// <summary>Exact, case-sensitive data purpose.</summary>
    public string Purpose { get; set; } = string.Empty;
    /// <summary>Exact, case-sensitive content type.</summary>
    public string ContentType { get; set; } = string.Empty;
}
