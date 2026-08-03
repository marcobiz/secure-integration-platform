namespace SecureIntegration.Broker.Infrastructure.Windows;

/// <summary>Windows Local Broker runtime settings.</summary>
public sealed class BrokerOptions
{
    /// <summary>Named Pipe name without the Windows prefix.</summary>
    public string PipeName { get; set; } = "SecureIntegration.Broker.v1";
    /// <summary>Stable Installation identifier.</summary>
    public string InstallationId { get; set; } = string.Empty;
    /// <summary>Broker-owned ProgramData directory.</summary>
    public string DataDirectory { get; set; } = string.Empty;
    /// <summary>Registered applications.</summary>
    public List<ApplicationPolicy> Applications { get; set; } = [];
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
    /// <summary>Allowed Gateway Connector/operation pairs formatted as connector:operation.</summary>
    public List<string> GatewayGrants { get; set; } = [];
}
