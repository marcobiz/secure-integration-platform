using System.Collections.ObjectModel;

namespace SecureIntegration.Tools.ConnectorProvisioning;

/// <summary>Closed ordered phases in the supported Connector provisioning workflow.</summary>
public enum ConnectorProvisioningPhase
{
    /// <summary>The immutable definition exists.</summary>
    DefinitionImported,
    /// <summary>The stored definition passed server validation.</summary>
    StoredValidation,
    /// <summary>The exact Environment binding exists.</summary>
    BindingConfiguration,
    /// <summary>The exact Installation operation grant exists.</summary>
    Grant,
    /// <summary>A checksum-specific approval was requested.</summary>
    Proposal,
    /// <summary>A distinct authorized principal approved the checksum.</summary>
    Approval,
    /// <summary>The exact version was Published.</summary>
    Publication,
    /// <summary>Published state and binding activation were read back.</summary>
    Verification
}

/// <summary>Closed redaction-safe state derived from authoritative server-side resources.</summary>
public enum ConnectorProvisioningCurrentState
{
    /// <summary>Authoritative discovery could not complete.</summary>
    Unknown,
    /// <summary>The exact version does not exist.</summary>
    Missing,
    /// <summary>The exact version is Draft.</summary>
    Draft,
    /// <summary>The exact version is Validated without a binding.</summary>
    Validated,
    /// <summary>The exact Validated version has its binding.</summary>
    BindingConfigured,
    /// <summary>The exact operation grant also exists.</summary>
    Granted,
    /// <summary>A current approval request exists.</summary>
    Proposed,
    /// <summary>The current request is Approved.</summary>
    Approved,
    /// <summary>The exact version is Published and its binding Active.</summary>
    PublishedActive
}

/// <summary>Exact logical provider identity and revisions used by a provisioning plan.</summary>
public sealed record ConnectorProvisioningProviderRevision(
    string BindingName,
    string ProviderId,
    string ResourceId,
    string? Version,
    long CatalogRevision,
    long PublicMetadataRevision);

/// <summary>
/// Connector-neutral identity whose values originate from the plan and supported server-side read APIs.
/// It deliberately contains no endpoint, credential value, token, certificate, or response metadata.
/// </summary>
public sealed class ConnectorProvisioningIdentity
{
    private readonly ReadOnlyCollection<ConnectorProvisioningProviderRevision> providerRevisions;

    /// <summary>Creates one exact, redaction-safe provisioning identity.</summary>
    public ConnectorProvisioningIdentity(
        string connectorId,
        string connectorVersion,
        string definitionChecksumSha256,
        Guid installationEnvironmentId,
        string bindingConfigurationDigestSha256,
        string operationProfileChecksumSha256,
        Guid applicationId,
        IEnumerable<ConnectorProvisioningProviderRevision> providerRevisions)
    {
        ConnectorId = Required(connectorId, 100, nameof(connectorId));
        ConnectorVersion = Required(connectorVersion, 64, nameof(connectorVersion));
        DefinitionChecksumSha256 = Checksum(definitionChecksumSha256, nameof(definitionChecksumSha256));
        InstallationEnvironmentId = installationEnvironmentId != Guid.Empty
            ? installationEnvironmentId
            : throw new ArgumentException("PROVISIONING_ENVIRONMENT_ID_INVALID", nameof(installationEnvironmentId));
        BindingConfigurationDigestSha256 = Checksum(bindingConfigurationDigestSha256, nameof(bindingConfigurationDigestSha256));
        OperationProfileChecksumSha256 = Checksum(operationProfileChecksumSha256, nameof(operationProfileChecksumSha256));
        ApplicationId = applicationId != Guid.Empty
            ? applicationId
            : throw new ArgumentException("PROVISIONING_APPLICATION_ID_INVALID", nameof(applicationId));
        ArgumentNullException.ThrowIfNull(providerRevisions);
        ConnectorProvisioningProviderRevision[] revisions = providerRevisions
            .Select(ValidateProvider)
            .OrderBy(value => value.BindingName, StringComparer.Ordinal)
            .ToArray();
        if (revisions.Length > 32 || revisions.Select(value => value.BindingName).Distinct(StringComparer.Ordinal).Count() != revisions.Length)
            throw new ArgumentException("PROVISIONING_PROVIDER_REVISIONS_INVALID", nameof(providerRevisions));
        this.providerRevisions = Array.AsReadOnly(revisions);
    }

    /// <summary>Exact Connector identifier.</summary>
    public string ConnectorId { get; }
    /// <summary>Exact Connector version.</summary>
    public string ConnectorVersion { get; }
    /// <summary>Canonical definition checksum.</summary>
    public string DefinitionChecksumSha256 { get; }
    /// <summary>Server-owned Installation Environment.</summary>
    public Guid InstallationEnvironmentId { get; }
    /// <summary>Plan binding-configuration digest.</summary>
    public string BindingConfigurationDigestSha256 { get; }
    /// <summary>Operation profile checksum.</summary>
    public string OperationProfileChecksumSha256 { get; }
    /// <summary>Server-owned installed application.</summary>
    public Guid ApplicationId { get; }
    /// <summary>Exact logical provider revisions, ordered by binding name.</summary>
    public IReadOnlyList<ConnectorProvisioningProviderRevision> ProviderRevisions => providerRevisions;

    internal bool ExactEquals(ConnectorProvisioningIdentity other)
    {
        if (!string.Equals(ConnectorId, other.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(ConnectorVersion, other.ConnectorVersion, StringComparison.Ordinal) ||
            !string.Equals(DefinitionChecksumSha256, other.DefinitionChecksumSha256, StringComparison.Ordinal) ||
            InstallationEnvironmentId != other.InstallationEnvironmentId ||
            !string.Equals(BindingConfigurationDigestSha256, other.BindingConfigurationDigestSha256, StringComparison.Ordinal) ||
            !string.Equals(OperationProfileChecksumSha256, other.OperationProfileChecksumSha256, StringComparison.Ordinal) ||
            ApplicationId != other.ApplicationId ||
            providerRevisions.Count != other.providerRevisions.Count)
            return false;

        for (int index = 0; index < providerRevisions.Count; index++)
        {
            ConnectorProvisioningProviderRevision left = providerRevisions[index];
            ConnectorProvisioningProviderRevision right = other.providerRevisions[index];
            if (!string.Equals(left.BindingName, right.BindingName, StringComparison.Ordinal) ||
                !string.Equals(left.ProviderId, right.ProviderId, StringComparison.Ordinal) ||
                !string.Equals(left.ResourceId, right.ResourceId, StringComparison.Ordinal) ||
                !string.Equals(left.Version, right.Version, StringComparison.Ordinal) ||
                left.CatalogRevision != right.CatalogRevision ||
                left.PublicMetadataRevision != right.PublicMetadataRevision)
                return false;
        }
        return true;
    }

    private static ConnectorProvisioningProviderRevision ValidateProvider(ConnectorProvisioningProviderRevision value)
    {
        ArgumentNullException.ThrowIfNull(value);
        string bindingName = Required(value.BindingName, 100, nameof(value.BindingName));
        string providerId = Required(value.ProviderId, 128, nameof(value.ProviderId));
        string resourceId = Required(value.ResourceId, 128, nameof(value.ResourceId));
        string? version = value.Version is null ? null : Required(value.Version, 128, nameof(value.Version));
        if (value.CatalogRevision < 1 || value.PublicMetadataRevision < 1)
            throw new ArgumentException("PROVISIONING_PROVIDER_REVISION_INVALID", nameof(value));
        return value with { BindingName = bindingName, ProviderId = providerId, ResourceId = resourceId, Version = version };
    }

    private static string Required(string value, int maximumLength, string parameter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameter);
        if (value.Length > maximumLength || !string.Equals(value, value.Trim(), StringComparison.Ordinal) || value.Any(char.IsControl))
            throw new ArgumentException("PROVISIONING_IDENTITY_VALUE_INVALID", parameter);
        return value;
    }

    private static string Checksum(string value, string parameter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameter);
        if (value.Length != 64 || !value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f'))
            throw new ArgumentException("PROVISIONING_CHECKSUM_INVALID", parameter);
        return value;
    }
}

/// <summary>Redaction-safe, closed phase decision returned by the shared state machine.</summary>
public sealed record ConnectorProvisioningSnapshot(
    ConnectorProvisioningCurrentState CurrentState,
    IReadOnlyList<ConnectorProvisioningPhase> CompletedPhases,
    ConnectorProvisioningPhase? NextRequiredPhase,
    bool RetrySafe);

/// <summary>Bounded result emitted when the Admin API rate limiter rejects an operation.</summary>
public sealed record ConnectorProvisioningRateLimitResult(
    string Code,
    ConnectorProvisioningCurrentState CurrentState,
    IReadOnlyList<ConnectorProvisioningPhase> CompletedPhases,
    ConnectorProvisioningPhase? NextRequiredPhase,
    bool RetrySafe,
    int? RetryAfterSeconds,
    string SupportedCommand);

/// <summary>Closed rate-limit signal produced by an Admin API adapter without retaining a response.</summary>
public sealed class ConnectorProvisioningRateLimitException(TimeSpan? retryAfter) : Exception("BGW-PROVISIONING-RATE-LIMITED")
{
    /// <summary>Parsed Retry-After value, or null when absent or invalid.</summary>
    public TimeSpan? RetryAfter { get; } = retryAfter;
}

/// <summary>Stable identity-drift error; mismatch details deliberately remain undisclosed.</summary>
public sealed class ConnectorProvisioningIdentityDriftException() : Exception("BGW-PROVISIONING-IDENTITY-DRIFT");

/// <summary>Connector-neutral exact-identity and monotonic-phase evaluator.</summary>
public static class ConnectorProvisioningStateMachine
{
    private static readonly ConnectorProvisioningPhase[] OrderedPhases = Enum.GetValues<ConnectorProvisioningPhase>();

    /// <summary>Validates exact identity and returns the next phase for one monotonic prefix.</summary>
    public static ConnectorProvisioningSnapshot Evaluate(
        ConnectorProvisioningIdentity expected,
        ConnectorProvisioningIdentity? observed,
        IEnumerable<ConnectorProvisioningPhase> completedPhases)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(completedPhases);
        if (observed is not null && !expected.ExactEquals(observed))
            throw new ConnectorProvisioningIdentityDriftException();

        ConnectorProvisioningPhase[] completed = completedPhases.ToArray();
        if (completed.Length > OrderedPhases.Length ||
            !completed.Select((phase, index) => phase == OrderedPhases[index]).All(value => value) ||
            (observed is null && completed.Length != 0) ||
            (observed is not null && completed.Length == 0))
            throw new InvalidOperationException("BGW-PROVISIONING-SERVER-STATE-INVALID");

        ConnectorProvisioningCurrentState current = completed.Length switch
        {
            0 => ConnectorProvisioningCurrentState.Missing,
            1 => ConnectorProvisioningCurrentState.Draft,
            2 => ConnectorProvisioningCurrentState.Validated,
            3 => ConnectorProvisioningCurrentState.BindingConfigured,
            4 => ConnectorProvisioningCurrentState.Granted,
            5 => ConnectorProvisioningCurrentState.Proposed,
            6 => ConnectorProvisioningCurrentState.Approved,
            7 or 8 => ConnectorProvisioningCurrentState.PublishedActive,
            _ => throw new InvalidOperationException("BGW-PROVISIONING-SERVER-STATE-INVALID")
        };
        ConnectorProvisioningPhase? next = completed.Length == OrderedPhases.Length ? null : OrderedPhases[completed.Length];
        return new(current, Array.AsReadOnly(completed), next, RetrySafe: true);
    }

    /// <summary>Creates the bounded redacted outcome for one non-retried HTTP 429.</summary>
    public static ConnectorProvisioningRateLimitResult RateLimited(
        ConnectorProvisioningSnapshot snapshot,
        TimeSpan? retryAfter,
        string supportedCommand)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentException.ThrowIfNullOrWhiteSpace(supportedCommand);
        if (supportedCommand.Length > 256 ||
            !string.Equals(supportedCommand, supportedCommand.Trim(), StringComparison.Ordinal) ||
            supportedCommand.Any(char.IsControl))
            throw new ArgumentException("PROVISIONING_SUPPORTED_COMMAND_INVALID", nameof(supportedCommand));
        int? seconds = null;
        if (retryAfter is { } delay && delay >= TimeSpan.Zero && delay <= TimeSpan.FromHours(1))
            seconds = checked((int)Math.Ceiling(delay.TotalSeconds));
        return new(
            "BGW-PROVISIONING-RATE-LIMITED",
            snapshot.CurrentState,
            snapshot.CompletedPhases,
            snapshot.NextRequiredPhase,
            snapshot.RetrySafe,
            seconds,
            supportedCommand);
    }
}
