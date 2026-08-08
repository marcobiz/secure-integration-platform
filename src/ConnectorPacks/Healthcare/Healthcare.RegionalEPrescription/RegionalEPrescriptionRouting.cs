using System.Collections.ObjectModel;
using System.Collections.Frozen;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.RegionalEPrescription;

/// <summary>Publication state of a server-owned regional profile.</summary>
public enum RegionalEPrescriptionProfileAvailability
{
    /// <summary>Published, current and eligible for dispatch.</summary>
    Active,
    /// <summary>Administratively disabled.</summary>
    Disabled,
    /// <summary>No production handler may be published until the named specification gaps are closed.</summary>
    BlockedBySpec
}

/// <summary>
/// Immutable server-side profile binding resolved from authenticated identity and Published
/// configuration. Collections are copied and a fingerprint covers the complete authority snapshot.
/// </summary>
public sealed class RegionalEPrescriptionProfileBinding
{
    /// <summary>Creates a snapshot from protected Published configuration.</summary>
    public RegionalEPrescriptionProfileBinding(
        Guid tenantId,
        Guid applicationId,
        Guid installationId,
        Guid environmentId,
        string connectorId,
        string connectorVersion,
        string operationId,
        string profileId,
        RegionalEPrescriptionProfileAvailability availability,
        string endpointBindingId,
        string authPolicyReference,
        IEnumerable<string> credentialBindingIds,
        long profileRevision,
        long endpointRevision,
        long authPolicyRevision,
        string resourceStamp,
        string? blockCode = null)
    {
        string[] credentials = credentialBindingIds?.ToArray() ?? throw new ArgumentNullException(nameof(credentialBindingIds));
        TenantId = tenantId;
        ApplicationId = applicationId;
        InstallationId = installationId;
        EnvironmentId = environmentId;
        ConnectorId = connectorId;
        ConnectorVersion = connectorVersion;
        OperationId = operationId;
        ProfileId = profileId;
        Availability = availability;
        EndpointBindingId = endpointBindingId;
        AuthPolicyReference = authPolicyReference;
        CredentialBindingIds = new ReadOnlyCollection<string>(credentials);
        ProfileRevision = profileRevision;
        EndpointRevision = endpointRevision;
        AuthPolicyRevision = authPolicyRevision;
        ResourceStamp = resourceStamp;
        BlockCode = blockCode;
        BindingFingerprint = ComputeFingerprint(this);
    }

    /// <summary>Server-derived Tenant.</summary>
    public Guid TenantId { get; }
    /// <summary>Server-derived Application.</summary>
    public Guid ApplicationId { get; }
    /// <summary>Server-derived Installation.</summary>
    public Guid InstallationId { get; }
    /// <summary>Server-derived Environment.</summary>
    public Guid EnvironmentId { get; }
    /// <summary>Published Connector ID.</summary>
    public string ConnectorId { get; }
    /// <summary>Published immutable Connector version.</summary>
    public string ConnectorVersion { get; }
    /// <summary>Authorized operation.</summary>
    public string OperationId { get; }
    /// <summary>Server-owned compiled profile ID.</summary>
    public string ProfileId { get; }
    /// <summary>Profile readiness/publication state.</summary>
    public RegionalEPrescriptionProfileAvailability Availability { get; }
    /// <summary>Logical endpoint binding selected by Published configuration.</summary>
    public string EndpointBindingId { get; }
    /// <summary>Logical authentication policy reference.</summary>
    public string AuthPolicyReference { get; }
    /// <summary>Exact copied logical credential binding set.</summary>
    public IReadOnlyList<string> CredentialBindingIds { get; }
    /// <summary>Profile revision.</summary>
    public long ProfileRevision { get; }
    /// <summary>Endpoint revision.</summary>
    public long EndpointRevision { get; }
    /// <summary>Authentication policy revision.</summary>
    public long AuthPolicyRevision { get; }
    /// <summary>Current Published resource stamp.</summary>
    public string ResourceStamp { get; }
    /// <summary>Public-safe block code when the profile is not active.</summary>
    public string? BlockCode { get; }
    /// <summary>SHA-256 over every authority and logical-resource dimension in this immutable snapshot.</summary>
    public string BindingFingerprint { get; }

    private static string ComputeFingerprint(RegionalEPrescriptionProfileBinding binding)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, binding.TenantId.ToString("D"));
        Append(hash, binding.ApplicationId.ToString("D"));
        Append(hash, binding.InstallationId.ToString("D"));
        Append(hash, binding.EnvironmentId.ToString("D"));
        Append(hash, binding.ConnectorId);
        Append(hash, binding.ConnectorVersion);
        Append(hash, binding.OperationId);
        Append(hash, binding.ProfileId);
        Append(hash, binding.Availability.ToString());
        Append(hash, binding.EndpointBindingId);
        Append(hash, binding.AuthPolicyReference);
        Append(hash, binding.CredentialBindingIds.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (string credential in binding.CredentialBindingIds) Append(hash, credential);
        Append(hash, binding.ProfileRevision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Append(hash, binding.EndpointRevision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Append(hash, binding.AuthPolicyRevision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Append(hash, binding.ResourceStamp);
        Append(hash, binding.BlockCode ?? string.Empty);
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void Append(IncrementalHash hash, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}

/// <summary>Lookup key derived only from the authenticated principal and authorized runtime route.</summary>
public sealed record RegionalEPrescriptionPublishedLookup(
    Guid TenantId,
    Guid ApplicationId,
    Guid InstallationId,
    Guid EnvironmentId,
    string ConnectorId,
    string OperationId);

/// <summary>Current stamp covering both publication state and the exact immutable binding snapshot.</summary>
public sealed record RegionalEPrescriptionResourceStamp(string ResourceStamp, string BindingFingerprint);

/// <summary>Protected adapter boundary over Published Connector configuration.</summary>
public interface IRegionalEPrescriptionPublishedConfigurationSource
{
    /// <summary>Resolves the exact profile binding for the server-derived lookup.</summary>
    Task<RegionalEPrescriptionProfileBinding> ResolveAsync(RegionalEPrescriptionPublishedLookup lookup, CancellationToken cancellationToken);
    /// <summary>Revalidates the complete binding immediately before dispatch.</summary>
    Task<RegionalEPrescriptionResourceStamp> GetCurrentStampAsync(RegionalEPrescriptionProfileBinding binding, CancellationToken cancellationToken);
}

/// <summary>Resolves a profile only from authenticated server state and Published configuration.</summary>
public interface IRegionalEPrescriptionProfileResolver
{
    /// <summary>Returns the exact profile binding authorized for the authenticated caller and operation.</summary>
    Task<RegionalEPrescriptionProfileBinding> ResolveAsync(GatewayClientPrincipal principal, string connectorId, string operationId, CancellationToken cancellationToken);
    /// <summary>Returns the current publication and binding stamp immediately before dispatch.</summary>
    Task<RegionalEPrescriptionResourceStamp> GetCurrentResourceStampAsync(RegionalEPrescriptionProfileBinding binding, CancellationToken cancellationToken);
}

/// <summary>Concrete adapter that prevents a caller from supplying Published lookup authority.</summary>
public sealed class PublishedRegionalEPrescriptionProfileResolver(IRegionalEPrescriptionPublishedConfigurationSource source)
    : IRegionalEPrescriptionProfileResolver
{
    /// <inheritdoc />
    public Task<RegionalEPrescriptionProfileBinding> ResolveAsync(
        GatewayClientPrincipal principal,
        string connectorId,
        string operationId,
        CancellationToken cancellationToken) =>
        source.ResolveAsync(new(
            principal.TenantId,
            principal.ApplicationId,
            principal.InstallationId,
            principal.Identity.EnvironmentId,
            connectorId,
            operationId), cancellationToken);

    /// <inheritdoc />
    public Task<RegionalEPrescriptionResourceStamp> GetCurrentResourceStampAsync(
        RegionalEPrescriptionProfileBinding binding,
        CancellationToken cancellationToken) => source.GetCurrentStampAsync(binding, cancellationToken);
}

/// <summary>Immutable compiled profile authority used to reject Published cross-profile substitution.</summary>
public sealed class RegionalEPrescriptionCompiledProfile
{
    private readonly FrozenSet<string> safeRegionalCodes;

    /// <summary>Creates a compiled operation profile with exact logical resource bindings and extension schema.</summary>
    public RegionalEPrescriptionCompiledProfile(
        string profileId,
        string operationId,
        string endpointBindingId,
        string authPolicyReference,
        IEnumerable<string> credentialBindingIds,
        IEnumerable<RegionalExtensionField> extensionSchema,
        IEnumerable<string>? safeRegionalCodes = null)
    {
        ProfileId = profileId;
        OperationId = operationId;
        EndpointBindingId = endpointBindingId;
        AuthPolicyReference = authPolicyReference;
        CredentialBindingIds = new ReadOnlyCollection<string>((credentialBindingIds ?? throw new ArgumentNullException(nameof(credentialBindingIds))).ToArray());
        ExtensionSchema = new ReadOnlyCollection<RegionalExtensionField>((extensionSchema ?? throw new ArgumentNullException(nameof(extensionSchema))).ToArray());
        this.safeRegionalCodes = (safeRegionalCodes ?? []).ToFrozenSet(StringComparer.Ordinal);
        Validate();
    }

    /// <summary>Exact profile ID.</summary>
    public string ProfileId { get; }
    /// <summary>Exact operation.</summary>
    public string OperationId { get; }
    /// <summary>Exact logical endpoint binding.</summary>
    public string EndpointBindingId { get; }
    /// <summary>Exact logical auth policy.</summary>
    public string AuthPolicyReference { get; }
    /// <summary>Exact copied logical credential binding set.</summary>
    public IReadOnlyList<string> CredentialBindingIds { get; }
    /// <summary>Server-owned copied extension schema.</summary>
    public IReadOnlyList<RegionalExtensionField> ExtensionSchema { get; }

    /// <summary>Determines whether a sanitized profile-specific outcome/fault code may cross the boundary.</summary>
    public bool AllowsSafeRegionalCode(RegionalSafeCode code) => safeRegionalCodes.Contains(code.Value);

    private void Validate()
    {
        if (string.IsNullOrWhiteSpace(ProfileId) || string.IsNullOrWhiteSpace(OperationId) || string.IsNullOrWhiteSpace(EndpointBindingId) || string.IsNullOrWhiteSpace(AuthPolicyReference))
            throw new ArgumentException("COMPILED_PROFILE_INVALID");
        if (CredentialBindingIds.Any(string.IsNullOrWhiteSpace) || CredentialBindingIds.Distinct(StringComparer.Ordinal).Count() != CredentialBindingIds.Count)
            throw new ArgumentException("COMPILED_PROFILE_CREDENTIALS_INVALID");
        if (ExtensionSchema.Count > 32)
            throw new ArgumentException("COMPILED_PROFILE_SCHEMA_COUNT_EXCEEDED");
        foreach (RegionalExtensionField field in ExtensionSchema) field.Validate();
        if (ExtensionSchema.Select(field => field.Name).Distinct(StringComparer.Ordinal).Count() != ExtensionSchema.Count)
            throw new ArgumentException("COMPILED_PROFILE_SCHEMA_DUPLICATE");
        foreach (string safeCode in safeRegionalCodes) _ = new RegionalSafeCode(safeCode);
    }
}

/// <summary>Read-only registry of compiled profile operations.</summary>
public sealed class RegionalEPrescriptionCompiledProfileCatalog
{
    private readonly ReadOnlyDictionary<ProfileOperationKey, RegionalEPrescriptionCompiledProfile> profiles;

    /// <summary>Creates an exact profile/operation registry; duplicates fail startup.</summary>
    public RegionalEPrescriptionCompiledProfileCatalog(IEnumerable<RegionalEPrescriptionCompiledProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        Dictionary<ProfileOperationKey, RegionalEPrescriptionCompiledProfile> values = [];
        foreach (RegionalEPrescriptionCompiledProfile profile in profiles)
        {
            if (!values.TryAdd(Key(profile.ProfileId, profile.OperationId), profile)) throw new ArgumentException("COMPILED_PROFILE_DUPLICATE", nameof(profiles));
        }
        this.profiles = new ReadOnlyDictionary<ProfileOperationKey, RegionalEPrescriptionCompiledProfile>(values);
    }

    /// <summary>Gets an exact compiled profile or fails closed.</summary>
    public RegionalEPrescriptionCompiledProfile GetRequired(string profileId, string operationId) =>
        profiles.TryGetValue(Key(profileId, operationId), out RegionalEPrescriptionCompiledProfile? profile)
            ? profile
            : throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable, "COMPILED-PROFILE-NOT-FOUND");

    private static ProfileOperationKey Key(string profileId, string operationId) => new(profileId, operationId);

    private readonly record struct ProfileOperationKey(string ProfileId, string OperationId);
}

/// <summary>Opaque execution capability constructed only after server-owned profile resolution.</summary>
public sealed class RegionalEPrescriptionExecution
{
    internal RegionalEPrescriptionExecution(GatewayClientPrincipal principal, RegionalEPrescriptionProfileBinding binding)
    {
        Principal = principal;
        Binding = binding;
    }

    /// <summary>Authenticated server-derived principal.</summary>
    public GatewayClientPrincipal Principal { get; }
    /// <summary>Exact immutable profile and logical resources selected by Published configuration.</summary>
    public RegionalEPrescriptionProfileBinding Binding { get; }
    /// <inheritdoc />
    public override string ToString() => $"RegionalEPrescriptionExecution({Binding.ConnectorId},{Binding.OperationId},rev:{Binding.ProfileRevision})";
}

/// <summary>Dispatches only an opaque execution capability; it cannot accept caller-selected routes or credentials.</summary>
public interface IRegionalEPrescriptionProfileDispatcher
{
    /// <summary>Invokes the compiled profile selected by the server-side binding.</summary>
    Task<RegionalEPrescriptionResponse> DispatchAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, CancellationToken cancellationToken);
}

/// <summary>Fail-closed entry point for regional ePrescription commands.</summary>
public sealed class RegionalEPrescriptionRouter(
    IGatewayInvocationAuthorizer authorizer,
    IRegionalEPrescriptionProfileResolver resolver,
    RegionalEPrescriptionCompiledProfileCatalog compiledProfiles,
    IRegionalEPrescriptionProfileDispatcher dispatcher)
{
    /// <summary>Resolves and dispatches without accepting tenant, profile, endpoint or auth selection from the command.</summary>
    public async Task<RegionalEPrescriptionResponse> InvokeAsync(
        GatewayClientPrincipal principal,
        string connectorId,
        string operationId,
        RegionalEPrescriptionCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectorId);
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        ArgumentNullException.ThrowIfNull(command);
        if (command.Prescription is null || command.Extensions is null)
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.Rejected, "PROFILE-COMMAND-INVALID");

        AuthorizedGatewayInvocation authorized = await AuthorizeSanitizedAsync(principal, connectorId, operationId, cancellationToken).ConfigureAwait(false);
        if (!ReferenceEquals(authorized.Principal, principal) ||
            !string.Equals(authorized.ConnectorId, connectorId, StringComparison.Ordinal) ||
            !string.Equals(authorized.OperationId, operationId, StringComparison.Ordinal))
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.Rejected, "INVOCATION-NOT-AUTHORIZED");

        RegionalEPrescriptionProfileBinding binding = await ResolveSanitizedAsync(principal, connectorId, operationId, cancellationToken).ConfigureAwait(false);
        ValidateAuthority(principal, connectorId, operationId, command, binding);
        if (binding.Availability is not RegionalEPrescriptionProfileAvailability.Active)
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable, UnavailableCode(binding));

        ValidateActiveBinding(binding);
        RegionalEPrescriptionCompiledProfile compiled = compiledProfiles.GetRequired(binding.ProfileId, binding.OperationId);
        ValidateCompiledAuthority(binding, compiled);
        try
        {
            command.Extensions.ValidateAgainst(compiled.ExtensionSchema);
        }
        catch (ArgumentException)
        {
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.Rejected, "PROFILE-EXTENSION-INVALID");
        }

        RegionalEPrescriptionResourceStamp current = await GetStampSanitizedAsync(binding, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(binding.ResourceStamp, current.ResourceStamp, StringComparison.Ordinal) ||
            !string.Equals(binding.BindingFingerprint, current.BindingFingerprint, StringComparison.Ordinal))
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable, "PROFILE-RESOURCE-STALE");

        RegionalEPrescriptionResponse response = await DispatchSanitizedAsync(new RegionalEPrescriptionExecution(principal, binding), command, compiled, cancellationToken).ConfigureAwait(false);
        bool responseMatches = command.Operation switch
        {
            RegionalEPrescriptionOperation.Lookup => response is PrescriptionLookupResult,
            RegionalEPrescriptionOperation.Dispense => response is DispenseOutcome,
            _ => false
        };
        if (!responseMatches || response.Prescription is null || response.Extensions is null || response.Prescription != command.Prescription)
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.InvalidState, "PROFILE-RESPONSE-MISMATCH");
        bool responseDomainValid = response switch
        {
            PrescriptionLookupResult lookup => lookup.Availability is PrescriptionAvailability.Available or PrescriptionAvailability.Unavailable,
            DispenseOutcome outcome => outcome.Disposition is DispenseDisposition.Accepted or DispenseDisposition.Rejected,
            _ => false
        };
        if (!responseDomainValid)
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.InvalidState, "PROFILE-RESPONSE-MISMATCH");
        RegionalSafeCode? responseCode = response switch
        {
            PrescriptionLookupResult lookup => lookup.SafeRegionalCode,
            DispenseOutcome outcome => outcome.SafeRegionalCode,
            _ => null
        };
        if (responseCode is not null && !compiled.AllowsSafeRegionalCode(responseCode))
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.InvalidState, "PROFILE-RESPONSE-MISMATCH");
        try
        {
            response.Extensions.ValidateAgainst(compiled.ExtensionSchema);
        }
        catch (ArgumentException)
        {
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.InvalidState, "PROFILE-RESPONSE-MISMATCH");
        }
        return response;
    }

    private async Task<RegionalEPrescriptionProfileBinding> ResolveSanitizedAsync(GatewayClientPrincipal principal, string connectorId, string operationId, CancellationToken cancellationToken)
    {
        try
        {
            return await resolver.ResolveAsync(principal, connectorId, operationId, cancellationToken).ConfigureAwait(false)
                ?? throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.TemporaryUnavailable, "PROFILE-RESOLUTION-FAILED");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (RegionalEPrescriptionException) { throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.TemporaryUnavailable, "PROFILE-RESOLUTION-FAILED"); }
        catch (Exception) { throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.TemporaryUnavailable, "PROFILE-RESOLUTION-FAILED"); }
    }

    private async Task<AuthorizedGatewayInvocation> AuthorizeSanitizedAsync(GatewayClientPrincipal principal, string connectorId, string operationId, CancellationToken cancellationToken)
    {
        try
        {
            return await authorizer.AuthorizeAsync(principal, connectorId, operationId, cancellationToken).ConfigureAwait(false)
                ?? throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.Rejected, "INVOCATION-NOT-AUTHORIZED");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (RegionalEPrescriptionException) { throw; }
        catch (GatewayException error) when (string.Equals(error.Code, "BGW-AUTHZ-OPERATION-DENIED", StringComparison.Ordinal))
        {
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.Rejected, "INVOCATION-NOT-AUTHORIZED");
        }
        catch (Exception) { throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.TemporaryUnavailable, "INVOCATION-AUTHORIZATION-FAILED"); }
    }

    private async Task<RegionalEPrescriptionResourceStamp> GetStampSanitizedAsync(RegionalEPrescriptionProfileBinding binding, CancellationToken cancellationToken)
    {
        try
        {
            return await resolver.GetCurrentResourceStampAsync(binding, cancellationToken).ConfigureAwait(false)
                ?? throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.TemporaryUnavailable, "PROFILE-STAMP-FAILED");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (RegionalEPrescriptionException) { throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.TemporaryUnavailable, "PROFILE-STAMP-FAILED"); }
        catch (Exception) { throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.TemporaryUnavailable, "PROFILE-STAMP-FAILED"); }
    }

    private async Task<RegionalEPrescriptionResponse> DispatchSanitizedAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, RegionalEPrescriptionCompiledProfile compiled, CancellationToken cancellationToken)
    {
        try
        {
            return await dispatcher.DispatchAsync(execution, command, cancellationToken).ConfigureAwait(false)
                ?? throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.TemporaryUnavailable, "PROFILE-DISPATCH-FAILED");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (RegionalEPrescriptionException error)
        {
            string? safeCode = error.SafeRegionalCode is not null && compiled.AllowsSafeRegionalCode(error.SafeRegionalCode)
                ? error.SafeRegionalCode.Value
                : null;
            throw new RegionalEPrescriptionException(error.Category, safeCode);
        }
        catch (Exception) { throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.TemporaryUnavailable, "PROFILE-DISPATCH-FAILED"); }
    }

    private static void ValidateAuthority(GatewayClientPrincipal principal, string connectorId, string operationId, RegionalEPrescriptionCommand command, RegionalEPrescriptionProfileBinding binding)
    {
        if (binding.TenantId != principal.TenantId || binding.ApplicationId != principal.ApplicationId ||
            binding.InstallationId != principal.InstallationId || binding.EnvironmentId != principal.Identity.EnvironmentId ||
            !string.Equals(binding.ConnectorId, connectorId, StringComparison.Ordinal) ||
            !string.Equals(binding.OperationId, operationId, StringComparison.Ordinal) ||
            !string.Equals(binding.OperationId, OperationId(command.Operation), StringComparison.Ordinal))
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable, "PROFILE-AUTHORITY-MISMATCH");
    }

    private static void ValidateActiveBinding(RegionalEPrescriptionProfileBinding binding)
    {
        if (string.IsNullOrWhiteSpace(binding.ProfileId) || string.IsNullOrWhiteSpace(binding.EndpointBindingId) ||
            string.IsNullOrWhiteSpace(binding.AuthPolicyReference) ||
            binding.CredentialBindingIds.Any(string.IsNullOrWhiteSpace) ||
            binding.CredentialBindingIds.Distinct(StringComparer.Ordinal).Count() != binding.CredentialBindingIds.Count ||
            string.IsNullOrWhiteSpace(binding.ResourceStamp) || binding.ProfileRevision < 1 ||
            binding.EndpointRevision < 1 || binding.AuthPolicyRevision < 1)
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable, "PROFILE-BINDING-INVALID");
    }

    private static void ValidateCompiledAuthority(RegionalEPrescriptionProfileBinding binding, RegionalEPrescriptionCompiledProfile compiled)
    {
        if (!string.Equals(binding.ProfileId, compiled.ProfileId, StringComparison.Ordinal) ||
            !string.Equals(binding.OperationId, compiled.OperationId, StringComparison.Ordinal) ||
            !string.Equals(binding.EndpointBindingId, compiled.EndpointBindingId, StringComparison.Ordinal) ||
            !string.Equals(binding.AuthPolicyReference, compiled.AuthPolicyReference, StringComparison.Ordinal) ||
            !binding.CredentialBindingIds.SequenceEqual(compiled.CredentialBindingIds, StringComparer.Ordinal))
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable, "PROFILE-RESOURCE-SUBSTITUTION");
    }

    private static string OperationId(RegionalEPrescriptionOperation operation) => operation switch
    {
        RegionalEPrescriptionOperation.Lookup => "prescription.lookup",
        RegionalEPrescriptionOperation.Dispense => "prescription.dispense",
        _ => throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable, "PROFILE-OPERATION-INVALID")
    };

    private static string UnavailableCode(RegionalEPrescriptionProfileBinding binding)
    {
        if (binding.Availability is RegionalEPrescriptionProfileAvailability.Disabled) return "PROFILE-DISABLED";
        if (binding.Availability is RegionalEPrescriptionProfileAvailability.BlockedBySpec)
        {
            if (binding.ProfileId == RegionalEPrescriptionWave1Readiness.Lombardia.ProfileId &&
                binding.BlockCode == RegionalEPrescriptionWave1Readiness.Lombardia.BlockCode)
                return RegionalEPrescriptionWave1Readiness.Lombardia.BlockCode;
            if (binding.ProfileId == RegionalEPrescriptionWave1Readiness.EmiliaRomagna.ProfileId &&
                binding.BlockCode == RegionalEPrescriptionWave1Readiness.EmiliaRomagna.BlockCode)
                return RegionalEPrescriptionWave1Readiness.EmiliaRomagna.BlockCode;
        }

        return "PROFILE-BLOCKED-BY-SPEC";
    }
}
