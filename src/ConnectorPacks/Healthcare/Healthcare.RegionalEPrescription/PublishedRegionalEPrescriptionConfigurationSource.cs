using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.ConnectorPacks.Healthcare.RegionalEPrescription;

/// <summary>Stable identifiers derived from validated immutable Published Connector content.</summary>
public static class RegionalEPrescriptionPublishedProfileKeys
{
    /// <summary>Derives the compiled profile key from one exact Connector version and operation.</summary>
    public static string ProfileId(string connectorId, string connectorVersion, string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectorId);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectorVersion);
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return $"published-profile-sha256:{Digest(connectorId, connectorVersion, operationId)}";
    }

    /// <summary>Derives the auth-policy key from the canonical authentication object.</summary>
    public static string AuthPolicyReference(string canonicalAuthenticationJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalAuthenticationJson);
        return $"published-auth-sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalAuthenticationJson)))}";
    }

    private static string Digest(params string[] values)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[sizeof(int)];
        foreach (string value in values)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }
}

/// <summary>
/// Production adapter over the existing Published Connector store. The protected lookup includes
/// the authenticated Installation, Tenant, Application, Environment and operation grant context.
/// </summary>
public sealed class PublishedConnectorRegionalEPrescriptionConfigurationSource : IRegionalEPrescriptionPublishedConfigurationSource
{
    private readonly Func<string, Guid, PublishedConnectorAccessContext, CancellationToken, Task<PublishedConnectorSnapshot?>> snapshots;
    private readonly ConnectorDefinitionValidator validator;

    /// <summary>Creates a source backed by the server-owned Connector configuration store.</summary>
    public PublishedConnectorRegionalEPrescriptionConfigurationSource(IConnectorConfigurationStore store, ConnectorDefinitionValidator validator)
        : this((connectorId, environmentId, access, cancellationToken) =>
            store.GetPublishedSnapshotAsync(connectorId, environmentId, access, cancellationToken), validator)
    {
    }

    internal PublishedConnectorRegionalEPrescriptionConfigurationSource(
        Func<string, Guid, PublishedConnectorAccessContext, CancellationToken, Task<PublishedConnectorSnapshot?>> snapshots,
        ConnectorDefinitionValidator validator)
    {
        this.snapshots = snapshots;
        this.validator = validator;
    }

    /// <inheritdoc />
    public async Task<RegionalEPrescriptionProfileBinding> ResolveAsync(RegionalEPrescriptionPublishedLookup lookup, CancellationToken cancellationToken)
    {
        PublishedConnectorAccessContext access = new(lookup.InstallationId, lookup.TenantId, lookup.ApplicationId, lookup.OperationId);
        PublishedConnectorSnapshot snapshot = await RequiredSnapshotAsync(lookup.ConnectorId, lookup.EnvironmentId, access, cancellationToken).ConfigureAwait(false);
        return Project(snapshot, lookup);
    }

    /// <inheritdoc />
    public async Task<RegionalEPrescriptionResourceStamp> GetCurrentStampAsync(RegionalEPrescriptionProfileBinding binding, CancellationToken cancellationToken)
    {
        PublishedConnectorAccessContext access = new(binding.InstallationId, binding.TenantId, binding.ApplicationId, binding.OperationId);
        PublishedConnectorSnapshot snapshot = await RequiredSnapshotAsync(binding.ConnectorId, binding.EnvironmentId, access, cancellationToken).ConfigureAwait(false);
        RegionalEPrescriptionProfileBinding current = Project(snapshot, new(
            binding.TenantId,
            binding.ApplicationId,
            binding.InstallationId,
            binding.EnvironmentId,
            binding.ConnectorId,
            binding.OperationId));
        return new(current.ResourceStamp, current.BindingFingerprint);
    }

    private async Task<PublishedConnectorSnapshot> RequiredSnapshotAsync(
        string connectorId,
        Guid environmentId,
        PublishedConnectorAccessContext access,
        CancellationToken cancellationToken)
    {
        PublishedConnectorSnapshot? snapshot = await snapshots(connectorId, environmentId, access, cancellationToken).ConfigureAwait(false);
        if (snapshot is null || snapshot.Version.State is not ConnectorVersionState.Published ||
            snapshot.Bindings.State is not ConnectorBindingState.Active || snapshot.Bindings.EnvironmentId != environmentId)
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable);
        return snapshot;
    }

    private RegionalEPrescriptionProfileBinding Project(PublishedConnectorSnapshot snapshot, RegionalEPrescriptionPublishedLookup lookup)
    {
        ValidatedConnectorDefinition definition = validator.ParseStored(snapshot.Version.CanonicalJson, snapshot.Version.ChecksumSha256);
        if (!string.Equals(snapshot.Version.ConnectorSlug, lookup.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(definition.ConnectorId, lookup.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(definition.Version, snapshot.Version.Version, StringComparison.Ordinal) ||
            snapshot.Version.Id != snapshot.Bindings.ConnectorVersionId || snapshot.Version.ConnectorId != snapshot.Bindings.ConnectorId ||
            snapshot.Stamp.VersionId != snapshot.Version.Id || snapshot.Stamp.BindingRevision != snapshot.Bindings.Revision ||
            !string.Equals(snapshot.Stamp.BindingChecksumSha256, snapshot.Bindings.ChecksumSha256, StringComparison.Ordinal) ||
            snapshot.Stamp.PublicationRevision < 1 || snapshot.Bindings.Revision < 1 || string.IsNullOrWhiteSpace(snapshot.Stamp.ResourceStampSha256))
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable);

        OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(definition.CanonicalJson, lookup.OperationId);
        if (!snapshot.Bindings.Endpoints.ContainsKey(dependencies.EndpointBindingId))
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable);
        ValidateResources(snapshot, lookup, dependencies);

        using JsonDocument document = JsonDocument.Parse(definition.CanonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
        JsonElement operation = document.RootElement.GetProperty("operations").EnumerateArray()
            .Single(value => string.Equals(value.GetProperty("operationId").GetString(), lookup.OperationId, StringComparison.Ordinal));
        string authPolicyReference = RegionalEPrescriptionPublishedProfileKeys.AuthPolicyReference(operation.GetProperty("authentication").GetRawText());
        string[] credentials = dependencies.SecretBindingIds.Select(value => $"secret:{value}")
            .Concat(dependencies.CertificateBindingIds.Select(value => $"certificate:{value}"))
            .Order(StringComparer.Ordinal)
            .ToArray();

        return new(
            lookup.TenantId,
            lookup.ApplicationId,
            lookup.InstallationId,
            lookup.EnvironmentId,
            lookup.ConnectorId,
            snapshot.Version.Version,
            lookup.OperationId,
            RegionalEPrescriptionPublishedProfileKeys.ProfileId(lookup.ConnectorId, snapshot.Version.Version, lookup.OperationId),
            RegionalEPrescriptionProfileAvailability.Active,
            dependencies.EndpointBindingId,
            authPolicyReference,
            credentials,
            snapshot.Stamp.PublicationRevision,
            snapshot.Bindings.Revision,
            snapshot.Stamp.PublicationRevision,
            snapshot.Stamp.ResourceStampSha256);
    }

    private static void ValidateResources(PublishedConnectorSnapshot snapshot, RegionalEPrescriptionPublishedLookup lookup, OperationBindingDependencies dependencies)
    {
        foreach (string logical in dependencies.SecretBindingIds)
        {
            if (!snapshot.Bindings.SecretResources.TryGetValue(logical, out ProviderResourceBinding? resource) ||
                !snapshot.SecretProviderReferences.TryGetValue(logical, out string? providerReference) || string.IsNullOrWhiteSpace(providerReference))
                throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable);
            ValidateResource(resource, ProviderResourceType.Secret, snapshot, lookup);
        }

        foreach (string logical in dependencies.CertificateBindingIds)
        {
            if (!snapshot.Bindings.CertificateResources.TryGetValue(logical, out ProviderResourceBinding? resource) ||
                !snapshot.CertificateProviderReferences.TryGetValue(logical, out string? providerReference) || string.IsNullOrWhiteSpace(providerReference))
                throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable);
            ValidateResource(resource, ProviderResourceType.ClientCertificate, snapshot, lookup);
        }
    }

    private static void ValidateResource(ProviderResourceBinding resource, ProviderResourceType expectedType, PublishedConnectorSnapshot snapshot, RegionalEPrescriptionPublishedLookup lookup)
    {
        if (resource.ResourceType != expectedType || resource.EnvironmentId != snapshot.Bindings.EnvironmentId ||
            !string.Equals(resource.ConnectorScope, lookup.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(resource.OperationScope, lookup.OperationId, StringComparison.Ordinal) || resource.CatalogRevision < 1)
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.ProfileUnavailable);
    }
}
