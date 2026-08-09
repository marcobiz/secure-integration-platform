using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>Lookup derived from authenticated runtime identity and the explicit operation type.</summary>
public sealed record Fse2PublishedProfileLookup(
    Guid TenantId,
    Guid ApplicationId,
    Guid InstallationId,
    Guid EnvironmentId,
    string ConnectorId,
    Fse2Operation Operation);

/// <summary>
/// Explicit test-only endpoint authority. Its constructor is unavailable to production consumers and it
/// can authorize only one exact synthetic HTTPS base URI.
/// </summary>
internal sealed class Fse2SyntheticEndpointAuthority
{
    private Fse2SyntheticEndpointAuthority(Uri baseEndpoint)
    {
        Fse2EndpointAuthority.ValidateStructural(baseEndpoint, allowNonDefaultPort: true);
        BaseEndpoint = baseEndpoint;
    }

    internal Uri BaseEndpoint { get; }
    internal static Fse2SyntheticEndpointAuthority CreateForTests(Uri baseEndpoint) => new(baseEndpoint);
}

/// <summary>
/// Production resolver over the real Published Connector and four-eyes stores. It returns only internal,
/// non-forgeable dispatch authority derived from the exact approved definition and binding snapshot.
/// </summary>
public sealed class PublishedConnectorFse2ProfileResolver
{
    private const string EnvelopePrefix = "fse2-organization-profile-v1:";
    private readonly IConnectorConfigurationStore connectors;
    private readonly IAdminSecurityStore security;
    private readonly ConnectorDefinitionValidator validator;
    private readonly Fse2SyntheticEndpointAuthority? syntheticAuthority;

    public PublishedConnectorFse2ProfileResolver(
        IConnectorConfigurationStore connectors,
        IAdminSecurityStore security,
        ConnectorDefinitionValidator validator)
        : this(connectors, security, validator, null)
    {
    }

    internal PublishedConnectorFse2ProfileResolver(
        IConnectorConfigurationStore connectors,
        IAdminSecurityStore security,
        ConnectorDefinitionValidator validator,
        Fse2SyntheticEndpointAuthority? syntheticAuthority)
    {
        this.connectors = connectors;
        this.security = security;
        this.validator = validator;
        this.syntheticAuthority = syntheticAuthority;
    }

    internal async Task<AuthorizedFse2Dispatch> ResolveAsync(Fse2PublishedProfileLookup lookup, CancellationToken cancellationToken)
    {
        ValidateLookup(lookup);
        PublishedConnectorAccessContext access = new(lookup.InstallationId, lookup.TenantId, lookup.ApplicationId,
            Fse2OperationCatalog.Get(lookup.Operation).OperationId);
        PublishedConnectorSnapshot snapshot = await connectors.GetPublishedSnapshotAsync(
            lookup.ConnectorId, lookup.EnvironmentId, access, cancellationToken).ConfigureAwait(false)
            ?? throw Denied("FSE2_PROFILE_NOT_PUBLISHED");

        return await ProjectApprovedAsync(snapshot, lookup, cancellationToken).ConfigureAwait(false);
    }

    internal async Task RevalidateAsync(AuthorizedFse2Dispatch authority, CancellationToken cancellationToken)
    {
        AuthorizedFse2Dispatch current = await ResolveAsync(authority.Profile.Authority, cancellationToken).ConfigureAwait(false);
        if (!FixedHexEquals(current.CompositeChecksumSha256, authority.CompositeChecksumSha256))
            throw Denied("FSE2_COMPOSITE_AUTHORITY_STALE");
    }

    private async Task<AuthorizedFse2Dispatch> ProjectApprovedAsync(
        PublishedConnectorSnapshot snapshot,
        Fse2PublishedProfileLookup lookup,
        CancellationToken cancellationToken)
    {
        if (snapshot.Version.State != ConnectorVersionState.Published || snapshot.Bindings.State != ConnectorBindingState.Active ||
            snapshot.Bindings.EnvironmentId != lookup.EnvironmentId || snapshot.Version.Id != snapshot.Bindings.ConnectorVersionId ||
            snapshot.Version.ConnectorId != snapshot.Bindings.ConnectorId || snapshot.Stamp.VersionId != snapshot.Version.Id ||
            snapshot.Stamp.PublicationRevision < 1 || snapshot.Bindings.Revision < 1 ||
            snapshot.Stamp.BindingRevision != snapshot.Bindings.Revision ||
            !string.Equals(snapshot.Stamp.BindingChecksumSha256, snapshot.Bindings.ChecksumSha256, StringComparison.Ordinal) ||
            !Fse2Validation.IsSha256(snapshot.Stamp.BindingChecksumSha256) || !Fse2Validation.IsSha256(snapshot.Stamp.ResourceStampSha256))
            throw Denied("FSE2_PUBLISHED_STATE_DENIED");

        ValidatedConnectorDefinition definition;
        try { definition = validator.ParseStored(snapshot.Version.CanonicalJson, snapshot.Version.ChecksumSha256); }
        catch (Exception) { throw Denied("FSE2_PUBLISHED_DEFINITION_DENIED"); }
        if (!string.Equals(snapshot.Version.ConnectorSlug, lookup.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(definition.ConnectorId, lookup.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(definition.Version, snapshot.Version.Version, StringComparison.Ordinal))
            throw Denied("FSE2_PUBLISHED_DEFINITION_DENIED");

        byte[] bindingDigest = await connectors.GetBindingBundleDigestAsync(snapshot.Version.Id, cancellationToken).ConfigureAwait(false);
        string bindingDigestHex = Convert.ToHexString(bindingDigest);
        IReadOnlyList<ConnectorApprovalRecord> approvals = await security.ListApprovalsAsync(snapshot.Version.Id, cancellationToken).ConfigureAwait(false);
        string definitionChecksum = Convert.ToHexString(snapshot.Version.ChecksumSha256);
        bool approved = approvals.Any(value =>
            value.ConnectorVersionId == snapshot.Version.Id && value.Status == ConnectorApprovalStatus.Approved &&
            value.ApprovedBy is Guid approver && approver != value.RequestedBy && value.ApprovedAt is not null && value.InvalidatedAt is null &&
            FixedHexEquals(value.ChecksumSha256, definitionChecksum) && FixedHexEquals(value.BindingDigestSha256, bindingDigestHex));
        if (!approved) throw Denied("FSE2_FOUR_EYES_APPROVAL_DENIED");

        Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(lookup.Operation);
        OperationBindingDependencies dependencies;
        JsonElement operation;
        Fse2ProfileEnvelope envelope;
        try
        {
            dependencies = ConnectorOperationBindings.Required(definition.CanonicalJson, descriptor.OperationId);
            using JsonDocument document = JsonDocument.Parse(definition.CanonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
            JsonElement root = document.RootElement;
            operation = root.GetProperty("operations").EnumerateArray().Single(value =>
                string.Equals(value.GetProperty("operationId").GetString(), descriptor.OperationId, StringComparison.Ordinal)).Clone();
            string description = root.GetProperty("description").GetString()!;
            envelope = Fse2ProfileEnvelope.Parse(description, EnvelopePrefix);
        }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception) { throw Denied("FSE2_PUBLISHED_DEFINITION_DENIED"); }

        ValidateOperation(operation, descriptor, dependencies);
        if (!snapshot.Bindings.Endpoints.TryGetValue(dependencies.EndpointBindingId, out Uri? baseEndpoint))
            throw Denied("FSE2_ENDPOINT_BINDING_DENIED");
        Fse2EnvironmentClass environmentClass = Fse2EndpointAuthority.Resolve(baseEndpoint, envelope.EnvironmentClass, syntheticAuthority);
        if (environmentClass == Fse2EnvironmentClass.Production && descriptor.Availability != Fse2OperationAvailability.ProductionAvailable)
            throw Denied("FSE2_OPERATION_NOT_PRODUCTION_AVAILABLE");

        Fse2ResolvedResourceAuthority signing = ResolveSigning(snapshot, lookup, dependencies.SecretBindingIds.Single(), envelope);
        Fse2ResolvedResourceAuthority mutualTls = ResolveMutualTls(snapshot, lookup, dependencies.CertificateBindingIds.Single(), envelope);
        if (string.Equals(signing.LogicalBindingId, mutualTls.LogicalBindingId, StringComparison.Ordinal) ||
            string.Equals(signing.ProviderReference, mutualTls.ProviderReference, StringComparison.Ordinal))
            throw Denied("FSE2_AUTHENTICATION_PURPOSE_SEPARATION");

        long timeoutMs = operation.GetProperty("timeoutMs").GetInt64();
        long maximumDocumentBytes = operation.GetProperty("request").GetProperty("maximumBytes").GetInt64();
        long maximumResponseBytes = operation.GetProperty("response").GetProperty("maximumBytes").GetInt64();
        Fse2PublishedOrganizationProfile profile = Fse2PublishedOrganizationProfile.CreateFromPublished(
            lookup, snapshot.Version.Id, snapshot.Version.Version, environmentClass, baseEndpoint, envelope,
            signing.LogicalBindingId, mutualTls.LogicalBindingId, snapshot.Stamp.PublicationRevision,
            definitionChecksum, TimeSpan.FromMilliseconds(timeoutMs), maximumDocumentBytes, maximumResponseBytes);
        Uri endpoint = Fse2OperationCatalog.BuildEndpoint(baseEndpoint, lookup.Operation, descriptor.RequiresResourceIdentifier ? "507f1f77bcf86cd799439011" : null);
        string composite = AuthorizedFse2Dispatch.ComputeChecksum(profile, descriptor, signing, mutualTls, dependencies.EndpointBindingId,
            snapshot.Bindings.Revision, snapshot.Bindings.ChecksumSha256, snapshot.Stamp.ResourceStampSha256, endpoint);
        return new(profile, descriptor, signing, mutualTls, dependencies.EndpointBindingId, snapshot.Bindings.Revision,
            snapshot.Bindings.ChecksumSha256, snapshot.Stamp.ResourceStampSha256, composite);
    }

    private static void ValidateOperation(JsonElement operation, Fse2OperationDescriptor descriptor, OperationBindingDependencies dependencies)
    {
        JsonElement authentication = operation.GetProperty("authentication");
        if (!string.Equals(operation.GetProperty("method").GetString(), descriptor.Method.Method, StringComparison.Ordinal) ||
            !string.Equals(operation.GetProperty("path").GetString(), "/" + descriptor.RelativePath, StringComparison.Ordinal) ||
            !string.Equals(authentication.GetProperty("kind").GetString(), "apiKeyAndMtls", StringComparison.Ordinal) ||
            dependencies.SecretBindingIds.Count != 1 || dependencies.CertificateBindingIds.Count != 1 ||
            dependencies.AuthorityEndpointBindingIds.Count != 0)
            throw Denied("FSE2_OPERATION_DEFINITION_DENIED");
    }

    private static Fse2ResolvedResourceAuthority ResolveSigning(PublishedConnectorSnapshot snapshot, Fse2PublishedProfileLookup lookup,
        string logicalBindingId, Fse2ProfileEnvelope envelope)
    {
        if (!snapshot.Bindings.SecretResources.TryGetValue(logicalBindingId, out ProviderResourceBinding? binding) ||
            !snapshot.SecretProviderReferences.TryGetValue(logicalBindingId, out string? providerReference))
            throw Denied("FSE2_SIGNING_BINDING_DENIED");
        ValidateBinding(binding, ProviderResourceType.Secret, snapshot, lookup, providerReference);
        return new(logicalBindingId, providerReference, AuthenticationResourcePurpose.JwtSigning, binding.CatalogRevision,
            binding.CatalogChecksumSha256, snapshot.Bindings.Revision, snapshot.Bindings.ChecksumSha256,
            envelope.SigningPublicMetadata);
    }

    private static Fse2ResolvedResourceAuthority ResolveMutualTls(PublishedConnectorSnapshot snapshot, Fse2PublishedProfileLookup lookup,
        string logicalBindingId, Fse2ProfileEnvelope envelope)
    {
        if (!snapshot.Bindings.CertificateResources.TryGetValue(logicalBindingId, out ProviderResourceBinding? binding) ||
            !snapshot.CertificateProviderReferences.TryGetValue(logicalBindingId, out string? providerReference) || binding.CertificateMetadata is null)
            throw Denied("FSE2_MTLS_BINDING_DENIED");
        ValidateBinding(binding, ProviderResourceType.ClientCertificate, snapshot, lookup, providerReference);
        CertificatePublicMetadata metadata = binding.CertificateMetadata;
        if (!FixedHexEquals(metadata.FingerprintSha256, envelope.MutualTlsFingerprintSha256) ||
            !string.Equals(metadata.Version, envelope.MutualTlsCertificateVersion, StringComparison.Ordinal))
            throw Denied("FSE2_MTLS_BINDING_DENIED");
        BoundResourcePublicMetadata publicMetadata = new(metadata.FingerprintSha256, envelope.MutualTlsSpkiSha256,
            metadata.NotBefore, metadata.NotAfter, metadata.KeyAlgorithm, metadata.PublicKeySize, metadata.Version);
        return new(logicalBindingId, providerReference, AuthenticationResourcePurpose.MutualTlsClientAuthentication,
            binding.CatalogRevision, binding.CatalogChecksumSha256, snapshot.Bindings.Revision,
            snapshot.Bindings.ChecksumSha256, publicMetadata);
    }

    private static void ValidateBinding(ProviderResourceBinding binding, ProviderResourceType type,
        PublishedConnectorSnapshot snapshot, Fse2PublishedProfileLookup lookup, string providerReference)
    {
        if (binding.ResourceType != type || binding.EnvironmentId != lookup.EnvironmentId || binding.CatalogRevision < 1 ||
            !string.Equals(binding.ConnectorScope, lookup.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(binding.OperationScope, Fse2OperationCatalog.Get(lookup.Operation).OperationId, StringComparison.Ordinal) ||
            !Fse2Validation.IsSha256(binding.CatalogChecksumSha256) || string.IsNullOrWhiteSpace(providerReference) ||
            providerReference.Length > 1024 || providerReference.Any(character => character is '\r' or '\n') ||
            snapshot.Bindings.Revision < 1)
            throw Denied("FSE2_RESOURCE_BINDING_DENIED");
    }

    private static void ValidateLookup(Fse2PublishedProfileLookup lookup)
    {
        ArgumentNullException.ThrowIfNull(lookup);
        if (lookup.TenantId == Guid.Empty || lookup.ApplicationId == Guid.Empty || lookup.InstallationId == Guid.Empty ||
            lookup.EnvironmentId == Guid.Empty || !Fse2Validation.IsSafeIdentifier(lookup.ConnectorId))
            throw Denied("FSE2_PROFILE_AUTHORITY_DENIED");
    }

    internal static string EncodeProfileForTests(Fse2ProfileEnvelope envelope) =>
        EnvelopePrefix + Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(envelope))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static Fse2ConnectorException Denied(string code) => new(Fse2ErrorCategory.PolicyDenied, code);
    private static bool FixedHexEquals(string left, string right) => Fse2Validation.IsSha256(left) && Fse2Validation.IsSha256(right) &&
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
}

internal sealed class Fse2PublishedOrganizationProfile
{
    private Fse2PublishedOrganizationProfile() { }

    internal required Fse2PublishedProfileLookup Authority { get; init; }
    internal required Guid ConnectorVersionId { get; init; }
    internal required string ConnectorVersion { get; init; }
    internal required Fse2EnvironmentClass EnvironmentClass { get; init; }
    internal required Uri BaseEndpoint { get; init; }
    internal required string OrganizationIdentifier { get; init; }
    internal required string OrganizationAssigningAuthorityOid { get; init; }
    internal required string OrganizationDescription { get; init; }
    internal required string OrganizationDomainId { get; init; }
    internal required string Locality { get; init; }
    internal string SubjectRole { get; init; } = "DAP";
    internal required string SubjectCx { get; init; }
    internal required string ApplicationId { get; init; }
    internal required string ApplicationVendor { get; init; }
    internal required string ApplicationVersion { get; init; }
    internal required string ProfileAuthorityId { get; init; }
    internal required string AuthenticationJwtProfileId { get; init; }
    internal required string SignatureJwtProfileId { get; init; }
    internal required string MutualTlsProfileId { get; init; }
    internal required string SigningBindingId { get; init; }
    internal required string MutualTlsBindingId { get; init; }
    internal TimeSpan TokenLifetime { get; init; } = TimeSpan.FromMinutes(5);
    internal TimeSpan AllowedClockSkew { get; init; } = TimeSpan.FromSeconds(30);
    internal required TimeSpan TransportTimeout { get; init; }
    internal required long MaximumDocumentBytes { get; init; }
    internal required long MaximumResponseBytes { get; init; }
    internal required long Revision { get; init; }
    internal required string ChecksumSha256 { get; init; }

    internal static Fse2PublishedOrganizationProfile CreateFromPublished(
        Fse2PublishedProfileLookup authority, Guid versionId, string connectorVersion, Fse2EnvironmentClass environmentClass,
        Uri baseEndpoint, Fse2ProfileEnvelope envelope, string signingBindingId, string mutualTlsBindingId,
        long revision, string checksum, TimeSpan timeout, long maximumDocumentBytes, long maximumResponseBytes)
    {
        string subject = Fse2IheFormatter.FormatOrganizationCx(envelope.OrganizationIdentifier, envelope.OrganizationAssigningAuthorityOid);
        string locality = Fse2IheFormatter.FormatLocalityXon(envelope.LocalityName, envelope.LocalityAssigningAuthorityOid, envelope.LocalityCode);
        _ = Fse2Validation.ValidateOrganizationName(envelope.OrganizationDescription);
        if (!Fse2Validation.IsSafeIdentifier(envelope.OrganizationDomainId)) throw new ArgumentException("FSE2_ORGANIZATION_DOMAIN_INVALID");
        foreach (string value in new[] { envelope.ApplicationId, envelope.ApplicationVendor, envelope.ApplicationVersion })
            if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value != value.Trim() || value.Any(char.IsControl))
                throw new ArgumentException("FSE2_APPLICATION_PROFILE_INVALID");
        if (timeout < TimeSpan.FromMilliseconds(100) || timeout > TimeSpan.FromMinutes(2) || maximumDocumentBytes is < 1 or > 128 * 1024 * 1024 || maximumResponseBytes is < 1 or > 16 * 1024 * 1024)
            throw new ArgumentException("FSE2_POLICY_LIMIT_INVALID");
        string suffix = Digest(authority.ConnectorId, connectorVersion, Fse2OperationCatalog.Get(authority.Operation).OperationId)[..24].ToLowerInvariant();
        return new()
        {
            Authority = authority, ConnectorVersionId = versionId, ConnectorVersion = connectorVersion,
            EnvironmentClass = environmentClass, BaseEndpoint = baseEndpoint,
            OrganizationIdentifier = Fse2Validation.ValidateItalianVatNumber(envelope.OrganizationIdentifier),
            OrganizationAssigningAuthorityOid = Fse2Validation.ValidateOid(envelope.OrganizationAssigningAuthorityOid),
            OrganizationDescription = envelope.OrganizationDescription, OrganizationDomainId = envelope.OrganizationDomainId,
            Locality = locality, SubjectCx = subject, ApplicationId = envelope.ApplicationId,
            ApplicationVendor = envelope.ApplicationVendor, ApplicationVersion = envelope.ApplicationVersion,
            ProfileAuthorityId = "fse2-profile-" + Digest(authority.ConnectorId, connectorVersion)[..24].ToLowerInvariant(),
            AuthenticationJwtProfileId = "fse2-auth-" + suffix, SignatureJwtProfileId = "fse2-signature-" + suffix,
            MutualTlsProfileId = "fse2-mtls-" + suffix, SigningBindingId = signingBindingId,
            MutualTlsBindingId = mutualTlsBindingId, TransportTimeout = timeout, MaximumDocumentBytes = maximumDocumentBytes,
            MaximumResponseBytes = maximumResponseBytes, Revision = revision, ChecksumSha256 = checksum
        };
    }

    private static string Digest(params string[] values)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (string value in values)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length); hash.AppendData(bytes);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }
}

internal sealed record Fse2ResolvedResourceAuthority(
    string LogicalBindingId,
    string ProviderReference,
    AuthenticationResourcePurpose Purpose,
    long CatalogRevision,
    string CatalogChecksumSha256,
    long BindingRevision,
    string BindingChecksumSha256,
    BoundResourcePublicMetadata PublicMetadata);

internal sealed class AuthorizedFse2Dispatch
{
    internal AuthorizedFse2Dispatch(Fse2PublishedOrganizationProfile profile, Fse2OperationDescriptor operation,
        Fse2ResolvedResourceAuthority signing, Fse2ResolvedResourceAuthority mutualTls, string endpointBindingId,
        long endpointBindingRevision, string endpointBindingChecksumSha256, string resourceStampSha256, string compositeChecksumSha256)
    {
        Profile = profile; Operation = operation; Signing = signing; MutualTls = mutualTls; EndpointBindingId = endpointBindingId;
        EndpointBindingRevision = endpointBindingRevision; EndpointBindingChecksumSha256 = endpointBindingChecksumSha256;
        ResourceStampSha256 = resourceStampSha256; CompositeChecksumSha256 = compositeChecksumSha256;
    }

    internal Fse2PublishedOrganizationProfile Profile { get; }
    internal Fse2OperationDescriptor Operation { get; }
    internal Fse2ResolvedResourceAuthority Signing { get; }
    internal Fse2ResolvedResourceAuthority MutualTls { get; }
    internal string EndpointBindingId { get; }
    internal long EndpointBindingRevision { get; }
    internal string EndpointBindingChecksumSha256 { get; }
    internal string ResourceStampSha256 { get; }
    internal string CompositeChecksumSha256 { get; }

    internal static string ComputeChecksum(Fse2PublishedOrganizationProfile profile, Fse2OperationDescriptor operation,
        Fse2ResolvedResourceAuthority signing, Fse2ResolvedResourceAuthority mutualTls, string endpointBindingId,
        long endpointBindingRevision, string endpointBindingChecksum, string resourceStamp, Uri endpoint)
    {
        string[] values =
        [
            profile.Authority.TenantId.ToString("D"), profile.Authority.ApplicationId.ToString("D"), profile.Authority.InstallationId.ToString("D"),
            profile.Authority.EnvironmentId.ToString("D"), profile.ConnectorVersionId.ToString("D"), profile.ConnectorVersion,
            profile.Authority.ConnectorId, operation.OperationId, profile.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture),
            profile.ChecksumSha256, profile.SubjectCx, profile.SubjectRole, operation.PurposeOfUse?.ToString() ?? string.Empty,
            operation.Action?.ToString() ?? string.Empty, Resource(signing), Resource(mutualTls), endpointBindingId,
            endpointBindingRevision.ToString(System.Globalization.CultureInfo.InvariantCulture), endpointBindingChecksum,
            resourceStamp, endpoint.AbsoluteUri
        ];
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (string value in values)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value); BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length); hash.AppendData(bytes);
        }
        return Convert.ToHexString(hash.GetHashAndReset());

        static string Resource(Fse2ResolvedResourceAuthority value) => string.Join('|', value.LogicalBindingId,
            value.ProviderReference, value.Purpose, value.CatalogRevision, value.CatalogChecksumSha256, value.BindingRevision,
            value.BindingChecksumSha256, value.PublicMetadata.FingerprintSha256, value.PublicMetadata.SubjectPublicKeyInfoSha256,
            value.PublicMetadata.Version);
    }
}

internal sealed record Fse2ProfileEnvelope(
    Fse2EnvironmentClass EnvironmentClass,
    string OrganizationIdentifier,
    string OrganizationAssigningAuthorityOid,
    string OrganizationDescription,
    string OrganizationDomainId,
    string LocalityName,
    string LocalityAssigningAuthorityOid,
    string LocalityCode,
    string ApplicationId,
    string ApplicationVendor,
    string ApplicationVersion,
    string SigningFingerprintSha256,
    string SigningSpkiSha256,
    string SigningCertificateVersion,
    long SigningNotBeforeUnixSeconds,
    long SigningNotAfterUnixSeconds,
    string SigningKeyAlgorithm,
    int SigningPublicKeySize,
    string MutualTlsFingerprintSha256,
    string MutualTlsSpkiSha256,
    string MutualTlsCertificateVersion)
{
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal BoundResourcePublicMetadata SigningPublicMetadata => new(SigningFingerprintSha256, SigningSpkiSha256,
        DateTimeOffset.FromUnixTimeSeconds(SigningNotBeforeUnixSeconds), DateTimeOffset.FromUnixTimeSeconds(SigningNotAfterUnixSeconds),
        SigningKeyAlgorithm, SigningPublicKeySize, SigningCertificateVersion);

    internal static Fse2ProfileEnvelope Parse(string description, string prefix)
    {
        if (string.IsNullOrWhiteSpace(description) || !description.StartsWith(prefix, StringComparison.Ordinal))
            throw new JsonException();
        string encoded = description[prefix.Length..].Replace('-', '+').Replace('_', '/');
        encoded += new string('=', (4 - encoded.Length % 4) % 4);
        byte[] json = Convert.FromBase64String(encoded);
        if (json.Length > 3072) throw new JsonException();
        Fse2ProfileEnvelope result = JsonSerializer.Deserialize<Fse2ProfileEnvelope>(json, StrictJson) ?? throw new JsonException();
        using JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
        if (document.RootElement.ValueKind != JsonValueKind.Object || document.RootElement.EnumerateObject().Count() != 21 ||
            !Fse2Validation.IsSha256(result.SigningFingerprintSha256) || !Fse2Validation.IsSha256(result.SigningSpkiSha256) ||
            !Fse2Validation.IsSha256(result.MutualTlsFingerprintSha256) || !Fse2Validation.IsSha256(result.MutualTlsSpkiSha256) ||
            result.SigningNotBeforeUnixSeconds >= result.SigningNotAfterUnixSeconds || result.SigningPublicKeySize < 2048 ||
            !string.Equals(result.SigningKeyAlgorithm, "RSA", StringComparison.Ordinal))
            throw new JsonException();
        return result;
    }
}

internal static class Fse2EndpointAuthority
{
    internal static readonly Uri Production = new("https://modipa.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1");
    internal static readonly Uri OfficialTest = new("https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1");

    internal static Fse2EnvironmentClass Resolve(Uri endpoint, Fse2EnvironmentClass declared, Fse2SyntheticEndpointAuthority? synthetic)
    {
        ValidateStructural(endpoint, allowNonDefaultPort: declared == Fse2EnvironmentClass.Synthetic);
        if (Exact(endpoint, Production) && declared == Fse2EnvironmentClass.Production) return declared;
        if (Exact(endpoint, OfficialTest) && declared == Fse2EnvironmentClass.OfficialTest) return declared;
        if (declared == Fse2EnvironmentClass.Synthetic && synthetic is not null && Exact(endpoint, synthetic.BaseEndpoint)) return declared;
        throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_BASE_ENDPOINT_DENIED");
    }

    internal static void ValidateStructural(Uri endpoint, bool allowNonDefaultPort = false)
    {
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps || (!allowNonDefaultPort && !endpoint.IsDefaultPort) ||
            !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment) ||
            !string.Equals(endpoint.Host, endpoint.IdnHost, StringComparison.OrdinalIgnoreCase) ||
            endpoint.AbsolutePath.EndsWith('/'))
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_BASE_ENDPOINT_DENIED");
    }

    private static bool Exact(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.Ordinal) &&
        string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase) && left.Port == right.Port &&
        string.Equals(left.AbsolutePath, right.AbsolutePath, StringComparison.Ordinal);
}
