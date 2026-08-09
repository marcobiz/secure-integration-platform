using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>Lookup derived from authenticated runtime identity and the explicit operation type.</summary>
public sealed record Fse2PublishedProfileLookup(
    Guid TenantId,
    Guid ApplicationId,
    Guid InstallationId,
    Guid EnvironmentId,
    string ConnectorId,
    Fse2Operation Operation);

/// <summary>Current immutable Published profile stamp.</summary>
public sealed record Fse2PublishedProfileStamp(long Revision, string ChecksumSha256, bool Enabled);

/// <summary>Protected Published configuration source. It exposes no credential value.</summary>
public interface IFse2PublishedProfileSource
{
    Task<Fse2PublishedOrganizationProfile> ResolveAsync(Fse2PublishedProfileLookup lookup, CancellationToken cancellationToken);
    Task<Fse2PublishedProfileStamp> GetCurrentStampAsync(Fse2PublishedOrganizationProfile profile, CancellationToken cancellationToken);
}

/// <summary>
/// Four-eyes-approved, operation-specific organization profile. The fixed CX subject and every logical
/// authentication binding are revision/checksum-bound. Human actor identity is deliberately absent.
/// </summary>
public sealed class Fse2PublishedOrganizationProfile
{
    private Fse2PublishedOrganizationProfile(
        Fse2PublishedProfileLookup authority,
        Guid connectorVersionId,
        Fse2EnvironmentClass environmentClass,
        Uri baseEndpoint,
        string organizationIdentifier,
        string organizationAssigningAuthorityOid,
        string organizationDescription,
        string organizationDomainId,
        string locality,
        string subjectRole,
        string applicationId,
        string applicationVendor,
        string applicationVersion,
        string authenticationJwtProfileId,
        string signatureJwtProfileId,
        string mutualTlsProfileId,
        string signingBindingId,
        string mutualTlsBindingId,
        TimeSpan tokenLifetime,
        TimeSpan allowedClockSkew,
        TimeSpan transportTimeout,
        long maximumDocumentBytes,
        long maximumResponseBytes,
        long revision,
        string createdBy,
        string approvedBy,
        bool enabled)
    {
        Authority = authority;
        ConnectorVersionId = connectorVersionId;
        EnvironmentClass = environmentClass;
        BaseEndpoint = baseEndpoint;
        OrganizationIdentifier = organizationIdentifier;
        OrganizationAssigningAuthorityOid = organizationAssigningAuthorityOid;
        OrganizationDescription = organizationDescription;
        OrganizationDomainId = organizationDomainId;
        Locality = locality;
        SubjectRole = subjectRole;
        SubjectCx = Fse2IheFormatter.FormatOrganizationCx(organizationIdentifier, organizationAssigningAuthorityOid);
        ApplicationId = applicationId;
        ApplicationVendor = applicationVendor;
        ApplicationVersion = applicationVersion;
        AuthenticationJwtProfileId = authenticationJwtProfileId;
        SignatureJwtProfileId = signatureJwtProfileId;
        MutualTlsProfileId = mutualTlsProfileId;
        SigningBindingId = signingBindingId;
        MutualTlsBindingId = mutualTlsBindingId;
        TokenLifetime = tokenLifetime;
        AllowedClockSkew = allowedClockSkew;
        TransportTimeout = transportTimeout;
        MaximumDocumentBytes = maximumDocumentBytes;
        MaximumResponseBytes = maximumResponseBytes;
        Revision = revision;
        CreatedBy = createdBy;
        ApprovedBy = approvedBy;
        Enabled = enabled;
        ChecksumSha256 = ComputeChecksum(this);
    }

    public Fse2PublishedProfileLookup Authority { get; }
    public Guid ConnectorVersionId { get; }
    public Fse2EnvironmentClass EnvironmentClass { get; }
    public Uri BaseEndpoint { get; }
    public string OrganizationIdentifier { get; }
    public string OrganizationAssigningAuthorityOid { get; }
    public string OrganizationDescription { get; }
    public string OrganizationDomainId { get; }
    public string Locality { get; }
    public string SubjectRole { get; }
    public string SubjectCx { get; }
    public string ApplicationId { get; }
    public string ApplicationVendor { get; }
    public string ApplicationVersion { get; }
    public string AuthenticationJwtProfileId { get; }
    public string SignatureJwtProfileId { get; }
    public string MutualTlsProfileId { get; }
    public string SigningBindingId { get; }
    public string MutualTlsBindingId { get; }
    public TimeSpan TokenLifetime { get; }
    public TimeSpan AllowedClockSkew { get; }
    public TimeSpan TransportTimeout { get; }
    public long MaximumDocumentBytes { get; }
    public long MaximumResponseBytes { get; }
    public long Revision { get; }
    public string CreatedBy { get; }
    public string ApprovedBy { get; }
    public bool Enabled { get; }
    public string ChecksumSha256 { get; }

    public static Fse2PublishedOrganizationProfile CreateApproved(
        Fse2PublishedProfileLookup authority,
        Guid connectorVersionId,
        Fse2EnvironmentClass environmentClass,
        Uri baseEndpoint,
        string organizationIdentifier,
        string organizationAssigningAuthorityOid,
        string organizationDescription,
        string organizationDomainId,
        string localityName,
        string localityAssigningAuthorityOid,
        string localityCode,
        string subjectRole,
        string applicationId,
        string applicationVendor,
        string applicationVersion,
        string authenticationJwtProfileId,
        string signatureJwtProfileId,
        string mutualTlsProfileId,
        string signingBindingId,
        string mutualTlsBindingId,
        TimeSpan tokenLifetime,
        TimeSpan allowedClockSkew,
        TimeSpan transportTimeout,
        long maximumDocumentBytes,
        long maximumResponseBytes,
        long revision,
        string createdBy,
        string approvedBy,
        bool enabled = true)
    {
        ArgumentNullException.ThrowIfNull(authority);
        if (authority.TenantId == Guid.Empty || authority.ApplicationId == Guid.Empty || authority.InstallationId == Guid.Empty || authority.EnvironmentId == Guid.Empty || connectorVersionId == Guid.Empty ||
            !Fse2Validation.IsSafeIdentifier(authority.ConnectorId) || revision < 1 || !Fse2Validation.IsSafeIdentifier(createdBy) || !Fse2Validation.IsSafeIdentifier(approvedBy) || string.Equals(createdBy, approvedBy, StringComparison.Ordinal))
            throw new ArgumentException("FSE2_PROFILE_APPROVAL_INVALID", nameof(authority));
        Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(authority.Operation);
        _ = Fse2OperationCatalog.BuildEndpoint(baseEndpoint, authority.Operation, operation.RequiresResourceIdentifier ? "507f1f77bcf86cd799439011" : null);
        _ = Fse2Validation.ValidateItalianVatNumber(organizationIdentifier);
        _ = Fse2Validation.ValidateOid(organizationAssigningAuthorityOid);
        _ = Fse2Validation.ValidateOrganizationName(organizationDescription);
        if (!Fse2Validation.IsSafeIdentifier(organizationDomainId)) throw new ArgumentException("FSE2_ORGANIZATION_DOMAIN_INVALID", nameof(organizationDomainId));
        string locality = Fse2IheFormatter.FormatLocalityXon(localityName, localityAssigningAuthorityOid, localityCode);
        if (subjectRole != "DAP") throw new ArgumentException("FSE2_ORGANIZATION_ROLE_DENIED", nameof(subjectRole));
        if (operation.Action is Fse2Action action && operation.PurposeOfUse is Fse2PurposeOfUse purpose)
            Fse2OperationCatalog.ValidateOrganizationCombination(subjectRole, operation.OperationId, purpose, action);
        foreach (string value in new[] { applicationId, applicationVendor, applicationVersion })
            if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value != value.Trim() || value.Any(char.IsControl)) throw new ArgumentException("FSE2_APPLICATION_PROFILE_INVALID");
        foreach (string value in new[] { authenticationJwtProfileId, signatureJwtProfileId, mutualTlsProfileId, signingBindingId, mutualTlsBindingId })
            if (!Fse2Validation.IsSafeIdentifier(value)) throw new ArgumentException("FSE2_LOGICAL_BINDING_INVALID");
        if (new[] { authenticationJwtProfileId, signatureJwtProfileId, mutualTlsProfileId }.Distinct(StringComparer.Ordinal).Count() != 3 || string.Equals(signingBindingId, mutualTlsBindingId, StringComparison.Ordinal))
            throw new ArgumentException("FSE2_AUTHENTICATION_PURPOSE_SEPARATION");
        if (tokenLifetime <= TimeSpan.Zero || tokenLifetime > TimeSpan.FromHours(1) || allowedClockSkew < TimeSpan.Zero || allowedClockSkew > TimeSpan.FromMinutes(5) ||
            transportTimeout < TimeSpan.FromMilliseconds(100) || transportTimeout > TimeSpan.FromMinutes(2) || maximumDocumentBytes is < 1 or > 128 * 1024 * 1024 || maximumResponseBytes is < 1 or > 16 * 1024 * 1024)
            throw new ArgumentException("FSE2_POLICY_LIMIT_INVALID");

        return new(authority, connectorVersionId, environmentClass, baseEndpoint, organizationIdentifier, organizationAssigningAuthorityOid,
            organizationDescription, organizationDomainId, locality, subjectRole, applicationId, applicationVendor,
            applicationVersion, authenticationJwtProfileId, signatureJwtProfileId, mutualTlsProfileId, signingBindingId,
            mutualTlsBindingId, tokenLifetime, allowedClockSkew, transportTimeout, maximumDocumentBytes,
            maximumResponseBytes, revision, createdBy, approvedBy, enabled);
    }

    internal static void ValidateAuthority(Fse2PublishedOrganizationProfile profile, Fse2PublishedProfileLookup lookup)
    {
        if (profile.Authority != lookup || !profile.Enabled || !Fse2Validation.IsSha256(profile.ChecksumSha256))
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_PROFILE_AUTHORITY_DENIED");
        Fse2IheFormatter.ValidateCx(profile.SubjectCx, organization: true);
        Fse2IheFormatter.ValidateXon(profile.Locality);
        Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(lookup.Operation);
        if (profile.EnvironmentClass == Fse2EnvironmentClass.Production && descriptor.Availability != Fse2OperationAvailability.ProductionAvailable)
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_OPERATION_NOT_PRODUCTION_AVAILABLE");
    }

    /// <summary>Validates publication lineage so an organization identity change cannot reuse a revision.</summary>
    public static void ValidateSuccessor(Fse2PublishedOrganizationProfile previous, Fse2PublishedOrganizationProfile successor)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(successor);
        if (previous.Authority != successor.Authority || previous.ConnectorVersionId != successor.ConnectorVersionId ||
            successor.Revision <= previous.Revision || string.Equals(previous.ChecksumSha256, successor.ChecksumSha256, StringComparison.Ordinal))
            throw new ArgumentException("FSE2_PROFILE_SUCCESSOR_INVALID", nameof(successor));
        if (!string.Equals(previous.SubjectCx, successor.SubjectCx, StringComparison.Ordinal) &&
            string.Equals(previous.OrganizationIdentifier, successor.OrganizationIdentifier, StringComparison.Ordinal))
            throw new ArgumentException("FSE2_ORGANIZATION_IDENTITY_LINEAGE_INVALID", nameof(successor));
    }

    private static string ComputeChecksum(Fse2PublishedOrganizationProfile profile)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Add(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
        Add(profile.Authority.TenantId.ToString("D")); Add(profile.Authority.ApplicationId.ToString("D")); Add(profile.Authority.InstallationId.ToString("D"));
        Add(profile.Authority.EnvironmentId.ToString("D")); Add(profile.ConnectorVersionId.ToString("D")); Add(profile.Authority.ConnectorId); Add(profile.Authority.Operation.ToString());
        Add(profile.EnvironmentClass.ToString()); Add(profile.BaseEndpoint.AbsoluteUri); Add(profile.OrganizationIdentifier); Add(profile.OrganizationAssigningAuthorityOid);
        Add(profile.OrganizationDescription); Add(profile.OrganizationDomainId); Add(profile.Locality); Add(profile.SubjectRole); Add(profile.SubjectCx);
        Add(profile.ApplicationId); Add(profile.ApplicationVendor); Add(profile.ApplicationVersion); Add(profile.AuthenticationJwtProfileId); Add(profile.SignatureJwtProfileId);
        Add(profile.MutualTlsProfileId); Add(profile.SigningBindingId); Add(profile.MutualTlsBindingId); Add(profile.TokenLifetime.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(profile.AllowedClockSkew.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture)); Add(profile.TransportTimeout.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(profile.MaximumDocumentBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)); Add(profile.MaximumResponseBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(profile.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture)); Add(profile.CreatedBy); Add(profile.ApprovedBy); Add(profile.Enabled ? "1" : "0");
        return Convert.ToHexString(hash.GetHashAndReset());
    }
}
