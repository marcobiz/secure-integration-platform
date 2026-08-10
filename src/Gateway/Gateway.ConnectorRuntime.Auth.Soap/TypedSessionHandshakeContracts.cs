using System.Security.Cryptography;
using System.Collections.Frozen;
using System.Text;
using System.Text.Json.Serialization;
using System.Xml;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>Logical selector for one handshake profile in an already-authorized Published operation.</summary>
public sealed class TypedSessionHandshakeAuthorityRequest
{
    /// <summary>Creates the only caller-visible selector. Adapter, endpoint and XML choices remain server-owned.</summary>
    public TypedSessionHandshakeAuthorityRequest(string profileId)
    {
        if (!TypedSessionHandshakeValidation.Identifier(profileId)) throw TypedSessionHandshakeFailures.Configuration();
        ProfileId = profileId;
    }

    /// <summary>Logical Published profile identifier.</summary>
    public string ProfileId { get; }

    /// <inheritdoc />
    public override string ToString() => $"TypedSessionHandshakeAuthorityRequest(ProfileId={ProfileId})";
}

/// <summary>Compiled request adapter registered by trusted server composition.</summary>
public interface ITypedSessionHandshakeRequestAdapter
{
    /// <summary>Logical adapter identifier selected by the Published profile.</summary>
    string AdapterId { get; }
    /// <summary>Closed logical adapter type selected by the Published profile. This is not a CLR reflection type.</summary>
    string AdapterType { get; }
    /// <summary>Static bounded names that must be mapped to approved server-owned bindings by the Published profile.</summary>
    IReadOnlySet<string> RequiredServerOwnedInputs => TypedSessionHandshakeAdapterDefaults.NoServerOwnedInputs;
    /// <summary>Writes only the structured children of the exact request element opened by hardened Core.</summary>
    void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context);
}

/// <summary>Compiled response adapter registered by trusted server composition.</summary>
public interface ITypedSessionHandshakeResponseAdapter
{
    /// <summary>Logical adapter identifier selected by the Published profile.</summary>
    string AdapterId { get; }
    /// <summary>Closed logical adapter type selected by the Published profile. This is not a CLR reflection type.</summary>
    string AdapterType { get; }
    /// <summary>Strictly interprets the already bounded, exact response payload.</summary>
    TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context);
}

/// <summary>
/// Compiled protocol adapter for external-session validation. It knows only typed XML semantics;
/// Core exclusively owns endpoints, DNS, credentials, HTTP, timeouts and response bounds.
/// </summary>
public interface ITypedExternalSessionValidationAdapter
{
    /// <summary>Logical adapter identifier selected by the Published validation profile.</summary>
    string AdapterId { get; }
    /// <summary>Closed logical adapter type selected by the Published validation profile.</summary>
    string AdapterType { get; }
    /// <summary>Static bounded names that must be mapped to approved server-owned bindings by the Published validation profile.</summary>
    IReadOnlySet<string> RequiredServerOwnedInputs => TypedSessionHandshakeAdapterDefaults.NoServerOwnedInputs;
    /// <summary>Writes typed children inside the exact validation request element opened by Core.</summary>
    void WriteValidationRequest(XmlWriter writer, ExternalSessionValidationRequestContext context);
    /// <summary>Maps an already bounded and structurally validated exact response payload to a closed result.</summary>
    ExternalSessionValidationResult ReadValidationResponse(XmlReader payload, ExternalSessionValidationResponseContext context);
}

/// <summary>Immutable, resolved request inputs derived only from authenticated and Published server state.</summary>
public sealed class TypedSessionHandshakeRequestContext
{
    internal TypedSessionHandshakeRequestContext(TypedSessionHandshakeAuthorityState state, AuthorizedConnectorBindingInputs serverOwnedInputs)
    {
        State = state;
        ServerOwnedInputs = serverOwnedInputs;
    }

    internal TypedSessionHandshakeAuthorityState State { get; }
    /// <summary>Authenticated Tenant identity.</summary>
    public Guid TenantId => State.ExecutionContext.TenantId;
    /// <summary>Authenticated Installation identity.</summary>
    public Guid InstallationId => State.ExecutionContext.InstallationId;
    /// <summary>Authenticated Application identity.</summary>
    public Guid ApplicationId => State.ExecutionContext.ApplicationId;
    /// <summary>Published Connector identifier.</summary>
    public string ConnectorId => State.ExecutionContext.ConnectorId;
    /// <summary>Published Connector version.</summary>
    public string ConnectorVersion => State.ExecutionContext.ConnectorVersion;
    /// <summary>Authorized operation.</summary>
    public string OperationId => State.ExecutionContext.OperationId;
    /// <summary>Published handshake profile.</summary>
    public string ProfileId => State.ProfileId;
    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId => State.ExecutionContext.CorrelationId;
    /// <summary>Checksum of the immutable Published Connector definition.</summary>
    public string PublishedPolicyChecksum => State.PublishedPolicyChecksum;
    /// <summary>Exact immutable input set resolved from Published-approved provider bindings for this adapter call.</summary>
    public AuthorizedConnectorBindingInputs ServerOwnedInputs { get; }

    /// <inheritdoc />
    public override string ToString() => $"TypedSessionHandshakeRequestContext(ConnectorId={ConnectorId}, OperationId={OperationId}, ProfileId={ProfileId}, CorrelationId={CorrelationId:D})";
}

/// <summary>Immutable metadata supplied after Core validates the SOAP envelope and exact payload QName.</summary>
public sealed class TypedSessionHandshakeResponseContext
{
    internal TypedSessionHandshakeResponseContext(TypedSessionHandshakeAuthorityState state) => State = state;

    internal TypedSessionHandshakeAuthorityState State { get; }
    /// <summary>Published Connector identifier.</summary>
    public string ConnectorId => State.ExecutionContext.ConnectorId;
    /// <summary>Authorized operation.</summary>
    public string OperationId => State.ExecutionContext.OperationId;
    /// <summary>Published handshake profile.</summary>
    public string ProfileId => State.ProfileId;
    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId => State.ExecutionContext.CorrelationId;

    /// <inheritdoc />
    public override string ToString() => $"TypedSessionHandshakeResponseContext(ConnectorId={ConnectorId}, OperationId={OperationId}, ProfileId={ProfileId}, CorrelationId={CorrelationId:D})";
}

/// <summary>Closed response-adapter outcome understood by the provider-neutral session lifecycle.</summary>
public abstract class TypedSessionHandshakeAdapterOutcome
{
    private protected TypedSessionHandshakeAdapterOutcome() { }

    /// <summary>Creates an issued-session outcome. The sensitive value is never publicly readable or serialized.</summary>
    public static TypedSessionHandshakeAdapterOutcome Issued(string sensitiveSessionValue, DateTimeOffset? remoteExpiry = null) =>
        new TypedSessionIssuedAdapterOutcome(sensitiveSessionValue, remoteExpiry);

    /// <summary>Requests the dedicated external-admission presentation boundary.</summary>
    public static TypedSessionHandshakeAdapterOutcome ExternalAdmissionRequired(ExternalSessionProvenance provenance = ExternalSessionProvenance.InteractiveHandoff) =>
        provenance == ExternalSessionProvenance.InteractiveHandoff
            ? new TypedExternalAdmissionRequiredAdapterOutcome(provenance)
            : throw TypedSessionHandshakeFailures.AdapterRejected();

    /// <summary>Creates a closed, sanitized rejection outcome.</summary>
    public static TypedSessionHandshakeAdapterOutcome Rejected(TypedSessionHandshakeRejection rejection) => new TypedSessionRejectedAdapterOutcome(rejection);
}

internal sealed class TypedSessionIssuedAdapterOutcome : TypedSessionHandshakeAdapterOutcome
{
    internal TypedSessionIssuedAdapterOutcome(string sensitiveSessionValue, DateTimeOffset? remoteExpiry)
    {
        if (!TypedSessionHandshakeValidation.SessionValue(sensitiveSessionValue)) throw TypedSessionHandshakeFailures.AdapterRejected();
        SensitiveSessionValue = sensitiveSessionValue;
        RemoteExpiry = remoteExpiry;
    }

    [JsonIgnore] internal string SensitiveSessionValue { get; }
    internal DateTimeOffset? RemoteExpiry { get; }
    public override string ToString() => "TypedSessionIssuedAdapterOutcome(Redacted=True)";
}

internal sealed class TypedExternalAdmissionRequiredAdapterOutcome(ExternalSessionProvenance provenance) : TypedSessionHandshakeAdapterOutcome
{
    internal ExternalSessionProvenance Provenance { get; } = provenance;
    public override string ToString() => $"TypedExternalAdmissionRequiredAdapterOutcome(Provenance={Provenance})";
}

internal sealed class TypedSessionRejectedAdapterOutcome(TypedSessionHandshakeRejection rejection) : TypedSessionHandshakeAdapterOutcome
{
    internal TypedSessionHandshakeRejection Rejection { get; } = rejection;
    public override string ToString() => $"TypedSessionRejectedAdapterOutcome(Rejection={Rejection})";
}

/// <summary>Closed sanitized rejection categories returned by a typed handshake adapter.</summary>
public enum TypedSessionHandshakeRejection
{
    /// <summary>The upstream authority rejected the handshake.</summary>
    Rejected,
    /// <summary>The authenticated installation is not eligible for a session.</summary>
    NotEligible,
    /// <summary>The Published profile is not accepted by the upstream authority.</summary>
    ProfileDenied
}

/// <summary>Closed provenance for an externally presented opaque session candidate.</summary>
public enum ExternalSessionProvenance
{
    /// <summary>A dedicated interactive presentation handoff supplied the candidate.</summary>
    InteractiveHandoff
}

/// <summary>Closed public lifecycle outcomes. Raw session material is never included.</summary>
public enum TypedSessionHandshakeResultKind
{
    /// <summary>A current opaque session reference was issued.</summary>
    Issued,
    /// <summary>A dedicated external-admission intent must be completed.</summary>
    ExternalAdmissionRequired,
    /// <summary>The typed handshake was rejected.</summary>
    Rejected
}

/// <summary>Public result of the typed session lifecycle, containing only opaque handles and safe metadata.</summary>
public sealed class TypedSessionHandshakeResult
{
    internal TypedSessionHandshakeResult(
        TypedSessionHandshakeResultKind kind,
        OpaqueSoapSessionReference? session,
        ExternalSessionAdmissionIntent? admissionIntent,
        TypedSessionHandshakeRejection? rejection,
        DateTimeOffset? expiresAt,
        ExternalSessionProvenance? provenance)
    {
        Kind = kind;
        Session = session;
        AdmissionIntent = admissionIntent;
        Rejection = rejection;
        ExpiresAt = expiresAt;
        Provenance = provenance;
    }

    /// <summary>Closed lifecycle result.</summary>
    public TypedSessionHandshakeResultKind Kind { get; }
    /// <summary>Opaque reference when <see cref="Kind"/> is <see cref="TypedSessionHandshakeResultKind.Issued"/>.</summary>
    public OpaqueSoapSessionReference? Session { get; }
    /// <summary>Opaque presentation intent when external admission is required.</summary>
    public ExternalSessionAdmissionIntent? AdmissionIntent { get; }
    /// <summary>Sanitized rejection category.</summary>
    public TypedSessionHandshakeRejection? Rejection { get; }
    /// <summary>Server-computed expiry for the issued session or admission intent.</summary>
    public DateTimeOffset? ExpiresAt { get; }
    /// <summary>External provenance safe for metadata-only audit.</summary>
    public ExternalSessionProvenance? Provenance { get; }

    /// <inheritdoc />
    public override string ToString() => $"TypedSessionHandshakeResult(Kind={Kind}, ExpiresAt={ExpiresAt:O}, Provenance={Provenance}, Redacted=True)";
}

/// <summary>Opaque, bounded, single-use intent created only by the authorized session lifecycle.</summary>
public sealed class ExternalSessionAdmissionIntent
{
    internal ExternalSessionAdmissionIntent(string reference, string profileId, ExternalSessionProvenance provenance, DateTimeOffset expiresAt, string authorityFingerprint)
    {
        Reference = reference;
        ProfileId = profileId;
        Provenance = provenance;
        ExpiresAt = expiresAt;
        AuthorityFingerprint = authorityFingerprint;
    }

    /// <summary>Opaque presentation reference. It carries no cache key or profile authority.</summary>
    public string Reference { get; }
    /// <summary>Safe logical profile metadata.</summary>
    public string ProfileId { get; }
    /// <summary>Closed presentation provenance.</summary>
    public ExternalSessionProvenance Provenance { get; }
    /// <summary>Absolute single-use intent expiry.</summary>
    public DateTimeOffset ExpiresAt { get; }
    [JsonIgnore] internal string AuthorityFingerprint { get; }

    /// <inheritdoc />
    public override string ToString() => $"ExternalSessionAdmissionIntent(ProfileId={ProfileId}, Provenance={Provenance}, ExpiresAt={ExpiresAt:O}, Redacted=True)";
}

/// <summary>Sensitive candidate accepted only by the dedicated external-admission presentation boundary.</summary>
internal sealed class ExternalSessionCandidate : IDisposable
{
    private byte[] value;
    private bool disposed;

    private ExternalSessionCandidate(byte[] value) => this.value = value;

    internal static ExternalSessionCandidate Create(ReadOnlySpan<byte> candidate)
    {
        if (candidate.Length is < 1 or > 16_384) throw TypedSessionHandshakeFailures.CandidateInvalid();
        byte[] copy = candidate.ToArray();
        try
        {
            string decoded = new UTF8Encoding(false, true).GetString(copy);
            if (!TypedSessionHandshakeValidation.SessionValue(decoded)) throw TypedSessionHandshakeFailures.CandidateInvalid();
            return new(copy);
        }
        catch (DecoderFallbackException)
        {
            CryptographicOperations.ZeroMemory(copy);
            throw TypedSessionHandshakeFailures.CandidateInvalid();
        }
        catch
        {
            CryptographicOperations.ZeroMemory(copy);
            throw;
        }
    }

    [JsonIgnore]
    internal ReadOnlyMemory<byte> SensitiveValue => !disposed ? value : throw new ObjectDisposedException(nameof(ExternalSessionCandidate));

    internal string DecodeForPromotion() => !disposed
        ? new UTF8Encoding(false, true).GetString(value)
        : throw TypedSessionHandshakeFailures.CandidateInvalid();

    internal byte[] DigestForValidationProof() => !disposed
        ? SHA256.HashData(value)
        : throw TypedSessionHandshakeFailures.CandidateInvalid();

    public void Dispose()
    {
        if (disposed) return;
        CryptographicOperations.ZeroMemory(value);
        value = [];
        disposed = true;
    }

    /// <inheritdoc />
    public override string ToString() => "ExternalSessionCandidate(Redacted=True)";
}

/// <summary>Typed validation input visible to the compiled adapter; wire authority is deliberately absent.</summary>
public sealed class ExternalSessionValidationRequestContext
{
    private readonly ExternalSessionCandidate candidate;

    internal ExternalSessionValidationRequestContext(
        TypedSessionHandshakeAuthorityState state,
        ExternalSessionCandidate candidate,
        ExternalSessionProvenance provenance,
        AuthorizedConnectorBindingInputs serverOwnedInputs)
    {
        this.candidate = candidate;
        TenantId = state.ExecutionContext.TenantId;
        InstallationId = state.ExecutionContext.InstallationId;
        ApplicationId = state.ExecutionContext.ApplicationId;
        ConnectorId = state.ExecutionContext.ConnectorId;
        ConnectorVersion = state.ExecutionContext.ConnectorVersion;
        OperationId = state.ExecutionContext.OperationId;
        ProfileId = state.ProfileId;
        CorrelationId = state.ExecutionContext.CorrelationId;
        Provenance = provenance;
        PublishedPolicyChecksum = state.PublishedPolicyChecksum;
        ServerOwnedInputs = serverOwnedInputs;
    }

    /// <summary>Owned sensitive bytes valid only for the duration of the adapter call.</summary>
    [JsonIgnore]
    public ReadOnlyMemory<byte> SensitiveCandidate => candidate.SensitiveValue;
    /// <summary>Authenticated Tenant identity.</summary>
    public Guid TenantId { get; }
    /// <summary>Authenticated Installation identity.</summary>
    public Guid InstallationId { get; }
    /// <summary>Authenticated Application identity.</summary>
    public Guid ApplicationId { get; }
    /// <summary>Published Connector identity.</summary>
    public string ConnectorId { get; }
    /// <summary>Published Connector version.</summary>
    public string ConnectorVersion { get; }
    /// <summary>Authorized operation.</summary>
    public string OperationId { get; }
    /// <summary>Published handshake profile.</summary>
    public string ProfileId { get; }
    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId { get; }
    /// <summary>Closed provenance recorded by the server-owned intent.</summary>
    public ExternalSessionProvenance Provenance { get; }
    /// <summary>Published immutable definition checksum.</summary>
    public string PublishedPolicyChecksum { get; }
    /// <summary>Exact immutable input set resolved from Published-approved provider bindings for this validator call.</summary>
    public AuthorizedConnectorBindingInputs ServerOwnedInputs { get; }

    /// <inheritdoc />
    public override string ToString() => $"ExternalSessionValidationRequestContext(ConnectorId={ConnectorId}, OperationId={OperationId}, ProfileId={ProfileId}, CorrelationId={CorrelationId:D}, Redacted=True)";
}

/// <summary>Safe metadata supplied after Core opens the exact bounded validation response payload.</summary>
public sealed class ExternalSessionValidationResponseContext
{
    internal ExternalSessionValidationResponseContext(TypedSessionHandshakeAuthorityState state)
    {
        ConnectorId = state.ExecutionContext.ConnectorId;
        OperationId = state.ExecutionContext.OperationId;
        ProfileId = state.ProfileId;
        CorrelationId = state.ExecutionContext.CorrelationId;
    }

    /// <summary>Published Connector identifier.</summary>
    public string ConnectorId { get; }
    /// <summary>Authorized operation.</summary>
    public string OperationId { get; }
    /// <summary>Published handshake profile.</summary>
    public string ProfileId { get; }
    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId { get; }

    /// <inheritdoc />
    public override string ToString() => $"ExternalSessionValidationResponseContext(ConnectorId={ConnectorId}, OperationId={OperationId}, ProfileId={ProfileId}, CorrelationId={CorrelationId:D}, Redacted=True)";
}

/// <summary>Closed typed validity returned by a registered external-session validator.</summary>
public enum ExternalSessionValidationStatus
{
    /// <summary>The remote authority accepted the candidate.</summary>
    Valid,
    /// <summary>The remote authority rejected the candidate.</summary>
    Rejected,
    /// <summary>The bounded remote response was malformed or outside the registered protocol.</summary>
    MalformedResponse,
    /// <summary>The remote validation authority was unavailable.</summary>
    Unavailable
}

/// <summary>Sanitized validator result. It contains no response body or remote diagnostic.</summary>
public sealed class ExternalSessionValidationResult
{
    private ExternalSessionValidationResult(ExternalSessionValidationStatus status, DateTimeOffset? remoteExpiry)
    {
        Status = status;
        RemoteExpiry = remoteExpiry;
    }

    /// <summary>Creates a valid result with mandatory remote expiry.</summary>
    public static ExternalSessionValidationResult Valid(DateTimeOffset remoteExpiry) => new(ExternalSessionValidationStatus.Valid, remoteExpiry);
    /// <summary>Creates a closed non-valid result.</summary>
    public static ExternalSessionValidationResult Invalid(ExternalSessionValidationStatus status) => status == ExternalSessionValidationStatus.Valid
        ? throw new ArgumentOutOfRangeException(nameof(status))
        : new(status, null);

    /// <summary>Closed remote validation status.</summary>
    public ExternalSessionValidationStatus Status { get; }
    /// <summary>Remote expiry used only when valid and capped by the Published local maximum.</summary>
    public DateTimeOffset? RemoteExpiry { get; }

    /// <inheritdoc />
    public override string ToString() => $"ExternalSessionValidationResult(Status={Status}, RemoteExpiry={RemoteExpiry:O}, Redacted=True)";
}

/// <summary>Immutable non-forgeable authority resolved from an authorized Published operation.</summary>
public sealed class ResolvedTypedSessionHandshake
{
    internal ResolvedTypedSessionHandshake(TypedSessionHandshakeAuthorityState state, Func<CancellationToken, Task<TypedSessionHandshakeAuthorityState>> revalidate)
    {
        State = state;
        Revalidate = revalidate;
    }

    /// <summary>Published Connector identifier.</summary>
    public string ConnectorId => State.ExecutionContext.ConnectorId;
    /// <summary>Authorized operation.</summary>
    public string OperationId => State.ExecutionContext.OperationId;
    /// <summary>Published typed handshake profile.</summary>
    public string ProfileId => State.ProfileId;
    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId => State.ExecutionContext.CorrelationId;

    [JsonIgnore] internal TypedSessionHandshakeAuthorityState State { get; }
    [JsonIgnore] internal Func<CancellationToken, Task<TypedSessionHandshakeAuthorityState>> Revalidate { get; }

    /// <inheritdoc />
    public override string ToString() => $"ResolvedTypedSessionHandshake(ConnectorId={ConnectorId}, OperationId={OperationId}, ProfileId={ProfileId}, CorrelationId={CorrelationId:D})";
}

/// <summary>Server-side registry for compiled adapters. Published profiles select exact ID/type pairs.</summary>
public sealed class TypedSessionHandshakeAdapterRegistry
{
    private readonly Dictionary<(string Id, string Type), RegisteredRequestAdapter> requests;
    private readonly Dictionary<(string Id, string Type), ITypedSessionHandshakeResponseAdapter> responses;
    private readonly Dictionary<(string Id, string Type), RegisteredValidationAdapter> validationAdapters;

    /// <summary>Creates an immutable bounded registry during trusted server composition.</summary>
    public TypedSessionHandshakeAdapterRegistry(
        IEnumerable<ITypedSessionHandshakeRequestAdapter> requestAdapters,
        IEnumerable<ITypedSessionHandshakeResponseAdapter> responseAdapters,
        IEnumerable<ITypedExternalSessionValidationAdapter>? admissionValidationAdapters = null)
    {
        requests = IndexRequests(requestAdapters);
        responses = Index(responseAdapters, value => value.AdapterId, value => value.AdapterType, "response");
        validationAdapters = IndexValidation(admissionValidationAdapters ?? []);
        if (requests.Count > 256 || responses.Count > 256 || validationAdapters.Count > 256) throw TypedSessionHandshakeFailures.Configuration();
    }

    internal RegisteredRequestAdapter Request(string id, string type) => requests.TryGetValue((id, type), out RegisteredRequestAdapter? value)
        ? value : throw TypedSessionHandshakeFailures.AdapterUnavailable();
    internal ITypedSessionHandshakeResponseAdapter Response(string id, string type) => responses.TryGetValue((id, type), out ITypedSessionHandshakeResponseAdapter? value)
        ? value : throw TypedSessionHandshakeFailures.AdapterUnavailable();
    internal RegisteredValidationAdapter? Validation(string? id, string? type) => id is null && type is null
        ? null
        : id is not null && type is not null && validationAdapters.TryGetValue((id, type), out RegisteredValidationAdapter? value)
            ? value : throw TypedSessionHandshakeFailures.AdapterUnavailable();

    private static Dictionary<(string Id, string Type), RegisteredRequestAdapter> IndexRequests(
        IEnumerable<ITypedSessionHandshakeRequestAdapter> values)
    {
        Dictionary<(string Id, string Type), RegisteredRequestAdapter> result = [];
        foreach (ITypedSessionHandshakeRequestAdapter value in values ?? throw new ArgumentNullException(nameof(values)))
        {
            FrozenSet<string> required = RequiredInputs(value.RequiredServerOwnedInputs);
            if (!TypedSessionHandshakeValidation.Identifier(value.AdapterId) || !TypedSessionHandshakeValidation.Identifier(value.AdapterType) ||
                !result.TryAdd((value.AdapterId, value.AdapterType), new(value, required)))
                throw TypedSessionHandshakeFailures.Configuration();
        }
        return result;
    }

    private static Dictionary<(string Id, string Type), RegisteredValidationAdapter> IndexValidation(
        IEnumerable<ITypedExternalSessionValidationAdapter> values)
    {
        Dictionary<(string Id, string Type), RegisteredValidationAdapter> result = [];
        foreach (ITypedExternalSessionValidationAdapter value in values ?? throw new ArgumentNullException(nameof(values)))
        {
            FrozenSet<string> required = RequiredInputs(value.RequiredServerOwnedInputs);
            if (!TypedSessionHandshakeValidation.Identifier(value.AdapterId) || !TypedSessionHandshakeValidation.Identifier(value.AdapterType) ||
                !result.TryAdd((value.AdapterId, value.AdapterType), new(value, required)))
                throw TypedSessionHandshakeFailures.Configuration();
        }
        return result;
    }

    private static FrozenSet<string> RequiredInputs(IReadOnlySet<string>? values)
    {
        string[] snapshot = values?.ToArray() ?? throw TypedSessionHandshakeFailures.Configuration();
        if (snapshot.Length > AuthorizedConnectorBindingInputs.MaximumInputs || snapshot.Any(value => !TypedSessionHandshakeValidation.Identifier(value)))
            throw TypedSessionHandshakeFailures.Configuration();
        FrozenSet<string> required = snapshot.ToFrozenSet(StringComparer.Ordinal);
        if (required.Count != snapshot.Length) throw TypedSessionHandshakeFailures.Configuration();
        return required;
    }

    private static Dictionary<(string Id, string Type), T> Index<T>(IEnumerable<T> values, Func<T, string> id, Func<T, string> type, string parameter)
    {
        Dictionary<(string Id, string Type), T> result = [];
        foreach (T value in values ?? throw new ArgumentNullException(parameter))
        {
            string adapterId = id(value);
            string adapterType = type(value);
            if (!TypedSessionHandshakeValidation.Identifier(adapterId) || !TypedSessionHandshakeValidation.Identifier(adapterType) ||
                !result.TryAdd((adapterId, adapterType), value))
                throw TypedSessionHandshakeFailures.Configuration();
        }
        return result;
    }
}

internal sealed class TypedSessionHandshakeAuthorityState
{
    internal required ConnectorAuthExecutionContext ExecutionContext { get; init; }
    internal required Guid ConnectorVersionId { get; init; }
    internal required string ProfileId { get; init; }
    internal required SoapEndpointBinding Endpoint { get; init; }
    internal required SoapOperationProfile Operation { get; init; }
    internal required ResolvedBasicCredentialBinding? BasicCredential { get; init; }
    internal required ITypedSessionHandshakeRequestAdapter RequestAdapter { get; init; }
    internal required IReadOnlyList<ServerOwnedBindingInputReference> RequestBindingInputs { get; init; }
    internal required ITypedSessionHandshakeResponseAdapter ResponseAdapter { get; init; }
    internal required TimeSpan LocalMaximumSessionLifetime { get; init; }
    internal required string PublishedPolicyChecksum { get; init; }
    internal required string ResourceStamp { get; init; }
    internal required string SecurityFingerprint { get; init; }
    internal ITypedExternalSessionValidationAdapter? AdmissionValidationAdapter { get; init; }
    internal IReadOnlyList<ServerOwnedBindingInputReference> AdmissionBindingInputs { get; init; } = [];
    internal Uri? AdmissionEndpoint { get; init; }
    internal SoapOperationProfile? AdmissionOperation { get; init; }
    internal TimeSpan AdmissionIntentLifetime { get; init; }
    internal required PublishedConnectorMutationAuthority MutationAuthority { get; init; }
    internal required PublishedConnectorAuthorityGeneration AuthorityGeneration { get; init; }

    internal SoapSessionCacheKey CacheKey => new(ExecutionContext.TenantId, ExecutionContext.InstallationId, ExecutionContext.ApplicationId,
        ExecutionContext.EnvironmentId, ExecutionContext.ConnectorId, ExecutionContext.ConnectorVersion, ExecutionContext.BindingRevision,
        ExecutionContext.EndpointRevision, ExecutionContext.CredentialRevision, ProfileId);
}

internal sealed record RegisteredRequestAdapter(
    ITypedSessionHandshakeRequestAdapter Adapter,
    IReadOnlySet<string> RequiredServerOwnedInputs);

internal sealed record RegisteredValidationAdapter(
    ITypedExternalSessionValidationAdapter Adapter,
    IReadOnlySet<string> RequiredServerOwnedInputs);

internal static class TypedSessionHandshakeAdapterDefaults
{
    internal static readonly IReadOnlySet<string> NoServerOwnedInputs = Array.Empty<string>().ToFrozenSet(StringComparer.Ordinal);
}

internal static class TypedSessionHandshakeValidation
{
    internal static bool Identifier(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    internal static bool SessionValue(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 16_384 &&
        !value.Any(character => character is '\r' or '\n' or '\0' || char.IsControl(character));
}

internal static class TypedSessionHandshakeFailures
{
    internal static SoapAuthException Configuration() => new("SOAP-TYPED-CONFIGURATION-INVALID");
    internal static SoapAuthException AuthorityRejected() => new("SOAP-TYPED-AUTHORITY-REJECTED");
    internal static SoapAuthException AuthorityStale() => new("SOAP-TYPED-AUTHORITY-STALE");
    internal static SoapAuthException AdapterUnavailable() => new("SOAP-TYPED-ADAPTER-UNAVAILABLE");
    internal static SoapAuthException AdapterRejected() => new("SOAP-TYPED-ADAPTER-REJECTED");
    internal static SoapAuthException AdmissionNotSupported() => new("SOAP-ADMISSION-NOT-SUPPORTED");
    internal static SoapAuthException AdmissionIntentInvalid() => new("SOAP-ADMISSION-INTENT-INVALID");
    internal static SoapAuthException CandidateInvalid() => new("SOAP-ADMISSION-CANDIDATE-INVALID");
    internal static SoapAuthException ValidationRejected() => new("SOAP-ADMISSION-VALIDATION-REJECTED");
    internal static SoapAuthException ValidationFailed() => new("SOAP-ADMISSION-VALIDATION-FAILED");
    internal static SoapAuthException RemoteExpiryInvalid() => new("SOAP-ADMISSION-REMOTE-EXPIRY-INVALID");
    internal static SoapAuthException BindingInputRejected() => new("SOAP-TYPED-BINDING-INPUT-REJECTED");
    internal static SoapAuthException BindingInputUnavailable() => new("SOAP-TYPED-BINDING-INPUT-UNAVAILABLE");
}
