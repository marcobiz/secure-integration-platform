using System.Collections.Frozen;
using System.Text;

namespace SecureIntegration.Gateway.Application;

/// <summary>Only signing algorithm currently authorized by the bounded expectation contract.</summary>
public enum AuthorizedSigningAlgorithm
{
    /// <summary>RSA PKCS#1 v1.5 with SHA-256.</summary>
    Rs256
}

/// <summary>Exact server-owned projection expected for one opaque signed token.</summary>
public enum AuthorizedSigningTokenProjectionKind
{
    /// <summary>HTTP Authorization Bearer projection.</summary>
    AuthorizationBearer,
    /// <summary>One Published bounded signed-token header.</summary>
    SignedTokenHeader
}

/// <summary>Exact temporal-claim shape expected from the Published signing policy.</summary>
public enum AuthorizedSigningTemporalMode
{
    /// <summary>Issued-at and expiration only.</summary>
    IssuedAtExpiration,
    /// <summary>Issued-at, not-before and expiration.</summary>
    IssuedAtNotBeforeExpiration
}

/// <summary>Exact certificate header shape expected from the Published signing policy.</summary>
public enum AuthorizedSigningCertificateHeaderMode
{
    /// <summary>No x5c header.</summary>
    None,
    /// <summary>Leaf certificate only.</summary>
    Leaf,
    /// <summary>Leaf-first certificate chain.</summary>
    Chain
}

/// <summary>Exact signing-certificate Key Usage expected from the Published policy.</summary>
public enum AuthorizedSigningCertificateKeyUsageMode
{
    /// <summary>Historical Published behavior requiring digitalSignature when Key Usage is present.</summary>
    DigitalSignature,
    /// <summary>Require a present contentCommitment/nonRepudiation Key Usage.</summary>
    ContentCommitment
}

/// <summary>Closed server-owned response handling for one qualified restricted transport.</summary>
public enum AuthorizedRestrictedTransportResponseMode
{
    /// <summary>Preserve the existing success-only restricted-transport semantics.</summary>
    SuccessOnly,
    /// <summary>Return one bounded non-success response for sanitized RFC 7807 mapping.</summary>
    BoundedProblemDetails
}

/// <summary>Closed issuer comparison supported by the Core-owned policy preflight.</summary>
public enum AuthorizedSigningIssuerExpectationKind
{
    /// <summary>Ordinal equality with one exact Published issuer.</summary>
    Exact,
    /// <summary>Ordinal equality with a fixed prefix plus the verified signing-certificate subject CN.</summary>
    FixedPrefixAndCertificateSubjectCommonName
}

/// <summary>Immutable bounded issuer expectation; it contains no certificate or provider metadata.</summary>
public sealed class AuthorizedSigningIssuerExpectation
{
    private AuthorizedSigningIssuerExpectation(AuthorizedSigningIssuerExpectationKind kind, string value)
    {
        Kind = kind;
        Value = AuthorizedPublishedExpectationBounds.ExactText(value, nameof(value), 512);
    }

    /// <summary>Closed comparison kind.</summary>
    public AuthorizedSigningIssuerExpectationKind Kind { get; }
    /// <summary>Exact issuer, or the fixed prefix for the verified subject-CN relation.</summary>
    public string Value { get; }

    /// <summary>Creates one exact ordinal issuer expectation.</summary>
    public static AuthorizedSigningIssuerExpectation Exact(string issuer) =>
        new(AuthorizedSigningIssuerExpectationKind.Exact, issuer);

    /// <summary>Creates a fixed-prefix plus verified signing-certificate subject-CN expectation.</summary>
    public static AuthorizedSigningIssuerExpectation FixedPrefixAndCertificateSubjectCommonName(string prefix) =>
        new(AuthorizedSigningIssuerExpectationKind.FixedPrefixAndCertificateSubjectCommonName, prefix);

    /// <inheritdoc />
    public override string ToString() => $"AuthorizedSigningIssuerExpectation(Kind={Kind}, Redacted=True)";
}

/// <summary>Immutable exact outbound projection expectation for one signing slot.</summary>
public sealed class AuthorizedSigningTokenProjectionExpectation
{
    private AuthorizedSigningTokenProjectionExpectation(AuthorizedSigningTokenProjectionKind kind, string? headerName)
    {
        Kind = kind;
        HeaderName = headerName;
    }

    /// <summary>Closed projection kind.</summary>
    public AuthorizedSigningTokenProjectionKind Kind { get; }
    /// <summary>Expected Published header name for <see cref="AuthorizedSigningTokenProjectionKind.SignedTokenHeader"/>.</summary>
    public string? HeaderName { get; }

    /// <summary>Expects the server-owned Authorization Bearer projection.</summary>
    public static AuthorizedSigningTokenProjectionExpectation AuthorizationBearer() =>
        new(AuthorizedSigningTokenProjectionKind.AuthorizationBearer, null);

    /// <summary>Expects one exact Published signed-token header.</summary>
    public static AuthorizedSigningTokenProjectionExpectation SignedTokenHeader(string headerName) =>
        new(AuthorizedSigningTokenProjectionKind.SignedTokenHeader,
            AuthorizedPublishedExpectationBounds.HttpFieldName(headerName, nameof(headerName)));

    /// <inheritdoc />
    public override string ToString() => $"AuthorizedSigningTokenProjectionExpectation(Kind={Kind}, HeaderName={HeaderName})";
}

/// <summary>Bounded semantic expectations for one exact Published signing slot.</summary>
public sealed class AuthorizedSigningSlotExpectation
{
    private readonly FrozenSet<string> allowedBusinessClaims;

    /// <summary>Creates an immutable exact slot expectation from bounded generic primitives.</summary>
    public AuthorizedSigningSlotExpectation(
        ConnectorSigningSlotKey signingSlot,
        bool required,
        AuthorizedSigningAlgorithm algorithm,
        AuthorizedSigningTokenProjectionExpectation projection,
        string audience,
        string fixedSubject,
        IReadOnlyCollection<string> allowedBusinessClaims,
        int tokenLifetimeSeconds,
        AuthorizedSigningTemporalMode temporalMode,
        bool jtiRequired,
        AuthorizedSigningCertificateHeaderMode certificateHeaderMode,
        AuthorizedSigningIssuerExpectation issuer) : this(
            signingSlot,
            required,
            algorithm,
            projection,
            audience,
            fixedSubject,
            allowedBusinessClaims,
            tokenLifetimeSeconds,
            temporalMode,
            jtiRequired,
            certificateHeaderMode,
            issuer,
            AuthorizedSigningCertificateKeyUsageMode.DigitalSignature)
    {
    }

    /// <summary>Creates an exact slot expectation with an explicit certificate Key Usage mode.</summary>
    public AuthorizedSigningSlotExpectation(
        ConnectorSigningSlotKey signingSlot,
        bool required,
        AuthorizedSigningAlgorithm algorithm,
        AuthorizedSigningTokenProjectionExpectation projection,
        string audience,
        string fixedSubject,
        IReadOnlyCollection<string> allowedBusinessClaims,
        int tokenLifetimeSeconds,
        AuthorizedSigningTemporalMode temporalMode,
        bool jtiRequired,
        AuthorizedSigningCertificateHeaderMode certificateHeaderMode,
        AuthorizedSigningIssuerExpectation issuer,
        AuthorizedSigningCertificateKeyUsageMode certificateKeyUsageMode)
    {
        SigningSlot = signingSlot ?? throw new ArgumentNullException(nameof(signingSlot));
        if (!Enum.IsDefined(algorithm)) throw new ArgumentOutOfRangeException(nameof(algorithm));
        if (!Enum.IsDefined(temporalMode)) throw new ArgumentOutOfRangeException(nameof(temporalMode));
        if (!Enum.IsDefined(certificateHeaderMode)) throw new ArgumentOutOfRangeException(nameof(certificateHeaderMode));
        if (!Enum.IsDefined(certificateKeyUsageMode)) throw new ArgumentOutOfRangeException(nameof(certificateKeyUsageMode));
        Projection = projection ?? throw new ArgumentNullException(nameof(projection));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        Audience = AuthorizedPublishedExpectationBounds.ExactText(audience, nameof(audience), 512);
        FixedSubject = AuthorizedPublishedExpectationBounds.ExactText(fixedSubject, nameof(fixedSubject), 256);
        this.allowedBusinessClaims = AuthorizedPublishedExpectationBounds.Claims(allowedBusinessClaims);
        if (tokenLifetimeSeconds is < 1 or > 3600) throw new ArgumentOutOfRangeException(nameof(tokenLifetimeSeconds));
        Required = required;
        Algorithm = algorithm;
        TokenLifetimeSeconds = tokenLifetimeSeconds;
        TemporalMode = temporalMode;
        JtiRequired = jtiRequired;
        CertificateHeaderMode = certificateHeaderMode;
        CertificateKeyUsageMode = certificateKeyUsageMode;
    }

    /// <summary>Exact Published signing-slot key.</summary>
    public ConnectorSigningSlotKey SigningSlot { get; }
    /// <summary>Exact required/optional transport completeness expectation.</summary>
    public bool Required { get; }
    /// <summary>Exact signing algorithm expectation.</summary>
    public AuthorizedSigningAlgorithm Algorithm { get; }
    /// <summary>Exact server-owned transport projection expectation.</summary>
    public AuthorizedSigningTokenProjectionExpectation Projection { get; }
    /// <summary>Exact audience compared ordinally after NFC validation.</summary>
    public string Audience { get; }
    /// <summary>Exact fixed subject compared ordinally after NFC validation.</summary>
    public string FixedSubject { get; }
    /// <summary>Exact immutable business-claim allowlist.</summary>
    public IReadOnlySet<string> AllowedBusinessClaims => allowedBusinessClaims;
    /// <summary>Exact token lifetime in seconds.</summary>
    public int TokenLifetimeSeconds { get; }
    /// <summary>Exact temporal-claim mode.</summary>
    public AuthorizedSigningTemporalMode TemporalMode { get; }
    /// <summary>Exact requirement for a Core-generated jti.</summary>
    public bool JtiRequired { get; }
    /// <summary>Exact certificate/x5c header mode.</summary>
    public AuthorizedSigningCertificateHeaderMode CertificateHeaderMode { get; }
    /// <summary>Exact signing-certificate Key Usage requirement.</summary>
    public AuthorizedSigningCertificateKeyUsageMode CertificateKeyUsageMode { get; }
    /// <summary>Bounded issuer comparison.</summary>
    public AuthorizedSigningIssuerExpectation Issuer { get; }

    /// <inheritdoc />
    public override string ToString() => $"AuthorizedSigningSlotExpectation(SigningSlot={SigningSlot}, Redacted=True)";
}

/// <summary>
/// Bounded module-owned semantic expectations that Core compares with one exact Published operation
/// before the strategy, signing and network are allowed to run.
/// </summary>
public sealed class AuthorizedPublishedOperationExpectations
{
    private readonly FrozenDictionary<ConnectorSigningSlotKey, AuthorizedSigningSlotExpectation> signingSlots;
    private readonly FrozenSet<ConnectorSigningSlotKey> sameSigningIdentitySlots;
    private readonly FrozenSet<ConnectorSigningSlotKey> signingIdentityDistinctFromMutualTlsSlots;

    /// <summary>Creates one immutable bounded expectation snapshot.</summary>
    public AuthorizedPublishedOperationExpectations(
        GatewayAuthenticationKind authenticationKind,
        bool restrictedTransportRequired,
        IReadOnlyCollection<AuthorizedSigningSlotExpectation> signingSlots,
        IReadOnlyCollection<ConnectorSigningSlotKey>? sameSigningIdentitySlots = null,
        IReadOnlyCollection<ConnectorSigningSlotKey>? signingIdentityDistinctFromMutualTlsSlots = null,
        AuthorizedRestrictedTransportResponseMode restrictedTransportResponseMode = AuthorizedRestrictedTransportResponseMode.SuccessOnly)
    {
        if (!Enum.IsDefined(authenticationKind)) throw new ArgumentOutOfRangeException(nameof(authenticationKind));
        if (!Enum.IsDefined(restrictedTransportResponseMode)) throw new ArgumentOutOfRangeException(nameof(restrictedTransportResponseMode));
        ArgumentNullException.ThrowIfNull(signingSlots);
        Dictionary<ConnectorSigningSlotKey, AuthorizedSigningSlotExpectation> slots = [];
        int count = 0;
        foreach (AuthorizedSigningSlotExpectation slot in signingSlots)
        {
            if (slot is null || ++count > AuthorizedSigningSlots.MaximumSlots || !slots.TryAdd(slot.SigningSlot, slot))
                throw new ArgumentException("Signing-slot expectations are invalid, duplicated or excessive.", nameof(signingSlots));
        }
        if (!restrictedTransportRequired && slots.Count != 0)
            throw new ArgumentException("Signing-slot expectations require restricted transport.", nameof(signingSlots));
        if (!restrictedTransportRequired && restrictedTransportResponseMode != AuthorizedRestrictedTransportResponseMode.SuccessOnly)
            throw new ArgumentException("Bounded response handling requires restricted transport.", nameof(restrictedTransportResponseMode));

        this.signingSlots = slots.ToFrozenDictionary();
        this.sameSigningIdentitySlots = IdentitySet(sameSigningIdentitySlots, slots, minimumCount: 2,
            nameof(sameSigningIdentitySlots));
        this.signingIdentityDistinctFromMutualTlsSlots = IdentitySet(
            signingIdentityDistinctFromMutualTlsSlots, slots, minimumCount: 0,
            nameof(signingIdentityDistinctFromMutualTlsSlots));
        AuthenticationKind = authenticationKind;
        RestrictedTransportRequired = restrictedTransportRequired;
        RestrictedTransportResponseMode = restrictedTransportResponseMode;
    }

    /// <summary>Exact outbound authentication kind expected by the module.</summary>
    public GatewayAuthenticationKind AuthenticationKind { get; }
    /// <summary>Exact expected restricted-transport presence; false requires verified absence and is not an opt-out.</summary>
    public bool RestrictedTransportRequired { get; }
    /// <summary>Closed server-owned response handling enabled only after the exact Published preflight.</summary>
    public AuthorizedRestrictedTransportResponseMode RestrictedTransportResponseMode { get; }
    /// <summary>Exact immutable signing-slot set; empty requires verified absence of legacy signing and signing slots.</summary>
    public IReadOnlyDictionary<ConnectorSigningSlotKey, AuthorizedSigningSlotExpectation> SigningSlots => signingSlots;
    /// <summary>Slots whose verified signing-certificate identities must all be equal.</summary>
    public IReadOnlySet<ConnectorSigningSlotKey> SameSigningIdentitySlots => sameSigningIdentitySlots;
    /// <summary>Slots whose verified signing identities must differ from the approved mTLS identity.</summary>
    public IReadOnlySet<ConnectorSigningSlotKey> SigningIdentityDistinctFromMutualTlsSlots => signingIdentityDistinctFromMutualTlsSlots;

    /// <inheritdoc />
    public override string ToString() =>
        $"AuthorizedPublishedOperationExpectations(AuthenticationKind={AuthenticationKind}, SigningSlotCount={SigningSlots.Count}, Redacted=True)";

    private static FrozenSet<ConnectorSigningSlotKey> IdentitySet(
        IReadOnlyCollection<ConnectorSigningSlotKey>? values,
        Dictionary<ConnectorSigningSlotKey, AuthorizedSigningSlotExpectation> slots,
        int minimumCount,
        string parameterName)
    {
        if (values is null) return Array.Empty<ConnectorSigningSlotKey>().ToFrozenSet();
        HashSet<ConnectorSigningSlotKey> result = [];
        int count = 0;
        foreach (ConnectorSigningSlotKey value in values)
        {
            if (value is null || ++count > AuthorizedSigningSlots.MaximumSlots || !slots.ContainsKey(value) || !result.Add(value))
                throw new ArgumentException("Signing-identity expectation set is invalid.", parameterName);
        }
        if (result.Count != 0 && result.Count < minimumCount)
            throw new ArgumentException("Signing-identity expectation set is incomplete.", parameterName);
        return result.ToFrozenSet();
    }
}

/// <summary>
/// Safe invocation-bound context supplied only to the module-owned expectation provider. It exposes
/// no payload, capability bridge, endpoint, provider, policy object or resource metadata.
/// </summary>
public sealed class AuthorizedPublishedOperationExpectationContext
{
    private readonly AuthorizedPublishedExtensionConfiguration extensionConfiguration;

    internal AuthorizedPublishedOperationExpectationContext(AuthorizedConnectorExecution execution)
    {
        ArgumentNullException.ThrowIfNull(execution);
        ConnectorId = execution.ConnectorId;
        ConnectorVersion = execution.ConnectorVersion;
        OperationId = execution.OperationId;
        ExecutionStrategyKey = execution.ExecutionStrategyKey;
        AuthenticationKind = execution.AuthenticationKind;
        extensionConfiguration = execution.OpenPublishedExtensionConfiguration();
    }

    /// <summary>Exact Connector identifier already authorized by Core.</summary>
    public string ConnectorId { get; }
    /// <summary>Exact immutable Published Connector version.</summary>
    public string ConnectorVersion { get; }
    /// <summary>Exact operation identifier already authorized by Core.</summary>
    public string OperationId { get; }
    /// <summary>Exact server-owned execution strategy key.</summary>
    public ConnectorExecutionStrategyKey ExecutionStrategyKey { get; }
    /// <summary>Exact server-owned outbound authentication kind.</summary>
    public GatewayAuthenticationKind AuthenticationKind { get; }

    /// <summary>Opens a defensive copy of the bounded open Published extension configuration.</summary>
    public AuthorizedPublishedExtensionConfiguration OpenPublishedExtensionConfiguration() => extensionConfiguration.Copy();

    /// <inheritdoc />
    public override string ToString() =>
        $"AuthorizedPublishedOperationExpectationContext(ConnectorId={ConnectorId}, ConnectorVersion={ConnectorVersion}, OperationId={OperationId}, ExecutionStrategyKey={ExecutionStrategyKey}, AuthenticationKind={AuthenticationKind}, Redacted=True)";
}

/// <summary>
/// Startup-registered module-owned source of bounded semantic expectations. Core, not the provider,
/// reads and compares the effective Published policies.
/// </summary>
public interface IAuthorizedPublishedOperationExpectationProvider
{
    /// <summary>Bounded strategy keys for which this provider supplies mandatory preflight expectations.</summary>
    IReadOnlySet<ConnectorExecutionStrategyKey> SupportedExecutionStrategies { get; }

    /// <summary>Builds expectations only from the safe exact-invocation context and its open extension configuration.</summary>
    AuthorizedPublishedOperationExpectations CreateExpectations(AuthorizedPublishedOperationExpectationContext context);
}

internal static class AuthorizedPublishedExpectationBounds
{
    private static readonly HashSet<string> ForbiddenHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "SOAPAction", "Content-Type", "Cookie", "Set-Cookie", "Host", "Content-Length",
        "Forwarded", "Via", "Expect", "TE", "Trailer", "Proxy-Authorization", "Proxy-Authenticate",
        "Connection", "Transfer-Encoding", "Upgrade", "X-Correlation-ID", "traceparent", "tracestate", "baggage"
    };

    internal static string ExactText(string value, string parameterName, int maximumCharacters)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (value.Length is < 1 || value.Length > maximumCharacters || !value.IsNormalized(NormalizationForm.FormC) ||
            value.Any(character => char.IsControl(character)) || string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Expected text must be non-empty NFC text without control characters.", parameterName);
        return value;
    }

    internal static FrozenSet<string> Claims(IReadOnlyCollection<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        HashSet<string> result = new(StringComparer.Ordinal);
        int count = 0;
        foreach (string value in values)
        {
            if (++count > 32 || value is null || value.Length is < 1 or > 64 ||
                value[0] is not (>= 'A' and <= 'Z') and not (>= 'a' and <= 'z') ||
                value.Any(character => character is not (>= 'A' and <= 'Z') and not (>= 'a' and <= 'z') and
                    not (>= '0' and <= '9') and not '.' and not '_' and not '-') || !result.Add(value))
                throw new ArgumentException("Business-claim expectation set is invalid, duplicated or excessive.", nameof(values));
        }
        return result.ToFrozenSet(StringComparer.Ordinal);
    }

    internal static string HttpFieldName(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (value.Length is < 1 or > 64 ||
            value.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '!' and not '#' and not '$' and not '%' and not '&' and not '\'' and not '*' and not '+' and not '-' and not '.' and not '^' and not '_' and not '`' and not '|' and not '~') ||
            ForbiddenHeaders.Contains(value) || value.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Expected signed-token header name is invalid.", parameterName);
        return value;
    }
}
