using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>Closed formatting choices for one opaque session header value.</summary>
public enum OpaqueSessionHttpHeaderValueFormat
{
    /// <summary>Place only the opaque upstream value.</summary>
    RawOpaqueValue,
    /// <summary>Place one fixed server-owned token followed by the opaque upstream value.</summary>
    FixedSchemeAndOpaqueValue
}

/// <summary>Validated typed HTTP-header placement. No arbitrary header collection is exposed.</summary>
public sealed class HttpRequestHeaderOpaqueSessionPlacementPolicy : OpaqueSessionPlacementPolicy
{
    private static readonly HashSet<string> Forbidden = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Host", "Content-Length", "Transfer-Encoding", "Connection", "Cookie", "Set-Cookie",
        "Proxy-Authorization", "Proxy-Authenticate", "Forwarded", "Via", "Expect", "Upgrade", "TE", "Trailer",
        "X-Correlation-ID"
    };

    internal HttpRequestHeaderOpaqueSessionPlacementPolicy(string headerName, OpaqueSessionHttpHeaderValueFormat valueFormat, string? fixedScheme)
        : base(OpaqueSessionPlacementKind.HttpRequestHeader)
    {
        if (!IsToken(headerName) || headerName.Length > 100 || Forbidden.Contains(headerName) || headerName.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase))
            throw new SoapAuthException("SESSION-HTTP-HEADER-FORBIDDEN");
        if (valueFormat == OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue && fixedScheme is not null)
            throw new SoapAuthException("SESSION-HTTP-POLICY-INVALID");
        if (valueFormat == OpaqueSessionHttpHeaderValueFormat.FixedSchemeAndOpaqueValue && (!IsToken(fixedScheme) || fixedScheme!.Length > 32))
            throw new SoapAuthException("SESSION-HTTP-POLICY-INVALID");
        HeaderName = headerName;
        ValueFormat = valueFormat;
        FixedScheme = fixedScheme;
    }

    /// <summary>Server-owned custom header name.</summary>
    public string HeaderName { get; }
    /// <summary>Closed value formatting mode.</summary>
    public OpaqueSessionHttpHeaderValueFormat ValueFormat { get; }
    /// <summary>Optional fixed scheme; never derived from an invocation payload.</summary>
    public string? FixedScheme { get; }

    internal string Format(string opaqueValue)
    {
        if (string.IsNullOrEmpty(opaqueValue) || opaqueValue.Length > 16_384 || opaqueValue.Any(character => character is '\r' or '\n' or '\0' || char.IsControl(character)))
            throw new SoapAuthException("SESSION-HTTP-SESSION-INVALID");
        return ValueFormat == OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue ? opaqueValue : FixedScheme + " " + opaqueValue;
    }

    /// <inheritdoc />
    public override string ToString() => $"{nameof(HttpRequestHeaderOpaqueSessionPlacementPolicy)}(HeaderName={HeaderName}, ValueFormat={ValueFormat})";

    private static bool IsToken(string? value) => !string.IsNullOrEmpty(value) && value.All(character =>
        char.IsAsciiLetterOrDigit(character) || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~');
}

/// <summary>Server-owned immutable policy for one Published Connector operation.</summary>
public sealed class ServerOwnedOpaqueSessionHttpPolicySnapshot
{
    private ServerOwnedOpaqueSessionHttpPolicySnapshot(
        string policyId, string connectorId, string connectorVersion, string operationId, string profileId, Guid environmentId,
        Uri endpoint, HttpMethod method, string? contentType, long bindingRevision, long endpointRevision, long credentialRevision,
        string resourceStamp, string headerName, OpaqueSessionHttpHeaderValueFormat valueFormat, string? fixedScheme,
        TimeSpan timeout, long maximumRequestBytes, long maximumResponseBytes)
    {
        if (!Identifier(policyId) || !Identifier(connectorId) || !Identifier(connectorVersion) || !Identifier(operationId) || !Identifier(profileId) || environmentId == Guid.Empty ||
            !HttpsEndpoint(endpoint) || method is null || (method != HttpMethod.Get && method != HttpMethod.Post && method != HttpMethod.Put && method != HttpMethod.Delete) ||
            bindingRevision < 1 || endpointRevision < 1 || credentialRevision < 1 || string.IsNullOrWhiteSpace(resourceStamp) || resourceStamp.Length > 256 || resourceStamp.Any(char.IsControl) ||
            timeout < TimeSpan.FromMilliseconds(100) || timeout > TimeSpan.FromMinutes(2) || maximumRequestBytes is < 1 or > 16 * 1024 * 1024 || maximumResponseBytes is < 1 or > 16 * 1024 * 1024 ||
            (method != HttpMethod.Get && (string.IsNullOrWhiteSpace(contentType) || !MediaTypeHeaderValue.TryParse(contentType, out _))) || (method == HttpMethod.Get && contentType is not null))
            throw new SoapAuthException("SESSION-HTTP-POLICY-INVALID");
        PolicyId = policyId;
        ConnectorId = connectorId;
        ConnectorVersion = connectorVersion;
        OperationId = operationId;
        ProfileId = profileId;
        EnvironmentId = environmentId;
        Endpoint = endpoint;
        Method = method;
        ContentType = contentType;
        BindingRevision = bindingRevision;
        EndpointRevision = endpointRevision;
        CredentialRevision = credentialRevision;
        ResourceStamp = resourceStamp;
        Placement = new(headerName, valueFormat, fixedScheme);
        Timeout = timeout;
        MaximumRequestBytes = maximumRequestBytes;
        MaximumResponseBytes = maximumResponseBytes;
        PolicyChecksumSha256 = Digest();
    }

    /// <summary>Creates a snapshot for a protected server-side policy catalogue.</summary>
    public static ServerOwnedOpaqueSessionHttpPolicySnapshot Create(
        string policyId, string connectorId, string connectorVersion, string operationId, string profileId, Guid environmentId,
        Uri endpoint, HttpMethod method, string? contentType, long bindingRevision, long endpointRevision, long credentialRevision,
        string resourceStamp, string headerName, OpaqueSessionHttpHeaderValueFormat valueFormat, string? fixedScheme,
        TimeSpan timeout, long maximumRequestBytes, long maximumResponseBytes) =>
        new(policyId, connectorId, connectorVersion, operationId, profileId, environmentId, endpoint, method, contentType, bindingRevision,
            endpointRevision, credentialRevision, resourceStamp, headerName, valueFormat, fixedScheme, timeout, maximumRequestBytes, maximumResponseBytes);

    /// <summary>Logical policy selected by connector-facing code.</summary>
    public string PolicyId { get; }
    /// <summary>Published Connector identifier.</summary>
    public string ConnectorId { get; }
    /// <summary>Published ConnectorVersion.</summary>
    public string ConnectorVersion { get; }
    /// <summary>Exact invoked operation.</summary>
    public string OperationId { get; }
    /// <summary>Exact opaque-session profile.</summary>
    public string ProfileId { get; }
    /// <summary>Authenticated server-derived Environment.</summary>
    public Guid EnvironmentId { get; }
    /// <summary>Approved destination; never accepted by the dispatch method.</summary>
    [JsonIgnore] public Uri Endpoint { get; }
    /// <summary>Approved HTTP method.</summary>
    [JsonIgnore] public HttpMethod Method { get; }
    /// <summary>Approved request media type.</summary>
    [JsonIgnore] public string? ContentType { get; }
    /// <summary>Immutable binding revision.</summary>
    public long BindingRevision { get; }
    /// <summary>Immutable endpoint revision.</summary>
    public long EndpointRevision { get; }
    /// <summary>Immutable credential resource revision.</summary>
    public long CredentialRevision { get; }
    /// <summary>Current Published resource stamp.</summary>
    [JsonIgnore] public string ResourceStamp { get; }
    /// <summary>Typed header placement.</summary>
    public HttpRequestHeaderOpaqueSessionPlacementPolicy Placement { get; }
    /// <summary>Approved one-shot timeout.</summary>
    public TimeSpan Timeout { get; }
    /// <summary>Approved maximum request bytes.</summary>
    public long MaximumRequestBytes { get; }
    /// <summary>Approved maximum bounded response bytes.</summary>
    public long MaximumResponseBytes { get; }
    /// <summary>Digest over all security-relevant policy fields.</summary>
    public string PolicyChecksumSha256 { get; }

    /// <inheritdoc />
    public override string ToString() => $"{nameof(ServerOwnedOpaqueSessionHttpPolicySnapshot)}(PolicyId={PolicyId}, ConnectorId={ConnectorId}, ConnectorVersion={ConnectorVersion}, OperationId={OperationId}, ProfileId={ProfileId})";

    private string Digest()
    {
        string canonical = string.Join('\n', PolicyId, ConnectorId, ConnectorVersion, OperationId, ProfileId, EnvironmentId.ToString("D"), Endpoint.AbsoluteUri,
            Method.Method, ContentType ?? string.Empty, BindingRevision, EndpointRevision, CredentialRevision, ResourceStamp, Placement.HeaderName,
            Placement.ValueFormat, Placement.FixedScheme ?? string.Empty, Timeout.Ticks, MaximumRequestBytes, MaximumResponseBytes);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    private static bool HttpsEndpoint(Uri value) => value.IsAbsoluteUri && value.Scheme == Uri.UriSchemeHttps && string.IsNullOrEmpty(value.UserInfo) && string.IsNullOrEmpty(value.Fragment);
}

/// <summary>Protected server-side source combining Published ConnectorVersion, operation dependencies and current bindings.</summary>
public interface IOpaqueSessionHttpPolicySource
{
    /// <summary>Resolves the exact current policy; callers supply only its logical identifier.</summary>
    Task<ServerOwnedOpaqueSessionHttpPolicySnapshot> ResolveAsync(ConnectorAuthExecutionContext context, string policyId, CancellationToken cancellationToken);
}

/// <summary>Bounded sanitized response from one authenticated HTTP dispatch.</summary>
public sealed record OpaqueSessionHttpResponse(int StatusCode, string ContentType, byte[] Body);

public sealed partial class SoapSessionClient
{
    /// <summary>
    /// Resolves and revalidates one server-owned policy, materializes the opaque value immediately before dispatch,
    /// and never exposes an authenticated request or session value.
    /// </summary>
    public async Task<OpaqueSessionHttpResponse> SendWithOpaqueSessionAsync(
        ConnectorAuthExecutionContext context,
        string policyId,
        ReadOnlyMemory<byte> businessBody,
        OpaqueSoapSessionReference? sessionReference,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        IOpaqueSessionHttpPolicySource policies = httpProjectionPolicies ?? throw new SoapAuthException("SESSION-HTTP-POLICY-UNAVAILABLE");
        if (string.IsNullOrWhiteSpace(policyId) || policyId.Length > 100) throw new SoapAuthException("SESSION-HTTP-POLICY-INVALID");
        EnsureDeadline(context);

        ServerOwnedOpaqueSessionHttpPolicySnapshot expected = await ResolveHttpPolicyAsync(policies, context, policyId, cancellationToken).ConfigureAwait(false);
        ValidateHttpPolicyBinding(context, policyId, expected);
        if (businessBody.Length > expected.MaximumRequestBytes || (expected.Method == HttpMethod.Get && !businessBody.IsEmpty))
            throw new SoapAuthException("SESSION-HTTP-REQUEST-INVALID");

        await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
        SoapSessionCacheKey key = ValidateAndKey(context, new SoapEndpointBinding(expected.Endpoint, expected.EndpointRevision), context.SessionProfileId);
        OpaqueSessionDispatchLease lease = cache.ResolveDispatchLease(key, sessionReference, clock.UtcNow);
        IPAddress[] addresses = await resolver.ResolveAsync(expected.Endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0 || addresses.Any(address => RestrictedEgressService.IsForbiddenAddress(address) && privateDestinationAllowance?.IsAllowed(expected.Endpoint.DnsSafeHost, address) != true))
            throw new SoapAuthException("SESSION-HTTP-EGRESS-DESTINATION-DENIED");

        await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
        EnsureCurrentLease(lease);
        ServerOwnedOpaqueSessionHttpPolicySnapshot current = await ResolveHttpPolicyAsync(policies, context, policyId, cancellationToken).ConfigureAwait(false);
        ValidateHttpPolicyBinding(context, policyId, current);
        await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
        EnsureCurrentLease(lease);
        if (!string.Equals(expected.PolicyChecksumSha256, current.PolicyChecksumSha256, StringComparison.Ordinal))
            throw new SoapAuthException("SESSION-HTTP-POLICY-STALE");
        EnsureCurrentLease(lease);
        EnsureDeadline(context);

        TimeSpan remaining = context.Deadline - clock.UtcNow;
        TimeSpan timeout = remaining < current.Timeout ? remaining : current.Timeout;
        if (timeout <= TimeSpan.Zero) throw new SoapAuthException("SESSION-HTTP-DEADLINE-EXPIRED");
        using HttpRequestMessage outbound = new(current.Method, current.Endpoint);
        outbound.Headers.TryAddWithoutValidation("X-Correlation-ID", context.CorrelationId.ToString("D"));
        if (current.Method != HttpMethod.Get)
            outbound.Content = new ByteArrayContent(businessBody.ToArray()) { Headers = { ContentType = MediaTypeHeaderValue.Parse(current.ContentType!) } };
        EnsureCurrentLease(lease);
        string projected = current.Placement.Format(lease.UpstreamSession);
        if (!outbound.Headers.TryAddWithoutValidation(current.Placement.HeaderName, projected) || outbound.Headers.GetValues(current.Placement.HeaderName).Count() != 1)
            throw new SoapAuthException("SESSION-HTTP-HEADER-DUPLICATE");

        try
        {
            ExternalResponse response = await transport.SendAsync(outbound, addresses, null, timeout, current.MaximumResponseBytes, cancellationToken).ConfigureAwait(false);
            await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
            EnsureCurrentLease(lease);
            ServerOwnedOpaqueSessionHttpPolicySnapshot afterDispatch = await ResolveHttpPolicyAsync(policies, context, policyId, cancellationToken).ConfigureAwait(false);
            ValidateHttpPolicyBinding(context, policyId, afterDispatch);
            if (!string.Equals(current.PolicyChecksumSha256, afterDispatch.PolicyChecksumSha256, StringComparison.Ordinal))
                throw new SoapAuthException("SESSION-HTTP-POLICY-STALE");
            return new(response.StatusCode, response.ContentType, response.Body);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new SoapAuthException("SESSION-HTTP-TIMEOUT"); }
        catch (OperationCanceledException) { throw; }
        catch (SoapAuthException) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or IOException or TimeoutException or GatewayException)
        {
            _ = exception;
            throw new SoapAuthException("SESSION-HTTP-TRANSPORT-FAILED");
        }
    }

    private static async Task<ServerOwnedOpaqueSessionHttpPolicySnapshot> ResolveHttpPolicyAsync(IOpaqueSessionHttpPolicySource source, ConnectorAuthExecutionContext context, string policyId, CancellationToken cancellationToken)
    {
        try { return await source.ResolveAsync(context, policyId, cancellationToken).ConfigureAwait(false) ?? throw new SoapAuthException("SESSION-HTTP-POLICY-UNAVAILABLE"); }
        catch (OperationCanceledException) { throw; }
        catch (SoapAuthException) { throw; }
        catch (Exception) { throw new SoapAuthException("SESSION-HTTP-POLICY-UNAVAILABLE"); }
    }

    private static void ValidateHttpPolicyBinding(ConnectorAuthExecutionContext context, string policyId, ServerOwnedOpaqueSessionHttpPolicySnapshot policy)
    {
        if (!string.Equals(policy.PolicyId, policyId, StringComparison.Ordinal) || !string.Equals(policy.ConnectorId, context.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(policy.ConnectorVersion, context.ConnectorVersion, StringComparison.Ordinal) || !string.Equals(policy.OperationId, context.OperationId, StringComparison.Ordinal) ||
            !string.Equals(policy.ProfileId, context.SessionProfileId, StringComparison.Ordinal) || policy.EnvironmentId != context.EnvironmentId ||
            policy.BindingRevision != context.BindingRevision || policy.EndpointRevision != context.EndpointRevision || policy.CredentialRevision != context.CredentialRevision ||
            !string.Equals(policy.ResourceStamp, context.ResourceStamp, StringComparison.Ordinal))
            throw new SoapAuthException("SESSION-HTTP-POLICY-BINDING-MISMATCH");
    }

    private void EnsureCurrentLease(OpaqueSessionDispatchLease lease)
    {
        if (!cache.IsCurrent(lease, clock.UtcNow)) throw new SoapAuthException("SESSION-HTTP-SESSION-STALE");
    }

}
