using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>
/// Typed, server-owned SOAP HTTP policy. Callers can observe the resolved semantics but cannot
/// construct or override the version, action, content type or header representation.
/// </summary>
public sealed class SoapHttpRequestMetadata
{
    internal SoapHttpRequestMetadata(SoapEnvelopeVersion version, string action)
    {
        if (!Enum.IsDefined(version) || string.IsNullOrWhiteSpace(action) || action.Length > 2_048 ||
            action.Any(character => char.IsControl(character) || char.IsWhiteSpace(character) || character is '"' or '\\') ||
            !Uri.TryCreate(action, UriKind.Absolute, out Uri? parsed) || !parsed.IsAbsoluteUri)
            throw new SoapAuthException("SOAP-HTTP-METADATA-INVALID");
        Version = version;
        Action = action;
    }

    /// <summary>Published SOAP envelope version.</summary>
    public SoapEnvelopeVersion Version { get; }

    /// <summary>Published operation-bound action URI.</summary>
    public string Action { get; }

    internal string BaseContentType => Version == SoapEnvelopeVersion.Soap11 ? "text/xml" : "application/soap+xml";

    internal void Apply(HttpRequestMessage request, byte[] envelope)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(envelope);
        if (request.Content is not null || request.Headers.Contains("SOAPAction"))
            throw new SoapAuthException("SOAP-HTTP-POLICY-VIOLATION");

        request.Content = new ClearingByteArrayContent(envelope);
        MediaTypeHeaderValue contentType = new(BaseContentType) { CharSet = "utf-8" };
        if (Version == SoapEnvelopeVersion.Soap11)
        {
            if (!request.Headers.TryAddWithoutValidation("SOAPAction", '"' + Action + '"'))
                throw new SoapAuthException("SOAP-HTTP-POLICY-VIOLATION");
        }
        else
        {
            contentType.Parameters.Add(new NameValueHeaderValue("action", '"' + Action + '"'));
        }
        request.Content.Headers.ContentType = contentType;
        EnsureApplied(request);
    }

    internal void EnsureApplied(HttpRequestMessage request)
    {
        MediaTypeHeaderValue? contentType = request.Content?.Headers.ContentType;
        if (contentType is null || !string.Equals(contentType.MediaType, BaseContentType, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(contentType.CharSet?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase))
            throw new SoapAuthException("SOAP-HTTP-POLICY-VIOLATION");

        if (Version == SoapEnvelopeVersion.Soap11)
        {
            string[] actions = request.Headers.TryGetValues("SOAPAction", out IEnumerable<string>? values) ? values.ToArray() : [];
            if (actions.Length != 1 || !string.Equals(actions[0], '"' + Action + '"', StringComparison.Ordinal))
                throw new SoapAuthException("SOAP-HTTP-POLICY-VIOLATION");
            if (contentType.Parameters.Any(parameter => string.Equals(parameter.Name, "action", StringComparison.OrdinalIgnoreCase)))
                throw new SoapAuthException("SOAP-HTTP-POLICY-VIOLATION");
        }
        else
        {
            if (request.Headers.Contains("SOAPAction")) throw new SoapAuthException("SOAP-HTTP-POLICY-VIOLATION");
            NameValueHeaderValue[] actions = contentType.Parameters.Where(parameter => string.Equals(parameter.Name, "action", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (actions.Length != 1 || !string.Equals(actions[0].Value?.Trim('"'), Action, StringComparison.Ordinal))
                throw new SoapAuthException("SOAP-HTTP-POLICY-VIOLATION");
        }
    }

    /// <inheritdoc />
    public override string ToString() => $"SoapHttpRequestMetadata(Version={Version})";

    private sealed class ClearingByteArrayContent : ByteArrayContent
    {
        private readonly byte[] bytes;

        internal ClearingByteArrayContent(byte[] bytes) : base(bytes) => this.bytes = bytes;

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) CryptographicOperations.ZeroMemory(bytes);
        }
    }
}

/// <summary>
/// Non-forgeable composed SOAP authority resolved from the current Published Connector snapshot.
/// Endpoint, bindings, placements, revisions and provider references remain internal.
/// </summary>
public sealed class ComposedSoapResolvedExecutionContext
{
    internal ComposedSoapResolvedExecutionContext(ComposedSoapAuthorityState state, Func<CancellationToken, Task<ComposedSoapAuthorityState>> revalidate)
    {
        State = state;
        Revalidate = revalidate;
    }

    /// <summary>Resolved Connector identifier.</summary>
    public string ConnectorId => State.SessionAuthority.ConnectorId;

    /// <summary>Resolved authorized operation.</summary>
    public string OperationId => State.SessionAuthority.OperationId;

    /// <summary>Logical composed policy selector.</summary>
    public string PolicyId => State.SessionAuthority.PolicyId;

    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId => State.SessionAuthority.CorrelationId;

    /// <summary>Read-only typed SOAP semantics selected by the Published policy.</summary>
    public SoapHttpRequestMetadata SoapHttp => State.SoapHttp;

    [JsonIgnore] internal ComposedSoapAuthorityState State { get; }
    [JsonIgnore] internal Func<CancellationToken, Task<ComposedSoapAuthorityState>> Revalidate { get; }

    /// <inheritdoc />
    public override string ToString() => $"ComposedSoapResolvedExecutionContext(ConnectorId={ConnectorId}, OperationId={OperationId}, PolicyId={PolicyId}, CorrelationId={CorrelationId:D})";
}

/// <summary>Bounded SOAP HTTP response preserved for the hardened SOAP response parser.</summary>
public sealed record ComposedSoapHttpResponse(int StatusCode, string ContentType, byte[] Body);

internal sealed record ComposedSoapAuthorityState(
    OpaqueSessionHttpAuthorityState SessionAuthority,
    ResolvedBasicCredentialBinding BasicCredential,
    SoapHttpRequestMetadata SoapHttp,
    TypedComposedSoapRequestAuthority? TypedRequest,
    string SecurityFingerprint);
