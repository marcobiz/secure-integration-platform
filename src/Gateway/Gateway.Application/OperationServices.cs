using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.Application;

/// <summary>Validated, immutable server-side operation catalogue.</summary>
public sealed class GatewayOperationCatalog : IGatewayOperationCatalog
{
    private readonly Dictionary<string, GatewayOperationDefinition> operations;

    /// <summary>Validates and freezes all operation definitions.</summary>
    public GatewayOperationCatalog(IEnumerable<GatewayOperationDefinition> definitions)
    {
        Dictionary<string, GatewayOperationDefinition> validated = new(StringComparer.Ordinal);
        foreach (GatewayOperationDefinition definition in definitions)
        {
            Validate(definition);
            if (!validated.TryAdd(Key(definition.ConnectorId, definition.OperationId), definition))
                throw new InvalidOperationException("Duplicate Gateway operation definition.");
        }
        operations = validated;
    }

    /// <inheritdoc />
    public Task<GatewayOperationDefinition> GetRequiredAsync(string connectorId, string operationId, Guid environmentId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!operations.TryGetValue(Key(connectorId, operationId), out GatewayOperationDefinition? value))
            throw new GatewayException("BGW-OPERATION-NOT-FOUND", 404);
        return Task.FromResult(value);
    }

    /// <inheritdoc />
    public void Invalidate(string connectorId) { }

    private static string Key(string connectorId, string operationId) => connectorId + "\n" + operationId;

    private static void Validate(GatewayOperationDefinition value)
    {
        if (!IsIdentifier(value.ConnectorId) || !IsIdentifier(value.OperationId) || string.IsNullOrWhiteSpace(value.Version))
            throw new InvalidOperationException("Invalid Gateway operation identifier.");
        if (!value.Endpoint.IsAbsoluteUri || value.Endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(value.Endpoint.UserInfo) || !string.IsNullOrEmpty(value.Endpoint.Fragment))
            throw new InvalidOperationException("Gateway operation endpoints must be absolute HTTPS URIs without user information or fragments.");
        if (value.Method != HttpMethod.Get && value.Method != HttpMethod.Post && value.Method != HttpMethod.Put && value.Method != HttpMethod.Delete)
            throw new InvalidOperationException("Unsupported Gateway operation method.");
        if (value.TimeoutMilliseconds is < 100 or > 120_000 || value.MaximumRequestBytes is <= 0 or > 16 * 1024 * 1024 || value.MaximumResponseBytes is <= 0 or > 16 * 1024 * 1024 || value.MaximumRetries is < 0 or > 2 || (!value.Idempotent && value.MaximumRetries != 0))
            throw new InvalidOperationException("Invalid Gateway operation bounds.");
        if (value.Authentication == GatewayAuthenticationKind.Basic && (string.IsNullOrWhiteSpace(value.UsernameSecretReference) || string.IsNullOrWhiteSpace(value.PasswordSecretReference)))
            throw new InvalidOperationException("Basic authentication requires server-side secret references.");
        if (value.Authentication == GatewayAuthenticationKind.ApiKey && (string.IsNullOrWhiteSpace(value.ApiKeySecretReference) || !IsHeaderName(value.ApiKeyHeaderName)))
            throw new InvalidOperationException("API key authentication requires a safe header and server-side secret reference.");
        if (value.Authentication == GatewayAuthenticationKind.MutualTls && string.IsNullOrWhiteSpace(value.ClientCertificateReference))
            throw new InvalidOperationException("mTLS authentication requires a server-side certificate reference.");
        if (value.Authentication == GatewayAuthenticationKind.ApiKeyAndMutualTls && (string.IsNullOrWhiteSpace(value.ApiKeySecretReference) || !IsHeaderName(value.ApiKeyHeaderName) || string.IsNullOrWhiteSpace(value.ClientCertificateReference)))
            throw new InvalidOperationException("Combined API key and mTLS authentication requires server-side secret references and a safe header.");
    }

    private static bool IsIdentifier(string value) => value.Length is > 0 and <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    private static bool IsHeaderName(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-');
}

/// <summary>Executes a granted operation using only server-owned destination and credentials.</summary>
public sealed class RestrictedEgressService(
    IGatewayRegistry registry,
    IGatewayOperationCatalog catalog,
    ISecretValueProvider secrets,
    IClientCertificateProvider certificates,
    IHostResolver resolver,
    IRestrictedTransport transport,
    IGatewayClock clock,
    IPrivateDestinationAllowance? privateDestinationAllowance = null)
{
    /// <summary>Authorizes and invokes a server-owned external operation.</summary>
    public async Task<GatewayInvokeResponse> InvokeAsync(GatewayClientPrincipal authenticated, string connectorId, string operationId, GatewayInvokeRequest request, CancellationToken cancellationToken)
    {
        if (!string.Equals(request.ProtocolVersion, "1.0", StringComparison.Ordinal) || request.CorrelationId == Guid.Empty)
            throw new GatewayException("BGW-PROTOCOL-VERSION", 400);
        if (request.IdempotencyKey is not null && (request.IdempotencyKey.Length is < 1 or > 128 || request.IdempotencyKey.Any(character => character is < '!' or > '~')))
            throw new GatewayException("BGW-IDEMPOTENCY-KEY", 400);
        RegisteredInstallationIdentity identity = authenticated.Identity;
        if (identity.TenantStatus != TenantStatus.Active || identity.ApplicationStatus != ApplicationStatus.Active || identity.InstallationStatus != InstallationStatus.Active)
            throw new GatewayException("BGW-INSTALLATION-REVOKED", 403);
        if (!await registry.IsGrantedAsync(identity.InstallationId, identity.TenantId, connectorId, operationId, clock.UtcNow, cancellationToken).ConfigureAwait(false))
            throw new GatewayException("BGW-AUTHZ-OPERATION-DENIED", 403);
        GatewayOperationDefinition operation = await catalog.GetRequiredAsync(connectorId, operationId, identity.EnvironmentId,
            new(identity.InstallationId, identity.TenantId, identity.ApplicationId, operationId), cancellationToken).ConfigureAwait(false);

        if (request.Metadata?.Count > 32 || request.Extensions?.Count > 16 || request.Metadata?.Values.Any(value => value.ValueKind is JsonValueKind.Array or JsonValueKind.Object) == true)
            throw new GatewayException("BGW-PROTOCOL-METADATA", 400);
        byte[] body;
        try
        {
            body = request.Payload.Encoding switch
            {
                "base64" => Convert.FromBase64String(request.Payload.Data),
                "utf8" => Encoding.UTF8.GetBytes(request.Payload.Data),
                _ => throw new GatewayException("BGW-PROTOCOL-PAYLOAD", 400)
            };
        }
        catch (FormatException) { throw new GatewayException("BGW-PROTOCOL-PAYLOAD", 400); }
        if (body.LongLength > operation.MaximumRequestBytes)
            throw new GatewayException("BGW-PROTOCOL-PAYLOAD", 413);

        IPAddress[] addresses = await resolver.ResolveAsync(operation.Endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0 || addresses.Any(address => IsForbiddenAddress(address) && privateDestinationAllowance?.IsAllowed(operation.Endpoint.DnsSafeHost, address) != true))
            throw new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 403);

        int attempts = operation.MaximumRetries + 1;
        for (int attempt = 1; ; attempt++)
        {
            using HttpRequestMessage outbound = new(operation.Method, operation.Endpoint);
            outbound.Headers.TryAddWithoutValidation("X-Correlation-ID", request.CorrelationId.ToString("D"));
            if (operation.Method != HttpMethod.Get)
                outbound.Content = new ByteArrayContent(body) { Headers = { ContentType = MediaTypeHeaderValue.Parse(operation.RequestContentType) } };
            X509Certificate2? clientCertificate = null;
            try
            {
                clientCertificate = await ApplyAuthenticationAsync(outbound, operation, cancellationToken).ConfigureAwait(false);
                ExternalResponse result = await transport.SendAsync(outbound, addresses, clientCertificate, TimeSpan.FromMilliseconds(operation.TimeoutMilliseconds), operation.MaximumResponseBytes, cancellationToken).ConfigureAwait(false);
                await registry.AppendAuditAsync(new GatewayAuditEvent(Guid.NewGuid(), clock.UtcNow, identity.TenantId, "installation", identity.InstallationId.ToString("D"), "operation.invoke", "operation", connectorId + "/" + operationId, request.CorrelationId, "success", "BGW-OPERATION-OK", new Dictionary<string, string> { ["connectorVersion"] = operation.Version, ["statusCategory"] = (result.StatusCode / 100).ToString(System.Globalization.CultureInfo.InvariantCulture) + "xx", ["callerKind"] = identity.InstallationKind.ToString() }), cancellationToken).ConfigureAwait(false);
                return new GatewayInvokeResponse(request.CorrelationId, operation.Version, new GatewayPayload(result.ContentType, "base64", Convert.ToBase64String(result.Body)));
            }
            catch (Exception exception) when (attempt < attempts && exception is HttpRequestException or TimeoutException)
            {
                // Retry only operations explicitly declared idempotent by server configuration.
            }
            finally { clientCertificate?.Dispose(); }
        }
    }

    private async Task<X509Certificate2?> ApplyAuthenticationAsync(HttpRequestMessage request, GatewayOperationDefinition operation, CancellationToken cancellationToken)
    {
        switch (operation.Authentication)
        {
            case GatewayAuthenticationKind.None:
                return null;
            case GatewayAuthenticationKind.Basic:
                string username = await secrets.GetSecretAsync(operation.UsernameSecretReference!, cancellationToken).ConfigureAwait(false);
                string password = await secrets.GetSecretAsync(operation.PasswordSecretReference!, cancellationToken).ConfigureAwait(false);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(username + ":" + password)));
                return null;
            case GatewayAuthenticationKind.ApiKey:
                string key = await secrets.GetSecretAsync(operation.ApiKeySecretReference!, cancellationToken).ConfigureAwait(false);
                request.Headers.TryAddWithoutValidation(operation.ApiKeyHeaderName!, key);
                return null;
            case GatewayAuthenticationKind.MutualTls:
                return await certificates.GetClientCertificateAsync(operation.ClientCertificateReference!, cancellationToken).ConfigureAwait(false);
            case GatewayAuthenticationKind.ApiKeyAndMutualTls:
                string combinedKey = await secrets.GetSecretAsync(operation.ApiKeySecretReference!, cancellationToken).ConfigureAwait(false);
                request.Headers.TryAddWithoutValidation(operation.ApiKeyHeaderName!, combinedKey);
                return await certificates.GetClientCertificateAsync(operation.ClientCertificateReference!, cancellationToken).ConfigureAwait(false);
            default:
                throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 500);
        }
    }

    /// <summary>Returns true for loopback, link-local, metadata and non-public address ranges.</summary>
    public static bool IsForbiddenAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return true;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && (address.GetAddressBytes()[0] & 0xfe) == 0xfc) return true;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            return bytes[0] is 0 or 10 or 127 || bytes[0] >= 224 || (bytes[0] == 169 && bytes[1] == 254) || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168) || (bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
        }
        return address.IsIPv4MappedToIPv6 && IsForbiddenAddress(address.MapToIPv4());
    }
}
