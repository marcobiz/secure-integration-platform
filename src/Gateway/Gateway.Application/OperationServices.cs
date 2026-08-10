using System.Collections.Frozen;
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
    private static readonly HashSet<string> ForbiddenAuthenticationHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "SOAPAction", "Content-Type", "Cookie", "Set-Cookie", "Host", "Content-Length", "Forwarded", "Via", "Expect", "TE", "Trailer",
        "Proxy-Authorization", "Proxy-Authenticate", "Connection", "Transfer-Encoding", "Upgrade", "X-Correlation-ID", "traceparent", "tracestate", "baggage"
    };
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
        if ((value.Authentication is GatewayAuthenticationKind.OAuthAuthorizationCode or GatewayAuthenticationKind.OAuthClientCredentials) && string.IsNullOrWhiteSpace(value.ApiKeySecretReference))
            throw new InvalidOperationException("OAuth authentication requires a server-side secret reference.");
        if (value.Authentication == GatewayAuthenticationKind.OpaqueSessionHttp && (string.IsNullOrWhiteSpace(value.ApiKeySecretReference) || !IsHeaderName(value.ApiKeyHeaderName)))
            throw new InvalidOperationException("Opaque-session authentication requires a server-side resource and safe custom header.");
        if (value.Authentication == GatewayAuthenticationKind.SoapBasicOpaqueSession &&
            (string.IsNullOrWhiteSpace(value.UsernameSecretReference) || string.IsNullOrWhiteSpace(value.PasswordSecretReference) ||
             string.IsNullOrWhiteSpace(value.ApiKeySecretReference) || !IsHeaderName(value.ApiKeyHeaderName)))
            throw new InvalidOperationException("Composed SOAP authentication requires server-side Basic/session resources and a safe custom header.");
    }

    private static bool IsIdentifier(string value) => value.Length is > 0 and <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    private static bool IsHeaderName(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~') &&
        value is not null && !ForbiddenAuthenticationHeaders.Contains(value) && !value.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase) && !value.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Executes a granted operation using only server-owned destination and credentials.</summary>
public sealed class RestrictedEgressService
{
    private readonly IGatewayRegistry registry;
    private readonly IGatewayOperationCatalog catalog;
    private readonly IGatewayClock clock;
    private readonly ConnectorExecutionStrategyRegistry executionStrategyRegistry;
    private readonly IAuthorizedConnectorCapabilityDispatcher? capabilityDispatcher;

    /// <summary>Creates the provider-neutral egress service with optional startup-fixed strategies.</summary>
    public RestrictedEgressService(
        IGatewayRegistry registry,
        IGatewayOperationCatalog catalog,
        ISecretValueProvider secrets,
        IClientCertificateProvider certificates,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance = null,
        IEnumerable<IConnectorExecutionStrategy>? executionStrategies = null)
        : this(registry, catalog, secrets, certificates, resolver, transport, clock, privateDestinationAllowance,
            executionStrategies, capabilityDispatcher: null)
    {
    }

    internal RestrictedEgressService(
        IGatewayRegistry registry,
        IGatewayOperationCatalog catalog,
        ISecretValueProvider secrets,
        IClientCertificateProvider certificates,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance,
        IEnumerable<IConnectorExecutionStrategy>? executionStrategies,
        IAuthorizedConnectorCapabilityDispatcher? capabilityDispatcher)
    {
        this.registry = registry ?? throw new ArgumentNullException(nameof(registry));
        this.catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        executionStrategyRegistry = new(PrependDefault(
            new DefaultHttpExecutionStrategy(secrets, certificates, resolver, transport, privateDestinationAllowance),
            executionStrategies));
        this.capabilityDispatcher = capabilityDispatcher;
    }

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
        PublishedConnectorAccessContext access = new(identity.InstallationId, identity.TenantId, identity.ApplicationId, operationId);
        AuthorizedPublishedOperation? published = catalog is IAuthorizedPublishedOperationCatalog authoritative
            ? await authoritative.GetRequiredAuthorizedAsync(connectorId, operationId, identity.EnvironmentId, access, cancellationToken).ConfigureAwait(false)
            : null;
        GatewayOperationDefinition operation = published?.Operation ?? await catalog.GetRequiredAsync(
            connectorId, operationId, identity.EnvironmentId, access, cancellationToken).ConfigureAwait(false);
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
        ConnectorExecutionStrategyKey strategyKey = ConnectorExecutionStrategyKeys.Resolve(operation);
        ConnectorExecutionStrategyRegistration registration = executionStrategyRegistry.Required(strategyKey, operation.Authentication);
        AuthorizedGatewayInvocation invocation = new(authenticated, connectorId, operationId);
        AuthorizedConnectorExecution execution = new(
            invocation,
            operation,
            strategyKey,
            body,
            capabilityDispatcher,
            published?.Authority,
            published?.ExtensionConfiguration);
        QualifiedGatewayExecutionResult result;
        try
        {
            using IDisposable capabilityScope = execution.EnterCapabilityScope();
            result = await registration.Strategy.ExecuteAsync(execution, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (AuthorizedConnectorCapabilityFailureException exception) when (execution.Owns(exception))
        {
            throw exception.Failure;
        }
        catch (CoreProviderExecutionException exception)
        {
            throw new ProviderAccessException(exception.Code, exception.Retryable);
        }
        catch (GatewayException) when (registration.PreservesCoreFailures) { throw; }
        catch (Exception) { throw new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502); }

        if (result is null || result.Body is null || result.StatusCode is < 100 or > 599 || string.IsNullOrWhiteSpace(result.ContentType) ||
            result.ContentType.Length > 512 || result.Body.LongLength > operation.MaximumResponseBytes)
            throw new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502);
        byte[] responseBody = result.Body.ToArray();
        await registry.AppendAuditAsync(new GatewayAuditEvent(Guid.NewGuid(), clock.UtcNow, identity.TenantId, "installation", identity.InstallationId.ToString("D"), "operation.invoke", "operation", connectorId + "/" + operationId, request.CorrelationId, "success", "BGW-OPERATION-OK", new Dictionary<string, string> { ["connectorVersion"] = operation.Version, ["statusCategory"] = (result.StatusCode / 100).ToString(System.Globalization.CultureInfo.InvariantCulture) + "xx", ["callerKind"] = identity.InstallationKind.ToString() }), cancellationToken).ConfigureAwait(false);
        return new GatewayInvokeResponse(request.CorrelationId, operation.Version, new GatewayPayload(result.ContentType, "base64", Convert.ToBase64String(responseBody)));
    }

    private static IEnumerable<IConnectorExecutionStrategy> PrependDefault(
        IConnectorExecutionStrategy defaultStrategy,
        IEnumerable<IConnectorExecutionStrategy>? configured)
    {
        yield return defaultStrategy;
        if (configured is null) yield break;
        foreach (IConnectorExecutionStrategy strategy in configured) yield return strategy;
    }

    private sealed class DefaultHttpExecutionStrategy(
        ISecretValueProvider secrets,
        IClientCertificateProvider certificates,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IPrivateDestinationAllowance? privateDestinationAllowance) : IConnectorExecutionStrategy, ICoreConnectorExecutionStrategy
    {
        private static readonly FrozenSet<GatewayAuthenticationKind> AuthenticationKinds = new[]
        {
            GatewayAuthenticationKind.None,
            GatewayAuthenticationKind.Basic,
            GatewayAuthenticationKind.ApiKey,
            GatewayAuthenticationKind.MutualTls,
            GatewayAuthenticationKind.ApiKeyAndMutualTls
        }.ToFrozenSet();

        public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKeys.DefaultHttp;

        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;

        public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
        {
            try
            {
                GatewayOperationDefinition operation = execution.Operation;
                IPAddress[] addresses = await resolver.ResolveAsync(operation.Endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false);
                if (addresses.Length == 0 || addresses.Any(address => IsForbiddenAddress(address) && privateDestinationAllowance?.IsAllowed(operation.Endpoint.DnsSafeHost, address) != true))
                    throw new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 403);

                int attempts = operation.MaximumRetries + 1;
                for (int attempt = 1; ; attempt++)
                {
                    using HttpRequestMessage outbound = new(operation.Method, operation.Endpoint);
                    outbound.Headers.TryAddWithoutValidation("X-Correlation-ID", execution.CorrelationId.ToString("D"));
                    if (operation.Method != HttpMethod.Get)
                        outbound.Content = new ByteArrayContent(execution.Payload.ToArray()) { Headers = { ContentType = MediaTypeHeaderValue.Parse(operation.RequestContentType) } };
                    X509Certificate2? clientCertificate = null;
                    try
                    {
                        clientCertificate = await ApplyAuthenticationAsync(outbound, operation, cancellationToken).ConfigureAwait(false);
                        ExternalResponse response = await transport.SendAsync(outbound, addresses, clientCertificate, TimeSpan.FromMilliseconds(operation.TimeoutMilliseconds), operation.MaximumResponseBytes, cancellationToken).ConfigureAwait(false);
                        return new(response.StatusCode, response.ContentType, response.Body);
                    }
                    catch (Exception exception) when (attempt < attempts && exception is HttpRequestException or TimeoutException)
                    {
                        // Retry only operations explicitly declared idempotent by server configuration.
                    }
                    finally { clientCertificate?.Dispose(); }
                }
            }
            catch (ProviderAccessException exception)
            {
                // Only the built-in Core strategy may preserve provider-neutral provider failures.
                // The outer strategy boundary still sanitizes the same exception from external modules.
                throw new CoreProviderExecutionException(exception.Code, exception.Retryable);
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
    }

    private sealed class CoreProviderExecutionException(string code, bool retryable) : Exception
    {
        internal string Code { get; } = code;
        internal bool Retryable { get; } = retryable;
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
