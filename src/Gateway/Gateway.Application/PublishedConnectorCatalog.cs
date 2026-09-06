using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>Published-only cache that validates a lightweight store stamp on every invocation.</summary>
public sealed class PublishedConnectorCatalog(
    IConnectorConfigurationStore store,
    ConnectorDefinitionValidator validator,
    IGatewayClock clock,
    TimeSpan ttl) : IGatewayOperationCatalog, IAuthorizedPublishedOperationCatalog
{
    private readonly ConcurrentDictionary<string, CacheEntry> cache = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<GatewayOperationDefinition> GetRequiredAsync(string connectorId, string operationId, Guid environmentId, CancellationToken cancellationToken) =>
        GetRequiredOperationAsync(connectorId, operationId, environmentId, null, cancellationToken);

    /// <inheritdoc />
    public Task<GatewayOperationDefinition> GetRequiredAsync(string connectorId, string operationId, Guid environmentId, PublishedConnectorAccessContext accessContext, CancellationToken cancellationToken) =>
        GetRequiredOperationAsync(connectorId, operationId, environmentId, accessContext, cancellationToken);

    async Task<AuthorizedPublishedOperation> IAuthorizedPublishedOperationCatalog.GetRequiredAuthorizedAsync(
        string connectorId,
        string operationId,
        Guid environmentId,
        PublishedConnectorAccessContext accessContext,
        CancellationToken cancellationToken) =>
        await GetRequiredCoreAsync(connectorId, operationId, environmentId, accessContext, cancellationToken).ConfigureAwait(false);

    private async Task<GatewayOperationDefinition> GetRequiredOperationAsync(
        string connectorId,
        string operationId,
        Guid environmentId,
        PublishedConnectorAccessContext? accessContext,
        CancellationToken cancellationToken) =>
        (await GetRequiredCoreAsync(connectorId, operationId, environmentId, accessContext, cancellationToken).ConfigureAwait(false)).Operation;

    private async Task<AuthorizedPublishedOperation> GetRequiredCoreAsync(string connectorId, string operationId, Guid environmentId, PublishedConnectorAccessContext? accessContext, CancellationToken cancellationToken)
    {
        if (accessContext is not null && !string.Equals(accessContext.OperationId, operationId, StringComparison.Ordinal))
            throw new GatewayException("BGW-AUTHZ-OPERATION-DENIED", 403);
        string key = connectorId + "\n" + environmentId.ToString("D") + "\n" + operationId + "\n" + (accessContext?.InstallationId.ToString("D") ?? "admin");
        PublishedConnectorStamp? stamp;
        try { stamp = await store.GetPublishedStampAsync(connectorId, environmentId, accessContext, cancellationToken).ConfigureAwait(false); }
        catch (GatewayException) { throw; }
        catch (Exception) { throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-UNAVAILABLE", 503, true); }
        if (stamp is null) { cache.TryRemove(key, out _); throw new GatewayException("BGW-CONNECTOR-NOT-PUBLISHED", 404); }
        if (!cache.TryGetValue(key, out CacheEntry? entry) || entry.ExpiresAt <= clock.UtcNow || entry.Stamp != stamp)
        {
            PublishedConnectorSnapshot snapshot;
            try { snapshot = await store.GetPublishedSnapshotAsync(connectorId, environmentId, accessContext, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-BINDING-MISSING", 503); }
            catch (GatewayException) { throw; }
            catch (Exception) { throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-UNAVAILABLE", 503, true); }
            if (snapshot.Stamp != stamp || snapshot.Version.State != ConnectorVersionState.Published) throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-STALE", 503, true);
            entry = Build(snapshot, operationId);
            cache[key] = entry;
        }
        if (!entry.Operations.TryGetValue(operationId, out AuthorizedPublishedOperation? operation)) throw new GatewayException("BGW-OPERATION-NOT-FOUND", 404);
        return operation;
    }

    /// <inheritdoc />
    public void Invalidate(string connectorId)
    {
        foreach (string key in cache.Keys.Where(value => value.StartsWith(connectorId + "\n", StringComparison.Ordinal)).ToArray()) cache.TryRemove(key, out _);
    }

    private CacheEntry Build(PublishedConnectorSnapshot snapshot, string requiredOperationId)
    {
        ValidatedConnectorDefinition parsed = validator.ParseStored(snapshot.Version.CanonicalJson, snapshot.Version.ChecksumSha256);
        using JsonDocument document = JsonDocument.Parse(parsed.CanonicalJson);
        Dictionary<string, AuthorizedPublishedOperation> operations = new(StringComparer.Ordinal);
        foreach (JsonElement operation in document.RootElement.GetProperty("operations").EnumerateArray())
        {
            string operationId = operation.GetProperty("operationId").GetString()!;
            if (!string.Equals(operationId, requiredOperationId, StringComparison.Ordinal)) continue;
            string endpointName = operation.GetProperty("endpointBinding").GetString()!;
            if (!snapshot.Bindings.Endpoints.TryGetValue(endpointName, out Uri? baseUri)) throw new GatewayException("BGW-CONNECTOR-ENDPOINT-BINDING-MISSING", 503);
            Uri endpoint = operation.TryGetProperty("pathTemplate", out JsonElement pathTemplate)
                ? ValidateTemplateBase(baseUri, pathTemplate.GetString()!)
                : PublishedEndpointUri.Compose(baseUri, operation.GetProperty("path").GetString()!, PublishedEndpointUri.AppendToBasePath(operation));
            JsonElement auth = operation.GetProperty("authentication");
            GatewayAuthenticationKind authKind = ParseAuthentication(auth.GetProperty("kind").GetString()!);
            string? Resolve(string property) => auth.TryGetProperty(property, out JsonElement logical) && (property == "certificateBinding" ? snapshot.CertificateProviderReferences : snapshot.SecretProviderReferences).TryGetValue(logical.GetString()!, out string? reference)
                ? reference
                : auth.TryGetProperty(property, out _) ? throw new GatewayException("BGW-CONNECTOR-SECRET-BINDING-MISSING", 503) : null;
            JsonElement request = operation.GetProperty("request");
            JsonElement response = operation.GetProperty("response");
            GatewayOperationDefinition definition = new(parsed.ConnectorId, operationId, parsed.Version, endpoint, new HttpMethod(operation.GetProperty("method").GetString()!), request.GetProperty("contentType").GetString()!, authKind,
                Resolve("usernameBinding"), Resolve("passwordBinding"), Resolve("secretBinding"), auth.TryGetProperty("headerName", out JsonElement header) ? header.GetString() : null, Resolve("certificateBinding"),
                operation.GetProperty("timeoutMs").GetInt32(), request.GetProperty("maximumBytes").GetInt64(), response.GetProperty("maximumBytes").GetInt64(),
                operation.TryGetProperty("idempotent", out JsonElement idempotent) && idempotent.GetBoolean(), operation.TryGetProperty("maximumRetries", out JsonElement retries) ? retries.GetInt32() : 0,
                auth.TryGetProperty("policyId", out JsonElement policyId) ? policyId.GetString() : null,
                auth.TryGetProperty("sessionProfileId", out JsonElement sessionProfileId) ? sessionProfileId.GetString() : null,
                operation.TryGetProperty("executionStrategy", out JsonElement executionStrategy)
                    ? ConnectorExecutionStrategyKey.Parse(executionStrategy.GetString()!)
                    : null);
            _ = new GatewayOperationCatalog([definition]);
            ConnectorExecutionStrategyKey strategyKey = ConnectorExecutionStrategyKeys.Resolve(definition);
            byte[] extensionConfiguration = operation.TryGetProperty("extensionConfiguration", out JsonElement extension)
                ? Encoding.UTF8.GetBytes(extension.GetRawText())
                : "{}"u8.ToArray();
            operations.Add(operationId, new(
                definition,
                AuthorizedPublishedExecutionStamp.Capture(snapshot, snapshot.Bindings.EnvironmentId, definition, strategyKey),
                new AuthorizedPublishedExtensionConfiguration(extensionConfiguration)));
        }
        return new(snapshot.Stamp, clock.UtcNow.Add(ttl), operations);
    }

    private static GatewayAuthenticationKind ParseAuthentication(string kind) => kind switch
    {
        "none" => GatewayAuthenticationKind.None,
        "basic" => GatewayAuthenticationKind.Basic,
        "apiKey" => GatewayAuthenticationKind.ApiKey,
        "mtls" => GatewayAuthenticationKind.MutualTls,
        "apiKeyAndMtls" => GatewayAuthenticationKind.ApiKeyAndMutualTls,
        "oauthAuthorizationCode" => GatewayAuthenticationKind.OAuthAuthorizationCode,
        "oauthClientCredentials" => GatewayAuthenticationKind.OAuthClientCredentials,
        "opaqueSessionHttp" => GatewayAuthenticationKind.OpaqueSessionHttp,
        "soapBasicOpaqueSession" => GatewayAuthenticationKind.SoapBasicOpaqueSession,
        _ => throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503)
    };

    private static Uri ValidateTemplateBase(Uri baseUri, string pathTemplate)
    {
        _ = PublishedPathTemplate.Validate(pathTemplate, nameof(pathTemplate));
        if (!baseUri.IsAbsoluteUri || !string.IsNullOrEmpty(baseUri.UserInfo) ||
            !string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
            throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503);
        return baseUri;
    }

    private sealed record CacheEntry(PublishedConnectorStamp Stamp, DateTimeOffset ExpiresAt, IReadOnlyDictionary<string, AuthorizedPublishedOperation> Operations);
}
