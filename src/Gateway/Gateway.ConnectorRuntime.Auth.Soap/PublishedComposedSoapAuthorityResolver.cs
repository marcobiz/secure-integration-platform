using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>
/// Resolves the closed Basic + SOAP metadata + opaque-session header composition from one
/// authenticated operation and its current Published Connector snapshot.
/// </summary>
public sealed class PublishedComposedSoapAuthorityResolver
{
    private readonly PublishedOpaqueSessionAuthorityResolver sessionAuthorities;
    private readonly TypedComposedSoapRequestAdapterRegistry requestAdapters;

    /// <summary>Creates the production resolver over the protected Connector configuration store.</summary>
    public PublishedComposedSoapAuthorityResolver(IConnectorConfigurationStore store, IGatewayClock clock)
        : this(store, clock, new TypedComposedSoapRequestAdapterRegistry([]))
    {
    }

    internal PublishedComposedSoapAuthorityResolver(
        IConnectorConfigurationStore store,
        IGatewayClock clock,
        TypedComposedSoapRequestAdapterRegistry requestAdapters)
    {
        sessionAuthorities = new(store ?? throw new ArgumentNullException(nameof(store)), clock ?? throw new ArgumentNullException(nameof(clock)));
        this.requestAdapters = requestAdapters ?? throw new ArgumentNullException(nameof(requestAdapters));
    }

    internal PublishedComposedSoapAuthorityResolver(
        Func<string, Guid, PublishedConnectorAccessContext, CancellationToken, Task<PublishedConnectorSnapshot?>> snapshotSource,
        IGatewayClock clock,
        TypedComposedSoapRequestAdapterRegistry? requestAdapters = null)
    {
        sessionAuthorities = new(snapshotSource ?? throw new ArgumentNullException(nameof(snapshotSource)), clock ?? throw new ArgumentNullException(nameof(clock)));
        this.requestAdapters = requestAdapters ?? new TypedComposedSoapRequestAdapterRegistry([]);
    }

    /// <summary>
    /// Resolves one logical composed policy. The invocation cannot be created by a connector and
    /// the request contains no endpoint, action, SOAP version, placement, binding or revision.
    /// </summary>
    public async Task<ComposedSoapResolvedExecutionContext> ResolveAsync(
        OpaqueSessionAuthorizedInvocation invocation,
        OpaqueSessionHttpAuthorityRequest request,
        CancellationToken cancellationToken) =>
        await ResolveCoreAsync(invocation, request, publishedAuthority: null, cancellationToken).ConfigureAwait(false);

    internal async Task<ComposedSoapResolvedExecutionContext> ResolveAuthorizedAsync(
        OpaqueSessionAuthorizedInvocation invocation,
        OpaqueSessionHttpAuthorityRequest request,
        AuthorizedPublishedExecutionStamp publishedAuthority,
        CancellationToken cancellationToken) =>
        await ResolveCoreAsync(invocation, request, publishedAuthority, cancellationToken).ConfigureAwait(false);

    private async Task<ComposedSoapResolvedExecutionContext> ResolveCoreAsync(
        OpaqueSessionAuthorizedInvocation invocation,
        OpaqueSessionHttpAuthorityRequest request,
        AuthorizedPublishedExecutionStamp? publishedAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        ArgumentNullException.ThrowIfNull(request);
        OpaqueSessionResolvedExecutionContext sessionContext;
        try
        {
            sessionContext = publishedAuthority is null
                ? await sessionAuthorities.ResolveAsync(invocation, request, OpaqueSessionAuthorityProfileKind.ComposedSoapBasic, cancellationToken).ConfigureAwait(false)
                : await sessionAuthorities.ResolveAuthorizedAsync(invocation, request, OpaqueSessionAuthorityProfileKind.ComposedSoapBasic, publishedAuthority, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (OpaqueSessionAuthException exception) { throw Map(exception); }

        ComposedSoapAuthorityState expected = Parse(sessionContext.State);

        async Task<ComposedSoapAuthorityState> Revalidate(CancellationToken token)
        {
            try
            {
                OpaqueSessionHttpAuthorityState currentSession = await sessionContext.Revalidate(token).ConfigureAwait(false);
                ComposedSoapAuthorityState current = Parse(currentSession);
                if (!string.Equals(expected.SecurityFingerprint, current.SecurityFingerprint, StringComparison.Ordinal))
                    throw new SoapAuthException("SOAP-AUTHORITY-STALE");
                return current;
            }
            catch (OperationCanceledException) { throw; }
            catch (OpaqueSessionAuthException exception) { throw Map(exception); }
        }

        return new(expected, Revalidate);
    }

    private ComposedSoapAuthorityState Parse(OpaqueSessionHttpAuthorityState sessionAuthority)
    {
        try
        {
            PublishedConnectorSnapshot snapshot = sessionAuthority.Snapshot;
            OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(snapshot.Version.CanonicalJson, sessionAuthority.OperationId);
            using JsonDocument document = JsonDocument.Parse(snapshot.Version.CanonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
            JsonElement operation = document.RootElement.GetProperty("operations").EnumerateArray()
                .Single(value => string.Equals(value.GetProperty("operationId").GetString(), sessionAuthority.OperationId, StringComparison.Ordinal));
            if (!string.Equals(operation.GetProperty("method").GetString(), "POST", StringComparison.Ordinal) || sessionAuthority.Method != HttpMethod.Post)
                throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");

            JsonElement authentication = operation.GetProperty("authentication");
            if (!string.Equals(authentication.GetProperty("kind").GetString(), "soapBasicOpaqueSession", StringComparison.Ordinal))
                throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");
            string usernameBinding = authentication.GetProperty("usernameBinding").GetString()!;
            string passwordBinding = authentication.GetProperty("passwordBinding").GetString()!;
            string sessionBinding = authentication.GetProperty("secretBinding").GetString()!;
            List<string> expectedBindings = [usernameBinding, passwordBinding, sessionBinding];

            (ProviderResourceBinding UsernameResource, string UsernameReference) = BasicResource(snapshot, usernameBinding, sessionAuthority);
            (ProviderResourceBinding PasswordResource, string PasswordReference) = BasicResource(snapshot, passwordBinding, sessionAuthority);
            _ = BasicResource(snapshot, sessionBinding, sessionAuthority);

            TypedComposedSoapRequestAuthority? typedRequest = null;
            if (operation.TryGetProperty("typedComposedSoapRequest", out JsonElement typed))
            {
                JsonElement adapterElement = typed.GetProperty("requestAdapter");
                string adapterId = adapterElement.GetProperty("id").GetString()!;
                string adapterType = adapterElement.GetProperty("type").GetString()!;
                RegisteredTypedComposedSoapRequestAdapter registration = requestAdapters.Required(adapterId, adapterType);
                JsonElement requestElement = typed.GetProperty("requestElement");
                SoapElementRule requestQName = new(
                    requestElement.GetProperty("localName").GetString()!,
                    requestElement.GetProperty("namespaceUri").GetString()!);
                ServerOwnedBindingInputReference[] inputs = ResolveTypedInputs(
                    document.RootElement,
                    typed,
                    registration.RequiredServerOwnedInputs,
                    snapshot,
                    sessionAuthority);
                expectedBindings.AddRange(inputs.Select(value => value.LogicalBindingId));
                string typedFingerprintInput = string.Join('\n', adapterId, adapterType,
                    requestQName.NamespaceUri, requestQName.LocalName, sessionAuthority.MaximumRequestBytes,
                    string.Join('|', inputs.Select(value => string.Join(':', value.Name, value.LogicalBindingId, value.ProviderReference,
                        snapshot.Bindings.SecretResources[value.LogicalBindingId].ProviderId,
                        snapshot.Bindings.SecretResources[value.LogicalBindingId].ResourceId,
                        snapshot.Bindings.SecretResources[value.LogicalBindingId].Version ?? string.Empty,
                        snapshot.Bindings.SecretResources[value.LogicalBindingId].CatalogRevision,
                        snapshot.Bindings.SecretResources[value.LogicalBindingId].CatalogChecksumSha256))));
                string typedFingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(typedFingerprintInput)));
                typedRequest = new(registration.Adapter, requestQName, inputs, sessionAuthority.MaximumRequestBytes, typedFingerprint);
            }

            if (expectedBindings.Distinct(StringComparer.Ordinal).Count() != expectedBindings.Count ||
                dependencies.SecretBindingIds.Count != expectedBindings.Count ||
                !dependencies.SecretBindingIds.Order(StringComparer.Ordinal).SequenceEqual(expectedBindings.Order(StringComparer.Ordinal), StringComparer.Ordinal))
                throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");

            JsonElement soap = authentication.GetProperty("soapHttp");
            SoapEnvelopeVersion version = soap.GetProperty("version").GetString() switch
            {
                "1.1" => SoapEnvelopeVersion.Soap11,
                "1.2" => SoapEnvelopeVersion.Soap12,
                _ => throw new SoapAuthException("SOAP-HTTP-METADATA-INVALID")
            };
            SoapHttpRequestMetadata metadata = new(version, soap.GetProperty("action").GetString()!);
            string configuredContentType = operation.GetProperty("request").GetProperty("contentType").GetString()!;
            if (!string.Equals(configuredContentType, metadata.BaseContentType, StringComparison.OrdinalIgnoreCase))
                throw new SoapAuthException("SOAP-HTTP-METADATA-INVALID");

            string fingerprintInput = string.Join('\n', sessionAuthority.SecurityFingerprint, usernameBinding, passwordBinding, sessionBinding,
                UsernameResource.ProviderId, UsernameResource.ResourceId, UsernameResource.Version ?? string.Empty, UsernameResource.CatalogRevision, UsernameResource.CatalogChecksumSha256,
                PasswordResource.ProviderId, PasswordResource.ResourceId, PasswordResource.Version ?? string.Empty, PasswordResource.CatalogRevision, PasswordResource.CatalogChecksumSha256,
                UsernameReference, PasswordReference, version, metadata.Action, configuredContentType,
                typedRequest?.SecurityFingerprint ?? string.Empty);
            string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintInput)));
            return new(sessionAuthority, new ResolvedBasicCredentialBinding(UsernameReference, PasswordReference), metadata, typedRequest, fingerprint);
        }
        catch (SoapAuthException) { throw; }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException or FormatException or OverflowException)
        {
            throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");
        }
    }

    private static (ProviderResourceBinding Resource, string ProviderReference) BasicResource(
        PublishedConnectorSnapshot snapshot,
        string logicalBinding,
        OpaqueSessionHttpAuthorityState authority)
    {
        if (!snapshot.Bindings.SecretResources.TryGetValue(logicalBinding, out ProviderResourceBinding? resource) ||
            !snapshot.SecretProviderReferences.TryGetValue(logicalBinding, out string? providerReference) || string.IsNullOrWhiteSpace(providerReference) ||
            resource.ResourceType != ProviderResourceType.Secret || resource.EnvironmentId != snapshot.Bindings.EnvironmentId || resource.CatalogRevision < 1 ||
            !string.Equals(resource.ConnectorScope, authority.ConnectorId, StringComparison.Ordinal) && !string.Equals(resource.ConnectorScope, "*", StringComparison.Ordinal) ||
            !string.Equals(resource.OperationScope, authority.OperationId, StringComparison.Ordinal) && !string.Equals(resource.OperationScope, "*", StringComparison.Ordinal))
            throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");
        return (resource, providerReference);
    }

    private static ServerOwnedBindingInputReference[] ResolveTypedInputs(
        JsonElement definition,
        JsonElement owner,
        IReadOnlySet<string> requiredNames,
        PublishedConnectorSnapshot snapshot,
        OpaqueSessionHttpAuthorityState authority)
    {
        if (!owner.TryGetProperty("serverOwnedInputs", out JsonElement configured))
        {
            if (requiredNames.Count != 0) throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");
            return [];
        }
        if (configured.ValueKind != JsonValueKind.Array || configured.GetArrayLength() > AuthorizedConnectorBindingInputs.MaximumInputs)
            throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");

        Dictionary<string, string> logicalKinds = definition.GetProperty("bindings").GetProperty("secrets").EnumerateArray()
            .ToDictionary(value => value.GetProperty("name").GetString()!, value => value.GetProperty("kind").GetString()!, StringComparer.Ordinal);
        Dictionary<string, ServerOwnedBindingInputReference> resolved = new(StringComparer.Ordinal);
        foreach (JsonElement input in configured.EnumerateArray())
        {
            string name = input.GetProperty("name").GetString()!;
            string logicalBinding = input.GetProperty("secretBinding").GetString()!;
            if (!requiredNames.Contains(name) || resolved.ContainsKey(name) ||
                !logicalKinds.TryGetValue(logicalBinding, out string? kind) || !string.Equals(kind, "opaque", StringComparison.Ordinal))
                throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");
            (_, string providerReference) = BasicResource(snapshot, logicalBinding, authority);
            resolved.Add(name, new(name, logicalBinding, providerReference));
        }
        if (resolved.Count != requiredNames.Count || requiredNames.Any(name => !resolved.ContainsKey(name)))
            throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");
        return resolved.Values.OrderBy(value => value.Name, StringComparer.Ordinal).ToArray();
    }

    private static SoapAuthException Map(OpaqueSessionAuthException exception) => exception.Code switch
    {
        "SESSION-HTTP-AUTHORITY-STALE" => new("SOAP-AUTHORITY-STALE"),
        "SESSION-HTTP-HEADER-FORBIDDEN" => new("SOAP-HTTP-POLICY-VIOLATION"),
        _ => new("SOAP-AUTHORITY-REJECTED")
    };
}
