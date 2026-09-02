using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>
/// Internal, opaque proof of the exact Published snapshot from which Core resolved and authorized
/// one operation. It is intentionally absent from the public Connector execution contract.
/// </summary>
internal sealed record AuthorizedPublishedExecutionStamp(
    string ConnectorId,
    string OperationId,
    Guid EnvironmentId,
    string ConnectorVersion,
    Guid VersionId,
    long PublicationRevision,
    string CanonicalChecksumSha256,
    Guid BindingId,
    long BindingRevision,
    string BindingChecksumSha256,
    string ResourceStampSha256,
    string OperationChecksumSha256,
    GatewayAuthenticationKind AuthenticationKind,
    ConnectorExecutionStrategyKey ExecutionStrategyKey)
{
    internal static AuthorizedPublishedExecutionStamp Capture(
        PublishedConnectorSnapshot snapshot,
        Guid environmentId,
        GatewayOperationDefinition operation,
        ConnectorExecutionStrategyKey executionStrategyKey)
    {
        JsonElement publishedOperation = RequiredOperation(snapshot, operation.OperationId);
        return new(
            operation.ConnectorId,
            operation.OperationId,
            environmentId,
            snapshot.Version.Version,
            snapshot.Version.Id,
            snapshot.Stamp.PublicationRevision,
            Convert.ToHexString(snapshot.Version.ChecksumSha256),
            snapshot.Bindings.Id,
            snapshot.Bindings.Revision,
            snapshot.Bindings.ChecksumSha256,
            snapshot.Stamp.ResourceStampSha256,
            Hash(publishedOperation.GetRawText()),
            operation.Authentication,
            executionStrategyKey);
    }

    internal bool Matches(PublishedConnectorSnapshot snapshot)
    {
        try
        {
            JsonElement operation = RequiredOperation(snapshot, OperationId);
            return snapshot.Version.State == ConnectorVersionState.Published && snapshot.Version.PublishedAt is not null &&
                snapshot.Bindings.State == ConnectorBindingState.Active && snapshot.Bindings.EnvironmentId == EnvironmentId &&
                string.Equals(snapshot.Version.ConnectorSlug, ConnectorId, StringComparison.Ordinal) &&
                string.Equals(snapshot.Version.Version, ConnectorVersion, StringComparison.Ordinal) &&
                snapshot.Version.Id == VersionId && snapshot.Stamp.VersionId == VersionId &&
                snapshot.Stamp.PublicationRevision == PublicationRevision &&
                string.Equals(Convert.ToHexString(snapshot.Version.ChecksumSha256), CanonicalChecksumSha256, StringComparison.Ordinal) &&
                snapshot.Bindings.Id == BindingId && snapshot.Bindings.ConnectorVersionId == VersionId &&
                snapshot.Bindings.Revision == BindingRevision && snapshot.Stamp.BindingRevision == BindingRevision &&
                string.Equals(snapshot.Bindings.ChecksumSha256, BindingChecksumSha256, StringComparison.Ordinal) &&
                string.Equals(snapshot.Stamp.BindingChecksumSha256, BindingChecksumSha256, StringComparison.Ordinal) &&
                string.Equals(snapshot.Stamp.ResourceStampSha256, ResourceStampSha256, StringComparison.Ordinal) &&
                string.Equals(Hash(operation.GetRawText()), OperationChecksumSha256, StringComparison.Ordinal) &&
                ParseAuthentication(operation) == AuthenticationKind &&
                ConnectorExecutionStrategyKeys.Resolve(operation) == ExecutionStrategyKey;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or KeyNotFoundException or
            ArgumentException or GatewayException)
        {
            return false;
        }
    }

    internal byte[] WorkflowContextConfigurationSha256()
    {
        using MemoryStream buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("connectorId", ConnectorId);
            writer.WriteString("environmentId", EnvironmentId);
            writer.WriteString("connectorVersion", ConnectorVersion);
            writer.WriteString("versionId", VersionId);
            writer.WriteNumber("publicationRevision", PublicationRevision);
            writer.WriteString("canonicalChecksumSha256", CanonicalChecksumSha256);
            writer.WriteString("bindingId", BindingId);
            writer.WriteNumber("bindingRevision", BindingRevision);
            writer.WriteString("bindingChecksumSha256", BindingChecksumSha256);
            writer.WriteString("resourceStampSha256", ResourceStampSha256);
            writer.WriteString("authenticationKind", AuthenticationKind.ToString());
            writer.WriteString("executionStrategyKey", ExecutionStrategyKey.Value);
            writer.WriteEndObject();
        }
        return SHA256.HashData(buffer.GetBuffer().AsSpan(0, checked((int)buffer.Length)));
    }

    private static JsonElement RequiredOperation(PublishedConnectorSnapshot snapshot, string operationId)
    {
        using JsonDocument document = JsonDocument.Parse(snapshot.Version.CanonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
        return document.RootElement.GetProperty("operations").EnumerateArray()
            .Single(value => string.Equals(value.GetProperty("operationId").GetString(), operationId, StringComparison.Ordinal))
            .Clone();
    }

    private static GatewayAuthenticationKind ParseAuthentication(JsonElement operation) =>
        operation.GetProperty("authentication").GetProperty("kind").GetString() switch
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
            _ => throw new InvalidOperationException()
        };

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

internal sealed record AuthorizedPublishedOperation(
    GatewayOperationDefinition Operation,
    AuthorizedPublishedExecutionStamp Authority,
    AuthorizedPublishedExtensionConfiguration ExtensionConfiguration);

internal interface IAuthorizedPublishedOperationCatalog
{
    Task<AuthorizedPublishedOperation> GetRequiredAuthorizedAsync(
        string connectorId,
        string operationId,
        Guid environmentId,
        PublishedConnectorAccessContext accessContext,
        CancellationToken cancellationToken);
}
