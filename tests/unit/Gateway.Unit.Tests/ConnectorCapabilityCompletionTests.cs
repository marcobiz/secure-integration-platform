using System.Text.Json;
using SecureIntegration.Gateway.Application;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class ConnectorCapabilityCompletionTests
{
    [Fact]
    public void Wave1_CT_Published_capability_profile_is_strict_bounded_and_dependency_complete()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument definition = JsonDocument.Parse(CapabilityDefinition());

        ValidatedConnectorDefinition validated = validator.ValidateRequired(definition.RootElement);
        OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(validated.CanonicalJson, "signed-submit");

        Assert.Equal(["mtls-certificate", "signing-certificate"], dependencies.CertificateBindingIds);
        Assert.Empty(dependencies.SecretBindingIds);
        Assert.Contains("\"authorizedCapabilities\"", validated.CanonicalJson, StringComparison.Ordinal);
        Assert.Contains("\"extensionConfiguration\"", validated.CanonicalJson, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("\"executionStrategy\":\"synthetic-signed-mtls\",", "")]
    [InlineData("\"kind\":\"mtls\",\"certificateBinding\":\"mtls-certificate\"", "\"kind\":\"none\"")]
    [InlineData("\"keyBinding\":\"signing-certificate\"", "\"keyBinding\":\"not-a-certificate\"")]
    public void Wave1_SEC_capability_profile_rejects_missing_strategy_wrong_auth_and_wrong_key_binding(string find, string replacement)
    {
        using JsonDocument definition = JsonDocument.Parse(CapabilityDefinition().Replace(find, replacement, StringComparison.Ordinal));
        ConnectorValidationResult result = new ConnectorDefinitionValidator().Validate(definition.RootElement);

        Assert.False(result.Valid);
    }

    [Fact]
    public void Wave1_CT_server_owned_adapter_inputs_participate_in_operation_dependencies()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument definition = JsonDocument.Parse(HandshakeDefinition());

        ValidatedConnectorDefinition validated = validator.ValidateRequired(definition.RootElement);
        OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(validated.CanonicalJson, "session-bootstrap");

        Assert.Equal(["organization"], dependencies.SecretBindingIds);
    }

    [Fact]
    public void Wave1_SEC_duplicate_or_non_opaque_server_owned_adapter_inputs_are_rejected()
    {
        string definition = HandshakeDefinition();
        string duplicate = definition.Replace(
            "{\"name\":\"organization-code\",\"secretBinding\":\"organization\"}",
            "{\"name\":\"organization-code\",\"secretBinding\":\"organization\"},{\"name\":\"organization-code\",\"secretBinding\":\"organization\"}",
            StringComparison.Ordinal);
        string wrongKind = definition.Replace("\"kind\":\"opaque\"", "\"kind\":\"password\"", StringComparison.Ordinal);

        using JsonDocument duplicateDocument = JsonDocument.Parse(duplicate);
        using JsonDocument wrongKindDocument = JsonDocument.Parse(wrongKind);
        ConnectorValidationResult duplicateResult = new ConnectorDefinitionValidator().Validate(duplicateDocument.RootElement);
        ConnectorValidationResult wrongKindResult = new ConnectorDefinitionValidator().Validate(wrongKindDocument.RootElement);

        Assert.Contains(duplicateResult.Issues, issue => issue.Code == "BGW-CONNECTOR-SERVER-INPUT-DUPLICATE");
        Assert.Contains(wrongKindResult.Issues, issue => issue.Code == "BGW-CONNECTOR-SERVER-INPUT-BINDING-INVALID");
    }

    private static string CapabilityDefinition() => """
        {
          "schemaVersion":"1.0","connectorId":"synthetic-capability","version":"1.0.0","displayName":"Synthetic capability",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"mtls-certificate","kind":"clientCertificate"},{"name":"signing-certificate","kind":"clientCertificate"},{"name":"not-a-certificate","kind":"opaque"}]},
          "operations":[{
            "operationId":"signed-submit","endpointBinding":"service","method":"POST","path":"/submit",
            "request":{"contentType":"application/json","maximumBytes":4096},"response":{"maximumBytes":4096},
            "authentication":{"kind":"mtls","certificateBinding":"mtls-certificate"},"executionStrategy":"synthetic-signed-mtls",
            "extensionConfiguration":{"claimName":"transaction-id","claimValue":"published-value","body":"published-body"},
            "authorizedCapabilities":{
              "signing":{"profileId":"synthetic-signing","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issuer":"synthetic-gateway","audience":"synthetic-upstream","subject":"installation","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"clockSkewSeconds":5,"certificateHeader":"chain","temporalClaims":"iat-nbf-exp","minimumRsaKeySize":2048},
              "restrictedTransport":{"profileId":"synthetic-transport","revision":1,"clientCertificateSpkiSha256":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","authorization":"signedTokenBearer","nearExpirySeconds":30}
            },
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }]
        }
        """;

    private static string HandshakeDefinition() => """
        {
          "schemaVersion":"1.0","connectorId":"synthetic-handshake","version":"1.0.0","displayName":"Synthetic handshake",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"organization","kind":"opaque"}]},
          "operations":[{
            "operationId":"session-bootstrap","endpointBinding":"service","method":"POST","path":"/session",
            "request":{"contentType":"text/xml","maximumBytes":4096},"response":{"maximumBytes":4096},"authentication":{"kind":"none"},
            "typedSessionHandshake":{"profileId":"synthetic-session","soapVersion":"1.1","action":"urn:synthetic:CreateSession","requestElement":{"localName":"CreateSessionRequest","namespaceUri":"urn:synthetic:typed-session"},"responseElement":{"localName":"CreateSessionResponse","namespaceUri":"urn:synthetic:typed-session"},"requestAdapter":{"id":"external-create-session-request","type":"external-compiled-request"},"responseAdapter":{"id":"external-create-session-response","type":"external-compiled-response"},"serverOwnedInputs":[{"name":"organization-code","secretBinding":"organization"}],"sessionLifetimeSeconds":3600},
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }]
        }
        """;
}
