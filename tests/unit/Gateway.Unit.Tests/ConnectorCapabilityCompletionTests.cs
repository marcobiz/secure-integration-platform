using System.Text.Json;
using System.Text.Json.Nodes;
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
        Assert.Equal("D0FF51B186AB8DB600DE14492ACE326F13A6BF4C13218215B95A2401D2401D7A", validated.ChecksumSha256);
        Assert.DoesNotContain("signingSlots", validated.CanonicalJson, StringComparison.Ordinal);
        Assert.Contains("\"authorizedCapabilities\"", validated.CanonicalJson, StringComparison.Ordinal);
        Assert.Contains("\"extensionConfiguration\"", validated.CanonicalJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_authorized_signing_slots_are_bounded_checksum_bound_and_dependency_complete()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument definition = JsonDocument.Parse(SigningSlotsDefinition());

        ValidatedConnectorDefinition validated = validator.ValidateRequired(definition.RootElement);
        OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(validated.CanonicalJson, "signed-submit");
        JsonObject changed = SigningSlotsNode();
        SigningSlots(changed)[1]!["signing"]!["issuer"] = "changed-secondary-issuer";
        using JsonDocument changedDocument = JsonDocument.Parse(changed.ToJsonString());
        ValidatedConnectorDefinition changedValidated = validator.ValidateRequired(changedDocument.RootElement);

        Assert.Equal(4, AuthorizedSigningSlots.MaximumSlots);
        Assert.Equal(["mtls-certificate", "signing-certificate"], dependencies.CertificateBindingIds);
        Assert.Contains("\"slot\":\"primary\"", validated.CanonicalJson, StringComparison.Ordinal);
        Assert.Contains("\"slot\":\"secondary\"", validated.CanonicalJson, StringComparison.Ordinal);
        Assert.NotEqual(validated.ChecksumSha256, changedValidated.ChecksumSha256);
    }

    [Fact]
    public void Wave1_SEC_authorized_signing_slot_schema_and_projection_matrix_fails_closed()
    {
        AssertInvalid(value => SigningSlots(value).Clear());
        AssertInvalid(value =>
        {
            JsonArray slots = SigningSlots(value);
            while (slots.Count < 5) slots.Add(slots[0]!.DeepClone());
        });
        AssertInvalid(value => SigningSlots(value)[1]!["slot"] = "primary", "BGW-CONNECTOR-SIGNING-SLOT-DUPLICATE");
        AssertInvalid(value => SigningSlots(value)[1]!["slot"] = "UpperCase");
        AssertInvalid(value => SigningSlots(value)[1]!["signing"]!["profileId"] = "synthetic-primary-signing", "BGW-CONNECTOR-SIGNING-PROFILE-DUPLICATE");
        AssertInvalid(value => SigningSlots(value)[1]!["projection"] = new JsonObject { ["kind"] = "authorizationBearer" },
            "BGW-CONNECTOR-SIGNING-AUTHORIZATION-DUPLICATE");
        AssertInvalid(value =>
        {
            SigningSlots(value)[0]!["projection"] = new JsonObject { ["kind"] = "signedTokenHeader", ["headerName"] = "X-Synthetic-Signature" };
            SigningSlots(value)[1]!["projection"] = new JsonObject { ["kind"] = "signedTokenHeader", ["headerName"] = "x-synthetic-signature" };
        }, "BGW-CONNECTOR-SIGNING-HEADER-DUPLICATE");
        AssertInvalid(value => SigningSlots(value)[1]!["projection"]!["headerName"] = "Host",
            "BGW-CONNECTOR-SIGNING-HEADER-FORBIDDEN");
        AssertInvalid(value => Capabilities(value)["signing"] = SigningSlots(value)[0]!["signing"]!.DeepClone());
        AssertInvalid(value => SigningSlots(value)[0]!["signing"]!.AsObject().Remove("keyBinding"));
        AssertInvalid(value => SigningSlots(value)[0]!["signing"]!["keyBinding"] = "not-a-certificate",
            "BGW-CONNECTOR-CAPABILITY-SIGNING-BINDING-INVALID");
        AssertInvalid(value => SigningSlots(value)[0]!["signing"]!["algorithm"] = "RS512");
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

    private static JsonObject SigningSlotsNode() => JsonNode.Parse(SigningSlotsDefinition())!.AsObject();

    private static JsonObject Capabilities(JsonObject definition) =>
        definition["operations"]![0]!["authorizedCapabilities"]!.AsObject();

    private static JsonArray SigningSlots(JsonObject definition) => Capabilities(definition)["signingSlots"]!.AsArray();

    private static void AssertInvalid(Action<JsonObject> mutate, string? expectedIssue = null)
    {
        JsonObject definition = SigningSlotsNode();
        mutate(definition);
        using JsonDocument document = JsonDocument.Parse(definition.ToJsonString());
        ConnectorValidationResult result = new ConnectorDefinitionValidator().Validate(document.RootElement);
        Assert.False(result.Valid);
        if (expectedIssue is not null) Assert.Contains(result.Issues, issue => issue.Code == expectedIssue);
    }

    private static string SigningSlotsDefinition() => """
        {
          "schemaVersion":"1.0","connectorId":"synthetic-signing-slots","version":"1.0.0","displayName":"Synthetic signing slots",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"mtls-certificate","kind":"clientCertificate"},{"name":"signing-certificate","kind":"clientCertificate"},{"name":"not-a-certificate","kind":"opaque"}]},
          "operations":[{
            "operationId":"signed-submit","endpointBinding":"service","method":"POST","path":"/submit",
            "request":{"contentType":"application/json","maximumBytes":4096},"response":{"maximumBytes":4096},
            "authentication":{"kind":"mtls","certificateBinding":"mtls-certificate"},"executionStrategy":"synthetic-dual-slot",
            "authorizedCapabilities":{
              "signingSlots":[
                {
                  "slot":"primary","required":true,
                  "signing":{"profileId":"synthetic-primary-signing","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issuer":"synthetic-primary-issuer","audience":"synthetic-upstream","subject":"installation","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"clockSkewSeconds":5,"certificateHeader":"chain","temporalClaims":"iat-nbf-exp","minimumRsaKeySize":2048},
                  "projection":{"kind":"authorizationBearer"}
                },
                {
                  "slot":"secondary","required":true,
                  "signing":{"profileId":"synthetic-secondary-signing","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issuer":"synthetic-secondary-issuer","audience":"synthetic-upstream","subject":"installation","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"clockSkewSeconds":5,"certificateHeader":"chain","temporalClaims":"iat-nbf-exp","minimumRsaKeySize":2048},
                  "projection":{"kind":"signedTokenHeader","headerName":"X-Synthetic-Signature"}
                }
              ],
              "restrictedTransport":{"profileId":"synthetic-transport","revision":1,"clientCertificateSpkiSha256":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","nearExpirySeconds":30}
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
