using System.Reflection;
using System.Text.Json;
using System.Xml;
using SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.Tests;

public sealed class SistemaTsPublicContractTests
{
    [Fact]
    public void HC_W1_SISTEMATS_CT_module_and_adapter_metadata_are_exact_and_constructor_closed()
    {
        SistemaTsExecutionStrategy strategy = new();
        Assert.Equal("healthcare-sistema-ts-eprescription", strategy.Key.Value);
        Assert.Equal([GatewayAuthenticationKind.Basic, GatewayAuthenticationKind.SoapBasicOpaqueSession],
            strategy.SupportedAuthenticationKinds.OrderBy(value => value));
        Assert.Equal("healthcare-sistema-ts", new SistemaTsExecutionModule().Id.Value);
        Assert.All(typeof(SistemaTsExecutionModule).GetConstructors(), constructor => Assert.Empty(constructor.GetParameters()));

        SistemaTsCreateSessionRequestAdapter request = new();
        SistemaTsCheckTokenAdapter validator = new();
        Assert.Equal("sistema-ts-create-session-request", request.AdapterId);
        Assert.Equal("compiled-sistema-ts-create-v0.1", request.AdapterType);
        Assert.Equal(["codice-asl", "codice-fiscale", "codice-regione", "codice-ssa", "identificativo-tipo", "identificativo-valore", "user-id"],
            request.RequiredServerOwnedInputs.Order(StringComparer.Ordinal));
        Assert.Equal(["codice-fiscale", "identificativo-tipo", "identificativo-valore", "user-id"],
            validator.RequiredServerOwnedInputs.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void HC_W1_SISTEMATS_CT_Published_definition_is_canonical_five_operation_no_retry_authority()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Samples", "sistema-ts.connector.json")));
        ValidatedConnectorDefinition validated = new ConnectorDefinitionValidator().ValidateRequired(document.RootElement);
        using JsonDocument canonical = JsonDocument.Parse(validated.CanonicalJson);
        JsonElement[] operations = canonical.RootElement.GetProperty("operations").EnumerateArray().ToArray();
        Assert.Equal(5, operations.Length);
        Assert.All(operations, operation =>
        {
            Assert.Equal("healthcare-sistema-ts-eprescription", operation.GetProperty("executionStrategy").GetString());
            Assert.Equal(0, operation.GetProperty("maximumRetries").GetInt32());
            Assert.Empty(operation.GetProperty("allowedClientHeaders").EnumerateArray());
        });
        JsonElement business = operations.Single(operation => operation.GetProperty("operationId").GetString() == "visualizza-erogato");
        Assert.Equal("Authorization2F", business.GetProperty("authentication").GetProperty("headerName").GetString());
        Assert.Equal("Bearer", business.GetProperty("authentication").GetProperty("fixedScheme").GetString());
    }

    [Fact]
    public void HC_W1_SISTEMATS_UT_nested_create_response_is_external_admission_only_and_duplicate_is_denied()
    {
        object accepted = Parse("ReadCreateResponse", """
            <aut:CreateAuthRes xmlns:aut="http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it" xmlns:dat="http://datatype.xsd.wsdl.auth.a2f.sts.sanita.finanze.it">
              <aut:codEsito>0</aut:codEsito><aut:comunicazioni><dat:comunicazione><dat:codice>AP02</dat:codice><dat:messaggio>handoff</dat:messaggio></dat:comunicazione></aut:comunicazioni>
            </aut:CreateAuthRes>
            """);
        Assert.True((bool)accepted.GetType().GetProperty("Success")!.GetValue(accepted)!);
        AssertMalformed("ReadCreateResponse", """
            <aut:CreateAuthRes xmlns:aut="http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it"><aut:codEsito>0</aut:codEsito><aut:codEsito>0</aut:codEsito></aut:CreateAuthRes>
            """);
    }

    [Fact]
    public void HC_W1_SISTEMATS_UT_checkToken_exact_nested_expiry_and_rejection()
    {
        object accepted = Parse("ReadCheckTokenResponse", """
            <aut:CheckTokenRes xmlns:aut="http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it" xmlns:dat="http://datatype.xsd.wsdl.auth.a2f.sts.sanita.finanze.it">
              <aut:codEsito>0</aut:codEsito><aut:infoToken><dat:stato>0</dat:stato><dat:descrizione>valid</dat:descrizione><dat:dataInizioValidita>2026-08-11T08:00:00Z</dat:dataInizioValidita><dat:dataFineValidita>2026-08-11T08:10:00Z</dat:dataFineValidita></aut:infoToken>
            </aut:CheckTokenRes>
            """);
        Assert.True((bool)accepted.GetType().GetProperty("Valid")!.GetValue(accepted)!);
        object rejected = Parse("ReadCheckTokenResponse", """
            <aut:CheckTokenRes xmlns:aut="http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it" xmlns:dat="http://datatype.xsd.wsdl.auth.a2f.sts.sanita.finanze.it">
              <aut:codEsito>1</aut:codEsito><aut:errori><dat:errore><dat:tipoErrore>E</dat:tipoErrore><dat:codEsito>401</dat:codEsito><dat:descrEsito>rejected</dat:descrEsito></dat:errore></aut:errori>
            </aut:CheckTokenRes>
            """);
        Assert.False((bool)rejected.GetType().GetProperty("Valid")!.GetValue(rejected)!);
    }

    private static object Parse(string methodName, string xml)
    {
        Type parser = typeof(SistemaTsExecutionModule).Assembly.GetType(
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.SistemaTsSessionXml", throwOnError: true)!;
        MethodInfo method = parser.GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic)!;
        using StringReader text = new(xml);
        using XmlReader reader = XmlReader.Create(text, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        return method.Invoke(null, [reader])!;
    }

    private static void AssertMalformed(string methodName, string xml)
    {
        TargetInvocationException exception = Assert.Throws<TargetInvocationException>(() => Parse(methodName, xml));
        Assert.IsType<XmlException>(exception.InnerException);
    }
}
