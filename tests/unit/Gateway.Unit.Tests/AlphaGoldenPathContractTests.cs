using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecureIntegration.Gateway.Application;
using Sample = SecureIntegration.Samples.DirectGatewayClient;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed partial class AlphaGoldenPathContractTests
{
    private static readonly string Root = FindRepositoryRoot();
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    [Fact]
    public void AlphaGoldenPath_Direct_sample_request_matches_public_InvokeRequest_schema()
    {
        string[] expected = ["correlationId", "extensions", "idempotencyKey", "metadata", "operatorContext", "payload", "protocolVersion"];
        Assert.Equal(expected, JsonPropertyNames(typeof(GatewayInvokeRequest)));
        Assert.Equal(expected, JsonPropertyNames(typeof(Sample.InvokeRequest)));
        AssertRequestTypesMatch();

        OpenApiSchema request = ReadSchema("InvokeRequest");
        Assert.True(request.AdditionalPropertiesFalse);
        Assert.Equal(expected, request.Properties.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(["correlationId", "payload", "protocolVersion"], request.Required.Order(StringComparer.Ordinal));
        Assert.Equal("InvokePayload", request.Properties["payload"].Reference);
        Assert.Equal("1.0", request.Properties["protocolVersion"].Constant);

        OpenApiSchema payload = ReadSchema("InvokePayload");
        Assert.True(payload.AdditionalPropertiesFalse);
        Assert.Equal(["contentType", "data", "encoding"], payload.Properties.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(["contentType", "data", "encoding"], payload.Required.Order(StringComparer.Ordinal));
        Assert.Equal(["base64", "utf8"], payload.Properties["encoding"].EnumValues.Order(StringComparer.Ordinal));

        string[] forbidden = ["endpoint", "url", "provider", "secret", "certificate", "transport", "artifact", "checksum", "tenant", "publishedProfile"];
        Assert.DoesNotContain(request.Properties.Keys, property => forbidden.Any(value => property.Contains(value, StringComparison.OrdinalIgnoreCase)));

        Sample.InvokeRequest sample = new(
            "1.0",
            new("application/json", "base64", Convert.ToBase64String("{\"message\":\"direct-gateway-sample\"}"u8)),
            Guid.Parse("11111111-1111-1111-1111-111111111111"));
        JsonElement serialized = JsonSerializer.SerializeToElement(sample, WebJson);
        Assert.Equal(["correlationId", "payload", "protocolVersion"], serialized.EnumerateObject().Select(value => value.Name).Order(StringComparer.Ordinal));
        Assert.Equal("1.0", serialized.GetProperty("protocolVersion").GetString());
        Assert.Equal("base64", serialized.GetProperty("payload").GetProperty("encoding").GetString());
    }

    [Fact]
    public void GatewayOpenApi_Invoke_200_response_matches_runtime_contract()
    {
        Assert.Equal(["connectorVersion", "correlationId", "result"], JsonPropertyNames(typeof(GatewayInvokeResponse)));
        Assert.Equal(["connectorVersion", "correlationId", "result"], JsonPropertyNames(typeof(Sample.InvokeResponse)));

        OpenApiSchema response = ReadSchema("InvokeResponse");
        Assert.True(response.AdditionalPropertiesFalse);
        Assert.Equal(["connectorVersion", "correlationId", "result"], response.Properties.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(["connectorVersion", "correlationId", "result"], response.Required.Order(StringComparer.Ordinal));
        Assert.Equal("InvokeResult", response.Properties["result"].Reference);
        Assert.Equal("InvokeResponse", ReadInvoke200ResponseReference());

        OpenApiSchema result = ReadSchema("InvokeResult");
        Assert.True(result.AdditionalPropertiesFalse);
        Assert.Equal(["contentType", "data", "encoding"], result.Properties.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(["contentType", "data", "encoding"], result.Required.Order(StringComparer.Ordinal));
        Assert.Equal("base64", result.Properties["encoding"].Constant);

        const string applicationJson = "{\"accepted\":true,\"vendorReference\":\"synthetic-order\"}";
        GatewayInvokeResponse runtime = new(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "1.0.0",
            new("application/json; charset=utf-8", "base64", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(applicationJson))));
        string wire = JsonSerializer.Serialize(runtime, WebJson);
        Sample.InvokeResponse? sample = JsonSerializer.Deserialize<Sample.InvokeResponse>(wire, WebJson);
        Assert.NotNull(sample);
        Assert.Equal(runtime.CorrelationId, sample.CorrelationId);
        Assert.Equal(runtime.ConnectorVersion, sample.ConnectorVersion);
        Assert.Equal(runtime.Result.Data, sample.Result.Data);
    }

    [Fact]
    public void DirectGatewayClient_deserializes_documented_invoke_success_response()
    {
        const string documented = """
            {
              "correlationId": "11111111-1111-1111-1111-111111111111",
              "connectorVersion": "1.0.0",
              "result": {
                "contentType": "application/json; charset=utf-8",
                "encoding": "base64",
                "data": "eyJhY2NlcHRlZCI6dHJ1ZSwidmVuZG9yUmVmZXJlbmNlIjoic3ludGhldGljLW9yZGVyIn0="
              }
            }
            """;
        Sample.InvokeResponse response = JsonSerializer.Deserialize<Sample.InvokeResponse>(documented, WebJson)
            ?? throw new InvalidOperationException("Documented response did not deserialize.");
        Sample.SyntheticSubmitResponse result = Sample.InvokeSuccessContract.DeserializeSyntheticSubmit(response);

        Assert.Equal(Guid.Parse("11111111-1111-1111-1111-111111111111"), response.CorrelationId);
        Assert.Equal("1.0.0", response.ConnectorVersion);
        Assert.True(result.Accepted);
        Assert.Equal("synthetic-order", result.VendorReference);

        const string observedApplicationResult = """{"accepted":true,"requestBytes":35,"vendorReference":"synthetic-order"}""";
        Sample.InvokeResponse observed = response with
        {
            Result = response.Result with { Data = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(observedApplicationResult)) }
        };
        Sample.SyntheticSubmitResponse observedResult = Sample.InvokeSuccessContract.DeserializeSyntheticSubmit(observed);
        Assert.True(observedResult.Accepted);
        Assert.Equal("synthetic-order", observedResult.VendorReference);

        string runbook = File.ReadAllText(Path.Combine(Root, "docs", "operations", "ALPHA-GOLDEN-PATH.md"));
        Assert.Contains("\"accepted\": true", runbook, StringComparison.Ordinal);
        Assert.Contains("\"vendorReference\": \"synthetic-order\"", runbook, StringComparison.Ordinal);
    }

    private static void AssertRequestTypesMatch()
    {
        Dictionary<string, PropertyInfo> runtime = typeof(GatewayInvokeRequest).GetProperties().ToDictionary(JsonName, StringComparer.Ordinal);
        Dictionary<string, PropertyInfo> sample = typeof(Sample.InvokeRequest).GetProperties().ToDictionary(JsonName, StringComparer.Ordinal);
        foreach (string scalar in new[] { "protocolVersion", "correlationId", "idempotencyKey", "operatorContext", "metadata", "extensions" })
            Assert.Equal(runtime[scalar].PropertyType, sample[scalar].PropertyType);
        Assert.Equal(typeof(GatewayPayload), runtime["payload"].PropertyType);
        Assert.Equal(typeof(Sample.GatewayPayload), sample["payload"].PropertyType);
        Assert.Equal(JsonPropertyNames(typeof(GatewayPayload)), JsonPropertyNames(typeof(Sample.GatewayPayload)));
    }

    private static string[] JsonPropertyNames(Type type) => type.GetProperties().Select(JsonName).Order(StringComparer.Ordinal).ToArray();
    private static string JsonName(PropertyInfo property) => JsonNamingPolicy.CamelCase.ConvertName(property.Name);

    private static OpenApiSchema ReadSchema(string name)
    {
        string[] lines = File.ReadAllLines(Path.Combine(Root, "docs", "api", "gateway-openapi.yaml"));
        int start = Array.FindIndex(lines, line => string.Equals(line, $"    {name}:", StringComparison.Ordinal));
        Assert.True(start >= 0, $"OpenAPI schema {name} was not found.");
        int end = Array.FindIndex(lines, start + 1, line => SchemaBoundary().IsMatch(line));
        if (end < 0) end = lines.Length;
        string[] block = lines[start..end];

        HashSet<string> required = [];
        string? requiredLine = block.FirstOrDefault(line => line.TrimStart().StartsWith("required: [", StringComparison.Ordinal));
        if (requiredLine is not null) required.UnionWith(ParseList(requiredLine));
        bool additionalPropertiesFalse = block.Any(line => string.Equals(line.Trim(), "additionalProperties: false", StringComparison.Ordinal));
        int properties = Array.FindIndex(block, line => string.Equals(line, "      properties:", StringComparison.Ordinal));
        Assert.True(properties >= 0, $"OpenAPI schema {name} has no properties block.");

        Dictionary<string, OpenApiProperty> parsed = new(StringComparer.Ordinal);
        for (int index = properties + 1; index < block.Length;)
        {
            Match match = PropertyBoundary().Match(block[index]);
            if (!match.Success) { index++; continue; }
            int next = index + 1;
            while (next < block.Length && !PropertyBoundary().IsMatch(block[next])) next++;
            string text = string.Join('\n', block[index..next]);
            Match reference = SchemaReference().Match(text);
            Match constant = ConstantValue().Match(text);
            Match enumeration = EnumValues().Match(text);
            parsed.Add(match.Groups[1].Value, new(
                reference.Success ? reference.Groups[1].Value : null,
                constant.Success ? constant.Groups[1].Value : null,
                enumeration.Success ? ParseCommaList(enumeration.Groups[1].Value) : []));
            index = next;
        }
        return new(required, parsed, additionalPropertiesFalse);
    }

    private static string ReadInvoke200ResponseReference()
    {
        string[] lines = File.ReadAllLines(Path.Combine(Root, "docs", "api", "gateway-openapi.yaml"));
        const string path = "  /v1/connectors/{connectorId}/operations/{operationId}:invoke:";
        int start = Array.FindIndex(lines, line => string.Equals(line, path, StringComparison.Ordinal));
        Assert.True(start >= 0);
        int end = Array.FindIndex(lines, start + 1, line => line.StartsWith("  /", StringComparison.Ordinal));
        if (end < 0) end = lines.Length;
        int status = Array.FindIndex(lines, start, end - start, line => string.Equals(line, "        '200':", StringComparison.Ordinal));
        Assert.True(status >= 0);
        int statusEnd = Array.FindIndex(lines, status + 1, end - status - 1, line => line.StartsWith("        default:", StringComparison.Ordinal));
        Assert.True(statusEnd > status);
        Match reference = SchemaReference().Match(string.Join('\n', lines[status..statusEnd]));
        Assert.True(reference.Success, "Invoke HTTP 200 has no named response schema reference.");
        return reference.Groups[1].Value;
    }

    private static string[] ParseList(string line)
    {
        int open = line.IndexOf('[', StringComparison.Ordinal);
        int close = line.IndexOf(']', open + 1);
        return ParseCommaList(line[(open + 1)..close]);
    }

    private static string[] ParseCommaList(string value) => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(item => item.Trim('\'', '"')).ToArray();

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "BrokerGateway.slnx")) ||
                File.Exists(Path.Combine(current.FullName, "BrokerGateway.Core.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("Repository root not found.");
    }

    private sealed record OpenApiSchema(HashSet<string> Required, Dictionary<string, OpenApiProperty> Properties, bool AdditionalPropertiesFalse);
    private sealed record OpenApiProperty(string? Reference, string? Constant, string[] EnumValues);

    [GeneratedRegex(@"^    [A-Za-z][A-Za-z0-9]*:\s*$")]
    private static partial Regex SchemaBoundary();
    [GeneratedRegex(@"^        ([A-Za-z][A-Za-z0-9]*):")]
    private static partial Regex PropertyBoundary();
    [GeneratedRegex(@"\$ref:\s*'#/components/schemas/([^']+)'")]
    private static partial Regex SchemaReference();
    [GeneratedRegex(@"\bconst:\s*'?([^,}\s']+)'?")]
    private static partial Regex ConstantValue();
    [GeneratedRegex(@"\benum:\s*\[([^\]]+)\]")]
    private static partial Regex EnumValues();
}
