using System.Text.RegularExpressions;
using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed partial class AdminOpenApiParityTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void FSE2_ADMIN_AUDIT_OpenAPI_generated_client_and_runtime_match()
    {
        string yaml = File.ReadAllText(Path.Combine(Root, "docs", "api", "gateway-openapi.yaml"));
        string generated = File.ReadAllText(Path.Combine(Root, "src", "Admin", "Admin.Web", "src", "api", "schema.d.ts"));
        string contracts = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "AdminContracts.cs"));
        string[] phases =
        [
            "DNS_FAILURE", "TCP_CONNECT_FAILURE", "TLS_SERVER_VALIDATION_FAILURE",
            "MTLS_CLIENT_AUTH_FAILURE", "TIMEOUT", "TRANSPORT_FAILURE_OTHER",
            "UPSTREAM_HTTP_RESPONSE", "LOCAL_RESPONSE_MAPPING_FAILURE"
        ];
        string[] categories =
        [
            "NO_UPSTREAM_RESPONSE", "INFORMATIONAL", "SUCCESS", "REDIRECTION",
            "CLIENT_ERROR", "SERVER_ERROR"
        ];
        string[] upstreamCodes =
        [
            "cda-element", "cda-extraction", "cda-match", "cda-validation", "document-hash",
            "document-type", "eds-document-missing", "eds-error", "empty-file", "fhir-element",
            "fhir-extraction", "fhir-mapping-type", "generic-error", "generic-timeout", "ini-error",
            "invalid-format", "jwt-validation", "mandatory-element", "mandatory-element-token",
            "max-day-limit-exceed", "missing-token", "record-not-found", "semantic", "service-error",
            "syntax", "vocabulary", "workflow-id-error-extraction"
        ];

        Assert.Contains("SafeFailureDiagnosticsResource", contracts, StringComparison.Ordinal);
        Assert.Contains("failureDiagnostics", yaml, StringComparison.Ordinal);
        Assert.Contains("failureDiagnostics", generated, StringComparison.Ordinal);
        foreach (string value in phases.Concat(categories))
        {
            Assert.Contains(value, yaml, StringComparison.Ordinal);
            Assert.Contains(value, generated, StringComparison.Ordinal);
        }
        Assert.Contains("upstreamStatus: number | null", generated, StringComparison.Ordinal);
        foreach (string value in upstreamCodes)
        {
            Assert.Contains(value, yaml, StringComparison.Ordinal);
            Assert.Contains(value, generated, StringComparison.Ordinal);
        }
        Assert.Contains("safeUpstreamCode: null |", generated, StringComparison.Ordinal);
        Assert.Contains("localSafeCode: null | \"FSE2_RESPONSE_INVALID\"", generated, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_public_http_route_is_declared_once_in_OpenAPI_and_no_documented_route_is_stale()
    {
        string program = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "Program.cs"));
        HashSet<string> implementation = [];
        foreach (Match match in RoutePattern().Matches(program))
        {
            string owner = match.Groups[1].Value;
            string method = match.Groups[2].Value.ToLowerInvariant();
            string route = Normalize((owner == "adminApi" ? "/admin/api/v1" : string.Empty) + match.Groups[3].Value);
            if (IsPublicContractRoute(route)) implementation.Add(method + " " + route);
        }

        string yaml = File.ReadAllText(Path.Combine(Root, "docs", "api", "gateway-openapi.yaml"));
        HashSet<string> contract = [];
        string? path = null;
        foreach (string line in yaml.Split('\n'))
        {
            Match pathMatch = PathPattern().Match(line);
            if (pathMatch.Success) { path = Normalize(pathMatch.Groups[1].Value); continue; }
            Match methodMatch = MethodPattern().Match(line);
            if (path is not null && methodMatch.Success && IsPublicContractRoute(path)) contract.Add(methodMatch.Groups[1].Value + " " + path);
        }

        string[] missing = implementation.Except(contract).Order().ToArray();
        string[] stale = contract.Except(implementation).Order().ToArray();
        Assert.True(missing.Length == 0 && stale.Length == 0, $"Missing OpenAPI operations: {string.Join(", ", missing)}{Environment.NewLine}Stale OpenAPI operations: {string.Join(", ", stale)}");
    }

    [Fact]
    public void Every_admin_api_operation_declares_session_security_and_every_mutation_declares_CSRF()
    {
        Dictionary<string, string> operations = ContractOperations(File.ReadAllText(Path.Combine(Root, "docs", "api", "gateway-openapi.yaml")));
        string[] missingSession = operations.Where(value => value.Key.Contains(" /admin/api/v1/", StringComparison.Ordinal) && !value.Value.Contains("AdminSession", StringComparison.Ordinal)).Select(value => value.Key).Order().ToArray();
        string[] csrfProtected = operations.Where(value => value.Key.StartsWith("post ", StringComparison.Ordinal) || value.Key.StartsWith("put ", StringComparison.Ordinal) || value.Key.StartsWith("delete ", StringComparison.Ordinal))
            .Where(value => value.Key.Contains(" /admin/api/v1/", StringComparison.Ordinal) || value.Key is "post /admin/auth/logout" or "post /admin/auth/development/login")
            .Where(value => !value.Value.Contains("#/components/parameters/Csrf", StringComparison.Ordinal)).Select(value => value.Key).Order().ToArray();
        Assert.True(missingSession.Length == 0, $"Admin operations without session security: {string.Join(", ", missingSession)}");
        Assert.True(csrfProtected.Length == 0, $"Admin mutations without CSRF contract: {string.Join(", ", csrfProtected)}");
    }

    [Fact]
    public void Every_authenticated_runtime_operation_declares_mTLS_and_BGW1_headers()
    {
        string program = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "Program.cs"));
        MatchCollection routes = RoutePattern().Matches(program);
        HashSet<string> authenticatedRuntimeRoutes = [];
        for (int index = 0; index < routes.Count; index++)
        {
            Match routeMatch = routes[index];
            string owner = routeMatch.Groups[1].Value;
            string method = routeMatch.Groups[2].Value.ToLowerInvariant();
            string route = Normalize((owner == "adminApi" ? "/admin/api/v1" : string.Empty) + routeMatch.Groups[3].Value);
            int blockEnd = index + 1 < routes.Count ? routes[index + 1].Index : program.Length;
            string implementationBlock = program[routeMatch.Index..blockEnd];
            if (route.StartsWith("/v1/", StringComparison.Ordinal) && implementationBlock.Contains("AuthenticateAsync(", StringComparison.Ordinal))
                authenticatedRuntimeRoutes.Add(method + " " + route);
        }

        Dictionary<string, string> operations = ContractOperations(File.ReadAllText(Path.Combine(Root, "docs", "api", "gateway-openapi.yaml")));
        string[] requiredTokens =
        [
            "InstallationMutualTLS",
            "#/components/parameters/BgwTimestamp",
            "#/components/parameters/BgwNonce",
            "#/components/parameters/BgwContentSha256",
            "#/components/parameters/BgwSignature"
        ];
        string[] incomplete = authenticatedRuntimeRoutes
            .Where(route => !operations.TryGetValue(route, out string? operation) || requiredTokens.Any(token => !operation.Contains(token, StringComparison.Ordinal)))
            .Order()
            .ToArray();

        Assert.True(incomplete.Length == 0, $"Authenticated runtime operations with an incomplete OpenAPI security contract: {string.Join(", ", incomplete)}");
    }

    [GeneratedRegex("\\b(app|adminApi)\\.Map(Get|Post|Put|Delete)\\(\\\"([^\\\"]+)\\\"")]
    private static partial Regex RoutePattern();
    [GeneratedRegex(@"^  (/\S+):\s*$")]
    private static partial Regex PathPattern();
    [GeneratedRegex(@"^    (get|post|put|delete):\s*$")]
    private static partial Regex MethodPattern();

    private static string Normalize(string value) => Regex.Replace(value, @"\{([^}:]+):[^}]+\}", "{$1}");
    private static bool IsPublicContractRoute(string route) =>
        route.StartsWith("/v1/", StringComparison.Ordinal) ||
        route.StartsWith("/admin/", StringComparison.Ordinal) ||
        route.StartsWith("/health/", StringComparison.Ordinal);
    private static Dictionary<string, string> ContractOperations(string yaml)
    {
        Dictionary<string, string> result = [];
        string? path = null; string? method = null; List<string> block = [];
        void Commit()
        {
            if (path is not null && method is not null) result[method + " " + Normalize(path)] = string.Join('\n', block);
            method = null; block.Clear();
        }
        foreach (string line in yaml.Split('\n'))
        {
            Match pathMatch = PathPattern().Match(line);
            if (pathMatch.Success) { Commit(); path = pathMatch.Groups[1].Value; continue; }
            Match methodMatch = MethodPattern().Match(line);
            if (path is not null && methodMatch.Success) { Commit(); method = methodMatch.Groups[1].Value; block.Add(line); continue; }
            if (method is not null) block.Add(line);
        }
        Commit();
        return result;
    }
    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "BrokerGateway.slnx")) || File.Exists(Path.Combine(current.FullName, "BrokerGateway.Core.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("Repository root not found.");
    }
}
