using System.Reflection;
using System.Text.Json;

namespace SecureIntegration.Gateway.Application;

/// <summary>Stable audit values reserved by the backend contract even when an optional mutation is not exposed by the current host.</summary>
public static class RuntimeAuditActions
{
    /// <summary>Revocation of an installation operation grant.</summary>
    public const string GrantRevoke = "grant.revoke";
    /// <summary>Stable successful grant-revocation reason.</summary>
    public const string GrantRevoked = "BGW-GRANT-REVOKED";
}

/// <summary>The embedded, versioned wire-value contract exported to Admin clients.</summary>
public sealed record RuntimeWireCodeCatalog(
    IReadOnlyList<string> Status,
    IReadOnlyList<string> Health,
    IReadOnlyList<string> Approval,
    IReadOnlyList<string> Role,
    IReadOnlyList<string> Scope,
    IReadOnlyList<string> AuditAction,
    IReadOnlyList<string> AuditOutcome,
    IReadOnlyList<string> Reason)
{
    private const string ResourceName = "SecureIntegration.Gateway.Application.Admin.runtime-wire-codes.json";
    private static readonly Lazy<RuntimeWireCodeCatalog> Contract = new(Load);
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    /// <summary>Gets the immutable catalog compiled into the backend.</summary>
    public static RuntimeWireCodeCatalog Current => Contract.Value;

    private static RuntimeWireCodeCatalog Load()
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException("Runtime wire-code contract is not embedded.");
        return JsonSerializer.Deserialize<RuntimeWireCodeCatalog>(stream, WebJson)
            ?? throw new InvalidOperationException("Runtime wire-code contract is invalid.");
    }
}
