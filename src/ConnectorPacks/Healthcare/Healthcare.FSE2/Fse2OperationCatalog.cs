using System.Collections.Frozen;
using System.Collections.Immutable;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>Immutable method/path/claim/retry definition for one frozen operation.</summary>
public sealed record Fse2OperationDescriptor(
    Fse2Operation Operation,
    string OperationId,
    HttpMethod Method,
    string PathTemplate,
    Fse2OperationAvailability Availability,
    Fse2RetryClass RetryClass,
    Fse2PurposeOfUse? PurposeOfUse,
    Fse2Action? Action,
    bool HasDocument,
    bool HasJsonBody,
    bool RequiresResourceIdentifier,
    string? PathParameterName,
    bool RequiresAttachmentHash,
    IReadOnlySet<int> SuccessStatusCodes);

/// <summary>Frozen FSE2 operation allowlist. No arbitrary relative URL is accepted.</summary>
public static class Fse2OperationCatalog
{
    private static readonly FrozenDictionary<string, Fse2ClaimAuthority> ClaimAuthorities =
        new Dictionary<string, Fse2ClaimAuthority>(StringComparer.Ordinal)
        {
            ["iss"] = Fse2ClaimAuthority.ServerOwned,
            ["aud"] = Fse2ClaimAuthority.ServerOwned,
            ["sub"] = Fse2ClaimAuthority.ServerOwned,
            ["iat"] = Fse2ClaimAuthority.ServerOwned,
            ["exp"] = Fse2ClaimAuthority.ServerOwned,
            ["jti"] = Fse2ClaimAuthority.ServerOwned,
            ["subject_role"] = Fse2ClaimAuthority.ServerOwned,
            ["subject_organization"] = Fse2ClaimAuthority.ServerOwned,
            ["subject_organization_id"] = Fse2ClaimAuthority.ServerOwned,
            ["locality"] = Fse2ClaimAuthority.ServerOwned,
            ["subject_application_id"] = Fse2ClaimAuthority.ServerOwned,
            ["subject_application_vendor"] = Fse2ClaimAuthority.ServerOwned,
            ["subject_application_version"] = Fse2ClaimAuthority.ServerOwned,
            ["person_id"] = Fse2ClaimAuthority.BusinessAllowlisted,
            ["patient_consent"] = Fse2ClaimAuthority.BusinessAllowlisted,
            ["resource_hl7_type"] = Fse2ClaimAuthority.BusinessAllowlisted,
            ["purpose_of_use"] = Fse2ClaimAuthority.Derived,
            ["action_id"] = Fse2ClaimAuthority.Derived,
            ["attachment_hash"] = Fse2ClaimAuthority.Derived
        }.ToFrozenDictionary(StringComparer.Ordinal);
    private static readonly FrozenDictionary<Fse2Operation, Fse2OperationDescriptor> Descriptors =
        new Dictionary<Fse2Operation, Fse2OperationDescriptor>
        {
            [Fse2Operation.ValidateCda] = Descriptor(Fse2Operation.ValidateCda, "validate-cda", HttpMethod.Post, "/documents/validation", Fse2OperationAvailability.ProductionAvailable, Fse2PurposeOfUse.Treatment, Fse2Action.Create, true, true, null, false, 200, 201),
            [Fse2Operation.ValidateFhir] = Descriptor(Fse2Operation.ValidateFhir, "validate-fhir", HttpMethod.Post, "/documents/fhir-validation", Fse2OperationAvailability.TestOnlyOfficial, Fse2PurposeOfUse.Treatment, Fse2Action.Create, true, true, null, false, 200, 201),
            [Fse2Operation.Create] = Descriptor(Fse2Operation.Create, "create", HttpMethod.Post, "/documents", Fse2OperationAvailability.ProductionAvailable, Fse2PurposeOfUse.Treatment, Fse2Action.Create, true, true, null, true, 202),
            [Fse2Operation.Replace] = Descriptor(Fse2Operation.Replace, "replace", HttpMethod.Put, "/documents/{document-id}", Fse2OperationAvailability.ProductionAvailable, Fse2PurposeOfUse.Update, Fse2Action.Update, true, true, "document-id", true, 202),
            [Fse2Operation.Delete] = Descriptor(Fse2Operation.Delete, "delete", HttpMethod.Delete, "/documents/{document-id}", Fse2OperationAvailability.ProductionAvailable, Fse2PurposeOfUse.Update, Fse2Action.Delete, false, false, "document-id", false, 200, 202),
            [Fse2Operation.UpdateMetadata] = Descriptor(Fse2Operation.UpdateMetadata, "update-metadata", HttpMethod.Put, "/documents/{document-id}/metadata-iti-57", Fse2OperationAvailability.ProductionAvailable, Fse2PurposeOfUse.Update, Fse2Action.Update, false, true, "document-id", false, 200, 202),
            [Fse2Operation.UpdateMetadataChainConcealment] = Descriptor(Fse2Operation.UpdateMetadataChainConcealment, "update-metadata-chain-concealment", HttpMethod.Put, "/documents/{document-id}/metadata-oscuramento-catena", Fse2OperationAvailability.TestOnlyOfficial, Fse2PurposeOfUse.AccessUpdate, Fse2Action.Update, false, true, "document-id", false, 200),
            [Fse2Operation.ValidateAndCreate] = Descriptor(Fse2Operation.ValidateAndCreate, "validate-and-create", HttpMethod.Post, "/documents/validate-and-create", Fse2OperationAvailability.ProductionAvailable, Fse2PurposeOfUse.Treatment, Fse2Action.Create, true, true, null, true, 202),
            [Fse2Operation.ValidateAndReplace] = Descriptor(Fse2Operation.ValidateAndReplace, "validate-and-replace", HttpMethod.Put, "/documents/validate-and-replace/{document-id}", Fse2OperationAvailability.ProductionAvailable, Fse2PurposeOfUse.Update, Fse2Action.Update, true, true, "document-id", true, 202),
            [Fse2Operation.GetStatusByWorkflow] = Descriptor(Fse2Operation.GetStatusByWorkflow, "get-status-by-workflow", HttpMethod.Get, "/status/{workflow-instance-id}", Fse2OperationAvailability.ProductionAvailable, null, null, false, false, "workflow-instance-id", false, 200, 404),
            [Fse2Operation.GetStatusByTrace] = Descriptor(Fse2Operation.GetStatusByTrace, "get-status-by-trace", HttpMethod.Get, "/status/search/{trace-id}", Fse2OperationAvailability.ProductionAvailable, null, null, false, false, "trace-id", false, 200, 404),
            [Fse2Operation.UpdateMetadataLegacy] = Descriptor(Fse2Operation.UpdateMetadataLegacy, "update-metadata-legacy", HttpMethod.Put, "/documents/{document-id}/metadata", Fse2OperationAvailability.ProductionAvailable, Fse2PurposeOfUse.Update, Fse2Action.Update, false, true, "document-id", false, 200),
            [Fse2Operation.CreateFhir] = Descriptor(Fse2Operation.CreateFhir, "create-fhir", HttpMethod.Post, "/fhir-documents", Fse2OperationAvailability.TestOnlyOfficial, Fse2PurposeOfUse.Treatment, Fse2Action.Create, true, true, null, true, 202),
            [Fse2Operation.ReplaceFhir] = Descriptor(Fse2Operation.ReplaceFhir, "replace-fhir", HttpMethod.Put, "/fhir-documents/{document-id}", Fse2OperationAvailability.TestOnlyOfficial, Fse2PurposeOfUse.Update, Fse2Action.Update, true, true, "document-id", true, 202)
        }.ToFrozenDictionary();

    public static ImmutableArray<Fse2OperationDescriptor> All { get; } =
        Descriptors.Values.OrderBy(value => value.Operation).ToImmutableArray();

    public static Fse2OperationDescriptor Get(Fse2Operation operation) =>
        Descriptors.TryGetValue(operation, out Fse2OperationDescriptor? descriptor)
            ? descriptor
            : throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_OPERATION_NOT_AVAILABLE");

    public static Fse2OperationDescriptor Get(string operationId) =>
        Descriptors.Values.SingleOrDefault(value => string.Equals(value.OperationId, operationId, StringComparison.Ordinal))
        ?? throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_OPERATION_NOT_AVAILABLE");

    public static Fse2OperationAvailability GetAvailability(string operationId)
    {
        Fse2OperationDescriptor? descriptor = Descriptors.Values.SingleOrDefault(value => string.Equals(value.OperationId, operationId, StringComparison.Ordinal));
        return descriptor?.Availability ?? Fse2OperationAvailability.NotAvailable;
    }

    /// <summary>Returns the frozen provenance class for an emitted claim; unknown claims are denied.</summary>
    public static Fse2ClaimAuthority GetClaimAuthority(string claimName) =>
        ClaimAuthorities.TryGetValue(claimName, out Fse2ClaimAuthority authority)
            ? authority
            : throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_CLAIM_NOT_ALLOWED");

    /// <summary>Fails closed unless the organization profile uses the exact frozen operation combination.</summary>
    public static void ValidateOrganizationCombination(string role, string operationReference, Fse2PurposeOfUse purpose, Fse2Action action)
    {
        Fse2OperationDescriptor? descriptor = Descriptors.Values.SingleOrDefault(value =>
            string.Equals(value.OperationId, operationReference, StringComparison.Ordinal));
        if (role != "DAP" || descriptor is null || descriptor.Action != action || descriptor.PurposeOfUse != purpose)
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_ROLE_PURPOSE_ACTION_DENIED");
    }

    public static string ClaimValue(Fse2PurposeOfUse value) => value switch
    {
        Fse2PurposeOfUse.Treatment => "TREATMENT",
        Fse2PurposeOfUse.Update => "UPDATE",
        Fse2PurposeOfUse.AccessUpdate => "ACCESS UPDATE",
        _ => throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_PURPOSE_DENIED")
    };

    public static string ClaimValue(Fse2Action value) => value switch
    {
        Fse2Action.Create => "CREATE",
        Fse2Action.Update => "UPDATE",
        Fse2Action.Delete => "DELETE",
        _ => throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_ACTION_DENIED")
    };

    private static Fse2OperationDescriptor Descriptor(Fse2Operation operation, string id, HttpMethod method, string path,
        Fse2OperationAvailability availability, Fse2PurposeOfUse? purpose, Fse2Action? action, bool document, bool json,
        string? pathParameterName, bool hash, params int[] success) =>
        new(operation, id, method, path, availability, availability == Fse2OperationAvailability.ProductionAvailable && operation is Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace
            ? Fse2RetryClass.SafeRetry : Fse2RetryClass.NoAutomaticRetry, purpose, action, document, json,
            pathParameterName is not null, pathParameterName, hash, success.ToFrozenSet());

    internal static void ValidateBaseEndpoint(Uri endpoint)
    {
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment) || !endpoint.AbsolutePath.TrimEnd('/').EndsWith("/v1", StringComparison.Ordinal))
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_BASE_ENDPOINT_DENIED");
    }
}
