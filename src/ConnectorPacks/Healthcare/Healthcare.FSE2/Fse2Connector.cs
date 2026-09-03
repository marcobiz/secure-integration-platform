using System.Collections.Frozen;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

internal enum Fse2ValidateCdaPublishedContract
{
    Historical100,
    OfficialTestParity101
}

internal static class Fse2ValidateCdaPublishedContractResolver
{
    internal static Fse2ValidateCdaPublishedContract Resolve(
        string connectorId,
        string connectorVersion,
        string operationId,
        Fse2EnvironmentClass environmentClass)
    {
        if (environmentClass != Fse2EnvironmentClass.OfficialTest ||
            !string.Equals(operationId, Fse2OfficialTestCanonicalDefinition.OperationId, StringComparison.Ordinal) ||
            !string.Equals(connectorId, Fse2OfficialTestCanonicalDefinition.ConnectorId, StringComparison.Ordinal))
            return Fse2ValidateCdaPublishedContract.Historical100;

        if (string.Equals(connectorVersion, Fse2OfficialTestCanonicalDefinition.HistoricalConnectorVersion, StringComparison.Ordinal))
            return Fse2ValidateCdaPublishedContract.Historical100;
        if (string.Equals(connectorVersion, Fse2OfficialTestCanonicalDefinition.ConnectorVersion, StringComparison.Ordinal))
            return Fse2ValidateCdaPublishedContract.OfficialTestParity101;

        throw new Fse2ConnectorException(
            Fse2ErrorCategory.PolicyDenied,
            "FSE2_OFFICIALTEST_CONNECTOR_VERSION_UNSUPPORTED");
    }
}

/// <summary>External Healthcare module for the frozen FSE2 Organization profile.</summary>
public sealed class Fse2OrganizationExecutionModule : IConnectorExecutionModule
{
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("healthcare-fse2");

    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        ArgumentNullException.ThrowIfNull(registrar);
        registrar.AddAuthorizedPublishedOperationExpectationProvider<Fse2OrganizationPublishedOperationExpectationProvider>();
        registrar.AddStrategy<Fse2OrganizationExecutionStrategy>();
    }
}

/// <summary>Exact connector-owned semantic policy expected for every FSE2 Organization operation.</summary>
public sealed class Fse2OrganizationPublishedOperationExpectationProvider : IAuthorizedPublishedOperationExpectationProvider
{
    private static readonly ConnectorExecutionStrategyKey StrategyKey =
        ConnectorExecutionStrategyKey.Parse("healthcare-fse2-organization");
    private static readonly IReadOnlySet<ConnectorExecutionStrategyKey> StrategyKeys =
        new HashSet<ConnectorExecutionStrategyKey> { StrategyKey }.ToFrozenSet();
    private static readonly string[] IntegrityClaims =
    [
        "subject_role", "purpose_of_use", "subject_organization", "subject_organization_id", "locality",
        "person_id", "patient_consent", "resource_hl7_type", "action_id", "attachment_hash",
        "subject_application_id", "subject_application_vendor", "subject_application_version"
    ];
    private static readonly string[] ValidateCdaOfficialTestIntegrityClaims = IntegrityClaims
        .Where(value => !string.Equals(value, "attachment_hash", StringComparison.Ordinal))
        .ToArray();
    private static readonly string[] WorkflowStatusIntegrityClaims = IntegrityClaims
        .Where(value => value is not ("person_id" or "patient_consent" or "resource_hl7_type" or "attachment_hash"))
        .ToArray();

    public IReadOnlySet<ConnectorExecutionStrategyKey> SupportedExecutionStrategies => StrategyKeys;

    public AuthorizedPublishedOperationExpectations CreateExpectations(
        AuthorizedPublishedOperationExpectationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.ExecutionStrategyKey != StrategyKey ||
            context.AuthenticationKind != GatewayAuthenticationKind.MutualTls)
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_EXPECTATION_CONTEXT_DENIED");

        Fse2PublishedOrganizationProfile profile = Fse2PublishedOrganizationProfile.Parse(
            context.OpenPublishedExtensionConfiguration(), context.OperationId);
        Fse2ValidateCdaPublishedContract validateCdaContract = Fse2ValidateCdaPublishedContractResolver.Resolve(
            context.ConnectorId,
            context.ConnectorVersion,
            context.OperationId,
            profile.EnvironmentClass);
        bool officialTestValidateCda = profile.EnvironmentClass == Fse2EnvironmentClass.OfficialTest &&
            profile.Operation.Operation == Fse2Operation.ValidateCda;
        if (officialTestValidateCda &&
            (profile.Activity is null || !Fse2PublishedOrganizationProfile.IsSupportedValidateCdaActivity(profile.Activity) ||
             !string.Equals(profile.AcceptMediaType, Fse2PublishedOrganizationProfile.OfficialAcceptMediaType, StringComparison.Ordinal)))
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_OFFICIALTEST_PROFILE_DENIED");
        ConnectorSigningSlotKey authorization = profile.AuthorizationSigningSlot;
        ConnectorSigningSlotKey integrity = profile.IntegritySigningSlot;
        AuthorizedSigningCertificateHeaderMode certificateHeaderMode =
            profile.EnvironmentClass == Fse2EnvironmentClass.OfficialTest &&
            (!officialTestValidateCda ||
             validateCdaContract == Fse2ValidateCdaPublishedContract.OfficialTestParity101)
            ? AuthorizedSigningCertificateHeaderMode.Leaf
            : AuthorizedSigningCertificateHeaderMode.Chain;
        AuthorizedSigningSlotExpectation authorizationExpectation = new(
            authorization,
            required: true,
            AuthorizedSigningAlgorithm.Rs256,
            AuthorizedSigningTokenProjectionExpectation.AuthorizationBearer(),
            profile.Audience,
            profile.SubjectCx,
            [],
            Fse2PublishedOrganizationProfile.TokenLifetimeSeconds,
            AuthorizedSigningTemporalMode.IssuedAtExpiration,
            jtiRequired: true,
            certificateHeaderMode,
            AuthorizedSigningIssuerExpectation.FixedPrefixAndCertificateSubjectCommonName("auth:"),
            AuthorizedSigningCertificateKeyUsageMode.ContentCommitment);
        AuthorizedSigningSlotExpectation integrityExpectation = new(
            integrity,
            required: true,
            AuthorizedSigningAlgorithm.Rs256,
            AuthorizedSigningTokenProjectionExpectation.SignedTokenHeader(Fse2PublishedOrganizationProfile.IntegrityHeaderName),
            profile.Audience,
            profile.SubjectCx,
            profile.Operation.Operation == Fse2Operation.GetStatusByWorkflow
                ? WorkflowStatusIntegrityClaims
                : officialTestValidateCda ? ValidateCdaOfficialTestIntegrityClaims : IntegrityClaims,
            Fse2PublishedOrganizationProfile.TokenLifetimeSeconds,
            AuthorizedSigningTemporalMode.IssuedAtExpiration,
            jtiRequired: true,
            certificateHeaderMode,
            AuthorizedSigningIssuerExpectation.FixedPrefixAndCertificateSubjectCommonName("integrity:"),
            AuthorizedSigningCertificateKeyUsageMode.ContentCommitment);
        return new(
            GatewayAuthenticationKind.MutualTls,
            restrictedTransportRequired: true,
            [authorizationExpectation, integrityExpectation],
            [authorization, integrity],
            [authorization, integrity],
            AuthorizedRestrictedTransportResponseMode.BoundedProblemDetails);
    }
}

/// <summary>
/// Connector-local FSE2 composition. Core has already authenticated, granted and resolved Published
/// A; the strategy receives no store, provider, endpoint, certificate, key, token or HttpClient.
/// </summary>
public sealed class Fse2OrganizationExecutionStrategy : IConnectorExecutionStrategy
{
    private static readonly ConnectorExecutionStrategyKey StrategyKey =
        ConnectorExecutionStrategyKey.Parse("healthcare-fse2-organization");
    private static readonly IReadOnlySet<GatewayAuthenticationKind> AuthenticationKinds =
        new HashSet<GatewayAuthenticationKind> { GatewayAuthenticationKind.MutualTls }.ToFrozenSet();
    private static readonly IReadOnlyDictionary<string, JsonElement> EmptyClaims =
        new Dictionary<string, JsonElement>(StringComparer.Ordinal).ToFrozenDictionary(StringComparer.Ordinal);
    private static readonly JsonSerializerOptions ResponseJson = new(JsonSerializerDefaults.Web);

    public ConnectorExecutionStrategyKey Key => StrategyKey;
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;

    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        if (execution.ExecutionStrategyKey != StrategyKey || execution.AuthenticationKind != GatewayAuthenticationKind.MutualTls)
            throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_EXECUTION_AUTHORITY_DENIED");

        Fse2PublishedOrganizationProfile profile =
            Fse2PublishedOrganizationProfile.Parse(execution.OpenPublishedExtensionConfiguration(), execution.OperationId);
        Fse2ValidateCdaPublishedContract validateCdaContract = Fse2ValidateCdaPublishedContractResolver.Resolve(
            execution.ConnectorId,
            execution.ConnectorVersion,
            execution.OperationId,
            profile.EnvironmentClass);

        Fse2InboundPayload inbound;
        using (Stream payload = execution.OpenPayloadStream())
            inbound = Fse2InboundPayload.Parse(payload, execution.PayloadLength);
        ValidateRequest(profile, inbound, validateCdaContract);

        Fse2WorkflowExecutionContext security = await ResolveSecurityContextAsync(
            execution, profile, inbound, cancellationToken).ConfigureAwait(false);
        string? exactAttachmentHash = profile.Operation.RequiresAttachmentHash
            ? Fse2Validation.ComputeAttachmentHash(inbound.Document)
            : null;
        IReadOnlyDictionary<string, JsonElement> integrityClaims = BuildIntegrityClaims(
            profile, security, exactAttachmentHash);
        byte[] exactOutboundBody = Fse2ExactBodyComposer.Compose(profile, inbound, execution.RequestContentType);

        _ = await execution.Capabilities.CreateSignedTokenAsync(
            profile.AuthorizationSigningSlot,
            EmptyClaims,
            cancellationToken).ConfigureAwait(false);
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            profile.IntegritySigningSlot,
            integrityClaims,
            cancellationToken).ConfigureAwait(false);

        IReadOnlyCollection<AuthorizedConnectorPathParameter> pathParameters = profile.Operation.PathParameterName is null
            ? []
            : [new AuthorizedConnectorPathParameter(profile.Operation.PathParameterName, inbound.ResourceIdentifier!)];
        AuthorizedConnectorRestrictedTransportRequest restrictedRequest =
            profile.Operation.HasDocument || profile.Operation.HasJsonBody
                ? new AuthorizedConnectorRestrictedTransportRequest(exactOutboundBody, pathParameters)
                : new AuthorizedConnectorRestrictedTransportRequest(pathParameters);
        QualifiedGatewayExecutionResult upstream = await execution.Capabilities.ExecuteRestrictedTransportAsync(
            restrictedRequest, cancellationToken).ConfigureAwait(false);
        if (!profile.Operation.SuccessStatusCodes.Contains(upstream.StatusCode))
        {
            Fse2ConnectorException problem = Fse2ResponseMapper.MapProblem(upstream, profile.Operation.RetryClass);
            execution.Capabilities.RejectRestrictedTransportResponse(upstream, problem.SafeUpstreamCode);
            throw problem;
        }
        Fse2Response normalized;
        try
        {
            normalized = Fse2ResponseMapper.Map(upstream, execution.CorrelationId, profile.Operation);
        }
        catch (Fse2ConnectorException exception) when (
            exception.Category == Fse2ErrorCategory.ResponseInvalid &&
            string.Equals(exception.SafeCode, "FSE2_RESPONSE_INVALID", StringComparison.Ordinal))
        {
            execution.Capabilities.RejectRestrictedTransportResponseMapping(upstream, exception.SafeCode);
            throw;
        }
        if (profile.Operation.Operation == Fse2Operation.GetStatusByWorkflow)
            normalized = normalized with { WorkflowInstanceId = inbound.ResourceIdentifier };
        if (profile.Operation.Operation is not (Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace) &&
            (normalized.WorkflowInstanceId is not null || normalized.TraceId is not null))
        {
            await execution.Capabilities.RecordWorkflowContextAsync(new(
                security.OperationReference,
                Fse2OperationCatalog.ClaimValue(security.Action),
                Fse2OperationCatalog.ClaimValue(security.PurposeOfUse),
                profile.OperationProfileChecksumSha256,
                normalized.WorkflowInstanceId,
                normalized.TraceId), cancellationToken).ConfigureAwait(false);
        }

        return new(upstream.StatusCode, "application/json", JsonSerializer.SerializeToUtf8Bytes(normalized, ResponseJson));
    }

    private static async Task<Fse2WorkflowExecutionContext> ResolveSecurityContextAsync(
        AuthorizedConnectorExecution execution,
        Fse2PublishedOrganizationProfile profile,
        Fse2InboundPayload inbound,
        CancellationToken cancellationToken)
    {
        Fse2OperationDescriptor operation = profile.Operation;
        if (operation.Action is Fse2Action action && operation.PurposeOfUse is Fse2PurposeOfUse purpose)
        {
            if (inbound.ClinicalClaims is null)
                throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_CLINICAL_CLAIMS_REQUIRED");
            if (operation.Operation != Fse2Operation.Delete && inbound.ClinicalClaims.ResourceHl7Type is null)
                throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_RESOURCE_HL7_TYPE_REQUIRED");
            Fse2OperationCatalog.ValidateOrganizationCombination(profile.SubjectRole, operation.OperationId, purpose, action);
            return new(action, purpose, inbound.ClinicalClaims, operation.OperationId);
        }

        try
        {
            ConnectorWorkflowIdentifierKind identifierKind = operation.Operation == Fse2Operation.GetStatusByWorkflow
                ? ConnectorWorkflowIdentifierKind.WorkflowInstanceId
                : ConnectorWorkflowIdentifierKind.TraceId;
            AuthorizedConnectorWorkflowContext stored = await execution.Capabilities.ResolveWorkflowContextAsync(
                new(identifierKind, inbound.ResourceIdentifier!), cancellationToken).ConfigureAwait(false);
            Fse2OperationDescriptor origin = Fse2OperationCatalog.Get(stored.OriginatingOperationId);
            Fse2Action resolvedAction = ParseAction(stored.ActionCode);
            Fse2PurposeOfUse resolvedPurpose = ParsePurposeOfUse(stored.PurposeOfUseCode);
            if (!string.Equals(origin.OperationId, stored.OriginatingOperationId, StringComparison.Ordinal) ||
                !string.Equals(stored.OperationProfileChecksumSha256,
                    profile.CalculateOperationProfileChecksum(origin), StringComparison.Ordinal))
                throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_DENIED");
            if (stored.WorkflowInstanceId is not null)
                _ = Fse2Validation.ValidateWorkflowId(stored.WorkflowInstanceId);
            if (stored.TraceId is not null)
                _ = Fse2Validation.ValidateTraceId(stored.TraceId);
            if (identifierKind == ConnectorWorkflowIdentifierKind.WorkflowInstanceId &&
                !string.Equals(stored.WorkflowInstanceId, inbound.ResourceIdentifier, StringComparison.Ordinal) ||
                identifierKind == ConnectorWorkflowIdentifierKind.TraceId &&
                !string.Equals(stored.TraceId, inbound.ResourceIdentifier, StringComparison.Ordinal))
                throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_DENIED");
            Fse2OperationCatalog.ValidateOrganizationCombination(
                profile.SubjectRole,
                stored.OriginatingOperationId,
                resolvedPurpose,
                resolvedAction);
            return new(resolvedAction, resolvedPurpose,
                profile.Operation.Operation == Fse2Operation.GetStatusByWorkflow ? null : inbound.ClinicalClaims,
                stored.OriginatingOperationId);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Fse2ConnectorException) { throw; }
    }

    private static Fse2Action ParseAction(string value) => value switch
    {
        "CREATE" => Fse2Action.Create,
        "UPDATE" => Fse2Action.Update,
        "DELETE" => Fse2Action.Delete,
        _ => throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_DENIED")
    };

    private static Fse2PurposeOfUse ParsePurposeOfUse(string value) => value switch
    {
        "TREATMENT" => Fse2PurposeOfUse.Treatment,
        "UPDATE" => Fse2PurposeOfUse.Update,
        "ACCESS UPDATE" => Fse2PurposeOfUse.AccessUpdate,
        _ => throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_DENIED")
    };

    private static void ValidateRequest(
        Fse2PublishedOrganizationProfile profile,
        Fse2InboundPayload inbound,
        Fse2ValidateCdaPublishedContract validateCdaContract)
    {
        Fse2OperationDescriptor operation = profile.Operation;
        bool workflowStatus = operation.Operation == Fse2Operation.GetStatusByWorkflow;
        if (workflowStatus == (inbound.ClinicalClaims is not null))
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_REQUEST_SHAPE_DENIED");
        if (inbound.Document.Length > profile.MaximumDocumentBytes ||
            operation.HasDocument != !inbound.Document.IsEmpty ||
            operation.HasJsonBody != !inbound.RequestBody.IsEmpty ||
            operation.RequiresResourceIdentifier != (inbound.ResourceIdentifier is not null))
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_REQUEST_SHAPE_DENIED");
        if (operation.Operation == Fse2Operation.ValidateCda)
        {
            try
            {
                Fse2Validation.ValidateJsonObject(
                    inbound.RequestBody,
                    operation.Operation,
                    validateCdaContract,
                    profile.Activity ?? Fse2PublishedOrganizationProfile.ValidateCdaActivity);
            }
            catch (ArgumentException)
            {
                throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_VALIDATE_CDA_PUBLISHED_CONTRACT_DENIED");
            }
        }
        else if (operation.HasJsonBody)
        {
            Fse2Validation.ValidateJsonObject(inbound.RequestBody, operation.Operation);
        }
        if (inbound.ResourceIdentifier is not null)
            _ = operation.Operation switch
            {
                Fse2Operation.GetStatusByWorkflow => Fse2Validation.ValidateWorkflowId(inbound.ResourceIdentifier),
                Fse2Operation.GetStatusByTrace => Fse2Validation.ValidateTraceId(inbound.ResourceIdentifier),
                _ => Fse2Validation.ValidateDocumentId(inbound.ResourceIdentifier)
            };
        if (operation.HasDocument && inbound.DocumentContentType is not ("application/pdf" or "application/json"))
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_DOCUMENT_CONTENT_TYPE_DENIED");
        if (operation.Operation != Fse2Operation.ValidateFhir && inbound.DocumentContentType == "application/json")
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_DOCUMENT_CONTENT_TYPE_DENIED");
    }

    private static FrozenDictionary<string, JsonElement> BuildIntegrityClaims(
        Fse2PublishedOrganizationProfile profile,
        Fse2WorkflowExecutionContext security,
        string? exactAttachmentHash)
    {
        Dictionary<string, JsonElement> claims = new(StringComparer.Ordinal)
        {
            ["subject_role"] = JsonSerializer.SerializeToElement(profile.SubjectRole),
            ["purpose_of_use"] = JsonSerializer.SerializeToElement(Fse2OperationCatalog.ClaimValue(security.PurposeOfUse)),
            ["subject_organization"] = JsonSerializer.SerializeToElement(profile.OrganizationDescription),
            ["subject_organization_id"] = JsonSerializer.SerializeToElement(profile.OrganizationDomainId),
            ["locality"] = JsonSerializer.SerializeToElement(profile.Locality),
            ["action_id"] = JsonSerializer.SerializeToElement(Fse2OperationCatalog.ClaimValue(security.Action)),
            ["subject_application_id"] = JsonSerializer.SerializeToElement(profile.ApplicationId),
            ["subject_application_vendor"] = JsonSerializer.SerializeToElement(profile.ApplicationVendor),
            ["subject_application_version"] = JsonSerializer.SerializeToElement(profile.ApplicationVersion)
        };
        if (security.ClinicalClaims is not null)
        {
            claims["person_id"] = JsonSerializer.SerializeToElement(security.ClinicalClaims.PersonId);
            claims["patient_consent"] = JsonSerializer.SerializeToElement(security.ClinicalClaims.PatientConsent);
            if (security.ClinicalClaims.ResourceHl7Type is not null)
                claims["resource_hl7_type"] = JsonSerializer.SerializeToElement(security.ClinicalClaims.ResourceHl7Type);
        }
        if (exactAttachmentHash is not null)
            claims["attachment_hash"] = JsonSerializer.SerializeToElement(exactAttachmentHash);
        return claims.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static Fse2ConnectorException Denied(Fse2ErrorCategory category, string code) => new(category, code);

    private sealed record Fse2WorkflowExecutionContext(
        Fse2Action Action,
        Fse2PurposeOfUse PurposeOfUse,
        Fse2ClinicalClaims? ClinicalClaims,
        string OperationReference);
}

internal sealed record Fse2InboundPayload(
    ReadOnlyMemory<byte> Document,
    ReadOnlyMemory<byte> RequestBody,
    string? DocumentContentType,
    string? ResourceIdentifier,
    Fse2ClinicalClaims? ClinicalClaims)
{
    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal)
    {
        "personId", "patientConsent", "resourceHl7Type", "documentBase64", "requestBodyBase64",
        "documentContentType", "resourceIdentifier"
    };

    internal static Fse2InboundPayload Parse(Stream stream, int payloadLength)
    {
        if (payloadLength is < 2 or > 16 * 1024 * 1024)
            throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_REQUEST_PAYLOAD_INVALID");
        try
        {
            using JsonDocument document = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new JsonException();
            HashSet<string> observed = new(StringComparer.Ordinal);
            foreach (JsonProperty property in root.EnumerateObject())
                if (!AllowedProperties.Contains(property.Name) || !observed.Add(property.Name)) throw new JsonException();
            bool hasPerson = observed.Contains("personId");
            bool hasConsent = observed.Contains("patientConsent");
            bool hasResourceType = observed.Contains("resourceHl7Type");
            if (hasPerson != hasConsent || !hasPerson && hasResourceType) throw new JsonException();
            Fse2ClinicalClaims? clinical = hasPerson
                ? Fse2ClinicalClaims.CreateCanonicalPerson(
                    String(root, "personId", 512)!,
                    root.GetProperty("patientConsent").GetBoolean(),
                    String(root, "resourceHl7Type", 256))
                : null;
            byte[] documentBytes = Decode(root, "documentBase64");
            byte[] requestBytes = Decode(root, "requestBodyBase64");
            return new(documentBytes, requestBytes, String(root, "documentContentType", 128),
                String(root, "resourceIdentifier", 512), clinical);
        }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException or JsonException or KeyNotFoundException or OverflowException)
        {
            throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_REQUEST_PAYLOAD_INVALID");
        }
    }

    private static string? String(JsonElement root, string name, int maximumLength)
    {
        if (!root.TryGetProperty(name, out JsonElement property) || property.ValueKind == JsonValueKind.Null) return null;
        if (property.ValueKind != JsonValueKind.String) throw new JsonException();
        string value = property.GetString()!;
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value != value.Trim() || value.Any(char.IsControl))
            throw new JsonException();
        return value;
    }

    private static byte[] Decode(JsonElement root, string name)
    {
        string? encoded = String(root, name, 21 * 1024 * 1024);
        return encoded is null ? [] : Convert.FromBase64String(encoded);
    }
}

internal static class Fse2ExactBodyComposer
{
    internal static byte[] Compose(
        Fse2PublishedOrganizationProfile profile,
        Fse2InboundPayload inbound,
        string publishedRequestContentType)
    {
        if (!profile.Operation.HasDocument)
            return inbound.RequestBody.ToArray();

        using MemoryStream output = new();
        const string prefix = "multipart/form-data; boundary=";
        if (!publishedRequestContentType.StartsWith(prefix, StringComparison.Ordinal) ||
            !IsSafeBoundary(publishedRequestContentType[prefix.Length..]))
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_PUBLISHED_CONTENT_TYPE_DENIED");
        string boundary = publishedRequestContentType[prefix.Length..];
        WriteAscii(output, $"--{boundary}\r\nContent-Disposition: form-data; name=\"requestBody\"\r\nContent-Type: application/json\r\n\r\n");
        output.Write(inbound.RequestBody.Span);
        WriteAscii(output, $"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{(inbound.DocumentContentType == "application/json" ? "bundle.json" : "document.pdf")}\"\r\nContent-Type: {inbound.DocumentContentType}\r\n\r\n");
        output.Write(inbound.Document.Span);
        WriteAscii(output, $"\r\n--{boundary}--\r\n");
        return output.ToArray();
    }

    private static void WriteAscii(Stream stream, string value) => stream.Write(Encoding.ASCII.GetBytes(value));

    private static bool IsSafeBoundary(string value) => value is { Length: >= 16 and <= 64 } &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
}

/// <summary>RFC7807 and success response mapper retaining technical allowlisted metadata only.</summary>
public static class Fse2ResponseMapper
{
    private const int MaximumProblemBytes = 16 * 1024;
    private const int MaximumProblemContentTypeCharacters = 512;
    private const int MaximumWorkflowEvents = 1000;
    private static readonly FrozenSet<string> OfficialProblemCodes = new[]
    {
        "cda-element", "cda-extraction", "cda-match", "cda-validation", "document-hash",
        "document-type", "eds-document-missing", "eds-error", "empty-file", "fhir-element",
        "fhir-extraction", "fhir-mapping-type", "generic-error", "generic-timeout", "ini-error",
        "invalid-format", "jwt-validation", "mandatory-element", "mandatory-element-token",
        "max-day-limit-exceed", "missing-token", "record-not-found", "semantic", "service-error",
        "syntax", "vocabulary", "workflow-id-error-extraction"
    }.ToFrozenSet(StringComparer.Ordinal);

    public static Fse2Response Map(QualifiedGatewayExecutionResult response, Guid correlationId, Fse2OperationDescriptor operation)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (!operation.SuccessStatusCodes.Contains(response.StatusCode)) throw MapProblem(response, operation.RetryClass);
        try
        {
            using JsonDocument document = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 16 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new JsonException();
            string? workflowInstanceId = Safe(root, "workflowInstanceId", Fse2OfficialIdentifierBounds.WorkflowInstanceIdMaximumLength, workflow: true);
            string? traceId = Safe(root, "traceID", Fse2OfficialIdentifierBounds.TraceIdMaximumLength);
            if (operation.Operation == Fse2Operation.Create && (workflowInstanceId is null || traceId is null))
                throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
            IReadOnlyList<Fse2WorkflowEvent> workflowEvents = operation.Operation == Fse2Operation.GetStatusByWorkflow
                ? MapWorkflowEvents(root)
                : [];
            return new(response.StatusCode, correlationId,
                workflowInstanceId,
                traceId,
                Safe(root, "spanID", Fse2OfficialIdentifierBounds.SpanIdMaximumLength),
                SafeWarning(root), operation.RetryClass, workflowEvents);
        }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception) { throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID"); }
    }

    private static List<Fse2WorkflowEvent> MapWorkflowEvents(JsonElement root)
    {
        if (!root.TryGetProperty("transactionData", out JsonElement transactionData) ||
            transactionData.ValueKind != JsonValueKind.Array ||
            transactionData.GetArrayLength() > MaximumWorkflowEvents)
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");

        List<Fse2WorkflowEvent> events = new(transactionData.GetArrayLength());
        DateTimeOffset? previous = null;
        foreach (JsonElement item in transactionData.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
                throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
            Fse2WorkflowEventType type = RequiredText(item, "eventType", 100) switch
            {
                "VALIDATION" => Fse2WorkflowEventType.Validation,
                "PUBLICATION" => Fse2WorkflowEventType.Publication,
                "SEND_TO_INI" => Fse2WorkflowEventType.SendToIni,
                "SEND_TO_UAR" => Fse2WorkflowEventType.SendToUar,
                "UAR_FINAL_STATUS" => Fse2WorkflowEventType.UarFinalStatus,
                _ => throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID")
            };
            Fse2WorkflowEventOutcome outcome = RequiredText(item, "eventStatus", 100) switch
            {
                "SUCCESS" => Fse2WorkflowEventOutcome.Success,
                "BLOCKING_ERROR" => Fse2WorkflowEventOutcome.BlockingError,
                _ => throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID")
            };
            string rawTimestamp = RequiredText(item, "eventDate", 100);
            string normalizedTimestamp = NormalizeOffset(rawTimestamp);
            if (!DateTimeOffset.TryParseExact(normalizedTimestamp, "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset timestamp) ||
                previous is DateTimeOffset earlier && timestamp < earlier)
                throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
            previous = timestamp;
            events.Add(new(type, timestamp, outcome));
        }
        return events;
    }

    private static string RequiredText(JsonElement root, string name, int maximumLength)
    {
        string? value = Safe(root, name, maximumLength, workflow: true);
        return value is not null && string.Equals(value, value.Trim(), StringComparison.Ordinal)
            ? value
            : throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
    }

    private static string NormalizeOffset(string value) =>
        value.Length >= 5 && value[^5] is '+' or '-' &&
        value.AsSpan(value.Length - 4).IndexOfAnyExceptInRange('0', '9') < 0
            ? value.Insert(value.Length - 2, ":")
            : value;

    public static Fse2ConnectorException MapProblem(QualifiedGatewayExecutionResult response, Fse2RetryClass retryClass)
    {
        string? safeUpstreamCode = null;
        if (response.Body.Length <= MaximumProblemBytes && IsProblemJson(response.ContentType))
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 12 });
                JsonElement root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object) throw new JsonException();
                foreach (string propertyName in new[] { "type", "code" })
                {
                    string? candidate = SafeProblemValue(root, propertyName);
                    if (candidate is null) continue;
                    int slash = candidate.LastIndexOf('/');
                    candidate = slash >= 0 ? candidate[(slash + 1)..] : candidate;
                    if (!OfficialProblemCodes.Contains(candidate)) continue;
                    safeUpstreamCode = candidate;
                    break;
                }
            }
            catch (Exception) { safeUpstreamCode = null; }
        }
        bool retryable = retryClass == Fse2RetryClass.SafeRetry && response.StatusCode is 429 or 502 or 503 or 504;
        Fse2ErrorCategory category = response.StatusCode is 429 or >= 500
            ? Fse2ErrorCategory.TemporarilyUnavailable
            : Fse2ErrorCategory.UpstreamRejected;
        return new(category, safeUpstreamCode ?? "FSE2_UPSTREAM_REJECTED", retryable, safeUpstreamCode);
    }

    private static bool IsProblemJson(string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType) ||
            contentType.Length > MaximumProblemContentTypeCharacters ||
            contentType.Any(char.IsControl))
            return false;

        ReadOnlySpan<char> value = contentType.AsSpan();
        int offset = 0;
        if (!TryReadHttpToken(value, ref offset, out ReadOnlySpan<char> type) ||
            offset >= value.Length || value[offset++] != '/' ||
            !TryReadHttpToken(value, ref offset, out ReadOnlySpan<char> subtype) ||
            !type.Equals("application", StringComparison.OrdinalIgnoreCase) ||
            !subtype.Equals("problem+json", StringComparison.OrdinalIgnoreCase))
            return false;

        SkipOptionalWhitespace(value, ref offset);
        while (offset < value.Length)
        {
            if (value[offset++] != ';') return false;
            SkipOptionalWhitespace(value, ref offset);
            if (!TryReadHttpToken(value, ref offset, out _)) return false;
            SkipOptionalWhitespace(value, ref offset);
            if (offset >= value.Length || value[offset++] != '=') return false;
            SkipOptionalWhitespace(value, ref offset);
            if (offset >= value.Length) return false;

            if (value[offset] == '"')
            {
                if (!TryReadHttpQuotedString(value, ref offset)) return false;
            }
            else if (!TryReadHttpToken(value, ref offset, out _))
            {
                return false;
            }
            SkipOptionalWhitespace(value, ref offset);
        }
        return true;
    }

    private static bool TryReadHttpToken(ReadOnlySpan<char> value, ref int offset, out ReadOnlySpan<char> token)
    {
        int start = offset;
        while (offset < value.Length && IsHttpTokenCharacter(value[offset])) offset++;
        token = value[start..offset];
        return token.Length > 0;
    }

    private static bool TryReadHttpQuotedString(ReadOnlySpan<char> value, ref int offset)
    {
        if (offset >= value.Length || value[offset++] != '"') return false;
        while (offset < value.Length)
        {
            char character = value[offset++];
            if (character == '"') return true;
            if (character == '\\')
            {
                if (offset >= value.Length || value[offset] is < (char)0x20 or > (char)0x7e) return false;
                offset++;
                continue;
            }
            if (character is < (char)0x20 or > (char)0x7e) return false;
        }
        return false;
    }

    private static void SkipOptionalWhitespace(ReadOnlySpan<char> value, ref int offset)
    {
        while (offset < value.Length && value[offset] == ' ') offset++;
    }

    private static bool IsHttpTokenCharacter(char value) =>
        char.IsAsciiLetterOrDigit(value) || value is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';

    private static string? SafeProblemValue(JsonElement root, string name)
    {
        JsonElement value = default;
        int matches = 0;
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (!string.Equals(property.Name, name, StringComparison.Ordinal)) continue;
            value = property.Value;
            matches++;
        }
        if (matches == 0 || value.ValueKind == JsonValueKind.Null) return null;
        if (matches != 1) throw new JsonException();
        if (value.ValueKind != JsonValueKind.String) throw new JsonException();
        string text = value.GetString()!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > 512 || text != text.Trim() || text.Any(char.IsControl)) throw new JsonException();
        return text;
    }

    private static string? Safe(JsonElement root, string name, int maximumLength, bool workflow = false)
    {
        if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String)
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        string text = value.GetString()!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > maximumLength || text.Any(char.IsControl))
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        if (!workflow && name != "warning" && !text.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        if (name == "warning" && !Fse2Validation.IsSafeCode(text))
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        return text;
    }

    private static string? SafeWarning(JsonElement root)
    {
        if (!root.TryGetProperty("warning", out JsonElement value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String)
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        string text = value.GetString()!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > 512 || text.Any(char.IsControl))
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        return "FSE2_UPSTREAM_WARNING";
    }
}
