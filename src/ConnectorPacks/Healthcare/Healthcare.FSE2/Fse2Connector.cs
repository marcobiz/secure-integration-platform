using System.Net.Http.Headers;
using System.Text.Json;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>
/// FSE2 Healthcare orchestration. It always composes two fresh RS256 JWTs and a separate purpose-bound
/// mTLS dispatch from server-owned Published state.
/// </summary>
public sealed class Fse2NationalConnector(
    IGatewayInvocationAuthorizer authorizer,
    IFse2PublishedProfileSource profiles,
    Rs256JwtSigner jwtSigner,
    PurposeBoundMutualTlsSender mutualTls,
    IFse2WorkflowCorrelationStore workflowStore)
{
    public async Task<Fse2Response> InvokeAsync(
        GatewayClientPrincipal principal,
        string connectorId,
        Fse2Request request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectorId);
        ArgumentNullException.ThrowIfNull(request);
        Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(request.Operation);
        AuthorizedGatewayInvocation authorized;
        try { authorized = await authorizer.AuthorizeAsync(principal, connectorId, operation.OperationId, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_OPERATION_GRANT_DENIED"); }
        if (!ReferenceEquals(authorized.Principal, principal) || !string.Equals(authorized.ConnectorId, connectorId, StringComparison.Ordinal) || !string.Equals(authorized.OperationId, operation.OperationId, StringComparison.Ordinal))
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_OPERATION_GRANT_DENIED");

        Fse2PublishedProfileLookup lookup = new(principal.TenantId, principal.ApplicationId, principal.InstallationId,
            principal.Identity.EnvironmentId, connectorId, request.Operation);
        Fse2PublishedOrganizationProfile profile = await ResolveProfileAsync(lookup, cancellationToken).ConfigureAwait(false);
        ValidateRequest(profile, operation, request);
        Fse2PublishedProfileStamp initialStamp = await CurrentStampAsync(profile, cancellationToken).ConfigureAwait(false);
        ValidateStamp(profile, initialStamp);

        Fse2WorkflowSecurityContext security = await ResolveSecurityContextAsync(profile, operation, request, cancellationToken).ConfigureAwait(false);
        Uri endpoint = Fse2OperationCatalog.BuildEndpoint(profile.BaseEndpoint, request.Operation, request.ResourceIdentifier);
        AuthenticationExecutionContext authenticationContext = Context(profile, operation, endpoint, profile.AuthenticationJwtProfileId, principal.CorrelationId);
        AuthenticationExecutionContext signatureContext = Context(profile, operation, endpoint, profile.SignatureJwtProfileId, principal.CorrelationId);
        AuthenticationExecutionContext mutualTlsContext = Context(profile, operation, endpoint, profile.MutualTlsProfileId, principal.CorrelationId);

        string authenticationJwt;
        string signatureJwt;
        try
        {
            authenticationJwt = await jwtSigner.SignJwtAsync(authenticationContext, profile.AuthenticationJwtProfileId, [], cancellationToken).ConfigureAwait(false);
            signatureJwt = await jwtSigner.SignJwtAsync(signatureContext, profile.SignatureJwtProfileId,
                BuildSignatureClaims(profile, operation, request, security), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (AuthenticationPrimitiveException exception) { throw MapAuthenticationFailure(exception); }
        catch (Exception) { throw AuthenticationFailure("FSE2_JWT_COMPOSITION_FAILED"); }

        Fse2PublishedProfileStamp currentStamp = await CurrentStampAsync(profile, cancellationToken).ConfigureAwait(false);
        ValidateStamp(profile, currentStamp);
        using HttpRequestMessage outbound = BuildRequest(endpoint, operation, request, authenticationJwt, signatureJwt);
        MutualTlsAuthenticatedResponse authenticatedResponse;
        try { authenticatedResponse = await mutualTls.SendAsync(mutualTlsContext, profile.MutualTlsProfileId, outbound, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (AuthenticationPrimitiveException exception) { throw MapAuthenticationFailure(exception); }
        catch (GatewayException) { throw new Fse2ConnectorException(Fse2ErrorCategory.UpstreamRejected, "FSE2_UPSTREAM_REJECTED", operation.RetryClass == Fse2RetryClass.SafeRetry); }
        catch (Exception) { throw new Fse2ConnectorException(Fse2ErrorCategory.TemporarilyUnavailable, "FSE2_TRANSPORT_FAILED", operation.RetryClass == Fse2RetryClass.SafeRetry); }

        Fse2Response response = Fse2ResponseMapper.Map(authenticatedResponse.Response, principal.CorrelationId, operation);
        if (request.Operation is not (Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace) && response.WorkflowInstanceId is not null)
            await RecordWorkflowAsync(principal.CorrelationId, connectorId, request.Operation, response, security, cancellationToken).ConfigureAwait(false);
        return response;
    }

    private async Task<Fse2PublishedOrganizationProfile> ResolveProfileAsync(Fse2PublishedProfileLookup lookup, CancellationToken cancellationToken)
    {
        try
        {
            Fse2PublishedOrganizationProfile profile = await profiles.ResolveAsync(lookup, cancellationToken).ConfigureAwait(false)
                ?? throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_PROFILE_NOT_PUBLISHED");
            Fse2PublishedOrganizationProfile.ValidateAuthority(profile, lookup);
            return profile;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception) { throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_PROFILE_NOT_PUBLISHED"); }
    }

    private async Task<Fse2PublishedProfileStamp> CurrentStampAsync(Fse2PublishedOrganizationProfile profile, CancellationToken cancellationToken)
    {
        try { return await profiles.GetCurrentStampAsync(profile, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_PROFILE_STAMP_UNAVAILABLE"); }
    }

    private static void ValidateStamp(Fse2PublishedOrganizationProfile profile, Fse2PublishedProfileStamp? stamp)
    {
        if (stamp is null || !stamp.Enabled || stamp.Revision != profile.Revision || !FixedHexEquals(stamp.ChecksumSha256, profile.ChecksumSha256))
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_PROFILE_STALE");
    }

    private static void ValidateRequest(Fse2PublishedOrganizationProfile profile, Fse2OperationDescriptor operation, Fse2Request request)
    {
        if (request.Document.Length > profile.MaximumDocumentBytes || request.RequestBody.Length > 1024 * 1024)
            throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_PAYLOAD_TOO_LARGE");
        if (operation.HasDocument != !request.Document.IsEmpty || operation.HasJsonBody != !request.RequestBody.IsEmpty || operation.RequiresResourceIdentifier != (request.ResourceIdentifier is not null))
            throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_REQUEST_SHAPE_DENIED");
        if (operation.HasJsonBody) Fse2Validation.ValidateJsonObject(request.RequestBody);
        if (operation.HasDocument && request.DocumentContentType is not ("application/pdf" or "application/json"))
            throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_DOCUMENT_CONTENT_TYPE_DENIED");
        if (request.Operation != Fse2Operation.ValidateFhir && request.DocumentContentType == "application/json")
            throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_DOCUMENT_CONTENT_TYPE_DENIED");
        if (request.Operation is Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace)
        {
            if (request.ClinicalClaims is not null) throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_STATUS_CALLER_CONTEXT_DENIED");
        }
        else if (request.ClinicalClaims is null)
            throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_CLINICAL_CONTEXT_REQUIRED");
    }

    private async Task<Fse2WorkflowSecurityContext> ResolveSecurityContextAsync(Fse2PublishedOrganizationProfile profile, Fse2OperationDescriptor operation, Fse2Request request, CancellationToken cancellationToken)
    {
        if (operation.Action is Fse2Action action && operation.PurposeOfUse is Fse2PurposeOfUse purpose)
        {
            Fse2ClinicalClaims claims = request.ClinicalClaims!;
            if (request.Operation != Fse2Operation.Delete && claims.ResourceHl7Type is null)
                throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_RESOURCE_HL7_TYPE_REQUIRED");
            Fse2OperationCatalog.ValidateOrganizationCombination(profile.SubjectRole, operation.OperationId, purpose, action);
            return new(action, purpose, claims, operation.OperationId);
        }
        try
        {
            Fse2WorkflowSecurityContext security = await workflowStore.ResolveAsync(profile.Authority.TenantId, profile.Authority.ApplicationId,
                profile.Authority.InstallationId, profile.Authority.ConnectorId, request.Operation, request.ResourceIdentifier!, cancellationToken).ConfigureAwait(false)
                ?? throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_NOT_FOUND");
            if (!Fse2Validation.IsSafeIdentifier(security.OperationReference) || security.ClinicalClaims is null)
                throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_DENIED");
            Fse2OperationCatalog.ValidateOrganizationCombination(profile.SubjectRole, security.OperationReference, security.PurposeOfUse, security.Action);
            return security;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception) { throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_NOT_FOUND"); }
    }

    private static List<JwtBoundClaim> BuildSignatureClaims(Fse2PublishedOrganizationProfile profile, Fse2OperationDescriptor operation, Fse2Request request, Fse2WorkflowSecurityContext security)
    {
        List<JwtBoundClaim> claims =
        [
            Claim("subject_role", profile.SubjectRole),
            Claim("purpose_of_use", Fse2OperationCatalog.ClaimValue(security.PurposeOfUse)),
            Claim("subject_organization", profile.OrganizationDescription),
            Claim("subject_organization_id", profile.OrganizationDomainId),
            Claim("locality", profile.Locality),
            Claim("person_id", security.ClinicalClaims.PersonId),
            new("patient_consent", JsonSerializer.SerializeToElement(security.ClinicalClaims.PatientConsent)),
            Claim("action_id", Fse2OperationCatalog.ClaimValue(security.Action)),
            Claim("subject_application_id", profile.ApplicationId),
            Claim("subject_application_vendor", profile.ApplicationVendor),
            Claim("subject_application_version", profile.ApplicationVersion)
        ];
        if (security.ClinicalClaims.ResourceHl7Type is not null) claims.Add(Claim("resource_hl7_type", security.ClinicalClaims.ResourceHl7Type));
        if (operation.RequiresAttachmentHash) claims.Add(Claim("attachment_hash", Fse2Validation.ComputeAttachmentHash(request.Document)));
        return claims;
    }

    private static JwtBoundClaim Claim(string name, string value) => new(name, JsonSerializer.SerializeToElement(value));

    private static HttpRequestMessage BuildRequest(Uri endpoint, Fse2OperationDescriptor operation, Fse2Request request, string authenticationJwt, string signatureJwt)
    {
        HttpRequestMessage outbound = new(operation.Method, endpoint);
        outbound.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authenticationJwt);
        if (!outbound.Headers.TryAddWithoutValidation("FSE-JWT-Signature", signatureJwt))
        {
            outbound.Dispose();
            throw AuthenticationFailure("FSE2_DUAL_JWT_HEADER_FAILED");
        }
        outbound.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (operation.HasDocument)
        {
            MultipartFormDataContent multipart = new();
            ByteArrayContent body = new(request.RequestBody.ToArray());
            body.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            multipart.Add(body, "requestBody");
            ByteArrayContent file = new(request.Document.ToArray());
            file.Headers.ContentType = new MediaTypeHeaderValue(request.DocumentContentType!);
            multipart.Add(file, "file", request.DocumentContentType == "application/json" ? "bundle.json" : "document.pdf");
            outbound.Content = multipart;
        }
        else if (operation.HasJsonBody)
        {
            outbound.Content = new ByteArrayContent(request.RequestBody.ToArray());
            outbound.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }
        return outbound;
    }

    private static AuthenticationExecutionContext Context(Fse2PublishedOrganizationProfile profile, Fse2OperationDescriptor operation, Uri endpoint, string profileId, Guid correlationId) =>
        new(profile.Authority.TenantId, profile.Authority.InstallationId, profile.Authority.ApplicationId, profile.Authority.EnvironmentId,
            profile.ConnectorVersionId, profile.Authority.ConnectorId, operation.OperationId, profileId, endpoint, correlationId);

    private async Task RecordWorkflowAsync(Guid correlationId, string connectorId, Fse2Operation operation, Fse2Response response, Fse2WorkflowSecurityContext security, CancellationToken cancellationToken)
    {
        try { await workflowStore.RecordAsync(correlationId, connectorId, operation, response, security, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_WORKFLOW_RECORD_FAILED"); }
    }

    private static Fse2ConnectorException MapAuthenticationFailure(AuthenticationPrimitiveException failure)
    {
        Fse2ErrorCategory category = failure.Code.Contains("DESTINATION", StringComparison.Ordinal) || failure.Code.Contains("REQUEST-BOUNDARY", StringComparison.Ordinal)
            ? Fse2ErrorCategory.DestinationDenied : Fse2ErrorCategory.AuthenticationDenied;
        return new(category, Fse2Validation.IsSafeCode(failure.Code) ? failure.Code : "FSE2_AUTHENTICATION_DENIED", failure.Retryable);
    }

    private static Fse2ConnectorException AuthenticationFailure(string safeCode) =>
        new(Fse2ErrorCategory.AuthenticationDenied, safeCode);

    private static bool FixedHexEquals(string left, string right) => Fse2Validation.IsSha256(left) && Fse2Validation.IsSha256(right) &&
        System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
}

/// <summary>RFC7807 and success response mapper retaining technical allowlisted metadata only.</summary>
public static class Fse2ResponseMapper
{
    public static Fse2Response Map(MutualTlsTransportResponse response, Guid correlationId, Fse2OperationDescriptor operation)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (!operation.SuccessStatusCodes.Contains(response.StatusCode)) throw MapProblem(response, operation.RetryClass);
        try
        {
            using JsonDocument document = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 16 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new JsonException();
            return new(response.StatusCode, correlationId, Safe(root, "workflowInstanceId", 512, workflow: true), Safe(root, "traceID", 128),
                Safe(root, "spanID", 128), Safe(root, "warning", 96), operation.RetryClass);
        }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception) { throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID"); }
    }

    public static Fse2ConnectorException MapProblem(MutualTlsTransportResponse response, Fse2RetryClass retryClass)
    {
        string safeCode = "FSE2_UPSTREAM_REJECTED";
        if (response.ContentType.StartsWith("application/problem+json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 12 });
                JsonElement root = document.RootElement;
                string? candidate = SafeProblemValue(root, "type") ?? SafeProblemValue(root, "code");
                if (candidate is not null)
                {
                    int slash = candidate.LastIndexOf('/');
                    candidate = slash >= 0 ? candidate[(slash + 1)..] : candidate;
                    if (Fse2Validation.IsSafeCode(candidate)) safeCode = candidate;
                }
            }
            catch (Exception) { safeCode = "FSE2_UPSTREAM_REJECTED"; }
        }
        bool retryable = retryClass == Fse2RetryClass.SafeRetry && response.StatusCode is 429 or 502 or 503 or 504;
        Fse2ErrorCategory category = response.StatusCode is 429 or >= 500 ? Fse2ErrorCategory.TemporarilyUnavailable : Fse2ErrorCategory.UpstreamRejected;
        return new(category, safeCode, retryable);
    }

    private static string? SafeProblemValue(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String) throw new JsonException();
        string text = value.GetString()!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > 512 || text != text.Trim() || text.Any(char.IsControl)) throw new JsonException();
        return text;
    }

    private static string? Safe(JsonElement root, string name, int maximumLength, bool workflow = false)
    {
        if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String) throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        string text = value.GetString()!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > maximumLength || text.Any(char.IsControl)) throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        if (!workflow && name != "warning" && !text.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        if (name == "warning" && !Fse2Validation.IsSafeCode(text)) throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        return text;
    }
}
