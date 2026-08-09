using System.Net.Http.Headers;
using System.Text.Json;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>FSE2 orchestration over one Published, composite, final-revalidated organization authority.</summary>
public sealed class Fse2NationalConnector
{
    private readonly IGatewayInvocationAuthorizer authorizer;
    private readonly PublishedConnectorFse2ProfileResolver profiles;
    private readonly Fse2DispatchAuthorityRegistry dispatches;
    private readonly Rs256JwtSigner jwtSigner;
    private readonly PurposeBoundMutualTlsSender mutualTls;
    private readonly IFse2WorkflowCorrelationStore workflowStore;
    private readonly IFse2DispatchTestHook hook;

    public Fse2NationalConnector(IGatewayInvocationAuthorizer authorizer, PublishedConnectorFse2ProfileResolver profiles,
        Fse2DispatchAuthorityRegistry dispatches, Rs256JwtSigner jwtSigner, PurposeBoundMutualTlsSender mutualTls,
        IFse2WorkflowCorrelationStore workflowStore)
        : this(authorizer, profiles, dispatches, jwtSigner, mutualTls, workflowStore, NoOpFse2DispatchTestHook.Instance)
    {
    }

    internal Fse2NationalConnector(IGatewayInvocationAuthorizer authorizer, PublishedConnectorFse2ProfileResolver profiles,
        Fse2DispatchAuthorityRegistry dispatches, Rs256JwtSigner jwtSigner, PurposeBoundMutualTlsSender mutualTls,
        IFse2WorkflowCorrelationStore workflowStore, IFse2DispatchTestHook hook)
    {
        this.authorizer = authorizer; this.profiles = profiles; this.dispatches = dispatches; this.jwtSigner = jwtSigner;
        this.mutualTls = mutualTls; this.workflowStore = workflowStore; this.hook = hook;
    }

    public async Task<Fse2Response> InvokeAsync(GatewayClientPrincipal principal, string connectorId,
        Fse2Request request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectorId);
        ArgumentNullException.ThrowIfNull(request);
        Fse2RequestSnapshot payload = request.CaptureSnapshot();
        Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(request.Operation);

        AuthorizedGatewayInvocation authorized;
        try { authorized = await authorizer.AuthorizeAsync(principal, connectorId, operation.OperationId, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_OPERATION_GRANT_DENIED"); }
        if (!ReferenceEquals(authorized.Principal, principal) || !string.Equals(authorized.ConnectorId, connectorId, StringComparison.Ordinal) ||
            !string.Equals(authorized.OperationId, operation.OperationId, StringComparison.Ordinal))
            throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_OPERATION_GRANT_DENIED");

        Fse2PublishedProfileLookup lookup = new(principal.TenantId, principal.ApplicationId, principal.InstallationId,
            principal.Identity.EnvironmentId, connectorId, request.Operation);
        AuthorizedFse2Dispatch authority;
        try { authority = await profiles.ResolveAsync(lookup, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception) { throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_PROFILE_NOT_PUBLISHED"); }
        Fse2PublishedOrganizationProfile profile = authority.Profile;
        ValidateRequest(profile, operation, payload);
        Fse2WorkflowExecutionContext security = await ResolveSecurityContextAsync(profile, operation, payload, cancellationToken).ConfigureAwait(false);
        Uri endpoint = Fse2OperationCatalog.BuildEndpoint(profile.BaseEndpoint, request.Operation, request.ResourceIdentifier);
        Fse2DispatchLease lease = dispatches.Begin(authority, endpoint, hook);
        HttpRequestMessage? outbound = null;
        try
        {
            AuthenticationExecutionContext authenticationContext = Context(profile, operation, endpoint, profile.AuthenticationJwtProfileId, lease.Id);
            AuthenticationExecutionContext signatureContext = Context(profile, operation, endpoint, profile.SignatureJwtProfileId, lease.Id);
            AuthenticationExecutionContext mutualTlsContext = Context(profile, operation, endpoint, profile.MutualTlsProfileId, lease.Id);
            string authenticationJwt;
            string signatureJwt;
            try
            {
                authenticationJwt = await jwtSigner.SignJwtAsync(authenticationContext, profile.AuthenticationJwtProfileId, [], cancellationToken).ConfigureAwait(false);
                signatureJwt = await jwtSigner.SignJwtAsync(signatureContext, profile.SignatureJwtProfileId,
                    BuildSignatureClaims(profile, operation, payload, security), cancellationToken).ConfigureAwait(false);
                await hook.AfterBothJwtPreparedAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (AuthenticationPrimitiveException exception) { throw MapAuthenticationFailure(exception); }
            catch (Fse2ConnectorException) { throw; }
            catch (Exception) { throw AuthenticationFailure("FSE2_JWT_COMPOSITION_FAILED"); }

            outbound = BuildRequest(endpoint, operation, payload);
            dispatches.Prepare(outbound, lease, authenticationJwt, signatureJwt);
            MutualTlsAuthenticatedResponse authenticatedResponse;
            try { authenticatedResponse = await mutualTls.SendAsync(mutualTlsContext, profile.MutualTlsProfileId, outbound, cancellationToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (AuthenticationPrimitiveException exception) { throw MapAuthenticationFailure(exception); }
            catch (GatewayException) { throw Denied(Fse2ErrorCategory.UpstreamRejected, "FSE2_UPSTREAM_REJECTED", operation.RetryClass == Fse2RetryClass.SafeRetry); }
            catch (Fse2ConnectorException) { throw; }
            catch (Exception) { throw Denied(Fse2ErrorCategory.TemporarilyUnavailable, "FSE2_TRANSPORT_FAILED", operation.RetryClass == Fse2RetryClass.SafeRetry); }

            Fse2Response response = Fse2ResponseMapper.Map(authenticatedResponse.Response, principal.CorrelationId, operation);
            if (request.Operation is not (Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace) &&
                (response.WorkflowInstanceId is not null || response.TraceId is not null))
                await RecordWorkflowAsync(principal.CorrelationId, profile, request.Operation, response, security, cancellationToken).ConfigureAwait(false);
            return response;
        }
        finally
        {
            dispatches.Complete(lease, outbound);
            outbound?.Dispose();
        }
    }

    private static void ValidateRequest(Fse2PublishedOrganizationProfile profile, Fse2OperationDescriptor operation, Fse2RequestSnapshot payload)
    {
        Fse2Request request = payload.Source;
        if (payload.Document.Length > profile.MaximumDocumentBytes || payload.RequestBody.Length > 1024 * 1024)
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_PAYLOAD_TOO_LARGE");
        if (operation.HasDocument != !payload.Document.IsEmpty || operation.HasJsonBody != !payload.RequestBody.IsEmpty ||
            operation.RequiresResourceIdentifier != (request.ResourceIdentifier is not null))
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_REQUEST_SHAPE_DENIED");
        if (operation.HasJsonBody) Fse2Validation.ValidateJsonObject(payload.RequestBody);
        if (operation.HasDocument && request.DocumentContentType is not ("application/pdf" or "application/json"))
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_DOCUMENT_CONTENT_TYPE_DENIED");
        if (request.Operation != Fse2Operation.ValidateFhir && request.DocumentContentType == "application/json")
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_DOCUMENT_CONTENT_TYPE_DENIED");
        if (request.ClinicalClaims is null) throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_CLINICAL_CONTEXT_REQUIRED");
    }

    private async Task<Fse2WorkflowExecutionContext> ResolveSecurityContextAsync(Fse2PublishedOrganizationProfile profile,
        Fse2OperationDescriptor operation, Fse2RequestSnapshot payload, CancellationToken cancellationToken)
    {
        Fse2ClinicalClaims claims = payload.Source.ClinicalClaims!;
        if (operation.Action is Fse2Action action && operation.PurposeOfUse is Fse2PurposeOfUse purpose)
        {
            if (payload.Source.Operation != Fse2Operation.Delete && claims.ResourceHl7Type is null)
                throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_RESOURCE_HL7_TYPE_REQUIRED");
            Fse2OperationCatalog.ValidateOrganizationCombination(profile.SubjectRole, operation.OperationId, purpose, action);
            return new(action, purpose, claims, operation.OperationId);
        }

        try
        {
            Fse2WorkflowAuthorityScope scope = WorkflowScope(profile);
            Fse2WorkflowRecord stored = await workflowStore.ResolveAsync(scope, payload.Source.Operation,
                payload.Source.ResourceIdentifier!, cancellationToken).ConfigureAwait(false)
                ?? throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_NOT_FOUND");
            if (stored.Authority != scope || !Fse2Validation.IsSafeIdentifier(stored.OriginatingOperationId))
                throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_DENIED");
            Fse2OperationDescriptor origin = Fse2OperationCatalog.Get(stored.OriginatingOperation);
            if (!string.Equals(origin.OperationId, stored.OriginatingOperationId, StringComparison.Ordinal))
                throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_DENIED");
            Fse2OperationCatalog.ValidateOrganizationCombination(profile.SubjectRole, stored.OriginatingOperationId,
                stored.PurposeOfUse, stored.Action);
            return new(stored.Action, stored.PurposeOfUse, claims, stored.OriginatingOperationId);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception) { throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_NOT_FOUND"); }
    }

    private static List<JwtBoundClaim> BuildSignatureClaims(Fse2PublishedOrganizationProfile profile,
        Fse2OperationDescriptor operation, Fse2RequestSnapshot payload, Fse2WorkflowExecutionContext security)
    {
        List<JwtBoundClaim> claims =
        [
            Claim("subject_role", profile.SubjectRole), Claim("purpose_of_use", Fse2OperationCatalog.ClaimValue(security.PurposeOfUse)),
            Claim("subject_organization", profile.OrganizationDescription), Claim("subject_organization_id", profile.OrganizationDomainId),
            Claim("locality", profile.Locality), Claim("person_id", security.ClinicalClaims.PersonId),
            new("patient_consent", JsonSerializer.SerializeToElement(security.ClinicalClaims.PatientConsent)),
            Claim("action_id", Fse2OperationCatalog.ClaimValue(security.Action)), Claim("subject_application_id", profile.ApplicationId),
            Claim("subject_application_vendor", profile.ApplicationVendor), Claim("subject_application_version", profile.ApplicationVersion)
        ];
        if (security.ClinicalClaims.ResourceHl7Type is not null) claims.Add(Claim("resource_hl7_type", security.ClinicalClaims.ResourceHl7Type));
        if (operation.RequiresAttachmentHash) claims.Add(Claim("attachment_hash", Fse2Validation.ComputeAttachmentHash(payload.Document)));
        return claims;
    }

    private static JwtBoundClaim Claim(string name, string value) => new(name, JsonSerializer.SerializeToElement(value));

    private static HttpRequestMessage BuildRequest(Uri endpoint, Fse2OperationDescriptor operation, Fse2RequestSnapshot payload)
    {
        HttpRequestMessage outbound = new(operation.Method, endpoint);
        outbound.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (operation.HasDocument)
        {
            MultipartFormDataContent multipart = new();
            ByteArrayContent body = new(payload.RequestBody.ToArray());
            body.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            multipart.Add(body, "requestBody");
            ByteArrayContent file = new(payload.Document.ToArray());
            file.Headers.ContentType = new MediaTypeHeaderValue(payload.Source.DocumentContentType!);
            multipart.Add(file, "file", payload.Source.DocumentContentType == "application/json" ? "bundle.json" : "document.pdf");
            outbound.Content = multipart;
        }
        else if (operation.HasJsonBody)
        {
            outbound.Content = new ByteArrayContent(payload.RequestBody.ToArray());
            outbound.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }
        return outbound;
    }

    private static AuthenticationExecutionContext Context(Fse2PublishedOrganizationProfile profile,
        Fse2OperationDescriptor operation, Uri endpoint, string profileId, Guid dispatchId) =>
        new(profile.Authority.TenantId, profile.Authority.InstallationId, profile.Authority.ApplicationId,
            profile.Authority.EnvironmentId, profile.ConnectorVersionId, profile.Authority.ConnectorId,
            operation.OperationId, profileId, endpoint, dispatchId);

    private async Task RecordWorkflowAsync(Guid correlationId, Fse2PublishedOrganizationProfile profile,
        Fse2Operation operation, Fse2Response response, Fse2WorkflowExecutionContext security, CancellationToken cancellationToken)
    {
        try
        {
            await workflowStore.RecordAsync(correlationId, new(WorkflowScope(profile), operation, security.OperationReference,
                security.Action, security.PurposeOfUse, response.WorkflowInstanceId, response.TraceId), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { throw Denied(Fse2ErrorCategory.ResponseInvalid, "FSE2_WORKFLOW_RECORD_FAILED"); }
    }

    private static Fse2WorkflowAuthorityScope WorkflowScope(Fse2PublishedOrganizationProfile profile) => new(
        profile.Authority.TenantId, profile.Authority.ApplicationId, profile.Authority.InstallationId,
        profile.Authority.EnvironmentId, profile.ConnectorVersionId, profile.ConnectorVersion,
        profile.Authority.ConnectorId, profile.ProfileAuthorityId, profile.Revision, profile.ChecksumSha256);

    private static Fse2ConnectorException MapAuthenticationFailure(AuthenticationPrimitiveException failure)
    {
        Fse2ErrorCategory category = failure.Code.Contains("DESTINATION", StringComparison.Ordinal) || failure.Code.Contains("REQUEST-BOUNDARY", StringComparison.Ordinal)
            ? Fse2ErrorCategory.DestinationDenied : Fse2ErrorCategory.AuthenticationDenied;
        return new(category, Fse2Validation.IsSafeCode(failure.Code) ? failure.Code : "FSE2_AUTHENTICATION_DENIED", failure.Retryable);
    }

    private static Fse2ConnectorException AuthenticationFailure(string safeCode) => new(Fse2ErrorCategory.AuthenticationDenied, safeCode);
    private static Fse2ConnectorException Denied(Fse2ErrorCategory category, string code, bool retryable = false) => new(category, code, retryable);
    private sealed record Fse2WorkflowExecutionContext(Fse2Action Action, Fse2PurposeOfUse PurposeOfUse,
        Fse2ClinicalClaims ClinicalClaims, string OperationReference);
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
                    int slash = candidate.LastIndexOf('/'); candidate = slash >= 0 ? candidate[(slash + 1)..] : candidate;
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
