using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Tests;

public sealed class Fse2SyntheticEndToEndTests
{
    [Fact]
    public async Task FSE2_E2E_real_HTTPS_mTLS_dual_RS256_JWT_x5c_fixed_organization_subject_and_exact_hash_pass()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create);
        byte[] document = "%PDF-1.7\r\nsynthetic exact bytes\0\xff"u8.ToArray();

        Fse2Response response = await harness.Connector.InvokeAsync(
            harness.Principal,
            "fse2-national",
            Fse2Request.Create(document, "{}"u8.ToArray(), Fse2TestData.Claims()),
            TestContext.Current.CancellationToken);

        Assert.Equal(202, response.StatusCode);
        Assert.Equal("workflow-synthetic-001", response.WorkflowInstanceId);
        Assert.Equal(1, harness.Server.AcceptedRequests);
        Assert.Equal(Fse2Validation.ComputeAttachmentHash(document), harness.Server.ObservedAttachmentHash);
        Assert.Equal(harness.Material.SigningKeyRevision1Fingerprint(), harness.Server.ObservedX5cFingerprint);
        Assert.Equal(harness.Material.ClientCertificateRevision1Fingerprint(), harness.Server.ObservedClientFingerprint);
        Assert.NotEqual(harness.Server.ObservedX5cFingerprint, harness.Server.ObservedClientFingerprint);
        Assert.Equal(2, harness.Server.ObservedJwtCount);
        Assert.Single(harness.Workflow.Records);
    }

    [Fact]
    public async Task FSE2_AUTHZ_wrong_grant_denies_before_profile_provider_DNS_or_network()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create, grant: false);

        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.Connector.InvokeAsync(
            harness.Principal, "fse2-national", Fse2Request.Create(new byte[] { 1 }, "{}"u8.ToArray(), Fse2TestData.Claims()), TestContext.Current.CancellationToken));

        Assert.Equal("FSE2_OPERATION_GRANT_DENIED", denied.SafeCode);
        Assert.Equal(0, harness.Profiles.ResolveCalls);
        Assert.Equal(0, harness.Resources.Calls);
        Assert.Equal(0, harness.Hosts.Calls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Fact]
    public async Task FSE2_PRODUCTION_test_only_FHIR_is_denied_before_provider_DNS_or_network()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.ValidateFhir, environmentClass: Fse2EnvironmentClass.Production);

        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.Connector.InvokeAsync(
            harness.Principal, "fse2-national", Fse2Request.ValidateFhir(new byte[] { 1 }, "{}"u8.ToArray(), "application/json", Fse2TestData.Claims()), TestContext.Current.CancellationToken));

        Assert.Equal("FSE2_OPERATION_NOT_PRODUCTION_AVAILABLE", denied.SafeCode);
        Assert.Equal(0, harness.Resources.Calls);
        Assert.Equal(0, harness.Hosts.Calls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Theory]
    [InlineData(Fse2ResourceMode.SigningAsMutualTls)]
    [InlineData(Fse2ResourceMode.MutualTlsAsSigning)]
    [InlineData(Fse2ResourceMode.DisabledSigning)]
    public async Task FSE2_CERT_signing_mTLS_cross_use_and_disabled_resource_are_denied_before_network(Fse2ResourceMode mode)
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create, resourceMode: mode);

        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.Connector.InvokeAsync(
            harness.Principal, "fse2-national", Fse2Request.Create(new byte[] { 1, 2 }, "{}"u8.ToArray(), Fse2TestData.Claims()), TestContext.Current.CancellationToken));

        Assert.Equal(Fse2ErrorCategory.AuthenticationDenied, denied.Category);
        Assert.Equal(0, harness.Hosts.Calls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Fact]
    public async Task FSE2_ROTATION_mid_flight_signing_identity_substitution_is_denied_before_network()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create, resourceMode: Fse2ResourceMode.RotateSigningMidFlight);

        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.Connector.InvokeAsync(
            harness.Principal, "fse2-national", Fse2Request.Create(new byte[] { 1, 2 }, "{}"u8.ToArray(), Fse2TestData.Claims()), TestContext.Current.CancellationToken));

        Assert.Equal(Fse2ErrorCategory.AuthenticationDenied, denied.Category);
        Assert.Equal(0, harness.Hosts.Calls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Theory]
    [InlineData(false, 8, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData(true, 7, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData(true, 8, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")]
    public async Task FSE2_PROFILE_disabled_stale_revision_or_checksum_is_denied_before_crypto_and_network(bool enabled, long revision, string checksum)
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create);
        harness.Profiles.Stamp = new(revision, checksum, enabled);

        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.Connector.InvokeAsync(
            harness.Principal, "fse2-national", Fse2Request.Create(new byte[] { 1 }, "{}"u8.ToArray(), Fse2TestData.Claims()), TestContext.Current.CancellationToken));

        Assert.Equal("FSE2_PROFILE_STALE", denied.SafeCode);
        Assert.Equal(0, harness.Resources.Calls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Fact]
    public async Task FSE2_DESTINATION_wrong_endpoint_is_denied_by_policy_before_provider_or_network()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create);
        AuthenticationExecutionContext context = new(Fse2TestData.TenantId, Fse2TestData.InstallationId, Fse2TestData.ApplicationId,
            Fse2TestData.EnvironmentId, Fse2TestData.ConnectorVersionId, "fse2-national", "create", harness.Profile.AuthenticationJwtProfileId,
            new Uri("https://attacker.example/v1/documents"), Guid.NewGuid());

        AuthenticationPrimitiveException denied = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => harness.Policies.ResolveRs256Async(
            context, harness.Profile.AuthenticationJwtProfileId, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-POLICY-BOUNDARY", denied.Code);
        Assert.Equal(0, harness.Resources.Calls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Fact]
    public async Task FSE2_WORKFLOW_status_reuses_server_stored_claim_context_and_is_safe_retry()
    {
        Fse2WorkflowSecurityContext stored = new(Fse2Action.Create, Fse2PurposeOfUse.Treatment, Fse2TestData.Claims(), "create");
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.GetStatusByWorkflow, storedContext: stored);

        Fse2Response response = await harness.Connector.InvokeAsync(harness.Principal, "fse2-national",
            Fse2Request.GetStatusByWorkflow("workflow-synthetic-001"), TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(Fse2RetryClass.SafeRetry, response.RetryClass);
        Assert.Equal(1, harness.Workflow.ResolveCalls);
        Assert.Empty(harness.Workflow.Records);
    }

    [Fact]
    public async Task FSE2_WORKFLOW_tampered_stored_role_purpose_action_context_is_denied_before_crypto_or_network()
    {
        Fse2WorkflowSecurityContext tampered = new(Fse2Action.Delete, Fse2PurposeOfUse.Treatment, Fse2TestData.Claims(), "create");
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.GetStatusByWorkflow, storedContext: tampered);

        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.Connector.InvokeAsync(harness.Principal,
            "fse2-national", Fse2Request.GetStatusByWorkflow("workflow-synthetic-001"), TestContext.Current.CancellationToken));

        Assert.Equal("FSE2_ROLE_PURPOSE_ACTION_DENIED", denied.SafeCode);
        Assert.Equal(0, harness.Resources.Calls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_timeout_is_bounded_and_sanitized()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create, timeout: TimeSpan.FromMilliseconds(100), serverDelay: TimeSpan.FromSeconds(2));

        Fse2ConnectorException failure = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.Connector.InvokeAsync(
            harness.Principal, "fse2-national", Fse2Request.Create(new byte[] { 1, 2 }, "{}"u8.ToArray(), Fse2TestData.Claims()), TestContext.Current.CancellationToken));

        Assert.Contains(failure.Category, new[] { Fse2ErrorCategory.TemporarilyUnavailable, Fse2ErrorCategory.UpstreamRejected });
        Assert.DoesNotContain("TaskCanceledException", failure.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(Fse2JwtFailure.MissingAuthentication)]
    [InlineData(Fse2JwtFailure.MissingSignature)]
    [InlineData(Fse2JwtFailure.WrongIssuer)]
    [InlineData(Fse2JwtFailure.WrongAudience)]
    [InlineData(Fse2JwtFailure.UnexpectedNotBefore)]
    [InlineData(Fse2JwtFailure.Expired)]
    [InlineData(Fse2JwtFailure.WrongX5c)]
    [InlineData(Fse2JwtFailure.SubstitutedSigningCertificate)]
    [InlineData(Fse2JwtFailure.WrongOrganizationSubject)]
    [InlineData(Fse2JwtFailure.WrongRole)]
    [InlineData(Fse2JwtFailure.WrongPurpose)]
    [InlineData(Fse2JwtFailure.WrongAction)]
    [InlineData(Fse2JwtFailure.MalformedPersonCx)]
    [InlineData(Fse2JwtFailure.WrongDocumentHash)]
    public async Task FSE2_SYNTHETIC_server_rejects_dual_JWT_x5c_claim_and_hash_negative_matrix(Fse2JwtFailure failure)
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create);

        HttpStatusCode status = await harness.Server.SendNegativeAsync(failure, harness.Material, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(0, harness.Server.AcceptedRequests);
    }
}

public enum Fse2ResourceMode { Normal, SigningAsMutualTls, MutualTlsAsSigning, DisabledSigning, RotateSigningMidFlight }
public enum Fse2JwtFailure { MissingAuthentication, MissingSignature, WrongIssuer, WrongAudience, UnexpectedNotBefore, Expired, WrongX5c, SubstitutedSigningCertificate, WrongOrganizationSubject, WrongRole, WrongPurpose, WrongAction, MalformedPersonCx, WrongDocumentHash }

internal sealed class Fse2Harness : IAsyncDisposable
{
    private Fse2Harness(SyntheticAuthenticationMaterial material, SyntheticFse2Server server, Fse2PublishedOrganizationProfile profile,
        RecordingProfileSource profiles, RecordingResourceCatalog resources, RecordingHostResolver hosts, RecordingWorkflowStore workflow,
        Fse2AuthenticationPolicySource policies, Fse2NationalConnector connector, GatewayClientPrincipal principal)
    {
        Material = material; Server = server; Profile = profile; Profiles = profiles; Resources = resources; Hosts = hosts;
        Workflow = workflow; Policies = policies; Connector = connector; Principal = principal;
    }

    internal SyntheticAuthenticationMaterial Material { get; }
    internal SyntheticFse2Server Server { get; }
    internal Fse2PublishedOrganizationProfile Profile { get; }
    internal RecordingProfileSource Profiles { get; }
    internal RecordingResourceCatalog Resources { get; }
    internal RecordingHostResolver Hosts { get; }
    internal RecordingWorkflowStore Workflow { get; }
    internal Fse2AuthenticationPolicySource Policies { get; }
    internal Fse2NationalConnector Connector { get; }
    internal GatewayClientPrincipal Principal { get; }

    internal static async Task<Fse2Harness> StartAsync(Fse2Operation operation, bool grant = true,
        Fse2EnvironmentClass environmentClass = Fse2EnvironmentClass.Synthetic, Fse2ResourceMode resourceMode = Fse2ResourceMode.Normal,
        TimeSpan? timeout = null, TimeSpan? serverDelay = null, Fse2WorkflowSecurityContext? storedContext = null)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(now);
        try
        {
            SyntheticFse2Server server = await SyntheticFse2Server.StartAsync(material, operation, serverDelay ?? TimeSpan.Zero, TestContext.Current.CancellationToken);
            try
            {
                Fse2PublishedOrganizationProfile profile = Fse2TestData.Profile(operation, server.BaseEndpoint, environmentClass, timeout: timeout);
                server.Configure(profile);
                RecordingProfileSource profiles = new(profile);
                RecordingResourceCatalog resources = new(material, resourceMode);
                InMemoryProvider provider = Provider(material);
                FixedClock clock = new(now);
                Fse2AuthenticationPolicySource policies = new(profiles, resources, provider);
                Fse2AuthenticationResourceBindingResolver bindings = new(policies);
                Rs256JwtSigner signer = new(policies, bindings, provider, new InMemoryJwtReplayStore(256, clock), clock, certificatePublicMaterial: provider);
                RecordingHostResolver hosts = new();
                PurposeBoundMutualTlsSender mtls = new(policies, bindings, provider, provider, hosts,
                    new PurposeBoundMutualTlsTransportAdapter(new SystemRestrictedTransport(
                        new X509Certificate2Collection(material.RootCertificate), material.ServerCertificateFingerprint())), clock, new LoopbackAllowance());
                RecordingWorkflowStore workflow = new(storedContext);
                IGatewayRegistry registry = GrantRegistryProxy.Create(grant);
                GatewayInvocationAuthorizer authorizer = new(registry, clock);
                Fse2NationalConnector connector = new(authorizer, profiles, signer, mtls, workflow);
                RegisteredInstallationIdentity identity = new(Fse2TestData.InstallationId, Fse2TestData.TenantId, Fse2TestData.ApplicationId,
                    Fse2TestData.EnvironmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active, Guid.NewGuid(),
                    CredentialStatus.Active, [1], now.AddMinutes(-5), now.AddHours(1), "1.0.0", null);
                return new(material, server, profile, profiles, resources, hosts, workflow, policies, connector, new(identity, Guid.NewGuid()));
            }
            catch { await server.DisposeAsync(); throw; }
        }
        catch { material.Dispose(); throw; }
    }

    private static InMemoryProvider Provider(SyntheticAuthenticationMaterial material) => new(
        new Dictionary<string, string>(),
        certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal) { ["mtls-r1"] = material.ClientCertificateRevision1, ["mtls-r2"] = material.ClientCertificateRevision2 },
        signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal) { ["sign-r1"] = material.SigningKeyRevision1, ["sign-r2"] = material.SigningKeyRevision2 },
        certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal) { ["sign-r1"] = [material.RootCertificate], ["sign-r2"] = [material.RootCertificate] });

    public async ValueTask DisposeAsync() { await Server.DisposeAsync(); Material.Dispose(); }
}

internal sealed class RecordingProfileSource(Fse2PublishedOrganizationProfile profile) : IFse2PublishedProfileSource
{
    internal int ResolveCalls { get; private set; }
    internal Fse2PublishedProfileStamp? Stamp { get; set; }
    public Task<Fse2PublishedOrganizationProfile> ResolveAsync(Fse2PublishedProfileLookup lookup, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); ResolveCalls++;
        return Task.FromResult(profile);
    }
    public Task<Fse2PublishedProfileStamp> GetCurrentStampAsync(Fse2PublishedOrganizationProfile current, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Stamp ?? new(current.Revision, current.ChecksumSha256, current.Enabled));
    }
}

internal sealed class RecordingResourceCatalog(SyntheticAuthenticationMaterial material, Fse2ResourceMode mode) : IFse2AuthenticationResourceCatalog
{
    internal int Calls { get; private set; }
    public Task<Fse2AuthenticationResource> ResolveAsync(Fse2PublishedOrganizationProfile profile, string logicalBindingId, AuthenticationResourcePurpose purpose, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Calls++;
        bool signing = purpose == AuthenticationResourcePurpose.JwtSigning;
        X509Certificate2 certificate = signing ? material.SigningKeyRevision1 : material.ClientCertificateRevision1;
        string reference = signing ? "sign-r1" : "mtls-r1";
        AuthenticationResourceStatus status = mode == Fse2ResourceMode.DisabledSigning && signing ? AuthenticationResourceStatus.Disabled : AuthenticationResourceStatus.Active;
        if (mode == Fse2ResourceMode.SigningAsMutualTls && !signing) { certificate = material.SigningKeyRevision1; reference = "sign-r1"; }
        if (mode == Fse2ResourceMode.MutualTlsAsSigning && signing) { certificate = material.ClientCertificateRevision1; reference = "mtls-r1"; }
        if (mode == Fse2ResourceMode.RotateSigningMidFlight && signing && Calls >= 4) { certificate = material.SigningKeyRevision2; reference = "sign-r2"; }
        return Task.FromResult(new Fse2AuthenticationResource(logicalBindingId, purpose, status, reference, certificate.BoundMetadata()));
    }
}

internal sealed class RecordingHostResolver : IAuthenticationHostResolver
{
    internal int Calls { get; private set; }
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Calls++;
        return Task.FromResult(new[] { IPAddress.Loopback });
    }
}

internal sealed class LoopbackAllowance : IAuthenticationPrivateDestinationAllowance
{
    public bool IsAllowed(string host, IPAddress address) => string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) && IPAddress.IsLoopback(address);
}

internal sealed class RecordingWorkflowStore(Fse2WorkflowSecurityContext? stored) : IFse2WorkflowCorrelationStore
{
    internal List<(Fse2Response Response, Fse2WorkflowSecurityContext Context)> Records { get; } = [];
    internal int ResolveCalls { get; private set; }
    public Task RecordAsync(Guid correlationId, string connectorId, Fse2Operation operation, Fse2Response response, Fse2WorkflowSecurityContext securityContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Records.Add((response, securityContext)); return Task.CompletedTask;
    }
    public Task<Fse2WorkflowSecurityContext> ResolveAsync(Guid tenantId, Guid applicationId, Guid installationId, string connectorId, Fse2Operation statusOperation, string resourceIdentifier, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); ResolveCalls++;
        return Task.FromResult(stored ?? throw new InvalidOperationException("synthetic workflow context absent"));
    }
}

internal sealed class FixedClock(DateTimeOffset now) : IGatewayClock, IAuthenticationClock
{
    public DateTimeOffset UtcNow { get; } = now;
}

#pragma warning disable CA1852 // DispatchProxy requires a non-sealed proxy type.
internal class GrantRegistryProxy : DispatchProxy
{
    internal bool Grant { get; set; }
    internal static IGatewayRegistry Create(bool grant)
    {
        IGatewayRegistry value = Create<IGatewayRegistry, GrantRegistryProxy>();
        ((GrantRegistryProxy)value).Grant = grant;
        return value;
    }
    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
        targetMethod?.Name == nameof(IGatewayRegistry.IsGrantedAsync)
            ? Task.FromResult(Grant)
            : throw new NotSupportedException(targetMethod?.Name);
}
#pragma warning restore CA1852

internal sealed class SyntheticFse2Server : IAsyncDisposable
{
    private readonly WebApplication application;
    private readonly X509Certificate2 expectedSigning;
    private readonly X509Certificate2 expectedClient;
    private readonly Fse2Operation operation;
    private readonly TimeSpan delay;
    private Fse2PublishedOrganizationProfile? profile;

    private SyntheticFse2Server(WebApplication application, Uri baseEndpoint, X509Certificate2 expectedSigning,
        X509Certificate2 expectedClient, Fse2Operation operation, TimeSpan delay)
    {
        this.application = application; BaseEndpoint = baseEndpoint; this.expectedSigning = expectedSigning;
        this.expectedClient = expectedClient; this.operation = operation; this.delay = delay;
    }

    internal Uri BaseEndpoint { get; }
    internal int TotalRequests { get; private set; }
    internal int AcceptedRequests { get; private set; }
    internal int ObservedJwtCount { get; private set; }
    internal string? ObservedAttachmentHash { get; private set; }
    internal string? ObservedX5cFingerprint { get; private set; }
    internal string? ObservedClientFingerprint { get; private set; }
    internal void Configure(Fse2PublishedOrganizationProfile value) => profile = value;

    internal static async Task<SyntheticFse2Server> StartAsync(SyntheticAuthenticationMaterial material, Fse2Operation operation, TimeSpan delay, CancellationToken cancellationToken)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        string expectedClient = material.ClientCertificateRevision1Fingerprint();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(https =>
        {
            https.ServerCertificate = material.ServerCertificate;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, _, _) => certificate is not null &&
                string.Equals(certificate.Fingerprint(), expectedClient, StringComparison.Ordinal);
            https.CheckCertificateRevocation = false;
        })));
        WebApplication app = builder.Build();
        SyntheticFse2Server? instance = null;
        app.Map("/{**path}", context => instance!.HandleAsync(context));
        await app.StartAsync(cancellationToken);
        string address = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        Uri listener = new(address);
        instance = new(app, new Uri($"https://localhost:{listener.Port}/v1"), material.SigningKeyRevision1, material.ClientCertificateRevision1, operation, delay);
        return instance;
    }

    private async Task HandleAsync(HttpContext context)
    {
        TotalRequests++;
        try
        {
            if (profile is null) throw new InvalidOperationException();
            if (delay > TimeSpan.Zero) await Task.Delay(delay, context.RequestAborted);
            X509Certificate2 client = await context.Connection.GetClientCertificateAsync() ?? throw new CryptographicException();
            ObservedClientFingerprint = client.Fingerprint();
            if (!string.Equals(ObservedClientFingerprint, expectedClient.Fingerprint(), StringComparison.Ordinal)) throw new CryptographicException();
            string? auth = context.Request.Headers.Authorization.SingleOrDefault();
            string? signature = context.Request.Headers["FSE-JWT-Signature"].SingleOrDefault();
            if (auth is null || !auth.StartsWith("Bearer ", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(signature)) throw new CryptographicException();
            JsonElement authPayload = ValidateJwt(auth[7..], "auth:");
            JsonElement signaturePayload = ValidateJwt(signature, "integrity:");
            ObservedJwtCount = 2;
            ValidateCommon(authPayload);
            ValidateCommon(signaturePayload);
            ValidateSignatureClaims(signaturePayload);
            if (Fse2OperationCatalog.Get(operation).RequiresAttachmentHash)
            {
                IFormCollection form = await context.Request.ReadFormAsync(context.RequestAborted);
                IFormFile file = form.Files.GetFile("file") ?? throw new InvalidDataException();
                using MemoryStream bytes = new();
                await file.CopyToAsync(bytes, context.RequestAborted);
                ObservedAttachmentHash = Fse2Validation.ComputeAttachmentHash(bytes.ToArray());
                if (!string.Equals(signaturePayload.GetProperty("attachment_hash").GetString(), ObservedAttachmentHash, StringComparison.Ordinal)) throw new CryptographicException();
            }
            AcceptedRequests++;
            context.Response.StatusCode = operation is Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace ? 200 : 202;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"workflowInstanceId\":\"workflow-synthetic-001\",\"traceID\":\"trace-synthetic-001\",\"spanID\":\"span-001\"}", context.RequestAborted);
        }
        catch (Exception) when (!context.RequestAborted.IsCancellationRequested)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/problem+json";
            await context.Response.WriteAsync("{\"type\":\"FSE2_SYNTHETIC_AUTH_DENIED\"}");
        }
    }

    private JsonElement ValidateJwt(string token, string issuerPrefix)
    {
        string[] segments = token.Split('.');
        if (segments.Length != 3) throw new CryptographicException();
        using JsonDocument headerDocument = JsonDocument.Parse(Base64UrlDecode(segments[0]));
        JsonElement header = headerDocument.RootElement;
        if (header.GetProperty("alg").GetString() != "RS256" || header.GetProperty("typ").GetString() != "JWT") throw new CryptographicException();
        JsonElement.ArrayEnumerator x5c = header.GetProperty("x5c").EnumerateArray();
        if (!x5c.MoveNext()) throw new CryptographicException();
        byte[] der = Convert.FromBase64String(x5c.Current.GetString()!);
        if (x5c.MoveNext() || !der.AsSpan().SequenceEqual(expectedSigning.RawData)) throw new CryptographicException();
        ObservedX5cFingerprint = Convert.ToHexString(SHA256.HashData(der));
        using RSA rsa = expectedSigning.GetRSAPublicKey() ?? throw new CryptographicException();
        if (!rsa.VerifyData(Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]), Base64UrlDecode(segments[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) throw new CryptographicException();
        using JsonDocument payload = JsonDocument.Parse(Base64UrlDecode(segments[1]));
        JsonElement clone = payload.RootElement.Clone();
        string commonName = expectedSigning.GetNameInfo(X509NameType.SimpleName, false);
        if (clone.GetProperty("iss").GetString() != issuerPrefix + commonName) throw new CryptographicException();
        return clone;
    }

    private void ValidateCommon(JsonElement payload)
    {
        if (profile is null || payload.GetProperty("sub").GetString() != profile.SubjectCx || payload.GetProperty("aud").GetString() != profile.BaseEndpoint.AbsoluteUri.TrimEnd('/')) throw new CryptographicException();
        if (payload.TryGetProperty("nbf", out _)) throw new CryptographicException();
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (payload.GetProperty("iat").GetInt64() > now + 60 || payload.GetProperty("exp").GetInt64() <= now) throw new CryptographicException();
    }

    private void ValidateSignatureClaims(JsonElement payload)
    {
        if (profile is null) throw new CryptographicException();
        Fse2WorkflowSecurityContext expected = operation is Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace
            ? new(Fse2Action.Create, Fse2PurposeOfUse.Treatment, Fse2TestData.Claims(), "create")
            : new(Fse2OperationCatalog.Get(operation).Action!.Value, Fse2OperationCatalog.Get(operation).PurposeOfUse!.Value, Fse2TestData.Claims(), Fse2OperationCatalog.Get(operation).OperationId);
        if (payload.GetProperty("subject_role").GetString() != "DAP" ||
            payload.GetProperty("purpose_of_use").GetString() != Fse2OperationCatalog.ClaimValue(expected.PurposeOfUse) ||
            payload.GetProperty("action_id").GetString() != Fse2OperationCatalog.ClaimValue(expected.Action) ||
            payload.GetProperty("subject_organization").GetString() != profile.OrganizationDescription ||
            payload.GetProperty("subject_organization_id").GetString() != profile.OrganizationDomainId ||
            payload.TryGetProperty("use_subject_as_author", out _)) throw new CryptographicException();
        Fse2IheFormatter.ValidateCx(payload.GetProperty("person_id").GetString()!, false);
        Fse2IheFormatter.ValidateXon(payload.GetProperty("locality").GetString()!);
    }

    internal async Task<HttpStatusCode> SendNegativeAsync(Fse2JwtFailure failure, SyntheticAuthenticationMaterial material, CancellationToken cancellationToken)
    {
        if (profile is null) throw new InvalidOperationException();
        byte[] document = [1, 2, 3, 4];
        Dictionary<string, object> common = Payload(profile, DateTimeOffset.UtcNow);
        Dictionary<string, object> signatureClaims = Payload(profile, DateTimeOffset.UtcNow);
        signatureClaims["subject_role"] = "DAP";
        signatureClaims["purpose_of_use"] = "TREATMENT";
        signatureClaims["action_id"] = "CREATE";
        signatureClaims["subject_organization"] = profile.OrganizationDescription;
        signatureClaims["subject_organization_id"] = profile.OrganizationDomainId;
        signatureClaims["locality"] = profile.Locality;
        signatureClaims["person_id"] = Fse2TestData.Claims().PersonId;
        signatureClaims["patient_consent"] = true;
        signatureClaims["resource_hl7_type"] = Fse2TestData.Claims().ResourceHl7Type!;
        signatureClaims["subject_application_id"] = profile.ApplicationId;
        signatureClaims["subject_application_vendor"] = profile.ApplicationVendor;
        signatureClaims["subject_application_version"] = profile.ApplicationVersion;
        signatureClaims["attachment_hash"] = Fse2Validation.ComputeAttachmentHash(document);
        X509Certificate2 signing = material.SigningKeyRevision1;
        X509Certificate2 x5c = material.SigningKeyRevision1;
        switch (failure)
        {
            case Fse2JwtFailure.WrongIssuer: signatureClaims["iss"] = "integrity:wrong"; break;
            case Fse2JwtFailure.WrongAudience: signatureClaims["aud"] = "https://attacker.example/v1"; break;
            case Fse2JwtFailure.UnexpectedNotBefore: signatureClaims["nbf"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); break;
            case Fse2JwtFailure.Expired: signatureClaims["exp"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds(); break;
            case Fse2JwtFailure.WrongX5c: x5c = material.SigningKeyRevision2; break;
            case Fse2JwtFailure.SubstitutedSigningCertificate: signing = material.SigningKeyRevision2; x5c = material.SigningKeyRevision2; break;
            case Fse2JwtFailure.WrongOrganizationSubject: signatureClaims["sub"] = "00488410010^^^&2.16.840.1&ISO"; break;
            case Fse2JwtFailure.WrongRole: signatureClaims["subject_role"] = "ASS"; break;
            case Fse2JwtFailure.WrongPurpose: signatureClaims["purpose_of_use"] = "UPDATE"; break;
            case Fse2JwtFailure.WrongAction: signatureClaims["action_id"] = "DELETE"; break;
            case Fse2JwtFailure.MalformedPersonCx: signatureClaims["person_id"] = "RSSMRA80A01H501U^^&bad"; break;
            case Fse2JwtFailure.WrongDocumentHash: signatureClaims["attachment_hash"] = new string('0', 64); break;
        }
        string authToken = CreateJwt(material.SigningKeyRevision1, material.SigningKeyRevision1, common, "auth:");
        string signatureToken = CreateJwt(signing, x5c, signatureClaims, "integrity:");
        string expectedServerFingerprint = material.ServerCertificateFingerprint();
        using HttpClientHandler handler = new()
        {
            ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate is not null &&
                string.Equals(Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData())), expectedServerFingerprint, StringComparison.Ordinal),
            UseProxy = false,
            AllowAutoRedirect = false
        };
        handler.ClientCertificates.Add(new X509Certificate2(material.ClientCertificateRevision1));
        using HttpClient client = new(handler);
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(BaseEndpoint, "v1/documents"));
        if (failure != Fse2JwtFailure.MissingAuthentication) request.Headers.Authorization = new("Bearer", authToken);
        if (failure != Fse2JwtFailure.MissingSignature) request.Headers.TryAddWithoutValidation("FSE-JWT-Signature", signatureToken);
        MultipartFormDataContent multipart = new();
        multipart.Add(new ByteArrayContent("{}"u8.ToArray()), "requestBody");
        multipart.Add(new ByteArrayContent(document), "file", "document.pdf");
        request.Content = multipart;
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        return response.StatusCode;
    }

    private static Dictionary<string, object> Payload(Fse2PublishedOrganizationProfile profile, DateTimeOffset now) => new(StringComparer.Ordinal)
    {
        ["iss"] = "unused", ["aud"] = profile.BaseEndpoint.AbsoluteUri.TrimEnd('/'), ["sub"] = profile.SubjectCx,
        ["iat"] = now.ToUnixTimeSeconds(), ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N")
    };

    private static string CreateJwt(X509Certificate2 signing, X509Certificate2 x5c, Dictionary<string, object> payload, string issuerPrefix)
    {
        payload["iss"] = payload["iss"] is string current && current != "unused" ? current : issuerPrefix + signing.GetNameInfo(X509NameType.SimpleName, false);
        string header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> { ["alg"] = "RS256", ["typ"] = "JWT", ["x5c"] = new[] { Convert.ToBase64String(x5c.RawData) } }));
        string body = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload));
        using RSA rsa = signing.GetRSAPrivateKey() ?? throw new CryptographicException();
        byte[] signature = rsa.SignData(Encoding.ASCII.GetBytes(header + "." + body), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return header + "." + body + "." + Base64UrlEncode(signature);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Base64UrlDecode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    public async ValueTask DisposeAsync() { await application.StopAsync(); await application.DisposeAsync(); }
}

internal static class CertificateTestExtensions
{
    internal static string Fingerprint(this X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData));
    internal static string SigningKeyRevision1Fingerprint(this SyntheticAuthenticationMaterial value) => value.SigningKeyRevision1.Fingerprint();
    internal static string ClientCertificateRevision1Fingerprint(this SyntheticAuthenticationMaterial value) => value.ClientCertificateRevision1.Fingerprint();
    internal static string ServerCertificateFingerprint(this SyntheticAuthenticationMaterial value) => value.ServerCertificate.Fingerprint();
    internal static BoundResourcePublicMetadata BoundMetadata(this X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        byte[] spki = rsa?.ExportSubjectPublicKeyInfo() ?? ecdsa?.ExportSubjectPublicKeyInfo() ?? [];
        return new(certificate.Fingerprint(), Convert.ToHexString(SHA256.HashData(spki)), certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime(),
            rsa is not null ? "RSA" : "ECDSA", rsa?.KeySize ?? ecdsa?.KeySize ?? 0, certificate.SerialNumber);
    }
}
