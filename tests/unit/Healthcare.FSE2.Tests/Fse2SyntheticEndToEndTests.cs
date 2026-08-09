using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
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
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SERVER_VALIDATION_TEST_missing_dual_header_or_malformed_JWT_is_rejected(bool missingSignature)
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create);
        HttpStatusCode status = await harness.Server.SendMalformedAsync(missingSignature, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(0, harness.Server.AcceptedRequests);
    }

    [Fact]
    public async Task CONNECTOR_SECURITY_PATH_real_Published_HTTPS_mTLS_dual_JWT_and_exact_payload_pass()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create);
        byte[] document = "%PDF-1.7\r\nexact\0\xff"u8.ToArray();
        Fse2Response response = await harness.InvokeAsync(Fse2Request.Create(document, "{}"u8.ToArray(), Fse2TestData.Claims()));

        Assert.Equal(202, response.StatusCode);
        Assert.Equal(1, harness.Server.AcceptedRequests);
        Assert.Equal(Fse2Validation.ComputeAttachmentHash(document), harness.Server.ObservedAttachmentHash);
        Assert.Equal(harness.Material.SigningKeyRevision1.Fingerprint(), harness.Server.ObservedX5cFingerprint);
        Assert.Equal(harness.Material.ClientCertificateRevision1.Fingerprint(), harness.Server.ObservedClientFingerprint);
        Assert.Equal(harness.Profile.SubjectCx, harness.Server.ObservedSubject);
        Assert.NotEqual(Fse2TestData.Claims().PersonId, harness.Server.ObservedSubject);
        Assert.Single(harness.Workflow.Records);
        Assert.DoesNotContain(typeof(Fse2WorkflowRecord).GetProperties(), value =>
            value.Name.Contains("Patient", StringComparison.OrdinalIgnoreCase) || value.Name.Contains("Clinical", StringComparison.OrdinalIgnoreCase) ||
            value.Name.Contains("Document", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CONNECTOR_SECURITY_PATH_invalidated_four_eyes_approval_denies_before_provider_and_network()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create);
        harness.State.Approval = harness.State.Approval with { InvalidatedAt = DateTimeOffset.UtcNow };
        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.InvokeAsync(
            Fse2Request.Create(new byte[] { 1 }, "{}"u8.ToArray(), Fse2TestData.Claims())));
        Assert.Equal("FSE2_FOUR_EYES_APPROVAL_DENIED", denied.SafeCode);
        Assert.Equal(0, harness.Provider.SignCalls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Fact]
    public async Task CONNECTOR_SECURITY_PATH_unauthorized_grant_denies_before_Published_provider_DNS_and_network()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create, grant: false);
        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.InvokeAsync(
            Fse2Request.Create(new byte[] { 1 }, "{}"u8.ToArray(), Fse2TestData.Claims())));
        Assert.Equal("FSE2_OPERATION_GRANT_DENIED", denied.SafeCode);
        Assert.Equal(0, harness.State.SnapshotCalls);
        Assert.Equal(0, harness.Provider.SignCalls);
        Assert.Equal(0, harness.Hosts.Calls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Theory]
    [InlineData(Fse2ProviderMode.StableSigningSubstitution)]
    [InlineData(Fse2ProviderMode.StableMutualTlsSubstitution)]
    [InlineData(Fse2ProviderMode.SigningAsMutualTls)]
    [InlineData(Fse2ProviderMode.MutualTlsAsSigning)]
    public async Task CONNECTOR_SECURITY_PATH_resource_substitution_or_cross_use_denies_before_network(Fse2ProviderMode mode)
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create, providerMode: mode);
        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.InvokeAsync(
            Fse2Request.Create(new byte[] { 1, 2 }, "{}"u8.ToArray(), Fse2TestData.Claims())));
        Assert.Equal(Fse2ErrorCategory.AuthenticationDenied, denied.Category);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Fact]
    public async Task CONNECTOR_SECURITY_PATH_arbitrary_endpoint_substitution_denies_before_provider_and_network()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create, endpointOverride: new("https://attacker.example/v1"));
        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.InvokeAsync(
            Fse2Request.Create(new byte[] { 1 }, "{}"u8.ToArray(), Fse2TestData.Claims())));
        Assert.Equal("FSE2_BASE_ENDPOINT_DENIED", denied.SafeCode);
        Assert.Equal(0, harness.Provider.SignCalls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Fact]
    public async Task CONNECTOR_SECURITY_PATH_test_only_operation_in_Production_denies_before_provider_and_network()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.ValidateFhir,
            environmentClass: Fse2EnvironmentClass.Production);
        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => harness.InvokeAsync(
            Fse2Request.ValidateFhir(new byte[] { 1 }, "{}"u8.ToArray(), "application/json", Fse2TestData.Claims())));
        Assert.Equal("FSE2_OPERATION_NOT_PRODUCTION_AVAILABLE", denied.SafeCode);
        Assert.Equal(0, harness.Provider.SignCalls);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Theory]
    [InlineData(Fse2Race.SigningAfterJwt)]
    [InlineData(Fse2Race.MutualTlsBeforeDispatch)]
    [InlineData(Fse2Race.ProfileBeforeDispatch)]
    [InlineData(Fse2Race.EndpointBeforeDispatch)]
    public async Task CONNECTOR_SECURITY_PATH_final_composite_authority_races_are_deterministically_denied(Fse2Race race)
    {
        BarrierDispatchHook hook = new(race == Fse2Race.SigningAfterJwt ? HookPoint.AfterJwt : HookPoint.BeforeFinal);
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create, hook: hook);
        Task<Fse2Response> invocation = harness.InvokeAsync(Fse2Request.Create(new byte[] { 1, 2, 3 }, "{}"u8.ToArray(), Fse2TestData.Claims()));
        await hook.Reached.Task.WaitAsync(TestContext.Current.CancellationToken);
        harness.State.Rotate(race, harness.Material);
        hook.Resume.TrySetResult();
        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => invocation);
        Assert.Equal(Fse2ErrorCategory.AuthenticationDenied, denied.Category);
        Assert.Equal(0, harness.Server.TotalRequests);
    }

    [Fact]
    public async Task CONNECTOR_SECURITY_PATH_payload_original_getter_and_signing_await_mutations_do_not_change_hash_or_body()
    {
        await using Fse2Harness harness = await Fse2Harness.StartAsync(Fse2Operation.Create, providerMode: Fse2ProviderMode.DelayedSigning);
        byte[] original = [1, 2, 3, 4, 5];
        Fse2Request request = Fse2Request.Create(original, "{}"u8.ToArray(), Fse2TestData.Claims());
        original[0] = 99;
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(request.Document, out ArraySegment<byte> exposed));
        exposed.Array![exposed.Offset + 1] = 98;
        Task<Fse2Response> invocation = harness.InvokeAsync(request);
        await harness.Provider.SigningReached.Task.WaitAsync(TestContext.Current.CancellationToken);
        original[2] = 97;
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(request.Document, out ArraySegment<byte> during));
        during.Array![during.Offset + 2] = 96;
        harness.Provider.ResumeSigning.TrySetResult();
        await invocation;
        byte[] expected = [1, 2, 3, 4, 5];
        Assert.Equal(Fse2Validation.ComputeAttachmentHash(expected), harness.Server.ObservedAttachmentHash);
        Assert.Equal(expected, harness.Server.ObservedDocument);
    }

    [Fact]
    public async Task CONNECTOR_SECURITY_PATH_workflow_status_uses_full_scope_and_persists_no_clinical_context()
    {
        await using Fse2Harness status = await Fse2Harness.StartAsync(Fse2Operation.GetStatusByWorkflow);
        status.Workflow.Stored = OriginatingRecord(status.Profile);
        Fse2Response response = await status.InvokeAsync(Fse2Request.GetStatusByWorkflow("workflow-synthetic-001", Fse2TestData.Claims()));
        Assert.Equal(200, response.StatusCode);
        Assert.Equal(1, status.Server.AcceptedRequests);
    }

    [Theory]
    [InlineData(WorkflowMutation.Tenant)]
    [InlineData(WorkflowMutation.Application)]
    [InlineData(WorkflowMutation.Installation)]
    [InlineData(WorkflowMutation.Environment)]
    [InlineData(WorkflowMutation.ProfileChecksum)]
    public async Task CONNECTOR_SECURITY_PATH_workflow_cross_authority_reuse_is_denied(WorkflowMutation mutation)
    {
        await using Fse2Harness status = await Fse2Harness.StartAsync(Fse2Operation.GetStatusByWorkflow);
        Fse2WorkflowRecord record = OriginatingRecord(status.Profile);
        status.Workflow.Stored = record with { Authority = Mutate(record.Authority, mutation) };
        Fse2ConnectorException denied = await Assert.ThrowsAsync<Fse2ConnectorException>(() => status.InvokeAsync(
            Fse2Request.GetStatusByWorkflow("workflow-synthetic-001", Fse2TestData.Claims())));
        Assert.Equal("FSE2_WORKFLOW_CONTEXT_NOT_FOUND", denied.SafeCode);
        Assert.Equal(0, status.Server.TotalRequests);
    }

    private static Fse2WorkflowAuthorityScope Mutate(Fse2WorkflowAuthorityScope value, WorkflowMutation mutation) => mutation switch
    {
        WorkflowMutation.Tenant => value with { TenantId = Guid.NewGuid() },
        WorkflowMutation.Application => value with { ApplicationId = Guid.NewGuid() },
        WorkflowMutation.Installation => value with { InstallationId = Guid.NewGuid() },
        WorkflowMutation.Environment => value with { EnvironmentId = Guid.NewGuid() },
        WorkflowMutation.ProfileChecksum => value with { PublishedChecksumSha256 = new string('A', 64), PublishedRevision = value.PublishedRevision + 1 },
        _ => throw new ArgumentOutOfRangeException(nameof(mutation))
    };

    private static Fse2WorkflowRecord OriginatingRecord(Fse2PublishedOrganizationProfile profile) => new(
        new(profile.Authority.TenantId, profile.Authority.ApplicationId, profile.Authority.InstallationId,
            profile.Authority.EnvironmentId, profile.ConnectorVersionId, profile.ConnectorVersion, profile.Authority.ConnectorId,
            profile.ProfileAuthorityId, profile.Revision, profile.ChecksumSha256), Fse2Operation.Create, "create",
        Fse2Action.Create, Fse2PurposeOfUse.Treatment, "workflow-synthetic-001", "trace-synthetic-001");
}

public enum Fse2ProviderMode { Normal, StableSigningSubstitution, StableMutualTlsSubstitution, SigningAsMutualTls, MutualTlsAsSigning, DelayedSigning }
public enum Fse2Race { SigningAfterJwt, MutualTlsBeforeDispatch, ProfileBeforeDispatch, EndpointBeforeDispatch }
public enum WorkflowMutation { Tenant, Application, Installation, Environment, ProfileChecksum }
internal enum HookPoint { AfterJwt, BeforeFinal }

internal sealed class BarrierDispatchHook(HookPoint point) : IFse2DispatchTestHook
{
    internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource Resume { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task AfterBothJwtPreparedAsync(CancellationToken cancellationToken) => point == HookPoint.AfterJwt ? Wait(cancellationToken) : Task.CompletedTask;
    public Task BeforeFinalRevalidationAsync(CancellationToken cancellationToken) => point == HookPoint.BeforeFinal ? Wait(cancellationToken) : Task.CompletedTask;
    private async Task Wait(CancellationToken cancellationToken) { Reached.TrySetResult(); await Resume.Task.WaitAsync(cancellationToken); }
}

internal sealed class Fse2Harness : IAsyncDisposable
{
    private Fse2Harness(SyntheticAuthenticationMaterial material, SyntheticFse2Server server, PublishedFse2TestState state,
        CountingProvider provider, RecordingHostResolver hosts, RecordingWorkflowStore workflow, Fse2NationalConnector connector,
        Fse2PublishedOrganizationProfile profile,
        GatewayClientPrincipal principal)
    {
        Material = material; Server = server; State = state; Provider = provider; Hosts = hosts; Workflow = workflow;
        Connector = connector; Profile = profile; Principal = principal;
    }

    internal SyntheticAuthenticationMaterial Material { get; }
    internal SyntheticFse2Server Server { get; }
    internal PublishedFse2TestState State { get; }
    internal CountingProvider Provider { get; }
    internal RecordingHostResolver Hosts { get; }
    internal RecordingWorkflowStore Workflow { get; }
    internal Fse2NationalConnector Connector { get; }
    internal Fse2PublishedOrganizationProfile Profile { get; }
    internal GatewayClientPrincipal Principal { get; }

    internal Task<Fse2Response> InvokeAsync(Fse2Request request) => Connector.InvokeAsync(Principal, "fse2-national", request, TestContext.Current.CancellationToken);

    internal static async Task<Fse2Harness> StartAsync(Fse2Operation operation, bool grant = true,
        Fse2EnvironmentClass environmentClass = Fse2EnvironmentClass.Synthetic, Fse2ProviderMode providerMode = Fse2ProviderMode.Normal,
        Uri? endpointOverride = null, IFse2DispatchTestHook? hook = null, Fse2WorkflowRecord? storedRecord = null)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(now);
        SyntheticFse2Server server = await SyntheticFse2Server.StartAsync(material, operation, TestContext.Current.CancellationToken);
        try
        {
            Uri endpoint = endpointOverride ?? (environmentClass == Fse2EnvironmentClass.Production ? Fse2EndpointAuthority.Production : server.BaseEndpoint);
            PublishedFse2TestState state = PublishedFse2TestState.Create(operation, environmentClass, endpoint, material);
            PublishedConnectorFse2ProfileResolver resolver = new(state.ConnectorStore, state.SecurityStore, new ConnectorDefinitionValidator(),
                Fse2SyntheticEndpointAuthority.CreateForTests(server.BaseEndpoint));
            Fse2PublishedOrganizationProfile? profile = null;
            if (environmentClass == Fse2EnvironmentClass.Synthetic && endpointOverride is null)
            {
                AuthorizedFse2Dispatch initial = await resolver.ResolveAsync(PublishedFse2TestState.Lookup(operation), TestContext.Current.CancellationToken);
                server.Configure(initial.Profile);
                profile = initial.Profile;
                state.ResetCounts();
            }
            CountingProvider provider = new(CreateProvider(material, providerMode), providerMode);
            FixedClock clock = new(now);
            Fse2DispatchAuthorityRegistry dispatches = new(resolver);
            Fse2AuthenticationPolicySource policies = new(dispatches, provider);
            Fse2AuthenticationResourceBindingResolver bindings = new(policies, dispatches);
            Rs256JwtSigner signer = new(policies, bindings, provider, new InMemoryJwtReplayStore(256, clock), clock, certificatePublicMaterial: provider);
            RecordingHostResolver hosts = new();
            IPurposeBoundMutualTlsTransport network = new PurposeBoundMutualTlsTransportAdapter(new SystemRestrictedTransport(
                new X509Certificate2Collection(material.RootCertificate), material.ServerCertificate.Fingerprint()));
            PurposeBoundMutualTlsSender mtls = new(policies, bindings, provider, provider, hosts,
                new Fse2FinalAuthorityTransport(dispatches, network), clock, new LoopbackAllowance());
            RecordingWorkflowStore workflow = new(storedRecord);
            GatewayInvocationAuthorizer authorizer = new(GrantRegistryProxy.Create(grant), clock);
            Fse2NationalConnector connector = new(authorizer, resolver, dispatches, signer, mtls, workflow, hook ?? NoOpFse2DispatchTestHook.Instance);
            RegisteredInstallationIdentity identity = new(Fse2TestData.InstallationId, Fse2TestData.TenantId, Fse2TestData.ApplicationId,
                Fse2TestData.EnvironmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active, Guid.NewGuid(),
                CredentialStatus.Active, [1], now.AddMinutes(-5), now.AddHours(1), "1.0.0", null);
            return new(material, server, state, provider, hosts, workflow, connector, profile!, new(identity, Guid.NewGuid()));
        }
        catch { await server.DisposeAsync(); material.Dispose(); throw; }
    }

    private static InMemoryProvider CreateProvider(SyntheticAuthenticationMaterial material, Fse2ProviderMode mode)
    {
        X509Certificate2 signing = mode is Fse2ProviderMode.StableSigningSubstitution ? material.SigningKeyRevision2 :
            mode is Fse2ProviderMode.MutualTlsAsSigning ? material.ClientCertificateRevision1 : material.SigningKeyRevision1;
        X509Certificate2 mtls = mode is Fse2ProviderMode.StableMutualTlsSubstitution ? material.ClientCertificateRevision2 :
            mode is Fse2ProviderMode.SigningAsMutualTls ? material.SigningKeyRevision1 : material.ClientCertificateRevision1;
        return new(new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal) { ["mtls-r1"] = mtls, ["mtls-r2"] = material.ClientCertificateRevision2 },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal) { ["sign-r1"] = signing, ["sign-r2"] = material.SigningKeyRevision2 },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            { ["sign-r1"] = [material.RootCertificate], ["sign-r2"] = [material.RootCertificate] });
    }

    public async ValueTask DisposeAsync() { await Server.DisposeAsync(); Material.Dispose(); }
}

internal sealed class PublishedFse2TestState
{
    private PublishedFse2TestState() { ConnectorStore = new ConnectorStoreProxy(this).Create(); SecurityStore = new SecurityStoreProxy(this).Create(); }
    internal required Fse2Operation Operation { get; init; }
    internal required Fse2EnvironmentClass EnvironmentClass { get; init; }
    internal required Uri Endpoint { get; set; }
    internal required SyntheticAuthenticationMaterial Material { get; init; }
    internal required PublishedConnectorSnapshot Snapshot { get; set; }
    internal required byte[] BundleDigest { get; set; }
    internal required ConnectorApprovalRecord Approval { get; set; }
    internal IConnectorConfigurationStore ConnectorStore { get; }
    internal IAdminSecurityStore SecurityStore { get; }
    internal int SnapshotCalls { get; set; }

    internal static PublishedFse2TestState Create(Fse2Operation operation, Fse2EnvironmentClass environmentClass, Uri endpoint, SyntheticAuthenticationMaterial material)
    {
        PublishedFse2TestState state = new() { Operation = operation, EnvironmentClass = environmentClass, Endpoint = endpoint, Material = material,
            Snapshot = null!, BundleDigest = [], Approval = null! };
        state.Rebuild(1, 1, material.SigningKeyRevision1, material.ClientCertificateRevision1, endpoint, organizationIdentifier: "01114601006");
        return state;
    }

    internal static Fse2PublishedProfileLookup Lookup(Fse2Operation operation) => new(Fse2TestData.TenantId, Fse2TestData.ApplicationId,
        Fse2TestData.InstallationId, Fse2TestData.EnvironmentId, "fse2-national", operation);
    internal void ResetCounts() => SnapshotCalls = 0;

    internal void Rotate(Fse2Race race, SyntheticAuthenticationMaterial material)
    {
        Uri endpoint = race == Fse2Race.EndpointBeforeDispatch ? new Uri(Endpoint.AbsoluteUri.Replace("/v1", "/v1-rotated", StringComparison.Ordinal)) : Endpoint;
        X509Certificate2 signing = race == Fse2Race.SigningAfterJwt ? material.SigningKeyRevision2 : material.SigningKeyRevision1;
        X509Certificate2 mtls = race == Fse2Race.MutualTlsBeforeDispatch ? material.ClientCertificateRevision2 : material.ClientCertificateRevision1;
        string organization = race == Fse2Race.ProfileBeforeDispatch ? "00488410010" : "01114601006";
        Rebuild(Snapshot.Stamp.PublicationRevision + 1, Snapshot.Bindings.Revision + 1, signing, mtls, endpoint, organization);
    }

    private void Rebuild(long publicationRevision, long bindingRevision, X509Certificate2 signing, X509Certificate2 mtls, Uri endpoint, string organizationIdentifier)
    {
        Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(Operation);
        BoundResourcePublicMetadata signingMetadata = signing.BoundMetadata();
        BoundResourcePublicMetadata mtlsMetadata = mtls.BoundMetadata();
        Fse2ProfileEnvelope envelope = new(EnvironmentClass, organizationIdentifier, "2.16.840.1.113883.2.9.4.1.2",
            "Azienda Sanitaria Sintetica", "asl-synthetic", "Azienda Sanitaria Sintetica", "2.16.840.1.113883.2.9.4.1.1", "001",
            "broker-gateway", "Synthetic Vendor", "1.0.0", signingMetadata.FingerprintSha256, signingMetadata.SubjectPublicKeyInfoSha256,
            signingMetadata.Version, signingMetadata.NotBefore.ToUnixTimeSeconds(), signingMetadata.NotAfter.ToUnixTimeSeconds(), "RSA",
            signingMetadata.PublicKeySize, mtlsMetadata.FingerprintSha256, mtlsMetadata.SubjectPublicKeyInfoSha256, mtlsMetadata.Version);
        string definitionJson = JsonSerializer.Serialize(new
        {
            schemaVersion = "1.0", connectorId = "fse2-national", version = "1.0.0", displayName = "FSE2 National",
            description = PublishedConnectorFse2ProfileResolver.EncodeProfileForTests(envelope),
            bindings = new { endpoints = new[] { new { name = "fse2-endpoint" } }, secrets = new object[] { new { name = "fse2-signing", kind = "opaque" }, new { name = "fse2-mtls", kind = "clientCertificate" } } },
            operations = new[] { new { operationId = descriptor.OperationId, endpointBinding = "fse2-endpoint", method = descriptor.Method.Method,
                path = "/" + descriptor.RelativePath, request = new { contentType = "application/json", maximumBytes = 8 * 1024 * 1024 },
                response = new { maximumBytes = 64 * 1024 }, authentication = new { kind = "apiKeyAndMtls", secretBinding = "fse2-signing",
                    headerName = "X-FSE2-Signing-Authority", certificateBinding = "fse2-mtls" }, timeoutMs = 5000,
                redirectPolicy = "deny", allowedClientHeaders = Array.Empty<string>(), idempotent = false, maximumRetries = 0 } }
        });
        using JsonDocument parsed = JsonDocument.Parse(definitionJson);
        ValidatedConnectorDefinition validated = new ConnectorDefinitionValidator().ValidateRequired(parsed.RootElement);
        byte[] definitionChecksum = Convert.FromHexString(validated.ChecksumSha256);
        string bindingChecksum = Hash($"binding-{bindingRevision}-{endpoint}-{signingMetadata.Version}-{mtlsMetadata.Version}");
        ProviderResourceBinding signingBinding = new("synthetic", "Synthetic", "synthetic", "signing", ProviderResourceType.Secret,
            "Signing", Fse2TestData.EnvironmentId, "fse2-national", descriptor.OperationId, signingMetadata.Version, bindingRevision,
            null, null, Hash($"sign-{bindingRevision}-{signingMetadata.Version}"));
        CertificatePublicMetadata certificateMetadata = new(mtlsMetadata.FingerprintSha256, mtls.Subject, mtls.Issuer,
            mtlsMetadata.NotBefore, mtlsMetadata.NotAfter, mtlsMetadata.KeyAlgorithm, mtlsMetadata.PublicKeySize, mtlsMetadata.Version);
        ProviderResourceBinding mtlsBinding = new("synthetic", "Synthetic", "synthetic", "mtls", ProviderResourceType.ClientCertificate,
            "mTLS", Fse2TestData.EnvironmentId, "fse2-national", descriptor.OperationId, mtlsMetadata.Version, bindingRevision,
            bindingRevision, certificateMetadata, Hash($"mtls-{bindingRevision}-{mtlsMetadata.Version}"));
        ConnectorVersionRecord version = new(Fse2TestData.ConnectorVersionId, Fse2TestData.ConnectorId, "fse2-national", "1.0.0", "1.0",
            ConnectorVersionState.Published, validated.CanonicalJson, definitionChecksum, "author", DateTimeOffset.UtcNow, 3,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        ConnectorBindingSet bindings = new(Fse2TestData.BindingId, Fse2TestData.ConnectorId, Fse2TestData.ConnectorVersionId,
            Fse2TestData.EnvironmentId, new Dictionary<string, Uri> { ["fse2-endpoint"] = endpoint },
            new Dictionary<string, ProviderResourceBinding> { ["fse2-signing"] = signingBinding },
            new Dictionary<string, ProviderResourceBinding> { ["fse2-mtls"] = mtlsBinding }, bindingRevision, bindingChecksum,
            ConnectorBindingState.Active, DateTimeOffset.UtcNow, "binder");
        Snapshot = new(version, bindings, new(version.Id, publicationRevision, bindingRevision, bindingChecksum,
            Hash($"resources-{bindingRevision}")), new Dictionary<string, string> { ["fse2-signing"] = signing == Material.SigningKeyRevision2 ? "sign-r2" : "sign-r1" },
            new Dictionary<string, string> { ["fse2-mtls"] = mtls == Material.ClientCertificateRevision2 ? "mtls-r2" : "mtls-r1" });
        BundleDigest = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"bundle-{bindingRevision}"));
        Approval = new(Guid.NewGuid(), version.Id, validated.ChecksumSha256, Convert.ToHexString(BundleDigest), Guid.NewGuid(), Guid.NewGuid(), null,
            ConnectorApprovalStatus.Approved, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, null, null, null);
    }

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)));
}

#pragma warning disable CA1852
internal abstract class InterfaceProxy<T> where T : class
{
    internal T Create() { T value = DispatchProxy.Create<T, InterfaceProxyImplementation<T>>(); ((InterfaceProxyImplementation<T>)(object)value).Handler = InvokeCore; return value; }
    protected abstract object? InvokeCore(MethodInfo method, object?[]? args);
}
internal class InterfaceProxyImplementation<T> : DispatchProxy where T : class
{
    internal Func<MethodInfo, object?[]?, object?>? Handler { get; set; }
    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => Handler!(targetMethod!, args);
}
internal sealed class ConnectorStoreProxy(PublishedFse2TestState state) : InterfaceProxy<IConnectorConfigurationStore>
{
    protected override object? InvokeCore(MethodInfo method, object?[]? args) => method.Name switch
    {
        nameof(IConnectorConfigurationStore.GetPublishedSnapshotAsync) => Snapshot(args!),
        nameof(IConnectorConfigurationStore.GetBindingBundleDigestAsync) => Task.FromResult(state.BundleDigest.ToArray()),
        _ => throw new NotSupportedException(method.Name)
    };
    private Task<PublishedConnectorSnapshot?> Snapshot(object?[] args)
    {
        state.SnapshotCalls++;
        PublishedConnectorAccessContext access = (PublishedConnectorAccessContext)args[2]!;
        if ((string)args[0]! != "fse2-national" || (Guid)args[1]! != Fse2TestData.EnvironmentId ||
            access.TenantId != Fse2TestData.TenantId || access.ApplicationId != Fse2TestData.ApplicationId ||
            access.InstallationId != Fse2TestData.InstallationId || access.OperationId != Fse2OperationCatalog.Get(state.Operation).OperationId)
            return Task.FromResult<PublishedConnectorSnapshot?>(null);
        return Task.FromResult<PublishedConnectorSnapshot?>(state.Snapshot);
    }
}
internal sealed class SecurityStoreProxy(PublishedFse2TestState state) : InterfaceProxy<IAdminSecurityStore>
{
    protected override object? InvokeCore(MethodInfo method, object?[]? args) => method.Name == nameof(IAdminSecurityStore.ListApprovalsAsync)
        ? Task.FromResult<IReadOnlyList<ConnectorApprovalRecord>>([state.Approval]) : throw new NotSupportedException(method.Name);
}
#pragma warning restore CA1852

internal sealed class CountingProvider(InMemoryProvider inner, Fse2ProviderMode mode) : ISigningKeyProvider,
    IClientCertificateProvider, ICertificateMetadataProvider, ICertificatePublicMaterialProvider
{
    internal int SignCalls { get; private set; }
    internal TaskCompletionSource SigningReached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource ResumeSigning { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public async Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken)
    {
        SignCalls++;
        if (mode == Fse2ProviderMode.DelayedSigning && SignCalls == 1)
        {
            SigningReached.TrySetResult();
            await ResumeSigning.Task.WaitAsync(cancellationToken);
        }
        return await inner.SignDigestAsync(logicalReference, algorithm, digest, cancellationToken);
    }
    public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken) => inner.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);
    public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) => inner.GetClientCertificateAsync(logicalReference, cancellationToken);
    public Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken) => inner.GetPublicMetadataAsync(logicalReference, cancellationToken);
    public Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken) => inner.GetPublicMaterialAsync(logicalReference, cancellationToken);
}

internal sealed class RecordingHostResolver : IAuthenticationHostResolver
{
    internal int Calls { get; private set; }
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) { Calls++; return Task.FromResult(new[] { IPAddress.Loopback }); }
}
internal sealed class LoopbackAllowance : IAuthenticationPrivateDestinationAllowance
{
    public bool IsAllowed(string host, IPAddress address) => string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) && IPAddress.IsLoopback(address);
}
internal sealed class RecordingWorkflowStore(Fse2WorkflowRecord? stored) : IFse2WorkflowCorrelationStore
{
    internal List<Fse2WorkflowRecord> Records { get; } = [];
    internal Fse2WorkflowRecord? Stored { get; set; } = stored;
    public Task RecordAsync(Guid correlationId, Fse2WorkflowRecord record, CancellationToken cancellationToken) { Records.Add(record); return Task.CompletedTask; }
    public Task<Fse2WorkflowRecord> ResolveAsync(Fse2WorkflowAuthorityScope authority, Fse2Operation statusOperation, string resourceIdentifier, CancellationToken cancellationToken)
    {
        if (Stored is null || Stored.Authority != authority || (statusOperation == Fse2Operation.GetStatusByWorkflow && Stored.WorkflowInstanceId != resourceIdentifier) ||
            (statusOperation == Fse2Operation.GetStatusByTrace && Stored.TraceId != resourceIdentifier)) throw new InvalidOperationException();
        return Task.FromResult(Stored);
    }
}
internal sealed class FixedClock(DateTimeOffset now) : IGatewayClock, IAuthenticationClock { public DateTimeOffset UtcNow { get; } = now; }

#pragma warning disable CA1852
internal class GrantRegistryProxy : DispatchProxy
{
    public GrantRegistryProxy() { }
    internal static IGatewayRegistry Create(bool grant) { IGatewayRegistry result = Create<IGatewayRegistry, GrantRegistryProxy>(); ((GrantRegistryProxy)result).Grant = grant; return result; }
    internal bool Grant { get; set; }
    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => targetMethod?.Name == nameof(IGatewayRegistry.IsGrantedAsync)
        ? Task.FromResult(Grant) : throw new NotSupportedException(targetMethod?.Name);
}
#pragma warning restore CA1852

internal sealed class SyntheticFse2Server : IAsyncDisposable
{
    private readonly WebApplication application;
    private readonly X509Certificate2 expectedSigning;
    private readonly X509Certificate2 expectedClient;
    private readonly string expectedServerFingerprint;
    private readonly Fse2Operation operation;
    private Fse2PublishedOrganizationProfile? profile;
    private SyntheticFse2Server(WebApplication application, Uri baseEndpoint, X509Certificate2 signing, X509Certificate2 client,
        string serverFingerprint, Fse2Operation operation)
    { this.application = application; BaseEndpoint = baseEndpoint; expectedSigning = signing; expectedClient = client; expectedServerFingerprint = serverFingerprint; this.operation = operation; }
    internal Uri BaseEndpoint { get; }
    internal int TotalRequests { get; private set; }
    internal int AcceptedRequests { get; private set; }
    internal string? ObservedAttachmentHash { get; private set; }
    internal byte[]? ObservedDocument { get; private set; }
    internal string? ObservedX5cFingerprint { get; private set; }
    internal string? ObservedClientFingerprint { get; private set; }
    internal string? ObservedSubject { get; private set; }
    internal void Configure(Fse2PublishedOrganizationProfile value) => profile = value;

    internal static async Task<SyntheticFse2Server> StartAsync(SyntheticAuthenticationMaterial material, Fse2Operation operation, CancellationToken cancellationToken)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        string expectedClient = material.ClientCertificateRevision1.Fingerprint();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(https =>
        {
            https.ServerCertificate = material.ServerCertificate; https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, _, _) => certificate is not null && certificate.Fingerprint() == expectedClient;
            https.CheckCertificateRevocation = false;
        })));
        WebApplication app = builder.Build();
        SyntheticFse2Server? instance = null;
        app.Map("/{**path}", context => instance!.HandleAsync(context));
        await app.StartAsync(cancellationToken);
        Uri listener = new(app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single());
        instance = new(app, new Uri($"https://localhost:{listener.Port}/v1"), material.SigningKeyRevision1,
            material.ClientCertificateRevision1, material.ServerCertificate.Fingerprint(), operation);
        return instance;
    }

    internal async Task<HttpStatusCode> SendMalformedAsync(bool missingSignature, CancellationToken cancellationToken)
    {
        using HttpClientHandler handler = new() { UseProxy = false, AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate is not null && certificate.Fingerprint() == expectedServerFingerprint };
        handler.ClientCertificates.Add(new X509Certificate2(expectedClient));
        using HttpClient client = new(handler);
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(BaseEndpoint.AbsoluteUri + "/documents"));
        request.Headers.Authorization = new("Bearer", "malformed.jwt.value");
        if (!missingSignature) request.Headers.TryAddWithoutValidation("FSE-JWT-Signature", "malformed.jwt.value");
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        return response.StatusCode;
    }

    private async Task HandleAsync(HttpContext context)
    {
        TotalRequests++;
        try
        {
            if (profile is null) throw new CryptographicException();
            X509Certificate2 client = await context.Connection.GetClientCertificateAsync() ?? throw new CryptographicException();
            ObservedClientFingerprint = client.Fingerprint();
            if (ObservedClientFingerprint != expectedClient.Fingerprint()) throw new CryptographicException();
            string auth = context.Request.Headers.Authorization.SingleOrDefault() ?? throw new CryptographicException();
            string signature = context.Request.Headers["FSE-JWT-Signature"].SingleOrDefault() ?? throw new CryptographicException();
            ValidateJwt(auth[7..], "auth:", signatureClaims: false);
            JsonElement payload = ValidateJwt(signature, "integrity:", signatureClaims: true);
            if (Fse2OperationCatalog.Get(operation).RequiresAttachmentHash)
            {
                IFormFile file = (await context.Request.ReadFormAsync()).Files.GetFile("file") ?? throw new CryptographicException();
                using MemoryStream bytes = new(); await file.CopyToAsync(bytes); ObservedDocument = bytes.ToArray();
                ObservedAttachmentHash = Fse2Validation.ComputeAttachmentHash(ObservedDocument);
                if (payload.GetProperty("attachment_hash").GetString() != ObservedAttachmentHash) throw new CryptographicException();
            }
            AcceptedRequests++;
            context.Response.StatusCode = operation is Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace ? 200 : 202;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"workflowInstanceId\":\"workflow-synthetic-001\",\"traceID\":\"trace-synthetic-001\",\"spanID\":\"span-001\"}");
        }
        catch { context.Response.StatusCode = 401; await context.Response.WriteAsync("{}"); }
    }

    private JsonElement ValidateJwt(string token, string issuerPrefix, bool signatureClaims)
    {
        string[] segments = token.Split('.'); if (segments.Length != 3) throw new CryptographicException();
        using JsonDocument header = JsonDocument.Parse(Decode(segments[0]));
        byte[] der = Convert.FromBase64String(header.RootElement.GetProperty("x5c")[0].GetString()!);
        ObservedX5cFingerprint = Convert.ToHexString(SHA256.HashData(der));
        if (!der.AsSpan().SequenceEqual(expectedSigning.RawData)) throw new CryptographicException();
        using RSA rsa = expectedSigning.GetRSAPublicKey()!;
        if (!rsa.VerifyData(System.Text.Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]), Decode(segments[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) throw new CryptographicException();
        using JsonDocument payload = JsonDocument.Parse(Decode(segments[1])); JsonElement result = payload.RootElement.Clone();
        string cn = Fse2X500CommonName.ReadExactlyOne(expectedSigning.SubjectName.RawData);
        ObservedSubject = result.GetProperty("sub").GetString();
        if (result.GetProperty("iss").GetString() != issuerPrefix + cn || ObservedSubject != profile!.SubjectCx ||
            result.GetProperty("aud").GetString() != profile.BaseEndpoint.AbsoluteUri || result.TryGetProperty("nbf", out _)) throw new CryptographicException();
        if (signatureClaims && (result.GetProperty("subject_role").GetString() != "DAP" || result.TryGetProperty("use_subject_as_author", out _))) throw new CryptographicException();
        return result;
    }
    private static byte[] Decode(string value) { string padded = value.Replace('-', '+').Replace('_', '/'); padded += new string('=', (4 - padded.Length % 4) % 4); return Convert.FromBase64String(padded); }
    public async ValueTask DisposeAsync() { await application.StopAsync(); await application.DisposeAsync(); }
}

internal static class CertificateTestExtensions
{
    internal static string Fingerprint(this X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData));
    internal static BoundResourcePublicMetadata BoundMetadata(this X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPublicKey(); using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        byte[] spki = rsa?.ExportSubjectPublicKeyInfo() ?? ecdsa?.ExportSubjectPublicKeyInfo() ?? [];
        return new(certificate.Fingerprint(), Convert.ToHexString(SHA256.HashData(spki)), certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime(),
            rsa is not null ? "RSA" : "ECDSA", rsa?.KeySize ?? ecdsa?.KeySize ?? 0, certificate.SerialNumber);
    }
}
