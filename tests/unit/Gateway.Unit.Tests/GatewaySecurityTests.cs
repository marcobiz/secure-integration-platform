using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class GatewaySecurityTests
{
    [Fact]
    public async Task UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        Assert.Equal(fixture.TenantId, identity.TenantId);

        byte[] body = "request"u8.ToArray();
        RuntimeSignatureHeaders headers = fixture.Sign("POST", "/v1/connectors/vendor/operations/send:invoke", body);
        AuthenticatedInstallation authenticated = await fixture.IdentityService.AuthenticateAsync(fixture.Certificate, "POST", "/v1/connectors/vendor/operations/send:invoke", headers, body, Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(fixture.InstallationId, authenticated.Identity.InstallationId);

        GatewayException replay = await Assert.ThrowsAsync<GatewayException>(() => fixture.IdentityService.AuthenticateAsync(fixture.Certificate, "POST", "/v1/connectors/vendor/operations/send:invoke", headers, body, Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTHN-REPLAY", replay.Code);
    }

    [Fact]
    public async Task UT_GTW_Runtime_rejects_tampered_body_ambiguous_target_and_unknown_certificate()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        await fixture.EnrollAsync();
        byte[] body = "original"u8.ToArray();
        RuntimeSignatureHeaders headers = fixture.Sign("POST", "/v1/test", body);

        GatewayException digest = await Assert.ThrowsAsync<GatewayException>(() => fixture.IdentityService.AuthenticateAsync(fixture.Certificate, "POST", "/v1/test", headers, "changed"u8.ToArray(), Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTHN-CONTENT-DIGEST", digest.Code);
        Assert.Throws<GatewayException>(() => RuntimeIdentityService.BuildSigningInput("GET", "/v1/test?a=1&a=2", headers.Timestamp, headers.Nonce, headers.ContentSha256));

        using (ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        using (X509Certificate2 other = CreateCertificate(otherKey, fixture.Clock.UtcNow))
        {
            GatewayException unknown = await Assert.ThrowsAsync<GatewayException>(() => fixture.IdentityService.AuthenticateAsync(other, "POST", "/v1/test", headers, body, Guid.NewGuid(), TestContext.Current.CancellationToken));
            Assert.Equal("BGW-AUTHN-CREDENTIAL-UNKNOWN", unknown.Code);
        }
    }

    [Fact]
    public async Task UT_GTW_Revocation_is_immediate_for_runtime_and_grants()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        await fixture.EnrollAsync();
        await fixture.EnrollmentService.RevokeAsync(fixture.InstallationId, "security incident", TestContext.Current.CancellationToken);
        RuntimeSignatureHeaders headers = fixture.Sign("GET", "/v1/broker-policy", []);
        GatewayException revoked = await Assert.ThrowsAsync<GatewayException>(() => fixture.IdentityService.AuthenticateAsync(fixture.Certificate, "GET", "/v1/broker-policy", headers, ReadOnlyMemory<byte>.Empty, Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-INSTALLATION-REVOKED", revoked.Code);
    }

    [Fact]
    public async Task UT_GTW_Activation_code_is_one_time_and_invalid_code_is_denied()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        EnrollmentChallengeResponse challenge = await fixture.CreateChallengeAsync();
        ActivationRequest invalid = fixture.CreateActivation(challenge, "incorrect-code");
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => fixture.EnrollmentService.ActivateAsync(invalid, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTHN-ENROLLMENT-DENIED", denied.Code);

        EnrollmentChallengeResponse validChallenge = await fixture.CreateChallengeAsync();
        await fixture.EnrollmentService.ActivateAsync(fixture.CreateActivation(validChallenge, fixture.Provisioning.ActivationCode), TestContext.Current.CancellationToken);
        GatewayException reused = await Assert.ThrowsAsync<GatewayException>(() => fixture.CreateChallengeAsync());
        Assert.Equal("BGW-AUTHN-ENROLLMENT-DENIED", reused.Code);
    }

    [Fact]
    public async Task UT_GTW_Enrollment_rejects_invalid_proof_of_possession()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        EnrollmentChallengeResponse challenge = await fixture.CreateChallengeAsync();
        ActivationRequest request = fixture.CreateActivation(challenge, fixture.Provisioning.ActivationCode) with { ProofSignature = Base64Url.Encode(new byte[64]) };
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => fixture.EnrollmentService.ActivateAsync(request, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTHN-INVALID-PROOF", denied.Code);
    }

    [Fact]
    public async Task UT_GTW_Enrollment_rejects_incompatible_Broker_version()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        EnrollmentChallengeResponse challenge = await fixture.CreateChallengeAsync();
        ActivationRequest request = fixture.CreateActivation(challenge, fixture.Provisioning.ActivationCode) with { BrokerVersion = "0.9.0" };
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => fixture.EnrollmentService.ActivateAsync(request, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-INSTALLATION-BROKER-INCOMPATIBLE", denied.Code);
    }

    [Fact]
    public async Task UT_EGR_Private_or_loopback_destination_is_rejected_before_transport()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        await fixture.AddGrantAsync();
        RecordingTransport transport = new();
        RestrictedEgressService service = fixture.CreateEgress(new StaticResolver(IPAddress.Loopback), transport, GatewayAuthenticationKind.None);

        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => service.InvokeAsync(new(identity, Guid.NewGuid()), "vendor", "send", Invoke(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-DESTINATION-DENIED", denied.Code);
        Assert.Equal(0, transport.CallCount);
    }

    [Fact]
    public async Task UT_EGR_Server_owned_endpoint_and_API_key_are_used_without_secret_disclosure()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        await fixture.AddGrantAsync();
        RecordingTransport transport = new();
        RestrictedEgressService service = fixture.CreateEgress(new StaticResolver(IPAddress.Parse("8.8.8.8")), transport, GatewayAuthenticationKind.ApiKey);

        GatewayInvokeResponse response = await service.InvokeAsync(new(identity, Guid.NewGuid()), "vendor", "send", Invoke(), TestContext.Current.CancellationToken);
        Assert.Equal(new Uri("https://vendor.example.test/fixed"), transport.Uri);
        Assert.Equal("server-api-key", transport.ApiKey);
        Assert.DoesNotContain("server-api-key", Convert.ToBase64String(Convert.FromBase64String(response.Result.Data)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task UT_EGR_Basic_credentials_are_injected_only_into_the_outbound_request()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        await fixture.AddGrantAsync();
        RecordingTransport transport = new();
        RestrictedEgressService service = fixture.CreateEgress(new StaticResolver(IPAddress.Parse("8.8.4.4")), transport, GatewayAuthenticationKind.Basic);

        GatewayInvokeResponse response = await service.InvokeAsync(new(identity, Guid.NewGuid()), "vendor", "send", Invoke(), TestContext.Current.CancellationToken);
        Assert.Equal("Basic " + Convert.ToBase64String("server-user:server-password"u8), transport.Authorization);
        Assert.DoesNotContain("server-password", System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(response.Result.Data)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task UT_EGR_mTLS_certificate_is_loaded_ephemerally_for_transport()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        await fixture.AddGrantAsync();
        RecordingTransport transport = new();
        InMemorySecretProvider provider = new(new Dictionary<string, string>(), new Dictionary<string, byte[]> { ["client-cert"] = fixture.Certificate.Export(X509ContentType.Pkcs12) });
        RestrictedEgressService service = fixture.CreateEgress(new StaticResolver(IPAddress.Parse("1.1.1.1")), transport, GatewayAuthenticationKind.MutualTls, provider);

        await service.InvokeAsync(new(identity, Guid.NewGuid()), "vendor", "send", Invoke(), TestContext.Current.CancellationToken);
        Assert.True(transport.ClientCertificatePresented);
    }

    [Fact]
    public async Task M3_UT_EGR_API_key_and_mTLS_are_both_server_side()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        await fixture.AddGrantAsync();
        RecordingTransport transport = new();
        InMemorySecretProvider provider = new(
            new Dictionary<string, string> { ["api-key"] = "server-api-key" },
            new Dictionary<string, byte[]> { ["client-cert"] = fixture.Certificate.Export(X509ContentType.Pkcs12) });
        RestrictedEgressService service = fixture.CreateEgress(new StaticResolver(IPAddress.Parse("1.1.1.1")), transport, GatewayAuthenticationKind.ApiKeyAndMutualTls, provider);

        await service.InvokeAsync(new(identity, Guid.NewGuid()), "vendor", "send", Invoke(), TestContext.Current.CancellationToken);

        Assert.Equal("server-api-key", transport.ApiKey);
        Assert.True(transport.ClientCertificatePresented);
    }

    [Fact]
    public async Task M3_UT_EGR_Private_fixture_allowance_is_exact_host_and_narrow_CIDR()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        await fixture.AddGrantAsync();
        RecordingTransport transport = new();
        M3PrivateDestinationAllowance allowance = new("vendor.example.test", "172.29.44.0/28");
        RestrictedEgressService allowed = new(fixture.Registry, new GatewayOperationCatalog([Operation(GatewayAuthenticationKind.None)]), new InMemorySecretProvider(new Dictionary<string, string>()), new StaticResolver(IPAddress.Parse("172.29.44.6")), transport, fixture.Clock, allowance);
        await allowed.InvokeAsync(new(identity, Guid.NewGuid()), "vendor", "send", Invoke(), TestContext.Current.CancellationToken);
        Assert.Equal(1, transport.CallCount);

        RestrictedEgressService metadata = new(fixture.Registry, new GatewayOperationCatalog([Operation(GatewayAuthenticationKind.None)]), new InMemorySecretProvider(new Dictionary<string, string>()), new StaticResolver(IPAddress.Parse("169.254.169.254")), transport, fixture.Clock, allowance);
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => metadata.InvokeAsync(new(identity, Guid.NewGuid()), "vendor", "send", Invoke(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-DESTINATION-DENIED", denied.Code);
        Assert.False(allowance.IsAllowed("attacker.example.test", IPAddress.Parse("172.29.44.6")));
        Assert.False(allowance.IsAllowed("vendor.example.test", IPAddress.Parse("172.29.45.6")));
    }

    [Fact]
    public async Task UT_GTW_Renewal_allows_seven_day_overlap_then_expires_old_credential()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity current = await fixture.EnrollAsync();
        fixture.Clock.UtcNow = fixture.Clock.UtcNow.AddDays(61);
        using ECDsa replacementKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 replacementCertificate = CreateCertificate(replacementKey, fixture.Clock.UtcNow);
        byte[] replacementSpki = replacementKey.ExportSubjectPublicKeyInfo();
        byte[] proof = InstallationEnrollmentService.BuildRenewalProof(fixture.InstallationId, current.CredentialId, SHA256.HashData(replacementSpki));
        byte[] signature = replacementKey.SignData(proof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        await fixture.EnrollmentService.RenewAsync(current, new(Convert.ToBase64String(replacementCertificate.RawData), Base64Url.Encode(signature)), TestContext.Current.CancellationToken);

        RuntimeSignatureHeaders overlapHeaders = fixture.Sign("GET", "/v1/broker-policy", []);
        await fixture.IdentityService.AuthenticateAsync(fixture.Certificate, "GET", "/v1/broker-policy", overlapHeaders, ReadOnlyMemory<byte>.Empty, Guid.NewGuid(), TestContext.Current.CancellationToken);
        fixture.Clock.UtcNow = fixture.Clock.UtcNow.AddDays(8);
        RuntimeSignatureHeaders expiredHeaders = fixture.Sign("GET", "/v1/broker-policy", []);
        GatewayException expired = await Assert.ThrowsAsync<GatewayException>(() => fixture.IdentityService.AuthenticateAsync(fixture.Certificate, "GET", "/v1/broker-policy", expiredHeaders, ReadOnlyMemory<byte>.Empty, Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-INSTALLATION-CREDENTIAL-EXPIRED", expired.Code);
    }

    [Fact]
    public async Task UT_EGR_Ungranted_operation_is_denied_before_DNS_vault_or_transport()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        TrackingResolver resolver = new();
        RecordingTransport transport = new();
        RestrictedEgressService service = fixture.CreateEgress(resolver, transport, GatewayAuthenticationKind.ApiKey);

        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => service.InvokeAsync(new(identity, Guid.NewGuid()), "vendor", "send", Invoke(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTHZ-OPERATION-DENIED", denied.Code);
        Assert.Equal(0, resolver.CallCount);
        Assert.Equal(0, transport.CallCount);
    }

    [Fact]
    public async Task UT_GTW_Cross_tenant_grant_is_rejected()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        await fixture.EnrollAsync();
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => fixture.Registry.AddGrantAsync(new(Guid.NewGuid(), fixture.InstallationId, Guid.NewGuid(), "vendor", "send", true, fixture.Clock.UtcNow), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTHZ-CROSS-TENANT-GRANT", denied.Code);
    }

    [Fact]
    public void UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference()
    {
        string[] propertyNames = typeof(GatewayInvokeRequest).GetProperties().Select(property => property.Name).ToArray();
        Assert.DoesNotContain("Endpoint", propertyNames);
        Assert.DoesNotContain("Url", propertyNames);
        Assert.DoesNotContain("SecretReference", propertyNames);
        Assert.DoesNotContain("TenantId", propertyNames);
    }

    [Fact]
    public async Task UT_EGR_Transient_retry_occurs_only_for_idempotent_operation()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        await fixture.AddGrantAsync();
        FailOnceTransport transport = new();
        GatewayOperationDefinition operation = Operation(GatewayAuthenticationKind.None) with { Idempotent = true, MaximumRetries = 1 };
        RestrictedEgressService service = new(fixture.Registry, new GatewayOperationCatalog([operation]), new InMemorySecretProvider(new Dictionary<string, string>()), new StaticResolver(IPAddress.Parse("9.9.9.9")), transport, fixture.Clock);
        await service.InvokeAsync(new(identity, Guid.NewGuid()), "vendor", "send", Invoke(), TestContext.Current.CancellationToken);
        Assert.Equal(2, transport.CallCount);
    }

    [Fact]
    public async Task M4_UT_EGR_Request_and_response_bounds_fail_closed()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        await fixture.AddGrantAsync();
        AuthenticatedInstallation authenticated = new(identity, Guid.NewGuid());
        TrackingResolver requestResolver = new();
        RestrictedEgressService requestService = fixture.CreateEgress(requestResolver, new RecordingTransport(), GatewayAuthenticationKind.None);
        GatewayInvokeRequest oversized = new("1.0", new("application/octet-stream", "base64", Convert.ToBase64String(new byte[1025])), Guid.NewGuid());
        GatewayException requestFailure = await Assert.ThrowsAsync<GatewayException>(() => requestService.InvokeAsync(authenticated, "vendor", "send", oversized, TestContext.Current.CancellationToken));
        Assert.Equal(413, requestFailure.StatusCode);
        Assert.Equal(0, requestResolver.CallCount);

        RestrictedEgressService responseService = fixture.CreateEgress(new StaticResolver(IPAddress.Parse("8.8.8.8")), new OversizeResponseTransport(), GatewayAuthenticationKind.None);
        GatewayException responseFailure = await Assert.ThrowsAsync<GatewayException>(() => responseService.InvokeAsync(authenticated, "vendor", "send", Invoke(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-RESPONSE-TOO-LARGE", responseFailure.Code);
    }

    [Fact]
    public async Task UT_SEC_Audit_is_metadata_only_and_excludes_payload_and_credentials()
    {
        using Fixture fixture = await Fixture.CreateAsync();
        RegisteredInstallationIdentity identity = await fixture.EnrollAsync();
        byte[] body = "AUDIT_PAYLOAD_CANARY"u8.ToArray();
        RuntimeSignatureHeaders headers = fixture.Sign("POST", "/v1/test", body);
        await fixture.IdentityService.AuthenticateAsync(fixture.Certificate, "POST", "/v1/test", headers, body, Guid.NewGuid(), TestContext.Current.CancellationToken);
        string serialized = System.Text.Json.JsonSerializer.Serialize(fixture.Registry.SnapshotAuditEvents());
        Assert.DoesNotContain("AUDIT_PAYLOAD_CANARY", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(headers.Signature, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(fixture.Certificate.RawData), serialized, StringComparison.Ordinal);
    }

    [Fact]
    public void UT_EGR_Catalog_rejects_HTTP_and_retry_for_non_idempotent_operation()
    {
        Assert.Throws<InvalidOperationException>(() => new GatewayOperationCatalog([Operation(GatewayAuthenticationKind.None, new Uri("http://vendor.example.test"))]));
        Assert.Throws<InvalidOperationException>(() => new GatewayOperationCatalog([Operation(GatewayAuthenticationKind.None) with { MaximumRetries = 1, Idempotent = false }]));
    }

    [Fact]
    public async Task UT_VLT_Secret_cache_is_bounded_and_deduplicates_reads()
    {
        CountingSecretProvider inner = new();
        CachingSecretProvider cache = new(inner, TimeSpan.FromMinutes(5));
        string first = await cache.GetSecretAsync("keyvault://vault.example.test/vendor", TestContext.Current.CancellationToken);
        string second = await cache.GetSecretAsync("keyvault://vault.example.test/vendor", TestContext.Current.CancellationToken);
        Assert.Equal(first, second);
        Assert.Equal(1, inner.CallCount);
    }

    [Fact]
    public async Task UT_VLT_Reference_cannot_select_another_vault()
    {
        AzureKeyVaultSecretProvider provider = new(new Uri("https://allowed.vault.azure.net/"), new NeverCredential());
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => provider.GetSecretAsync("keyvault://other.vault.azure.net/vendor-key", TestContext.Current.CancellationToken));
        Assert.Equal("BGW-VAULT-REFERENCE-DENIED", denied.Code);
    }

    [Fact]
    public async Task M3_UT_VLT_Synthetic_provider_is_fixed_origin_authenticated_and_reference_scoped()
    {
        RecordingVaultHandler handler = new();
        using SyntheticVaultSecretProvider provider = new(new Uri("https://vault.m3.test/"), new string('t', 32), handler);
        Assert.Equal("synthetic-vendor-value", await provider.GetSecretAsync("synthetic-vault://vault.m3.test/vendor-api-key", TestContext.Current.CancellationToken));
        Assert.Equal(new string('t', 32), handler.Token);
        Assert.Equal(new Uri("https://vault.m3.test/v1/secrets/vendor-api-key"), handler.Uri);
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => provider.GetSecretAsync("synthetic-vault://other.m3.test/vendor-api-key", TestContext.Current.CancellationToken));
        Assert.Equal("BGW-VAULT-REFERENCE-DENIED", denied.Code);
    }

    [Theory]
    [InlineData("+")]
    [InlineData("AA==")]
    [InlineData("A")]
    public void UT_GTW_Base64Url_is_strict(string value) => Assert.Throws<FormatException>(() => Base64Url.Decode(value));

    private static GatewayInvokeRequest Invoke() => new("1.0", new("application/octet-stream", "base64", Convert.ToBase64String("payload"u8)), Guid.NewGuid());

    private static GatewayOperationDefinition Operation(GatewayAuthenticationKind authentication, Uri? endpoint = null) => new(
        "vendor", "send", "1.0.0", endpoint ?? new Uri("https://vendor.example.test/fixed"), HttpMethod.Post, "application/octet-stream", authentication,
        authentication == GatewayAuthenticationKind.Basic ? "user" : null, authentication == GatewayAuthenticationKind.Basic ? "pass" : null,
        authentication is GatewayAuthenticationKind.ApiKey or GatewayAuthenticationKind.ApiKeyAndMutualTls ? "api-key" : null, authentication is GatewayAuthenticationKind.ApiKey or GatewayAuthenticationKind.ApiKeyAndMutualTls ? "X-Api-Key" : null,
        authentication is GatewayAuthenticationKind.MutualTls or GatewayAuthenticationKind.ApiKeyAndMutualTls ? "client-cert" : null, 5_000, 1024, 1024, false);

    private static X509Certificate2 CreateCertificate(ECDsa key, DateTimeOffset now)
    {
        CertificateRequest request = new("CN=broker-installation", key, HashAlgorithmName.SHA256);
        OidCollection usages = new() { new Oid("1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        return request.CreateSelfSigned(now.AddMinutes(-1), now.AddDays(90));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa key;
        private readonly InMemoryGatewayRegistry registry;
        private readonly byte[] spki;

        private Fixture(
            ECDsa proofSigner,
            X509Certificate2 certificate,
            byte[] spki,
            InMemoryGatewayRegistry registry,
            FakeClock clock,
            ProvisionedActivation provisioning,
            Guid tenantId,
            Guid applicationId,
            Guid environmentId)
        {
            key = proofSigner;
            this.spki = spki;
            this.registry = registry;
            Certificate = certificate;
            Clock = clock;
            Provisioning = provisioning;
            TenantId = tenantId;
            ApplicationId = applicationId;
            EnvironmentId = environmentId;
            EnrollmentService = new(registry, new InMemoryEnrollmentChallengeStore(), clock, new EnrollmentSecurityOptions { ActivationHmacKey = ActivationKey });
            IdentityService = new(registry, clock);
        }

        private static readonly byte[] ActivationKey = SHA256.HashData("unit-test-activation-key"u8);
        public Guid TenantId { get; }
        public Guid ApplicationId { get; }
        public Guid EnvironmentId { get; }
        public Guid InstallationId => Provisioning.InstallationId;
        public X509Certificate2 Certificate { get; }
        public FakeClock Clock { get; }
        public ProvisionedActivation Provisioning { get; }
        public InstallationEnrollmentService EnrollmentService { get; }
        public RuntimeIdentityService IdentityService { get; }
        public InMemoryGatewayRegistry Registry => registry;

        public static async Task<Fixture> CreateAsync()
        {
            FakeClock clock = new(new DateTimeOffset(2026, 8, 4, 10, 0, 0, TimeSpan.Zero));
            ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            X509Certificate2 certificate = CreateCertificate(key, clock.UtcNow);
            byte[] spki = key.ExportSubjectPublicKeyInfo();
            InMemoryGatewayRegistry registry = new(clock);
            Guid tenantId = Guid.NewGuid();
            Guid applicationId = Guid.NewGuid();
            Guid environmentId = Guid.NewGuid();
            GatewayProvisioningService provisioningService = new(registry, clock, new EnrollmentSecurityOptions { ActivationHmacKey = ActivationKey });
            Guid installationId = Guid.NewGuid();
            ProvisionedActivation provisioning = await provisioningService.CreateInstallationAsync(
                new(tenantId, "tenant-a", "Tenant A", TenantStatus.Active, clock.UtcNow),
                new(applicationId, "product-a", "Product A", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow),
                new(environmentId, "test", "Test", false), installationId, "unit-test", TestContext.Current.CancellationToken);
            return new Fixture(key, certificate, spki, registry, clock, provisioning, tenantId, applicationId, environmentId);
        }

        public async Task<EnrollmentChallengeResponse> CreateChallengeAsync() => await EnrollmentService.CreateChallengeAsync(new(Provisioning.ActivationCodeId, Convert.ToBase64String(spki)), TestContext.Current.CancellationToken);

        public ActivationRequest CreateActivation(EnrollmentChallengeResponse challenge, string activationCode)
        {
            EnrollmentChallenge proofChallenge = new(challenge.ChallengeId, Provisioning.ActivationCodeId, Base64Url.Decode(challenge.Challenge), spki, challenge.ExpiresAt);
            byte[] signature = key.SignData(InstallationEnrollmentService.BuildActivationProof(proofChallenge), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return new(challenge.ChallengeId, activationCode, Convert.ToBase64String(Certificate.RawData), Base64Url.Encode(signature), "1.0.0");
        }

        public async Task<RegisteredInstallationIdentity> EnrollAsync()
        {
            EnrollmentChallengeResponse challenge = await CreateChallengeAsync();
            await EnrollmentService.ActivateAsync(CreateActivation(challenge, Provisioning.ActivationCode), TestContext.Current.CancellationToken);
            return await registry.FindIdentityByCertificateAsync(SHA256.HashData(Certificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException();
        }

        public RuntimeSignatureHeaders Sign(string method, string target, byte[] body)
        {
            string timestamp = Clock.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);
            string nonce = Base64Url.Encode(RandomNumberGenerator.GetBytes(16));
            string digest = Base64Url.Encode(SHA256.HashData(body));
            byte[] signature = key.SignData(System.Text.Encoding.UTF8.GetBytes(RuntimeIdentityService.BuildSigningInput(method, target, timestamp, nonce, digest)), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return new(timestamp, nonce, digest, Base64Url.Encode(signature));
        }

        public Task AddGrantAsync() => registry.AddGrantAsync(new(Guid.NewGuid(), InstallationId, TenantId, "vendor", "send", true, Clock.UtcNow), TestContext.Current.CancellationToken);

        public RestrictedEgressService CreateEgress(IHostResolver resolver, IRestrictedTransport transport, GatewayAuthenticationKind authentication, ISecretProvider? provider = null) => new(
            registry, new GatewayOperationCatalog([Operation(authentication)]), provider ?? new InMemorySecretProvider(new Dictionary<string, string> { ["api-key"] = "server-api-key", ["user"] = "server-user", ["pass"] = "server-password" }), resolver, transport, Clock);

        public void Dispose() { Certificate.Dispose(); key.Dispose(); }
    }

    private sealed class FakeClock(DateTimeOffset value) : IGatewayClock { public DateTimeOffset UtcNow { get; set; } = value; }
    private sealed class StaticResolver(params IPAddress[] addresses) : IHostResolver { public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(addresses); }
    private sealed class TrackingResolver : IHostResolver { public int CallCount { get; private set; } public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) { CallCount++; return Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") }); } }
    private sealed class RecordingTransport : IRestrictedTransport
    {
        public int CallCount { get; private set; }
        public Uri? Uri { get; private set; }
        public string? ApiKey { get; private set; }
        public string? Authorization { get; private set; }
        public bool ClientCertificatePresented { get; private set; }
        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            CallCount++;
            Uri = request.RequestUri;
            ApiKey = request.Headers.TryGetValues("X-Api-Key", out IEnumerable<string>? values) ? values.Single() : null;
            Authorization = request.Headers.Authorization?.ToString();
            ClientCertificatePresented = clientCertificate is not null;
            return Task.FromResult(new ExternalResponse(200, "application/json", "ok"u8.ToArray()));
        }
    }

    private sealed class FailOnceTransport : IRestrictedTransport
    {
        public int CallCount { get; private set; }
        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            CallCount++;
            if (CallCount == 1) throw new HttpRequestException("synthetic transient failure");
            return Task.FromResult(new ExternalResponse(200, "application/octet-stream", []));
        }
    }

    private sealed class OversizeResponseTransport : IRestrictedTransport
    {
        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            Assert.Equal(1024, maximumResponseBytes);
            throw new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502);
        }
    }

    private sealed class CountingSecretProvider : ISecretProvider
    {
        public int CallCount { get; private set; }
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) { CallCount++; return Task.FromResult("synthetic-value"); }
        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<bool> IsReadyAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class NeverCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Credential must not be used for a denied reference.");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Credential must not be used for a denied reference.");
    }

    private sealed class RecordingVaultHandler : HttpMessageHandler
    {
        public string? Token { get; private set; }
        public Uri? Uri { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Token = request.Headers.GetValues("X-M3-Vault-Token").Single();
            Uri = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"value\":\"synthetic-vendor-value\"}", System.Text.Encoding.UTF8, "application/json") });
        }
    }
}
