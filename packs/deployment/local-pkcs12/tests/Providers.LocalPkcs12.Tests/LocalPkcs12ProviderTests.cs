using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Providers.LocalPkcs12.Tests;

public sealed class LocalPkcs12ProviderTests
{
    [Fact]
    public async Task LOCAL_P12_positive_exposes_distinct_mtls_signing_and_leaf_first_chain_capabilities()
    {
        using Fixture fixture = Fixture.Create();
        ProviderServices services = fixture.CreateServices();

        Assert.True(services.CapabilitySource.Capabilities.ClientCertificates);
        Assert.True(services.CapabilitySource.Capabilities.SigningKeys);
        Assert.True(services.CapabilitySource.Capabilities.CertificatePublicMaterial);
        Assert.False(services.CapabilitySource.Capabilities.Mac);

        using X509Certificate2 client = await services.ClientCertificates.GetClientCertificateAsync(Fixture.AuthReference, TestContext.Current.CancellationToken);
        Assert.True(client.HasPrivateKey);
        Assert.Equal(fixture.AuthFingerprint, Fingerprint(client));

        byte[] digest = SHA256.HashData("bounded-local-provider"u8);
        byte[] signature = await services.SigningKeys!.SignDigestAsync(Fixture.SignReference, "RS256", digest, TestContext.Current.CancellationToken);
        ProviderSigningKeyPublicMetadata signing = await services.SigningKeys.GetSigningKeyMetadataAsync(Fixture.SignReference, TestContext.Current.CancellationToken);
        using RSA verifier = RSA.Create();
        verifier.ImportSubjectPublicKeyInfo(signing.SubjectPublicKeyInfo, out int read);
        Assert.Equal(signing.SubjectPublicKeyInfo.Length, read);
        Assert.True(verifier.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Equal(fixture.SignFingerprint, signing.FingerprintSha256);

        ProviderCertificatePublicMaterial material = await services.CertificatePublicMaterial!.GetPublicMaterialAsync(Fixture.SignReference, TestContext.Current.CancellationToken);
        Assert.Equal(fixture.SignFingerprint, Convert.ToHexString(SHA256.HashData(material.LeafCertificateDer.Span)));
        ReadOnlyMemory<byte> issuer = Assert.Single(material.CertificateChainDer);
        Assert.Equal(fixture.RootFingerprint, Convert.ToHexString(SHA256.HashData(issuer.Span)));
        Assert.Equal(X509KeyUsageFlags.NonRepudiation, material.Metadata.KeyUsage);
        Assert.NotEqual(fixture.AuthSpki, material.SubjectPublicKeyInfoSha256);
        Assert.True(await services.Health.IsReadyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LOCAL_P12_roles_are_exact_and_cross_capability_requests_are_denied()
    {
        using Fixture fixture = Fixture.Create();
        ProviderServices services = fixture.CreateServices();

        ProviderAccessException signingAsMtls = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.ClientCertificates.GetClientCertificateAsync(Fixture.SignReference, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-CAPABILITY-DENIED", signingAsMtls.Code);

        ProviderAccessException mtlsAsSigning = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.SigningKeys!.SignDigestAsync(Fixture.AuthReference, "RS256", SHA256.HashData("x"u8), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-CAPABILITY-DENIED", mtlsAsSigning.Code);

        ProviderAccessException wrongAlgorithm = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.SigningKeys!.SignDigestAsync(Fixture.SignReference, "RS512", new byte[64], TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-SIGNING-ALGORITHM-DENIED", wrongAlgorithm.Code);
    }

    [Theory]
    [InlineData("file:///material/sign.p12")]
    [InlineData("local-pkcs12://other/sign")]
    [InlineData("local-pkcs12://fse2-lab/sign/extra")]
    [InlineData("local-pkcs12://fse2-lab/../sign")]
    [InlineData("local-pkcs12://fse2-lab/sign?file=other")]
    [InlineData("local-pkcs12://fse2-lab/sign#other")]
    public async Task LOCAL_P12_reference_parser_never_accepts_a_path_or_other_authority(string reference)
    {
        using Fixture fixture = Fixture.Create();
        ProviderServices services = fixture.CreateServices();
        ProviderAccessException denied = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.SigningKeys!.GetSigningKeyMetadataAsync(reference, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-REFERENCE-DENIED", denied.Code);
    }

    [Fact]
    public async Task LOCAL_P12_public_leaf_tamper_is_denied_and_readiness_fails_closed()
    {
        using Fixture fixture = Fixture.Create();
        ProviderServices services = fixture.CreateServices();
        File.WriteAllText(Path.Combine(fixture.MaterialRoot, "sign-leaf.pem"), fixture.Material.RootCertificate.ExportCertificatePem());

        ProviderAccessException denied = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.CertificatePublicMaterial!.GetPublicMaterialAsync(Fixture.SignReference, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-MATERIAL-INVALID", denied.Code);
        Assert.False(await services.Health.IsReadyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LOCAL_P12_unrelated_pinned_chain_is_denied_and_readiness_fails_closed()
    {
        using Fixture fixture = Fixture.Create();
        File.WriteAllText(Path.Combine(fixture.MaterialRoot, "root.pem"), fixture.Material.ClientCertificateRevision1.ExportCertificatePem());
        File.WriteAllText(fixture.ManifestPath, File.ReadAllText(fixture.ManifestPath)
            .Replace(fixture.RootFingerprint, fixture.AuthFingerprint, StringComparison.Ordinal));
        ProviderServices services = fixture.CreateServices();

        ProviderAccessException denied = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.CertificatePublicMaterial!.GetPublicMaterialAsync(Fixture.SignReference, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-MATERIAL-INVALID", denied.Code);
        Assert.False(await services.Health.IsReadyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LOCAL_P12_private_material_or_password_tamper_is_sanitized_and_fails_closed()
    {
        using Fixture fixture = Fixture.Create();
        ProviderServices services = fixture.CreateServices();
        await File.WriteAllBytesAsync(Path.Combine(fixture.MaterialRoot, "sign.p12"), RandomNumberGenerator.GetBytes(512), TestContext.Current.CancellationToken);

        ProviderAccessException denied = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.SigningKeys!.SignDigestAsync(Fixture.SignReference, "RS256", SHA256.HashData("x"u8), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-MATERIAL-INVALID", denied.Code);
        Assert.Null(denied.InnerException);
        Assert.False(await services.Health.IsReadyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public void LOCAL_P12_factory_rejects_unknown_settings_relative_paths_and_non_https_endpoint()
    {
        using Fixture fixture = Fixture.Create();
        LocalPkcs12ProviderPackFactory factory = new();
        Dictionary<string, string> settings = fixture.Settings();
        settings["Unknown"] = "value";
        AssertConfigurationDenied(() => factory.Create(new(new Uri("https://fse2-lab/"), null, settings)));
        AssertConfigurationDenied(() => factory.Create(new(new Uri("https://fse2-lab/"), null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ManifestPath"] = "manifest.json",
                ["MaterialRootPath"] = fixture.MaterialRoot
            })));
        AssertConfigurationDenied(() => factory.Create(new(new Uri("http://fse2-lab/"), null, fixture.Settings())));
    }

    [Fact]
    public void LOCAL_P12_manifest_rejects_duplicate_resources_path_segments_and_file_aliases()
    {
        using Fixture fixture = Fixture.Create();
        string manifest = File.ReadAllText(fixture.ManifestPath);
        using JsonDocument document = JsonDocument.Parse(manifest);
        JsonElement auth = document.RootElement.GetProperty("resources")[0];
        File.WriteAllText(fixture.ManifestPath, JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            resources = new[] { auth, auth }
        }));
        AssertConfigurationDenied(() => fixture.CreateServices());

        File.WriteAllText(fixture.ManifestPath, JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            resources = new[]
            {
                new { id = "secret", kind = "Secret", fileName = "../escape" }
            }
        }));
        AssertConfigurationDenied(() => fixture.CreateServices());

        File.WriteAllText(fixture.ManifestPath, manifest.Replace("sign-leaf.pem", "auth-leaf.pem", StringComparison.Ordinal));
        AssertConfigurationDenied(() => fixture.CreateServices());
    }

    private static void AssertConfigurationDenied(Action action)
    {
        ProviderAccessException denied = Assert.Throws<ProviderAccessException>(action);
        Assert.Equal("BGW-PROVIDER-CONFIGURATION-INVALID", denied.Code);
        Assert.Null(denied.InnerException);
    }

    private static string Fingerprint(X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData));

    private sealed class Fixture : IDisposable
    {
        private readonly string root;

        private Fixture(string root, SyntheticAuthenticationMaterial material, string manifestPath)
        {
            this.root = root;
            Material = material;
            ManifestPath = manifestPath;
            MaterialRoot = Path.Combine(root, "material");
            AuthFingerprint = Fingerprint(material.ClientCertificateRevision1);
            SignFingerprint = Fingerprint(material.SigningKeyRevision1);
            RootFingerprint = Fingerprint(material.RootCertificate);
            AuthSpki = Spki(material.ClientCertificateRevision1);
        }

        internal SyntheticAuthenticationMaterial Material { get; }
        internal string ManifestPath { get; }
        internal string MaterialRoot { get; }
        internal string AuthFingerprint { get; }
        internal string SignFingerprint { get; }
        internal string RootFingerprint { get; }
        internal string AuthSpki { get; }
        internal const string AuthReference = "local-pkcs12://fse2-lab/auth";
        internal const string SignReference = "local-pkcs12://fse2-lab/sign";

        internal static Fixture Create()
        {
            string root = Path.Combine(Path.GetTempPath(), "local-pkcs12-provider-tests-" + Guid.NewGuid().ToString("N"));
            string materialRoot = Path.Combine(root, "material");
            Directory.CreateDirectory(materialRoot);
            SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
            string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            WritePrivate(Path.Combine(materialRoot, "auth.p12"), material.ClientCertificateRevision1, password);
            WritePrivate(Path.Combine(materialRoot, "sign.p12"), material.SigningKeyRevision1, password);
            File.WriteAllText(Path.Combine(materialRoot, "auth.password"), password);
            File.WriteAllText(Path.Combine(materialRoot, "sign.password"), password);
            File.WriteAllText(Path.Combine(materialRoot, "auth-leaf.pem"), material.ClientCertificateRevision1.ExportCertificatePem());
            File.WriteAllText(Path.Combine(materialRoot, "sign-leaf.pem"), material.SigningKeyRevision1.ExportCertificatePem());
            File.WriteAllText(Path.Combine(materialRoot, "root.pem"), material.RootCertificate.ExportCertificatePem());
            string manifestPath = Path.Combine(root, "manifest.json");
            File.WriteAllText(manifestPath, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                resources = new object[]
                {
                    Resource("auth", "ClientCertificate", material.ClientCertificateRevision1),
                    Resource("sign", "SigningCertificate", material.SigningKeyRevision1)
                }
            }));
            return new(root, material, manifestPath);

            object Resource(string id, string kind, X509Certificate2 certificate) => new
            {
                id,
                kind,
                pkcs12FileName = id + ".p12",
                passwordFileName = id + ".password",
                leafFileName = id + "-leaf.pem",
                certificateSha256 = Fingerprint(certificate),
                subjectPublicKeyInfoSha256 = Spki(certificate),
                version = certificate.SerialNumber,
                chain = new[] { new { fileName = "root.pem", certificateSha256 = Fingerprint(material.RootCertificate) } }
            };
        }

        internal ProviderServices CreateServices() => new LocalPkcs12ProviderPackFactory().Create(
            new ProviderPackContext(new Uri("https://fse2-lab/"), null, Settings()));

        internal Dictionary<string, string> Settings() => new(StringComparer.Ordinal)
        {
            ["ManifestPath"] = ManifestPath,
            ["MaterialRootPath"] = MaterialRoot
        };

        private static string Spki(X509Certificate2 certificate)
        {
            using RSA? rsa = certificate.GetRSAPublicKey();
            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            byte[] spki = rsa?.ExportSubjectPublicKeyInfo() ?? ecdsa!.ExportSubjectPublicKeyInfo();
            return Convert.ToHexString(SHA256.HashData(spki));
        }

        private static void WritePrivate(string path, X509Certificate2 certificate, string password)
        {
            byte[] encoded = certificate.Export(X509ContentType.Pkcs12, password);
            try { File.WriteAllBytes(path, encoded); }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }

        public void Dispose()
        {
            Material.Dispose();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
