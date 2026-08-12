using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureIntegration.Providers.Abstractions;
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
        Assert.False(services.CapabilitySource.Capabilities.SecretValues);
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
        Assert.Equal(2, material.CertificateChainDer.Count);
        Assert.Equal(fixture.IntermediateFingerprint, Convert.ToHexString(SHA256.HashData(material.CertificateChainDer[0].Span)));
        Assert.Equal(fixture.RootFingerprint, Convert.ToHexString(SHA256.HashData(material.CertificateChainDer[1].Span)));
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
        File.WriteAllText(Path.Combine(fixture.MaterialRoot, "sign-leaf.pem"), fixture.RootCertificatePem);

        ProviderAccessException denied = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.CertificatePublicMaterial!.GetPublicMaterialAsync(Fixture.SignReference, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-MATERIAL-INVALID", denied.Code);
        Assert.False(await services.Health.IsReadyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LOCAL_P12_unrelated_pinned_chain_is_denied_and_readiness_fails_closed()
    {
        using Fixture fixture = Fixture.Create();
        File.WriteAllText(Path.Combine(fixture.MaterialRoot, "root.pem"), fixture.AuthCertificatePem);
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

    [Theory]
    [InlineData("sign", "chain-deleted")]
    [InlineData("sign", "chain-substituted")]
    [InlineData("sign", "chain-reordered")]
    [InlineData("sign", "root-substituted")]
    [InlineData("sign", "leaf-substituted")]
    [InlineData("sign", "pkcs12-substituted")]
    [InlineData("sign", "pkcs12-reencoded")]
    [InlineData("client", "chain-deleted")]
    [InlineData("client", "chain-substituted")]
    [InlineData("client", "chain-reordered")]
    [InlineData("client", "root-substituted")]
    [InlineData("client", "leaf-substituted")]
    [InlineData("client", "pkcs12-substituted")]
    [InlineData("client", "pkcs12-reencoded")]
    public async Task LOCAL_P12_private_use_revalidates_exact_chain_leaf_and_pkcs12_after_preflight(
        string role,
        string mutation)
    {
        using Fixture fixture = Fixture.Create();
        ProviderServices services = fixture.CreateServices();
        string materialRole = role == "client" ? "auth" : role;
        fixture.ApplyPrivateUseMutation(materialRole, mutation);

        ProviderAccessException denied = role == "sign"
            ? await Assert.ThrowsAsync<ProviderAccessException>(() => services.SigningKeys!.SignDigestAsync(
                Fixture.SignReference,
                "RS256",
                SHA256.HashData("must-not-sign"u8),
                TestContext.Current.CancellationToken))
            : await Assert.ThrowsAsync<ProviderAccessException>(() => services.ClientCertificates.GetClientCertificateAsync(
                Fixture.AuthReference,
                TestContext.Current.CancellationToken));

        Assert.Equal("BGW-PROVIDER-MATERIAL-INVALID", denied.Code);
        Assert.Null(denied.InnerException);
        Assert.False(await services.Health.IsReadyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LOCAL_P12_private_use_rereads_and_exact_matches_the_initial_manifest_resource()
    {
        using Fixture fixture = Fixture.Create();
        ProviderServices services = fixture.CreateServices();
        File.WriteAllText(fixture.ManifestPath, File.ReadAllText(fixture.ManifestPath)
            .Replace(fixture.SignVersion, fixture.SignVersion + "-changed", StringComparison.Ordinal));

        ProviderAccessException denied = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.SigningKeys!.SignDigestAsync(
                Fixture.SignReference,
                "RS256",
                SHA256.HashData("must-not-sign"u8),
                TestContext.Current.CancellationToken));

        Assert.Equal("BGW-PROVIDER-MATERIAL-INVALID", denied.Code);
        Assert.Null(denied.InnerException);
        Assert.False(await services.Health.IsReadyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LOCAL_P12_generic_secret_retrieval_is_deny_only_without_filesystem_resolution()
    {
        using Fixture fixture = Fixture.Create();
        ProviderServices services = fixture.CreateServices();
        string sentinel = Path.Combine(fixture.MaterialRoot, "must-not-be-read.txt");
        File.WriteAllText(sentinel, "synthetic-canary");

        ProviderAccessException denied = await Assert.ThrowsAsync<ProviderAccessException>(() =>
            services.SecretValues.GetSecretAsync(sentinel, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-PROVIDER-CAPABILITY-DENIED", denied.Code);
        Assert.Null(denied.InnerException);
        Assert.Equal("synthetic-canary", File.ReadAllText(sentinel));
        Assert.False(services.CapabilitySource.Capabilities.SecretValues);
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

    [Fact]
    public void LOCAL_P12_manifest_rejects_every_secret_resource_kind()
    {
        using Fixture fixture = Fixture.Create();
        File.WriteAllText(fixture.ManifestPath, JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            resources = new[] { new { id = "secret", kind = "Secret", fileName = "value.txt" } }
        }));

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
        private readonly X509Certificate2 rootCertificate;
        private readonly X509Certificate2 intermediateCertificate;
        private readonly X509Certificate2 authCertificate;
        private readonly X509Certificate2 signCertificate;

        private Fixture(
            string root,
            X509Certificate2 rootCertificate,
            X509Certificate2 intermediateCertificate,
            X509Certificate2 authCertificate,
            X509Certificate2 signCertificate,
            string manifestPath)
        {
            this.root = root;
            this.rootCertificate = rootCertificate;
            this.intermediateCertificate = intermediateCertificate;
            this.authCertificate = authCertificate;
            this.signCertificate = signCertificate;
            ManifestPath = manifestPath;
            MaterialRoot = Path.Combine(root, "material");
            AuthFingerprint = Fingerprint(authCertificate);
            SignFingerprint = Fingerprint(signCertificate);
            IntermediateFingerprint = Fingerprint(intermediateCertificate);
            RootFingerprint = Fingerprint(rootCertificate);
            AuthSpki = Spki(authCertificate);
            SignVersion = signCertificate.SerialNumber;
        }

        internal string ManifestPath { get; }
        internal string MaterialRoot { get; }
        internal string AuthFingerprint { get; }
        internal string SignFingerprint { get; }
        internal string IntermediateFingerprint { get; }
        internal string RootFingerprint { get; }
        internal string AuthSpki { get; }
        internal string SignVersion { get; }
        internal string RootCertificatePem => rootCertificate.ExportCertificatePem();
        internal string AuthCertificatePem => authCertificate.ExportCertificatePem();
        internal const string AuthReference = "local-pkcs12://fse2-lab/auth";
        internal const string SignReference = "local-pkcs12://fse2-lab/sign";

        internal static Fixture Create()
        {
            string root = Path.Combine(Path.GetTempPath(), "local-pkcs12-provider-tests-" + Guid.NewGuid().ToString("N"));
            string materialRoot = Path.Combine(root, "material");
            Directory.CreateDirectory(materialRoot);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            X509Certificate2 rootCertificate = CreateRoot(now);
            X509Certificate2 intermediateCertificate = CreateIntermediate(rootCertificate, now);
            X509Certificate2 authCertificate = CreateLeaf(
                intermediateCertificate,
                "CN=Local PKCS12 Synthetic A1",
                X509KeyUsageFlags.DigitalSignature,
                "1.3.6.1.5.5.7.3.2",
                now);
            X509Certificate2 signCertificate = CreateLeaf(
                intermediateCertificate,
                "CN=Local PKCS12 Synthetic S1",
                X509KeyUsageFlags.NonRepudiation,
                null,
                now);
            string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            WritePrivate(Path.Combine(materialRoot, "auth.p12"), authCertificate, password);
            WritePrivate(Path.Combine(materialRoot, "sign.p12"), signCertificate, password);
            File.WriteAllText(Path.Combine(materialRoot, "auth.password"), password);
            File.WriteAllText(Path.Combine(materialRoot, "sign.password"), password);
            File.WriteAllText(Path.Combine(materialRoot, "auth-leaf.pem"), authCertificate.ExportCertificatePem());
            File.WriteAllText(Path.Combine(materialRoot, "sign-leaf.pem"), signCertificate.ExportCertificatePem());
            File.WriteAllText(Path.Combine(materialRoot, "intermediate.pem"), intermediateCertificate.ExportCertificatePem());
            File.WriteAllText(Path.Combine(materialRoot, "root.pem"), rootCertificate.ExportCertificatePem());
            string manifestPath = Path.Combine(root, "manifest.json");
            File.WriteAllText(manifestPath, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                resources = new object[]
                {
                    Resource("auth", "ClientCertificate", authCertificate),
                    Resource("sign", "SigningCertificate", signCertificate)
                }
            }));
            return new(root, rootCertificate, intermediateCertificate, authCertificate, signCertificate, manifestPath);

            object Resource(string id, string kind, X509Certificate2 certificate) => new
            {
                id,
                kind,
                pkcs12FileName = id + ".p12",
                pkcs12Sha256 = FileHash(Path.Combine(materialRoot, id + ".p12")),
                passwordFileName = id + ".password",
                passwordFileSha256 = FileHash(Path.Combine(materialRoot, id + ".password")),
                leafFileName = id + "-leaf.pem",
                certificateSha256 = Fingerprint(certificate),
                subjectPublicKeyInfoSha256 = Spki(certificate),
                version = certificate.SerialNumber,
                chain = new[]
                {
                    new { fileName = "intermediate.pem", certificateSha256 = Fingerprint(intermediateCertificate) },
                    new { fileName = "root.pem", certificateSha256 = Fingerprint(rootCertificate) }
                }
            };

            static string FileHash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        }

        internal void ApplyPrivateUseMutation(string role, string mutation)
        {
            string otherRole = role == "sign" ? "auth" : "sign";
            switch (mutation)
            {
                case "chain-deleted":
                    File.Delete(Path.Combine(MaterialRoot, "intermediate.pem"));
                    break;
                case "chain-substituted":
                    File.WriteAllText(Path.Combine(MaterialRoot, "intermediate.pem"), authCertificate.ExportCertificatePem());
                    break;
                case "chain-reordered":
                    string intermediate = File.ReadAllText(Path.Combine(MaterialRoot, "intermediate.pem"));
                    string rootValue = File.ReadAllText(Path.Combine(MaterialRoot, "root.pem"));
                    File.WriteAllText(Path.Combine(MaterialRoot, "intermediate.pem"), rootValue);
                    File.WriteAllText(Path.Combine(MaterialRoot, "root.pem"), intermediate);
                    break;
                case "root-substituted":
                    File.WriteAllText(Path.Combine(MaterialRoot, "root.pem"), authCertificate.ExportCertificatePem());
                    break;
                case "leaf-substituted":
                    File.Copy(Path.Combine(MaterialRoot, otherRole + "-leaf.pem"), Path.Combine(MaterialRoot, role + "-leaf.pem"), overwrite: true);
                    break;
                case "pkcs12-substituted":
                    File.Copy(Path.Combine(MaterialRoot, otherRole + ".p12"), Path.Combine(MaterialRoot, role + ".p12"), overwrite: true);
                    break;
                case "pkcs12-reencoded":
                    X509Certificate2 certificate = role == "sign" ? signCertificate : authCertificate;
                    WritePrivate(
                        Path.Combine(MaterialRoot, role + ".p12"),
                        certificate,
                        File.ReadAllText(Path.Combine(MaterialRoot, role + ".password")));
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mutation));
            }
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

        private static X509Certificate2 CreateRoot(DateTimeOffset now)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new("CN=Local PKCS12 Synthetic Root", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));
        }

        private static X509Certificate2 CreateIntermediate(X509Certificate2 issuer, DateTimeOffset now)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new("CN=Local PKCS12 Synthetic Intermediate", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            using X509Certificate2 publicCertificate = request.Create(issuer, now.AddDays(-1), now.AddDays(20), RandomNumberGenerator.GetBytes(16));
            return publicCertificate.CopyWithPrivateKey(key);
        }

        private static X509Certificate2 CreateLeaf(
            X509Certificate2 issuer,
            string subject,
            X509KeyUsageFlags keyUsage,
            string? enhancedKeyUsage,
            DateTimeOffset now)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
            if (enhancedKeyUsage is not null)
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(enhancedKeyUsage) }, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            using X509Certificate2 publicCertificate = request.Create(issuer, now.AddDays(-1), now.AddDays(10), RandomNumberGenerator.GetBytes(16));
            return publicCertificate.CopyWithPrivateKey(key);
        }

        private static void WritePrivate(string path, X509Certificate2 certificate, string password)
        {
            byte[] encoded = certificate.Export(X509ContentType.Pkcs12, password);
            try { File.WriteAllBytes(path, encoded); }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }

        public void Dispose()
        {
            signCertificate.Dispose();
            authCertificate.Dispose();
            intermediateCertificate.Dispose();
            rootCertificate.Dispose();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
