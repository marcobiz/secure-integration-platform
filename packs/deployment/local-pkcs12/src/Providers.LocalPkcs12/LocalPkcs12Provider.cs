using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Providers.LocalPkcs12;

/// <summary>Creates the self-hosted, file-mounted PKCS#12 provider pack.</summary>
public sealed class LocalPkcs12ProviderPackFactory : IProviderPackFactory
{
    private const string ManifestPathSetting = "ManifestPath";
    private const string MaterialRootPathSetting = "MaterialRootPath";

    /// <inheritdoc />
    public ProviderServices Create(ProviderPackContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        try
        {
            if (context.Endpoint.Scheme != Uri.UriSchemeHttps || context.Endpoint.AbsolutePath != "/" ||
                !string.IsNullOrEmpty(context.Endpoint.UserInfo) || !string.IsNullOrEmpty(context.Endpoint.Query) ||
                !string.IsNullOrEmpty(context.Endpoint.Fragment) || !string.IsNullOrWhiteSpace(context.ClientIdentity) ||
                context.Settings.Count != 2 || !context.Settings.TryGetValue(ManifestPathSetting, out string? manifestPath) ||
                !context.Settings.TryGetValue(MaterialRootPathSetting, out string? materialRootPath))
                throw ConfigurationInvalid();

            LocalPkcs12Provider provider = LocalPkcs12Provider.Create(context.Endpoint, manifestPath, materialRootPath);
            return new(provider, provider, provider, provider, SigningKeys: provider,
                CertificateMetadata: provider, CertificatePublicMaterial: provider);
        }
        catch (ProviderAccessException) { throw; }
        catch (Exception) { throw ConfigurationInvalid(); }
    }

    private static ProviderAccessException ConfigurationInvalid() =>
        new("BGW-PROVIDER-CONFIGURATION-INVALID");
}

/// <summary>
/// Self-hosted provider for explicitly allowlisted read-only secret files and PKCS#12 identities.
/// It never accepts a caller-selected path and never exports private-key material.
/// </summary>
public sealed class LocalPkcs12Provider : ISecretValueProvider, IClientCertificateProvider,
    ICertificateMetadataProvider, ICertificatePublicMaterialProvider, IKeyOperationProvider,
    IProviderHealthCheck, IProviderCapabilitySource
{
    private const int MaximumManifestBytes = 256 * 1024;
    private const int MaximumSecretBytes = 64 * 1024;
    private const int MaximumPkcs12Bytes = 1024 * 1024;
    private const int MaximumPublicCertificateBytes = 128 * 1024;
    private const int MaximumPasswordBytes = 2048;
    private const string ClientAuthenticationEku = "1.3.6.1.5.5.7.3.2";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions ManifestJson = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly string authority;
    private readonly string materialRootPath;
    private readonly FrozenDictionary<string, LocalResource> resources;

    private LocalPkcs12Provider(string authority, string materialRootPath, FrozenDictionary<string, LocalResource> resources)
    {
        this.authority = authority;
        this.materialRootPath = materialRootPath;
        this.resources = resources;
    }

    /// <inheritdoc />
    public ProviderCapabilities Capabilities { get; } = new(
        SecretValues: true,
        ClientCertificates: true,
        SigningKeys: true,
        Mac: false,
        CertificatePublicMaterial: true);

    internal static LocalPkcs12Provider Create(Uri endpoint, string manifestPath, string materialRootPath)
    {
        string manifestFullPath = RequiredAbsoluteFile(manifestPath, MaximumManifestBytes);
        string materialRootFullPath = RequiredAbsoluteDirectory(materialRootPath);
        byte[] encoded = ReadFile(manifestFullPath, MaximumManifestBytes);
        try
        {
            LocalProviderManifest manifest = JsonSerializer.Deserialize<LocalProviderManifest>(encoded, ManifestJson)
                ?? throw ConfigurationInvalid();
            FrozenDictionary<string, LocalResource> resources = ValidateManifest(manifest);
            return new(endpoint.IdnHost.ToLowerInvariant(), materialRootFullPath, resources);
        }
        catch (ProviderAccessException) { throw; }
        catch (Exception) { throw ConfigurationInvalid(); }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    /// <inheritdoc />
    public async Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
    {
        LocalResource resource = Resolve(logicalReference, LocalResourceKind.Secret);
        byte[] encoded = await ReadFileAsync(MaterialPath(resource.FileName!), MaximumSecretBytes, cancellationToken).ConfigureAwait(false);
        try { return StrictUtf8.GetString(encoded); }
        catch (DecoderFallbackException) { throw MaterialInvalid(); }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    /// <inheritdoc />
    public async Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
    {
        LocalResource resource = Resolve(logicalReference, LocalResourceKind.ClientCertificate);
        return await LoadPrivateCertificateAsync(resource, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken)
    {
        LocalResource resource = ResolveCertificate(logicalReference);
        using X509Certificate2 leaf = await LoadPublicCertificateAsync(resource, cancellationToken).ConfigureAwait(false);
        return PublicMetadata(leaf, resource.Version!);
    }

    /// <inheritdoc />
    public async Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken)
    {
        LocalResource resource = ResolveCertificate(logicalReference);
        using X509Certificate2 leaf = await LoadPublicCertificateAsync(resource, cancellationToken).ConfigureAwait(false);
        List<X509Certificate2> issuers = await LoadChainAsync(resource, cancellationToken).ConfigureAwait(false);
        try
        {
            ValidateChain(leaf, issuers);
            return new ProviderCertificatePublicMaterial(
                leaf.RawData,
                issuers.Select(value => (ReadOnlyMemory<byte>)value.RawData).ToArray(),
                PublicMetadata(leaf, resource.Version!));
        }
        finally
        {
            foreach (X509Certificate2 issuer in issuers) issuer.Dispose();
        }
    }

    /// <inheritdoc />
    public async Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken)
    {
        if (!string.Equals(algorithm, "RS256", StringComparison.Ordinal) || digest.Length != 32)
            throw new ProviderAccessException("BGW-PROVIDER-SIGNING-ALGORITHM-DENIED");
        LocalResource resource = Resolve(logicalReference, LocalResourceKind.SigningCertificate);
        using X509Certificate2 certificate = await LoadPrivateCertificateAsync(resource, cancellationToken).ConfigureAwait(false);
        try
        {
            using RSA rsa = certificate.GetRSAPrivateKey() ?? throw MaterialInvalid();
            return rsa.SignHash(digest.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (ProviderAccessException) { throw; }
        catch (CryptographicException) { throw MaterialInvalid(); }
    }

    /// <inheritdoc />
    public async Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken)
    {
        LocalResource resource = Resolve(logicalReference, LocalResourceKind.SigningCertificate);
        using X509Certificate2 certificate = await LoadPublicCertificateAsync(resource, cancellationToken).ConfigureAwait(false);
        using RSA rsa = certificate.GetRSAPublicKey() ?? throw MaterialInvalid();
        return new(
            Fingerprint(certificate),
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            "RSA",
            rsa.KeySize,
            resource.Version!,
            rsa.ExportSubjectPublicKeyInfo());
    }

    /// <inheritdoc />
    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            foreach (LocalResource resource in resources.Values)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (resource.Kind == LocalResourceKind.Secret)
                {
                    byte[] secret = await ReadFileAsync(MaterialPath(resource.FileName!), MaximumSecretBytes, cancellationToken).ConfigureAwait(false);
                    try { _ = StrictUtf8.GetCharCount(secret); }
                    finally { CryptographicOperations.ZeroMemory(secret); }
                    continue;
                }

                using X509Certificate2 leaf = await LoadPublicCertificateAsync(resource, cancellationToken).ConfigureAwait(false);
                using X509Certificate2 privateCertificate = await LoadPrivateCertificateAsync(resource, cancellationToken).ConfigureAwait(false);
                List<X509Certificate2> issuers = await LoadChainAsync(resource, cancellationToken).ConfigureAwait(false);
                try { ValidateChain(leaf, issuers); }
                finally { foreach (X509Certificate2 issuer in issuers) issuer.Dispose(); }
            }
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return false; }
    }

    private LocalResource ResolveCertificate(string logicalReference)
    {
        LocalResource resource = Resolve(logicalReference);
        if (resource.Kind is not (LocalResourceKind.ClientCertificate or LocalResourceKind.SigningCertificate))
            throw CapabilityDenied();
        return resource;
    }

    private LocalResource Resolve(string logicalReference, LocalResourceKind expectedKind)
    {
        LocalResource resource = Resolve(logicalReference);
        if (resource.Kind != expectedKind) throw CapabilityDenied();
        return resource;
    }

    private LocalResource Resolve(string logicalReference)
    {
        string prefix = "local-pkcs12://" + authority + "/";
        if (string.IsNullOrEmpty(logicalReference) || !logicalReference.StartsWith(prefix, StringComparison.Ordinal) ||
            !IsIdentifier(logicalReference[prefix.Length..]) ||
            !Uri.TryCreate(logicalReference, UriKind.Absolute, out Uri? reference) ||
            !string.Equals(reference.Scheme, "local-pkcs12", StringComparison.Ordinal) ||
            !string.Equals(reference.IdnHost, authority, StringComparison.Ordinal) || reference.Port != -1 ||
            !string.IsNullOrEmpty(reference.UserInfo) || !string.IsNullOrEmpty(reference.Query) ||
            !string.IsNullOrEmpty(reference.Fragment))
            throw ReferenceDenied();
        string[] segments = reference.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 1 || !IsIdentifier(segments[0]) || !resources.TryGetValue(segments[0], out LocalResource? resource))
            throw ReferenceDenied();
        return resource;
    }

    private async Task<X509Certificate2> LoadPublicCertificateAsync(LocalResource resource, CancellationToken cancellationToken)
    {
        byte[] encoded = await ReadFileAsync(MaterialPath(resource.LeafFileName!), MaximumPublicCertificateBytes, cancellationToken).ConfigureAwait(false);
        try
        {
            X509Certificate2 certificate = LoadPublicCertificate(encoded);
            ValidatePublicIdentity(certificate, resource);
            return certificate;
        }
        catch (ProviderAccessException) { throw; }
        catch (Exception) { throw MaterialInvalid(); }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    private async Task<X509Certificate2> LoadPrivateCertificateAsync(LocalResource resource, CancellationToken cancellationToken)
    {
        byte[] encodedPkcs12 = await ReadFileAsync(MaterialPath(resource.Pkcs12FileName!), MaximumPkcs12Bytes, cancellationToken).ConfigureAwait(false);
        byte[] encodedPassword = await ReadFileAsync(MaterialPath(resource.PasswordFileName!), MaximumPasswordBytes, cancellationToken).ConfigureAwait(false);
        char[] password = DecodePassword(encodedPassword);
        try
        {
            X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12(
                encodedPkcs12,
                password,
                X509KeyStorageFlags.EphemeralKeySet);
            ValidatePrivateIdentity(certificate, resource);
            return certificate;
        }
        catch (ProviderAccessException) { throw; }
        catch (Exception) { throw MaterialInvalid(); }
        finally
        {
            CryptographicOperations.ZeroMemory(encodedPkcs12);
            CryptographicOperations.ZeroMemory(encodedPassword);
            Array.Clear(password);
        }
    }

    private async Task<List<X509Certificate2>> LoadChainAsync(LocalResource resource, CancellationToken cancellationToken)
    {
        List<X509Certificate2> chain = [];
        try
        {
            foreach (LocalChainCertificate configured in resource.Chain)
            {
                byte[] encoded = await ReadFileAsync(MaterialPath(configured.FileName), MaximumPublicCertificateBytes, cancellationToken).ConfigureAwait(false);
                try
                {
                    X509Certificate2 certificate = LoadPublicCertificate(encoded);
                    if (!FixedHexEquals(Fingerprint(certificate), configured.CertificateSha256))
                    {
                        certificate.Dispose();
                        throw MaterialInvalid();
                    }
                    chain.Add(certificate);
                }
                finally { CryptographicOperations.ZeroMemory(encoded); }
            }
            return chain;
        }
        catch
        {
            foreach (X509Certificate2 certificate in chain) certificate.Dispose();
            throw;
        }
    }

    private static X509Certificate2 LoadPublicCertificate(byte[] encoded)
    {
        if (encoded.AsSpan().IndexOf("-----BEGIN CERTIFICATE-----"u8) >= 0)
            return X509Certificate2.CreateFromPem(StrictUtf8.GetString(encoded));
        return X509CertificateLoader.LoadCertificate(encoded);
    }

    private static void ValidateChain(X509Certificate2 leaf, List<X509Certificate2> issuers)
    {
        if (issuers.Count is < 1 or > ProviderCertificatePublicMaterial.MaximumCertificateChainCount)
            throw MaterialInvalid();
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        for (int index = 0; index < issuers.Count - 1; index++) chain.ChainPolicy.ExtraStore.Add(issuers[index]);
        chain.ChainPolicy.CustomTrustStore.Add(issuers[^1]);
        if (!chain.Build(leaf) || chain.ChainElements.Count != issuers.Count + 1) throw MaterialInvalid();
        for (int index = 0; index < chain.ChainElements.Count; index++)
        {
            X509Certificate2 expected = index == 0 ? leaf : issuers[index - 1];
            if (!FixedHexEquals(Fingerprint(chain.ChainElements[index].Certificate), Fingerprint(expected)))
                throw MaterialInvalid();
        }
    }

    private static void ValidatePublicIdentity(X509Certificate2 certificate, LocalResource resource)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        byte[] spki = rsa?.ExportSubjectPublicKeyInfo() ?? ecdsa?.ExportSubjectPublicKeyInfo() ?? throw MaterialInvalid();
        if (!FixedHexEquals(Fingerprint(certificate), resource.CertificateSha256!) ||
            !FixedHexEquals(Convert.ToHexString(SHA256.HashData(spki)), resource.SubjectPublicKeyInfoSha256!) ||
            certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow ||
            certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(value => value.CertificateAuthority) ||
            (resource.Kind == LocalResourceKind.SigningCertificate && (rsa is null || rsa.KeySize < 2048)))
            throw MaterialInvalid();

        if (resource.Kind == LocalResourceKind.ClientCertificate)
        {
            X509EnhancedKeyUsageExtension? eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
            X509KeyUsageExtension? keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
            if (eku is null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(value => string.Equals(value.Value, ClientAuthenticationEku, StringComparison.Ordinal)) ||
                keyUsage is null || (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
                throw MaterialInvalid();
        }
    }

    private static void ValidatePrivateIdentity(X509Certificate2 certificate, LocalResource resource)
    {
        ValidatePublicIdentity(certificate, resource);
        if (!certificate.HasPrivateKey) throw MaterialInvalid();
        using RSA? rsa = certificate.GetRSAPrivateKey();
        using ECDsa? ecdsa = certificate.GetECDsaPrivateKey();
        byte[] privateSpki = rsa?.ExportSubjectPublicKeyInfo() ?? ecdsa?.ExportSubjectPublicKeyInfo() ?? throw MaterialInvalid();
        if (!FixedHexEquals(Convert.ToHexString(SHA256.HashData(privateSpki)), resource.SubjectPublicKeyInfoSha256!) ||
            (resource.Kind == LocalResourceKind.SigningCertificate && rsa is null))
            throw MaterialInvalid();
    }

    private static ProviderCertificatePublicMetadata PublicMetadata(X509Certificate2 certificate, string version)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        string algorithm = rsa is not null ? "RSA" : ecdsa is not null ? "ECDSA" : throw MaterialInvalid();
        int keySize = rsa?.KeySize ?? ecdsa!.KeySize;
        IReadOnlyList<string>? enhancedKeyUsages = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault()?
            .EnhancedKeyUsages.Cast<Oid>().Select(value => value.Value ?? string.Empty).ToArray();
        X509KeyUsageFlags? keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault()?.KeyUsages;
        return new(
            Fingerprint(certificate),
            certificate.Subject,
            certificate.Issuer,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            algorithm,
            keySize,
            version,
            enhancedKeyUsages,
            keyUsage);
    }

    private static FrozenDictionary<string, LocalResource> ValidateManifest(LocalProviderManifest manifest)
    {
        if (manifest.SchemaVersion != 1 || manifest.Resources is null || manifest.Resources.Length is < 1 or > 64)
            throw ConfigurationInvalid();
        Dictionary<string, LocalResource> resources = new(StringComparer.Ordinal);
        HashSet<string> privateFiles = new(StringComparer.Ordinal);
        HashSet<string> leafFiles = new(StringComparer.Ordinal);
        HashSet<string> chainFiles = new(StringComparer.Ordinal);
        foreach (LocalResourceManifest value in manifest.Resources)
        {
            if (!IsIdentifier(value.Id) || !Enum.TryParse(value.Kind, ignoreCase: false, out LocalResourceKind kind) ||
                !resources.TryAdd(value.Id!, ValidateResource(value, kind)))
                throw ConfigurationInvalid();
            LocalResource resource = resources[value.Id!];
            if (kind == LocalResourceKind.Secret)
            {
                if (!privateFiles.Add(resource.FileName!)) throw ConfigurationInvalid();
            }
            else
            {
                if (!privateFiles.Add(resource.Pkcs12FileName!) || !privateFiles.Add(resource.PasswordFileName!) ||
                    !leafFiles.Add(resource.LeafFileName!))
                    throw ConfigurationInvalid();
                foreach (LocalChainCertificate chain in resource.Chain) chainFiles.Add(chain.FileName);
            }
        }
        if (privateFiles.Overlaps(leafFiles) || privateFiles.Overlaps(chainFiles) || leafFiles.Overlaps(chainFiles))
            throw ConfigurationInvalid();
        return resources.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static LocalResource ValidateResource(LocalResourceManifest value, LocalResourceKind kind)
    {
        if (kind == LocalResourceKind.Secret)
        {
            if (!IsFileName(value.FileName) || value.Pkcs12FileName is not null || value.PasswordFileName is not null ||
                value.LeafFileName is not null || value.CertificateSha256 is not null || value.SubjectPublicKeyInfoSha256 is not null ||
                value.Version is not null || value.Chain is { Length: > 0 })
                throw ConfigurationInvalid();
            return new(value.Id!, kind, value.FileName, null, null, null, null, null, null, []);
        }

        if (value.FileName is not null || !IsFileName(value.Pkcs12FileName) || !IsFileName(value.PasswordFileName) ||
            !IsFileName(value.LeafFileName) || !IsSha256(value.CertificateSha256) || !IsSha256(value.SubjectPublicKeyInfoSha256) ||
            !IsVersion(value.Version) || value.Chain is null || value.Chain.Length is < 1 ||
            value.Chain.Length > ProviderCertificatePublicMaterial.MaximumCertificateChainCount)
            throw ConfigurationInvalid();
        HashSet<string> chainNames = new(StringComparer.Ordinal);
        LocalChainCertificate[] chain = value.Chain.Select(item =>
        {
            if (!IsFileName(item.FileName) || !IsSha256(item.CertificateSha256) || !chainNames.Add(item.FileName!))
                throw ConfigurationInvalid();
            return new LocalChainCertificate(item.FileName!, item.CertificateSha256!.ToUpperInvariant());
        }).ToArray();
        return new(value.Id!, kind, null, value.Pkcs12FileName, value.PasswordFileName, value.LeafFileName,
            value.CertificateSha256!.ToUpperInvariant(), value.SubjectPublicKeyInfoSha256!.ToUpperInvariant(), value.Version, chain);
    }

    private string MaterialPath(string fileName) => Path.Combine(materialRootPath, fileName);

    private static char[] DecodePassword(byte[] encoded)
    {
        int length = encoded.Length;
        if (length > 0 && encoded[length - 1] == (byte)'\n') length--;
        if (length > 0 && encoded[length - 1] == (byte)'\r') length--;
        if (length is < 16 or > 1024) throw MaterialInvalid();
        char[] password;
        try
        {
            password = new char[StrictUtf8.GetCharCount(encoded, 0, length)];
            _ = StrictUtf8.GetChars(encoded, 0, length, password, 0);
        }
        catch (DecoderFallbackException) { throw MaterialInvalid(); }
        if (password.Length is < 16 or > 256 || password.Any(char.IsControl))
        {
            Array.Clear(password);
            throw MaterialInvalid();
        }
        return password;
    }

    private static string RequiredAbsoluteFile(string path, int maximumBytes)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) throw ConfigurationInvalid();
        string fullPath = Path.GetFullPath(path);
        FileInfo file = new(fullPath);
        file.Refresh();
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 || file.Length > maximumBytes)
            throw ConfigurationInvalid();
        return fullPath;
    }

    private static string RequiredAbsoluteDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) throw ConfigurationInvalid();
        string fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        DirectoryInfo directory = new(fullPath);
        directory.Refresh();
        if (!directory.Exists || directory.LinkTarget is not null) throw ConfigurationInvalid();
        return fullPath;
    }

    private static byte[] ReadFile(string path, int maximumBytes)
    {
        try
        {
            FileInfo file = new(path);
            file.Refresh();
            if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 || file.Length > maximumBytes) throw MaterialInvalid();
            byte[] encoded = File.ReadAllBytes(path);
            if (encoded.Length is < 1 || encoded.Length > maximumBytes) { CryptographicOperations.ZeroMemory(encoded); throw MaterialInvalid(); }
            return encoded;
        }
        catch (ProviderAccessException) { throw; }
        catch (IOException) { throw ProviderUnavailable(); }
        catch (UnauthorizedAccessException) { throw ProviderUnavailable(); }
    }

    private static async Task<byte[]> ReadFileAsync(string path, int maximumBytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            FileInfo file = new(path);
            file.Refresh();
            if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 || file.Length > maximumBytes) throw MaterialInvalid();
            byte[] encoded = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            if (encoded.Length is < 1 || encoded.Length > maximumBytes) { CryptographicOperations.ZeroMemory(encoded); throw MaterialInvalid(); }
            return encoded;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (ProviderAccessException) { throw; }
        catch (IOException) { throw ProviderUnavailable(); }
        catch (UnauthorizedAccessException) { throw ProviderUnavailable(); }
    }

    private static bool IsIdentifier(string? value) => value is { Length: >= 1 and <= 64 } &&
        value.All(character => character is >= 'a' and <= 'z' || char.IsAsciiDigit(character) || character == '-');

    private static bool IsFileName(string? value) => value is { Length: >= 1 and <= 128 } &&
        value != "." && value != ".." && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    private static bool IsVersion(string? value) => value is { Length: >= 1 and <= 128 } &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    private static bool IsSha256(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static string Fingerprint(X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData));

    private static bool FixedHexEquals(string left, string right) => IsSha256(left) && IsSha256(right) &&
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));

    private static ProviderAccessException ConfigurationInvalid() => new("BGW-PROVIDER-CONFIGURATION-INVALID");
    private static ProviderAccessException ReferenceDenied() => new("BGW-PROVIDER-REFERENCE-DENIED");
    private static ProviderAccessException CapabilityDenied() => new("BGW-PROVIDER-CAPABILITY-DENIED");
    private static ProviderAccessException MaterialInvalid() => new("BGW-PROVIDER-MATERIAL-INVALID");
    private static ProviderAccessException ProviderUnavailable() => new("BGW-PROVIDER-UNAVAILABLE", retryable: true);

    private sealed record LocalResource(
        string Id,
        LocalResourceKind Kind,
        string? FileName,
        string? Pkcs12FileName,
        string? PasswordFileName,
        string? LeafFileName,
        string? CertificateSha256,
        string? SubjectPublicKeyInfoSha256,
        string? Version,
        IReadOnlyList<LocalChainCertificate> Chain);

    private sealed record LocalChainCertificate(string FileName, string CertificateSha256);

    private enum LocalResourceKind
    {
        Secret,
        ClientCertificate,
        SigningCertificate
    }

    private sealed record LocalProviderManifest(int SchemaVersion, LocalResourceManifest[] Resources);

    private sealed record LocalResourceManifest(
        string? Id,
        string? Kind,
        string? FileName,
        string? Pkcs12FileName,
        string? PasswordFileName,
        string? LeafFileName,
        string? CertificateSha256,
        string? SubjectPublicKeyInfoSha256,
        string? Version,
        LocalChainCertificateManifest[]? Chain);

    private sealed record LocalChainCertificateManifest(string? FileName, string? CertificateSha256);
}
