using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecureIntegration.Providers.Synthetic;

/// <summary>Per-run RSA keys and X.509 certificates for authentication primitive tests only.</summary>
public sealed class SyntheticAuthenticationMaterial : IDisposable
{
    private SyntheticAuthenticationMaterial(
        X509Certificate2 rootCertificate,
        X509Certificate2 serverCertificate,
        X509Certificate2 signingKeyRevision1,
        X509Certificate2 signingKeyRevision2,
        X509Certificate2 clientCertificateRevision1,
        X509Certificate2 clientCertificateRevision2,
        X509Certificate2 expiredClientCertificate,
        X509Certificate2 nearExpiryClientCertificate,
        X509Certificate2 wrongPurposeCertificate)
    {
        RootCertificate = rootCertificate;
        ServerCertificate = serverCertificate;
        SigningKeyRevision1 = signingKeyRevision1;
        SigningKeyRevision2 = signingKeyRevision2;
        ClientCertificateRevision1 = clientCertificateRevision1;
        ClientCertificateRevision2 = clientCertificateRevision2;
        ExpiredClientCertificate = expiredClientCertificate;
        NearExpiryClientCertificate = nearExpiryClientCertificate;
        WrongPurposeCertificate = wrongPurposeCertificate;
    }

    /// <summary>Synthetic trust anchor.</summary>
    public X509Certificate2 RootCertificate { get; }
    /// <summary>Localhost ServerAuth certificate.</summary>
    public X509Certificate2 ServerCertificate { get; }
    /// <summary>JWT signing key revision 1.</summary>
    public X509Certificate2 SigningKeyRevision1 { get; }
    /// <summary>JWT signing key revision 2.</summary>
    public X509Certificate2 SigningKeyRevision2 { get; }
    /// <summary>ClientAuth certificate revision 1.</summary>
    public X509Certificate2 ClientCertificateRevision1 { get; }
    /// <summary>ClientAuth certificate revision 2.</summary>
    public X509Certificate2 ClientCertificateRevision2 { get; }
    /// <summary>Expired ClientAuth certificate.</summary>
    public X509Certificate2 ExpiredClientCertificate { get; }
    /// <summary>Valid ClientAuth certificate inside the warning window.</summary>
    public X509Certificate2 NearExpiryClientCertificate { get; }
    /// <summary>ServerAuth-only certificate that must be denied for outbound client authentication.</summary>
    public X509Certificate2 WrongPurposeCertificate { get; }

    /// <summary>Generates all private material at runtime and never writes it to disk.</summary>
    public static SyntheticAuthenticationMaterial Create(DateTimeOffset now)
    {
        using RSA rootKey = RSA.Create(2048);
        CertificateRequest rootRequest = new("CN=BrokerGateway M6 Synthetic Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddDays(-30), now.AddYears(2));

        X509Certificate2 Issue(string subject, DateTimeOffset notBefore, DateTimeOffset notAfter, string eku, bool localhostSan = false)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            OidCollection usages = new() { new Oid(eku) };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            if (localhostSan)
            {
                SubjectAlternativeNameBuilder san = new();
                san.AddDnsName("localhost");
                san.AddIpAddress(IPAddress.Loopback);
                request.CertificateExtensions.Add(san.Build());
            }
            byte[] serial = RandomNumberGenerator.GetBytes(16);
            using X509Certificate2 publicCertificate = request.Create(root, notBefore, notAfter, serial);
            using X509Certificate2 combined = publicCertificate.CopyWithPrivateKey(key);
            byte[] runtimePkcs12 = combined.Export(X509ContentType.Pkcs12);
            try { return X509CertificateLoader.LoadPkcs12(runtimePkcs12, null, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable); }
            finally { CryptographicOperations.ZeroMemory(runtimePkcs12); }
        }

        X509Certificate2 IssueSigning(string subject)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            using X509Certificate2 publicCertificate = request.Create(root, now.AddDays(-1), now.AddDays(90), RandomNumberGenerator.GetBytes(16));
            return publicCertificate.CopyWithPrivateKey(key);
        }

        return new(
            root,
            Issue("CN=localhost", now.AddDays(-1), now.AddDays(30), "1.3.6.1.5.5.7.3.1", true),
            IssueSigning("CN=M6 Synthetic JWT Signing R1"),
            IssueSigning("CN=M6 Synthetic JWT Signing R2"),
            Issue("CN=M6 Synthetic Client R1", now.AddDays(-1), now.AddDays(60), "1.3.6.1.5.5.7.3.2"),
            Issue("CN=M6 Synthetic Client R2", now.AddDays(-1), now.AddDays(90), "1.3.6.1.5.5.7.3.2"),
            Issue("CN=M6 Synthetic Expired Client", now.AddDays(-10), now.AddDays(-1), "1.3.6.1.5.5.7.3.2"),
            Issue("CN=M6 Synthetic Near Expiry Client", now.AddDays(-1), now.AddDays(2), "1.3.6.1.5.5.7.3.2"),
            Issue("CN=M6 Synthetic Wrong Purpose", now.AddDays(-1), now.AddDays(60), "1.3.6.1.5.5.7.3.1"));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        WrongPurposeCertificate.Dispose();
        NearExpiryClientCertificate.Dispose();
        ExpiredClientCertificate.Dispose();
        ClientCertificateRevision2.Dispose();
        ClientCertificateRevision1.Dispose();
        SigningKeyRevision2.Dispose();
        SigningKeyRevision1.Dispose();
        ServerCertificate.Dispose();
        RootCertificate.Dispose();
    }
}
