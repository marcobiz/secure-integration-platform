using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.LocalPkcs12;

namespace SecureIntegration.Tools.Fse2.ProviderProbe;

internal static class Program
{
    private const string AuthReference = "local-pkcs12://fse2-lab/fse2-auth";
    private const string SignReference = "local-pkcs12://fse2-lab/fse2-sign";

    public static async Task<int> Main(string[] args)
    {
        if (args.Length is < 2 or > 3)
            return 2;
        bool expectNotReady = args.Length == 3 && string.Equals(args[2], "--expect-not-ready", StringComparison.Ordinal);
        if (args.Length == 3 && !expectNotReady)
            return 2;

        try
        {
            ProviderServices services = new LocalPkcs12ProviderPackFactory().Create(new(
                new Uri("https://fse2-lab/"),
                null,
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ManifestPath"] = args[0],
                    ["MaterialRootPath"] = args[1]
                }));

            if (expectNotReady)
            {
                if (await services.Health.IsReadyAsync(CancellationToken.None).ConfigureAwait(false))
                    return 3;
                await ExpectDeniedAsync(() => services.SigningKeys!.SignDigestAsync(
                    SignReference,
                    "RS256",
                    SHA256.HashData("synthetic-probe"u8),
                    CancellationToken.None)).ConfigureAwait(false);
                await ExpectDeniedAsync(() => services.ClientCertificates.GetClientCertificateAsync(
                    AuthReference,
                    CancellationToken.None)).ConfigureAwait(false);
                Console.WriteLine("FSE2_LOCAL_PROVIDER_PROBE_TAMPER_PASS; SIGNATURES=0; CERTIFICATES=0");
                return 0;
            }

            if (!await services.Health.IsReadyAsync(CancellationToken.None).ConfigureAwait(false) ||
                services.CapabilitySource.Capabilities.SecretValues ||
                !services.CapabilitySource.Capabilities.ClientCertificates ||
                !services.CapabilitySource.Capabilities.SigningKeys)
                return 3;

            using X509Certificate2 clientCertificate = await services.ClientCertificates.GetClientCertificateAsync(
                AuthReference,
                CancellationToken.None).ConfigureAwait(false);
            if (!clientCertificate.HasPrivateKey)
                return 3;

            byte[] digest = SHA256.HashData("synthetic-probe"u8);
            byte[] signature = await services.SigningKeys!.SignDigestAsync(
                SignReference,
                "RS256",
                digest,
                CancellationToken.None).ConfigureAwait(false);
            ProviderSigningKeyPublicMetadata metadata = await services.SigningKeys.GetSigningKeyMetadataAsync(
                SignReference,
                CancellationToken.None).ConfigureAwait(false);
            using RSA verifier = RSA.Create();
            verifier.ImportSubjectPublicKeyInfo(metadata.SubjectPublicKeyInfo, out int bytesRead);
            if (bytesRead != metadata.SubjectPublicKeyInfo.Length ||
                !verifier.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                return 3;

            try
            {
                _ = await services.SecretValues.GetSecretAsync("local-pkcs12://fse2-lab/secret", CancellationToken.None).ConfigureAwait(false);
                return 3;
            }
            catch (ProviderAccessException exception) when (exception.Code == "BGW-PROVIDER-CAPABILITY-DENIED") { }

            Console.WriteLine("FSE2_LOCAL_PROVIDER_PROBE_PASS; SIGNATURES=1; CERTIFICATES=1; SECRET_VALUES=0");
            return 0;
        }
        catch (ProviderAccessException)
        {
            return 3;
        }
        catch (CryptographicException)
        {
            return 3;
        }
    }

    private static async Task ExpectDeniedAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
            throw new InvalidOperationException("Expected provider denial.");
        }
        catch (ProviderAccessException exception) when (
            exception.Code is "BGW-PROVIDER-MATERIAL-INVALID" or "BGW-PROVIDER-UNAVAILABLE") { }
    }

    private static async Task ExpectDeniedAsync<T>(Func<Task<T>> action) =>
        await ExpectDeniedAsync(async () => { _ = await action().ConfigureAwait(false); }).ConfigureAwait(false);
}
