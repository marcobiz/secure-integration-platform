using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Authentication.CertificateSigning.Tests;

public sealed class ProviderCertificatePublicMaterialImmutabilityTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Wave1_public_material_snapshot_isolated_from_leaf_chain_and_collection_input_mutation()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        byte[] leafInput = material.SigningKeyRevision1.RawData.ToArray();
        byte[] chainInput = material.RootCertificate.RawData.ToArray();
        ReadOnlyMemory<byte>[] chainCollection = [chainInput];
        ProviderCertificatePublicMaterial snapshot = new(leafInput, chainCollection, Metadata(material.SigningKeyRevision1));

        leafInput[0] ^= 0xff;
        chainInput[0] ^= 0xff;
        chainCollection[0] = material.SigningKeyRevision2.RawData;

        Assert.Equal(material.SigningKeyRevision1.RawData, snapshot.LeafCertificateDer.ToArray());
        Assert.Equal(material.RootCertificate.RawData, Assert.Single(snapshot.CertificateChainDer).ToArray());
    }

    [Fact]
    public void Wave1_public_material_getters_return_unshared_copies_and_non_array_collection()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        ProviderCertificatePublicMaterial snapshot = new(
            material.SigningKeyRevision1.RawData,
            [(ReadOnlyMemory<byte>)material.RootCertificate.RawData],
            Metadata(material.SigningKeyRevision1));

        ReadOnlyMemory<byte> firstLeaf = snapshot.LeafCertificateDer;
        Assert.True(MemoryMarshal.TryGetArray(firstLeaf, out ArraySegment<byte> leafBacking));
        leafBacking.Array![leafBacking.Offset] ^= 0xff;
        IReadOnlyList<ReadOnlyMemory<byte>> firstChain = snapshot.CertificateChainDer;
        Assert.False(firstChain is ReadOnlyMemory<byte>[]);
        ReadOnlyMemory<byte> firstIssuer = Assert.Single(firstChain);
        Assert.True(MemoryMarshal.TryGetArray(firstIssuer, out ArraySegment<byte> issuerBacking));
        issuerBacking.Array![issuerBacking.Offset] ^= 0xff;

        Assert.Equal(material.SigningKeyRevision1.RawData, snapshot.LeafCertificateDer.ToArray());
        Assert.Equal(material.RootCertificate.RawData, Assert.Single(snapshot.CertificateChainDer).ToArray());
    }

    [Fact]
    public void Wave1_public_material_metadata_collection_is_copy_safe()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        string[] enhancedKeyUsages = ["1.3.6.1.5.5.7.3.2"];
        ProviderCertificatePublicMetadata metadata = Metadata(material.SigningKeyRevision1) with { EnhancedKeyUsages = enhancedKeyUsages };
        ProviderCertificatePublicMaterial snapshot = new(material.SigningKeyRevision1.RawData, [], metadata);

        enhancedKeyUsages[0] = "mutated";
        ProviderCertificatePublicMetadata first = snapshot.Metadata;
        Assert.False(first.EnhancedKeyUsages is string[]);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)first.EnhancedKeyUsages!)[0] = "mutated-again");

        Assert.Equal("1.3.6.1.5.5.7.3.2", Assert.Single(snapshot.Metadata.EnhancedKeyUsages!));
    }

    [Fact]
    public void Wave1_public_material_accepts_exact_chain_bounds_without_exposing_mutable_storage()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        ReadOnlyMemory<byte>[] maximumCount = Enumerable.Range(0, ProviderCertificatePublicMaterial.MaximumCertificateChainCount)
            .Select(_ => (ReadOnlyMemory<byte>)material.RootCertificate.RawData)
            .ToArray();
        ProviderCertificatePublicMaterial countBoundary = new(material.SigningKeyRevision1.RawData, maximumCount, Metadata(material.SigningKeyRevision1));
        ProviderCertificatePublicMaterial entryBoundary = new(
            material.SigningKeyRevision1.RawData,
            [new byte[ProviderCertificatePublicMaterial.MaximumCertificateDerBytes]],
            Metadata(material.SigningKeyRevision1));

        Assert.Equal(ProviderCertificatePublicMaterial.MaximumCertificateChainCount, countBoundary.CertificateChainDer.Count);
        Assert.Equal(ProviderCertificatePublicMaterial.MaximumCertificateDerBytes, Assert.Single(entryBoundary.CertificateChainDer).Length);
    }

    [Fact]
    public void Wave1_public_material_rejects_oversize_leaf_before_certificate_parsing_or_copy()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        byte[] oversized = new byte[ProviderCertificatePublicMaterial.MaximumCertificateDerBytes + 1];

        ArgumentOutOfRangeException failure = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ProviderCertificatePublicMaterial(oversized, [], Metadata(material.SigningKeyRevision1)));

        Assert.Equal("leafCertificateDer", failure.ParamName);
    }

    [Fact]
    public void Wave1_public_material_rejects_too_many_chain_entries_before_copy()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        ReadOnlyMemory<byte>[] tooMany = Enumerable.Range(0, ProviderCertificatePublicMaterial.MaximumCertificateChainCount + 1)
            .Select(_ => (ReadOnlyMemory<byte>)material.RootCertificate.RawData)
            .ToArray();

        ArgumentOutOfRangeException failure = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ProviderCertificatePublicMaterial(material.SigningKeyRevision1.RawData, tooMany, Metadata(material.SigningKeyRevision1)));

        Assert.Equal("certificateChainDer", failure.ParamName);
    }

    [Fact]
    public void Wave1_public_material_rejects_oversize_chain_entry_and_total_before_copy()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        ReadOnlyMemory<byte> oversizedEntry = new byte[ProviderCertificatePublicMaterial.MaximumCertificateDerBytes + 1];
        ReadOnlyMemory<byte>[] oversizedTotal = Enumerable.Range(0, 4)
            .Select(_ => (ReadOnlyMemory<byte>)new byte[ProviderCertificatePublicMaterial.MaximumCertificateDerBytes])
            .ToArray();

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ProviderCertificatePublicMaterial(material.SigningKeyRevision1.RawData, [oversizedEntry], Metadata(material.SigningKeyRevision1)));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ProviderCertificatePublicMaterial(material.SigningKeyRevision1.RawData, oversizedTotal, Metadata(material.SigningKeyRevision1)));
    }

    private static ProviderCertificatePublicMetadata Metadata(X509Certificate2 certificate)
    {
        using RSA rsa = certificate.GetRSAPublicKey()!;
        return new(
            Convert.ToHexString(SHA256.HashData(certificate.RawData)),
            certificate.Subject,
            certificate.Issuer,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            "RSA",
            rsa.KeySize,
            certificate.SerialNumber);
    }
}
