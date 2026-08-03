using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SecureIntegration.Broker.Core;

/// <summary>Creates versioned AES-256-GCM envelopes bound to installation, application and purpose.</summary>
public sealed class AeadDataProtector
{
    private static readonly byte[] Magic = "BGA1"u8.ToArray();
    private readonly IDataKeyRepository keys;
    private readonly string installationId;

    /// <summary>Creates the protector.</summary>
    public AeadDataProtector(IDataKeyRepository keys, string installationId)
    {
        this.keys = keys ?? throw new ArgumentNullException(nameof(keys));
        this.installationId = Require(installationId, nameof(installationId), 128);
    }

    /// <summary>Protects plaintext and returns a self-describing binary envelope.</summary>
    public async Task<byte[]> ProtectAsync(string applicationId, string purpose, string contentType, byte[] plaintext, CancellationToken cancellationToken)
    {
        ValidateContext(applicationId, purpose, contentType);
        ArgumentNullException.ThrowIfNull(plaintext);
        DataKey key = await keys.GetActiveAsync(cancellationToken).ConfigureAwait(false);
        ValidateKey(key.Value);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] aad = CreateAad(applicationId, purpose, contentType);
        try
        {
            using AesGcm aes = new(key.Value, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            byte[] envelope = new byte[4 + 4 + nonce.Length + tag.Length + ciphertext.Length];
            Magic.CopyTo(envelope, 0);
            BinaryPrimitives.WriteUInt32BigEndian(envelope.AsSpan(4, 4), key.Version);
            nonce.CopyTo(envelope, 8);
            tag.CopyTo(envelope, 20);
            ciphertext.CopyTo(envelope, 36);
            return envelope;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(key.Value);
        }
    }

    /// <summary>Authenticates and decrypts a versioned envelope.</summary>
    public async Task<byte[]> UnprotectAsync(string applicationId, string purpose, string contentType, byte[] envelope, CancellationToken cancellationToken)
    {
        ValidateContext(applicationId, purpose, contentType);
        ArgumentNullException.ThrowIfNull(envelope);
        if (envelope.Length < 36 || !envelope.AsSpan(0, 4).SequenceEqual(Magic))
        {
            throw new BrokerException("invalid_envelope", "validation");
        }

        uint version = BinaryPrimitives.ReadUInt32BigEndian(envelope.AsSpan(4, 4));
        DataKey? key = await keys.GetAsync(version, cancellationToken).ConfigureAwait(false);
        if (key is null)
        {
            throw new BrokerException("key_version_not_found", "crypto");
        }

        ValidateKey(key.Value);
        byte[] plaintext = new byte[envelope.Length - 36];
        byte[] aad = CreateAad(applicationId, purpose, contentType);
        try
        {
            using AesGcm aes = new(key.Value, 16);
            aes.Decrypt(envelope.AsSpan(8, 12), envelope.AsSpan(36), envelope.AsSpan(20, 16), plaintext, aad);
            return plaintext;
        }
        catch (CryptographicException exception)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new BrokerException("authentication_failed", "crypto", innerException: exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(key.Value);
        }
    }

    private byte[] CreateAad(string applicationId, string purpose, string contentType) =>
        Encoding.UTF8.GetBytes($"broker-aead-v1\n{installationId}\n{applicationId}\n{purpose}\n{contentType}");

    private static void ValidateContext(string applicationId, string purpose, string contentType)
    {
        _ = Require(applicationId, nameof(applicationId), 128);
        _ = Require(purpose, nameof(purpose), 128);
        _ = Require(contentType, nameof(contentType), 128);
    }

    private static string Require(string value, string name, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum)
        {
            throw new BrokerException("invalid_" + name, "validation");
        }

        return value;
    }

    private static void ValidateKey(byte[] key)
    {
        if (key.Length != 32)
        {
            throw new BrokerException("invalid_data_key", "configuration");
        }
    }
}
