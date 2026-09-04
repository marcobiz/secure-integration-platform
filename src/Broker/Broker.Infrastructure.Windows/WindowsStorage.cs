using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using SecureIntegration.Broker.Core;

namespace SecureIntegration.Broker.Infrastructure.Windows;

/// <summary>DPAPI CurrentUser protection bound to the service profile.</summary>
public sealed class WindowsDpapiProtectionProvider : ILocalProtectionProvider
{
    /// <inheritdoc />
    public byte[] Protect(byte[] plaintext, byte[] entropy) => ProtectedData.Protect(plaintext, entropy, DataProtectionScope.CurrentUser);
    /// <inheritdoc />
    public byte[] Unprotect(byte[] protectedData, byte[] entropy) => ProtectedData.Unprotect(protectedData, entropy, DataProtectionScope.CurrentUser);
}

/// <summary>Hardens Broker storage so only the service identity, SYSTEM and administrators inherit access.</summary>
public static class WindowsStorageSecurity
{
    /// <summary>Creates or hardens a directory ACL.</summary>
    public static void HardenDirectory(string path)
    {
        Directory.CreateDirectory(path);
        DirectoryInfo directory = new(path);
        DirectorySecurity security = directory.GetAccessControl();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>())
        {
            security.RemoveAccessRuleSpecific(rule);
        }

        SecurityIdentifier current = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("The service identity has no SID.");
        AddFullControl(security, current);
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        directory.SetAccessControl(security);
    }

    private static void AddFullControl(DirectorySecurity security, SecurityIdentifier identity) =>
        security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
}

/// <summary>Atomic file repository containing only DPAPI-protected secret values.</summary>
public sealed class FileLocalSecretRepository : ILocalSecretRepository, IDisposable
{
    private readonly string directory;
    private readonly SemaphoreSlim mutex = new(1, 1);

    /// <summary>Creates the repository below a hardened directory.</summary>
    public FileLocalSecretRepository(string dataDirectory)
    {
        directory = Path.Combine(dataDirectory, "secrets");
        WindowsStorageSecurity.HardenDirectory(directory);
    }

    /// <inheritdoc />
    public async Task SaveAsync(LocalSecretRecord record, CancellationToken cancellationToken)
    {
        await mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            SecretDocument document = new(record.SecretRef, record.OwnerApplicationId, record.LogicalName, record.SecretClass.ToString(), [.. record.AllowedOperations], Convert.ToBase64String(record.ProtectedValue));
            await AtomicWriteAsync(PathFor(record.SecretRef), JsonSerializer.SerializeToUtf8Bytes(document), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            mutex.Release();
        }
    }

    /// <inheritdoc />
    public async Task<LocalSecretRecord?> FindAsync(string secretRef, CancellationToken cancellationToken)
    {
        string path = PathFor(secretRef);
        if (!File.Exists(path)) return null;
        byte[] json = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        SecretDocument document;
        try
        {
            document = JsonSerializer.Deserialize<SecretDocument>(json) ?? throw new BrokerException("local_storage_corrupt", "storage");
        }
        catch (JsonException exception)
        {
            throw new BrokerException("local_storage_corrupt", "storage", innerException: exception);
        }

        if (!Enum.TryParse(document.SecretClass, out LocalSecretClass secretClass) || document.AllowedOperations is null || string.IsNullOrWhiteSpace(document.ProtectedValueBase64)) throw new BrokerException("local_storage_corrupt", "storage");
        try
        {
            return new LocalSecretRecord(document.SecretRef, document.OwnerApplicationId, document.LogicalName, secretClass, new HashSet<string>(document.AllowedOperations, StringComparer.Ordinal), Convert.FromBase64String(document.ProtectedValueBase64));
        }
        catch (FormatException exception)
        {
            throw new BrokerException("local_storage_corrupt", "storage", innerException: exception);
        }
    }

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string secretRef, CancellationToken cancellationToken)
    {
        string path = PathFor(secretRef);
        if (!File.Exists(path)) return Task.FromResult(false);
        File.Delete(path);
        return Task.FromResult(true);
    }

    private string PathFor(string secretRef)
    {
        if (!secretRef.StartsWith("lsr_", StringComparison.Ordinal) || secretRef.Any(static value => !char.IsAsciiLetterOrDigit(value) && value != '_')) throw new BrokerException("invalid_secret_ref", "validation");
        return Path.Combine(directory, secretRef + ".json");
    }

    private static async Task AtomicWriteAsync(string path, byte[] data, CancellationToken cancellationToken)
    {
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllBytesAsync(temporary, data, cancellationToken).ConfigureAwait(false);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private sealed record SecretDocument(string SecretRef, string OwnerApplicationId, string LogicalName, string SecretClass, string[] AllowedOperations, string ProtectedValueBase64);

    /// <inheritdoc />
    public void Dispose() => mutex.Dispose();
}

/// <summary>DPAPI-wrapped, versioned Installation key repository.</summary>
public sealed class FileDataKeyRepository : IDataKeyRepository, IDisposable
{
    private static readonly byte[] Entropy = SHA256.HashData("broker-data-key-v1"u8);
    private readonly string directory;
    private readonly ILocalProtectionProvider protection;
    private readonly SemaphoreSlim mutex = new(1, 1);

    /// <summary>Creates a key repository.</summary>
    public FileDataKeyRepository(string dataDirectory, ILocalProtectionProvider protection)
    {
        directory = Path.Combine(dataDirectory, "keys");
        this.protection = protection;
        WindowsStorageSecurity.HardenDirectory(directory);
    }

    /// <summary>Explicit first-use provisioning. Existing keys are verified, never replaced; partial initialization fails closed.</summary>
    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (File.Exists(Path.Combine(directory, "active.txt")))
            {
                DataKey existing = await ReadActiveAsync(cancellationToken).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(existing.Value);
                return;
            }

            if (Directory.EnumerateFileSystemEntries(directory).Any()) throw new BrokerException("data_key_initialization_incomplete", "storage");
            // CreateNew is the cross-process claim. Keep it on every failure, including interrupted writes.
            await CreateNewAsync(Path.Combine(directory, "initialized.marker"), "broker-data-key-v1"u8.ToArray(), cancellationToken).ConfigureAwait(false);
            byte[] key = RandomNumberGenerator.GetBytes(32);
            try
            {
                byte[] wrapped = protection.Protect(key, Entropy);
                await CreateNewAsync(KeyPath(1), wrapped, cancellationToken).ConfigureAwait(false);
                await CreateNewAsync(Path.Combine(directory, "active.txt"), "1"u8.ToArray(), cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            throw new BrokerException("data_key_initialization_failed", "storage");
        }
        finally { mutex.Release(); }
    }

    /// <inheritdoc />
    public async Task<DataKey> GetActiveAsync(CancellationToken cancellationToken)
    {
        await mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ReadActiveAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            mutex.Release();
        }
    }

    /// <inheritdoc />
    public async Task<DataKey?> GetAsync(uint version, CancellationToken cancellationToken) => File.Exists(KeyPath(version)) ? await LoadAsync(version, cancellationToken).ConfigureAwait(false) : null;

    private async Task<DataKey> ReadActiveAsync(CancellationToken cancellationToken)
    {
        try
        {
            string activePath = Path.Combine(directory, "active.txt");
            if (!File.Exists(activePath)) throw new BrokerException("data_key_store_not_initialized", "storage");
            if (new FileInfo(activePath).Length > 16 ||
                !uint.TryParse(await File.ReadAllTextAsync(activePath, cancellationToken).ConfigureAwait(false), out uint version) || version == 0)
                throw new BrokerException("key_metadata_corrupt", "storage");
            return await LoadAsync(version, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new BrokerException("data_key_storage_unavailable", "storage");
        }
    }

    private async Task<DataKey> LoadAsync(uint version, CancellationToken cancellationToken)
    {
        try
        {
            if (new FileInfo(KeyPath(version)).Length > 16384) throw new BrokerException("data_key_unwrap_failed", "crypto");
            byte[] wrapped = await File.ReadAllBytesAsync(KeyPath(version), cancellationToken).ConfigureAwait(false);
            byte[] key = protection.Unprotect(wrapped, Entropy);
            if (key.Length != 32)
            {
                CryptographicOperations.ZeroMemory(key);
                throw new BrokerException("data_key_unwrap_failed", "crypto");
            }
            return new DataKey(version, key);
        }
        catch (CryptographicException) { throw new BrokerException("data_key_unwrap_failed", "crypto"); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new BrokerException("data_key_storage_unavailable", "storage");
        }
    }

    private static async Task CreateNewAsync(string path, byte[] data, CancellationToken cancellationToken)
    {
        await using FileStream file = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.Asynchronous);
        await file.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        file.Flush(flushToDisk: true);
    }

    private string KeyPath(uint version) => Path.Combine(directory, $"key-{version}.bin");

    /// <inheritdoc />
    public void Dispose() => mutex.Dispose();
}
