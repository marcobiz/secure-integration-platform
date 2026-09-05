using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;

namespace SecureIntegration.Samples.LocalBroker;

// Application-owned data, not a Broker secret repository. No key or new IPC operation.
internal static class CredentialExample
{
    internal const string Purpose = "installation-credential";
    internal const string ContentType = "text/plain";
    internal const int MaximumCharacters = 1024;
    private const int MaximumEnvelopeBytes = 8192;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static byte[] ReadInput(TextReader? redirectedInput)
    {
        char[] characters = new char[MaximumCharacters];
        int count = 0;
        try
        {
            if (redirectedInput is null) Console.Error.Write("Credential (input hidden): ");
            while (true)
            {
                int value;
                if (redirectedInput is not null) value = redirectedInput.Read();
                else
                {
                    ConsoleKeyInfo key = Console.ReadKey(intercept: true);
                    if (key.Key == ConsoleKey.Enter) break;
                    if (key.Key == ConsoleKey.Backspace)
                    {
                        if (count > 0) characters[--count] = '\0';
                        continue;
                    }
                    if (key.Key == ConsoleKey.Escape) throw new OperationCanceledException();
                    value = key.KeyChar;
                }
                if (value is -1 or '\n') break;
                if (value == '\r' && redirectedInput is not null)
                {
                    if (redirectedInput.Read() != '\n') throw new InvalidOperationException("CREDENTIAL_INPUT_INVALID");
                    break;
                }
                if (char.IsControl((char)value) || count == characters.Length)
                    throw new InvalidOperationException("CREDENTIAL_INPUT_INVALID");
                characters[count++] = (char)value;
            }
            if (count == 0) throw new InvalidOperationException("CREDENTIAL_INPUT_INVALID");
            byte[] result = new byte[Utf8.GetByteCount(characters.AsSpan(0, count))];
            _ = Utf8.GetBytes(characters.AsSpan(0, count), result);
            return result;
        }
        finally
        {
            Array.Clear(characters);
            if (redirectedInput is null) Console.Error.WriteLine();
        }
    }

    internal static async Task ConfigureAsync(BrokerClient client, string path, byte[] plaintext, CancellationToken cancellationToken)
    {
        if (plaintext.Length is 0 or > MaximumCharacters * 4) throw new InvalidOperationException("CREDENTIAL_INPUT_INVALID");
        path = PreparePath(path, createDirectory: true);
        bool replacing = File.Exists(path);
        if (replacing)
        {
            // Refuse to replace a foreign, corrupt or differently scoped configuration.
            byte[] previous = await ReadAsync(client, path, cancellationToken);
            CryptographicOperations.ZeroMemory(previous);
        }
        ProtectedDataResult protectedData = await client.ProtectDataAsync(new ProtectDataRequest
        {
            Purpose = Purpose, ContentType = ContentType, PlaintextBase64 = Convert.ToBase64String(plaintext)
        }, cancellationToken);
        byte[] envelope = Convert.FromBase64String(protectedData.EnvelopeBase64);
        string staging = Path.Combine(Path.GetDirectoryName(path)!, $".credential-{Guid.NewGuid():N}.tmp");
        bool stagingCreated = false;
        try
        {
            // Only ciphertext is staged. Same-directory replacement never truncates the old file.
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            FileSecurity security = new();
            security.SetOwner(identity.User!);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (SecurityIdentifier owner in AllowedOwners(identity.User!))
                security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
            await using (FileStream file = new FileInfo(staging).Create(FileMode.CreateNew, FileSystemRights.Write,
                FileShare.None, 4096, FileOptions.None, security))
            {
                stagingCreated = true;
                await file.WriteAsync(envelope, cancellationToken);
                file.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            _ = PreparePath(path, createDirectory: false);
            if (replacing) File.Replace(staging, path, destinationBackupFileName: null);
            else File.Move(staging, path, overwrite: false);
            stagingCreated = false;
        }
        finally
        {
            if (stagingCreated) File.Delete(staging);
        }
    }

    internal static async Task<byte[]> ReadAsync(BrokerClient client, string path, CancellationToken cancellationToken)
    {
        path = PreparePath(path, createDirectory: false);
        await using FileStream file = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is 0 or > MaximumEnvelopeBytes) throw new InvalidOperationException("CREDENTIAL_ENVELOPE_INVALID");
        byte[] envelope = new byte[checked((int)file.Length)];
        await file.ReadExactlyAsync(envelope, cancellationToken);
        UnprotectedDataResult result = await client.UnprotectDataAsync(new UnprotectDataRequest
        {
            Purpose = Purpose, ContentType = ContentType, EnvelopeBase64 = Convert.ToBase64String(envelope)
        }, cancellationToken);
        return Convert.FromBase64String(result.PlaintextBase64);
    }

    private static string PreparePath(string path, bool createDirectory)
    {
        string fullPath = Path.GetFullPath(path);
        // Local regular paths only; never follow links or alter an existing directory's ACL.
        if (fullPath.StartsWith("\\\\", StringComparison.Ordinal) || fullPath.AsSpan(2).Contains(':'))
            throw new InvalidOperationException("CREDENTIAL_PATH_DENIED");
        DirectoryInfo directory = new(Path.GetDirectoryName(fullPath)!);
        for (DirectoryInfo? ancestor = directory; ancestor is not null; ancestor = ancestor.Parent)
            if (ancestor.Exists && (ancestor.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("CREDENTIAL_PATH_DENIED");
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("CREDENTIAL_OWNER_UNAVAILABLE");
        if (!directory.Exists && createDirectory)
        {
            if (directory.Parent?.Exists != true) throw new InvalidOperationException("CREDENTIAL_PARENT_REQUIRED");
            DirectorySecurity security = new();
            security.SetOwner(user);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (SecurityIdentifier owner in AllowedOwners(user))
                security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            directory.Create(security);
        }
        AssertPrivateOwner(directory.GetAccessControl(), user);
        FileInfo existing = new(fullPath);
        if (existing.Exists)
        {
            if ((existing.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("CREDENTIAL_PATH_DENIED");
            AssertPrivateOwner(existing.GetAccessControl(), user);
        }
        return fullPath;
    }

    private static SecurityIdentifier[] AllowedOwners(SecurityIdentifier user) =>
        [user, new(WellKnownSidType.LocalSystemSid, null), new(WellKnownSidType.BuiltinAdministratorsSid, null)];

    private static void AssertPrivateOwner(FileSystemSecurity security, SecurityIdentifier user)
    {
        if (!user.Equals(security.GetOwner(typeof(SecurityIdentifier)))) throw new InvalidOperationException("CREDENTIAL_OWNERSHIP_DENIED");
        SecurityIdentifier[] allowed = AllowedOwners(user);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !allowed.Contains(rule.IdentityReference))
                throw new InvalidOperationException("CREDENTIAL_OWNERSHIP_DENIED");
    }
}
