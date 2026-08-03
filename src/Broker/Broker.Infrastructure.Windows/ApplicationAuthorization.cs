using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SecureIntegration.Broker.Core;

namespace SecureIntegration.Broker.Infrastructure.Windows;

/// <summary>Identity and live process handle retained for the complete Named Pipe connection.</summary>
public sealed class CallerIdentity : IDisposable
{
    private readonly SafeProcessHandle processHandle;
    private readonly FileStream executableFile;

    internal CallerIdentity(uint processId, string userSid, string executablePath, string executableSha256, string? publisherThumbprint, DateTimeOffset processStartTimeUtc, SafeProcessHandle processHandle, FileStream executableFile)
    {
        ProcessId = processId;
        UserSid = userSid;
        ExecutablePath = executablePath;
        ExecutableSha256 = executableSha256;
        PublisherThumbprint = publisherThumbprint;
        ProcessStartTimeUtc = processStartTimeUtc;
        this.processHandle = processHandle;
        this.executableFile = executableFile;
    }

    /// <summary>Kernel process ID.</summary>
    public uint ProcessId { get; }
    /// <summary>SID from the process primary token.</summary>
    public string UserSid { get; }
    /// <summary>Canonical executable path.</summary>
    public string ExecutablePath { get; }
    /// <summary>SHA-256 of the opened executable.</summary>
    public string ExecutableSha256 { get; }
    /// <summary>Trusted Authenticode publisher leaf thumbprint, if present.</summary>
    public string? PublisherThumbprint { get; }
    /// <summary>Process creation time captured while holding its handle.</summary>
    public DateTimeOffset ProcessStartTimeUtc { get; }
    /// <inheritdoc />
    public void Dispose()
    {
        executableFile.Dispose();
        processHandle.Dispose();
    }
}

/// <summary>Authorizes a caller against its registered SID, executable and operation grants.</summary>
public sealed class ApplicationAuthorizer
{
    private readonly Dictionary<string, ApplicationPolicy> policies;

    /// <summary>Creates an authorizer from application manifests.</summary>
    public ApplicationAuthorizer(IEnumerable<ApplicationPolicy> policies) =>
        this.policies = policies.ToDictionary(static policy => policy.RegistrationId, StringComparer.Ordinal);

    /// <summary>Authorizes the handshake identity and returns the selected policy.</summary>
    public ApplicationPolicy AuthorizeApplication(string registrationId, CallerIdentity caller)
    {
        if (!policies.TryGetValue(registrationId, out ApplicationPolicy? policy) ||
            !policy.AllowedUserSids.Contains(caller.UserSid, StringComparer.OrdinalIgnoreCase) ||
            !policy.ExecutablePaths.Any(path => string.Equals(Path.GetFullPath(path), caller.ExecutablePath, StringComparison.OrdinalIgnoreCase)) ||
            (policy.ExecutableSha256.Count > 0 && !policy.ExecutableSha256.Contains(caller.ExecutableSha256, StringComparer.OrdinalIgnoreCase)) ||
            (policy.AllowedPublisherThumbprints.Count > 0 && (caller.PublisherThumbprint is null || !policy.AllowedPublisherThumbprints.Contains(caller.PublisherThumbprint, StringComparer.OrdinalIgnoreCase))))
        {
            throw new BrokerException("application_not_authorized", "authorization");
        }

        return policy;
    }

    /// <summary>Authorizes an operation and its optional fixed Gateway grant.</summary>
    public static void AuthorizeOperation(ApplicationPolicy policy, string operation, string? connectorId = null, string? operationId = null)
    {
        if (!policy.AllowedOperations.Contains(operation, StringComparer.Ordinal))
        {
            throw new BrokerException("operation_not_granted", "authorization");
        }

        if (operation == "InvokeGateway" && !policy.GatewayGrants.Contains(connectorId + ":" + operationId, StringComparer.Ordinal))
        {
            throw new BrokerException("gateway_operation_not_granted", "authorization");
        }
    }
}

/// <summary>Captures PID, SID, path and hash from an already connected Named Pipe.</summary>
public static class NamedPipeCallerIdentity
{
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint Synchronize = 0x00100000;
    private const uint StillActive = 259;

    /// <summary>Captures caller identity before request dispatch.</summary>
    public static CallerIdentity Capture(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint processId)) throw new BrokerException("caller_identity_unavailable", "authorization");
        SafeProcessHandle processHandle = OpenProcess(ProcessQueryLimitedInformation | Synchronize, false, processId);
        FileStream? executable = null;
        try
        {
            if (processHandle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open the Named Pipe client process.");
            DateTimeOffset startTime = GetProcessStartTimeUtc(processHandle);
            if (!OpenProcessToken(processHandle, (uint)TokenAccessLevels.Query, out SafeAccessTokenHandle accessToken)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open the Named Pipe client process token.");
            using (accessToken)
            using (WindowsIdentity identity = new(accessToken.DangerousGetHandle()))
            {
                string sid = identity.User?.Value ?? throw new InvalidOperationException("Cannot identify Named Pipe client SID.");
                string path = GetProcessImagePath(processHandle);
                executable = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                string hash = Convert.ToHexString(SHA256.HashData(executable));
                string? publisher = AuthenticodePublisher.TryGetTrustedThumbprint(path);
                if (!GetExitCodeProcess(processHandle, out uint exitCode) || exitCode != StillActive || GetProcessStartTimeUtc(processHandle) != startTime) throw new BrokerException("caller_process_exited", "authorization");
                return new CallerIdentity(processId, sid, path, hash, publisher, startTime, processHandle, executable);
            }
        }
        catch (Exception exception)
        {
            executable?.Dispose();
            processHandle.Dispose();
            if (exception is Win32Exception or InvalidOperationException or UnauthorizedAccessException)
            {
                throw new BrokerException("caller_identity_unavailable", "authorization");
            }
            throw;
        }
    }

    private static DateTimeOffset GetProcessStartTimeUtc(SafeProcessHandle processHandle)
    {
        if (!GetProcessTimes(processHandle, out long creationTime, out _, out _, out _)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read the Named Pipe client process creation time.");
        return new DateTimeOffset(DateTime.FromFileTimeUtc(creationTime));
    }

    private static string GetProcessImagePath(SafeProcessHandle processHandle)
    {
        uint length = 32768;
        IntPtr path = Marshal.AllocHGlobal(checked((int)length * sizeof(char)));
        try
        {
            if (!QueryFullProcessImageName(processHandle, 0, path, ref length)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot identify the Named Pipe client executable.");
            return Path.GetFullPath(Marshal.PtrToStringUni(path) ?? throw new InvalidOperationException("Cannot identify the Named Pipe client executable."));
        }
        finally
        {
            Marshal.FreeHGlobal(path);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
#pragma warning disable SYSLIB1054 // SafeHandle signature does not require source-generated marshalling.
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);
#pragma warning restore SYSLIB1054

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle processHandle, uint flags, IntPtr executablePath, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle processHandle, out long creationTime, out long exitTime, out long kernelTime, out long userTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle processHandle, out uint exitCode);

#pragma warning disable SYSLIB1054 // SafeHandle signature does not require source-generated marshalling.
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);
#pragma warning restore SYSLIB1054
}

internal static class AuthenticodePublisher
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public static string? TryGetTrustedThumbprint(string path)
    {
        IntPtr pathPointer = Marshal.StringToCoTaskMemUni(path);
        WinTrustFileInfo file = new() { StructureSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(), FilePath = pathPointer };
        IntPtr filePointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(file, filePointer, false);
            WinTrustData data = new()
            {
                StructureSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2,
                RevocationChecks = 0,
                UnionChoice = 1,
                FileInfo = filePointer,
                StateAction = 0,
                ProviderFlags = 0x1000,
            };
            Guid action = GenericVerifyV2;
            if (WinVerifyTrust(IntPtr.Zero, ref action, ref data) != 0) return null;
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is required to obtain the verified PE signer certificate.
            using X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            using X509Certificate2 certificate2 = new(certificate);
            return certificate2.Thumbprint;
        }
        catch (CryptographicException)
        {
            return null;
        }
        finally
        {
            Marshal.FreeCoTaskMem(filePointer);
            Marshal.FreeCoTaskMem(pathPointer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructureSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructureSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

#pragma warning disable SYSLIB1054 // WinVerifyTrust uses a mutable Guid and blittable structures.
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr windowHandle, ref Guid actionId, ref WinTrustData trustData);
#pragma warning restore SYSLIB1054
}
