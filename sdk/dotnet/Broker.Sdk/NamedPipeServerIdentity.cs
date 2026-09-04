using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecureIntegration.Broker.Sdk;

// SCM configuration and the virtual service SID are installation authority, not wire claims.
internal sealed class NamedPipeServerIdentity : IDisposable
{
    private readonly SafeProcessHandle process;
    private readonly uint processId;
    private readonly byte[] ownerSid;

    internal NamedPipeServerIdentity(uint processId, byte[] ownerSid)
    {
        this.processId = processId;
        this.ownerSid = ownerSid;
        process = OpenProcess(0x1000 | 0x100000, false, processId); // limited query + synchronize only
        if (process.IsInvalid) { process.Dispose(); throw Rejected(); }
    }

    internal static NamedPipeServerIdentity Open(string serviceName)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) throw Rejected();
        using ServiceHandle manager = OpenSCManager(null, null, 1);
        using ServiceHandle service = OpenService(manager, serviceName, 4); // SERVICE_QUERY_STATUS
        if (manager.IsInvalid || service.IsInvalid || !QueryServiceStatusEx(service, 0, out ServiceStatus status, 36, out _) ||
            status.Type != 0x10 || status.State != 4 || status.ProcessId == 0) throw Rejected();
        NamedPipeServerIdentity identity = new(status.ProcessId, AccountSid("NT SERVICE\\" + serviceName));
        try
        {
            if (!QueryServiceStatusEx(service, 0, out ServiceStatus confirmed, 36, out _) ||
                confirmed.State != 4 || confirmed.ProcessId != status.ProcessId) throw Rejected();
            return identity;
        }
        catch { identity.Dispose(); throw; }
    }

    internal void Verify(NamedPipeClientStream pipe)
    {
        if (WaitForSingleObject(process, 0) != 258 ||
            !GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint connectedProcessId) || connectedProcessId != processId) throw Rejected();
        IntPtr descriptor = IntPtr.Zero;
        try
        {
            // The owner is kernel-authenticated and cannot be set to the service SID by a normal user.
            // This also rejects a stale-PID pipe whose creator has exited and transferred its handles.
            if (GetSecurityInfo(pipe.SafePipeHandle, 6, 1, out IntPtr owner, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out descriptor) != 0 ||
                owner == IntPtr.Zero || !EqualSid(ownerSid, owner) || WaitForSingleObject(process, 0) != 258) throw Rejected();
        }
        finally { if (descriptor != IntPtr.Zero) _ = LocalFree(descriptor); }
    }

    public void Dispose() => process.Dispose();
    private static BrokerClientException Rejected() => new("broker_server_not_authenticated", "authentication", false);

    private static byte[] AccountSid(string account)
    {
        uint sidSize = 0, domainSize = 0;
        _ = LookupAccountName(null, account, null, ref sidSize, null, ref domainSize, out _);
        if (sidSize == 0 || sidSize > 256 || domainSize > 256) throw Rejected();
        byte[] sid = new byte[sidSize];
        char[] domain = new char[domainSize];
        if (!LookupAccountName(null, account, sid, ref sidSize, domain, ref domainSize, out _)) throw Rejected();
        return sid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint Type, State, Controls, Win32ExitCode, ServiceExitCode, CheckPoint, WaitHint, ProcessId, Flags;
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

#pragma warning disable SYSLIB1054 // The SDK also targets netstandard2.0, without source-generated marshalling.
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW", ExactSpelling = true)]
    private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "OpenServiceW", ExactSpelling = true)]
    private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatus status, int size, out int needed);
    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafePipeHandle handle, int type, uint information, out IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EqualSid(byte[] expected, IntPtr actual);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "LookupAccountNameW", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupAccountName(string? system, string account, byte[]? sid, ref uint sidSize, [Out] char[]? domain, ref uint domainSize, out int use);
#pragma warning restore SYSLIB1054
}
