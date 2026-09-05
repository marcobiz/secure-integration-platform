using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using SecureIntegration.Broker.Core;

namespace SecureIntegration.Broker.Infrastructure.Windows;

/// <summary>Allows configured clients to retain and verify this Broker process, without memory or mutation rights.</summary>
public static class WindowsProcessSecurity
{
    internal const int VerificationRights = 0x00101000; // PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE

    /// <summary>Updates only this process's DACL before IPC starts; existing owner, ACL entries and SACL are preserved.</summary>
    public static void AllowClientVerification(IEnumerable<ApplicationPolicy> applications)
    {
        ArgumentNullException.ThrowIfNull(applications);
        IntPtr descriptor = IntPtr.Zero;
        try
        {
            // A current-process pseudo handle cannot select or alter another process.
            IntPtr process = new(-1);
            if (GetSecurityInfo(process, 6, 4, IntPtr.Zero, IntPtr.Zero, out IntPtr originalDacl, IntPtr.Zero, out descriptor) != 0 ||
                descriptor == IntPtr.Zero || originalDacl == IntPtr.Zero) throw Unavailable();
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length is 0 or > 65536) throw Unavailable();
            byte[] bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            RawSecurityDescriptor security = new(bytes, 0);
            DiscretionaryAcl acl = BuildVerificationAcl(security.DiscretionaryAcl ?? throw Unavailable(),
                applications.SelectMany(static application => application.AllowedUserSids));
            byte[] updated = new byte[acl.BinaryLength];
            acl.GetBinaryForm(updated, 0);
            // DACL_SECURITY_INFORMATION only: never replace owner, group or mandatory-integrity/SACL information.
            if (SetSecurityInfo(process, 6, 4, IntPtr.Zero, IntPtr.Zero, updated, IntPtr.Zero) != 0) throw Unavailable();
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or UnauthorizedAccessException)
        {
            throw Unavailable();
        }
        finally { if (descriptor != IntPtr.Zero) _ = LocalFree(descriptor); }
    }

    internal static DiscretionaryAcl BuildVerificationAcl(RawAcl existing, IEnumerable<string> userSids)
    {
        DiscretionaryAcl acl = new(false, false, existing);
        if (!acl.IsCanonical) throw Unavailable();
        foreach (string value in userSids.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            SecurityIdentifier sid = new(value);
            // Do not convert broad pipe-policy mistakes into process-observation grants.
            if (!sid.IsAccountSid()) throw Unavailable();
            acl.AddAccess(AccessControlType.Allow, sid, VerificationRights, InheritanceFlags.None, PropagationFlags.None);
        }
        return acl;
    }

    private static BrokerException Unavailable() => new("broker_process_security_unavailable", "configuration");

#pragma warning disable SYSLIB1054 // Explicit small Win32 ACL boundary, consistent with the Windows transport interop.
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(IntPtr handle, int type, uint information, IntPtr owner, IntPtr group, out IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint SetSecurityInfo(IntPtr handle, int type, uint information, IntPtr owner, IntPtr group, byte[] dacl, IntPtr sacl);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr pointer);
#pragma warning restore SYSLIB1054
}
