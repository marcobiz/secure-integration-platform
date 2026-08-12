Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:IsWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT

if ($script:IsWindows -and $null -eq ('Fse2.SafePath.NativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;

namespace Fse2.SafePath
{
    public static class NativeMethods
    {
        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            FileShare shareMode,
            IntPtr securityAttributes,
            FileMode creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out BY_HANDLE_FILE_INFORMATION information);

        private static SafeFileHandle Open(string path)
        {
            SafeFileHandle handle = CreateFile(
                path,
                FILE_READ_ATTRIBUTES,
                FileShare.ReadWrite | FileShare.Delete,
                IntPtr.Zero,
                FileMode.Open,
                FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error);
            }
            return handle;
        }

        public static string FinalPath(string path)
        {
            using (SafeFileHandle handle = Open(path))
            {
                StringBuilder value = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandle(handle, value, (uint)value.Capacity, 0);
                if (length == 0 || length >= value.Capacity)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                string result = value.ToString();
                if (result.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                    return @"\\" + result.Substring(8);
                if (result.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                    return result.Substring(4);
                return result;
            }
        }

        public static string Identity(string path)
        {
            using (SafeFileHandle handle = Open(path))
            {
                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return information.VolumeSerialNumber.ToString("X8") + ":" +
                    information.FileIndexHigh.ToString("X8") + information.FileIndexLow.ToString("X8");
            }
        }
    }
}
'@
}

function Test-Fse2PathEqual {
    param([string] $Left, [string] $Right)
    $comparison = if ($script:IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    return [string]::Equals($Left, $Right, $comparison)
}

function Test-Fse2PathContained {
    param([string] $Candidate, [string] $Root)
    $comparison = if ($script:IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    $separator = [IO.Path]::DirectorySeparatorChar
    $normalizedRoot = $Root.TrimEnd('\', '/')
    return [string]::Equals($Candidate.TrimEnd('\', '/'), $normalizedRoot, $comparison) -or
        $Candidate.StartsWith($normalizedRoot + $separator, $comparison)
}

function Get-Fse2FileIdentity {
    param([Parameter(Mandatory = $true)][string] $Path)
    if ($script:IsWindows) { return [Fse2.SafePath.NativeMethods]::Identity($Path) }
    $value = (& stat -Lc '%d:%i' -- $Path 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)) { throw 'FSE2_PATH_IDENTITY_FAILED' }
    return $value
}

function Get-Fse2FinalPath {
    param([Parameter(Mandatory = $true)][string] $Path)
    if ($script:IsWindows) { return [IO.Path]::GetFullPath([Fse2.SafePath.NativeMethods]::FinalPath($Path)).TrimEnd('\', '/') }
    return (Resolve-Path -LiteralPath $Path).Path.TrimEnd('\', '/')
}

function Assert-Fse2PathSyntax {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][string] $ErrorCodePrefix)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw ($ErrorCodePrefix + '_INVALID') }
    if ($script:IsWindows) {
        if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
            $Path.StartsWith('//', [StringComparison]::Ordinal) -or
            $Path.StartsWith('\\?\', [StringComparison]::Ordinal) -or
            $Path.StartsWith('\\.\', [StringComparison]::Ordinal) -or
            $Path.Substring(2).Contains(':')) {
            throw ($ErrorCodePrefix + '_INVALID')
        }
        $drive = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
        if ([IO.DriveInfo]::new($drive).DriveType -eq [IO.DriveType]::Network) { throw ($ErrorCodePrefix + '_NETWORK_DENIED') }
    }
    elseif (-not $Path.StartsWith('/', [StringComparison]::Ordinal) -or $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw ($ErrorCodePrefix + '_INVALID')
    }
}

function Get-Fse2PathSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][ValidateSet('File', 'Directory', 'OutputDirectory')][string] $Kind,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $ErrorCodePrefix,
        [long] $MaximumBytes = 0
    )

    Assert-Fse2PathSyntax -Path $Path -ErrorCodePrefix $ErrorCodePrefix
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $repository = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
    if (Test-Fse2PathContained -Candidate $fullPath -Root $repository) { throw ($ErrorCodePrefix + '_REPOSITORY_DENIED') }

    $exists = Test-Path -LiteralPath $fullPath
    if ($Kind -eq 'OutputDirectory') {
        if ($exists) { throw ($ErrorCodePrefix + '_EXISTS') }
        $inspectionPath = Split-Path -Parent $fullPath
        if (-not (Test-Path -LiteralPath $inspectionPath -PathType Container)) { throw ($ErrorCodePrefix + '_PARENT_INVALID') }
    }
    else {
        if (-not $exists) { throw ($ErrorCodePrefix + '_MISSING') }
        if ($Kind -eq 'File' -and -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw ($ErrorCodePrefix + '_TYPE_INVALID') }
        if ($Kind -eq 'Directory' -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) { throw ($ErrorCodePrefix + '_TYPE_INVALID') }
        $inspectionPath = $fullPath
    }

    if (-not $script:IsWindows) {
        $fileSystemType = (& stat -f -c '%T' -- $inspectionPath 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($fileSystemType)) {
            throw ($ErrorCodePrefix + '_FILESYSTEM_INVALID')
        }
        if ($fileSystemType -match '^(?:nfs|nfs4|cifs|smb2|smb3|fuse\.sshfs|9p|afs|ceph|glusterfs)$') {
            throw ($ErrorCodePrefix + '_NETWORK_DENIED')
        }
    }

    $cursor = $inspectionPath
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ($ErrorCodePrefix + '_REPARSE_DENIED') }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or (Test-Fse2PathEqual -Left $parent -Right $cursor)) { break }
        $cursor = $parent
    }

    if ($Kind -eq 'File' -and $MaximumBytes -gt 0) {
        $file = [IO.FileInfo]::new($fullPath)
        $file.Refresh()
        if ($file.Length -lt 1 -or $file.Length -gt $MaximumBytes) { throw ($ErrorCodePrefix + '_SIZE_INVALID') }
    }

    $resolvedInspection = Get-Fse2FinalPath -Path $inspectionPath
    $resolvedPath = if ($Kind -eq 'OutputDirectory') {
        Join-Path $resolvedInspection (Split-Path -Leaf $fullPath)
    } else { $resolvedInspection }
    $resolvedPath = [IO.Path]::GetFullPath($resolvedPath).TrimEnd('\', '/')
    if (Test-Fse2PathContained -Candidate $resolvedPath -Root $repository) { throw ($ErrorCodePrefix + '_REPOSITORY_DENIED') }

    $parentPath = if ($Kind -eq 'OutputDirectory') { $inspectionPath } else { Split-Path -Parent $fullPath }
    $parentResolved = Get-Fse2FinalPath -Path $parentPath
    [pscustomobject]@{
        FullPath = $fullPath
        ResolvedPath = $resolvedPath
        Identity = if ($Kind -eq 'OutputDirectory') { $null } else { Get-Fse2FileIdentity -Path $fullPath }
        ParentFullPath = $parentPath
        ParentResolvedPath = $parentResolved
        ParentIdentity = Get-Fse2FileIdentity -Path $parentPath
        Kind = $Kind
        RepositoryRoot = $repository
        ErrorCodePrefix = $ErrorCodePrefix
        MaximumBytes = $MaximumBytes
    }
}

function Assert-Fse2PathSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $Snapshot)
    $current = Get-Fse2PathSnapshot -Path $Snapshot.FullPath -Kind $Snapshot.Kind -RepositoryRoot $Snapshot.RepositoryRoot `
        -ErrorCodePrefix $Snapshot.ErrorCodePrefix -MaximumBytes $Snapshot.MaximumBytes
    if (-not (Test-Fse2PathEqual -Left $current.ResolvedPath -Right $Snapshot.ResolvedPath) -or
        -not (Test-Fse2PathEqual -Left $current.ParentResolvedPath -Right $Snapshot.ParentResolvedPath) -or
        $current.ParentIdentity -ne $Snapshot.ParentIdentity -or $current.Identity -ne $Snapshot.Identity) {
        throw ($Snapshot.ErrorCodePrefix + '_CHANGED')
    }
    return $current
}

function New-Fse2OwnershipMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $DirectorySnapshot,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-f0-9]{32}$')][string] $RunId
    )
    Assert-Fse2PathSnapshot -Snapshot $DirectorySnapshot | Out-Null
    $markerPath = Join-Path $DirectorySnapshot.FullPath '.fse2-owner.json'
    if (Test-Path -LiteralPath $markerPath) { throw ($DirectorySnapshot.ErrorCodePrefix + '_MARKER_EXISTS') }
    $marker = [ordered]@{ schemaVersion = 1; runId = $RunId; directoryIdentity = $DirectorySnapshot.Identity }
    [IO.File]::WriteAllText($markerPath, ($marker | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    return Get-Fse2PathSnapshot -Path $markerPath -Kind File -RepositoryRoot $DirectorySnapshot.RepositoryRoot `
        -ErrorCodePrefix ($DirectorySnapshot.ErrorCodePrefix + '_MARKER') -MaximumBytes 4096
}

function Remove-Fse2OwnedDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $DirectorySnapshot,
        [Parameter(Mandatory = $true)] $MarkerSnapshot,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-f0-9]{32}$')][string] $RunId
    )
    Assert-Fse2PathSnapshot -Snapshot $DirectorySnapshot | Out-Null
    Assert-Fse2PathSnapshot -Snapshot $MarkerSnapshot | Out-Null
    $marker = Get-Content -LiteralPath $MarkerSnapshot.FullPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([int]$marker.schemaVersion -ne 1 -or [string]$marker.runId -cne $RunId -or
        [string]$marker.directoryIdentity -cne [string]$DirectorySnapshot.Identity) {
        throw ($DirectorySnapshot.ErrorCodePrefix + '_MARKER_INVALID')
    }
    foreach ($item in Get-ChildItem -LiteralPath $DirectorySnapshot.FullPath -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ($DirectorySnapshot.ErrorCodePrefix + '_CLEANUP_REPARSE_DENIED')
        }
    }
    Assert-Fse2PathSnapshot -Snapshot $DirectorySnapshot | Out-Null
    if ($script:IsWindows) {
        $operator = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        foreach ($item in @((Get-Item -LiteralPath $DirectorySnapshot.FullPath -Force)) + @(Get-ChildItem -LiteralPath $DirectorySnapshot.FullPath -Recurse -Force)) {
            $grant = if ($item.PSIsContainer) { ('*' + $operator + ':(OI)(CI)(F)') } else { ('*' + $operator + ':(F)') }
            & icacls $item.FullName /grant:r $grant *> $null
            if ($LASTEXITCODE -ne 0) { throw ($DirectorySnapshot.ErrorCodePrefix + '_CLEANUP_ACL_FAILED') }
        }
    } else {
        & chmod -R u+rwX -- $DirectorySnapshot.FullPath
        if ($LASTEXITCODE -ne 0) { throw ($DirectorySnapshot.ErrorCodePrefix + '_CLEANUP_ACL_FAILED') }
    }
    Assert-Fse2PathSnapshot -Snapshot $DirectorySnapshot | Out-Null
    Remove-Item -LiteralPath $DirectorySnapshot.FullPath -Recurse -Force
    if (Test-Path -LiteralPath $DirectorySnapshot.FullPath) { throw ($DirectorySnapshot.ErrorCodePrefix + '_CLEANUP_FAILED') }
}

function Assert-Fse2ExactRuntimeAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $RuntimeIdentity
    )
    try {
        $items = @((Get-Item -LiteralPath $Path -Force)) + @(Get-ChildItem -LiteralPath $Path -Recurse -Force)
        if ($script:IsWindows) {
            if (-not $RuntimeIdentity.IsWindows) { throw 'platform-mismatch' }
            $expectedSids = @('S-1-5-18', 'S-1-5-32-544', [string]$RuntimeIdentity.Value)
            foreach ($item in $items) {
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
                $acl = Get-Acl -LiteralPath $item.FullName
                if (-not $acl.AreAccessRulesProtected) { throw 'inheritance' }
                $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
                if ($rules.Count -ne 3 -or @($rules | Where-Object {
                    $_.IsInherited -or $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow
                }).Count -ne 0) { throw 'unexpected-rule' }
                $expectedInheritance = if ($item.PSIsContainer) {
                    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
                } else { [Security.AccessControl.InheritanceFlags]::None }
                $expectedRuntimeRights = if ($item.PSIsContainer) {
                    [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
                } else {
                    [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Synchronize
                }
                $expectedRights = @(
                    [Security.AccessControl.FileSystemRights]::FullControl,
                    [Security.AccessControl.FileSystemRights]::FullControl,
                    $expectedRuntimeRights)
                for ($index = 0; $index -lt $expectedSids.Count; $index++) {
                    $matches = @($rules | Where-Object {
                        $_.IdentityReference.Value -eq $expectedSids[$index] -and
                        $_.FileSystemRights -eq $expectedRights[$index] -and
                        $_.InheritanceFlags -eq $expectedInheritance -and
                        $_.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None
                    })
                    if ($matches.Count -ne 1) { throw 'rule-mismatch' }
                }
            }
        } else {
            if ($RuntimeIdentity.IsWindows) { throw 'platform-mismatch' }
            foreach ($item in $items) {
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
                $metadata = (& stat -Lc '%u:%a' -- $item.FullName 2>$null | Out-String).Trim()
                $expectedMode = if ($item.PSIsContainer) { '550' } else { '440' }
                if ($LASTEXITCODE -ne 0 -or $metadata -cne (([string]$RuntimeIdentity.Value) + ':' + $expectedMode)) {
                    throw 'mode-or-owner-mismatch'
                }
            }
        }
    }
    catch {
        if ($_.Exception.Message -eq 'FSE2_LOCAL_IMPORT_ACL_VERIFY_FAILED') { throw }
        throw 'FSE2_LOCAL_IMPORT_ACL_VERIFY_FAILED'
    }
}

Export-ModuleMember -Function Get-Fse2PathSnapshot, Assert-Fse2PathSnapshot, New-Fse2OwnershipMarker, `
    Remove-Fse2OwnedDirectory, Assert-Fse2ExactRuntimeAcl
