Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-CoreInventoryJsonString {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value)

    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $code = [int][char]$character
        if ($code -eq 0x22) { [void]$builder.Append('\"') }
        elseif ($code -eq 0x5c) { [void]$builder.Append('\\') }
        elseif ($code -eq 0x08) { [void]$builder.Append('\b') }
        elseif ($code -eq 0x09) { [void]$builder.Append('\t') }
        elseif ($code -eq 0x0a) { [void]$builder.Append('\n') }
        elseif ($code -eq 0x0c) { [void]$builder.Append('\f') }
        elseif ($code -eq 0x0d) { [void]$builder.Append('\r') }
        elseif ($code -lt 0x20) { [void]$builder.Append(('\u{0:x4}' -f $code)) }
        else { [void]$builder.Append($character) }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Get-CoreInventorySha256 {
    param([Parameter(Mandatory = $true)][byte[]] $Bytes)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($Bytes)
        try { return ([BitConverter]::ToString($hash)).Replace('-', '') }
        finally { [Array]::Clear($hash, 0, $hash.Length) }
    }
    finally { $sha256.Dispose() }
}

function Test-CoreInventoryPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('\') -or $Path.Contains(':') -or
        $Path.StartsWith('/', [StringComparison]::Ordinal) -or
        $Path.Contains('//')) { return $false }
    foreach ($character in $Path.ToCharArray()) { if ([char]::IsControl($character)) { return $false } }
    foreach ($segment in $Path.Split('/')) {
        if ($segment.Length -eq 0 -or $segment -eq '.' -or $segment -eq '..') { return $false }
    }
    return $true
}

function New-CoreInventoryIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $SourceCommit,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]] $Files
    )

    if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'CORE_INVENTORY_SOURCE_COMMIT_INVALID' }
    $byPath = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $byPathIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $Files) {
        if ($file -is [Collections.IDictionary]) {
            if (-not $file.Contains('path') -or -not $file.Contains('bytes') -or -not $file.Contains('sha256')) { throw 'CORE_INVENTORY_ENTRY_SHAPE_INVALID' }
            $pathValue = $file['path']; $bytesValue = $file['bytes']; $shaValue = $file['sha256']
        }
        else {
            $pathProperty = $file.PSObject.Properties['path']
            $bytesProperty = $file.PSObject.Properties['bytes']
            $shaProperty = $file.PSObject.Properties['sha256']
            if ($null -eq $pathProperty -or $null -eq $bytesProperty -or $null -eq $shaProperty) { throw 'CORE_INVENTORY_ENTRY_SHAPE_INVALID' }
            $pathValue = $pathProperty.Value; $bytesValue = $bytesProperty.Value; $shaValue = $shaProperty.Value
        }
        $path = [string]$pathValue
        if (-not (Test-CoreInventoryPath -Path $path)) { throw "CORE_INVENTORY_PATH_INVALID: $path" }
        if ($byPath.ContainsKey($path) -or -not $byPathIgnoreCase.Add($path)) { throw "CORE_INVENTORY_PATH_DUPLICATE: $path" }
        try { $bytes = [Convert]::ToInt64($bytesValue, [Globalization.CultureInfo]::InvariantCulture) }
        catch { throw "CORE_INVENTORY_BYTE_COUNT_INVALID: $path" }
        if ($bytes -lt 0) { throw "CORE_INVENTORY_BYTE_COUNT_INVALID: $path" }
        $sha256 = ([string]$shaValue).ToUpperInvariant()
        if ($sha256 -cnotmatch '^[0-9A-F]{64}$') { throw "CORE_INVENTORY_SHA256_INVALID: $path" }
        $byPath.Add($path, [pscustomobject]@{ path = $path; bytes = $bytes; sha256 = $sha256 })
    }

    [string[]]$paths = @($byPath.Keys)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $entries = New-Object 'Collections.Generic.List[string]'
    foreach ($path in $paths) {
        $entry = $byPath[$path]
        $entryJson = '{"path":' + (ConvertTo-CoreInventoryJsonString -Value $entry.path) +
            ',"bytes":' + $entry.bytes.ToString([Globalization.CultureInfo]::InvariantCulture) +
            ',"sha256":' + (ConvertTo-CoreInventoryJsonString -Value $entry.sha256) + '}'
        $entries.Add($entryJson)
    }
    $canonicalJson = '{"schemaVersion":1,"sourceCommit":' +
        (ConvertTo-CoreInventoryJsonString -Value $SourceCommit) +
        ',"fileCount":' + $paths.Length.ToString([Globalization.CultureInfo]::InvariantCulture) +
        ',"files":[' + ($entries -join ',') + ']}'
    [byte[]]$canonicalBytes = [Text.UTF8Encoding]::new($false).GetBytes($canonicalJson)
    try { $sha256 = Get-CoreInventorySha256 -Bytes $canonicalBytes }
    finally { [Array]::Clear($canonicalBytes, 0, $canonicalBytes.Length) }
    return [pscustomobject]@{ canonicalJson = $canonicalJson; normalizedInventorySha256 = $sha256; fileCount = $paths.Length }
}

function Write-CoreInventoryUtf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string] $LiteralPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value
    )
    [IO.File]::WriteAllText($LiteralPath, $Value, [Text.UTF8Encoding]::new($false))
}

Export-ModuleMember -Function New-CoreInventoryIdentity, Get-CoreInventorySha256, Write-CoreInventoryUtf8NoBom
