$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$jsonFiles = @(
    'docs/connectors/connector-definition.schema.json',
    'docs/connectors/examples/secure-layer.example.json',
    'docs/connectors/examples/managed-connector.example.json',
    'docs/connectors/examples/sample-secure-service.connector.json'
)

foreach ($relative in $jsonFiles) {
    Get-Content -Raw -LiteralPath (Join-Path $root $relative) | ConvertFrom-Json | Out-Null
}

$badLinks = @()
Get-ChildItem -LiteralPath (Join-Path $root 'docs') -Recurse -Filter '*.md' | ForEach-Object {
    $file = $_
    $raw = Get-Content -Raw -LiteralPath $file.FullName
    [regex]::Matches($raw, '\[[^\]]+\]\(([^)]+)\)') | ForEach-Object {
        $target = $_.Groups[1].Value
        if ($target -notmatch '^(https?://|mailto:|#|C:/)') {
            $clean = ($target -split '#')[0]
            if ($clean) {
                $resolved = Join-Path $file.DirectoryName ([uri]::UnescapeDataString($clean))
                if (-not (Test-Path -LiteralPath $resolved)) { $badLinks += "$($file.FullName): $target" }
            }
        }
    }
}

if ($badLinks.Count -gt 0) {
    $badLinks | Write-Error
    exit 1
}

$sequenceCount = (Select-String -LiteralPath (Join-Path $root 'docs/architecture/sequence-diagrams.md') -Pattern '^sequenceDiagram$' | Measure-Object).Count
if ($sequenceCount -ne 12) { throw "Expected 12 sequence diagrams, found $sequenceCount." }

Write-Host 'Documentation validation succeeded.'
exit 0
