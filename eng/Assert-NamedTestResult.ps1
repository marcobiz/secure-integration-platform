param(
    [Parameter(Mandatory = $true)][string]$ResultsDirectory,
    [Parameter(Mandatory = $true)][string]$FullyQualifiedName
)

$ErrorActionPreference = 'Stop'
$results = @(foreach ($file in Get-ChildItem -LiteralPath $ResultsDirectory -Filter '*.trx' -File -Recurse) {
    [xml]$trx = Get-Content -LiteralPath $file.FullName -Raw
    foreach ($test in $trx.TestRun.TestDefinitions.UnitTest) {
        if ("$($test.TestMethod.className).$($test.TestMethod.name)" -ceq $FullyQualifiedName) {
            @($trx.TestRun.Results.UnitTestResult | Where-Object { $_.testId -ceq $test.id })
        }
    }
})
if ($results.Count -ne 1 -or $results[0].outcome -cne 'Passed') {
    throw "NAMED_TEST_RESULT_INVALID: $FullyQualifiedName must have exactly one Passed execution; found $($results.Count)."
}
Write-Output "NAMED_TEST_RESULT_PASS: $FullyQualifiedName"
