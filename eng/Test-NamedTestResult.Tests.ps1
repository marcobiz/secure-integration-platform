$ErrorActionPreference = 'Stop'
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) ('named-result-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$resultFile = Join-Path $testDirectory 'result.trx'
$verify = Join-Path $PSScriptRoot 'Assert-NamedTestResult.ps1'
function Assert-Rejected {
    try { & $verify -ResultsDirectory $testDirectory -FullyQualifiedName 'Synthetic.Case.Exact'; throw 'EXPECTED_REJECTION' }
    catch { if ($_.Exception.Message -eq 'EXPECTED_REJECTION') { throw } }
}
try {
    Assert-Rejected
    $passed = '<TestRun><TestDefinitions><UnitTest id="target"><TestMethod className="Synthetic.Case" name="Exact" /></UnitTest><UnitTest id="other"><TestMethod className="Synthetic.Case" name="Unrelated" /></UnitTest></TestDefinitions><Results><UnitTestResult testId="target" outcome="Passed" /><UnitTestResult testId="other" outcome="Passed" /></Results></TestRun>'
    [IO.File]::WriteAllText($resultFile, $passed)
    & $verify -ResultsDirectory $testDirectory -FullyQualifiedName 'Synthetic.Case.Exact'
    [IO.File]::WriteAllText($resultFile, $passed.Replace('testId="target" outcome="Passed"', 'testId="target" outcome="NotExecuted"'))
    Assert-Rejected
    [IO.File]::WriteAllText($resultFile, $passed.Replace('testId="target" outcome="Passed"', 'testId="target" outcome="Failed"'))
    Assert-Rejected
    [IO.File]::WriteAllText($resultFile, $passed)
    [IO.File]::WriteAllText((Join-Path $testDirectory 'duplicate.trx'), $passed)
    Assert-Rejected
    Write-Output 'NAMED_RESULT_TESTS_PASS'
}
finally {
    $resolved = [IO.Path]::GetFullPath($testDirectory)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notlike 'named-result-test-*') { throw 'TEST_CLEANUP_PATH_DENIED' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
