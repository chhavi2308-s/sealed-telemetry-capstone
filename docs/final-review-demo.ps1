param([string]$OutputRoot = "demo-final", [string]$Python = "python")
$ErrorActionPreference = "Stop"
foreach ($scenario in @("normal", "replay-suppression", "benign-log-failure")) {
    & $Python -m sealed_telemetry.cli demo --scenario $scenario --output "$OutputRoot/$scenario"
    if ($LASTEXITCODE -ne 0) { throw "Scenario failed: $scenario" }
}
Write-Output "Local synthetic demonstration only. Inspect evidence, decisions and forensic reports; AWS acceptance is separate."


