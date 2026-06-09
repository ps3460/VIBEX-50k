$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RunId = "server2025_sandbox_campaign_20260608T1830Z_fasttank500_fulltools"
$RunDir = Join-Path $RepoRoot "evidence\sandbox\$RunId"
$LogPath = Join-Path $RunDir "dashboard_exporter_vm107.log"
$StatusPath = Join-Path $env:TEMP "sandbox_campaign_status.json"

New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
Push-Location $RepoRoot
try {
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    "=== VM107 dashboard exporter start $stamp ===" | Out-File -FilePath $LogPath -Append -Encoding utf8
    $python = Get-Command py -ErrorAction SilentlyContinue
    if ($python) {
        $cmd = @("-3")
    } else {
        $python = Get-Command python -ErrorAction Stop
        $cmd = @()
    }
    $cmd += @(
        "tools\vibex_export_sandbox_campaign_dashboard_status.py",
        "--campaign-dir", "evidence\sandbox\$RunId",
        "--output", $StatusPath,
        "--copy-to", "root@10.64.0.87:/opt/mv2025-dashboard/data/sandbox_campaign_status.json",
        "--pve", "root@10.0.0.11",
        "--watch-seconds", "60"
    )
    & $python.Source @cmd *>> $LogPath
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
