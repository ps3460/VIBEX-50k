$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RunId = "server2025_sandbox_campaign_20260608T1830Z_fasttank500_fulltools"
$RunDir = Join-Path $RepoRoot "evidence\sandbox\$RunId"
$LogPath = Join-Path $RunDir "threshold_notifier_vm107.log"

New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
Push-Location $RepoRoot
try {
    "=== VM107 threshold notifier start $(Get-Date -AsUTC -Format 'yyyy-MM-ddTHH:mm:ssZ') ===" | Out-File -FilePath $LogPath -Append -Encoding utf8
    $python = Get-Command py -ErrorAction SilentlyContinue
    if ($python) {
        $cmd = @("-3")
    } else {
        $python = Get-Command python -ErrorAction Stop
        $cmd = @()
    }
    $cmd += @(
        "tools\vibex_server2025_threshold_notifier.py",
        "--campaign-dir", "evidence\sandbox\$RunId",
        "--source-completed-rows", "1075",
        "--total-rows", "21754",
        "--poll-seconds", "300"
    )
    & $python.Source @cmd *>> $LogPath
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
