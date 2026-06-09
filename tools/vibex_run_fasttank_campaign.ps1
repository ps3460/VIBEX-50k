$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RunId = "server2025_sandbox_campaign_20260608T1830Z_fasttank500_fulltools"
$RunDir = Join-Path $RepoRoot "evidence\sandbox\$RunId"
$LogPath = Join-Path $RunDir "campaign_runner_vm107.log"

New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
Push-Location $RepoRoot
try {
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    "=== VM107 campaign runner start $stamp ===" | Out-File -FilePath $LogPath -Append -Encoding utf8
    $python = Get-Command py -ErrorAction SilentlyContinue
    if ($python) {
        $cmd = @("-3")
    } else {
        $python = Get-Command python -ErrorAction Stop
        $cmd = @()
    }
    $cmd += @(
        "tools\vibex_server2025_sandbox_campaign.py", "run",
        "--run-id", $RunId,
        "--output-dir", "evidence\sandbox\$RunId",
        "--pve", "root@10.0.0.11",
        "--vmid", "116",
        "--snapshot", "pre-detonation-4core-static",
        "--batch-size", "500",
        "--guest-timeout", "43200",
        "--iso-timeout", "7200",
        "--pve-iso-storage", "tank-iso",
        "--pve-iso-dir", "/tank/proxmox-iso/template/iso",
        "--cdrom-slot", "ide0",
        "--tool-profile", "fast",
        "--no-rollback",
        "--reboot-before-batch",
        "--max-consecutive-errors", "0",
        "--start-batch", "2"
    )
    & $python.Source @cmd *>> $LogPath
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
