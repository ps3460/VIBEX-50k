$ErrorActionPreference = "Stop"

$RepoRoot = "C:\Users\phil\GitHub\VIBEX-50k"
$TaskPrefix = "VIBEX"
$Scripts = @{
    "SandboxCampaignRunner" = "tools\vibex_run_fasttank_campaign.ps1"
    "SandboxDashboardExporter" = "tools\vibex_run_sandbox_dashboard_exporter.ps1"
    "SandboxThresholdNotifier" = "tools\vibex_run_threshold_notifier.ps1"
}

foreach ($name in $Scripts.Keys) {
    $taskName = "$TaskPrefix $name"
    $script = Join-Path $RepoRoot $Scripts[$name]
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`"" -WorkingDirectory $RepoRoot
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 7) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
}

[pscustomobject]@{
    RepoRoot = $RepoRoot
    Tasks = $Scripts.Keys | ForEach-Object { "$TaskPrefix $_" }
} | ConvertTo-Json -Compress
