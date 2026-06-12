param(
  [string]$BaseDir = "C:\Users\phil\codex\vibex_deep_static_manager",
  [string]$Key = "C:\Users\phil\.ssh\vibex_vm107_sandbox_ed25519",
  [string]$JumpHost = "phil@10.64.0.57",
  [string]$SandboxHost = "phil@10.192.101.130",
  [int]$TargetRows = 19324,
  [int]$ActiveStaleMinutes = 180,
  [int]$PollSeconds = 120,
  [int]$SettleSeconds = 90
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

New-Item -ItemType Directory -Force $BaseDir | Out-Null
$Log = Join-Path $BaseDir "manager.log"
$StatePath = Join-Path $BaseDir "manager_state.json"
$ProgressLocal = Join-Path $BaseDir "deep_static_family_progress.live.json"
$LockPath = Join-Path $BaseDir "manager.lock"

function Write-Log([string]$Message) {
  $line = "$(Get-Date -Format o) $Message"
  Add-Content -Encoding UTF8 -Path $Log -Value $line
}

function Save-State($Payload) {
  $Payload.updated_utc = (Get-Date).ToUniversalTime().ToString("o")
  $Payload | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $StatePath
}

function Ssh-CommonArgs() {
  $keyPath = $Key.Replace("\", "/")
  return @(
    "-i", $keyPath,
    "-J", $JumpHost,
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=6",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=30",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=NUL"
  )
}

function Invoke-SandboxText([string]$RemoteCommand, [int]$TimeoutSeconds = 0) {
  $args = @(Ssh-CommonArgs) + @($SandboxHost, $RemoteCommand)
  $stdout = Join-Path $BaseDir ("ssh_{0}.out" -f [guid]::NewGuid())
  $stderr = Join-Path $BaseDir ("ssh_{0}.err" -f [guid]::NewGuid())
  $result = [ordered]@{ exit_code=$null; stdout=""; stderr=""; timed_out=$false }
  try {
    $p = Start-Process -FilePath "ssh.exe" -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if ($TimeoutSeconds -gt 0 -and -not $p.WaitForExit($TimeoutSeconds * 1000)) {
      try { $p.Kill() } catch {}
      $result.timed_out = $true
      $result.exit_code = 124
    } else {
      $p.WaitForExit()
      $result.exit_code = $p.ExitCode
    }
    if (Test-Path $stdout) { $result.stdout = Get-Content $stdout -Raw -ErrorAction SilentlyContinue }
    if (Test-Path $stderr) { $result.stderr = Get-Content $stderr -Raw -ErrorAction SilentlyContinue }
  } finally {
    Remove-Item $stdout,$stderr -Force -ErrorAction SilentlyContinue
  }
  return [pscustomobject]$result
}

function Read-SandboxProgress() {
  $res = Invoke-SandboxText "cmd /c type S:\results\deep_static_family_progress.json" 60
  if ($res.exit_code -ne 0 -or -not $res.stdout) {
    Write-Log "progress read failed exit=$($res.exit_code) stderr=$($res.stderr -replace '[\r\n]+',' ')"
    return $null
  }
  $jsonStart = $res.stdout.IndexOf("{")
  if ($jsonStart -lt 0) { return $null }
  $json = $res.stdout.Substring($jsonStart)
  $json | Set-Content -Encoding UTF8 $ProgressLocal
  try { return $json | ConvertFrom-Json } catch { return $null }
}

function Invoke-SandboxPowerShell([string]$Script, [int]$TimeoutSeconds = 0) {
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
  return Invoke-SandboxText "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded" $TimeoutSeconds
}

function Next-Target([int]$Saved) {
  if ($Saved -lt 1000) {
    return [Math]::Min(1000, ([Math]::Ceiling(($Saved + 1) / 50.0) * 50))
  }
  if ($Saved -lt 2000) {
    return [Math]::Min(2000, ([Math]::Ceiling(($Saved + 1) / 100.0) * 100))
  }
  return [Math]::Min($TargetRows, ([Math]::Ceiling(($Saved + 1) / 250.0) * 250))
}

function Test-ActiveProgress($Progress) {
  if (-not $Progress) { return $false }
  $saved = [int]$Progress.saved_rows
  $target = [int]$Progress.target_rows
  if ($target -le 0 -or $saved -ge $target) { return $false }
  try {
    $updated = [datetime]::Parse($Progress.updated_utc).ToUniversalTime()
    return (((Get-Date).ToUniversalTime() - $updated).TotalMinutes -lt $ActiveStaleMinutes)
  } catch {
    return $true
  }
}

function Test-Duplicates() {
  $script = @'
$rows = @(Import-Csv 'S:/results/deep_static_family_results.csv')
$dups = @($rows | Group-Object raw_sha256 | Where-Object Count -gt 1)
[pscustomobject]@{
  rows=$rows.Count
  unique=@($rows.raw_sha256 | Sort-Object -Unique).Count
  duplicate_groups=$dups.Count
  checked_utc=(Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json -Compress
'@
  $res = Invoke-SandboxPowerShell $script 600
  if ($res.exit_code -ne 0) {
    Write-Log "duplicate check failed exit=$($res.exit_code) stderr=$($res.stderr -replace '[\r\n]+',' ')"
    return $null
  }
  try { return $res.stdout | ConvertFrom-Json } catch { return $null }
}

if (Test-Path $LockPath) {
  $existing = Get-Content $LockPath -Raw -ErrorAction SilentlyContinue
  if ($existing -match 'pid=(\d+)') {
    $pidValue = [int]$Matches[1]
    if (Get-Process -Id $pidValue -ErrorAction SilentlyContinue) {
      Write-Log "another manager appears active pid=$pidValue"
      Save-State ([ordered]@{status="blocked_existing_manager"; existing_pid=$pidValue; target_rows=$TargetRows})
      exit 2
    }
  }
}
"pid=$PID started_utc=$((Get-Date).ToUniversalTime().ToString('o'))" | Set-Content -Encoding UTF8 $LockPath

try {
  Write-Log "manager_v2 starting pid=$PID"
  Save-State ([ordered]@{status="starting"; pid=$PID; target_rows=$TargetRows})

  while ($true) {
    $progress = Read-SandboxProgress
    $saved = 0
    if ($progress -and $progress.saved_rows) { $saved = [int]$progress.saved_rows }

    if ($saved -ge $TargetRows) {
      $dupes = Test-Duplicates
      Write-Log "complete saved=$saved"
      Save-State ([ordered]@{status="complete"; pid=$PID; saved_rows=$saved; target_rows=$TargetRows; progress=$progress; duplicate_summary=$dupes})
      break
    }

    if (Test-ActiveProgress $progress) {
      Write-Log "active sandbox chunk observed saved=$($progress.saved_rows) target=$($progress.target_rows) updated_utc=$($progress.updated_utc)"
      Save-State ([ordered]@{status="waiting_active_chunk"; pid=$PID; saved_rows=$saved; target_rows=$TargetRows; progress=$progress})
      Start-Sleep -Seconds $PollSeconds
      continue
    }

    if ($progress -and ([int]$progress.saved_rows) -ge ([int]$progress.target_rows) -and ([int]$progress.target_rows) -gt 0) {
      Write-Log "chunk boundary detected saved=$saved target=$($progress.target_rows); settling $SettleSeconds seconds"
      Save-State ([ordered]@{status="settling_at_chunk_boundary"; pid=$PID; saved_rows=$saved; target_rows=$TargetRows; progress=$progress})
      Start-Sleep -Seconds $SettleSeconds
      $settled = Read-SandboxProgress
      if (Test-ActiveProgress $settled) { continue }
      if ($settled -and $settled.saved_rows) { $saved = [int]$settled.saved_rows; $progress = $settled }
    }

    $target = Next-Target $saved
    Write-Log "chunk starting saved=$saved target=$target"
    Save-State ([ordered]@{status="chunk_running"; pid=$PID; saved_rows=$saved; chunk_target=$target; target_rows=$TargetRows; progress=$progress})

    $chunkScript = "& powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'S:/tools/vibex_sandbox_deep_static_classifier.ps1' -Limit $target; exit `$LASTEXITCODE"
    $started = Get-Date
    $res = Invoke-SandboxPowerShell $chunkScript 0
    $elapsed = [int]((Get-Date) - $started).TotalSeconds
    $after = Read-SandboxProgress
    $afterSaved = $saved
    if ($after -and $after.saved_rows) { $afterSaved = [int]$after.saved_rows }
    Write-Log "chunk finished target=$target exit=$($res.exit_code) saved=$afterSaved elapsed_seconds=$elapsed"

    $dupes = Test-Duplicates
    Save-State ([ordered]@{status="chunk_finished"; pid=$PID; saved_rows=$afterSaved; chunk_target=$target; target_rows=$TargetRows; exit_code=$res.exit_code; elapsed_seconds=$elapsed; progress=$after; duplicate_summary=$dupes})

    if ($res.exit_code -ne 0) {
      Write-Log "stopping after nonzero exit=$($res.exit_code) target=$target"
      Save-State ([ordered]@{status="stopped_error"; pid=$PID; saved_rows=$afterSaved; chunk_target=$target; target_rows=$TargetRows; exit_code=$res.exit_code; progress=$after; stderr=$res.stderr})
      break
    }
    if ($afterSaved -le $saved) {
      Write-Log "stopping because no progress saved_before=$saved saved_after=$afterSaved"
      Save-State ([ordered]@{status="stopped_no_progress"; pid=$PID; saved_rows=$afterSaved; chunk_target=$target; target_rows=$TargetRows; progress=$after})
      break
    }
  }
} finally {
  Remove-Item $LockPath -Force -ErrorAction SilentlyContinue
  Write-Log "manager_v2 exiting pid=$PID"
}
