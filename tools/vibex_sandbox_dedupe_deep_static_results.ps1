param(
  [string]$ResultsPath = "S:\results\deep_static_family_results.csv",
  [string]$ProgressPath = "S:\results\deep_static_family_progress.json"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ResultsPath)) {
  throw "Results CSV missing: $ResultsPath"
}

$backup = $ResultsPath -replace "\.csv$", ".before_dedupe.csv"
Copy-Item $ResultsPath $backup -Force

$rows = @(Import-Csv $ResultsPath)
$last = @{}
for ($i = 0; $i -lt $rows.Count; $i++) {
  $sha = ($rows[$i].raw_sha256 + "").ToLowerInvariant()
  if ($sha) { $last[$sha] = $i }
}

$dedup = New-Object System.Collections.Generic.List[object]
for ($i = 0; $i -lt $rows.Count; $i++) {
  $sha = ($rows[$i].raw_sha256 + "").ToLowerInvariant()
  if ($sha -and $last[$sha] -eq $i) {
    $dedup.Add($rows[$i]) | Out-Null
  }
}

$dedup | Export-Csv -NoTypeInformation -Encoding UTF8 $ResultsPath

if (Test-Path $ProgressPath) {
  $progress = Get-Content $ProgressPath -Raw | ConvertFrom-Json
  $progress.saved_rows = $dedup.Count
  $progress.updated_utc = (Get-Date).ToUniversalTime().ToString("o")
  $progress | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $ProgressPath
}

$dups = @($dedup | Group-Object raw_sha256 | Where-Object Count -gt 1)
[pscustomobject]@{
  before = $rows.Count
  after = $dedup.Count
  unique = @($dedup.raw_sha256 | Sort-Object -Unique).Count
  duplicate_groups = $dups.Count
  backup = $backup
} | ConvertTo-Json -Compress
