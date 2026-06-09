#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_SCAN_ROOTS = [
    "/home/phil/vibex_secure_dataset/evidence/clamav_workhorse_parallel_20260518T162855Z/shards",
    "/home/phil/vibex_secure_dataset/evidence/clamav_workhorse_smoke20",
    "/home/phil/vibex_secure_dataset/raw",
    "/home/phil/vibex_secure_dataset/sandbox_transfer",
]


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def candidate_files(roots: list[Path]) -> list[Path]:
    out: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            out.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__"}]
            for name in filenames:
                path = Path(dirpath) / name
                if path.suffix.lower() in {".csv", ".json", ".md", ".log", ".png", ".zip", ".iso", ".7z"}:
                    continue
                out.append(path)
    return out


def load_index(index_path: Path) -> dict[str, str]:
    if not index_path.exists():
        return {}
    mapping: dict[str, str] = {}
    with index_path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            sha = str(row.get("sha256") or "").lower()
            path = str(row.get("path") or "")
            if len(sha) == 64 and path and Path(path).exists():
                mapping.setdefault(sha, path)
    return mapping


def append_index(index_path: Path, rows: list[dict[str, str]]) -> None:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    with index_path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def ensure_index_for(targets: set[str], index_path: Path, roots: list[Path], max_index_files: int | None) -> dict[str, str]:
    mapping = load_index(index_path)
    missing = targets - set(mapping)
    if not missing:
        return mapping

    indexed: list[dict[str, str]] = []
    scanned = 0
    for path in candidate_files(roots):
        if max_index_files is not None and scanned >= max_index_files:
            break
        scanned += 1
        try:
            sha = sha256_file(path)
        except (OSError, PermissionError):
            continue
        row = {"sha256": sha, "path": str(path), "indexed_utc": utc_now()}
        indexed.append(row)
        mapping.setdefault(sha, str(path))
        if sha in missing:
            missing.remove(sha)
            if not missing:
                break
    if indexed:
        append_index(index_path, indexed)
    return mapping


POWERSHELL_RUNNER = r'''
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

function Shorten([string]$Text, [int]$Max) {
  if ($null -eq $Text) { return "" }
  $clean = ($Text -replace "[\r\n]+", " ") -replace "\s+", " "
  $clean = $clean -replace '[^A-Za-z0-9 \._:/\\\-\(\)\[\];!@#%+=]', ' '
  $clean = ($clean -replace "\s+", " ").Trim()
  if ($clean.Length -le $Max) { return $clean }
  return $clean.Substring(0, $Max)
}

function Invoke-Tool([string]$Name, [string]$Exe, [string[]]$ToolArgs, [int]$TimeoutSeconds) {
  $result = [ordered]@{ name=$Name; status="missing"; exit_code=$null; stdout=""; stderr="" }
  if (-not (Test-Path $Exe)) { return $result }
  $stdout = Join-Path $env:TEMP ("vibex_{0}_{1}.out" -f $Name, [guid]::NewGuid())
  $stderr = Join-Path $env:TEMP ("vibex_{0}_{1}.err" -f $Name, [guid]::NewGuid())
  try {
    $p = Start-Process -FilePath $Exe -ArgumentList $ToolArgs -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
      try { $p.Kill() } catch {}
      $result.status = "timeout"
    } else {
      $result.status = "completed"
      $result.exit_code = $p.ExitCode
    }
    if (Test-Path $stdout) { $result.stdout = Shorten (Get-Content $stdout -Raw -ErrorAction SilentlyContinue) 3000 }
    if (Test-Path $stderr) { $result.stderr = Shorten (Get-Content $stderr -Raw -ErrorAction SilentlyContinue) 1200 }
  } catch {
    $result.status = "error"
    $result.stderr = Shorten $_.Exception.Message 1200
  } finally {
    Remove-Item $stdout,$stderr -Force -ErrorAction SilentlyContinue
  }
  return $result
}

function Family-From-Text([string]$Text) {
  $value = ($Text + "").ToLowerInvariant()
  $patterns = @("zbot","zeus","emotet","trickbot","ramnit","sality","expiro","virut","gamarue","fareit","lokibot","formbook","agenttesla","azorult","njrat","remcos","nanocore","ursnif","gozi","dridex","qakbot","redline","smokeloader","upatre","zusy","sivis","salgorea","juko","urelas","selfdel")
  foreach ($p in $patterns) {
    if ($value -match [regex]::Escape($p)) { return $p }
  }
  if ($value -match "win32/([^!:/\s\.]+)") { return $Matches[1].ToLowerInvariant() }
  if ($value -match "trojan:([^/]+)/([^!:/\s\.]+)") { return $Matches[2].ToLowerInvariant() }
  return ""
}

$iso = Get-Volume | Where-Object {
  $_.DriveType -eq "CD-ROM" -and (Test-Path (Join-Path ($_.DriveLetter + ":\") "manifest.csv"))
} | Select-Object -First 1
if (-not $iso) { throw "No VIBEX batch ISO with manifest.csv found" }
$root = $iso.DriveLetter + ":\"
$manifest = Join-Path $root "manifest.csv"
$batchId = (Import-Csv $manifest | Select-Object -First 1).batch_id
if (-not $batchId) { $batchId = "unknown_batch" }
$profilePath = Join-Path $root "tool_profile.txt"
$toolProfile = "full"
if (Test-Path $profilePath) { $toolProfile = ((Get-Content $profilePath -Raw).Trim().ToLowerInvariant()) }
if (-not $toolProfile) { $toolProfile = "full" }

$outDir = Join-Path "C:\SandboxResults" $batchId
$workDir = Join-Path "C:\SandboxWork" $batchId
New-Item -ItemType Directory -Path $outDir,$workDir -Force | Out-Null
$csvPath = Join-Path $outDir "server2025_family_hints.csv"
$jsonPath = Join-Path $outDir "server2025_batch_status.json"
$progressPath = Join-Path $outDir "server2025_batch_progress.json"

$tool = @{
  capa = "C:\Tools\capa-v9.4.0-windows\capa.exe"
  diec = "C:\Tools\die_win64_portable_3.21_x64\die\diec.exe"
  floss = "C:\Tools\floss-v3.1.1-windows\floss.exe"
  sigcheck = "C:\Tools\SysinternalsSuite\sigcheck64.exe"
  strings = "C:\Tools\SysinternalsSuite\strings64.exe"
  yara = "C:\Tools\yara-4.5.5-2368-win64\yara64.exe"
}

$defenderPreferenceBefore = Get-MpPreference | Select-Object DisableRealtimeMonitoring,ExclusionPath
$defenderStatusBefore = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated
$rows = @()
if (Test-Path $csvPath) {
  $rows = @(Import-Csv $csvPath)
}
$completedHashes = @{}
foreach ($existing in $rows) {
  $existingSha = ($existing.raw_sha256 + "").ToLowerInvariant()
  if ($existingSha) { $completedHashes[$existingSha] = $true }
}
$toolVersions = [ordered]@{}
foreach ($k in $tool.Keys) {
  if (Test-Path $tool[$k]) {
    $toolVersions[$k] = (Get-Item $tool[$k]).VersionInfo.FileVersion
  } else {
    $toolVersions[$k] = "missing"
  }
}

try {
  if ($toolProfile -eq "fast") {
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -MAPSReporting 0 -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
  } else {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
  }
  Add-MpPreference -ExclusionPath $workDir -ErrorAction SilentlyContinue
  foreach ($row in Import-Csv $manifest) {
    $sha = ($row.raw_sha256 + "").ToLowerInvariant()
    if ($completedHashes.ContainsKey($sha)) { continue }
    $sampleIso = Join-Path $root $row.sample_rel_path
    $sampleWork = Join-Path $workDir ($sha + ".bin")
    $status = "started"
    $defenderName = ""
    $defenderStatus = "not_run"
    $errorText = ""
    $magic = ""
    $size = 0
    $hashOk = $false
    try {
      if (-not (Test-Path $sampleIso)) { throw "missing sample on ISO: $sampleIso" }
      Copy-Item $sampleIso $sampleWork -Force
      $item = Get-Item $sampleWork
      $size = $item.Length
      $fs = [System.IO.File]::OpenRead($sampleWork)
      try {
        $buf = New-Object byte[] 2
        $n = $fs.Read($buf,0,2)
        if ($n -ge 2) { $magic = "{0:X2}{1:X2}" -f $buf[0],$buf[1] }
      } finally {
        $fs.Dispose()
      }
      $actual = (Get-FileHash -Algorithm SHA256 $sampleWork).Hash.ToLowerInvariant()
      $hashOk = ($actual -eq $sha)
      if (-not $hashOk) { throw "sha256 mismatch actual=$actual expected=$sha" }

      if ($toolProfile -eq "fast") {
        $sigcheck = Invoke-Tool -Name "sigcheck" -Exe $tool.sigcheck -ToolArgs @("-accepteula","-nobanner","-q","-m","-h",$sampleWork) -TimeoutSeconds 15
        $diec = Invoke-Tool -Name "diec" -Exe $tool.diec -ToolArgs @("-j",$sampleWork) -TimeoutSeconds 20
        $capa = [ordered]@{ name="capa"; status="skipped_fast_mode"; exit_code=$null; stdout=""; stderr="" }
        $floss = [ordered]@{ name="floss"; status="skipped_fast_mode"; exit_code=$null; stdout=""; stderr="" }
        $strings = Invoke-Tool -Name "strings" -Exe $tool.strings -ToolArgs @("-accepteula","-nobanner","-n","8",$sampleWork) -TimeoutSeconds 20
        $defenderStatus = "skipped_fast_mode"
      } else {
        $sigcheck = Invoke-Tool -Name "sigcheck" -Exe $tool.sigcheck -ToolArgs @("-accepteula","-nobanner","-q","-m","-h",$sampleWork) -TimeoutSeconds 45
        $diec = Invoke-Tool -Name "diec" -Exe $tool.diec -ToolArgs @("-j",$sampleWork) -TimeoutSeconds 45
        $capa = Invoke-Tool -Name "capa" -Exe $tool.capa -ToolArgs @("-q",$sampleWork) -TimeoutSeconds 90
        $floss = Invoke-Tool -Name "floss" -Exe $tool.floss -ToolArgs @("-q","--no-static-strings",$sampleWork) -TimeoutSeconds 90
        $strings = Invoke-Tool -Name "strings" -Exe $tool.strings -ToolArgs @("-accepteula","-nobanner","-n","8",$sampleWork) -TimeoutSeconds 45

        $scanJob = Start-Job -ScriptBlock { param($Path) Start-MpScan -ScanPath $Path -ScanType CustomScan } -ArgumentList $sampleWork
        if (Wait-Job $scanJob -Timeout 60) {
          Receive-Job $scanJob | Out-Null
          $defenderStatus = "completed"
        } else {
          Stop-Job $scanJob -ErrorAction SilentlyContinue
          $defenderStatus = "timeout"
        }
        Remove-Job $scanJob -Force -ErrorAction SilentlyContinue
        $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
          ($_.Resources -join " ") -like ("*" + $sha + "*") -or ($_.Resources -join " ") -like ("*" + $sampleWork + "*")
        } | Sort-Object InitialDetectionTime -Descending)
        if ($detections.Count -gt 0) {
          $defenderName = ($detections | Select-Object -First 1).ThreatName
        }
      }

      $joined = ($defenderName + " " + $sigcheck.stdout + " " + $diec.stdout + " " + $capa.stdout + " " + $floss.stdout + " " + $strings.stdout)
      $hint = Family-From-Text $joined
      $sources = @()
      if (Family-From-Text $defenderName) { $sources += "defender" }
      if (Family-From-Text $diec.stdout) { $sources += "diec" }
      if (Family-From-Text $capa.stdout) { $sources += "capa" }
      if (Family-From-Text $floss.stdout) { $sources += "floss" }
      if (Family-From-Text $strings.stdout) { $sources += "strings" }
      if ($hint) { $status = "supporting_hint" } else { $status = "no_hint" }

      $rows += [pscustomobject]@{
        raw_sha256=$sha; batch_id=$row.batch_id; batch_index=$row.batch_index; source=$row.source
        family_label_status=$row.family_label_status; exclusion_reason=$row.exclusion_reason; vt_consensus_family=$row.consensus_family
        raw_size_bytes=$size; file_magic=$magic; sha256_verified=$hashOk
        defender_status=$defenderStatus; defender_name=$defenderName
        tool_hint_family=$hint; hint_sources=($sources -join ";")
        sigcheck_status=$sigcheck.status; diec_status=$diec.status; capa_status=$capa.status; floss_status=$floss.status; strings_status=$strings.status
        diec_summary=(Shorten $diec.stdout 500); capa_summary=(Shorten $capa.stdout 800); strings_summary=(Shorten $strings.stdout 800)
        tool_errors=(Shorten (($sigcheck.stderr + " " + $diec.stderr + " " + $capa.stderr + " " + $floss.stderr + " " + $strings.stderr) -join " ") 1000)
        candidate_status=$status; error=""
      }
    } catch {
      $errorText = Shorten $_.Exception.Message 1000
      $rows += [pscustomobject]@{
        raw_sha256=$sha; batch_id=$row.batch_id; batch_index=$row.batch_index; source=$row.source
        family_label_status=$row.family_label_status; exclusion_reason=$row.exclusion_reason; vt_consensus_family=$row.consensus_family
        raw_size_bytes=$size; file_magic=$magic; sha256_verified=$hashOk
        defender_status=$defenderStatus; defender_name=$defenderName
        tool_hint_family=""; hint_sources=""
        sigcheck_status="not_run"; diec_status="not_run"; capa_status="not_run"; floss_status="not_run"; strings_status="not_run"
        diec_summary=""; capa_summary=""; strings_summary=""
        tool_errors=""
        candidate_status="blocked_or_error"; error=$errorText
      }
    } finally {
      Remove-Item $sampleWork -Force -ErrorAction SilentlyContinue
      $rows | Export-Csv -NoTypeInformation -Encoding UTF8 $csvPath
      [pscustomobject]@{
        batch_id=$batchId
        updated_utc=(Get-Date).ToUniversalTime().ToString("o")
        row_count=$rows.Count
        last_sha256=$sha
        tool_profile=$toolProfile
      } | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $progressPath
    }
  }
} finally {
  Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
}

$rows | Export-Csv -NoTypeInformation -Encoding UTF8 $csvPath
[pscustomobject]@{
  batch_id=$batchId
  completed_utc=(Get-Date).ToUniversalTime().ToString("o")
  row_count=$rows.Count
  tool_profile=$toolProfile
  defender_preference_before=$defenderPreferenceBefore
  defender_status_before=$defenderStatusBefore
  tool_versions=$toolVersions
  output_csv=$csvPath
} | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $jsonPath
Write-Output "VIBEX_BATCH_RESULT_BEGIN"
Get-Content $csvPath -Raw
Write-Output "VIBEX_BATCH_RESULT_END"
Write-Output "VIBEX_BATCH_STATUS_BEGIN"
Get-Content $jsonPath -Raw
Write-Output "VIBEX_BATCH_STATUS_END"
'''


def build_iso(args: argparse.Namespace) -> dict[str, Any]:
    targets = read_csv(Path(args.targets))
    batch_rows = targets[args.batch_index * args.batch_size : (args.batch_index + 1) * args.batch_size]
    if args.limit:
        batch_rows = batch_rows[: args.limit]
    if not batch_rows:
        raise SystemExit(f"No rows for batch_index={args.batch_index}")

    batch_id = f"{args.run_id}_batch_{args.batch_index:04d}"
    output_root = Path(args.output_root)
    batch_root = output_root / "batches" / batch_id
    iso_path = output_root / "isos" / f"{batch_id}.iso"
    stage = batch_root / "iso_root"
    sample_dir = stage / "samples"
    shutil.rmtree(batch_root, ignore_errors=True)
    stage.mkdir(parents=True, exist_ok=True)
    sample_dir.mkdir(parents=True, exist_ok=True)
    iso_path.parent.mkdir(parents=True, exist_ok=True)

    targets_set = {row["raw_sha256"].strip().lower() for row in batch_rows}
    roots = [Path(item) for item in args.scan_roots]
    mapping = ensure_index_for(targets_set, Path(args.index), roots, args.max_index_files)

    manifest_rows: list[dict[str, Any]] = []
    missing_rows: list[dict[str, Any]] = []
    for offset, row in enumerate(batch_rows):
        sha = row["raw_sha256"].strip().lower()
        src = mapping.get(sha)
        out_name = f"s{offset:06d}.bin"
        out_path = sample_dir / out_name
        if not src or not Path(src).exists():
            missing = dict(row)
            missing.update({"batch_id": batch_id, "batch_index": args.batch_index, "missing_reason": "raw_path_not_found"})
            missing_rows.append(missing)
            continue
        shutil.copy2(src, out_path)
        manifest = dict(row)
        manifest.update(
            {
                "batch_id": batch_id,
                "batch_index": args.batch_index,
                "batch_offset": offset,
                "sample_rel_path": f"samples/{out_name}",
                "workhorse_raw_path": src,
                "iso_sample_size": out_path.stat().st_size,
            }
        )
        manifest_rows.append(manifest)

    if not manifest_rows:
        raise SystemExit(f"No raw samples found for {batch_id}; missing={len(missing_rows)}")

    fields = list(dict.fromkeys([key for row in manifest_rows for key in row.keys()]))
    write_csv(stage / "manifest.csv", manifest_rows, fields)
    if missing_rows:
        write_csv(batch_root / "missing_raw.csv", missing_rows, list(dict.fromkeys([key for row in missing_rows for key in row.keys()])))
    (stage / "run_vibex_batch.ps1").write_text(POWERSHELL_RUNNER, encoding="utf-8")
    (stage / "tool_profile.txt").write_text(args.tool_profile + "\r\n", encoding="utf-8")
    (stage / "README.txt").write_text(
        "VIBEX Server 2025 sandbox static triage batch. Raw samples are for isolated VM analysis only.\r\n",
        encoding="utf-8",
    )

    subprocess.run(
        [
            "xorriso",
            "-as",
            "mkisofs",
            "-iso-level",
            "3",
            "-full-iso9660-filenames",
            "-volid",
            f"VIBEX{args.batch_index:04d}",
            "-o",
            str(iso_path),
            str(stage),
        ],
        check=True,
    )
    status = {
        "run_id": args.run_id,
        "batch_id": batch_id,
        "batch_index": args.batch_index,
        "created_utc": utc_now(),
        "iso_path": str(iso_path),
        "manifest_rows": len(manifest_rows),
        "missing_rows": len(missing_rows),
        "iso_bytes": iso_path.stat().st_size,
        "tool_profile": args.tool_profile,
    }
    (batch_root / "build_status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(status, indent=2, sort_keys=True))
    return status


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build VIBEX Server 2025 sandbox batch ISO on workhorse.")
    parser.add_argument("--targets", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--index", required=True)
    parser.add_argument("--batch-index", type=int, required=True)
    parser.add_argument("--batch-size", type=int, default=250)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--scan-roots", nargs="+", default=DEFAULT_SCAN_ROOTS)
    parser.add_argument("--max-index-files", type=int)
    parser.add_argument("--tool-profile", choices=["full", "fast"], default="full")
    return parser.parse_args()


if __name__ == "__main__":
    build_iso(parse_args())
