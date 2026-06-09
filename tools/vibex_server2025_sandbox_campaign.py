#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKHORSE_ROOT = "/home/phil/vibex_secure_dataset/evidence/server2025_sandbox_campaign"
DEFAULT_PVE = "root@10.0.0.11"
DEFAULT_VMID = "103"
DEFAULT_SNAPSHOT = "pre-detonation"
DEFAULT_PVE_ISO_STORAGE = "local"
DEFAULT_PVE_ISO_DIR = "/var/lib/vz/template/iso"
DEFAULT_CDROM_SLOT = "ide2"


def utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd: list[str], timeout: int | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed rc={proc.returncode}: {shlex.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def ssh(host: str, command: str, timeout: int | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["ssh", host, command], timeout=timeout, check=check)


def scp(src: str, dst: str, timeout: int | None = None) -> None:
    run(["scp", src, dst], timeout=timeout, check=True)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(dict.fromkeys([key for row in rows for key in row.keys()]))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def unresolved_targets(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    targets: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        sha = row.get("raw_sha256", "").strip().lower()
        if not sha or sha in seen or row.get("binary_label") != "malware":
            continue
        seen.add(sha)
        status = row.get("family_label_status", "")
        reason = row.get("exclusion_reason", "")
        unresolved = status != "labelled" or bool(reason)
        if not unresolved:
            continue
        kind = row.get("file_kind", "").lower()
        out = dict(row)
        out["raw_sha256"] = sha
        if kind in {"pe", "mz"}:
            targets.append(out)
        else:
            out["skip_reason"] = f"non_pe_mz:{kind or 'unknown'}"
            skipped.append(out)
    return targets, skipped


def init_campaign(args: argparse.Namespace) -> dict[str, Any]:
    run_id = args.run_id or f"server2025_sandbox_campaign_{utc_stamp()}"
    output_dir = Path(args.output_dir or ROOT / "evidence" / "sandbox" / run_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = read_csv(Path(args.family_extended))
    targets, skipped = unresolved_targets(rows)
    if args.limit:
        targets = targets[: args.limit]
    target_fields = [
        "raw_sha256",
        "split",
        "source_split",
        "source",
        "file_kind",
        "consensus_family",
        "family_label_status",
        "family_label_votes",
        "family_label_engine_count",
        "family_label_confidence",
        "exclusion_reason",
        "vt_report_path",
        "dataset_image_path",
        "original_family_field",
    ]
    write_csv(output_dir / "server2025_targets.csv", targets, target_fields)
    write_csv(output_dir / "server2025_skipped_non_pe_mz.csv", skipped)
    status = {
        "run_id": run_id,
        "created_utc": utc_now(),
        "output_dir": str(output_dir),
        "family_extended": args.family_extended,
        "target_rows": len(targets),
        "skipped_non_pe_mz": len(skipped),
        "batch_size": args.batch_size,
        "batch_count": math.ceil(len(targets) / args.batch_size) if targets else 0,
        "candidate_statuses": ["supporting_hint", "conflict_needs_review", "no_hint", "tool_timeout", "blocked_or_error"],
    }
    (output_dir / "campaign_status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_report(output_dir, status)
    print(json.dumps(status, indent=2, sort_keys=True))
    return status


def write_report(output_dir: Path, status: dict[str, Any], rows: list[dict[str, str]] | None = None) -> None:
    rows = rows or []
    counts = Counter(row.get("candidate_status", "") for row in rows)
    hints = Counter(row.get("tool_hint_family", "") for row in rows if row.get("tool_hint_family"))
    lines = [
        "# Server 2025 Sandbox Campaign",
        "",
        f"- Run ID: `{status.get('run_id')}`",
        f"- Updated UTC: `{utc_now()}`",
        f"- Target PE/MZ rows: `{status.get('target_rows')}`",
        f"- Skipped non-PE/MZ rows: `{status.get('skipped_non_pe_mz')}`",
        f"- Batch size: `{status.get('batch_size')}`",
        f"- Completed result rows: `{len(rows)}`",
        "- Raw malware and full tool output remain outside this repo.",
        "",
        "## Candidate Status Counts",
        "",
    ]
    for key, value in counts.most_common():
        lines.append(f"- `{key or 'blank'}`: {value}")
    lines.extend(["", "## Top Hints", ""])
    for key, value in hints.most_common(25):
        lines.append(f"- `{key}`: {value}")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- Sandbox evidence is supplemental only.",
            "- Canonical manifests are not changed by this campaign.",
        ]
    )
    (output_dir / "server2025_sandbox_campaign_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def preflight(args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    checks: dict[str, Any] = {"created_utc": utc_now()}
    checks["pve_vm"] = ssh(
        args.pve,
        f"qm status {args.vmid}; qm config {args.vmid}; qm listsnapshot {args.vmid}; ip -4 addr show vmbr3 || true; pvesm status",
        timeout=30,
        check=False,
    ).stdout
    checks["qga"] = ssh(
        args.pve,
        f"qm guest exec {args.vmid} -- powershell.exe -NoProfile -Command \"Write-Output OK\"",
        timeout=30,
        check=False,
    ).stdout
    checks["workhorse"] = ssh(
        "workhorse",
        "hostname; date -u; command -v xorriso; nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits; ps -eo pid,etime,stat,pcpu,pmem,args | grep -E 'python3 tools/vibex_|xorriso|qemu' | grep -v grep || true",
        timeout=30,
        check=False,
    ).stdout
    failed = []
    vm = checks["pve_vm"]
    if "net0:" not in vm or "bridge=vmbr3" not in vm:
        failed.append("vm_net0_not_vmbr3")
    if "vmbr3" in checks["pve_vm"] and re.search(r"inet\s+\d+\.\d+\.\d+\.\d+", checks["pve_vm"]):
        failed.append("vmbr3_has_ipv4")
    if not args.no_rollback and args.snapshot not in vm:
        failed.append("snapshot_missing")
    if "OK" not in checks["qga"]:
        failed.append("qga_failed")
    checks["failed"] = failed
    (output_dir / "preflight_status.json").write_text(json.dumps(checks, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if failed:
        raise SystemExit(f"preflight failed: {failed}")
    print(json.dumps({"preflight": "ok", "output": str(output_dir / "preflight_status.json")}, indent=2))
    return checks


def install_workhorse_helper(args: argparse.Namespace, output_dir: Path) -> str:
    remote_root = f"{args.workhorse_root}/{args.run_id}"
    helper = ROOT / "tools" / "vibex_workhorse_build_sandbox_iso.py"
    targets = output_dir / "server2025_targets.csv"
    ssh("workhorse", f"mkdir -p {shlex.quote(remote_root)}/tools {shlex.quote(remote_root)}/input", timeout=30)
    scp(str(helper), f"workhorse:{remote_root}/tools/")
    scp(str(targets), f"workhorse:{remote_root}/input/server2025_targets.csv")
    return remote_root


def parse_build_status(stdout: str) -> dict[str, Any]:
    start = stdout.find("{")
    if start < 0:
        raise RuntimeError(f"no JSON status in build output: {stdout[:1000]}")
    return json.loads(stdout[start:])


def ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def qga_powershell(
    args: argparse.Namespace,
    ps: str,
    timeout: int = 60,
    check_exit: bool = True,
    attempts: int = 1,
    retry_sleep: int = 5,
) -> dict[str, Any]:
    guest_cmd = (
        f"qm guest exec {args.vmid} --timeout {timeout} -- "
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command {shlex.quote(ps)}"
    )
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        try:
            proc = ssh(args.pve, guest_cmd, timeout=timeout + 60, check=True)
            payload = json.loads(proc.stdout)
            exitcode = int(payload.get("exitcode", 0))
            if check_exit and exitcode != 0:
                raise RuntimeError(
                    "guest powershell failed "
                    f"exitcode={exitcode} stdout={payload.get('out-data', '')} stderr={payload.get('err-data', '')}"
                )
            return payload
        except (json.JSONDecodeError, RuntimeError, subprocess.TimeoutExpired) as exc:
            last_error = exc
            if attempt + 1 >= max(1, attempts):
                break
            time.sleep(retry_sleep)
    raise RuntimeError(f"QGA powershell failed after {max(1, attempts)} attempts: {last_error}") from last_error


def qga_read_text_file(args: argparse.Namespace, guest_path: str, chunk_size: int = 131072) -> str:
    size_ps = f"$p={ps_single_quote(guest_path)}; (Get-Item -LiteralPath $p).Length"
    size_text = qga_powershell(args, size_ps, timeout=60, attempts=3).get("out-data", "").strip()
    size = int(size_text.splitlines()[-1]) if size_text else 0
    if size <= 2_000_000:
        read_all_ps = (
            f"$p={ps_single_quote(guest_path)};"
            "[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))"
        )
        file_b64 = qga_powershell(args, read_all_ps, timeout=180, attempts=3).get("out-data", "").strip()
        if file_b64:
            return base64.b64decode(file_b64.splitlines()[-1]).decode("utf-8-sig", errors="replace")
    parts: list[bytes] = []
    for offset in range(0, size, chunk_size):
        read_ps = (
            f"$p={ps_single_quote(guest_path)};"
            f"$offset={offset};$count={chunk_size};"
            "$fs=[IO.File]::OpenRead($p);"
            "try{"
            "if($offset -ge $fs.Length){''}else{"
            "$fs.Seek($offset,[IO.SeekOrigin]::Begin)>$null;"
            "$len=[Math]::Min($count,$fs.Length-$offset);"
            "$buf=New-Object byte[] $len;"
            "$n=$fs.Read($buf,0,$buf.Length);"
            "if($n -lt $buf.Length){$tmp=New-Object byte[] $n;[Array]::Copy($buf,$tmp,$n);$buf=$tmp};"
            "[Convert]::ToBase64String($buf)"
            "}"
            "}finally{$fs.Dispose()}"
        )
        chunk_b64 = qga_powershell(args, read_ps, timeout=120, attempts=3).get("out-data", "").strip()
        if chunk_b64:
            parts.append(base64.b64decode(chunk_b64.splitlines()[-1]))
    data = b"".join(parts)
    return data.decode("utf-8-sig", errors="replace")


def build_batch_iso(args: argparse.Namespace, remote_root: str, batch_index: int, limit: int = 0) -> dict[str, Any]:
    cmd = " ".join(
        [
            "python3",
            shlex.quote(f"{remote_root}/tools/vibex_workhorse_build_sandbox_iso.py"),
            "--targets",
            shlex.quote(f"{remote_root}/input/server2025_targets.csv"),
            "--run-id",
            shlex.quote(args.run_id),
            "--output-root",
            shlex.quote(remote_root),
            "--index",
            shlex.quote(f"{remote_root}/raw_sha256_index.jsonl"),
            "--batch-index",
            str(batch_index),
            "--batch-size",
            str(args.batch_size),
            "--limit",
            str(limit),
            "--tool-profile",
            shlex.quote(args.tool_profile),
        ]
    )
    proc = ssh("workhorse", cmd, timeout=args.iso_timeout, check=True)
    return parse_build_status(proc.stdout)


def expected_rows_for_batch(output_dir: Path, args: argparse.Namespace, batch_index: int) -> int:
    targets = read_csv(output_dir / "server2025_targets.csv")
    remaining = len(targets) - (batch_index * args.batch_size)
    if remaining <= 0:
        return 0
    return min(args.batch_size, remaining)


def attach_iso_and_run(args: argparse.Namespace, output_dir: Path, build: dict[str, Any]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    iso_path = build["iso_path"]
    iso_name = Path(iso_path).name
    pve_iso_path = f"{args.pve_iso_dir.rstrip('/')}/{iso_name}"
    expected_iso_bytes = int(build.get("iso_bytes") or 0)
    remote_check = f"test -f {shlex.quote(pve_iso_path)} && stat -c %s {shlex.quote(pve_iso_path)}"
    remote_size = ssh(args.pve, remote_check, timeout=30, check=False).stdout.strip()
    if not (expected_iso_bytes and remote_size == str(expected_iso_bytes)):
        direct_copy = f"scp {shlex.quote(iso_path)} {shlex.quote(f'{args.pve}:{pve_iso_path}')}"
        try:
            ssh("workhorse", direct_copy, timeout=max(600, args.iso_timeout), check=True)
        except (RuntimeError, subprocess.TimeoutExpired):
            local_iso = Path("/tmp") / iso_name
            scp(f"workhorse:{iso_path}", str(local_iso), timeout=max(600, args.iso_timeout))
            scp(str(local_iso), f"{args.pve}:{pve_iso_path}", timeout=max(600, args.iso_timeout))
            local_iso.unlink(missing_ok=True)

    iso_volume = f"{args.pve_iso_storage}:iso/{iso_name}"
    cdrom_arg = f"--{args.cdrom_slot}"
    if args.no_rollback:
        if args.reboot_before_batch:
            pve_cmd = (
                f"qm set {args.vmid} {cdrom_arg} {shlex.quote(iso_volume)},media=cdrom; "
                f"if qm status {args.vmid} | grep -q 'status: running'; then qm reboot {args.vmid}; else qm start {args.vmid}; fi; "
                f"for i in $(seq 1 120); do qm guest exec {args.vmid} -- powershell.exe -NoProfile -Command \"Write-Output READY\" 2>/dev/null | grep -q READY && exit 0; sleep 5; done; exit 1"
            )
        else:
            pve_cmd = (
                f"qm set {args.vmid} {cdrom_arg} {shlex.quote(iso_volume)},media=cdrom; "
                f"qm status {args.vmid} | grep -q 'status: running' || qm start {args.vmid}; "
                f"for i in $(seq 1 60); do qm guest exec {args.vmid} -- powershell.exe -NoProfile -Command \"Write-Output READY\" 2>/dev/null | grep -q READY && exit 0; sleep 5; done; exit 1"
            )
    else:
        pve_cmd = (
            f"qm stop {args.vmid} --skiplock 1 || true; "
            f"qm rollback {args.vmid} {shlex.quote(args.snapshot)}; "
            f"qm set {args.vmid} {cdrom_arg} {shlex.quote(iso_volume)},media=cdrom; "
            f"qm start {args.vmid}; "
            f"for i in $(seq 1 60); do qm guest exec {args.vmid} -- powershell.exe -NoProfile -Command \"Write-Output READY\" 2>/dev/null | grep -q READY && exit 0; sleep 5; done; exit 1"
        )
    ssh(args.pve, pve_cmd, timeout=480, check=True)
    guest_out_dir = f"C:\\SandboxResults\\{build['batch_id']}"
    guest_csv = f"{guest_out_dir}\\server2025_family_hints.csv"
    guest_status = f"{guest_out_dir}\\server2025_batch_status.json"
    if args.no_rollback:
        cleanup_status = f"$p={ps_single_quote(guest_status)};Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue"
        qga_powershell(args, cleanup_status, timeout=45, check_exit=False, attempts=3)
    ps = (
        "$existing=Get-CimInstance Win32_Process -Filter \"Name = 'powershell.exe'\" | "
        "Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -match '(?i)-File\\s+\\S:\\\\run_vibex_batch\\.ps1\\s*$'} | "
        "Select-Object -First 1;"
        "if($existing){Write-Output 'ALREADY_RUNNING'; exit 0};"
        "$d=(Get-Volume|Where-Object {$_.DriveType -eq 'CD-ROM' -and "
        " (Test-Path (Join-Path ($_.DriveLetter + ':\\') 'run_vibex_batch.ps1'))}|Select-Object -First 1).DriveLetter;"
        "if(-not $d){throw 'batch ISO not found'};"
        "$p=($d + ':\\run_vibex_batch.ps1');"
        "Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$p) -WindowStyle Hidden;"
        "Write-Output 'STARTED'"
    )
    for start_attempt in range(1, 31):
        try:
            qga_powershell(args, ps, timeout=60, attempts=3)
            break
        except RuntimeError as exc:
            if "batch ISO not found" not in str(exc) or start_attempt >= 30:
                raise
            time.sleep(10)

    poll = (
        f"$csv={ps_single_quote(guest_csv)};"
        f"$json={ps_single_quote(guest_status)};"
        "if((Test-Path $csv) -and (Test-Path $json)){Write-Output 'DONE'}"
        "else{Write-Output 'RUNNING'}"
    )
    deadline = time.monotonic() + args.guest_timeout
    qga_failures = 0
    while time.monotonic() < deadline:
        try:
            state = qga_powershell(args, poll, timeout=45, attempts=3).get("out-data", "").strip()
            qga_failures = 0
            if "DONE" in state:
                break
        except Exception:
            qga_failures += 1
            if qga_failures > 60:
                raise
        time.sleep(30)
    else:
        raise TimeoutError(f"timed out waiting for guest batch output: {build['batch_id']}")

    csv_text = qga_read_text_file(args, guest_csv)
    status_text = qga_read_text_file(args, guest_status)
    rows = list(csv.DictReader(io.StringIO(csv_text))) if csv_text.strip() else []
    status = json.loads(status_text) if status_text.strip() else {"batch_id": build["batch_id"], "status": "missing_status"}
    batch_dir = output_dir / "batches" / build["batch_id"]
    batch_dir.mkdir(parents=True, exist_ok=True)
    write_csv(batch_dir / "server2025_family_hints.csv", rows)
    (batch_dir / "server2025_batch_status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (batch_dir / "workhorse_build_status.json").write_text(json.dumps(build, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ssh(args.pve, f"rm -f {shlex.quote(args.pve_iso_dir.rstrip('/') + '/' + iso_name)}", timeout=60, check=False)
    return rows, status


def extract_block(text: str, start: str, end: str) -> str:
    if start not in text or end not in text:
        return ""
    return text.split(start, 1)[1].split(end, 1)[0].strip()


def combine_results(output_dir: Path, status: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted((output_dir / "batches").glob("*/server2025_family_hints.csv")):
        rows.extend(read_csv(path))
    fields = [
        "raw_sha256",
        "batch_id",
        "batch_index",
        "source",
        "family_label_status",
        "exclusion_reason",
        "vt_consensus_family",
        "raw_size_bytes",
        "file_magic",
        "sha256_verified",
        "defender_status",
        "defender_name",
        "tool_hint_family",
        "hint_sources",
        "sigcheck_status",
        "diec_status",
        "capa_status",
        "floss_status",
        "strings_status",
        "diec_summary",
        "capa_summary",
        "strings_summary",
        "tool_errors",
        "candidate_status",
        "error",
    ]
    write_csv(output_dir / "server2025_family_hints.csv", rows, fields)
    candidates = []
    for row in rows:
        candidate = dict(row)
        if row.get("candidate_status") == "supporting_hint" and row.get("tool_hint_family"):
            candidate["recommendation"] = "supplemental_review_candidate"
        elif row.get("candidate_status") == "no_hint":
            candidate["recommendation"] = "no_family_promotion"
        else:
            candidate["recommendation"] = "manual_review"
        candidates.append(candidate)
    write_csv(output_dir / "server2025_rebuild_candidates.csv", candidates)
    status["completed_result_rows"] = len(rows)
    status["updated_utc"] = utc_now()
    (output_dir / "campaign_status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_report(output_dir, status, rows)
    return rows


def run_campaign(args: argparse.Namespace) -> None:
    if not args.run_id:
        args.run_id = f"server2025_sandbox_campaign_{utc_stamp()}"
    output_dir = Path(args.output_dir or ROOT / "evidence" / "sandbox" / args.run_id)
    if not (output_dir / "server2025_targets.csv").exists():
        status = init_campaign(args)
    else:
        status = json.loads((output_dir / "campaign_status.json").read_text(encoding="utf-8"))
    preflight(args, output_dir)
    remote_root = install_workhorse_helper(args, output_dir)
    targets = read_csv(output_dir / "server2025_targets.csv")
    total_batches = math.ceil(len(targets) / args.batch_size)
    if args.max_batches:
        total_batches = min(total_batches, args.max_batches)
    consecutive_errors = 0
    for batch_index in range(args.start_batch, total_batches):
        try:
            batch_id = f"{args.run_id}_batch_{batch_index:04d}"
            existing_csv = output_dir / "batches" / batch_id / "server2025_family_hints.csv"
            expected_rows = expected_rows_for_batch(output_dir, args, batch_index)
            if existing_csv.exists() and len(read_csv(existing_csv)) >= expected_rows:
                continue
            limit = args.smoke_limit if batch_index == args.start_batch and args.smoke_limit else 0
            build = build_batch_iso(args, remote_root, batch_index, limit=limit)
            rows, _ = attach_iso_and_run(args, output_dir, build)
            if len(rows) < expected_rows:
                raise RuntimeError(f"batch {batch_index} returned {len(rows)} rows, expected {expected_rows}")
            consecutive_errors = 0
            combine_results(output_dir, status)
            if args.smoke_limit:
                break
        except Exception as exc:
            consecutive_errors += 1
            err = {
                "batch_index": batch_index,
                "error": str(exc),
                "utc": utc_now(),
                "consecutive_errors": consecutive_errors,
            }
            err_path = output_dir / "batch_errors.jsonl"
            with err_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(err, sort_keys=True) + "\n")
            if consecutive_errors > args.max_consecutive_errors:
                raise
    combine_results(output_dir, status)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Orchestrate VIBEX Server 2025 sandbox static triage.")
    parser.add_argument("command", choices=["init", "preflight", "run"])
    parser.add_argument("--family-extended", default=str(ROOT / "datasets" / "family_extended" / "manifest.csv"))
    parser.add_argument("--output-dir")
    parser.add_argument("--run-id")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--batch-size", type=int, default=250)
    parser.add_argument("--start-batch", type=int, default=0)
    parser.add_argument("--max-batches", type=int, default=0)
    parser.add_argument("--smoke-limit", type=int, default=0)
    parser.add_argument("--workhorse-root", default=DEFAULT_WORKHORSE_ROOT)
    parser.add_argument("--pve", default=DEFAULT_PVE)
    parser.add_argument("--vmid", default=DEFAULT_VMID)
    parser.add_argument("--snapshot", default=DEFAULT_SNAPSHOT)
    parser.add_argument("--pve-iso-storage", default=DEFAULT_PVE_ISO_STORAGE)
    parser.add_argument("--pve-iso-dir", default=DEFAULT_PVE_ISO_DIR)
    parser.add_argument("--cdrom-slot", default=DEFAULT_CDROM_SLOT)
    parser.add_argument("--tool-profile", choices=["full", "fast"], default="full")
    parser.add_argument("--no-rollback", action="store_true")
    parser.add_argument("--reboot-before-batch", action="store_true")
    parser.add_argument("--iso-timeout", type=int, default=7200)
    parser.add_argument("--guest-timeout", type=int, default=21600)
    parser.add_argument("--max-consecutive-errors", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "init":
        init_campaign(args)
    elif args.command == "preflight":
        if not args.output_dir:
            raise SystemExit("--output-dir is required for preflight")
        preflight(args, Path(args.output_dir))
    elif args.command == "run":
        run_campaign(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
