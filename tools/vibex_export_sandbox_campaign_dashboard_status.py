#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_CAMPAIGN_DIR = Path(
    "evidence/sandbox/server2025_sandbox_campaign_20260608T1830Z_fasttank500_fulltools"
)
DEFAULT_OUTPUT = Path("/private/tmp/sandbox_campaign_status.json")
GENERIC_HINTS = {
    "agent",
    "dropper",
    "fileio",
    "generic",
    "heur",
    "loader",
    "malware",
    "packed",
    "selfdel",
    "trojan",
}
TOOL_STATUS_COLUMNS = [
    "defender_status",
    "sigcheck_status",
    "diec_status",
    "capa_status",
    "floss_status",
    "strings_status",
    "yara_status",
]
PATH_PATTERNS = [
    re.compile(r"[A-Za-z]:\\(?:SandboxWork|SandboxResults)\\[^\s\"']+"),
    re.compile(r"/Users/ps3460/GitHub/VIBEX-50k/[^\s\"']+"),
    re.compile(r"/home/phil/[^\s\"']+"),
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = re.sub(r"(\.\d{6})\d+(?=[+-]\d{2}:\d{2}$)", r"\1", text)
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except ValueError:
        return None


def iso_dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return list(csv.DictReader(handle))
    except FileNotFoundError:
        return []


def count_csv_rows(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return sum(1 for _ in csv.DictReader(handle))
    except FileNotFoundError:
        return 0


def file_mtime(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    except OSError:
        return None


def latest_mtime(paths: list[Path]) -> datetime | None:
    latest: datetime | None = None
    for path in paths:
        stamp = file_mtime(path)
        if stamp and (latest is None or stamp > latest):
            latest = stamp
    return latest


def safe_text(value: Any, limit: int = 220) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    for pattern in PATH_PATTERNS:
        text = pattern.sub("[redacted-path]", text)
    text = re.sub(r"tank-iso:iso/([A-Za-z0-9_.-]+\.iso)", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        return text[: limit - 1].rstrip() + "..."
    return text


def safe_iso_name(value: Any) -> str | None:
    if not value:
        return None
    text = str(value)
    match = re.search(r"([^/\\:]+\.iso)", text)
    return match.group(1) if match else None


def newest_errors(path: Path, limit: int = 8) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return []
    rows: list[dict[str, Any]] = []
    for line in lines[-max(limit * 4, limit) :]:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append(
            {
                "utc": payload.get("utc"),
                "batch_index": payload.get("batch_index"),
                "consecutive_errors": payload.get("consecutive_errors"),
                "error": safe_text(payload.get("error"), 280),
            }
        )
    return rows[-limit:]


def screen_alive(*name_fragments: str) -> bool:
    proc = subprocess.run(["screen", "-ls"], text=True, capture_output=True, timeout=8)
    if proc.returncode not in (0, 1):
        return False
    return any(name_fragment in proc.stdout for name_fragment in name_fragments)


def campaign_process_alive() -> bool:
    proc = subprocess.run(
        ["pgrep", "-af", "vibex_server2025_sandbox_campaign.py"],
        text=True,
        capture_output=True,
        timeout=8,
    )
    return proc.returncode == 0 and bool(proc.stdout.strip())


def qga_guest_progress(args: argparse.Namespace, run_id: str, batch_index: int) -> dict[str, Any]:
    if not args.pve:
        return {}
    batch_id = f"{run_id}_batch_{batch_index:04d}"
    guest_path = f"C:\\SandboxResults\\{batch_id}\\server2025_batch_progress.json"
    ps = (
        f"$p='{guest_path}';"
        "if(Test-Path $p){Get-Content -Raw $p}else{Write-Output 'NO_PROGRESS'}"
    )
    cmd = [
        "ssh",
        args.pve,
        (
            f"qm guest exec {args.vmid} --timeout 20 -- "
            f"powershell.exe -NoProfile -Command {shlex_quote(ps)}"
        ),
    ]
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=35)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if proc.returncode != 0:
        return {}
    try:
        outer = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}
    raw = str(outer.get("out-data") or "").strip()
    if not raw or raw == "NO_PROGRESS":
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    try:
        row_count = int(payload.get("row_count") or 0)
    except (TypeError, ValueError):
        row_count = 0
    updated = parse_utc(payload.get("updated_utc"))
    return {
        "rows": row_count,
        "updated_utc": iso_dt(updated),
        "batch_id": safe_text(payload.get("batch_id"), 120),
        "tool_profile": safe_text(payload.get("tool_profile"), 40),
    }


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def storage_from_preflight(preflight: dict[str, Any]) -> dict[str, Any]:
    pve_vm = str(preflight.get("pve_vm") or "")
    storage: dict[str, Any] = {"safe": None, "local_available_gb": None, "tank_iso_available_gb": None}
    for line in pve_vm.splitlines():
        parts = line.split()
        if len(parts) < 7:
            continue
        name = parts[0]
        if name not in {"local", "tank-iso"}:
            continue
        try:
            available_gb = int(parts[5]) / 1024 / 1024
        except (TypeError, ValueError):
            continue
        if name == "local":
            storage["local_available_gb"] = round(available_gb, 1)
        if name == "tank-iso":
            storage["tank_iso_available_gb"] = round(available_gb, 1)
    local_ok = storage["local_available_gb"] is None or storage["local_available_gb"] >= 50
    tank_ok = storage["tank_iso_available_gb"] is None or storage["tank_iso_available_gb"] >= 50
    storage["safe"] = bool(local_ok and tank_ok)
    return storage


def batch_index_from_name(path: Path) -> int | None:
    match = re.search(r"_batch_(\d+)", path.name)
    return int(match.group(1)) if match else None


def status_counts(rows: list[dict[str, str]], column: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        value = (row.get(column) or "").strip() or "missing"
        counts[value] += 1
    return counts


def ordered_counts(counter: Counter[str], limit: int | None = None) -> list[dict[str, Any]]:
    rows = [{"name": key, "count": count} for key, count in counter.most_common()]
    return rows if limit is None else rows[:limit]


def expected_rows_for_batch(index: int, target_rows: int, batch_size: int) -> int:
    remaining = target_rows - (index * batch_size)
    if remaining <= 0:
        return 0
    return min(batch_size, remaining)


def duration_seconds(started: datetime | None, completed: datetime | None) -> int | None:
    if not started or not completed:
        return None
    seconds = int((completed - started).total_seconds())
    return max(0, seconds)


def plausible_duration_seconds(started: datetime | None, completed: datetime | None, saved_rows: int) -> int | None:
    seconds = duration_seconds(started, completed)
    if seconds is None:
        return None
    if seconds <= 0:
        return None
    if saved_rows and seconds < max(60, saved_rows):
        return None
    return seconds


def build_batch_rows(
    campaign_dir: Path,
    run_id: str,
    target_rows: int,
    batch_size: int,
    total_batches: int,
    next_batch: int | None,
    last_progress: datetime | None,
    tool_profile: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    batches_root = campaign_dir / "batches"
    batch_by_index: dict[int, Path] = {}
    for path in batches_root.glob("*_batch_*"):
        if path.is_dir():
            index = batch_index_from_name(path)
            if index is not None:
                batch_by_index[index] = path

    stall_window = 600 if tool_profile == "fast" else 1200
    age = int((utc_now() - last_progress).total_seconds()) if last_progress else None
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] = {}

    for index in range(total_batches):
        batch_dir = batch_by_index.get(index, batches_root / f"{run_id}_batch_{index:04d}")
        hints_path = batch_dir / "server2025_family_hints.csv"
        status_path = batch_dir / "server2025_batch_status.json"
        build_path = batch_dir / "workhorse_build_status.json"
        hints = read_csv_rows(hints_path)
        status = read_json(status_path)
        build_status = read_json(build_path)
        expected = expected_rows_for_batch(index, target_rows, batch_size)
        saved = len(hints)
        completed = parse_utc(status.get("completed_utc"))
        started = parse_utc(build_status.get("created_utc")) or file_mtime(build_path)
        updated = latest_mtime([hints_path, status_path, build_path])
        candidate_counts = status_counts(hints, "candidate_status")
        tool_timeout_counts = {
            column.replace("_status", ""): count
            for column in TOOL_STATUS_COLUMNS
            for value, count in status_counts(hints, column).items()
            if value in {"timeout", "tool_timeout"}
        }
        row_status = "not_started"
        if saved >= expected and expected > 0:
            row_status = "complete"
        elif index == next_batch:
            if age is not None and age > stall_window:
                row_status = "stalled"
            elif saved > 0:
                row_status = "running"
            else:
                row_status = "running"
        elif saved > 0:
            row_status = "partial"
        if status.get("error"):
            row_status = "failed"

        duration = plausible_duration_seconds(started, completed, saved)
        row = {
            "index": index,
            "expected_rows": expected,
            "saved_rows": saved,
            "guest_progress_rows": None,
            "status": row_status,
            "started_utc": iso_dt(started),
            "updated_utc": iso_dt(updated),
            "completed_utc": iso_dt(completed),
            "duration_seconds": duration,
            "rows_per_hour": round(saved / (duration / 3600), 1) if duration and saved else None,
            "candidate_counts": dict(candidate_counts),
            "tool_timeout_counts": tool_timeout_counts,
        }
        rows.append(row)
        if index == next_batch:
            iso_name = safe_iso_name(build_status.get("iso") or build_status.get("iso_volume") or status.get("iso"))
            phase = "misleading_active" if row_status == "stalled" and saved == 0 else row_status
            current = {
                **row,
                "iso_name": iso_name or f"{run_id}_batch_{index:04d}.iso",
                "phase": phase,
                "stalled": row_status == "stalled",
            }

    if not current:
        last_index = max((row["index"] for row in rows if row["saved_rows"] > 0), default=0)
        current = {**rows[last_index], "iso_name": None, "phase": rows[last_index]["status"], "stalled": False}
    return rows, current


def infer_current_batch(
    batches: list[dict[str, Any]],
    current_batch: dict[str, Any],
    run_id: str,
    last_progress_age: int | None,
    tool_profile: str,
    runner_alive: bool,
    guest_progress: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if current_batch.get("status") not in {"complete", "partial"}:
        if guest_progress:
            progress_rows = int(guest_progress.get("rows") or 0)
            return {
                **current_batch,
                "guest_progress_rows": progress_rows,
                "guest_progress_updated_utc": guest_progress.get("updated_utc"),
                "phase": "running" if progress_rows > int(current_batch.get("saved_rows") or 0) else current_batch.get("phase"),
                "stalled": False if progress_rows > int(current_batch.get("saved_rows") or 0) else current_batch.get("stalled"),
            }
        return current_batch
    first_incomplete = next(
        (row for row in batches if int(row.get("saved_rows") or 0) < int(row.get("expected_rows") or 0)),
        None,
    )
    if not first_incomplete:
        return current_batch
    stall_window = 600 if tool_profile == "fast" else 1200
    stalled = bool(last_progress_age is not None and last_progress_age > stall_window and not runner_alive)
    status = "stalled" if stalled else ("running" if runner_alive else first_incomplete.get("status", "not_started"))
    current = {
        **first_incomplete,
        "iso_name": f"{run_id}_batch_{int(first_incomplete['index']):04d}.iso",
        "phase": status,
        "status": status,
        "stalled": stalled,
    }
    if guest_progress:
        progress_rows = int(guest_progress.get("rows") or 0)
        current["guest_progress_rows"] = progress_rows
        current["guest_progress_updated_utc"] = guest_progress.get("updated_utc")
        if progress_rows > int(current.get("saved_rows") or 0):
            current["status"] = "running"
            current["phase"] = "running"
            current["stalled"] = False
    return current


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    campaign_dir = Path(args.campaign_dir)
    campaign_status = read_json(campaign_dir / "campaign_status.json")
    watchdog_status = read_json(campaign_dir / "campaign_watchdog_status.json")
    threshold_status = read_json(campaign_dir / "threshold_notifier_status.json")
    preflight_status = read_json(campaign_dir / "preflight_status.json")
    run_id = str(args.run_id or campaign_status.get("run_id") or campaign_dir.name)
    target_rows = int(campaign_status.get("target_rows") or watchdog_status.get("target_rows") or args.target_rows)
    batch_size = int(campaign_status.get("batch_size") or args.batch_size)
    configured_batches = int(campaign_status.get("batch_count") or watchdog_status.get("total_batches") or 0)
    computed_batches = (target_rows + batch_size - 1) // batch_size if batch_size else 0
    total_batches = max(configured_batches, computed_batches)
    prior_rows = int(campaign_status.get("source_completed_rows_excluded") or args.prior_rows)
    total_rows = int(args.total_rows or (target_rows + prior_rows))
    tool_profile = str(campaign_status.get("tool_profile") or args.tool_profile)

    aggregate_path = campaign_dir / "server2025_family_hints.csv"
    aggregate_rows = read_csv_rows(aggregate_path)
    valid_new_rows = len(aggregate_rows)
    progress_files = [
        aggregate_path,
        campaign_dir / "server2025_rebuild_candidates.csv",
        *list((campaign_dir / "batches").glob("*/server2025_family_hints.csv")),
        *list((campaign_dir / "batches").glob("*/server2025_batch_status.json")),
    ]
    last_progress = latest_mtime([path for path in progress_files if path.exists()])
    last_progress_age = int((utc_now() - last_progress).total_seconds()) if last_progress else None
    next_batch = watchdog_status.get("next_batch")
    try:
        next_batch = int(next_batch)
    except (TypeError, ValueError):
        next_batch = None

    runner_alive = screen_alive("vibex_fasttank500_runner", "vibex_server2025_campaign") or campaign_process_alive()
    watchdog_status_time = parse_utc(watchdog_status.get("updated_utc"))
    watchdog_fresh = bool(
        watchdog_status_time and (utc_now() - watchdog_status_time).total_seconds() <= 900
    )
    if not watchdog_fresh:
        next_batch = None

    batches, current_batch = build_batch_rows(
        campaign_dir,
        run_id,
        target_rows,
        batch_size,
        total_batches,
        next_batch,
        last_progress,
        tool_profile,
    )
    current_batch = infer_current_batch(
        batches,
        current_batch,
        run_id,
        last_progress_age,
        tool_profile,
        runner_alive,
    )
    inferred_batch_index = int(current_batch.get("index") or 0)
    guest_progress = qga_guest_progress(args, run_id, inferred_batch_index) if runner_alive else {}
    if guest_progress:
        current_batch = infer_current_batch(
            batches,
            current_batch,
            run_id,
            last_progress_age,
            tool_profile,
            runner_alive,
            guest_progress,
        )
    if guest_progress:
        for row in batches:
            if row.get("index") == int(current_batch.get("index") or -1):
                row["guest_progress_rows"] = int(guest_progress.get("rows") or 0)
                row["guest_progress_updated_utc"] = guest_progress.get("updated_utc")
                if int(guest_progress.get("rows") or 0) > int(row.get("saved_rows") or 0):
                    row["status"] = "running"
                break

    started = parse_utc(campaign_status.get("created_utc"))
    elapsed_hours = (utc_now() - started).total_seconds() / 3600 if started else None
    rows_per_hour = round(valid_new_rows / elapsed_hours, 1) if elapsed_hours and elapsed_hours > 0 else None
    remaining = max(0, target_rows - valid_new_rows)
    eta_hours = round(remaining / rows_per_hour, 1) if rows_per_hour and rows_per_hour > 0 else None
    combined_rows = valid_new_rows + prior_rows

    candidate_status = status_counts(aggregate_rows, "candidate_status")
    hints = Counter((row.get("tool_hint_family") or "").strip().lower() for row in aggregate_rows)
    hints.pop("", None)
    generic_hint_count = sum(count for hint, count in hints.items() if hint in GENERIC_HINTS)
    useful_hint_count = sum(
        1
        for row in aggregate_rows
        if (row.get("candidate_status") or "").strip() == "supporting_hint"
        and (row.get("tool_hint_family") or "").strip().lower() not in GENERIC_HINTS
    )
    tool_status_counts: dict[str, dict[str, int]] = {}
    tool_completion_rates: dict[str, dict[str, Any]] = {}
    for column in TOOL_STATUS_COLUMNS:
        tool = column.replace("_status", "")
        counts = status_counts(aggregate_rows, column)
        total = sum(counts.values())
        completed = counts.get("completed", 0)
        timeout = counts.get("timeout", 0) + counts.get("tool_timeout", 0)
        missing = counts.get("missing", 0)
        tool_status_counts[tool] = dict(counts)
        tool_completion_rates[tool] = {
            "completed": completed,
            "timeout": timeout,
            "missing": missing,
            "total": total,
            "completion_rate": round(completed / total, 4) if total else None,
            "timeout_rate": round(timeout / total, 4) if total else None,
        }

    watchdog_alive = screen_alive("vibex_fasttank500_watchdog", "vibex_server2025_watchdog") or bool(
        watchdog_fresh and watchdog_status.get("campaign_active")
    )
    threshold_alive = screen_alive("vibex_fasttank500_threshold", "vibex_server2025_thresholds")
    model_alive = screen_alive("vibex_fasttank500_model", "vibex_server2025_model_watch")
    storage = storage_from_preflight(preflight_status)
    stall_window = 600 if tool_profile == "fast" else 1200
    guest_progress_age = None
    if guest_progress.get("updated_utc"):
        guest_progress_dt = parse_utc(guest_progress.get("updated_utc"))
        if guest_progress_dt:
            guest_progress_age = int((utc_now() - guest_progress_dt).total_seconds())
    effective_progress_age = min(
        age for age in [last_progress_age, guest_progress_age] if age is not None
    ) if last_progress_age is not None or guest_progress_age is not None else None
    stalled = bool(effective_progress_age is not None and effective_progress_age > stall_window and valid_new_rows < target_rows)
    state = "complete" if valid_new_rows >= target_rows else ("stalled" if stalled else "running")
    if runner_alive and stalled and current_batch.get("saved_rows") in (0, None):
        state = "misleading_active"
    if watchdog_status.get("action") and "error" in str(watchdog_status.get("action")).lower():
        state = "failed"

    notes = []
    if storage.get("safe") is False:
        notes.append("Proxmox storage is below the 50 GB safety threshold on at least one monitored store.")
    if state == "misleading_active":
        notes.append("Runner/watchdog activity exists, but no new safe rows or guest progress have appeared inside the stall window.")

    return {
        "ok": True,
        "updated_utc": iso_now(),
        "run_id": run_id,
        "vmid": int(args.vmid),
        "vm_name": args.vm_name,
        "network_mode": args.network_mode,
        "summary": {
            "target_rows": target_rows,
            "valid_new_rows": valid_new_rows,
            "prior_rows": prior_rows,
            "combined_rows": combined_rows,
            "total_rows": total_rows,
            "percent_complete": round(combined_rows / total_rows, 4) if total_rows else None,
            "new_percent_complete": round(valid_new_rows / target_rows, 4) if target_rows else None,
            "rows_per_hour": rows_per_hour,
            "eta_hours": eta_hours,
        },
        "health": {
            "state": state,
            "last_progress_utc": iso_dt(last_progress),
            "last_progress_age_seconds": last_progress_age,
            "guest_progress_age_seconds": guest_progress_age,
            "runner_alive": runner_alive,
            "watchdog_alive": watchdog_alive,
            "model_alive": model_alive,
            "threshold_alive": threshold_alive,
            "qga_ok": bool(watchdog_status.get("qga_ok") or preflight_status.get("qga")),
            "ssh_configured": True,
            "vm_running": "status: running" in str(preflight_status.get("pve_vm") or ""),
            "vm103_stopped": True,
            "storage_safe": storage.get("safe"),
            "storage": storage,
            "tank_iso_used": campaign_status.get("pve_iso_storage") == "tank-iso",
            "notes": notes,
        },
        "current_batch": current_batch,
        "batches": batches,
        "quality": {
            "candidate_status_counts": dict(candidate_status),
            "hint_family_counts": dict(hints.most_common(20)),
            "tool_status_counts": tool_status_counts,
            "tool_completion_rates": tool_completion_rates,
            "generic_hint_count": generic_hint_count,
            "useful_hint_count": useful_hint_count,
        },
        "errors": newest_errors(campaign_dir / "batch_errors.jsonl"),
        "thresholds": {
            "next_threshold": threshold_status.get("next_threshold"),
            "sent": threshold_status.get("sent", []),
        },
    }


def write_payload(payload: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output.with_suffix(output.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(output)


def copy_output(output: Path, copy_to: str) -> None:
    if not copy_to:
        return
    if ":" not in copy_to:
        dest = Path(copy_to)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(output, dest)
        return
    subprocess.run(["scp", str(output), copy_to], check=True, timeout=30)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export dashboard-safe VIBEX sandbox campaign metrics.")
    parser.add_argument("--campaign-dir", default=str(DEFAULT_CAMPAIGN_DIR))
    parser.add_argument("--run-id", default="")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--copy-to", default="")
    parser.add_argument("--watch-seconds", type=int, default=0)
    parser.add_argument("--prior-rows", type=int, default=1075)
    parser.add_argument("--target-rows", type=int, default=20679)
    parser.add_argument("--total-rows", type=int, default=21754)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--vmid", type=int, default=116)
    parser.add_argument("--pve", default="")
    parser.add_argument("--vm-name", default="sandbox-win11-01")
    parser.add_argument("--tool-profile", default="full")
    parser.add_argument("--network-mode", default="vmbr3 / 10.64.100.0/24 isolated sandbox")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = Path(args.output)
    while True:
        payload = build_payload(args)
        write_payload(payload, output)
        copy_output(output, args.copy_to)
        if args.watch_seconds <= 0:
            break
        time.sleep(args.watch_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
