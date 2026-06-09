#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import shlex
import subprocess
import time
import csv
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd: list[str], timeout: int | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=check)


def append_log(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{utc_now()} {message}\n")


def load_status(campaign_dir: Path) -> dict:
    return json.loads((campaign_dir / "campaign_status.json").read_text(encoding="utf-8"))


def expected_rows_for_batch(status: dict, batch_index: int, batch_size: int) -> int:
    target_rows = int(status.get("target_rows") or 0)
    remaining = target_rows - (batch_index * batch_size)
    if remaining <= 0:
        return 0
    return min(batch_size, remaining)


def csv_row_count(path: Path) -> int:
    try:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            return sum(1 for _ in csv.DictReader(handle))
    except FileNotFoundError:
        return 0


def completed_batches(campaign_dir: Path, run_id: str, status: dict, batch_size: int) -> set[int]:
    done: set[int] = set()
    for csv_path in sorted((campaign_dir / "batches").glob(f"{run_id}_batch_*/server2025_family_hints.csv")):
        try:
            idx = int(csv_path.parent.name.rsplit("_", 1)[1])
        except (IndexError, ValueError):
            continue
        expected = expected_rows_for_batch(status, idx, batch_size)
        if expected > 0 and csv_row_count(csv_path) >= expected:
            done.add(idx)
    return done


def next_missing_batch(campaign_dir: Path, run_id: str, status: dict, total_batches: int, batch_size: int) -> int | None:
    done = completed_batches(campaign_dir, run_id, status, batch_size)
    for idx in range(total_batches):
        if idx not in done:
            return idx
    return None


def active_campaign(run_id: str) -> bool:
    proc = run(["pgrep", "-af", f"vibex_server2025_sandbox_campaign.py.*{run_id}"], timeout=10)
    return proc.returncode == 0 and "pgrep -af" not in proc.stdout


def screen_exists(name: str) -> bool:
    proc = run(["screen", "-ls"], timeout=10)
    return name in proc.stdout


def quit_screen(name: str) -> None:
    run(["screen", "-S", name, "-X", "quit"], timeout=10)


def pve(args: argparse.Namespace, command: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return run(["ssh", args.pve, command], timeout=timeout)


def qga_ok(args: argparse.Namespace) -> bool:
    proc = pve(
        args,
        f"qm guest exec {args.vmid} --timeout 30 -- powershell.exe -NoProfile -Command \"Write-Output OK\"",
        timeout=45,
    )
    return proc.returncode == 0 and "OK" in proc.stdout


def pve_iso_name(args: argparse.Namespace, run_id: str, batch_index: int) -> str:
    preferred = f"{run_id}_batch_{batch_index:04d}.iso"
    proc = pve(args, f"test -f {shlex.quote(args.pve_iso_dir.rstrip('/') + '/' + preferred)}", timeout=20)
    return preferred if proc.returncode == 0 else ""


def recover_vm(args: argparse.Namespace, run_id: str, batch_index: int, log_path: Path) -> bool:
    iso_name = pve_iso_name(args, run_id, batch_index)
    append_log(log_path, f"recover_vm batch={batch_index} iso={iso_name} no_rollback={args.no_rollback}")
    cdrom_arg = f"--{args.cdrom_slot}"
    if args.no_rollback:
        attach = f"qm set {args.vmid} {cdrom_arg} {shlex.quote(args.pve_iso_storage + ':iso/' + iso_name)},media=cdrom; " if iso_name else ""
        command = (
            f"{attach}"
            f"qm status {args.vmid} | grep -q 'status: running' || qm start {args.vmid}; "
            f"for i in $(seq 1 {args.qga_wait_attempts}); do "
            f"qm guest exec {args.vmid} -- powershell.exe -NoProfile -Command \"Write-Output READY\" 2>/dev/null | grep -q READY && exit 0; "
            "sleep 5; "
            "done; exit 1"
        )
    else:
        command = (
            f"qm stop {args.vmid} --skiplock 1 || true; "
            f"qm rollback {args.vmid} {shlex.quote(args.snapshot)}; "
            f"qm set {args.vmid} {cdrom_arg} {shlex.quote(args.pve_iso_storage + ':iso/' + iso_name)},media=cdrom; "
            f"qm start {args.vmid}; "
            f"for i in $(seq 1 {args.qga_wait_attempts}); do "
            f"qm guest exec {args.vmid} -- powershell.exe -NoProfile -Command \"Write-Output READY\" 2>/dev/null | grep -q READY && exit 0; "
            "sleep 5; "
            "done; exit 1"
        )
    proc = pve(args, command, timeout=args.qga_wait_attempts * 5 + 180)
    append_log(log_path, f"recover_vm rc={proc.returncode} stdout_tail={proc.stdout[-500:].replace(chr(10), ' ')} stderr_tail={proc.stderr[-500:].replace(chr(10), ' ')}")
    return proc.returncode == 0


def start_campaign(args: argparse.Namespace, campaign_dir: Path, start_batch: int, log_path: Path) -> None:
    quit_screen(args.campaign_screen)
    cmd = (
        f"cd {shlex.quote(str(ROOT))} && "
        f"python3 tools/vibex_server2025_sandbox_campaign.py run "
        f"--run-id {shlex.quote(args.run_id)} "
        f"--output-dir {shlex.quote(str(campaign_dir))} "
        f"--pve {shlex.quote(args.pve)} "
        f"--vmid {shlex.quote(args.vmid)} "
        f"--snapshot {shlex.quote(args.snapshot)} "
        f"--batch-size {args.batch_size} "
        f"--guest-timeout {args.guest_timeout} "
        f"--iso-timeout {args.iso_timeout} "
        f"--pve-iso-storage {shlex.quote(args.pve_iso_storage)} "
        f"--pve-iso-dir {shlex.quote(args.pve_iso_dir)} "
        f"--cdrom-slot {shlex.quote(args.cdrom_slot)} "
        f"--tool-profile {shlex.quote(args.tool_profile)} "
        f"{'--no-rollback ' if args.no_rollback else ''}"
        f"--max-consecutive-errors 0 "
        f"--start-batch {start_batch} "
        f">> {shlex.quote(str(campaign_dir / 'campaign_runner.log'))} 2>&1"
    )
    run(["screen", "-dmS", args.campaign_screen, "zsh", "-lc", cmd], timeout=10)
    append_log(log_path, f"started_campaign start_batch={start_batch}")


def ensure_model_watcher(args: argparse.Namespace, campaign_dir: Path, log_path: Path) -> None:
    if screen_exists(args.model_screen):
        return
    cmd = (
        f"cd {shlex.quote(str(ROOT))} && "
        f"python3 tools/vibex_server2025_post_campaign_watch.py "
        f"--campaign-dir {shlex.quote(str(campaign_dir))} "
        f"--poll-seconds 600 --max-wait-seconds 604800 --model-max-wait-seconds 604800 --telegram "
        f"> {shlex.quote(str(campaign_dir / 'post_campaign_watch.log'))} 2>&1"
    )
    run(["screen", "-dmS", args.model_screen, "zsh", "-lc", cmd], timeout=10)
    append_log(log_path, "started_model_watcher")


def write_watchdog_status(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def watchdog_once(args: argparse.Namespace, campaign_dir: Path, log_path: Path) -> dict:
    status = load_status(campaign_dir)
    total_batches = int(status.get("batch_count") or math.ceil(int(status["target_rows"]) / args.batch_size))
    next_batch = next_missing_batch(campaign_dir, args.run_id, status, total_batches, args.batch_size)
    done_batches = len(completed_batches(campaign_dir, args.run_id, status, args.batch_size))
    completed_rows = int(status.get("completed_result_rows") or 0)
    payload = {
        "updated_utc": utc_now(),
        "run_id": args.run_id,
        "completed_result_rows": completed_rows,
        "target_rows": int(status.get("target_rows", 0)),
        "done_batches": done_batches,
        "total_batches": total_batches,
        "next_batch": next_batch,
        "campaign_active": active_campaign(args.run_id),
        "qga_ok": False,
        "action": "none",
    }
    ensure_model_watcher(args, campaign_dir, log_path)
    if next_batch is None:
        payload["action"] = "complete"
        return payload

    payload["qga_ok"] = qga_ok(args)
    if payload["campaign_active"]:
        payload["action"] = "campaign_active"
        return payload

    if not payload["qga_ok"]:
        if not recover_vm(args, args.run_id, next_batch, log_path):
            payload["action"] = "recover_failed"
            return payload
        payload["qga_ok"] = True

    start_campaign(args, campaign_dir, next_batch, log_path)
    payload["action"] = f"started_from_batch_{next_batch}"
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Keep the Server 2025 sandbox campaign moving unattended.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--campaign-dir", required=True)
    parser.add_argument("--batch-size", type=int, default=25)
    parser.add_argument("--snapshot", default="pre-detonation-4core-static")
    parser.add_argument("--pve", default="root@10.0.0.11")
    parser.add_argument("--vmid", default="103")
    parser.add_argument("--pve-iso-storage", default="local")
    parser.add_argument("--pve-iso-dir", default="/var/lib/vz/template/iso")
    parser.add_argument("--cdrom-slot", default="ide2")
    parser.add_argument("--tool-profile", choices=["full", "fast"], default="full")
    parser.add_argument("--no-rollback", action="store_true")
    parser.add_argument("--guest-timeout", type=int, default=7200)
    parser.add_argument("--iso-timeout", type=int, default=7200)
    parser.add_argument("--poll-seconds", type=int, default=300)
    parser.add_argument("--qga-wait-attempts", type=int, default=60)
    parser.add_argument("--campaign-screen", default="vibex_server2025_campaign")
    parser.add_argument("--model-screen", default="vibex_server2025_model_watch")
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    campaign_dir = Path(args.campaign_dir)
    log_path = campaign_dir / "campaign_watchdog.log"
    status_path = campaign_dir / "campaign_watchdog_status.json"
    while True:
        try:
            payload = watchdog_once(args, campaign_dir, log_path)
        except Exception as exc:  # noqa: BLE001
            payload = {"updated_utc": utc_now(), "run_id": args.run_id, "action": "watchdog_error", "error": repr(exc)}
            append_log(log_path, f"watchdog_error {exc!r}")
        write_watchdog_status(status_path, payload)
        append_log(log_path, f"status {json.dumps(payload, sort_keys=True)}")
        if args.once or payload.get("action") == "complete":
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
