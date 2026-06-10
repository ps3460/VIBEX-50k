#!/usr/bin/env python3
"""Lightweight watchdog for unattended workhorse model runs.

This script is intentionally repo-safe: it reads only summary/status files and
sends plain Telegram status if a detached model job stops or stops updating.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo


TELEGRAM_CMD = [
    "ssh",
    "phil@10.64.0.62",
    "sudo",
    "/usr/local/bin/vibex_send_telegram_text.py",
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def is_process_alive(pid: int) -> bool:
    return subprocess.run(["ps", "-p", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def read_leaderboard(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def best_metrics(rows: list[dict[str, str]]) -> tuple[str, float, float, float]:
    best_name = "none yet"
    best_macro = -1.0
    best_weighted = 0.0
    best_accuracy = 0.0
    for row in rows:
        if row.get("status") != "completed":
            continue
        try:
            macro = float(row.get("macro_f1_mean") or 0)
            weighted = float(row.get("weighted_f1_mean") or 0)
            accuracy = float(row.get("accuracy_mean") or 0)
        except ValueError:
            continue
        if macro > best_macro:
            best_name = f"{row.get('phase', 'unknown')} / {row.get('architecture', 'unknown')}"
            best_macro = macro
            best_weighted = weighted
            best_accuracy = accuracy
    return best_name, max(best_macro, 0.0), best_weighted, best_accuracy


def is_quiet(args: argparse.Namespace) -> bool:
    hour = datetime.now(ZoneInfo(args.telegram_timezone)).hour
    return hour >= args.quiet_start or hour < args.quiet_end


def queue_telegram(args: argparse.Namespace, message: str) -> None:
    path = Path(args.run_dir) / "logs" / "watchdog_queued_telegram.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"queued_utc": utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"), "message": message}) + "\n")


def flush_queued_telegram(args: argparse.Namespace) -> None:
    if is_quiet(args):
        return
    path = Path(args.run_dir) / "logs" / "watchdog_queued_telegram.jsonl"
    if not path.exists():
        return
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        return
    digest = ["VIBEX model test update", f"Watchdog quiet-hours digest: {len(rows)} queued alerts"]
    for row in rows[-6:]:
        digest.append("---")
        digest.append(row["message"][-1200:])
    subprocess.run(TELEGRAM_CMD, input="\n".join(digest), text=True, check=False)
    path.unlink()


def send_telegram(args: argparse.Namespace, message: str) -> None:
    flush_queued_telegram(args)
    if is_quiet(args):
        queue_telegram(args, message)
        return
    subprocess.run(TELEGRAM_CMD, input=message, text=True, check=False)


def build_message(title: str, args: argparse.Namespace, rows: list[dict[str, str]], age_minutes: float, alive: bool) -> str:
    completed = sum(1 for row in rows if row.get("status") == "completed")
    failures = sum(1 for row in rows if row.get("status") != "completed")
    best_name, macro, weighted, accuracy = best_metrics(rows)
    current = "unknown"
    if alive:
        proc = subprocess.run(
            ["pgrep", "-af", "vibex_planb_native_family_experiment.py"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        current = proc.stdout.strip().splitlines()[-1][:180] if proc.stdout.strip() else "model process not visible"

    return "\n".join(
        [
            "VIBEX model test update",
            f"Run: {args.run_id}",
            f"State: {title}",
            f"Completed models: {completed} of {args.expected_groups}",
            f"Failures: {failures}",
            f"Best so far: {best_name}",
            f"Best macro-F1: {macro:.4f}",
            f"Best weighted-F1: {weighted:.4f}",
            f"Best accuracy: {accuracy:.4f}",
            f"Last leaderboard update: about {age_minutes:.0f} minutes ago",
            f"Runner alive: {'yes' if alive else 'no'}",
            f"Current process: {current}",
        ]
    )


def check_once(args: argparse.Namespace) -> None:
    run_dir = Path(args.run_dir)
    state_path = run_dir / "logs" / "model_watchdog_status.json"
    state = load_json(state_path)
    rows = read_leaderboard(run_dir / "overall_leaderboard.csv")
    pid = read_pid(run_dir / "model_run.pid")
    alive = is_process_alive(pid) if pid else False
    leaderboard = run_dir / "overall_leaderboard.csv"
    mtime = leaderboard.stat().st_mtime if leaderboard.exists() else run_dir.stat().st_mtime
    age_minutes = max(0.0, (time.time() - mtime) / 60.0)
    completed = sum(1 for row in rows if row.get("status") == "completed")

    status = {
        "updated_utc": utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run_id": args.run_id,
        "pid": pid,
        "runner_alive": alive,
        "completed_groups": completed,
        "expected_groups": args.expected_groups,
        "last_leaderboard_age_minutes": age_minutes,
    }
    save_json(state_path, status)

    if completed >= args.expected_groups:
        return

    if not alive:
        key = f"stopped:{completed}"
        if state.get("last_alert_key") != key:
            send_telegram(args, build_message("runner stopped before completion", args, rows, age_minutes, alive))
            state["last_alert_key"] = key
            save_json(state_path, state | status)
        return

    if age_minutes >= args.stall_minutes:
        bucket = int(age_minutes // args.stall_minutes)
        key = f"stall:{completed}:{bucket}"
        if state.get("last_alert_key") != key:
            send_telegram(args, build_message("possible stall", args, rows, age_minutes, alive))
            state["last_alert_key"] = key
            save_json(state_path, state | status)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--expected-groups", type=int, default=10)
    parser.add_argument("--stall-minutes", type=int, default=180)
    parser.add_argument("--interval-seconds", type=int, default=300)
    parser.add_argument("--telegram-timezone", default="Europe/London")
    parser.add_argument("--quiet-start", type=int, default=22)
    parser.add_argument("--quiet-end", type=int, default=6)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    while True:
        check_once(args)
        if args.once:
            return 0
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
