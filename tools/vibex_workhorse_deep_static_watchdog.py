#!/usr/bin/env python3
"""Telegram watchdog for the Windows 11 deep static family classifier.

This monitor reads only safe progress/summary files and runner logs. It never
copies raw samples or raw tool dumps out of the sandbox.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo


DEFAULT_RUN_ROOT = "/home/phil/vibex_secure_dataset/evidence/sandbox_drive/windows11_drive_triage_20260611"
DEFAULT_SANDBOX_KEY = "/home/phil/.ssh/vibex_sandbox_transfer_ed25519"
DEFAULT_JUMP_HOST = "phil@10.64.0.57"
DEFAULT_SANDBOX_HOST = "phil@10.192.101.130"
DEFAULT_TELEGRAM_HOST = "phil@10.64.0.62"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except Exception:
        return {}


def save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def quiet_hours(args: argparse.Namespace) -> bool:
    hour = datetime.now(ZoneInfo(args.telegram_timezone)).hour
    return hour >= args.quiet_start or hour < args.quiet_end


def send_telegram(args: argparse.Namespace, message: str) -> None:
    queue_path = Path(args.run_root) / "logs" / "deep_static_family_telegram_queued.jsonl"
    if quiet_hours(args):
        queue_path.parent.mkdir(parents=True, exist_ok=True)
        with queue_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"queued_utc": utc_now(), "message": message}) + "\n")
        return

    if queue_path.exists():
        rows = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if rows:
            digest = ["VIBEX malware classification update", f"Quiet-hours digest: {len(rows)} queued alerts"]
            for row in rows[-8:]:
                digest.append("")
                digest.append(str(row.get("message", ""))[-1200:])
            subprocess.run(
                ["ssh", args.telegram_host, "sudo", "/usr/local/bin/vibex_send_telegram_text.py"],
                input="\n".join(digest),
                text=True,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        queue_path.unlink(missing_ok=True)

    subprocess.run(
        ["ssh", args.telegram_host, "sudo", "/usr/local/bin/vibex_send_telegram_text.py"],
        input=message,
        text=True,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def runner_alive(args: argparse.Namespace) -> bool:
    if args.runner_pid:
        return subprocess.run(["ps", "-p", str(args.runner_pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    proc = subprocess.run(
        ["pgrep", "-af", "vibex_workhorse_run_deep_static_classifier.sh"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    lines = [line for line in proc.stdout.splitlines() if "pgrep" not in line and "deep_static_watchdog" not in line]
    return bool(lines)


def fetch_sandbox_progress(args: argparse.Namespace) -> dict[str, Any]:
    live_path = Path(args.run_root) / "results" / "deep_static_family_progress.live.json"
    proxy = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {args.jump_host} -W %h:%p"
    script = (
        "if (Test-Path 'S:\\results\\deep_static_family_progress.json') { "
        "Get-Content 'S:\\results\\deep_static_family_progress.json' -Raw "
        "} elseif (Test-Path 'S:\\results\\deep_static_family_summary.json') { "
        "Get-Content 'S:\\results\\deep_static_family_summary.json' -Raw "
        "} else { Write-Output '{}' }"
    )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    command = f"powershell -NoProfile -EncodedCommand {encoded}"
    try:
        proc = subprocess.run(
            [
                "ssh",
                "-i",
                args.sandbox_key,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                f"ProxyCommand={proxy}",
                args.sandbox_host,
                command,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=args.sandbox_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        data = load_json(live_path)
        data["progress_read_timeout_utc"] = utc_now()
        save_json(live_path, data)
        return data
    try:
        data = json.loads(proc.stdout.strip() or "{}")
    except json.JSONDecodeError:
        data = {}
    save_json(live_path, data)
    return data


def local_summary(args: argparse.Namespace) -> dict[str, Any]:
    return load_json(Path(args.run_root) / "results" / "deep_static_family" / "deep_static_family_summary.json")


def decision_counts(summary: dict[str, Any]) -> str:
    rows = summary.get("decision_counts") or []
    parts = [f"{row.get('name')}: {row.get('count')}" for row in rows if row.get("name")]
    return ", ".join(parts) if parts else "decision counts unavailable"


def notify_once(args: argparse.Namespace, state: dict[str, Any], key: str, message: str) -> bool:
    sent = set(state.get("sent", []))
    if key in sent:
        return False
    send_telegram(args, message)
    sent.add(key)
    state["sent"] = sorted(sent)
    state["updated_utc"] = utc_now()
    save_json(Path(args.state_path), state)
    return True


def build_progress_message(args: argparse.Namespace, rows: int, target: int, milestone: str, stage: str) -> str:
    pct = (rows / target * 100.0) if target else 0.0
    return "\n".join(
        [
            "VIBEX malware classification update",
            "",
            f"Milestone: {milestone}",
            f"Stage: {stage}",
            f"Rows processed: {rows:,} of {target:,} ({pct:.1f}%)",
            "Raw malware remains on sandbox S: only.",
        ]
    )


def check_once(args: argparse.Namespace) -> None:
    state_path = Path(args.state_path)
    state = load_json(state_path)
    now_epoch = time.time()
    log_dir = Path(args.run_root) / "logs"
    runner_log = read_text(log_dir / "deep_static_family_runner.log")
    full_log = read_text(log_dir / "deep_static_family_full.log")
    smoke_summary = load_json(Path(args.run_root) / "results" / "deep_static_family_smoke" / "deep_static_family_summary.json")
    sandbox = fetch_sandbox_progress(args)
    summary = local_summary(args)

    stage = "toolchain/smoke gate"
    if "running full deep static classifier" in runner_log:
        stage = "full deep static classifier"
    if "deep static classifier complete" in runner_log:
        stage = "complete"

    target = int(sandbox.get("target_rows") or summary.get("target_rows") or args.target_rows)
    rows = int(sandbox.get("saved_rows") or summary.get("saved_rows") or 0)
    previous_rows = int(state.get("last_rows") or 0)
    if rows > previous_rows:
        state["last_rows"] = rows
        state["last_progress_epoch"] = now_epoch
        state["last_progress_utc"] = utc_now()
        save_json(state_path, state)

    notify_once(
        args,
        state,
        "watchdog_started",
        "\n".join(
            [
                "VIBEX malware classification update",
                "",
                "Telegram watchdog is now attached to the Windows 11 deep static family classifier.",
                f"Stage: {stage}",
                f"Rows processed: {rows:,} of {target:,}",
            ]
        ),
    )

    if int(smoke_summary.get("saved_rows") or 0) >= 20 or "running full deep static classifier" in runner_log:
        notify_once(
            args,
            state,
            "smoke_complete",
            "\n".join(
                [
                    "VIBEX malware classification update",
                    "",
                    "The 20-row deep static smoke gate completed successfully.",
                    "The full classifier is cleared to run.",
                ]
            ),
        )

    if "running full deep static classifier" in runner_log:
        notify_once(
            args,
            state,
            "full_started",
            "\n".join(
                [
                    "VIBEX malware classification update",
                    "",
                    "The full Windows 11 deep static classifier has started.",
                    f"Target rows: {target:,}",
                    "Tools: PE metadata, DIE, strings, FLOSS, capa, YARA when curated rules are present.",
                ]
            ),
        )

    for threshold in args.thresholds:
        if rows >= threshold:
            notify_once(args, state, f"rows_{threshold}", build_progress_message(args, rows, target, f"{threshold:,} rows", stage))

    completed = summary or ("deep static classifier complete" in runner_log and rows >= min(target, 1))
    if completed:
        final_rows = int(summary.get("saved_rows") or rows)
        final_target = int(summary.get("target_rows") or target)
        if final_rows >= final_target or "deep static classifier complete" in runner_log:
            notify_once(
                args,
                state,
                "complete",
                "\n".join(
                    [
                        "VIBEX malware classification update",
                        "",
                        "The full Windows 11 deep static classifier has completed.",
                        f"Saved rows: {final_rows:,} of {final_target:,}.",
                        f"Decisions: {decision_counts(summary)}.",
                        "Next step: build the high-confidence balanced family manifest on workhorse.",
                    ]
                ),
            )
            return

    if "Smoke failed:" in runner_log:
        notify_once(
            args,
            state,
            "smoke_failed",
            "\n".join(
                [
                    "VIBEX malware classification update",
                    "",
                    "The deep static classifier smoke gate failed.",
                    "The full run was not started. Check deep_static_family_runner.log on workhorse.",
                ]
            ),
        )
        return

    if not runner_alive(args) and "deep static classifier complete" not in runner_log:
        notify_once(
            args,
            state,
            f"runner_stopped_{rows}",
            "\n".join(
                [
                    "VIBEX malware classification update",
                    "",
                    "The deep static classifier runner stopped before recorded completion.",
                    f"Last rows seen: {rows:,} of {target:,}.",
                    "Check workhorse logs before restarting.",
                ]
            ),
        )
        return

    last_progress_epoch = float(state.get("last_progress_epoch") or now_epoch)
    if now_epoch - last_progress_epoch >= args.stall_minutes * 60:
        bucket = int((now_epoch - last_progress_epoch) // (args.stall_minutes * 60))
        notify_once(
            args,
            state,
            f"stall_{rows}_{bucket}",
            "\n".join(
                [
                    "VIBEX malware classification update",
                    "",
                    "The deep static classifier may be stalled.",
                    f"Last rows seen: {rows:,} of {target:,}.",
                    f"No row increase for at least {args.stall_minutes} minutes.",
                ]
            ),
        )

    if full_log and "Exception" in full_log[-4000:]:
        notify_once(
            args,
            state,
            f"exception_hint_{rows}",
            "\n".join(
                [
                    "VIBEX malware classification update",
                    "",
                    "The deep static classifier log contains a recent exception marker.",
                    f"Rows seen: {rows:,} of {target:,}.",
                    "Check deep_static_family_full.log on workhorse.",
                ]
            ),
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", default=DEFAULT_RUN_ROOT)
    parser.add_argument("--target-rows", type=int, default=19324)
    parser.add_argument("--runner-pid", type=int)
    parser.add_argument("--interval-seconds", type=int, default=300)
    parser.add_argument("--stall-minutes", type=int, default=45)
    parser.add_argument("--sandbox-key", default=DEFAULT_SANDBOX_KEY)
    parser.add_argument("--jump-host", default=DEFAULT_JUMP_HOST)
    parser.add_argument("--sandbox-host", default=DEFAULT_SANDBOX_HOST)
    parser.add_argument("--sandbox-timeout-seconds", type=int, default=60)
    parser.add_argument("--telegram-host", default=DEFAULT_TELEGRAM_HOST)
    parser.add_argument("--telegram-timezone", default="Europe/London")
    parser.add_argument("--quiet-start", type=int, default=22)
    parser.add_argument("--quiet-end", type=int, default=6)
    parser.add_argument(
        "--thresholds",
        type=int,
        nargs="*",
        default=[100, 1000, 5000, 10000, 15000, 19324],
    )
    parser.add_argument("--state-path")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not args.state_path:
        args.state_path = str(Path(args.run_root) / "logs" / "deep_static_family_watchdog_state.json")

    while True:
        check_once(args)
        if args.once:
            return 0
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
