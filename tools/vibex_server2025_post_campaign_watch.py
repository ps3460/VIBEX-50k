#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def csv_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(newline="", encoding="utf-8") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def send_telegram(title: str, body: str) -> dict[str, object]:
    message = f"{title}\n\n{body}"
    proc = subprocess.run(
        ["ssh", "phil@10.64.0.62", "sudo /usr/local/bin/vibex_send_telegram_text.py"],
        input=message,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout[-1000:],
        "stderr": proc.stderr[-1000:],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Wait for Server 2025 campaign completion, then queue augmented model test.")
    parser.add_argument("--campaign-dir", required=True)
    parser.add_argument("--poll-seconds", type=int, default=600)
    parser.add_argument("--max-wait-seconds", type=int, default=604800)
    parser.add_argument("--model-max-wait-seconds", type=int, default=604800)
    parser.add_argument("--telegram", action="store_true")
    args = parser.parse_args()

    campaign_dir = Path(args.campaign_dir)
    status_path = campaign_dir / "campaign_status.json"
    hints_path = campaign_dir / "server2025_family_hints.csv"
    watcher_status = campaign_dir / "post_campaign_watch_status.json"
    start = time.time()
    while True:
        status = json.loads(status_path.read_text(encoding="utf-8"))
        target_rows = int(status.get("target_rows") or 0)
        complete_rows = csv_count(hints_path)
        payload = {
            "updated_utc": utc_now(),
            "target_rows": target_rows,
            "completed_rows": complete_rows,
            "ready_for_model": target_rows > 0 and complete_rows >= target_rows,
        }
        watcher_status.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if payload["ready_for_model"]:
            break
        if time.time() - start > args.max_wait_seconds:
            payload["timed_out"] = True
            if args.telegram:
                payload["telegram"] = send_telegram(
                    "VIBEX Server 2025 Campaign Watch Timed Out",
                    f"Campaign: {campaign_dir.name}\nCompleted rows: {complete_rows}/{target_rows}\nUTC: {payload['updated_utc']}",
                )
            watcher_status.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return 2
        time.sleep(args.poll_seconds)

    if args.telegram:
        payload = json.loads(watcher_status.read_text(encoding="utf-8"))
        payload["telegram_campaign_done"] = send_telegram(
            "VIBEX Server 2025 Campaign Complete",
            f"Campaign: {campaign_dir.name}\nCompleted rows: {payload['completed_rows']}/{payload['target_rows']}\nUTC: {payload['updated_utc']}\nNext: building augmented manifest and queueing workhorse model test.",
        )
        watcher_status.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    model_dir = campaign_dir / "model_test_inputs"
    run(
        [
            "python3",
            str(ROOT / "tools" / "vibex_build_augmented_family_manifest.py"),
            "--hints",
            str(hints_path),
            "--output-dir",
            str(model_dir),
        ]
    )
    run_id = f"{campaign_dir.name}_augmented_family_model"
    run(
        [
            "python3",
            str(ROOT / "tools" / "vibex_workhorse_augmented_family_model.py"),
            "--baseline-manifest",
            str(model_dir / "family_core_baseline_manifest.csv"),
            "--augmented-manifest",
            str(model_dir / "family_augmented_experimental_manifest.csv"),
            "--output-dir",
            str(campaign_dir / "model_test"),
            "--run-id",
            run_id,
            "--profile",
            "full",
            "--wait",
            "--max-wait-seconds",
            str(args.model_max_wait_seconds),
            "--background",
        ]
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
