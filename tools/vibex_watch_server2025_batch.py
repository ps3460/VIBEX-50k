#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def csv_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(newline="", encoding="utf-8") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def send_telegram(title: str, body: str) -> dict[str, object]:
    proc = subprocess.run(
        ["ssh", "phil@10.64.0.62", "sudo /usr/local/bin/vibex_send_telegram_text.py"],
        input=f"{title}\n\n{body}",
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
    parser = argparse.ArgumentParser(description="Watch one Server 2025 sandbox batch for completion.")
    parser.add_argument("--campaign-dir", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--expected-rows", type=int, default=250)
    parser.add_argument("--poll-seconds", type=int, default=60)
    parser.add_argument("--telegram", action="store_true")
    args = parser.parse_args()

    campaign_dir = Path(args.campaign_dir)
    batch_csv = campaign_dir / "batches" / args.batch_id / "server2025_family_hints.csv"
    status_path = campaign_dir / f"{args.batch_id}_watch_status.json"
    notified = False
    while True:
        rows = csv_count(batch_csv)
        payload = {
            "updated_utc": utc_now(),
            "batch_id": args.batch_id,
            "batch_csv": str(batch_csv),
            "completed_rows": rows,
            "expected_rows": args.expected_rows,
            "complete": rows >= args.expected_rows,
        }
        if payload["complete"] and args.telegram and not notified:
            payload["telegram"] = send_telegram(
                "VIBEX Server 2025 Batch Complete",
                f"Batch: {args.batch_id}\nRows: {rows}/{args.expected_rows}\nUTC: {payload['updated_utc']}",
            )
            notified = True
        status_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if payload["complete"]:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
