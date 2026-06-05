#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path("/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb")
REPO = Path("/home/phil/GitHub/VIBEX-50k")
RUN_ID = "planb_scale_20260605_25k"
EXPAND_RUN_ID = "planb_scale_20260605_25k_native"
RUN_ROOT = ROOT / RUN_ID
EVIDENCE = RUN_ROOT / "evidence"
LOG = EVIDENCE / "weekly_mb_harvest.log"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message: str) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    line = f"{utc_now()} {message}\n"
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(line)
    print(line, end="", flush=True)


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def run_cmd(command: list[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    log("$ " + " ".join(command))
    result = subprocess.run(
        command,
        cwd=str(REPO),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(result.stdout)
        if result.stdout and not result.stdout.endswith("\n"):
            handle.write("\n")
    log(f"rc={result.returncode}")
    return result


def selected_families() -> list[str]:
    selected = read_json(EVIDENCE / "planb_scale25_selected_families.json")
    families = [str(item).strip() for item in selected.get("families", []) if str(item).strip()]
    if families:
        return families
    census = read_json(EVIDENCE / "planb_scale25_census.json")
    rows = []
    for family in census.get("families", []):
        name = str(family.get("signature") or "").strip()
        selected_samples = int(family.get("selected_samples") or 0)
        if name and selected_samples:
            rows.append((selected_samples, name))
    return [name for _, name in sorted(rows, reverse=True)[:25]]


def current_verified() -> int:
    report = read_json(ROOT / EXPAND_RUN_ID / "evidence" / "planb_stagea_report.json")
    return int(report.get("verified_malware_rows") or 0)


def sleep_until_next_window(hours: float) -> None:
    wake = datetime.now(timezone.utc) + timedelta(hours=hours)
    log(f"sleeping_until={wake.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    while datetime.now(timezone.utc) < wake:
        time.sleep(min(300, max(1, (wake - datetime.now(timezone.utc)).total_seconds())))


def run_harvest(args: argparse.Namespace, families: list[str]) -> int:
    census = EVIDENCE / "planb_scale25_census.json"
    command = [
        sys.executable,
        "tools/vibex_planb_stagea_native_png.py",
        "--source-report",
        str(census),
        "--run-id",
        EXPAND_RUN_ID,
        "--families",
        ",".join(families),
        "--target-per-family",
        str(args.target_per_family),
        "--metadata-limit",
        "1000",
        "--request-multiplier",
        "2.0",
        "--request-buffer",
        "150",
        "--max-download-attempts",
        str(args.daily_download_attempts),
        "--image-sizes",
        "256,512",
        "--image-modes",
        "gray",
        "--resize-method",
        "bilinear",
        "--sleep-seconds",
        str(args.sleep_seconds),
    ]
    return run_cmd(command).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Quota-paced MalwareBazaar weekly Plan B harvester.")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--daily-download-attempts", type=int, default=1800)
    parser.add_argument("--target-per-family", type=int, default=1000)
    parser.add_argument("--sleep-hours", type=float, default=24.2)
    parser.add_argument("--sleep-seconds", type=float, default=0.25)
    args = parser.parse_args()

    families = selected_families()
    if not families:
        raise SystemExit("No selected families available for weekly harvest")
    log(
        "weekly harvest started "
        f"days={args.days} daily_download_attempts={args.daily_download_attempts} "
        f"families={','.join(families)}"
    )
    for day in range(1, args.days + 1):
        before = current_verified()
        log(f"day={day} starting verified_before={before}")
        rc = run_harvest(args, families)
        after = current_verified()
        log(f"day={day} finished rc={rc} verified_after={after} gained={after - before}")
        if after >= len(families) * args.target_per_family:
            log("target_per_family reached for selected family count")
            return 0
        if day < args.days:
            sleep_until_next_window(args.sleep_hours)
    log("weekly harvest finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
