#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path("/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb")
REPO = Path("/home/phil/GitHub/VIBEX-50k")
RUN_ID = "planb_scale_20260605_25k"
EXPAND_RUN_ID = "planb_scale_20260605_25k_native"
FAMILY_SWEEP_RUN_ID = "planb_scale_20260605_25k_family_pi"
BINARY_SWEEP_RUN_ID = "planb_scale_20260605_25k_binary_pi"
RUN_ROOT = ROOT / RUN_ID
EXPAND_ROOT = ROOT / EXPAND_RUN_ID
FAMILY_SWEEP_ROOT = ROOT / "model_sweeps" / FAMILY_SWEEP_RUN_ID
BINARY_SWEEP_ROOT = ROOT / "model_sweeps" / BINARY_SWEEP_RUN_ID
STATUS_JSON = RUN_ROOT / "evidence" / "scale25_status.json"
LOG = RUN_ROOT / "evidence" / "scale25_monitor.log"
TELEGRAM_SSH = ["ssh", "phil@10.64.0.62", "sudo /usr/local/bin/vibex_send_telegram_text.py"]
DASHBOARD_TMP = "/tmp/planb_scale25_status.json"
DASHBOARD_IMPORT = "/opt/mv2025-dashboard/imports/planb_overnight_status.json"


def utc_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    line = f"{utc_now()} {message}\n"
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(line)
    print(line, end="", flush=True)


def run_cmd(command: list[str], input_text: str | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def read_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except Exception:
        return []


def process_alive(pid: int | None) -> bool:
    return bool(pid and os.path.exists(f"/proc/{pid}"))


def read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def file_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.rglob("*") if item.is_file())


def executable_count(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and item.stat().st_mode & 0o111:
                count += 1
        except OSError:
            continue
    return count


def gpu_status() -> str:
    result = run_cmd(
        [
            "nvidia-smi",
            "--query-gpu=temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw",
            "--format=csv,noheader,nounits",
        ],
        timeout=8,
    )
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def disk_status() -> str:
    result = run_cmd(["df", "-h", "/home"], timeout=8)
    return " | ".join(result.stdout.strip().splitlines()[-1:]) if result.returncode == 0 else "unavailable"


def best_from_leaderboard(path: Path, task: str | None = None) -> dict[str, str] | None:
    rows = read_csv(path)
    if task:
        rows = [row for row in rows if row.get("task") == task]
    if not rows:
        return None
    return max(rows, key=lambda row: (float(row.get("macro_f1_mean") or 0), float(row.get("accuracy_mean") or 0)))


def sweep_status(root: Path, task: str | None = None) -> dict[str, Any]:
    results = read_json(root / "evidence" / "planb_overnight_cnn_results.json")
    leaderboard = root / "evidence" / "planb_overnight_cnn_leaderboard.csv"
    rows = results.get("results", [])
    return {
        "run_id": root.name,
        "results_json": str(root / "evidence" / "planb_overnight_cnn_results.json"),
        "completed": len([row for row in rows if row.get("status") == "completed"]),
        "failed": len([row for row in rows if row.get("status") == "failed"]),
        "best": best_from_leaderboard(leaderboard, task),
        "pid": read_pid(root / "scale25_sweep.pid"),
        "active": process_alive(read_pid(root / "scale25_sweep.pid")),
    }


def status_payload(stage: str, detail: str) -> dict[str, Any]:
    report = read_json(EXPAND_ROOT / "evidence" / "planb_stagea_report.json")
    family_counts = report.get("families", {})
    usable = {family: count for family, count in family_counts.items() if int(count or 0) > 0}
    payload = {
        "updated_at": utc_now(),
        "stage": stage,
        "detail": detail,
        "dashboard_url": "https://malwarelab.i.steadnet.com/plan-b",
        "target": {
            "malware_png_rows": 25000,
            "benign_png_rows": 25000,
            "preferred_family_count": 25,
            "preferred_rows_per_family": 1000,
        },
        "expand": {
            "run_id": EXPAND_RUN_ID,
            "report_path": str(EXPAND_ROOT / "evidence" / "planb_stagea_report.json"),
            "verified_malware_rows": report.get("verified_malware_rows", 0),
            "native_png_rows": report.get("native_png_rows", file_count(EXPAND_ROOT / "images")),
            "family_count": report.get("family_count", 0),
            "usable_family_count": len(usable),
            "families": family_counts,
            "quarantine_executable_file_count": report.get(
                "quarantine_executable_file_count",
                executable_count(EXPAND_ROOT / "quarantine"),
            ),
        },
        "sweep": {
            "family": sweep_status(FAMILY_SWEEP_ROOT, "malware_family"),
            "binary": sweep_status(BINARY_SWEEP_ROOT, "binary"),
        },
        "gpu": gpu_status(),
        "disk": disk_status(),
    }
    STATUS_JSON.parent.mkdir(parents=True, exist_ok=True)
    STATUS_JSON.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sync_dashboard_status()
    return payload


def sync_dashboard_status() -> None:
    if not STATUS_JSON.exists():
        return
    copy_result = run_cmd(["scp", str(STATUS_JSON), f"root@10.0.0.11:{DASHBOARD_TMP}"], timeout=30)
    if copy_result.returncode != 0:
        log(f"dashboard scp failed rc={copy_result.returncode} {copy_result.stdout[-500:]}")
        return
    push_result = run_cmd(
        [
            "ssh",
            "root@10.0.0.11",
            (
                f"pct push 102 {DASHBOARD_TMP} {DASHBOARD_IMPORT} && "
                f"pct exec 102 -- chown malwaredash:malwaredash {DASHBOARD_IMPORT}"
            ),
        ],
        timeout=30,
    )
    if push_result.returncode != 0:
        log(f"dashboard pct push failed rc={push_result.returncode} {push_result.stdout[-500:]}")


def telegram_body() -> str:
    payload = status_payload("1400_report", "14:00 report generated from safe Plan B scale evidence.")
    expand = payload["expand"]
    family_best = (payload["sweep"]["family"] or {}).get("best") or {}
    binary_best = (payload["sweep"]["binary"] or {}).get("best") or {}
    family_line = "No malware-family model has finished yet."
    if family_best:
        family_line = (
            f"Best malware-family model: {family_best.get('architecture')} "
            f"macro-F1 {float(family_best.get('macro_f1_mean') or 0):.4f}, "
            f"accuracy {float(family_best.get('accuracy_mean') or 0):.4f}."
        )
    binary_line = "No binary model has finished yet."
    if binary_best:
        binary_line = (
            f"Best malware-vs-benign model: {binary_best.get('architecture')} "
            f"macro-F1 {float(binary_best.get('macro_f1_mean') or 0):.4f}, "
            f"accuracy {float(binary_best.get('accuracy_mean') or 0):.4f}."
        )
    return "\n".join(
        [
            "Plan B 25k/25k status in normal English:",
            f"Verified malware samples: {expand.get('verified_malware_rows') or 0}.",
            f"Malware PNG rows: {expand.get('native_png_rows') or 0}.",
            f"Usable malware families: {expand.get('usable_family_count') or 0}.",
            "Benign target: 25,000 matched PNG rows from the existing safe benign manifest.",
            family_line,
            binary_line,
            f"Quarantine executable-file count: {expand.get('quarantine_executable_file_count')}.",
            f"GPU: {payload.get('gpu')}.",
            f"Disk: {payload.get('disk')}.",
            "Dashboard: https://malwarelab.i.steadnet.com/plan-b",
        ]
    )


def send_telegram(title: str, body: str) -> None:
    result = run_cmd(TELEGRAM_SSH, input_text=f"{title}\n\n{body}", timeout=30)
    log(f"telegram title={title!r} rc={result.returncode}")
    if result.returncode != 0:
        log(result.stdout[-1000:])


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor Plan B 25k scale run and publish safe dashboard status.")
    parser.add_argument("--poll-seconds", type=int, default=300)
    parser.add_argument("--send-1400", action="store_true")
    args = parser.parse_args()
    log("scale25 monitor started")
    sent = False
    while True:
        now = datetime.now()
        status_payload("running", "25k/25k scale run is being monitored from safe evidence.")
        if args.send_1400 and not sent and (now.hour > 14 or (now.hour == 14 and now.minute >= 0)):
            send_telegram("VIBEX Plan B 14:00 Scale Report", telegram_body())
            sent = True
        family_active = process_alive(read_pid(FAMILY_SWEEP_ROOT / "scale25_sweep.pid"))
        binary_active = process_alive(read_pid(BINARY_SWEEP_ROOT / "scale25_sweep.pid"))
        if sent and not family_active and not binary_active:
            status_payload("complete_or_waiting", "14:00 report sent; no active scale sweep process detected.")
            log("scale25 monitor finished")
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
