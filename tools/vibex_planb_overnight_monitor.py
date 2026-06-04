#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


RUN_ID = "planb_overnight_20260604"
EXPAND_RUN_ID = "planb_overnight_20260604_native_17x500"
SWEEP_RUN_ID = "planb_overnight_20260604_odd_cnn_17x500"
ROOT = Path("/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb")
REPO = Path("/home/phil/GitHub/VIBEX-50k")
RUN_ROOT = ROOT / RUN_ID
EXPAND_ROOT = ROOT / EXPAND_RUN_ID
SWEEP_ROOT = ROOT / "model_sweeps" / SWEEP_RUN_ID
LOG = RUN_ROOT / "evidence" / "overnight_monitor.log"
STATUS_JSON = RUN_ROOT / "evidence" / "overnight_status.json"
TELEGRAM_SSH = ["ssh", "phil@10.64.0.62", "sudo /usr/local/bin/vibex_send_telegram_text.py"]
DASHBOARD_TMP = "/tmp/planb_overnight_status.json"
DASHBOARD_IMPORT = "/opt/mv2025-dashboard/imports/planb_overnight_status.json"


def utc_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    line = f"{utc_now()} {message}\n"
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(line)
    print(line, end="", flush=True)


def run_cmd(command: list[str], cwd: Path | None = None, input_text: str | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def process_alive(pid: int) -> bool:
    return os.path.exists(f"/proc/{pid}")


def read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


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


def count_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.rglob("*") if item.is_file())


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


def status_payload(stage: str, detail: str) -> dict[str, Any]:
    expand_report = read_json(EXPAND_ROOT / "evidence" / "planb_stagea_report.json")
    sweep_results = read_json(SWEEP_ROOT / "evidence" / "planb_overnight_cnn_results.json")
    leaderboard = SWEEP_ROOT / "evidence" / "planb_overnight_cnn_leaderboard.csv"
    best_binary = best_from_leaderboard(leaderboard, "binary")
    best_family = best_from_leaderboard(leaderboard, "malware_family")
    payload = {
        "updated_at": utc_now(),
        "stage": stage,
        "detail": detail,
        "dashboard_url": "https://malwarelab.i.steadnet.com/plan-b",
        "expand": {
            "run_id": EXPAND_RUN_ID,
            "report_path": str(EXPAND_ROOT / "evidence" / "planb_stagea_report.json"),
            "verified_malware_rows": expand_report.get("verified_malware_rows", 0),
            "native_png_rows": expand_report.get("native_png_rows", count_files(EXPAND_ROOT / "images")),
            "family_count": expand_report.get("family_count", 0),
            "families": expand_report.get("families", {}),
            "quarantine_executable_file_count": expand_report.get("quarantine_executable_file_count"),
        },
        "sweep": {
            "run_id": SWEEP_RUN_ID,
            "results_json": str(SWEEP_ROOT / "evidence" / "planb_overnight_cnn_results.json"),
            "completed": len([row for row in sweep_results.get("results", []) if row.get("status") == "completed"]),
            "failed": len([row for row in sweep_results.get("results", []) if row.get("status") == "failed"]),
            "best_binary": best_binary,
            "best_family": best_family,
        },
        "gpu": gpu_status(),
        "disk": disk_status(),
    }
    STATUS_JSON.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sync_dashboard_status()
    return payload


def sync_dashboard_status() -> None:
    if not STATUS_JSON.exists():
        return
    copy_result = run_cmd(["scp", str(STATUS_JSON), f"root@10.0.0.11:{DASHBOARD_TMP}"], timeout=30)
    if copy_result.returncode != 0:
        log(f"dashboard status scp failed rc={copy_result.returncode} {copy_result.stdout[-500:]}")
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
        log(f"dashboard status pct push failed rc={push_result.returncode} {push_result.stdout[-500:]}")


def send_telegram(title: str, body: str) -> None:
    message = f"{title}\n\n{body}"
    result = run_cmd(TELEGRAM_SSH, input_text=message, timeout=30)
    log(f"telegram title={title!r} rc={result.returncode}")
    if result.returncode != 0:
        log(result.stdout[-1000:])


def start_sweep() -> int:
    manifest = EXPAND_ROOT / "evidence" / "planb_stagea_native_png_manifest.csv"
    command = [
        "nohup",
        "python3",
        "tools/vibex_planb_overnight_cnn_sweep.py",
        "--image-manifest",
        str(manifest),
        "--run-id",
        SWEEP_RUN_ID,
        "--target-per-family",
        "500",
        "--image-size",
        "256",
        "--image-mode",
        "gray",
        "--tasks",
        "binary,malware_family,mixed_multiclass",
        "--architectures",
        "compact_cnn,residual_small,inception_small,separable_extreme,barcode_dilated,random_reservoir,patch_shuffle_cnn,blurpool_cnn,large_kernel_texture,squeeze_excite_cnn,multiscale_pyramid,fixed_edge_bank",
        "--seeds",
        "1337",
        "--epochs",
        "8",
        "--patience",
        "2",
    ]
    SWEEP_ROOT.mkdir(parents=True, exist_ok=True)
    log_path = SWEEP_ROOT / "overnight_cnn_sweep.log"
    with log_path.open("w", encoding="utf-8") as handle:
        proc = subprocess.Popen(command, cwd=str(REPO), stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
    (SWEEP_ROOT / "overnight_cnn_sweep.pid").write_text(f"{proc.pid}\n", encoding="utf-8")
    log(f"started sweep pid={proc.pid} log={log_path}")
    return proc.pid


def morning_body() -> str:
    payload = status_payload("morning_report", "06:30 summary generated from safe workhorse evidence.")
    expand = payload["expand"]
    sweep = payload["sweep"]
    best_binary = sweep.get("best_binary") or {}
    best_family = sweep.get("best_family") or {}
    binary_line = "No binary model has finished yet."
    if best_binary:
        binary_line = (
            f"Best malware-vs-benign model: {best_binary.get('architecture')} "
            f"with macro-F1 {float(best_binary.get('macro_f1_mean') or 0):.4f} "
            f"and accuracy {float(best_binary.get('accuracy_mean') or 0):.4f}."
        )
    family_line = "No malware-family model has finished yet."
    if best_family:
        family_line = (
            f"Best family model: {best_family.get('architecture')} "
            f"with macro-F1 {float(best_family.get('macro_f1_mean') or 0):.4f} "
            f"and accuracy {float(best_family.get('accuracy_mean') or 0):.4f}."
        )
    return "\n".join(
        [
            "Normal-English morning result:",
            f"Malware families: {expand.get('family_count') or 0}.",
            f"Verified malware samples: {expand.get('verified_malware_rows') or 0}.",
            f"Malware PNG rows: {expand.get('native_png_rows') or 0}.",
            f"Odd CNN runs completed: {sweep.get('completed') or 0}, failed: {sweep.get('failed') or 0}.",
            binary_line,
            family_line,
            f"Quarantine executable-file count: {expand.get('quarantine_executable_file_count')}.",
            f"GPU: {payload.get('gpu')}.",
            f"Disk: {payload.get('disk')}.",
            "Dashboard: https://malwarelab.i.steadnet.com/plan-b",
        ]
    )


def run(args: argparse.Namespace) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    log("overnight monitor started")
    morning_sent = False
    expand_pid = read_pid(EXPAND_ROOT / "evidence" / "overnight_expand.pid")
    sweep_pid: int | None = read_pid(SWEEP_ROOT / "overnight_cnn_sweep.pid")
    while True:
        now = datetime.now()
        if not morning_sent and now.hour == 6 and now.minute >= 30:
            send_telegram("VIBEX Plan B Morning Results", morning_body())
            morning_sent = True
        if expand_pid and process_alive(expand_pid):
            status_payload("expansion_running", f"Expansion PID {expand_pid} is still running.")
            time.sleep(args.poll_seconds)
            continue
        report = EXPAND_ROOT / "evidence" / "planb_stagea_report.json"
        if not report.exists():
            status_payload("expansion_waiting", "Expansion process ended but report is not present yet.")
            time.sleep(args.poll_seconds)
            continue
        if not sweep_pid:
            status_payload("sweep_starting", "Expansion complete; starting odd CNN sweep.")
            sweep_pid = start_sweep()
        if sweep_pid and process_alive(sweep_pid):
            status_payload("sweep_running", f"Odd CNN sweep PID {sweep_pid} is running.")
            time.sleep(args.poll_seconds)
            continue
        status_payload("sweep_complete", "Expansion and odd CNN sweep are complete.")
        if morning_sent or datetime.now() > datetime.now().replace(hour=6, minute=30, second=0, microsecond=0) + timedelta(hours=2):
            break
        time.sleep(args.poll_seconds)
    log("overnight monitor finished")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor Plan B overnight expansion/sweep and send morning Telegram.")
    parser.add_argument("--poll-seconds", type=int, default=300)
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
