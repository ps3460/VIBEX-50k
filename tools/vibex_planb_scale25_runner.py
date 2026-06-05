#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path("/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb")
REPO = Path("/home/phil/GitHub/VIBEX-50k")
RUN_ID = "planb_scale_20260605_25k"
EXPAND_RUN_ID = "planb_scale_20260605_25k_native"
FAMILY_SWEEP_RUN_ID = "planb_scale_20260605_25k_family_pi"
BINARY_SWEEP_RUN_ID = "planb_scale_20260605_25k_binary_pi"
RUN_ROOT = ROOT / RUN_ID
EVIDENCE = RUN_ROOT / "evidence"
LOG = EVIDENCE / "scale25_runner.log"
API_KEY_FILE = Path("/home/phil/vibex_secure_dataset/secrets/family-api-keys.env")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message: str) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    line = f"{utc_now()} {message}\n"
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(line)
    print(line, end="", flush=True)


def run_cmd(command: list[str], cwd: Path = REPO, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    log("$ " + " ".join(command))
    result = subprocess.run(
        command,
        cwd=str(cwd),
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


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_api_key_env() -> None:
    text = API_KEY_FILE.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() in {"MALWAREBAZAAR_API_KEY", "MB_API_KEY", "API_KEY"}:
            os.environ["MALWAREBAZAAR_API_KEY"] = value.strip().strip("\"'")
            return
    raise SystemExit("MalwareBazaar API key not found in secure workhorse env file")


def selected_families(census: dict[str, Any], preferred_count: int) -> list[str]:
    blocked = {
        "CobaltStrike",
        "DarkCloud",
        "GuLoader",
        "LummaStealer",
        "MassLogger",
        "a310Logger",
        "njrat",
    }
    rows = []
    for family in census.get("families", []):
        name = str(family.get("signature") or "").strip()
        selected = int(family.get("selected_samples") or 0)
        pe_like = int(family.get("pe_like_samples") or 0)
        if not name or selected <= 0:
            continue
        if name in blocked and selected < 500:
            continue
        rows.append((selected, pe_like, name))
    rows.sort(reverse=True)
    strong = [name for selected, _, name in rows if selected >= 500]
    if len(strong) >= preferred_count:
        return strong[:preferred_count]
    return [name for _, _, name in rows[:preferred_count]]


def start_and_wait(command: list[str], pid_path: Path, log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as handle:
        proc = subprocess.Popen(command, cwd=str(REPO), stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
    pid_path.write_text(f"{proc.pid}\n", encoding="utf-8")
    log(f"started pid={proc.pid} log={log_path}")
    return proc.wait()


def run_stage(source_report: Path, families: list[str], target_per_family: int, run_id: str) -> int:
    command = [
        sys.executable,
        "tools/vibex_planb_stagea_native_png.py",
        "--source-report",
        str(source_report),
        "--run-id",
        run_id,
        "--families",
        ",".join(families),
        "--target-per-family",
        str(target_per_family),
        "--metadata-limit",
        "1000",
        "--request-multiplier",
        "2.0",
        "--request-buffer",
        "150",
        "--image-sizes",
        "256,512",
        "--image-modes",
        "gray",
        "--resize-method",
        "bilinear",
        "--sleep-seconds",
        "0.15",
    ]
    return run_cmd(command, timeout=None).returncode


def run_sweep(run_id: str, tasks: str, architectures: str, target_per_family: int, seeds: str, epochs: int) -> int:
    manifest = ROOT / EXPAND_RUN_ID / "evidence" / "planb_stagea_native_png_manifest.csv"
    output_root = ROOT / "model_sweeps" / run_id
    command = [
        sys.executable,
        "tools/vibex_planb_overnight_cnn_sweep.py",
        "--image-manifest",
        str(manifest),
        "--run-id",
        run_id,
        "--target-per-family",
        str(target_per_family),
        "--image-size",
        "256",
        "--image-mode",
        "gray",
        "--tasks",
        tasks,
        "--architectures",
        architectures,
        "--seeds",
        seeds,
        "--epochs",
        str(epochs),
        "--patience",
        "3",
        "--export-tflite",
    ]
    return start_and_wait(command, output_root / "scale25_sweep.pid", output_root / "scale25_sweep.log")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Plan B 25k scale expansion and Pi-focused CNN sweeps.")
    parser.add_argument("--preferred-family-count", type=int, default=25)
    args = parser.parse_args()

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    load_api_key_env()
    log("scale25 runner started")
    census_path = EVIDENCE / "planb_scale25_census.json"
    census_cmd = [
        sys.executable,
        "tools/vibex_malwarebazaar_planb_census.py",
        "--max-signatures",
        "120",
        "--signature-limit",
        "1000",
        "--min-family-samples",
        "500",
        "--cap-per-family",
        "1000",
        "--target-rows",
        "25000",
        "--sleep-seconds",
        "0.05",
        "--output",
        str(census_path),
    ]
    if run_cmd(census_cmd, timeout=None).returncode != 0:
        return 2

    census = read_json(census_path)
    families = selected_families(census, args.preferred_family_count)
    selection = {
        "created_at": utc_now(),
        "preferred_family_count": args.preferred_family_count,
        "families": families,
        "census_path": str(census_path),
        "selection_policy": "top non-generic PE-like MalwareBazaar signatures; previous zero-yield families require >=500 selected samples",
    }
    write_json(EVIDENCE / "planb_scale25_selected_families.json", selection)
    if not families:
        log("no families selected")
        return 3
    log(f"selected families: {', '.join(families)}")

    if run_stage(census_path, families, 500, EXPAND_RUN_ID) != 0:
        return 4

    family_architectures = ",".join(
        [
            "separable_lite",
            "mobilenet_tiny",
            "pi_depthwise_quant_candidate",
            "separable_extreme",
            "squeeze_excite_cnn",
            "inception_small",
            "residual_small",
            "compact_cnn",
            "blurpool_cnn",
        ]
    )
    if run_sweep(FAMILY_SWEEP_RUN_ID, "malware_family", family_architectures, 500, "1337", 12) != 0:
        log("family sweep returned nonzero; continuing to binary sanity check")

    binary_architectures = "separable_lite,mobilenet_tiny,pi_depthwise_quant_candidate,compact_cnn"
    if run_sweep(BINARY_SWEEP_RUN_ID, "binary", binary_architectures, 500, "1337", 8) != 0:
        log("binary sweep returned nonzero; continuing scale-up")

    run_stage(census_path, families, 1000, EXPAND_RUN_ID)
    log("scale25 runner finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
