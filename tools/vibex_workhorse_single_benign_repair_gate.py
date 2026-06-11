#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
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


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def is_quiet(args: argparse.Namespace) -> bool:
    hour = datetime.now(ZoneInfo(args.telegram_timezone)).hour
    return hour >= args.quiet_start or hour < args.quiet_end


def send_telegram(args: argparse.Namespace, run_dir: Path, lines: list[str]) -> None:
    if not args.telegram:
        return
    text = "\n".join(lines)
    queue = run_dir / "telegram_quiet_queue.jsonl"
    if is_quiet(args):
        queue.parent.mkdir(parents=True, exist_ok=True)
        with queue.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"queued_utc": utc_now(), "text": text}) + "\n")
        return
    subprocess.run(TELEGRAM_CMD, input=text, text=True, check=False)


def manifest_size_mode(manifest: Path) -> tuple[str, str]:
    rows = read_csv(manifest)
    if not rows:
        raise ValueError(f"empty manifest: {manifest}")
    return str(rows[0].get("image_size") or ""), str(rows[0].get("image_mode") or "gray")


def load_best(leaderboard: Path) -> dict[str, Any] | None:
    if not leaderboard.exists():
        return None
    rows = read_csv(leaderboard)
    if not rows:
        return None
    return rows[0]


def run_candidate(args: argparse.Namespace, run_dir: Path, rep: str, arch: str, index: int, total: int) -> dict[str, Any]:
    manifest = Path(args.repair_dir) / "manifests" / f"malware_plus_single_benign_{rep}.csv"
    image_size, image_mode = manifest_size_mode(manifest)
    candidate_id = f"{index:04d}_{rep}_{arch}"
    native_run_id = f"{args.run_id}_{candidate_id}"
    started = time.time()
    command = [
        args.python,
        args.native_runner,
        "--image-manifest",
        str(manifest),
        "--output-root",
        str(run_dir / "native_runs"),
        "--run-id",
        native_run_id,
        "--target-per-family",
        "0",
        "--image-sizes",
        image_size,
        "--image-modes",
        image_mode,
        "--architectures",
        arch,
        "--seeds",
        args.seeds,
        "--epochs",
        str(args.epochs),
        "--patience",
        str(args.patience),
        "--split-ratios",
        args.split_ratios,
        "--learning-rate",
        str(args.learning_rate),
        "--dropout",
        str(args.dropout),
        "--label-smoothing",
        str(args.label_smoothing),
    ]
    if args.mixed_precision:
        command.append("--mixed-precision")

    log_path = run_dir / "logs" / f"{candidate_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, text=True)
    elapsed = time.time() - started
    evidence_dir = run_dir / "native_runs" / native_run_id / "evidence"
    best = load_best(evidence_dir / "planb_native_family_leaderboard.csv")
    row: dict[str, Any] = {
        "candidate_id": candidate_id,
        "completed_utc": utc_now(),
        "representation": rep,
        "architecture": arch,
        "image_size": image_size,
        "image_mode": image_mode,
        "status": "completed" if proc.returncode == 0 and best else "failed",
        "returncode": proc.returncode,
        "elapsed_seconds": round(elapsed, 3),
        "native_run_id": native_run_id,
        "evidence_dir": str(evidence_dir),
        "log_path": str(log_path),
    }
    if best:
        for key in [
            "accuracy_mean",
            "macro_f1_mean",
            "weighted_f1_mean",
            "macro_f1_std",
            "completed_seeds",
            "nonzero_family_f1_mean",
        ]:
            row[key] = best.get(key, "")
    return row


def numeric(row: dict[str, Any], key: str) -> float:
    try:
        return float(row.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def best_row(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    completed = [row for row in rows if row.get("status") == "completed"]
    if not completed:
        return None
    return sorted(completed, key=lambda row: (numeric(row, "macro_f1_mean"), numeric(row, "accuracy_mean")), reverse=True)[0]


def status_payload(args: argparse.Namespace, run_dir: Path, rows: list[dict[str, Any]], current: dict[str, Any] | None = None) -> dict[str, Any]:
    best = best_row(rows)
    total = len(args.representations) * len(args.architectures)
    return {
        "run_id": args.run_id,
        "updated_utc": utc_now(),
        "repair_dir": str(args.repair_dir),
        "run_dir": str(run_dir),
        "total_candidates": total,
        "completed_candidates": len([row for row in rows if row.get("status") == "completed"]),
        "failed_candidates": len([row for row in rows if row.get("status") == "failed"]),
        "current": current,
        "best": best,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a controlled single-benign repaired manifest model gate on workhorse.")
    parser.add_argument("--repair-dir", required=True)
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/evidence/single_benign_repair_gate")
    parser.add_argument("--run-id", default=f"single_benign_repair_gate_{utc_stamp()}")
    parser.add_argument("--native-runner", default="/home/phil/vibex_secure_dataset/tools/vibex_planb_native_family_experiment.py")
    parser.add_argument("--python", default="python3")
    parser.add_argument("--representations", default="section_table_layout_64,prefix4096_64,pe_header_layout_128,prefix12288_128_padded")
    parser.add_argument("--architectures", default="convnext_tiny_scratch,residual_small,inception_small")
    parser.add_argument("--seeds", default="1337,2026,4242")
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--split-ratios", default="0.8,0.1,0.1")
    parser.add_argument("--learning-rate", type=float, default=3e-4)
    parser.add_argument("--dropout", type=float, default=0.3)
    parser.add_argument("--label-smoothing", type=float, default=0.02)
    parser.add_argument("--mixed-precision", action="store_true")
    parser.add_argument("--telegram", action="store_true")
    parser.add_argument("--telegram-timezone", default="Europe/London")
    parser.add_argument("--quiet-start", type=int, default=22)
    parser.add_argument("--quiet-end", type=int, default=6)
    args = parser.parse_args()
    args.repair_dir = Path(args.repair_dir)
    args.output_root = Path(args.output_root)
    args.representations = [item.strip() for item in args.representations.split(",") if item.strip()]
    args.architectures = [item.strip() for item in args.architectures.split(",") if item.strip()]
    return args


def main() -> None:
    args = parse_args()
    run_dir = args.output_root / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    write_json(run_dir / "single_benign_gate_status.json", status_payload(args, run_dir, rows))
    total = len(args.representations) * len(args.architectures)
    send_telegram(
        args,
        run_dir,
        [
            "VIBEX model repair update",
            "",
            "Starting the repaired single-benign model gate.",
            f"Candidates: {total}.",
            f"Representations: {', '.join(args.representations)}.",
            f"Models: {', '.join(args.architectures)}.",
            "Next update: first candidate completion.",
        ],
    )

    previous_best = None
    index = 0
    for rep in args.representations:
        for arch in args.architectures:
            index += 1
            current = {"candidate_index": index, "total_candidates": total, "representation": rep, "architecture": arch}
            write_json(run_dir / "single_benign_gate_status.json", status_payload(args, run_dir, rows, current=current))
            row = run_candidate(args, run_dir, rep, arch, index, total)
            rows.append(row)
            write_csv(run_dir / "single_benign_gate_results.csv", rows)
            write_json(run_dir / "single_benign_gate_status.json", status_payload(args, run_dir, rows))
            current_best = best_row(rows)
            is_new_best = (
                current_best
                and current_best.get("candidate_id") == row.get("candidate_id")
                and (not previous_best or numeric(current_best, "macro_f1_mean") > numeric(previous_best, "macro_f1_mean"))
            )
            if index == 1 or row.get("status") == "failed" or is_new_best:
                best = current_best or {}
                send_telegram(
                    args,
                    run_dir,
                    [
                        "VIBEX model repair update",
                        "",
                        f"Completed candidate {index} of {total}.",
                        f"Current: {rep} / {arch}.",
                        f"Status: {row.get('status')}.",
                        f"Macro-F1: {row.get('macro_f1_mean', 'n/a')}.",
                        f"Accuracy: {row.get('accuracy_mean', 'n/a')}.",
                        "",
                        f"Best so far: {best.get('representation', 'n/a')} / {best.get('architecture', 'n/a')}.",
                        f"Best macro-F1: {best.get('macro_f1_mean', 'n/a')}.",
                        f"Best accuracy: {best.get('accuracy_mean', 'n/a')}.",
                    ],
                )
            previous_best = current_best or previous_best
    best = best_row(rows) or {}
    send_telegram(
        args,
        run_dir,
        [
            "VIBEX model repair update",
            "",
            "Repaired single-benign model gate completed.",
            f"Completed: {len([row for row in rows if row.get('status') == 'completed'])} of {total}.",
            f"Failed: {len([row for row in rows if row.get('status') == 'failed'])}.",
            f"Best model: {best.get('representation', 'n/a')} / {best.get('architecture', 'n/a')}.",
            f"Best macro-F1: {best.get('macro_f1_mean', 'n/a')}.",
            f"Best accuracy: {best.get('accuracy_mean', 'n/a')}.",
        ],
    )


if __name__ == "__main__":
    main()
