#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shlex
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from PIL import Image


DEFAULT_ARCHITECTURES = [
    "compact_cnn",
    "dense_small",
    "separable_cnn",
    "squeeze_cnn",
    "residual_small",
    "wide_residual_small",
    "inception_small",
    "dual_kernel_cnn",
    "attention_pool_cnn",
    "convnext_tiny_scratch",
]


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_strings(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_ints(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def resolve_raw_path(row: dict[str, str], raw_root: Path) -> Path:
    source = row.get("source", "").strip()
    original = row.get("original_family_field", "").strip()
    if not source or not original.startswith("VirusShare_"):
        raise ValueError(f"Cannot resolve raw path for {row.get('raw_sha256', '')}")
    return raw_root / source / original


def write_gray_png(path: Path, data: bytes, image_size: int) -> str:
    needed = image_size * image_size
    payload = data[:needed].ljust(needed, b"\x00")
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.frombytes("L", (image_size, image_size), payload)
    image.save(path, format="PNG", optimize=True)
    return sha256_bytes(path.read_bytes())


def build_split_manifests(args: argparse.Namespace, run_dir: Path) -> dict[str, Any]:
    rows = read_csv(Path(args.family_core))
    raw_root = Path(args.raw_root)
    image_root = run_dir / "derived_pngs"
    manifest_root = run_dir / "manifests"
    views = {
        "prefix1024": {
            "image_size": args.prefix_image_size,
            "offset": 0,
            "length": args.prefix_bytes,
            "description": "first_1024_bytes_32x32_gray_pad_00",
        },
        "body_after1024": {
            "image_size": args.body_image_size,
            "offset": args.prefix_bytes,
            "length": args.body_bytes,
            "description": "bytes_after_1024_first_65536_bytes_256x256_gray_pad_00",
        },
    }
    manifests: dict[str, Any] = {}
    build_audit: list[dict[str, Any]] = []
    for view_name, view in views.items():
        native_rows: list[dict[str, Any]] = []
        missing = 0
        short_body = 0
        for row in rows:
            sha = row.get("raw_sha256", "").strip().lower()
            family = row.get("consensus_family", "").strip().lower()
            if len(sha) != 64 or not family:
                continue
            raw_path = resolve_raw_path(row, raw_root)
            if not raw_path.exists():
                missing += 1
                build_audit.append({"view": view_name, "raw_sha256": sha, "status": "missing_raw"})
                continue
            raw = raw_path.read_bytes()
            offset = int(view["offset"])
            length = int(view["length"])
            segment = raw[offset : offset + length] if len(raw) > offset else b""
            if view_name == "body_after1024" and len(segment) < length:
                short_body += 1
            image_path = image_root / view_name / family / f"{sha}.png"
            image_sha = write_gray_png(image_path, segment, int(view["image_size"]))
            item = dict(row)
            item.update(
                {
                    "family": family,
                    "sha256_hash": sha,
                    "image_path": str(image_path),
                    "image_size": str(view["image_size"]),
                    "image_mode": "gray",
                    "split_view": view_name,
                    "split_offset": str(offset),
                    "split_length": str(length),
                    "split_bytes_available": str(len(segment)),
                    "split_image_sha256": image_sha,
                }
            )
            native_rows.append(item)
        manifest_path = manifest_root / f"{view_name}_native_manifest.csv"
        write_csv(manifest_path, native_rows)
        counts = dict(sorted(Counter(row["family"] for row in native_rows).items()))
        manifests[view_name] = {
            "manifest_path": str(manifest_path),
            "rows": len(native_rows),
            "missing_raw": missing,
            "short_body_rows": short_body,
            "image_size": view["image_size"],
            "image_mode": "gray",
            "description": view["description"],
            "class_counts": counts,
            "family_count": len(counts),
        }
    write_csv(manifest_root / "split_png_build_audit.csv", build_audit)
    write_json(manifest_root / "split_manifest_summary.json", manifests)
    return manifests


def run_command(cmd: list[str], log_path: Path) -> subprocess.CompletedProcess[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"$ {shlex.join(cmd)}\n")
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(proc.stdout or "")
        handle.write(f"\n[exit {proc.returncode}]\n")
    return proc


def send_telegram(args: argparse.Namespace, title: str, lines: list[str]) -> None:
    if not args.telegram:
        return
    body = title + "\n" + "\n".join(lines)
    subprocess.run(
        ["ssh", "phil@10.64.0.62", "sudo", "/usr/local/bin/vibex_send_telegram_text.py"],
        input=body,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


def best_from_result(evidence_dir: Path) -> dict[str, Any]:
    path = evidence_dir / "planb_native_family_results.json"
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    completed = [row for row in payload.get("results", []) if row.get("status") == "completed"]
    aggregates = payload.get("aggregates") or []
    if not completed:
        return {}
    best_seed = max(
        completed,
        key=lambda row: (row.get("macro_f1") or 0.0, row.get("weighted_f1") or 0.0, row.get("accuracy") or 0.0),
    )
    per_class = best_seed.get("per_class_f1") or {}
    weakest = sorted(per_class.items(), key=lambda item: item[1])[:5]
    return {"best_seed": best_seed, "best_group": aggregates[0] if aggregates else {}, "weakest": weakest}


def write_summary(run_dir: Path, metadata: dict[str, Any], group_results: list[dict[str, Any]]) -> None:
    write_json(run_dir / "overall_results.json", {"metadata": metadata, "groups": group_results})
    rows = []
    for group in group_results:
        best = group.get("best", {}).get("best_group", {})
        rows.append(
            {
                "view": group.get("view"),
                "architecture": group.get("architecture"),
                "status": group.get("status"),
                "macro_f1_mean": best.get("macro_f1_mean"),
                "weighted_f1_mean": best.get("weighted_f1_mean"),
                "accuracy_mean": best.get("accuracy_mean"),
                "completed_seeds": best.get("completed_seeds"),
                "elapsed_seconds": group.get("elapsed_seconds"),
                "log_path": group.get("log_path"),
            }
        )
    write_csv(run_dir / "overall_leaderboard.csv", rows)
    completed = [row for row in rows if row.get("status") == "completed" and row.get("macro_f1_mean") not in (None, "")]
    best_by_view: dict[str, dict[str, Any]] = {}
    for row in completed:
        view = str(row["view"])
        if view not in best_by_view or float(row["macro_f1_mean"]) > float(best_by_view[view]["macro_f1_mean"]):
            best_by_view[view] = row
    best_overall = max(completed, key=lambda row: float(row["macro_f1_mean"])) if completed else {}
    lines = [
        "# VIBEX Prefix/Body Malware Family Model Experiment",
        "",
        f"- Run ID: `{metadata['run_id']}`",
        f"- Created UTC: `{metadata['created_utc']}`",
        f"- Views: `{', '.join(metadata['views'])}`",
        f"- Models per view: `{len(metadata['architectures'])}`",
        f"- Seeds: `{', '.join(str(seed) for seed in metadata['seeds'])}`",
        f"- Raw malware and derived PNGs remain on workhorse only.",
        "",
        "## Best By View",
        "",
    ]
    for view in metadata["views"]:
        row = best_by_view.get(view)
        if row:
            lines.append(
                f"- `{view}`: `{row['architecture']}` macro-F1 `{float(row['macro_f1_mean']):.4f}`, "
                f"weighted-F1 `{float(row['weighted_f1_mean']):.4f}`, accuracy `{float(row['accuracy_mean']):.4f}`"
            )
        else:
            lines.append(f"- `{view}`: not complete")
    if best_overall:
        lines.extend(
            [
                "",
                "## Best Overall",
                "",
                f"- View: `{best_overall['view']}`",
                f"- Architecture: `{best_overall['architecture']}`",
                f"- Macro-F1: `{float(best_overall['macro_f1_mean']):.4f}`",
                f"- Weighted-F1: `{float(best_overall['weighted_f1_mean']):.4f}`",
                f"- Accuracy: `{float(best_overall['accuracy_mean']):.4f}`",
            ]
        )
    lines.extend(
        [
            "",
            "## Leaderboard",
            "",
            "| View | Architecture | Status | Seeds | Macro-F1 | Weighted-F1 | Accuracy |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in sorted(completed, key=lambda item: float(item["macro_f1_mean"]), reverse=True):
        lines.append(
            f"| {row['view']} | {row['architecture']} | {row['status']} | {row.get('completed_seeds') or ''} | "
            f"{float(row['macro_f1_mean']):.4f} | {float(row['weighted_f1_mean']):.4f} | {float(row['accuracy_mean']):.4f} |"
        )
    (run_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def telegram_progress(args: argparse.Namespace, metadata: dict[str, Any], group_results: list[dict[str, Any]], current: dict[str, Any]) -> None:
    completed = sum(1 for row in group_results if row.get("status") == "completed")
    total = len(metadata["views"]) * len(metadata["architectures"])
    safe_rows = [row for row in group_results if row.get("status") == "completed"]
    best = None
    for row in safe_rows:
        best_group = row.get("best", {}).get("best_group", {})
        if not best_group:
            continue
        if best is None or float(best_group.get("macro_f1_mean") or 0.0) > float(best.get("best", {}).get("best_group", {}).get("macro_f1_mean") or 0.0):
            best = row
    lines = [
        f"Run: {metadata['run_id']}",
        f"Completed models: {completed} of {total}",
        f"Latest: {current['view']} / {current['architecture']} = {current['status']}",
    ]
    latest_best = current.get("best", {}).get("best_group", {})
    if latest_best:
        lines.extend(
            [
                f"Latest macro-F1: {float(latest_best.get('macro_f1_mean') or 0.0):.4f}",
                f"Latest weighted-F1: {float(latest_best.get('weighted_f1_mean') or 0.0):.4f}",
                f"Latest accuracy: {float(latest_best.get('accuracy_mean') or 0.0):.4f}",
            ]
        )
    if best:
        best_group = best["best"]["best_group"]
        weakest = ", ".join(f"{label}={value:.3f}" for label, value in best.get("best", {}).get("weakest", [])[:5])
        lines.extend(
            [
                f"Best so far: {best['view']} / {best['architecture']}",
                f"Best macro-F1: {float(best_group.get('macro_f1_mean') or 0.0):.4f}",
                f"Best weighted-F1: {float(best_group.get('weighted_f1_mean') or 0.0):.4f}",
                f"Best accuracy: {float(best_group.get('accuracy_mean') or 0.0):.4f}",
                f"Weakest classes: {weakest or 'not available'}",
            ]
        )
    lines.append(f"Elapsed: {round((time.time() - metadata['started_epoch']) / 60, 1)} minutes")
    send_telegram(args, "VIBEX model test update", lines)


def run(args: argparse.Namespace) -> int:
    run_id = args.run_id or f"vibex_prefix_body_family_{utc_stamp()}"
    run_dir = Path(args.output_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    manifests = build_split_manifests(args, run_dir)
    metadata = {
        "run_id": run_id,
        "created_utc": utc_now(),
        "started_epoch": time.time(),
        "views": ["prefix1024", "body_after1024"],
        "architectures": args.architectures,
        "seeds": args.seeds,
        "epochs": args.epochs,
        "patience": args.patience,
        "target_per_class": args.target_per_class,
        "manifests": manifests,
        "raw_artifacts_in_git": False,
    }
    write_json(run_dir / "run_metadata.json", metadata)
    send_telegram(
        args,
        "VIBEX model test update",
        [
            f"Run: {run_id}",
            "Phase: prefix1024 versus body_after1024 malware-family CNN test",
            f"Total model groups: {len(metadata['views']) * len(args.architectures)}",
            f"Seeds per group: {', '.join(str(seed) for seed in args.seeds)}",
            "Raw malware and derived PNGs stay on workhorse.",
        ],
    )
    group_results: list[dict[str, Any]] = []
    for view in metadata["views"]:
        manifest = manifests[view]
        for architecture in args.architectures:
            start = time.time()
            output_root = run_dir / "model_sweeps" / view
            group_run_id = f"{run_id}_{view}_{architecture}"
            log_path = run_dir / "logs" / f"{view}_{architecture}.log"
            cmd = [
                "python3",
                str(Path(args.native_runner)),
                "--image-manifest",
                manifest["manifest_path"],
                "--output-root",
                str(output_root),
                "--run-id",
                group_run_id,
                "--architectures",
                architecture,
                "--image-sizes",
                str(manifest["image_size"]),
                "--image-modes",
                "gray",
                "--seeds",
                ",".join(str(seed) for seed in args.seeds),
                "--epochs",
                str(args.epochs),
                "--patience",
                str(args.patience),
                "--target-per-family",
                str(args.target_per_class),
            ]
            proc = run_command(cmd, log_path)
            evidence_dir = output_root / group_run_id / "evidence"
            status = "completed" if proc.returncode == 0 else "failed"
            result = {
                "view": view,
                "architecture": architecture,
                "status": status,
                "returncode": proc.returncode,
                "elapsed_seconds": round(time.time() - start, 3),
                "log_path": str(log_path),
                "evidence_dir": str(evidence_dir),
                "best": best_from_result(evidence_dir),
            }
            group_results.append(result)
            write_summary(run_dir, metadata, group_results)
            telegram_progress(args, metadata, group_results, result)
    write_summary(run_dir, metadata, group_results)
    send_telegram(
        args,
        "VIBEX model test update",
        [
            f"Run: {run_id}",
            "Phase: final summary",
            (run_dir / "summary.md").read_text(encoding="utf-8")[-2500:],
        ],
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run malware-family models on first-1024-byte and body-after-1024-byte PNG views.")
    parser.add_argument("--run-id")
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/evidence/prefix_body_family_model_runs")
    parser.add_argument("--family-core", required=True)
    parser.add_argument("--raw-root", default="/home/phil/vibex_secure_dataset/raw/malware_quarantine")
    parser.add_argument("--native-runner", required=True)
    parser.add_argument("--architectures", default=",".join(DEFAULT_ARCHITECTURES))
    parser.add_argument("--seeds", default="1337,2026,4242")
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--target-per-class", type=int, default=20)
    parser.add_argument("--prefix-bytes", type=int, default=1024)
    parser.add_argument("--prefix-image-size", type=int, default=32)
    parser.add_argument("--body-bytes", type=int, default=65536)
    parser.add_argument("--body-image-size", type=int, default=256)
    parser.add_argument("--telegram", action="store_true")
    args = parser.parse_args()
    args.architectures = parse_strings(args.architectures)
    args.seeds = parse_ints(args.seeds)
    return args


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
