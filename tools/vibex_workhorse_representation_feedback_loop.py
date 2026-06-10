#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import shlex
import subprocess
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from statistics import mean
from typing import Any
from zoneinfo import ZoneInfo

from PIL import Image


LIGHTWEIGHT_MODELS = [
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

SCOUT_MODELS = ["compact_cnn", "squeeze_cnn", "inception_small", "convnext_tiny_scratch"]

LARGE_MODELS = [
    "efficientnetb0_scratch",
    "efficientnetb1_scratch",
    "vgg16_scratch",
    "mobilenetv3small_scratch",
    "resnet50_scratch",
]

REPRESENTATIONS = {
    "prefix1024_32": {"kind": "prefix", "offset": 0, "length": 1024, "image_size": 32},
    "prefix1024_1024": {"kind": "prefix_upscale", "offset": 0, "length": 1024, "image_size": 1024, "source_size": 32},
    "prefix4096_64": {"kind": "prefix", "offset": 0, "length": 4096, "image_size": 64},
    "prefix16384_128": {"kind": "prefix", "offset": 0, "length": 16384, "image_size": 128},
    "prefix65536_256": {"kind": "prefix", "offset": 0, "length": 65536, "image_size": 256},
    "body_after1024_256": {"kind": "slice", "offset": 1024, "length": 65536, "image_size": 256},
    "body_after4096_256": {"kind": "slice", "offset": 4096, "length": 65536, "image_size": 256},
    "tail65536_256": {"kind": "tail", "length": 65536, "image_size": 256},
    "stride_sample_256": {"kind": "stride", "length": 65536, "image_size": 256},
    "entropy_map_64": {"kind": "entropy", "pixels": 4096, "image_size": 64},
    "byte_histogram_256": {"kind": "histogram", "chunks": 256, "image_size": 256},
}


def utc_now() -> str:
    return datetime.now(ZoneInfo("UTC")).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_stamp() -> str:
    return datetime.now(ZoneInfo("UTC")).strftime("%Y%m%dT%H%M%SZ")


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


def parse_strings(value: str) -> list[str]:
    return [item.strip() for item in str(value).split(",") if item.strip()]


def parse_ints(value: str) -> list[int]:
    return [int(item.strip()) for item in str(value).split(",") if item.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_malware_raw_path(row: dict[str, str], raw_root: Path) -> Path:
    source = row.get("source", "").strip()
    original = row.get("original_family_field", "").strip()
    if not source or not original.startswith("VirusShare_"):
        raise ValueError(f"Cannot resolve raw path for {row.get('raw_sha256', '')}")
    return raw_root / source / original


def gray_png(path: Path, payload: bytes, image_size: int) -> str:
    needed = image_size * image_size
    data = payload[:needed].ljust(needed, b"\x00")
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.frombytes("L", (image_size, image_size), data).save(path, format="PNG", optimize=True)
    return sha256_file(path)


def prefix_upscale_png(path: Path, payload: bytes, source_size: int, image_size: int) -> str:
    needed = source_size * source_size
    data = payload[:needed].ljust(needed, b"\x00")
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.frombytes("L", (source_size, source_size), data)
    image = image.resize((image_size, image_size), Image.Resampling.NEAREST)
    image.save(path, format="PNG", optimize=True)
    return sha256_file(path)


def stride_payload(raw: bytes, length: int) -> bytes:
    if not raw:
        return b"\x00" * length
    if len(raw) >= length:
        return bytes(raw[round(i * (len(raw) - 1) / max(1, length - 1))] for i in range(length))
    return raw.ljust(length, b"\x00")


def entropy_value(chunk: bytes) -> int:
    if not chunk:
        return 0
    counts = Counter(chunk)
    total = len(chunk)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return max(0, min(255, round((entropy / 8.0) * 255)))


def entropy_payload(raw: bytes, pixels: int) -> bytes:
    if not raw:
        return b"\x00" * pixels
    chunk_size = max(1, math.ceil(len(raw) / pixels))
    values = bytearray()
    for index in range(pixels):
        start = index * chunk_size
        values.append(entropy_value(raw[start : start + chunk_size]))
    return bytes(values[:pixels]).ljust(pixels, b"\x00")


def histogram_payload(raw: bytes, chunks: int) -> bytes:
    if not raw:
        return b"\x00" * (chunks * 256)
    chunk_size = max(1, math.ceil(len(raw) / chunks))
    values = bytearray()
    for index in range(chunks):
        chunk = raw[index * chunk_size : (index + 1) * chunk_size]
        counts = Counter(chunk)
        max_count = max(counts.values()) if counts else 1
        values.extend(round((counts.get(byte, 0) / max_count) * 255) for byte in range(256))
    return bytes(values[: chunks * 256]).ljust(chunks * 256, b"\x00")


def render_representation(raw: bytes, rep: dict[str, Any], output_path: Path) -> tuple[str, int]:
    kind = rep["kind"]
    if kind == "prefix":
        segment = raw[: int(rep["length"])]
        return gray_png(output_path, segment, int(rep["image_size"])), len(segment)
    if kind == "prefix_upscale":
        segment = raw[: int(rep["length"])]
        return prefix_upscale_png(output_path, segment, int(rep["source_size"]), int(rep["image_size"])), len(segment)
    if kind == "slice":
        offset = int(rep["offset"])
        segment = raw[offset : offset + int(rep["length"])] if len(raw) > offset else b""
        return gray_png(output_path, segment, int(rep["image_size"])), len(segment)
    if kind == "tail":
        segment = raw[-int(rep["length"]) :]
        return gray_png(output_path, segment, int(rep["image_size"])), len(segment)
    if kind == "stride":
        segment = stride_payload(raw, int(rep["length"]))
        return gray_png(output_path, segment, int(rep["image_size"])), min(len(raw), int(rep["length"]))
    if kind == "entropy":
        segment = entropy_payload(raw, int(rep["pixels"]))
        return gray_png(output_path, segment, int(rep["image_size"])), len(raw)
    if kind == "histogram":
        segment = histogram_payload(raw, int(rep["chunks"]))
        return gray_png(output_path, segment, int(rep["image_size"])), len(raw)
    raise ValueError(f"Unsupported representation kind: {kind}")


def limit_rows_per_family(rows: list[dict[str, str]], limit: int) -> list[dict[str, str]]:
    if limit <= 0:
        return rows
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        grouped.setdefault(row.get("consensus_family", row.get("family", "")), []).append(row)
    out = []
    for family in sorted(grouped):
        out.extend(sorted(grouped[family], key=lambda row: row.get("raw_sha256", ""))[:limit])
    return out


def build_malware_manifests(args: argparse.Namespace, run_dir: Path, reps: list[str]) -> dict[str, Any]:
    source_rows = limit_rows_per_family(read_csv(Path(args.family_core)), args.limit_per_family)
    raw_root = Path(args.raw_root)
    image_root = run_dir / "derived_pngs" / "malware"
    manifest_root = run_dir / "manifests"
    manifests: dict[str, Any] = {}
    audit = []
    for rep_name in reps:
        rep = REPRESENTATIONS[rep_name]
        rows = []
        missing = 0
        for row in source_rows:
            sha = row.get("raw_sha256", "").strip().lower()
            family = row.get("consensus_family", "").strip().lower()
            if len(sha) != 64 or not family:
                continue
            raw_path = resolve_malware_raw_path(row, raw_root)
            if not raw_path.exists():
                missing += 1
                audit.append({"representation": rep_name, "raw_sha256": sha, "status": "missing_raw"})
                continue
            raw = raw_path.read_bytes()
            image_path = image_root / rep_name / family / f"{sha}.png"
            image_sha, bytes_available = render_representation(raw, rep, image_path)
            item = dict(row)
            item.update(
                {
                    "family": family,
                    "sha256_hash": sha,
                    "image_path": str(image_path),
                    "image_size": str(rep["image_size"]),
                    "image_mode": "gray",
                    "representation": rep_name,
                    "representation_kind": rep["kind"],
                    "representation_bytes_available": str(bytes_available),
                    "representation_image_sha256": image_sha,
                }
            )
            rows.append(item)
        manifest_path = manifest_root / f"{rep_name}_malware_manifest.csv"
        write_csv(manifest_path, rows)
        manifests[rep_name] = {
            "manifest_path": str(manifest_path),
            "rows": len(rows),
            "missing_raw": missing,
            "image_size": rep["image_size"],
            "image_mode": "gray",
            "class_counts": dict(sorted(Counter(row["family"] for row in rows).items())),
            "family_count": len({row["family"] for row in rows}),
            "representation": rep,
        }
    write_csv(manifest_root / "malware_representation_build_audit.csv", audit)
    write_json(manifest_root / "malware_manifest_summary.json", manifests)
    return manifests


def build_benign_index(raw_root: Path, needed: set[str]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for dirpath, _, filenames in os.walk(raw_root):
        for filename in filenames:
            if len(found) >= len(needed):
                return found
            path = Path(dirpath) / filename
            try:
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                sha = digest.hexdigest()
            except OSError:
                continue
            if sha in needed:
                found[sha] = path
    return found


def build_benign_manifest(args: argparse.Namespace, run_dir: Path, rep_name: str) -> dict[str, Any]:
    malware_rows = read_csv(Path(run_dir / "manifests" / f"{rep_name}_malware_manifest.csv"))
    benign_rows = []
    for row in read_csv(Path(args.release_manifest)):
        if row.get("binary_label") == "benign" and row.get("file_kind", "").lower() in {"pe", "mz"}:
            benign_rows.append(row)
    benign_rows = sorted(benign_rows, key=lambda row: row.get("raw_sha256", ""))[: args.benign_scan_limit]
    needed = {row["raw_sha256"].lower() for row in benign_rows if len(row.get("raw_sha256", "")) == 64}
    index = build_benign_index(Path(args.benign_raw_root), needed)
    rep = REPRESENTATIONS[rep_name]
    output_rows = list(malware_rows)
    image_root = run_dir / "derived_pngs" / "benign" / rep_name
    for row in benign_rows:
        sha = row.get("raw_sha256", "").strip().lower()
        raw_path = index.get(sha)
        if not raw_path:
            continue
        raw = raw_path.read_bytes()
        image_path = image_root / f"{sha}.png"
        image_sha, bytes_available = render_representation(raw, rep, image_path)
        item = dict(row)
        item.update(
            {
                "family": "benign",
                "consensus_family": "benign",
                "sha256_hash": sha,
                "image_path": str(image_path),
                "image_size": str(rep["image_size"]),
                "image_mode": "gray",
                "representation": rep_name,
                "representation_kind": rep["kind"],
                "representation_bytes_available": str(bytes_available),
                "representation_image_sha256": image_sha,
            }
        )
        output_rows.append(item)
    manifest_path = run_dir / "manifests" / f"{rep_name}_plus_benign_manifest.csv"
    write_csv(manifest_path, output_rows)
    summary = {
        "manifest_path": str(manifest_path),
        "rows": len(output_rows),
        "benign_rows": sum(1 for row in output_rows if row["family"] == "benign"),
        "image_size": rep["image_size"],
        "image_mode": "gray",
        "class_counts": dict(sorted(Counter(row["family"] for row in output_rows).items())),
        "family_count": len({row["family"] for row in output_rows}),
    }
    write_json(run_dir / "manifests" / f"{rep_name}_plus_benign_summary.json", summary)
    return summary


class Messenger:
    def __init__(self, args: argparse.Namespace, run_dir: Path):
        self.enabled = args.telegram
        self.tz = ZoneInfo(args.telegram_timezone)
        self.quiet_start = args.quiet_start
        self.quiet_end = args.quiet_end
        self.queue_path = run_dir / "logs" / "queued_telegram.jsonl"

    def is_quiet(self) -> bool:
        hour = datetime.now(self.tz).hour
        return hour >= self.quiet_start or hour < self.quiet_end

    def send_now(self, message: str) -> None:
        if not self.enabled:
            return
        subprocess.run(
            ["ssh", "phil@10.64.0.62", "sudo", "/usr/local/bin/vibex_send_telegram_text.py"],
            input=message,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

    def queue(self, message: str) -> None:
        self.queue_path.parent.mkdir(parents=True, exist_ok=True)
        with self.queue_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"queued_utc": utc_now(), "message": message}) + "\n")

    def flush_if_allowed(self) -> None:
        if not self.enabled or self.is_quiet() or not self.queue_path.exists():
            return
        rows = [json.loads(line) for line in self.queue_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not rows:
            return
        digest = ["VIBEX model test update", f"Quiet-hours digest: {len(rows)} queued updates"]
        for row in rows[-8:]:
            digest.append("---")
            digest.append(row["message"][-1200:])
        self.send_now("\n".join(digest))
        self.queue_path.unlink()

    def send(self, title: str, lines: list[str]) -> None:
        message = title + "\n" + "\n".join(lines)
        self.flush_if_allowed()
        if self.is_quiet():
            self.queue(message)
        else:
            self.send_now(message)

    def flush_after_quiet(self) -> None:
        if not self.enabled or not self.queue_path.exists() or not self.is_quiet():
            self.flush_if_allowed()
            return
        now = datetime.now(self.tz)
        target = now.replace(hour=self.quiet_end, minute=0, second=0, microsecond=0)
        if now.hour >= self.quiet_start:
            target += timedelta(days=1)
        sleep_seconds = max(0, min(8 * 3600, int((target - now).total_seconds())))
        if sleep_seconds:
            time.sleep(sleep_seconds)
        self.flush_if_allowed()


def run_command(cmd: list[str], log_path: Path) -> subprocess.CompletedProcess[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"$ {shlex.join(cmd)}\n")
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(proc.stdout or "")
        handle.write(f"\n[exit {proc.returncode}]\n")
    return proc


def best_from_result(evidence_dir: Path) -> dict[str, Any]:
    path = evidence_dir / "planb_native_family_results.json"
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    aggregates = payload.get("aggregates") or []
    results = [row for row in payload.get("results", []) if row.get("status") == "completed"]
    if not aggregates or not results:
        return {}
    best_seed = max(results, key=lambda row: (row.get("macro_f1") or 0.0, row.get("accuracy") or 0.0))
    weakest = sorted((best_seed.get("per_class_f1") or {}).items(), key=lambda item: item[1])[:5]
    return {"best_group": aggregates[0], "best_seed": best_seed, "weakest": weakest}


def group_metric(group: dict[str, Any], metric: str) -> float:
    return float(group.get("best", {}).get("best_group", {}).get(metric) or 0.0)


def write_overall(run_dir: Path, metadata: dict[str, Any], groups: list[dict[str, Any]]) -> None:
    write_json(run_dir / "overall_results.json", {"metadata": metadata, "groups": groups})
    rows = []
    for group in groups:
        best = group.get("best", {}).get("best_group", {})
        rows.append(
            {
                "stage": group.get("stage"),
                "representation": group.get("representation"),
                "architecture": group.get("architecture"),
                "status": group.get("status"),
                "completed_seeds": best.get("completed_seeds"),
                "val_macro_f1_mean": best.get("val_macro_f1_mean"),
                "val_accuracy_mean": best.get("val_accuracy_mean"),
                "macro_f1_mean": best.get("macro_f1_mean"),
                "macro_f1_std": best.get("macro_f1_std"),
                "weighted_f1_mean": best.get("weighted_f1_mean"),
                "accuracy_mean": best.get("accuracy_mean"),
                "accuracy_std": best.get("accuracy_std"),
                "elapsed_seconds": group.get("elapsed_seconds"),
                "log_path": group.get("log_path"),
            }
        )
    write_csv(run_dir / "overall_leaderboard.csv", rows)
    completed = [row for row in rows if row["status"] == "completed" and row.get("macro_f1_mean") not in (None, "")]
    best = max(completed, key=lambda row: float(row["macro_f1_mean"])) if completed else {}
    lines = [
        "# VIBEX Representation Feedback Loop",
        "",
        f"- Run ID: `{metadata['run_id']}`",
        f"- Created UTC: `{metadata['created_utc']}`",
        f"- Split: `80/10/10`",
        f"- Gate: accuracy `>= {metadata['benign_accuracy_gate']}` and macro-F1 `>= {metadata['benign_macro_gate']}`",
        f"- Raw malware, benign files, derived PNGs, and model binaries remain on workhorse only.",
        "",
        "## Best Overall",
        "",
    ]
    if best:
        lines.extend(
            [
                f"- Stage: `{best['stage']}`",
                f"- Representation: `{best['representation']}`",
                f"- Architecture: `{best['architecture']}`",
                f"- Test macro-F1: `{float(best['macro_f1_mean']):.4f}`",
                f"- Test accuracy: `{float(best['accuracy_mean']):.4f}`",
                f"- Validation macro-F1: `{float(best['val_macro_f1_mean'] or 0.0):.4f}`",
                f"- Beats prior `0.7733 / 0.8105`: `{float(best['macro_f1_mean']) > 0.7733 and float(best['accuracy_mean']) > 0.8105}`",
            ]
        )
    lines.extend(
        [
            "",
            "## Leaderboard",
            "",
            "| Stage | Representation | Model | Seeds | Val macro-F1 | Test macro-F1 | Accuracy |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in sorted(completed, key=lambda item: float(item["macro_f1_mean"]), reverse=True)[:40]:
        lines.append(
            f"| {row['stage']} | {row['representation']} | {row['architecture']} | {row.get('completed_seeds') or ''} | "
            f"{float(row.get('val_macro_f1_mean') or 0.0):.4f} | {float(row['macro_f1_mean']):.4f} | {float(row['accuracy_mean']):.4f} |"
        )
    (run_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_group(
    args: argparse.Namespace,
    run_dir: Path,
    manifests: dict[str, Any],
    stage: str,
    representation: str,
    architecture: str,
    seeds: list[int],
    epochs: int,
    patience: int,
    learning_rate: float,
    dropout: float,
    label_smoothing: float,
    mixed_precision: bool,
    target_per_class: int,
    manifest_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = manifest_override or manifests[representation]
    output_root = run_dir / "model_sweeps" / stage / representation
    group_run_id = f"{args.run_id}_{stage}_{representation}_{architecture}"
    log_path = run_dir / "logs" / f"{stage}_{representation}_{architecture}.log"
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
        ",".join(str(seed) for seed in seeds),
        "--epochs",
        str(epochs),
        "--patience",
        str(patience),
        "--target-per-family",
        str(target_per_class),
        "--split-ratios",
        "0.8,0.1,0.1",
        "--learning-rate",
        str(learning_rate),
        "--dropout",
        str(dropout),
        "--label-smoothing",
        str(label_smoothing),
    ]
    if mixed_precision:
        cmd.append("--mixed-precision")
    start = time.time()
    proc = run_command(cmd, log_path)
    evidence_dir = output_root / group_run_id / "evidence"
    return {
        "stage": stage,
        "representation": representation,
        "architecture": architecture,
        "status": "completed" if proc.returncode == 0 else "failed",
        "returncode": proc.returncode,
        "elapsed_seconds": round(time.time() - start, 3),
        "log_path": str(log_path),
        "evidence_dir": str(evidence_dir),
        "best": best_from_result(evidence_dir),
    }


def notify_progress(messenger: Messenger, metadata: dict[str, Any], groups: list[dict[str, Any]], current: dict[str, Any]) -> None:
    completed = sum(1 for group in groups if group.get("status") == "completed")
    best = max((group for group in groups if group.get("best")), key=lambda group: group_metric(group, "macro_f1_mean"), default=None)
    lines = [
        f"Run: {metadata['run_id']}",
        f"Stage: {current['stage']}",
        f"Latest: {current['representation']} / {current['architecture']} = {current['status']}",
        f"Completed groups: {completed}",
    ]
    current_best = current.get("best", {}).get("best_group", {})
    if current_best:
        lines.extend(
            [
                f"Latest test macro-F1: {float(current_best.get('macro_f1_mean') or 0.0):.4f}",
                f"Latest test accuracy: {float(current_best.get('accuracy_mean') or 0.0):.4f}",
                f"Latest val macro-F1: {float(current_best.get('val_macro_f1_mean') or 0.0):.4f}",
            ]
        )
    if best:
        best_group = best["best"]["best_group"]
        weakest = ", ".join(f"{label}={value:.3f}" for label, value in best.get("best", {}).get("weakest", [])[:5])
        lines.extend(
            [
                f"Best so far: {best['representation']} / {best['architecture']}",
                f"Best test macro-F1: {float(best_group.get('macro_f1_mean') or 0.0):.4f}",
                f"Best test accuracy: {float(best_group.get('accuracy_mean') or 0.0):.4f}",
                f"Weakest classes: {weakest or 'not available'}",
            ]
        )
    lines.append(f"Elapsed: {round((time.time() - metadata['started_epoch']) / 60, 1)} minutes")
    messenger.send("VIBEX model test update", lines)


def top_representations(groups: list[dict[str, Any]], stage: str, count: int) -> list[str]:
    best_by_rep: dict[str, dict[str, Any]] = {}
    for group in groups:
        if group.get("stage") != stage or group.get("status") != "completed" or not group.get("best"):
            continue
        rep = group["representation"]
        if rep not in best_by_rep or group_metric(group, "val_macro_f1_mean") > group_metric(best_by_rep[rep], "val_macro_f1_mean"):
            best_by_rep[rep] = group
    ranked = sorted(best_by_rep.values(), key=lambda group: (group_metric(group, "val_macro_f1_mean"), group_metric(group, "val_accuracy_mean")), reverse=True)
    return [group["representation"] for group in ranked[:count]]


def top_pairs(groups: list[dict[str, Any]], count: int) -> list[tuple[str, str]]:
    completed = [group for group in groups if group.get("status") == "completed" and group.get("best")]
    ranked = sorted(completed, key=lambda group: (group_metric(group, "macro_f1_mean"), group_metric(group, "accuracy_mean")), reverse=True)
    pairs = []
    seen = set()
    for group in ranked:
        pair = (group["representation"], group["architecture"])
        if pair not in seen:
            pairs.append(pair)
            seen.add(pair)
        if len(pairs) >= count:
            break
    return pairs


def gate_candidate(groups: list[dict[str, Any]], accuracy_gate: float, macro_gate: float) -> dict[str, Any] | None:
    candidates = []
    for group in groups:
        best = group.get("best", {}).get("best_group", {})
        if not best:
            continue
        if (
            float(best.get("accuracy_mean") or 0.0) >= accuracy_gate
            and float(best.get("macro_f1_mean") or 0.0) >= macro_gate
            and int(best.get("completed_seeds") or 0) >= 3
        ):
            candidates.append(group)
    return max(candidates, key=lambda group: (group_metric(group, "macro_f1_mean"), group_metric(group, "accuracy_mean")), default=None)


def run(args: argparse.Namespace) -> int:
    args.run_id = args.run_id or f"vibex_representation_feedback_{utc_stamp()}"
    run_dir = Path(args.output_root) / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    representations = parse_strings(args.representations)
    manifests = build_malware_manifests(args, run_dir, representations)
    metadata = {
        "run_id": args.run_id,
        "created_utc": utc_now(),
        "started_epoch": time.time(),
        "representations": representations,
        "scout_models": SCOUT_MODELS,
        "lightweight_models": LIGHTWEIGHT_MODELS,
        "large_models": LARGE_MODELS,
        "split_ratios": [0.8, 0.1, 0.1],
        "benign_accuracy_gate": args.benign_accuracy_gate,
        "benign_macro_gate": args.benign_macro_gate,
        "manifests": manifests,
        "raw_artifacts_in_git": False,
    }
    write_json(run_dir / "run_metadata.json", metadata)
    messenger = Messenger(args, run_dir)
    if args.smoke:
        groups: list[dict[str, Any]] = []
        smoke_models = ["compact_cnn"] + LARGE_MODELS
        smoke_rep = "prefix1024_32" if "prefix1024_32" in manifests else next(iter(manifests))
        metadata["smoke"] = True
        for architecture in smoke_models:
            group = run_group(
                args,
                run_dir,
                manifests,
                "smoke",
                smoke_rep,
                architecture,
                [args.scout_seed],
                1,
                1,
                1e-3,
                0.3,
                0.0,
                architecture in LARGE_MODELS,
                args.smoke_target_per_class,
            )
            groups.append(group)
            write_overall(run_dir, metadata, groups)
        write_json(run_dir / "smoke_status.json", {"status": "completed", "groups": groups})
        return 0

    messenger.send(
        "VIBEX model test update",
        [
            f"Run: {args.run_id}",
            "Phase: representation feedback loop started",
            f"Representations: {len(representations)}",
            "Split: 80/10/10",
            "Benign starts only after accuracy >= 0.90 and macro-F1 >= 0.85.",
        ],
    )
    groups: list[dict[str, Any]] = []

    for rep in representations:
        for architecture in SCOUT_MODELS:
            group = run_group(args, run_dir, manifests, "scout", rep, architecture, [args.scout_seed], args.scout_epochs, 1, 1e-3, 0.3, 0.0, False, args.target_per_class)
            groups.append(group)
            write_overall(run_dir, metadata, groups)
            notify_progress(messenger, metadata, groups, group)

    full_reps = top_representations(groups, "scout", 4)
    if "prefix1024_1024" not in full_reps:
        full_reps.append("prefix1024_1024")
    write_json(run_dir / "selected_full_representations.json", full_reps)
    messenger.send("VIBEX model test update", [f"Run: {args.run_id}", f"Scout complete. Full loop reps: {', '.join(full_reps)}"])

    for rep in full_reps:
        for architecture in LIGHTWEIGHT_MODELS:
            group = run_group(args, run_dir, manifests, "full", rep, architecture, args.seeds, args.epochs, args.patience, 1e-3, 0.3, 0.0, False, args.target_per_class)
            groups.append(group)
            write_overall(run_dir, metadata, groups)
            notify_progress(messenger, metadata, groups, group)

    large_reps = top_representations(groups, "full", 2) or full_reps[:2]
    write_json(run_dir / "selected_large_representations.json", large_reps)
    messenger.send("VIBEX model test update", [f"Run: {args.run_id}", f"Large-model loop reps: {', '.join(large_reps)}"])
    for rep in large_reps:
        for architecture in LARGE_MODELS:
            group = run_group(args, run_dir, manifests, "large", rep, architecture, args.seeds, args.epochs, args.patience, 7e-4, 0.35, 0.0, args.mixed_precision_large, args.target_per_class)
            groups.append(group)
            write_overall(run_dir, metadata, groups)
            notify_progress(messenger, metadata, groups, group)

    refine_pairs = top_pairs(groups, 2)
    write_json(run_dir / "selected_refinement_pairs.json", [{"representation": rep, "architecture": arch} for rep, arch in refine_pairs])
    messenger.send("VIBEX model test update", [f"Run: {args.run_id}", f"Refinement pairs: {', '.join(f'{rep}/{arch}' for rep, arch in refine_pairs)}"])
    for rep, architecture in refine_pairs:
        group = run_group(args, run_dir, manifests, "refinement", rep, architecture, args.refinement_seeds, args.refinement_epochs, args.refinement_patience, 5e-4, 0.4, 0.03, "efficientnet" in architecture or architecture in {"vgg16_scratch", "resnet50_scratch"}, args.target_per_class)
        groups.append(group)
        write_overall(run_dir, metadata, groups)
        notify_progress(messenger, metadata, groups, group)

    gate = gate_candidate(groups, args.benign_accuracy_gate, args.benign_macro_gate)
    if gate:
        rep = gate["representation"]
        architecture = gate["architecture"]
        messenger.send("VIBEX model test update", [f"Run: {args.run_id}", f"Benign gate reached by {rep} / {architecture}. Starting benign phase."])
        benign_manifest = build_benign_manifest(args, run_dir, rep)
        group = run_group(args, run_dir, manifests, "benign", rep, architecture, args.seeds, args.epochs, args.patience, 5e-4, 0.4, 0.03, "efficientnet" in architecture or architecture in {"vgg16_scratch", "resnet50_scratch"}, args.target_per_class, manifest_override=benign_manifest)
        groups.append(group)
        write_overall(run_dir, metadata, groups)
        notify_progress(messenger, metadata, groups, group)
    else:
        messenger.send("VIBEX model test update", [f"Run: {args.run_id}", "Benign gate not reached. Benign class was not added."])

    write_overall(run_dir, metadata, groups)
    messenger.send("VIBEX model test update", [f"Run: {args.run_id}", "Final summary", (run_dir / "summary.md").read_text(encoding="utf-8")[-2500:]])
    messenger.flush_after_quiet()
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a staged malware-family representation feedback loop on workhorse.")
    parser.add_argument("--run-id")
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/evidence/representation_feedback_model_runs")
    parser.add_argument("--family-core", required=True)
    parser.add_argument("--release-manifest", required=True)
    parser.add_argument("--raw-root", default="/home/phil/vibex_secure_dataset/raw/malware_quarantine")
    parser.add_argument("--benign-raw-root", default="/home/phil/vibex_secure_dataset/raw/benign_sources")
    parser.add_argument("--native-runner", required=True)
    parser.add_argument("--representations", default=",".join(REPRESENTATIONS))
    parser.add_argument("--target-per-class", type=int, default=20)
    parser.add_argument("--limit-per-family", type=int, default=0)
    parser.add_argument("--scout-seed", type=int, default=1337)
    parser.add_argument("--scout-epochs", type=int, default=5)
    parser.add_argument("--seeds", default="1337,2026,4242")
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--refinement-seeds", default="1337,2026,4242,5150,9001")
    parser.add_argument("--refinement-epochs", type=int, default=18)
    parser.add_argument("--refinement-patience", type=int, default=4)
    parser.add_argument("--benign-accuracy-gate", type=float, default=0.90)
    parser.add_argument("--benign-macro-gate", type=float, default=0.85)
    parser.add_argument("--benign-scan-limit", type=int, default=40000)
    parser.add_argument("--mixed-precision-large", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--smoke-target-per-class", type=int, default=5)
    parser.add_argument("--telegram", action="store_true")
    parser.add_argument("--telegram-timezone", default="Europe/London")
    parser.add_argument("--quiet-start", type=int, default=22)
    parser.add_argument("--quiet-end", type=int, default=6)
    args = parser.parse_args()
    args.seeds = parse_ints(args.seeds)
    args.refinement_seeds = parse_ints(args.refinement_seeds)
    unknown = [rep for rep in parse_strings(args.representations) if rep not in REPRESENTATIONS]
    if unknown:
        raise SystemExit(f"Unknown representations: {unknown}")
    return args


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
