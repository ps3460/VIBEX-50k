#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import random
import re
import shlex
import subprocess
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from PIL import Image


GENERIC_FAMILIES = {
    "adware",
    "agent",
    "application",
    "backdoor",
    "dropper",
    "generic",
    "generickd",
    "heur",
    "malware",
    "packed",
    "packer",
    "riskware",
    "trojan",
    "unsafe",
    "variant",
    "virus",
    "vmprotect",
    "win32",
    "wintool",
    "worm",
}

PRIMARY_REPRESENTATIONS = {
    "prefix4096_64": {"kind": "prefix", "length": 4096, "image_size": 64},
    "prefix8192_128_padded": {"kind": "prefix", "length": 8192, "image_size": 128},
    "prefix12288_128_padded": {"kind": "prefix", "length": 12288, "image_size": 128},
    "prefix16384_128": {"kind": "prefix", "length": 16384, "image_size": 128},
    "pe_header_layout_128": {"kind": "pe_header_layout", "image_size": 128},
    "section_table_layout_64": {"kind": "section_table", "image_size": 64},
}

EXPLORATION_REPRESENTATIONS = {
    "entropy_map_64": {"kind": "entropy", "pixels": 4096, "image_size": 64},
    "byte_histogram_256": {"kind": "histogram", "chunks": 256, "image_size": 256},
    "stride_sample_128": {"kind": "stride", "length": 16384, "image_size": 128},
    "body_after4096_128": {"kind": "slice", "offset": 4096, "length": 16384, "image_size": 128},
}

REPRESENTATIONS = {**PRIMARY_REPRESENTATIONS, **EXPLORATION_REPRESENTATIONS}

PRIMARY_ARCHITECTURES = [
    "convnext_tiny_scratch",
    "residual_small",
    "wide_residual_small",
    "inception_small",
    "attention_pool_cnn",
    "dual_kernel_cnn",
    "separable_cnn",
]

SECONDARY_ARCHITECTURES = [
    "efficientnetb0_scratch",
    "mobilenetv3small_scratch",
    "vgg16_scratch",
    "resnet50_scratch",
]

TELEGRAM_CMD = [
    "ssh",
    "phil@10.64.0.62",
    "sudo",
    "/usr/local/bin/vibex_send_telegram_text.py",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_label(value: str, prefix: str = "") -> str:
    text = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return f"{prefix}{text}"[:96] or f"{prefix}unknown"


def raw_path_for_malware(row: dict[str, str], raw_root: Path) -> Path:
    original = row.get("original_family_field", "").strip()
    source = row.get("source", "").strip()
    if not original.startswith("VirusShare_"):
        raise ValueError(f"unsupported original field for {row.get('raw_sha256')}")
    return raw_root / source / original


def selected_malware_rows(args: argparse.Namespace) -> list[dict[str, str]]:
    rows_by_sha: dict[str, dict[str, str]] = {}
    for source_path in [Path(args.family_core), Path(args.family_extended)]:
        for row in read_csv(source_path):
            sha = row.get("raw_sha256", "").strip().lower()
            family = safe_label(row.get("consensus_family", ""))
            if len(sha) != 64 or row.get("binary_label") != "malware":
                continue
            if row.get("file_kind", "").lower() not in {"pe", "mz"}:
                continue
            if row.get("family_label_status") != "labelled":
                continue
            if family in GENERIC_FAMILIES or "generic" in family or "packer" in family:
                continue
            if "generic" in row.get("exclusion_reason", "").lower():
                continue
            item = dict(row)
            item["family"] = family
            item["sha256_hash"] = sha
            item["dataset_mode"] = "malware_defensible_extended"
            rows_by_sha.setdefault(sha, item)

    counts = Counter(row["family"] for row in rows_by_sha.values())
    keep = {family for family, count in counts.items() if count >= args.min_family_rows}
    rows = [row for row in rows_by_sha.values() if row["family"] in keep]
    if args.max_malware_rows_per_family > 0:
        grouped: dict[str, list[dict[str, str]]] = {}
        for row in rows:
            grouped.setdefault(row["family"], []).append(row)
        limited = []
        for family, items in sorted(grouped.items()):
            limited.extend(sorted(items, key=lambda row: row["sha256_hash"])[: args.max_malware_rows_per_family])
        rows = limited
    return sorted(rows, key=lambda row: (row["family"], row["sha256_hash"]))


def selected_benign_rows(args: argparse.Namespace) -> list[dict[str, str]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in read_csv(Path(args.release_manifest)):
        if row.get("binary_label") != "benign":
            continue
        if row.get("file_kind", "").lower() not in {"pe", "mz"}:
            continue
        sha = row.get("raw_sha256", "").strip().lower()
        if len(sha) != 64:
            continue
        source = row.get("source") or row.get("vibex50_source_component") or "benign"
        family = safe_label(source, "benign_")
        item = dict(row)
        item["family"] = family
        item["sha256_hash"] = sha
        item["dataset_mode"] = "malware_plus_benign_sources"
        grouped.setdefault(family, []).append(item)
    rows = []
    for family, items in sorted(grouped.items()):
        rows.extend(sorted(items, key=lambda row: row["sha256_hash"])[: args.benign_rows_per_source])
    return rows


def raw_manifest_index(raw_manifest: Path, needed: set[str]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    if not raw_manifest.exists():
        return found
    for row in read_csv(raw_manifest):
        sha = (row.get("sha256") or row.get("raw_sha256") or "").strip().lower()
        path = Path((row.get("path") or row.get("raw_path") or "").strip())
        if sha in needed and path.exists():
            found[sha] = path
            if len(found) >= len(needed):
                break
    return found


def build_benign_index(raw_root: Path, needed: set[str]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for dirpath, _, filenames in os.walk(raw_root):
        for filename in filenames:
            if len(found) >= len(needed):
                return found
            path = Path(dirpath) / filename
            try:
                digest = sha256_file(path)
                if digest in needed:
                    found[digest] = path
            except OSError:
                continue
    return found


def gray_png(path: Path, payload: bytes, image_size: int) -> str:
    needed = image_size * image_size
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.frombytes("L", (image_size, image_size), payload[:needed].ljust(needed, b"\x00")).save(path, "PNG", optimize=True)
    return sha256_file(path)


def pe_offsets(raw: bytes) -> tuple[int | None, int | None, int]:
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        return None, None, 0
    pe = int.from_bytes(raw[0x3C:0x40], "little", signed=False)
    if pe <= 0 or pe + 24 >= len(raw) or raw[pe : pe + 4] != b"PE\x00\x00":
        return pe, None, 0
    sections = int.from_bytes(raw[pe + 6 : pe + 8], "little", signed=False)
    opt_size = int.from_bytes(raw[pe + 20 : pe + 22], "little", signed=False)
    return pe, pe + 24 + opt_size, sections


def entropy_payload(raw: bytes, pixels: int) -> bytes:
    if not raw:
        return b"\x00" * pixels
    chunk_size = max(1, math.ceil(len(raw) / pixels))
    out = bytearray()
    for index in range(pixels):
        chunk = raw[index * chunk_size : (index + 1) * chunk_size]
        if not chunk:
            out.append(0)
            continue
        counts = Counter(chunk)
        entropy = -sum((count / len(chunk)) * math.log2(count / len(chunk)) for count in counts.values())
        out.append(max(0, min(255, round((entropy / 8.0) * 255))))
    return bytes(out).ljust(pixels, b"\x00")


def histogram_payload(raw: bytes, chunks: int) -> bytes:
    if not raw:
        return b"\x00" * (chunks * 256)
    chunk_size = max(1, math.ceil(len(raw) / chunks))
    out = bytearray()
    for index in range(chunks):
        chunk = raw[index * chunk_size : (index + 1) * chunk_size]
        counts = Counter(chunk)
        max_count = max(counts.values()) if counts else 1
        out.extend(round((counts.get(byte, 0) / max_count) * 255) for byte in range(256))
    return bytes(out)


def render_representation(raw: bytes, rep: dict[str, Any], output_path: Path) -> tuple[str, int]:
    kind = rep["kind"]
    image_size = int(rep["image_size"])
    if kind == "prefix":
        length = int(rep["length"])
        return gray_png(output_path, raw[:length], image_size), min(len(raw), length)
    if kind == "slice":
        offset = int(rep["offset"])
        length = int(rep["length"])
        segment = raw[offset : offset + length] if len(raw) > offset else b""
        return gray_png(output_path, segment, image_size), len(segment)
    if kind == "stride":
        length = int(rep["length"])
        segment = bytes(raw[round(i * (len(raw) - 1) / max(1, length - 1))] for i in range(length)) if raw else b""
        return gray_png(output_path, segment, image_size), min(len(raw), length)
    if kind == "entropy":
        return gray_png(output_path, entropy_payload(raw, int(rep["pixels"])), image_size), len(raw)
    if kind == "histogram":
        return gray_png(output_path, histogram_payload(raw, int(rep["chunks"])), image_size), len(raw)
    if kind == "pe_header_layout":
        pe, section_offset, sections = pe_offsets(raw)
        parts = [raw[:512]]
        if pe:
            parts.append(raw[pe : pe + 4096])
        if section_offset:
            parts.append(raw[section_offset : section_offset + max(4096, sections * 40)])
        parts.append(raw[:8192])
        payload = b"".join(parts)
        return gray_png(output_path, payload, image_size), len(payload)
    if kind == "section_table":
        _, section_offset, sections = pe_offsets(raw)
        payload = raw[section_offset : section_offset + max(4096, sections * 40)] if section_offset else b""
        return gray_png(output_path, payload, image_size), len(payload)
    raise ValueError(f"unknown representation kind: {kind}")


def build_manifests(args: argparse.Namespace, run_dir: Path) -> dict[str, dict[str, Any]]:
    malware = selected_malware_rows(args)
    benign = selected_benign_rows(args)
    needed_benign = {row["sha256_hash"] for row in benign}
    benign_index = raw_manifest_index(Path(args.raw_manifest), needed_benign)
    missing_benign = needed_benign - set(benign_index)
    if missing_benign:
        benign_index.update(build_benign_index(Path(args.benign_raw_root), missing_benign))
    manifests: dict[str, dict[str, Any]] = {}
    audit = []

    selected_reps = [item.strip() for item in args.representations.split(",") if item.strip()]
    unknown_reps = [item for item in selected_reps if item not in REPRESENTATIONS]
    if unknown_reps:
        raise SystemExit(f"Unknown representations: {unknown_reps}")
    for rep_name in selected_reps:
        rep = REPRESENTATIONS[rep_name]
        malware_rows = []
        benign_rows = []
        for row in malware:
            raw_path = raw_path_for_malware(row, Path(args.raw_root))
            if not raw_path.exists():
                audit.append({"representation": rep_name, "sha256": row["sha256_hash"], "status": "missing_malware_raw"})
                continue
            raw = raw_path.read_bytes()
            image_path = run_dir / "derived_pngs" / rep_name / row["family"] / f"{row['sha256_hash']}.png"
            image_sha, available = render_representation(raw, rep, image_path)
            item = dict(row)
            item.update({"image_path": str(image_path), "image_size": str(rep["image_size"]), "image_mode": "gray", "representation": rep_name, "representation_image_sha256": image_sha, "representation_bytes_available": available})
            malware_rows.append(item)
        for row in benign:
            raw_path = benign_index.get(row["sha256_hash"])
            if not raw_path:
                audit.append({"representation": rep_name, "sha256": row["sha256_hash"], "status": "missing_benign_raw"})
                continue
            raw = raw_path.read_bytes()
            image_path = run_dir / "derived_pngs" / rep_name / row["family"] / f"{row['sha256_hash']}.png"
            image_sha, available = render_representation(raw, rep, image_path)
            item = dict(row)
            item.update({"image_path": str(image_path), "image_size": str(rep["image_size"]), "image_mode": "gray", "representation": rep_name, "representation_image_sha256": image_sha, "representation_bytes_available": available})
            benign_rows.append(item)

        for mode, rows in [("malware_defensible_extended", malware_rows), ("malware_plus_benign_sources", malware_rows + benign_rows)]:
            path = run_dir / "manifests" / f"{mode}_{rep_name}.csv"
            write_csv(path, rows)
            manifests[f"{mode}:{rep_name}"] = {
                "mode": mode,
                "representation": rep_name,
                "manifest_path": str(path),
                "image_size": rep["image_size"],
                "image_mode": "gray",
                "rows": len(rows),
                "class_counts": dict(sorted(Counter(row["family"] for row in rows).items())),
                "family_count": len({row["family"] for row in rows}),
            }

    write_csv(run_dir / "manifests" / "build_audit.csv", audit)
    write_json(run_dir / "manifests" / "manifest_summary.json", manifests)
    return manifests


class SqlStore:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.conn = None
        try:
            import mysql.connector

            self.conn = mysql.connector.connect(
                host=args.sql_host,
                user=args.sql_user,
                password=args.sql_password,
                database=args.sql_database,
                autocommit=True,
            )
        except Exception as exc:
            if args.sql_required:
                raise
            print(f"SQL disabled: {exc}", flush=True)

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        if not self.conn:
            return
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        cursor.close()

    def init_schema(self) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS vibex_family_search_runs (
              run_id VARCHAR(128) PRIMARY KEY,
              status VARCHAR(32) NOT NULL,
              host_label VARCHAR(128),
              target_candidates INT NOT NULL,
              completed_candidates INT NOT NULL DEFAULT 0,
              failed_candidates INT NOT NULL DEFAULT 0,
              best_candidate_id VARCHAR(128),
              best_macro_f1 DOUBLE,
              best_accuracy DOUBLE,
              metadata_json LONGTEXT,
              started_at DATETIME,
              updated_at DATETIME
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS vibex_family_search_candidates (
              run_id VARCHAR(128) NOT NULL,
              candidate_index INT NOT NULL,
              candidate_id VARCHAR(128) NOT NULL,
              status VARCHAR(32) NOT NULL,
              dataset_mode VARCHAR(64),
              representation VARCHAR(96),
              architecture VARCHAR(96),
              seed INT,
              learning_rate DOUBLE,
              dropout DOUBLE,
              label_smoothing DOUBLE,
              image_size INT,
              rows_count INT,
              class_count INT,
              started_at DATETIME,
              finished_at DATETIME,
              duration_seconds DOUBLE,
              macro_f1 DOUBLE,
              weighted_f1 DOUBLE,
              accuracy DOUBLE,
              val_macro_f1 DOUBLE,
              val_accuracy DOUBLE,
              error_text TEXT,
              metrics_json LONGTEXT,
              updated_at DATETIME,
              PRIMARY KEY (run_id, candidate_index),
              KEY idx_vibex_family_search_best (run_id, status, macro_f1, accuracy)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS vibex_family_search_class_f1 (
              run_id VARCHAR(128) NOT NULL,
              candidate_index INT NOT NULL,
              class_label VARCHAR(128) NOT NULL,
              f1 DOUBLE,
              val_f1 DOUBLE,
              PRIMARY KEY (run_id, candidate_index, class_label)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS vibex_family_search_advisor_notes (
              run_id VARCHAR(128) NOT NULL,
              note_index INT NOT NULL,
              created_at DATETIME,
              completed_candidates INT,
              prompt_json LONGTEXT,
              recommendation_json LONGTEXT,
              accepted_json LONGTEXT,
              rationale TEXT,
              PRIMARY KEY (run_id, note_index)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS vibex_family_search_gpu_events (
              run_id VARCHAR(128) NOT NULL,
              event_index BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
              candidate_index INT,
              created_at DATETIME,
              event_type VARCHAR(64),
              gpu_temp_c DOUBLE,
              gpu_util_pct DOUBLE,
              gpu_mem_used_mib DOUBLE,
              gpu_mem_total_mib DOUBLE,
              sleep_seconds DOUBLE,
              details_json LONGTEXT,
              KEY idx_vibex_family_gpu_run (run_id, candidate_index)
            )
            """,
        ]
        for sql in statements:
            self.execute(sql)

    def upsert_run(self, run_id: str, status: str, target: int, metadata: dict[str, Any], completed: int = 0, failed: int = 0, best: dict[str, Any] | None = None) -> None:
        self.execute(
            """
            INSERT INTO vibex_family_search_runs
            (run_id, status, host_label, target_candidates, completed_candidates, failed_candidates,
             best_candidate_id, best_macro_f1, best_accuracy, metadata_json, started_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP())
            ON DUPLICATE KEY UPDATE
              status=VALUES(status),
              host_label=VALUES(host_label),
              target_candidates=VALUES(target_candidates),
              completed_candidates=VALUES(completed_candidates),
              failed_candidates=VALUES(failed_candidates),
              best_candidate_id=VALUES(best_candidate_id),
              best_macro_f1=VALUES(best_macro_f1),
              best_accuracy=VALUES(best_accuracy),
              metadata_json=VALUES(metadata_json),
              updated_at=UTC_TIMESTAMP()
            """,
            (
                run_id,
                status,
                metadata.get("host_label"),
                target,
                completed,
                failed,
                (best or {}).get("candidate_id"),
                (best or {}).get("macro_f1"),
                (best or {}).get("accuracy"),
                json.dumps(metadata, sort_keys=True),
            ),
        )

    def upsert_candidate(self, run_id: str, candidate: dict[str, Any]) -> None:
        self.execute(
            """
            REPLACE INTO vibex_family_search_candidates
            (run_id,candidate_index,candidate_id,status,dataset_mode,representation,architecture,seed,
             learning_rate,dropout,label_smoothing,image_size,rows_count,class_count,started_at,finished_at,
             duration_seconds,macro_f1,weighted_f1,accuracy,val_macro_f1,val_accuracy,error_text,metrics_json,updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP())
            """,
            (
                run_id,
                candidate["candidate_index"],
                candidate["candidate_id"],
                candidate["status"],
                candidate.get("dataset_mode"),
                candidate.get("representation"),
                candidate.get("architecture"),
                candidate.get("seed"),
                candidate.get("learning_rate"),
                candidate.get("dropout"),
                candidate.get("label_smoothing"),
                candidate.get("image_size"),
                candidate.get("rows_count"),
                candidate.get("class_count"),
                candidate.get("started_at_sql"),
                candidate.get("finished_at_sql"),
                candidate.get("duration_seconds"),
                candidate.get("macro_f1"),
                candidate.get("weighted_f1"),
                candidate.get("accuracy"),
                candidate.get("val_macro_f1"),
                candidate.get("val_accuracy"),
                candidate.get("error_text"),
                json.dumps(candidate.get("metrics") or {}, sort_keys=True),
            ),
        )

    def insert_class_f1(self, run_id: str, candidate_index: int, per_class: dict[str, float], val_per_class: dict[str, float]) -> None:
        for label, value in per_class.items():
            self.execute(
                "REPLACE INTO vibex_family_search_class_f1 (run_id,candidate_index,class_label,f1,val_f1) VALUES (%s,%s,%s,%s,%s)",
                (run_id, candidate_index, label, value, val_per_class.get(label)),
            )

    def insert_advice(self, run_id: str, index: int, completed: int, prompt: dict[str, Any], raw: dict[str, Any], accepted: dict[str, Any]) -> None:
        self.execute(
            """
            REPLACE INTO vibex_family_search_advisor_notes
            (run_id,note_index,created_at,completed_candidates,prompt_json,recommendation_json,accepted_json,rationale)
            VALUES (%s,%s,UTC_TIMESTAMP(),%s,%s,%s,%s,%s)
            """,
            (run_id, index, completed, json.dumps(prompt, sort_keys=True), json.dumps(raw, sort_keys=True), json.dumps(accepted, sort_keys=True), str(raw.get("rationale") or "")),
        )

    def insert_gpu(self, run_id: str, candidate_index: int | None, event_type: str, gpu: dict[str, float], sleep_seconds: float, details: dict[str, Any] | None = None) -> None:
        self.execute(
            """
            INSERT INTO vibex_family_search_gpu_events
            (run_id,candidate_index,created_at,event_type,gpu_temp_c,gpu_util_pct,gpu_mem_used_mib,gpu_mem_total_mib,sleep_seconds,details_json)
            VALUES (%s,%s,UTC_TIMESTAMP(),%s,%s,%s,%s,%s,%s,%s)
            """,
            (run_id, candidate_index, event_type, gpu.get("temp"), gpu.get("util"), gpu.get("mem_used"), gpu.get("mem_total"), sleep_seconds, json.dumps(details or {}, sort_keys=True)),
        )


class Messenger:
    def __init__(self, run_dir: Path, enabled: bool, tz: str, quiet_start: int, quiet_end: int):
        self.enabled = enabled
        self.tz = ZoneInfo(tz)
        self.quiet_start = quiet_start
        self.quiet_end = quiet_end
        self.queue_path = run_dir / "logs" / "queued_telegram.jsonl"

    def is_quiet(self) -> bool:
        hour = datetime.now(self.tz).hour
        return hour >= self.quiet_start or hour < self.quiet_end

    def send_now(self, message: str) -> None:
        if not self.enabled:
            return
        subprocess.run(TELEGRAM_CMD, input=message, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)

    def flush(self) -> None:
        if not self.enabled or self.is_quiet() or not self.queue_path.exists():
            return
        rows = [json.loads(line) for line in self.queue_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not rows:
            return
        msg = ["VIBEX model search update", f"Quiet-hours digest: {len(rows)} queued updates"]
        for row in rows[-10:]:
            msg.append("---")
            msg.append(row["message"][-1200:])
        self.send_now("\n".join(msg))
        self.queue_path.unlink()

    def send(self, lines: list[str]) -> None:
        message = "VIBEX model search update\n" + "\n".join(lines)
        self.flush()
        if self.is_quiet():
            self.queue_path.parent.mkdir(parents=True, exist_ok=True)
            with self.queue_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"queued_utc": utc_now(), "message": message}) + "\n")
        else:
            self.send_now(message)


def parse_result(evidence_dir: Path) -> dict[str, Any]:
    path = evidence_dir / "planb_native_family_results.json"
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    results = [row for row in payload.get("results", []) if row.get("status") == "completed"]
    if not results:
        return {}
    row = results[0]
    return {
        "accuracy": row.get("accuracy"),
        "weighted_f1": row.get("weighted_f1"),
        "macro_f1": row.get("macro_f1"),
        "val_accuracy": row.get("val_accuracy"),
        "val_macro_f1": row.get("val_macro_f1"),
        "per_class_f1": row.get("per_class_f1") or {},
        "val_per_class_f1": row.get("val_per_class_f1") or {},
        "confusion_matrix": row.get("confusion_matrix"),
        "classes": row.get("classes"),
        "model_sha256": row.get("model_sha256"),
    }


def run_command(cmd: list[str], log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"$ {shlex.join(cmd)}\n")
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(proc.stdout or "")
        handle.write(f"\n[exit {proc.returncode}]\n")
    return proc.returncode


def nvidia_state() -> dict[str, float]:
    proc = subprocess.run(
        ["nvidia-smi", "--query-gpu=temperature.gpu,utilization.gpu,memory.used,memory.total", "--format=csv,noheader,nounits"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return {"temp": 0.0, "util": 0.0, "mem_used": 0.0, "mem_total": 0.0}
    temp, util, mem_used, mem_total = [float(part.strip()) for part in proc.stdout.splitlines()[0].split(",")[:4]]
    return {"temp": temp, "util": util, "mem_used": mem_used, "mem_total": mem_total}


def cooldown(args: argparse.Namespace, store: SqlStore, run_id: str, candidate_index: int) -> None:
    slept = 0.0
    time.sleep(args.min_cooldown_seconds)
    slept += args.min_cooldown_seconds
    while True:
        gpu = nvidia_state()
        if gpu["temp"] < args.max_gpu_temp_c and gpu["mem_used"] <= args.max_gpu_mem_after_run_mib and gpu["util"] <= args.max_gpu_util_after_run_pct:
            store.insert_gpu(run_id, candidate_index, "cooldown_ok", gpu, slept)
            return
        store.insert_gpu(run_id, candidate_index, "cooldown_wait", gpu, args.cooldown_poll_seconds)
        time.sleep(args.cooldown_poll_seconds)
        slept += args.cooldown_poll_seconds


def weighted_choice(rng: random.Random, weights: dict[str, float]) -> str:
    items = [(key, max(0.001, float(value))) for key, value in weights.items()]
    total = sum(value for _, value in items)
    pick = rng.random() * total
    upto = 0.0
    for key, value in items:
        upto += value
        if upto >= pick:
            return key
    return items[-1][0]


def default_state(args: argparse.Namespace) -> dict[str, Any]:
    rep_weights = {name: (6.0 if name in PRIMARY_REPRESENTATIONS else 1.0) for name in REPRESENTATIONS}
    arch_weights = {name: (4.0 if name in PRIMARY_ARCHITECTURES else 0.8) for name in PRIMARY_ARCHITECTURES + SECONDARY_ARCHITECTURES}
    return {
        "completed": [],
        "failed": [],
        "best": {},
        "next_index": 1,
        "advice_index": 0,
        "last_advice_completed": 0,
        "representation_weights": rep_weights,
        "architecture_weights": arch_weights,
        "dataset_mode_weights": {"malware_plus_benign_sources": 2.0, "malware_defensible_extended": 1.0},
        "learning_rate_range": [2e-4, 1.2e-3],
        "dropout_range": [0.18, 0.45],
        "label_smoothing_range": [0.0, 0.06],
        "seeds": [1337, 2026, 4242, 5150, 9001],
        "milestones_sent": [],
    }


def candidate_from_state(args: argparse.Namespace, state: dict[str, Any], manifests: dict[str, dict[str, Any]], rng: random.Random) -> dict[str, Any]:
    for _ in range(100):
        mode = weighted_choice(rng, state["dataset_mode_weights"])
        rep = weighted_choice(rng, state["representation_weights"])
        manifest = manifests.get(f"{mode}:{rep}")
        if manifest and manifest["rows"] > 0:
            break
    else:
        raise RuntimeError("could not sample valid manifest")
    arch = weighted_choice(rng, state["architecture_weights"])
    index = int(state["next_index"])
    lr_min, lr_max = state["learning_rate_range"]
    d_min, d_max = state["dropout_range"]
    ls_min, ls_max = state["label_smoothing_range"]
    return {
        "candidate_index": index,
        "candidate_id": f"{args.run_id}_cand_{index:04d}",
        "dataset_mode": mode,
        "representation": rep,
        "architecture": arch,
        "seed": state["seeds"][(index - 1) % len(state["seeds"])],
        "learning_rate": 10 ** rng.uniform(math.log10(lr_min), math.log10(lr_max)),
        "dropout": rng.uniform(d_min, d_max),
        "label_smoothing": rng.uniform(ls_min, ls_max),
        "manifest": manifest,
    }


def validate_advice(raw: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    accepted: dict[str, Any] = {}
    for key, allowed in [
        ("representation_weights", set(REPRESENTATIONS)),
        ("architecture_weights", set(PRIMARY_ARCHITECTURES + SECONDARY_ARCHITECTURES)),
        ("dataset_mode_weights", {"malware_plus_benign_sources", "malware_defensible_extended"}),
    ]:
        values = raw.get(key)
        if isinstance(values, dict):
            clean = {}
            for name, value in values.items():
                if name in allowed:
                    clean[name] = max(0.1, min(12.0, float(value)))
            if clean:
                accepted[key] = clean
                state[key].update(clean)
    for key, low, high in [
        ("learning_rate_range", 1e-5, 3e-3),
        ("dropout_range", 0.05, 0.6),
        ("label_smoothing_range", 0.0, 0.12),
    ]:
        values = raw.get(key)
        if isinstance(values, list) and len(values) == 2:
            a = max(low, min(high, float(values[0])))
            b = max(low, min(high, float(values[1])))
            if a <= b:
                state[key] = [a, b]
                accepted[key] = [a, b]
    accepted["weak_families"] = [safe_label(str(item)) for item in raw.get("weak_families", [])[:10]] if isinstance(raw.get("weak_families"), list) else []
    accepted["strategy"] = str(raw.get("strategy") or "balanced")[:32]
    return accepted


def ask_gemma(args: argparse.Namespace, run_dir: Path, state: dict[str, Any], store: SqlStore) -> None:
    completed = state["completed"]
    if len(completed) - int(state.get("last_advice_completed") or 0) < args.ai_interval:
        return
    top = sorted(completed, key=lambda row: (row.get("macro_f1") or 0.0, row.get("accuracy") or 0.0), reverse=True)[:20]
    recent = completed[-25:]
    prompt = {
        "instruction": "Return strict JSON only. Recommend bounded sampling weights/ranges for the next VIBEX malware-family model-search batch.",
        "allowed_representations": list(REPRESENTATIONS),
        "allowed_architectures": PRIMARY_ARCHITECTURES + SECONDARY_ARCHITECTURES,
        "allowed_dataset_modes": ["malware_defensible_extended", "malware_plus_benign_sources"],
        "top_completed": top,
        "recent_completed": recent,
        "current_state": {key: state[key] for key in ["representation_weights", "architecture_weights", "dataset_mode_weights", "learning_rate_range", "dropout_range", "label_smoothing_range"]},
        "output_schema": {
            "representation_weights": {"name": "float 0.1..12"},
            "architecture_weights": {"name": "float 0.1..12"},
            "dataset_mode_weights": {"name": "float 0.1..12"},
            "learning_rate_range": ["float", "float"],
            "dropout_range": ["float", "float"],
            "label_smoothing_range": ["float", "float"],
            "weak_families": ["label"],
            "strategy": "explore|exploit|balanced",
            "rationale": "short safe text",
        },
    }
    proc = subprocess.run(
        ["ollama", "run", args.ollama_model],
        input=json.dumps(prompt, sort_keys=True),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=args.ai_timeout_seconds,
        check=False,
    )
    raw_text = proc.stdout.strip()
    try:
        start = raw_text.index("{")
        end = raw_text.rindex("}") + 1
        raw = json.loads(raw_text[start:end])
    except Exception:
        raw = {"rationale": "AI response was not valid JSON", "raw_excerpt": raw_text[:500], "returncode": proc.returncode}
    accepted = validate_advice(raw, state)
    state["advice_index"] = int(state.get("advice_index") or 0) + 1
    state["last_advice_completed"] = len(completed)
    write_json(run_dir / "advisor" / f"advice_{state['advice_index']:04d}.json", {"prompt": prompt, "raw": raw, "accepted": accepted, "created_utc": utc_now()})
    store.insert_advice(args.run_id, state["advice_index"], len(completed), prompt, raw, accepted)


def run_candidate(args: argparse.Namespace, run_dir: Path, candidate: dict[str, Any], store: SqlStore) -> dict[str, Any]:
    manifest = candidate["manifest"]
    output_root = run_dir / "model_runs" / f"{candidate['candidate_index']:04d}_{candidate['dataset_mode']}_{candidate['representation']}_{candidate['architecture']}"
    log_path = run_dir / "logs" / f"candidate_{candidate['candidate_index']:04d}.log"
    native_run_id = candidate["candidate_id"]
    started_at_sql = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    row = {
        **{k: v for k, v in candidate.items() if k != "manifest"},
        "status": "running",
        "image_size": manifest["image_size"],
        "rows_count": manifest["rows"],
        "class_count": manifest["family_count"],
        "started_at_sql": started_at_sql,
        "metrics": {},
    }
    store.upsert_candidate(args.run_id, row)
    cmd = [
        "python3",
        args.native_runner,
        "--image-manifest",
        manifest["manifest_path"],
        "--output-root",
        str(output_root),
        "--run-id",
        native_run_id,
        "--target-per-family",
        "0",
        "--image-sizes",
        str(manifest["image_size"]),
        "--image-modes",
        "gray",
        "--architectures",
        candidate["architecture"],
        "--seeds",
        str(candidate["seed"]),
        "--epochs",
        str(args.epochs),
        "--patience",
        str(args.patience),
        "--split-ratios",
        "0.8,0.1,0.1",
        "--learning-rate",
        f"{candidate['learning_rate']:.8g}",
        "--dropout",
        f"{candidate['dropout']:.6f}",
        "--label-smoothing",
        f"{candidate['label_smoothing']:.6f}",
    ]
    if candidate["architecture"] in SECONDARY_ARCHITECTURES:
        cmd.append("--mixed-precision")
    started = time.time()
    returncode = run_command(cmd, log_path)
    duration = time.time() - started
    evidence_dir = output_root / native_run_id / "evidence"
    metrics = parse_result(evidence_dir)
    finished_at_sql = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    status = "completed" if returncode == 0 and metrics else "failed"
    row.update(
        {
            "status": status,
            "finished_at_sql": finished_at_sql,
            "duration_seconds": round(duration, 3),
            "macro_f1": metrics.get("macro_f1"),
            "weighted_f1": metrics.get("weighted_f1"),
            "accuracy": metrics.get("accuracy"),
            "val_macro_f1": metrics.get("val_macro_f1"),
            "val_accuracy": metrics.get("val_accuracy"),
            "error_text": "" if status == "completed" else f"returncode={returncode}; metrics_found={bool(metrics)}",
            "metrics": {**metrics, "evidence_dir": str(evidence_dir), "log_path": str(log_path), "returncode": returncode},
        }
    )
    store.upsert_candidate(args.run_id, row)
    if status == "completed":
        store.insert_class_f1(args.run_id, candidate["candidate_index"], metrics.get("per_class_f1") or {}, metrics.get("val_per_class_f1") or {})
    return row


def write_status(run_dir: Path, args: argparse.Namespace, state: dict[str, Any]) -> None:
    completed = state["completed"]
    failed = state["failed"]
    best = state.get("best") or {}
    payload = {
        "ok": True,
        "updated_utc": utc_now(),
        "run_id": args.run_id,
        "target_candidates": args.max_candidates,
        "completed_candidates": len(completed),
        "failed_candidates": len(failed),
        "best": best,
        "next_index": state["next_index"],
        "latest_completed": completed[-1] if completed else None,
        "latest_failed": failed[-1] if failed else None,
        "state": {k: state[k] for k in ["representation_weights", "architecture_weights", "dataset_mode_weights", "learning_rate_range", "dropout_range", "label_smoothing_range"]},
    }
    write_json(run_dir / "status.json", payload)
    write_csv(run_dir / "leaderboard.csv", sorted(completed, key=lambda row: (row.get("macro_f1") or 0.0, row.get("accuracy") or 0.0), reverse=True))


def maybe_notify(args: argparse.Namespace, messenger: Messenger, state: dict[str, Any], row: dict[str, Any]) -> None:
    completed = len(state["completed"])
    best = state.get("best") or {}
    milestones = set(state.setdefault("milestones_sent", []))
    should = False
    reason = ""
    if completed and completed % args.telegram_every == 0 and completed not in milestones:
        milestones.add(completed)
        should = True
        reason = f"{completed} candidates completed"
    if row.get("candidate_id") == best.get("candidate_id"):
        should = True
        reason = "new best model"
    if should:
        state["milestones_sent"] = sorted(milestones)
        messenger.send(
            [
                f"Run: {args.run_id}",
                f"Reason: {reason}",
                f"Completed: {completed} of {args.max_candidates}",
                f"Failed: {len(state['failed'])}",
                f"Latest: {row.get('dataset_mode')} / {row.get('representation')} / {row.get('architecture')}",
                f"Latest macro-F1: {float(row.get('macro_f1') or 0):.4f}",
                f"Latest accuracy: {float(row.get('accuracy') or 0):.4f}",
                f"Best: {best.get('dataset_mode')} / {best.get('representation')} / {best.get('architecture')}",
                f"Best macro-F1: {float(best.get('macro_f1') or 0):.4f}",
                f"Best accuracy: {float(best.get('accuracy') or 0):.4f}",
            ]
        )


def run(args: argparse.Namespace) -> int:
    args.run_id = args.run_id or f"vibex_ai_family_search_{utc_stamp()}"
    run_dir = Path(args.output_root) / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "model_run.pid").write_text(str(os.getpid()) + "\n", encoding="utf-8")
    manifests = build_manifests(args, run_dir)
    metadata = {
        "run_id": args.run_id,
        "host_label": args.host_label,
        "created_utc": utc_now(),
        "target_candidates": args.max_candidates,
        "dataset_policy": "family_core plus defensible non-generic family_extended >= min_family_rows; benign PE/MZ source groups",
        "split_ratios": [0.8, 0.1, 0.1],
        "ai_policy": "Gemma JSON advice only; allowlist validated; no commands or code edits",
        "manifests": manifests,
    }
    write_json(run_dir / "run_metadata.json", metadata)
    store = SqlStore(args)
    store.init_schema()
    messenger = Messenger(run_dir, args.telegram, args.telegram_timezone, args.quiet_start, args.quiet_end)
    state_path = run_dir / "scheduler_state.json"
    state = load_json(state_path, default_state(args))
    rng = random.Random(args.scheduler_seed)
    store.upsert_run(args.run_id, "running", args.max_candidates, metadata, len(state["completed"]), len(state["failed"]), state.get("best"))
    messenger.send([f"Run: {args.run_id}", "AI-guided VIBEX model search started", f"Target: {args.max_candidates} full candidates", f"Classes/manifests: {len(manifests)} representation-mode manifests"])

    while int(state["next_index"]) <= args.max_candidates:
        candidate = candidate_from_state(args, state, manifests, rng)
        row = run_candidate(args, run_dir, candidate, store)
        if row["status"] == "completed":
            state["completed"].append({k: row.get(k) for k in ["candidate_index", "candidate_id", "dataset_mode", "representation", "architecture", "seed", "learning_rate", "dropout", "label_smoothing", "macro_f1", "weighted_f1", "accuracy", "val_macro_f1", "val_accuracy", "duration_seconds"]})
            best = state.get("best") or {}
            if not best or (row.get("macro_f1") or 0.0, row.get("accuracy") or 0.0) > (best.get("macro_f1") or 0.0, best.get("accuracy") or 0.0):
                state["best"] = state["completed"][-1]
        else:
            state["failed"].append({k: row.get(k) for k in ["candidate_index", "candidate_id", "dataset_mode", "representation", "architecture", "seed", "error_text", "duration_seconds"]})
        state["next_index"] = int(state["next_index"]) + 1
        ask_gemma(args, run_dir, state, store)
        write_json(state_path, state)
        write_status(run_dir, args, state)
        store.upsert_run(args.run_id, "running", args.max_candidates, metadata, len(state["completed"]), len(state["failed"]), state.get("best"))
        maybe_notify(args, messenger, state, row)
        cooldown(args, store, args.run_id, row["candidate_index"])

    store.upsert_run(args.run_id, "completed", args.max_candidates, metadata, len(state["completed"]), len(state["failed"]), state.get("best"))
    messenger.send([f"Run: {args.run_id}", "Search completed", f"Completed: {len(state['completed'])} of {args.max_candidates}", f"Failed: {len(state['failed'])}", f"Best macro-F1: {float((state.get('best') or {}).get('macro_f1') or 0):.4f}", f"Best accuracy: {float((state.get('best') or {}).get('accuracy') or 0):.4f}"])
    messenger.flush()
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run AI-guided VIBEX family and benign-source CNN search on workhorse.")
    parser.add_argument("--run-id")
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/evidence/ai_guided_family_model_search")
    parser.add_argument("--family-core", required=True)
    parser.add_argument("--family-extended", required=True)
    parser.add_argument("--release-manifest", required=True)
    parser.add_argument("--raw-root", default="/home/phil/vibex_secure_dataset/raw/malware_quarantine")
    parser.add_argument("--benign-raw-root", default="/home/phil/vibex_secure_dataset/raw/benign_sources")
    parser.add_argument("--raw-manifest", default="/home/phil/vibex_secure_dataset/derived/manifests/raw_manifest_20260517T190008Z.csv")
    parser.add_argument("--native-runner", required=True)
    parser.add_argument("--max-candidates", type=int, default=2000)
    parser.add_argument("--min-family-rows", type=int, default=20)
    parser.add_argument("--max-malware-rows-per-family", type=int, default=0)
    parser.add_argument("--benign-rows-per-source", type=int, default=300)
    parser.add_argument("--representations", default=",".join(REPRESENTATIONS))
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--scheduler-seed", type=int, default=20260611)
    parser.add_argument("--host-label", default="workhorse")
    parser.add_argument("--ai-interval", type=int, default=25)
    parser.add_argument("--ai-timeout-seconds", type=int, default=180)
    parser.add_argument("--ollama-model", default="gemma2:2b")
    parser.add_argument("--min-cooldown-seconds", type=int, default=25)
    parser.add_argument("--cooldown-poll-seconds", type=int, default=180)
    parser.add_argument("--max-gpu-temp-c", type=float, default=70.0)
    parser.add_argument("--max-gpu-mem-after-run-mib", type=float, default=512.0)
    parser.add_argument("--max-gpu-util-after-run-pct", type=float, default=10.0)
    parser.add_argument("--sql-host", default=os.environ.get("VIBEX_SQL_HOST", os.environ.get("MV2025_DB_HOST", "10.64.0.98")))
    parser.add_argument("--sql-user", default=os.environ.get("VIBEX_SQL_USER", os.environ.get("MV2025_DB_USER", "phil")))
    parser.add_argument("--sql-password", default=os.environ.get("VIBEX_SQL_PASSWORD", os.environ.get("MV2025_DB_PASSWORD", "")))
    parser.add_argument("--sql-database", default=os.environ.get("VIBEX_SQL_DATABASE", os.environ.get("MV2025_DB_NAME", "mv2025_lab")))
    parser.add_argument("--sql-required", action="store_true")
    parser.add_argument("--telegram", action="store_true")
    parser.add_argument("--telegram-every", type=int, default=100)
    parser.add_argument("--telegram-timezone", default="Europe/London")
    parser.add_argument("--quiet-start", type=int, default=22)
    parser.add_argument("--quiet-end", type=int, default=6)
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
