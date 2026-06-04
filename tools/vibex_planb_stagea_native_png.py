#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image


MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = "infected"
MAX_FILE_BYTES = 20 * 1024 * 1024
PE_FILE_TYPES = {"exe", "dll", "msi", "scr", "sys", "cab"}
PE_TAGS = {"exe", "dll", "pe", "win32", "win64", "windows", "msi"}


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def slug(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return text.strip("_") or "unknown"


def read_api_key(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() in {"MALWAREBAZAAR_API_KEY", "MB_API_KEY", "API_KEY"}:
            return value.strip().strip("\"'")
    return text.strip().strip("\"'")


def post_api(api_key: str, data: dict[str, Any], timeout: float) -> dict[str, Any] | bytes:
    body = urllib.parse.urlencode({key: str(value) for key, value in data.items()}).encode("utf-8")
    request = urllib.request.Request(
        MALWAREBAZAAR_API,
        data=body,
        headers={
            "Auth-Key": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "VIBEX-PlanB-stageA-native-png/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read()
    if data.get("query") == "get_file":
        return payload
    return json.loads(payload.decode("utf-8"))


def data_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    data = payload.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def is_pe_like(item: dict[str, Any]) -> bool:
    file_type = str(item.get("file_type") or item.get("file_format") or "").strip().lower()
    mime = str(item.get("file_type_mime") or "").strip().lower()
    tags = {str(tag).strip().lower() for tag in item.get("tags") or []}
    file_name = str(item.get("file_name") or "").strip().lower()
    if file_type in PE_FILE_TYPES:
        return True
    if "pe32" in file_type or "pe32+" in file_type:
        return True
    if "application/x-dosexec" in mime or "msdownload" in mime:
        return True
    if tags & PE_TAGS:
        return True
    return bool(re.search(r"\.(exe|dll|msi|scr|sys)$", file_name))


def safe_sample(item: dict[str, Any], family: str) -> dict[str, str]:
    tags = item.get("tags") or []
    if isinstance(tags, list):
        tag_text = ",".join(str(tag) for tag in tags)
    else:
        tag_text = str(tags)
    return {
        "sha256_hash": str(item.get("sha256_hash") or "").lower(),
        "family": family,
        "file_type": str(item.get("file_type") or item.get("file_format") or ""),
        "file_type_mime": str(item.get("file_type_mime") or ""),
        "first_seen": str(item.get("first_seen") or ""),
        "last_seen": str(item.get("last_seen") or ""),
        "file_size": str(item.get("file_size") or ""),
        "imphash": str(item.get("imphash") or ""),
        "tlsh": str(item.get("tlsh") or ""),
        "tags": tag_text,
    }


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row}) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        if not fieldnames:
            return
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def scan_previous(output_root: Path, families: set[str]) -> tuple[dict[str, dict[str, dict[str, str]]], dict[str, set[str]]]:
    verified: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    attempted: dict[str, set[str]] = defaultdict(set)
    for manifest in output_root.glob("*/evidence/*manifest*.csv"):
        try:
            rows = read_csv(manifest)
        except Exception:
            continue
        for row in rows:
            family = str(row.get("family") or "").strip()
            sha = str(row.get("sha256_hash") or row.get("actual_sha256") or "").lower()
            if family not in families or not re.fullmatch(r"[0-9a-f]{64}", sha):
                continue
            attempted[family].add(sha)
            if row.get("status") != "verified_image":
                continue
            sample_path = str(row.get("sample_path") or "")
            archive_path = str(row.get("archive_path") or "")
            verified[family][sha] = {
                "sha256_hash": sha,
                "family": family,
                "sample_path": sample_path,
                "archive_path": archive_path,
                "source_manifest": str(manifest),
                "file_bytes": str(row.get("file_bytes") or ""),
                "imphash": str(row.get("imphash") or ""),
                "tlsh": str(row.get("tlsh") or ""),
            }
    return verified, attempted


def archive_registry(output_root: Path) -> dict[str, Path]:
    archives: dict[str, Path] = {}
    for path in output_root.glob("*/quarantine/archives/*.zip"):
        if re.fullmatch(r"[0-9a-f]{64}", path.stem.lower()):
            archives.setdefault(path.stem.lower(), path)
    return archives


def extract_single_file(zip_path: Path) -> tuple[bytes | None, str]:
    tool = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
    if not tool:
        return None, "reject_missing_7z"
    extract_root = zip_path.parent / f".extract_{zip_path.stem}"
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [tool, "x", f"-p{ZIP_PASSWORD}", "-y", "-bd", f"-o{extract_root}", str(zip_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            return None, f"reject_7z_exit:{result.returncode}"
        files = [path for path in extract_root.rglob("*") if path.is_file()]
        if len(files) != 1:
            return None, f"reject_archive_file_count:{len(files)}"
        file_path = files[0]
        size = file_path.stat().st_size
        if size <= 0:
            return None, "reject_empty_file"
        if size > MAX_FILE_BYTES:
            return None, f"reject_oversize:{size}"
        return file_path.read_bytes(), "ok"
    finally:
        shutil.rmtree(extract_root, ignore_errors=True)


def raw_bytes_for(record: dict[str, str]) -> bytes | None:
    sample_path = Path(record.get("sample_path") or "")
    if sample_path.exists() and sample_path.is_file():
        return sample_path.read_bytes()
    archive_path = Path(record.get("archive_path") or "")
    if archive_path.exists() and archive_path.is_file():
        data, status = extract_single_file(archive_path)
        if status == "ok":
            return data
    return None


def bytes_to_png(data: bytes, output_path: Path, size: int, mode: str, resize_method: str) -> dict[str, Any]:
    resampling = getattr(Image.Resampling, resize_method.upper())
    if mode == "gray":
        source_width = int(math.ceil(math.sqrt(len(data))))
        padded = data + b"\x00" * ((source_width * source_width) - len(data))
        array = np.frombuffer(padded, dtype=np.uint8).reshape((source_width, source_width))
        image = Image.fromarray(array, mode="L")
    elif mode == "rgb_triplet":
        source_width = int(math.ceil(math.sqrt(len(data) / 3)))
        padded = data + b"\x00" * ((source_width * source_width * 3) - len(data))
        array = np.frombuffer(padded, dtype=np.uint8).reshape((source_width, source_width, 3))
        image = Image.fromarray(array, mode="RGB")
    else:
        raise ValueError(f"unsupported image mode: {mode}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.resize((size, size), resampling).save(output_path)
    return {
        "source_byte_width": source_width,
        "image_sha256": sha256_file(output_path),
        "image_generation": f"byte_square_{mode}",
        "resize_method": resize_method.lower(),
    }


def fetch_candidates(api_key: str, families: list[str], limit: int, timeout: float, sleep_seconds: float) -> tuple[dict[str, list[dict[str, str]]], dict[str, str]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    statuses: dict[str, str] = {}
    for index, family in enumerate(families, start=1):
        payload = post_api(api_key, {"query": "get_siginfo", "signature": family, "limit": limit}, timeout)
        assert isinstance(payload, dict)
        statuses[family] = str(payload.get("query_status") or "")
        seen: set[str] = set()
        rows: list[dict[str, str]] = []
        for item in data_items(payload):
            sha = str(item.get("sha256_hash") or "").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", sha) or sha in seen or not is_pe_like(item):
                continue
            rows.append(safe_sample(item, family))
            seen.add(sha)
        grouped[family] = rows
        if sleep_seconds and index < len(families):
            time.sleep(sleep_seconds)
    return grouped, statuses


def families_from_source_report(source_report: dict[str, Any]) -> list[str]:
    raw = source_report.get("families") or {}
    if isinstance(raw, dict):
        return sorted(str(key) for key in raw if str(key).strip())
    if isinstance(raw, list):
        families = []
        for item in raw:
            if isinstance(item, dict):
                signature = str(item.get("signature") or "").strip()
                selected = int(item.get("selected_samples") or item.get("pe_like_samples") or 0)
                if signature and selected > 0:
                    families.append(signature)
            else:
                signature = str(item or "").strip()
                if signature:
                    families.append(signature)
        return sorted(dict.fromkeys(families))
    return []


def count_executable_files(path: Path) -> int:
    count = 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and item.stat().st_mode & 0o111:
                count += 1
        except OSError:
            continue
    return count


def run(args: argparse.Namespace) -> dict[str, Any]:
    source_report = json.loads(Path(args.source_report).read_text(encoding="utf-8"))
    families = args.families or families_from_source_report(source_report)
    if not families:
        raise SystemExit("No families supplied or found in source report")
    run_id = args.run_id or f"planb_stagea_native_{utc_stamp()}"
    output_root = Path(args.output_root)
    root = output_root / run_id
    archives_dir = root / "quarantine" / "archives"
    samples_dir = root / "quarantine" / "samples"
    images_dir = root / "images" / "native"
    evidence_dir = root / "evidence"
    for path in (archives_dir, samples_dir, images_dir, evidence_dir):
        path.mkdir(parents=True, exist_ok=True)

    api_key = read_api_key(Path(args.api_key_file))
    previous_verified, previous_attempted = scan_previous(output_root, set(families))
    archives = archive_registry(output_root)
    candidates, query_statuses = fetch_candidates(api_key, families, args.metadata_limit, args.timeout, args.sleep_seconds)

    download_rows: list[dict[str, Any]] = []
    verified: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for family in families:
        verified[family].update(previous_verified.get(family, {}))
        needed = max(0, args.target_per_family - len(verified[family]))
        budget = int(math.ceil(needed * args.request_multiplier)) + args.request_buffer
        attempted = 0
        for candidate in candidates.get(family, []):
            if len(verified[family]) >= args.target_per_family or attempted >= budget:
                break
            sha = candidate["sha256_hash"]
            if sha in verified[family] or sha in previous_attempted.get(family, set()):
                continue
            attempted += 1
            archive_path = archives_dir / f"{sha}.zip"
            sample_path = samples_dir / slug(family) / sha
            row: dict[str, Any] = dict(candidate)
            row.update({"archive_path": str(archive_path), "sample_path": str(sample_path), "round": "stage_a"})
            try:
                if not archive_path.exists():
                    source_archive = archives.get(sha)
                    if source_archive and source_archive.exists():
                        shutil.copy2(source_archive, archive_path)
                        row["archive_source"] = str(source_archive)
                    else:
                        payload = post_api(api_key, {"query": "get_file", "sha256_hash": sha}, args.timeout)
                        assert isinstance(payload, bytes)
                        archive_path.write_bytes(payload)
                        archive_path.chmod(0o640)
                        row["archive_source"] = "malwarebazaar_api"
                        if args.sleep_seconds:
                            time.sleep(args.sleep_seconds)
                data, extract_status = extract_single_file(archive_path)
                row["extract_status"] = extract_status
                if extract_status != "ok" or data is None:
                    row["status"] = extract_status
                    download_rows.append(row)
                    continue
                actual_sha = sha256_bytes(data)
                row["actual_sha256"] = actual_sha
                row["file_bytes"] = len(data)
                if actual_sha != sha:
                    row["status"] = "reject_sha256_mismatch"
                    download_rows.append(row)
                    continue
                sample_path.parent.mkdir(parents=True, exist_ok=True)
                sample_path.write_bytes(data)
                sample_path.chmod(0o640)
                row["status"] = "verified_image"
                verified[family][sha] = {
                    "sha256_hash": sha,
                    "family": family,
                    "sample_path": str(sample_path),
                    "archive_path": str(archive_path),
                    "file_bytes": str(len(data)),
                    "imphash": candidate.get("imphash", ""),
                    "tlsh": candidate.get("tlsh", ""),
                }
            except Exception as exc:
                row["status"] = f"error:{type(exc).__name__}"
                row["error"] = str(exc)[:300]
            download_rows.append(row)

    image_rows: list[dict[str, Any]] = []
    missing_raw: list[dict[str, str]] = []
    for family in families:
        records = [verified[family][sha] for sha in sorted(verified[family])[: args.target_per_family]]
        for record in records:
            data = raw_bytes_for(record)
            if data is None:
                missing_raw.append(record)
                continue
            for mode in args.image_modes:
                for size in args.image_sizes:
                    output_path = images_dir / mode / str(size) / slug(family) / f"{record['sha256_hash']}.png"
                    info = bytes_to_png(data, output_path, size, mode, args.resize_method)
                    image_rows.append(
                        {
                            "sha256_hash": record["sha256_hash"],
                            "family": family,
                            "image_mode": mode,
                            "image_size": size,
                            "image_path": str(output_path),
                            "source_bytes": len(data),
                            "sample_path": record.get("sample_path", ""),
                            "archive_path": record.get("archive_path", ""),
                            "imphash": record.get("imphash", ""),
                            "tlsh": record.get("tlsh", ""),
                            **info,
                        }
                    )

    family_counts = {family: min(len(verified[family]), args.target_per_family) for family in families}
    audit_rows = []
    for family in families:
        records = [verified[family][sha] for sha in sorted(verified[family])[: args.target_per_family]]
        imphashes = [row.get("imphash", "") for row in records if row.get("imphash")]
        tlsh_values = [row.get("tlsh", "") for row in records if row.get("tlsh")]
        byte_sizes = [row.get("file_bytes", "") for row in records if row.get("file_bytes")]
        audit_rows.append(
            {
                "family": family,
                "verified_rows": len(records),
                "candidate_rows": len(candidates.get(family, [])),
                "metadata_query_status": query_statuses.get(family, ""),
                "unique_imphash": len(set(imphashes)),
                "unique_tlsh": len(set(tlsh_values)),
                "unique_file_sizes": len(set(byte_sizes)),
                "duplicate_imphash_groups": sum(1 for count in Counter(imphashes).values() if count > 1),
                "duplicate_tlsh_groups": sum(1 for count in Counter(tlsh_values).values() if count > 1),
            }
        )

    write_csv(evidence_dir / "planb_stagea_download_manifest.csv", download_rows)
    write_csv(evidence_dir / "planb_stagea_native_png_manifest.csv", image_rows)
    write_csv(evidence_dir / "planb_stagea_family_audit.csv", audit_rows)
    report = {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": str(root),
        "source_report": str(args.source_report),
        "target_per_family": args.target_per_family,
        "families": family_counts,
        "family_count": len(families),
        "verified_malware_rows": sum(family_counts.values()),
        "native_png_rows": len(image_rows),
        "image_sizes": args.image_sizes,
        "image_modes": args.image_modes,
        "image_generation": "byte_square_native_from_verified_raw_bytes",
        "resize_method": args.resize_method.lower(),
        "metadata_query_statuses": query_statuses,
        "download_status_counts": dict(Counter(str(row.get("status") or "") for row in download_rows)),
        "missing_raw_count": len(missing_raw),
        "quarantine_executable_file_count": count_executable_files(root / "quarantine"),
        "artifacts": {
            "download_manifest_csv": str(evidence_dir / "planb_stagea_download_manifest.csv"),
            "native_png_manifest_csv": str(evidence_dir / "planb_stagea_native_png_manifest.csv"),
            "family_audit_csv": str(evidence_dir / "planb_stagea_family_audit.csv"),
            "report_json": str(evidence_dir / "planb_stagea_report.json"),
        },
    }
    (evidence_dir / "planb_stagea_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Plan B Stage A Native PNG Dataset",
        "",
        f"- Run ID: `{run_id}`",
        f"- Verified malware rows: `{report['verified_malware_rows']}`",
        f"- Native PNG rows: `{report['native_png_rows']}`",
        f"- Image sizes: `{', '.join(str(size) for size in args.image_sizes)}`",
        f"- Image modes: `{', '.join(args.image_modes)}`",
        f"- Resize method: `{args.resize_method.lower()}`",
        "- Raw malware remains in workhorse quarantine only.",
        "",
        "## Family Counts",
        "",
    ]
    for family, count in sorted(family_counts.items()):
        lines.append(f"- `{family}`: `{count}`")
    (evidence_dir / "planb_stagea_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"run_id": run_id, "root": str(root), "report": report["artifacts"]["report_json"]}, indent=2, sort_keys=True))
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Plan B Stage A native byte-PNG dataset at higher resolutions.")
    parser.add_argument("--source-report", default="/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb/planb_mb_round3_20260604T133000Z/evidence/planb_round_report.json")
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb")
    parser.add_argument("--api-key-file", default="/home/phil/vibex_secure_dataset/secrets/family-api-keys.env")
    parser.add_argument("--run-id")
    parser.add_argument("--families", type=lambda value: [item.strip() for item in value.split(",") if item.strip()], default=None)
    parser.add_argument("--target-per-family", type=int, default=300)
    parser.add_argument("--metadata-limit", type=int, default=1000)
    parser.add_argument("--request-multiplier", type=float, default=1.6)
    parser.add_argument("--request-buffer", type=int, default=40)
    parser.add_argument("--image-sizes", type=lambda value: [int(item) for item in value.split(",") if item.strip()], default=[256, 512, 1024])
    parser.add_argument("--image-modes", type=lambda value: [item.strip() for item in value.split(",") if item.strip()], default=["gray", "rgb_triplet"])
    parser.add_argument("--resize-method", default="bilinear", choices=["nearest", "bilinear", "bicubic", "lanczos"])
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--sleep-seconds", type=float, default=0.15)
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
