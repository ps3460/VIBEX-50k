#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
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
IMAGE_SIZE = (96, 96)
MAX_FILE_BYTES = 20 * 1024 * 1024
BENIGN_MANIFEST = Path("/home/phil/vibex_secure_dataset/release/VIBEX-50K/manifests/safe_dataset_manifest_VIBEX-50K_20260518T081144Z.csv")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_api_key(path: Path) -> str:
    key = path.read_text(encoding="utf-8").strip()
    if not key:
        raise SystemExit(f"API key file is empty: {path}")
    return key


def post_api(api_key: str, data: dict[str, Any], timeout: float) -> bytes:
    body = urllib.parse.urlencode({key: str(value) for key, value in data.items()}).encode("utf-8")
    request = urllib.request.Request(
        MALWAREBAZAAR_API,
        data=body,
        headers={
            "Auth-Key": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "VIBEX-PlanB-expansion/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def slug(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return text.strip("_") or "unknown"


def load_census(
    path: Path, family_count: int, candidate_cap: int, excluded_families: set[str]
) -> tuple[list[str], dict[str, list[dict[str, Any]]]]:
    report = json.loads(path.read_text(encoding="utf-8"))
    supported = [
        family
        for family in report.get("families", [])
        if int(family.get("pe_like_samples") or 0) >= candidate_cap
        and int(family.get("selected_samples") or 0) >= candidate_cap
        and str(family.get("signature") or "") not in excluded_families
    ]
    supported.sort(key=lambda row: (int(row.get("pe_like_samples") or 0), int(row.get("selected_samples") or 0)), reverse=True)
    families = [str(row["signature"]) for row in supported[:family_count]]
    grouped: dict[str, list[dict[str, Any]]] = {family: [] for family in families}
    seen: set[str] = set()
    for sample in report.get("selected_samples", []):
        family = str(sample.get("signature") or "").strip()
        sha = str(sample.get("sha256_hash") or "").lower()
        if family in grouped and re.fullmatch(r"[0-9a-f]{64}", sha) and sha not in seen:
            grouped[family].append(sample)
            seen.add(sha)
    for family in families:
        grouped[family] = grouped[family][:candidate_cap]
    return families, grouped


def scan_previous_verified(output_root: Path) -> dict[str, dict[str, dict[str, str]]]:
    verified: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for manifest in output_root.glob("*/evidence/*manifest*.csv"):
        try:
            with manifest.open(newline="", encoding="utf-8") as handle:
                for row in csv.DictReader(handle):
                    if row.get("status") != "verified_image":
                        continue
                    family = str(row.get("family") or "").strip()
                    sha = str(row.get("sha256_hash") or row.get("actual_sha256") or "").lower()
                    image_path = Path(str(row.get("image_path") or ""))
                    if family and re.fullmatch(r"[0-9a-f]{64}", sha) and image_path.exists():
                        verified[family][sha] = {
                            "sha256_hash": sha,
                            "family": family,
                            "image_path": str(image_path),
                            "source_run": manifest.parent.parent.name,
                        }
        except Exception:
            continue
    return verified


def scan_previous_attempted(output_root: Path) -> dict[str, set[str]]:
    attempted: dict[str, set[str]] = defaultdict(set)
    for manifest in output_root.glob("*/evidence/*manifest*.csv"):
        try:
            with manifest.open(newline="", encoding="utf-8") as handle:
                for row in csv.DictReader(handle):
                    family = str(row.get("family") or "").strip()
                    sha = str(row.get("sha256_hash") or row.get("actual_sha256") or "").lower()
                    if family and re.fullmatch(r"[0-9a-f]{64}", sha):
                        attempted[family].add(sha)
        except Exception:
            continue
    return attempted


def archive_registry(output_root: Path) -> dict[str, Path]:
    archives: dict[str, Path] = {}
    for path in output_root.glob("*/quarantine/archives/*.zip"):
        sha = path.stem.lower()
        if re.fullmatch(r"[0-9a-f]{64}", sha):
            archives.setdefault(sha, path)
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


def bytes_to_image(data: bytes, output_path: Path) -> None:
    width = int(math.ceil(math.sqrt(len(data))))
    padded = data + b"\x00" * ((width * width) - len(data))
    array = np.frombuffer(padded, dtype=np.uint8).reshape((width, width))
    image = Image.fromarray(array, mode="L").resize(IMAGE_SIZE, Image.Resampling.BILINEAR)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path)


def benign_role(raw_path: str) -> str:
    path = raw_path.lower().replace("\\", "/")
    if "/windows/system32/drivers/" in path or "/windows/syswow64/drivers/" in path:
        return "drivers"
    if "/windows/system32/" in path:
        return "system32"
    if "/windows/syswow64/" in path:
        return "syswow64"
    if "/program files (x86)/" in path:
        return "program_files_x86"
    if "/program files/" in path:
        return "program_files"
    if "/windows/winsxs/" in path:
        return "winsxs"
    if "/windows/servicing/" in path:
        return "servicing"
    if "/boot/" in path or "/efi/" in path:
        return "boot"
    return "other"


def load_benign_rows(limit: int, output_dir: Path) -> list[dict[str, str]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    with BENIGN_MANIFEST.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row.get("binary_label") != "benign":
                continue
            image_path = Path(str(row.get("image_path") or row.get("dataset_image_path") or ""))
            if not image_path.exists():
                continue
            source = str(row.get("source") or "unknown")
            role = benign_role(str(row.get("raw_path") or row.get("dataset_image_path") or row.get("image_path") or ""))
            label = f"{source}::{role}"
            grouped[label].append(
                {
                    "raw_sha256": str(row.get("raw_sha256") or ""),
                    "image_path": str(image_path),
                    "source": source,
                    "role": role,
                    "benign_class": label,
                }
            )
    merged: dict[str, list[dict[str, str]]] = defaultdict(list)
    for label, rows in grouped.items():
        source = label.split("::", 1)[0]
        target = label if len(rows) >= 50 else f"{source}::other"
        for row in rows:
            row["benign_class"] = target
            row["role"] = target.split("::", 1)[1]
            merged[target].append(row)
    rng = random.Random(1337)
    for rows in merged.values():
        rng.shuffle(rows)
    selected: list[dict[str, str]] = []
    labels = sorted(merged)
    index = 0
    while len(selected) < limit and labels:
        label = labels[index % len(labels)]
        rows = merged[label]
        if rows:
            selected.append(rows.pop())
        labels = [item for item in labels if merged[item]]
        index += 1
    linked: list[dict[str, str]] = []
    for row in selected:
        src = Path(row["image_path"])
        dest = output_dir / slug(row["benign_class"]) / src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            dest.symlink_to(src)
        copied = dict(row)
        copied["round_image_path"] = str(dest)
        linked.append(copied)
    return linked


def image_to_array(path: Path) -> np.ndarray:
    image = Image.open(path).convert("L").resize(IMAGE_SIZE, Image.Resampling.BILINEAR)
    return np.asarray(image, dtype=np.float32) / 255.0


def train_cnn(samples: list[tuple[Path, str]], model_name: str, output_dir: Path) -> dict[str, Any]:
    import tensorflow as tf
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
    from sklearn.model_selection import train_test_split

    labels = sorted({label for _, label in samples})
    label_to_id = {label: index for index, label in enumerate(labels)}
    rng = random.Random(1337)
    shuffled = list(samples)
    rng.shuffle(shuffled)
    x = np.stack([image_to_array(path) for path, _ in shuffled], axis=0)[..., np.newaxis]
    y = np.asarray([label_to_id[label] for _, label in shuffled], dtype=np.int64)
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.25, random_state=1337, stratify=y)
    if len(labels) == 2 and model_name == "binary":
        model = tf.keras.Sequential(
            [
                tf.keras.layers.Input(shape=(IMAGE_SIZE[1], IMAGE_SIZE[0], 1)),
                tf.keras.layers.Conv2D(16, 3, activation="relu"),
                tf.keras.layers.MaxPooling2D(),
                tf.keras.layers.Conv2D(32, 3, activation="relu"),
                tf.keras.layers.MaxPooling2D(),
                tf.keras.layers.Flatten(),
                tf.keras.layers.Dense(32, activation="relu"),
                tf.keras.layers.Dropout(0.25),
                tf.keras.layers.Dense(1, activation="sigmoid"),
            ]
        )
        model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
        history = model.fit(x_train, y_train, validation_split=0.2, epochs=3, batch_size=32, verbose=2)
        probs = model.predict(x_test, verbose=0).reshape(-1)
        y_pred = (probs >= 0.5).astype(np.int64)
    else:
        model = tf.keras.Sequential(
            [
                tf.keras.layers.Input(shape=(IMAGE_SIZE[1], IMAGE_SIZE[0], 1)),
                tf.keras.layers.Conv2D(16, 3, activation="relu"),
                tf.keras.layers.MaxPooling2D(),
                tf.keras.layers.Conv2D(32, 3, activation="relu"),
                tf.keras.layers.MaxPooling2D(),
                tf.keras.layers.Flatten(),
                tf.keras.layers.Dense(64, activation="relu"),
                tf.keras.layers.Dropout(0.25),
                tf.keras.layers.Dense(len(labels), activation="softmax"),
            ]
        )
        model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
        history = model.fit(x_train, y_train, validation_split=0.2, epochs=3, batch_size=32, verbose=2)
        y_pred = np.argmax(model.predict(x_test, verbose=0), axis=1)
    cm = confusion_matrix(y_test, y_pred, labels=list(range(len(labels))))
    per_class_f1 = f1_score(y_test, y_pred, labels=list(range(len(labels))), average=None, zero_division=0)
    model_path = output_dir / f"planb_{model_name}_cnn.keras"
    model.save(model_path)
    result = {
        "model_name": model_name,
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "class_count": len(labels),
        "classes": labels,
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "per_class_f1": {label: float(per_class_f1[index]) for index, label in enumerate(labels)},
        "confusion_matrix": cm.astype(int).tolist(),
        "history": {key: [float(item) for item in values] for key, values in history.history.items()},
        "model_path": str(model_path),
        "model_sha256": sha256_file(model_path),
    }
    if model_name == "binary" and labels == ["benign", "malware"]:
        tn, fp, fn, tp = [int(value) for value in cm.ravel()]
        result["confusion"] = {"tn": tn, "fp": fp, "fn": fn, "tp": tp}
        result["benign_false_positive_rate"] = float(fp / (fp + tn)) if (fp + tn) else 0.0
    return result


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run(args: argparse.Namespace) -> dict[str, Any]:
    run_id = args.run_id or f"planb_mb_round{args.round_index}_{utc_stamp()}"
    root = Path(args.output_root) / run_id
    archives = root / "quarantine" / "archives"
    samples_dir = root / "quarantine" / "samples"
    images_dir = root / "images" / "malware"
    benign_dir = root / "images" / "benign"
    evidence_dir = root / "evidence"
    models_dir = root / "models"
    for path in (archives, samples_dir, images_dir, benign_dir, evidence_dir, models_dir):
        path.mkdir(parents=True, exist_ok=True)

    families, grouped_candidates = load_census(
        Path(args.census_json), args.family_count, args.candidate_cap, set(args.exclude_family)
    )
    previous_verified = scan_previous_verified(Path(args.output_root))
    previous_attempted = scan_previous_attempted(Path(args.output_root))
    existing_archives = archive_registry(Path(args.output_root))
    api_key = read_api_key(Path(args.api_key_file))
    rows: list[dict[str, Any]] = []
    counters: Counter[str] = Counter()
    new_verified: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)

    for family in families:
        cumulative = dict(previous_verified.get(family, {}))
        needed = max(0, args.target_per_family - len(cumulative))
        request_budget = min(len(grouped_candidates[family]), int(math.ceil(needed * args.request_multiplier)) + args.request_buffer)
        attempted = 0
        for sample in grouped_candidates[family]:
            if len(cumulative) >= args.target_per_family:
                break
            sha = str(sample["sha256_hash"]).lower()
            if sha in cumulative:
                continue
            if sha in previous_attempted.get(family, set()):
                continue
            if attempted >= request_budget:
                break
            attempted += 1
            archive_path = archives / f"{sha}.zip"
            sample_path = samples_dir / slug(family) / sha
            image_path = images_dir / slug(family) / f"{sha}.png"
            row: dict[str, Any] = {
                "sha256_hash": sha,
                "family": family,
                "archive_path": str(archive_path),
                "sample_path": str(sample_path),
                "image_path": str(image_path),
                "round_index": args.round_index,
            }
            try:
                if not archive_path.exists():
                    source_archive = existing_archives.get(sha)
                    if source_archive and source_archive.exists():
                        shutil.copy2(source_archive, archive_path)
                        row["archive_source"] = str(source_archive)
                    else:
                        archive_path.write_bytes(post_api(api_key, {"query": "get_file", "sha256_hash": sha}, args.timeout))
                        row["archive_source"] = "malwarebazaar_api"
                        time.sleep(args.sleep_seconds)
                data, extract_status = extract_single_file(archive_path)
                row["extract_status"] = extract_status
                if extract_status != "ok" or data is None:
                    row["status"] = extract_status
                    counters[extract_status] += 1
                    rows.append(row)
                    continue
                actual_sha = sha256_bytes(data)
                row["actual_sha256"] = actual_sha
                row["file_bytes"] = len(data)
                if actual_sha != sha:
                    row["status"] = "reject_sha256_mismatch"
                    counters[row["status"]] += 1
                    rows.append(row)
                    continue
                sample_path.parent.mkdir(parents=True, exist_ok=True)
                sample_path.write_bytes(data)
                bytes_to_image(data, image_path)
                row["status"] = "verified_image"
                counters["verified_image"] += 1
                record = {"sha256_hash": sha, "family": family, "image_path": str(image_path), "source_run": run_id}
                cumulative[sha] = record
                new_verified[family][sha] = record
            except Exception as exc:
                row["status"] = f"error:{type(exc).__name__}"
                row["error"] = str(exc)[:300]
                counters["error"] += 1
            rows.append(row)

    cumulative_verified: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for family in families:
        cumulative_verified[family].update(previous_verified.get(family, {}))
        cumulative_verified[family].update(new_verified.get(family, {}))
    malware_samples: list[tuple[Path, str]] = []
    malware_family_samples: list[tuple[Path, str]] = []
    for family in families:
        for record in list(cumulative_verified[family].values())[: args.target_per_family]:
            path = Path(record["image_path"])
            if path.exists():
                malware_samples.append((path, "malware"))
                malware_family_samples.append((path, family))

    benign_rows = load_benign_rows(len(malware_samples), benign_dir)
    benign_samples_binary = [(Path(row["round_image_path"]), "benign") for row in benign_rows]
    mixed_samples = [(path, f"malware::{label}") for path, label in malware_family_samples] + [
        (Path(row["round_image_path"]), f"benign::{row['benign_class']}") for row in benign_rows
    ]

    model_results: dict[str, Any] = {}
    if len(malware_samples) >= 20 and len(benign_samples_binary) >= 20:
        model_results["binary"] = train_cnn(malware_samples + benign_samples_binary, "binary", models_dir)
    if len(malware_family_samples) >= args.family_count * 10:
        model_results["malware_family"] = train_cnn(malware_family_samples, "malware_family", models_dir)
    if len(mixed_samples) >= 40:
        model_results["mixed_multiclass"] = train_cnn(mixed_samples, "mixed_multiclass", models_dir)

    manifest_path = evidence_dir / "planb_round_manifest.csv"
    benign_path = evidence_dir / "planb_benign_classes.csv"
    metrics_path = evidence_dir / "planb_model_metrics.json"
    write_csv(manifest_path, rows)
    write_csv(benign_path, benign_rows)
    metrics_path.write_text(json.dumps(model_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    family_counts = {family: min(len(cumulative_verified[family]), args.target_per_family) for family in families}
    report = {
        "run_id": run_id,
        "round_index": args.round_index,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": str(root),
        "census_json": str(args.census_json),
        "target_per_family": args.target_per_family,
        "family_count": len(families),
        "families": family_counts,
        "new_verified_images": sum(len(items) for items in new_verified.values()),
        "cumulative_verified_images": sum(family_counts.values()),
        "downloaded_archives_in_run": len(list(archives.glob("*.zip"))),
        "status_counts": dict(counters),
        "benign_rows": len(benign_rows),
        "benign_classes": dict(Counter(row["benign_class"] for row in benign_rows)),
        "model_results": model_results,
        "artifacts": {
            "manifest_csv": str(manifest_path),
            "benign_classes_csv": str(benign_path),
            "model_metrics_json": str(metrics_path),
        },
    }
    report_path = evidence_dir / "planb_round_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "run_id": run_id,
                "report_path": str(report_path),
                "family_count": len(families),
                "target_per_family": args.target_per_family,
                "new_verified_images": report["new_verified_images"],
                "cumulative_verified_images": report["cumulative_verified_images"],
                "benign_rows": len(benign_rows),
                "models": sorted(model_results),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Expand MalwareBazaar Plan B rounds and train CNNs.")
    parser.add_argument("--census-json", required=True)
    parser.add_argument("--api-key-file", required=True)
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--round-index", type=int, required=True)
    parser.add_argument("--family-count", type=int, default=10)
    parser.add_argument("--exclude-family", action="append", default=[])
    parser.add_argument("--target-per-family", type=int, required=True)
    parser.add_argument("--candidate-cap", type=int, default=120)
    parser.add_argument("--request-multiplier", type=float, default=1.15)
    parser.add_argument("--request-buffer", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--sleep-seconds", type=float, default=0.2)
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
