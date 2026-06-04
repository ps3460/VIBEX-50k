#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEED = 1337
DEFAULT_ARCHITECTURES = [
    "tiny_cnn",
    "baseline_cnn",
    "deep_cnn_bn",
    "wide_cnn",
    "separable_cnn",
    "residual_small",
    "inception_small",
    "dense_small",
    "mobilenetv2_scratch",
    "efficientnetb0_scratch",
]


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def slug(value: str) -> str:
    clean = "".join(char if char.isalnum() or char in "._-" else "_" for char in value.strip())
    return clean.strip("_") or "unknown"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})


def load_source_report(source_root: Path) -> dict[str, Any]:
    report_path = source_root / "evidence" / "planb_round_report.json"
    if report_path.exists():
        return json.loads(report_path.read_text(encoding="utf-8"))
    reports = sorted((source_root / "evidence").glob("*report*.json"))
    if reports:
        return json.loads(reports[-1].read_text(encoding="utf-8"))
    raise SystemExit(f"No Plan B report found under {source_root / 'evidence'}")


def scan_verified_malware(planb_root: Path, families: list[str], target_per_family: int) -> list[dict[str, str]]:
    family_set = set(families)
    grouped: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for manifest in sorted(planb_root.glob("*/evidence/*manifest*.csv")):
        for row in read_csv(manifest):
            if row.get("status") != "verified_image":
                continue
            family = str(row.get("family") or "").strip()
            sha = str(row.get("sha256_hash") or row.get("actual_sha256") or "").lower()
            image_path = Path(str(row.get("image_path") or ""))
            if family not in family_set or len(sha) != 64 or not image_path.exists():
                continue
            grouped[family][sha] = {
                "kind": "malware",
                "sha256": sha,
                "class_label": family,
                "binary_label": "malware",
                "family": family,
                "image_path": str(image_path),
                "source_manifest": str(manifest),
            }
    selected: list[dict[str, str]] = []
    shortfalls: dict[str, int] = {}
    for family in families:
        rows = [grouped[family][sha] for sha in sorted(grouped[family])[:target_per_family]]
        if len(rows) < target_per_family:
            shortfalls[family] = target_per_family - len(rows)
        selected.extend(rows)
    if shortfalls:
        raise SystemExit(f"Insufficient verified malware images for sweep: {shortfalls}")
    return selected


def load_benign(source_root: Path, count: int) -> list[dict[str, str]]:
    benign_csv = source_root / "evidence" / "planb_benign_classes.csv"
    rows = []
    for row in read_csv(benign_csv):
        image_path = Path(str(row.get("round_image_path") or row.get("image_path") or ""))
        if not image_path.exists():
            continue
        label = str(row.get("benign_class") or "benign::unknown")
        rows.append(
            {
                "kind": "benign",
                "sha256": str(row.get("raw_sha256") or ""),
                "class_label": label,
                "binary_label": "benign",
                "family": "",
                "image_path": str(image_path),
                "source": str(row.get("source") or ""),
                "role": str(row.get("role") or ""),
            }
        )
    if len(rows) < count:
        raise SystemExit(f"Need {count} benign rows, found {len(rows)}")
    rng = random.Random(SEED)
    rng.shuffle(rows)
    return rows[:count]


def build_tasks(malware: list[dict[str, str]], benign: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    binary = []
    for row in malware:
        item = dict(row)
        item["task_label"] = "malware"
        binary.append(item)
    for row in benign:
        item = dict(row)
        item["task_label"] = "benign"
        binary.append(item)

    malware_family = []
    for row in malware:
        item = dict(row)
        item["task_label"] = row["family"]
        malware_family.append(item)

    mixed = []
    for row in malware:
        item = dict(row)
        item["task_label"] = f"malware::{row['family']}"
        mixed.append(item)
    for row in benign:
        item = dict(row)
        item["task_label"] = f"benign::{row['class_label']}"
        mixed.append(item)
    return {"binary": binary, "malware_family": malware_family, "mixed_multiclass": mixed}


def stratified_split(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row["task_label"]].append(row)
    split = {"train": [], "val": [], "test": []}
    rng = random.Random(SEED)
    for label in sorted(grouped):
        items = list(grouped[label])
        rng.shuffle(items)
        n = len(items)
        test_n = max(1, round(n * 0.15))
        val_n = max(1, round(n * 0.15))
        train_n = n - test_n - val_n
        if train_n <= 0:
            raise SystemExit(f"Class {label} has too few rows for split: {n}")
        split["test"].extend(items[:test_n])
        split["val"].extend(items[test_n : test_n + val_n])
        split["train"].extend(items[test_n + val_n :])
    for values in split.values():
        rng.shuffle(values)
    return split


def batch_size_for(image_size: int, architecture: str) -> int:
    if image_size >= 1024:
        return 1 if "efficientnet" in architecture else 2
    if image_size >= 512:
        return 4
    if image_size >= 256:
        return 8
    return 32


def make_tf_dataset(rows: list[dict[str, str]], label_to_id: dict[str, int], image_size: int, batch_size: int, shuffle: bool):
    import tensorflow as tf

    paths = [row["image_path"] for row in rows]
    labels = [label_to_id[row["task_label"]] for row in rows]
    dataset = tf.data.Dataset.from_tensor_slices((paths, labels))
    if shuffle:
        dataset = dataset.shuffle(buffer_size=len(rows), seed=SEED, reshuffle_each_iteration=True)

    def load_image(path, label):
        image = tf.io.read_file(path)
        image = tf.image.decode_png(image, channels=1)
        image = tf.image.resize(image, [image_size, image_size], method="bilinear")
        image = tf.cast(image, tf.float32) / 255.0
        return image, label

    return dataset.map(load_image, num_parallel_calls=tf.data.AUTOTUNE).batch(batch_size).prefetch(tf.data.AUTOTUNE)


def conv_block(tf, x, filters: int, separable: bool = False, batch_norm: bool = False):
    layer = tf.keras.layers.SeparableConv2D if separable else tf.keras.layers.Conv2D
    x = layer(filters, 3, padding="same", use_bias=not batch_norm)(x)
    if batch_norm:
        x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.Activation("relu")(x)
    return x


def build_model(architecture: str, image_size: int, class_count: int, binary: bool):
    import tensorflow as tf

    inputs = tf.keras.Input(shape=(image_size, image_size, 1))
    if architecture == "tiny_cnn":
        x = conv_block(tf, inputs, 16)
        x = tf.keras.layers.MaxPooling2D()(x)
        x = conv_block(tf, x, 32)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(32, activation="relu")(x)
    elif architecture == "baseline_cnn":
        x = conv_block(tf, inputs, 24)
        x = tf.keras.layers.MaxPooling2D()(x)
        x = conv_block(tf, x, 48)
        x = tf.keras.layers.MaxPooling2D()(x)
        x = conv_block(tf, x, 96)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(96, activation="relu")(x)
    elif architecture == "deep_cnn_bn":
        x = inputs
        for filters in (24, 48, 96, 128):
            x = conv_block(tf, x, filters, batch_norm=True)
            x = conv_block(tf, x, filters, batch_norm=True)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(128, activation="relu")(x)
    elif architecture == "wide_cnn":
        x = conv_block(tf, inputs, 48)
        x = tf.keras.layers.MaxPooling2D()(x)
        x = conv_block(tf, x, 96)
        x = tf.keras.layers.MaxPooling2D()(x)
        x = conv_block(tf, x, 192)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(160, activation="relu")(x)
    elif architecture == "separable_cnn":
        x = inputs
        for filters in (32, 64, 128, 192):
            x = conv_block(tf, x, filters, separable=True, batch_norm=True)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(128, activation="relu")(x)
    elif architecture == "residual_small":
        x = tf.keras.layers.Conv2D(32, 3, padding="same", activation="relu")(inputs)
        for filters in (32, 64, 128):
            shortcut = tf.keras.layers.Conv2D(filters, 1, strides=2, padding="same")(x)
            y = tf.keras.layers.Conv2D(filters, 3, strides=2, padding="same", activation="relu")(x)
            y = tf.keras.layers.Conv2D(filters, 3, padding="same")(y)
            x = tf.keras.layers.Activation("relu")(tf.keras.layers.Add()([shortcut, y]))
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(128, activation="relu")(x)
    elif architecture == "inception_small":
        x = tf.keras.layers.Conv2D(32, 3, padding="same", activation="relu")(inputs)
        for filters in (32, 64, 96):
            a = tf.keras.layers.Conv2D(filters, 1, padding="same", activation="relu")(x)
            b = tf.keras.layers.Conv2D(filters, 3, padding="same", activation="relu")(x)
            c = tf.keras.layers.Conv2D(filters, 5, padding="same", activation="relu")(x)
            x = tf.keras.layers.Concatenate()([a, b, c])
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(128, activation="relu")(x)
    elif architecture == "dense_small":
        x = tf.keras.layers.Conv2D(32, 3, padding="same", activation="relu")(inputs)
        for filters in (32, 48, 64):
            y = tf.keras.layers.Conv2D(filters, 3, padding="same", activation="relu")(x)
            x = tf.keras.layers.Concatenate()([x, y])
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(128, activation="relu")(x)
    elif architecture == "mobilenetv2_scratch":
        rgb = tf.keras.layers.Concatenate()([inputs, inputs, inputs])
        base = tf.keras.applications.MobileNetV2(
            input_shape=(image_size, image_size, 3),
            include_top=False,
            weights=None,
            alpha=0.35,
            pooling="avg",
        )
        x = base(rgb)
        x = tf.keras.layers.Dense(128, activation="relu")(x)
    elif architecture == "efficientnetb0_scratch":
        rgb = tf.keras.layers.Concatenate()([inputs, inputs, inputs])
        base = tf.keras.applications.EfficientNetB0(
            input_shape=(image_size, image_size, 3),
            include_top=False,
            weights=None,
            pooling="avg",
        )
        x = base(rgb, training=True)
        x = tf.keras.layers.Dense(128, activation="relu")(x)
    else:
        raise ValueError(f"Unknown architecture: {architecture}")
    x = tf.keras.layers.Dropout(0.25)(x)
    if binary:
        outputs = tf.keras.layers.Dense(1, activation="sigmoid")(x)
        loss = "binary_crossentropy"
    else:
        outputs = tf.keras.layers.Dense(class_count, activation="softmax")(x)
        loss = "sparse_categorical_crossentropy"
    model = tf.keras.Model(inputs, outputs, name=f"{architecture}_{image_size}")
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3), loss=loss, metrics=["accuracy"])
    return model


def train_one(
    task: str,
    architecture: str,
    image_size: int,
    split: dict[str, list[dict[str, str]]],
    output_root: Path,
    epochs: int,
) -> dict[str, Any]:
    import numpy as np
    import tensorflow as tf
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

    labels = sorted({row["task_label"] for rows in split.values() for row in rows})
    label_to_id = {label: index for index, label in enumerate(labels)}
    is_binary = labels == ["benign", "malware"]
    batch_size = batch_size_for(image_size, architecture)
    run_name = f"{task}_{architecture}_{image_size}"
    model_dir = output_root / "models" / run_name
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / f"{run_name}.keras"
    start = time.time()
    result: dict[str, Any] = {
        "task": task,
        "architecture": architecture,
        "image_size": image_size,
        "class_count": len(labels),
        "classes": labels,
        "train_rows": len(split["train"]),
        "val_rows": len(split["val"]),
        "test_rows": len(split["test"]),
        "batch_size": batch_size,
        "status": "running",
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        tf.keras.backend.clear_session()
        train_ds = make_tf_dataset(split["train"], label_to_id, image_size, batch_size, shuffle=True)
        val_ds = make_tf_dataset(split["val"], label_to_id, image_size, batch_size, shuffle=False)
        test_ds = make_tf_dataset(split["test"], label_to_id, image_size, batch_size, shuffle=False)
        model = build_model(architecture, image_size, len(labels), is_binary)
        result["param_count"] = int(model.count_params())
        history = model.fit(
            train_ds,
            validation_data=val_ds,
            epochs=epochs,
            verbose=2,
            callbacks=[tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=1, restore_best_weights=True)],
        )
        predict_start = time.time()
        predictions = model.predict(test_ds, verbose=0)
        result["predict_seconds"] = round(time.time() - predict_start, 3)
        y_true = np.asarray([label_to_id[row["task_label"]] for row in split["test"]], dtype=np.int64)
        if is_binary:
            y_pred = (predictions.reshape(-1) >= 0.5).astype(np.int64)
        else:
            y_pred = np.argmax(predictions, axis=1)
        cm = confusion_matrix(y_true, y_pred, labels=list(range(len(labels))))
        per_class = f1_score(y_true, y_pred, labels=list(range(len(labels))), average=None, zero_division=0)
        model.save(model_path)
        result.update(
            {
                "status": "completed",
                "accuracy": float(accuracy_score(y_true, y_pred)),
                "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
                "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
                "per_class_f1": {label: float(per_class[index]) for index, label in enumerate(labels)},
                "confusion_matrix": cm.astype(int).tolist(),
                "history": {key: [float(item) for item in values] for key, values in history.history.items()},
                "model_path": str(model_path),
                "model_sha256": sha256_file(model_path),
                "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
        if is_binary:
            tn, fp, fn, tp = [int(value) for value in cm.ravel()]
            result["confusion"] = {"tn": tn, "fp": fp, "fn": fn, "tp": tp}
            result["benign_false_positive_rate"] = float(fp / (fp + tn)) if (fp + tn) else 0.0
    except Exception as exc:
        result.update(
            {
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc)[:800],
                "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
    finally:
        result["train_seconds"] = round(time.time() - start, 3)
    return result


def safe_result_row(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "task": result.get("task"),
        "architecture": result.get("architecture"),
        "image_size": result.get("image_size"),
        "status": result.get("status"),
        "accuracy": result.get("accuracy"),
        "macro_f1": result.get("macro_f1"),
        "weighted_f1": result.get("weighted_f1"),
        "benign_false_positive_rate": result.get("benign_false_positive_rate"),
        "train_rows": result.get("train_rows"),
        "val_rows": result.get("val_rows"),
        "test_rows": result.get("test_rows"),
        "class_count": result.get("class_count"),
        "param_count": result.get("param_count"),
        "batch_size": result.get("batch_size"),
        "train_seconds": result.get("train_seconds"),
        "predict_seconds": result.get("predict_seconds"),
        "model_path": result.get("model_path"),
        "model_sha256": result.get("model_sha256"),
        "error_type": result.get("error_type"),
        "error": result.get("error"),
    }


def write_evidence(evidence_dir: Path, results: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "planb_model_sweep_results.json").write_text(
        json.dumps({"metadata": metadata, "results": results}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_csv(evidence_dir / "planb_model_sweep_results.csv", [safe_result_row(result) for result in results])
    completed = [result for result in results if result.get("status") == "completed"]
    leaderboard = sorted(completed, key=lambda row: (row.get("macro_f1") or 0.0, row.get("accuracy") or 0.0), reverse=True)
    write_csv(evidence_dir / "planb_model_sweep_leaderboard.csv", [safe_result_row(result) for result in leaderboard])
    confusions = {
        f"{result.get('task')}::{result.get('architecture')}::{result.get('image_size')}": {
            "classes": result.get("classes"),
            "confusion_matrix": result.get("confusion_matrix"),
            "per_class_f1": result.get("per_class_f1"),
        }
        for result in completed
    }
    (evidence_dir / "planb_model_sweep_confusion_matrices.json").write_text(
        json.dumps(confusions, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checksum_rows = [
        {
            "task": result.get("task"),
            "architecture": result.get("architecture"),
            "image_size": result.get("image_size"),
            "model_path": result.get("model_path"),
            "model_sha256": result.get("model_sha256"),
        }
        for result in completed
        if result.get("model_sha256")
    ]
    write_csv(evidence_dir / "planb_model_sweep_model_checksums.csv", checksum_rows)
    by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in completed:
        by_task[str(result["task"])].append(result)
    lines = [
        "# Plan B CNN Model Sweep",
        "",
        f"- Run ID: `{metadata['run_id']}`",
        f"- Created UTC: `{metadata['created_at']}`",
        f"- Source root: `{metadata['source_root']}`",
        f"- Dataset rows: malware `{metadata['malware_rows']}`, benign `{metadata['benign_rows']}`",
        f"- Completed runs: `{len(completed)}`",
        f"- Failed runs: `{len([row for row in results if row.get('status') == 'failed'])}`",
        "- Raw malware and model binaries remain on workhorse only; repository evidence is metrics/checksums only.",
        "",
        "## Best Runs By Task",
        "",
        "| Task | Architecture | Size | Accuracy | Macro-F1 | Benign FP rate |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for task in sorted(by_task):
        best = sorted(by_task[task], key=lambda row: (row.get("macro_f1") or 0.0, row.get("accuracy") or 0.0), reverse=True)[0]
        lines.append(
            f"| {task} | {best['architecture']} | {best['image_size']} | "
            f"{best.get('accuracy', 0):.4f} | {best.get('macro_f1', 0):.4f} | "
            f"{best.get('benign_false_positive_rate', '')} |"
        )
    lines.extend(["", "## Run Counts", ""])
    for task, count in sorted(Counter(str(row.get("task")) for row in results).items()):
        lines.append(f"- `{task}`: `{count}`")
    (evidence_dir / "planb_model_sweep_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def top_architectures(results: list[dict[str, Any]], task: str, limit: int) -> list[str]:
    completed = [
        row
        for row in results
        if row.get("task") == task and row.get("status") == "completed" and int(row.get("image_size") or 0) > 0
    ]
    ordered = sorted(completed, key=lambda row: (row.get("macro_f1") or 0.0, row.get("accuracy") or 0.0), reverse=True)
    seen = []
    for row in ordered:
        arch = str(row["architecture"])
        if arch not in seen:
            seen.append(arch)
        if len(seen) >= limit:
            break
    return seen


def run(args: argparse.Namespace) -> dict[str, Any]:
    source_root = Path(args.source_root)
    planb_root = source_root.parent
    report = load_source_report(source_root)
    families = sorted((report.get("families") or {}).keys())
    if not families:
        raise SystemExit("No families found in source report")
    run_id = args.run_id or f"planb_sweep_{utc_stamp()}"
    output_root = Path(args.output_root) / run_id
    evidence_dir = output_root / "evidence"
    output_root.mkdir(parents=True, exist_ok=True)
    malware = scan_verified_malware(planb_root, families, args.target_per_family)
    benign = load_benign(source_root, len(malware))
    tasks = build_tasks(malware, benign)
    splits = {task: stratified_split(rows) for task, rows in tasks.items()}
    metadata = {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_root": str(source_root),
        "output_root": str(output_root),
        "families": families,
        "malware_rows": len(malware),
        "benign_rows": len(benign),
        "tasks": {
            task: {
                "rows": len(rows),
                "classes": len({row["task_label"] for row in rows}),
                "class_counts": dict(Counter(row["task_label"] for row in rows)),
            }
            for task, rows in tasks.items()
        },
        "broad_size": args.broad_size,
        "ablation_sizes": args.ablation_sizes,
        "architectures": args.architectures,
        "epochs": args.epochs,
        "ablation_epochs": args.ablation_epochs,
    }
    (evidence_dir / "planb_model_sweep_dataset_manifest.json").parent.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "planb_model_sweep_dataset_manifest.json").write_text(
        json.dumps({"metadata": metadata, "malware": malware, "benign": benign}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    results: list[dict[str, Any]] = []
    for task in ("binary", "malware_family", "mixed_multiclass"):
        for architecture in args.architectures:
            result = train_one(task, architecture, args.broad_size, splits[task], output_root, args.epochs)
            results.append(result)
            write_evidence(evidence_dir, results, metadata)
            print(json.dumps(safe_result_row(result), sort_keys=True), flush=True)
    ablation_plan = []
    for task in ("binary", "malware_family", "mixed_multiclass"):
        for architecture in top_architectures(results, task, args.top_architectures):
            for image_size in args.ablation_sizes:
                ablation_plan.append((task, architecture, image_size))
    seen_runs = {(row.get("task"), row.get("architecture"), row.get("image_size")) for row in results}
    for task, architecture, image_size in ablation_plan:
        if (task, architecture, image_size) in seen_runs:
            continue
        result = train_one(task, architecture, image_size, splits[task], output_root, args.ablation_epochs)
        results.append(result)
        seen_runs.add((task, architecture, image_size))
        write_evidence(evidence_dir, results, metadata)
        print(json.dumps(safe_result_row(result), sort_keys=True), flush=True)
    write_evidence(evidence_dir, results, metadata)
    summary = {
        "run_id": run_id,
        "output_root": str(output_root),
        "evidence_dir": str(evidence_dir),
        "completed": len([row for row in results if row.get("status") == "completed"]),
        "failed": len([row for row in results if row.get("status") == "failed"]),
        "results_json": str(evidence_dir / "planb_model_sweep_results.json"),
        "summary_md": str(evidence_dir / "planb_model_sweep_summary.md"),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Plan B 10-architecture CNN sweep and resolution ablation.")
    parser.add_argument("--source-root", default="/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb/planb_mb_round3_20260604T133000Z")
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb/model_sweeps")
    parser.add_argument("--run-id")
    parser.add_argument("--target-per-family", type=int, default=100)
    parser.add_argument("--broad-size", type=int, default=160)
    parser.add_argument("--ablation-sizes", default="96,256,512,1024")
    parser.add_argument("--architectures", default=",".join(DEFAULT_ARCHITECTURES))
    parser.add_argument("--top-architectures", type=int, default=3)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--ablation-epochs", type=int, default=2)
    args = parser.parse_args()
    args.ablation_sizes = [int(item) for item in str(args.ablation_sizes).split(",") if item.strip()]
    args.architectures = [item.strip() for item in str(args.architectures).split(",") if item.strip()]
    return args


if __name__ == "__main__":
    run(parse_args())
