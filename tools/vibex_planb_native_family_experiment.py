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
from statistics import mean, pstdev
from typing import Any


PREVIOUS_BEST_FAMILY_MACRO_F1 = 0.1716344470733068
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
            safe_row = {}
            for key, value in row.items():
                if isinstance(value, (dict, list)):
                    safe_row[key] = json.dumps(value, sort_keys=True)
                else:
                    safe_row[key] = value
            writer.writerow(safe_row)


def parse_ints(value: str) -> list[int]:
    return [int(item.strip()) for item in str(value).split(",") if item.strip()]


def parse_strings(value: str) -> list[str]:
    return [item.strip() for item in str(value).split(",") if item.strip()]


def load_native_manifest(path: Path, image_sizes: set[int], image_modes: set[str], target_per_family: int) -> list[dict[str, str]]:
    rows = []
    grouped: dict[tuple[str, int, str], dict[str, dict[str, str]]] = defaultdict(dict)
    for row in read_csv(path):
        family = str(row.get("family") or "").strip()
        sha = str(row.get("sha256_hash") or "").lower()
        image_path = Path(str(row.get("image_path") or ""))
        try:
            image_size = int(row.get("image_size") or 0)
        except ValueError:
            image_size = 0
        image_mode = str(row.get("image_mode") or "").strip()
        if (
            not family
            or len(sha) != 64
            or image_size not in image_sizes
            or image_mode not in image_modes
            or not image_path.exists()
        ):
            continue
        item = dict(row)
        item["task_label"] = family
        item["image_path"] = str(image_path)
        item["image_size"] = str(image_size)
        item["image_mode"] = image_mode
        grouped[(family, image_size, image_mode)][sha] = item
    families = sorted({family for family, _, _ in grouped})
    for image_size in sorted(image_sizes):
        for image_mode in sorted(image_modes):
            shortfalls = {}
            for family in families:
                samples = grouped.get((family, image_size, image_mode), {})
                if len(samples) < target_per_family:
                    shortfalls[family] = target_per_family - len(samples)
            if shortfalls:
                raise SystemExit(
                    f"Insufficient native PNG rows for size={image_size} mode={image_mode}: {shortfalls}"
                )
            for family in families:
                selected = [grouped[(family, image_size, image_mode)][sha] for sha in sorted(grouped[(family, image_size, image_mode)])[:target_per_family]]
                rows.extend(selected)
    return rows


def subset_rows(rows: list[dict[str, str]], image_size: int, image_mode: str) -> list[dict[str, str]]:
    return [
        row
        for row in rows
        if int(row["image_size"]) == image_size and str(row["image_mode"]) == image_mode
    ]


def stratified_split(rows: list[dict[str, str]], seed: int) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row["task_label"]].append(row)
    rng = random.Random(seed)
    split = {"train": [], "val": [], "test": []}
    for label in sorted(grouped):
        items = list(grouped[label])
        rng.shuffle(items)
        n = len(items)
        test_n = max(1, round(n * 0.15))
        val_n = max(1, round(n * 0.15))
        train_n = n - test_n - val_n
        if train_n <= 0:
            raise SystemExit(f"Class {label} has too few rows for train/val/test split: {n}")
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


def class_weight_for(rows: list[dict[str, str]], label_to_id: dict[str, int]) -> dict[int, float]:
    counts = Counter(label_to_id[row["task_label"]] for row in rows)
    total = sum(counts.values())
    class_count = len(counts)
    return {label_id: total / (class_count * count) for label_id, count in counts.items() if count}


def make_tf_dataset(
    rows: list[dict[str, str]],
    label_to_id: dict[str, int],
    image_size: int,
    image_mode: str,
    batch_size: int,
    seed: int,
    shuffle: bool,
):
    import tensorflow as tf

    channels = 3 if image_mode == "rgb_triplet" else 1
    paths = [row["image_path"] for row in rows]
    labels = [label_to_id[row["task_label"]] for row in rows]
    dataset = tf.data.Dataset.from_tensor_slices((paths, labels))
    if shuffle:
        dataset = dataset.shuffle(buffer_size=len(rows), seed=seed, reshuffle_each_iteration=True)

    def load_image(path, label):
        image = tf.io.read_file(path)
        image = tf.image.decode_png(image, channels=channels)
        # Native images should already match image_size. This keeps tensor shapes
        # stable without relying on legacy 96px source images.
        image = tf.image.resize(image, [image_size, image_size], method="nearest")
        image = tf.cast(image, tf.float32) / 255.0
        return image, label

    return dataset.map(load_image, num_parallel_calls=tf.data.AUTOTUNE).batch(batch_size).prefetch(tf.data.AUTOTUNE)


def conv_block(tf, x, filters: int, kernel: int = 3, separable: bool = False, batch_norm: bool = True):
    layer = tf.keras.layers.SeparableConv2D if separable else tf.keras.layers.Conv2D
    x = layer(filters, kernel, padding="same", use_bias=not batch_norm)(x)
    if batch_norm:
        x = tf.keras.layers.BatchNormalization()(x)
    return tf.keras.layers.Activation("relu")(x)


def convnext_block(tf, x, filters: int):
    shortcut = x
    x = tf.keras.layers.DepthwiseConv2D(7, padding="same")(x)
    x = tf.keras.layers.LayerNormalization(epsilon=1e-6)(x)
    x = tf.keras.layers.Conv2D(filters * 4, 1, activation="gelu")(x)
    x = tf.keras.layers.Conv2D(filters, 1)(x)
    if shortcut.shape[-1] != filters:
        shortcut = tf.keras.layers.Conv2D(filters, 1, padding="same")(shortcut)
    return tf.keras.layers.Add()([shortcut, x])


def build_model(architecture: str, image_size: int, image_mode: str, class_count: int):
    import tensorflow as tf

    channels = 3 if image_mode == "rgb_triplet" else 1
    inputs = tf.keras.Input(shape=(image_size, image_size, channels))
    if architecture == "compact_cnn":
        x = inputs
        for filters in (24, 48, 96, 128):
            x = conv_block(tf, x, filters, batch_norm=True)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(128, activation="relu")(x)
    elif architecture == "dense_small":
        x = tf.keras.layers.Conv2D(32, 3, padding="same", activation="relu")(inputs)
        for filters in (32, 48, 64, 96):
            y = conv_block(tf, x, filters, batch_norm=True)
            x = tf.keras.layers.Concatenate()([x, y])
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(160, activation="relu")(x)
    elif architecture == "separable_cnn":
        x = inputs
        for filters in (32, 64, 96, 160):
            x = conv_block(tf, x, filters, separable=True, batch_norm=True)
            x = conv_block(tf, x, filters, separable=True, batch_norm=True)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(160, activation="relu")(x)
    elif architecture == "squeeze_cnn":
        x = tf.keras.layers.Conv2D(32, 3, padding="same", activation="relu")(inputs)
        for squeeze, expand in ((16, 48), (24, 72), (32, 96), (48, 144)):
            y = tf.keras.layers.Conv2D(squeeze, 1, padding="same", activation="relu")(x)
            a = tf.keras.layers.Conv2D(expand, 1, padding="same", activation="relu")(y)
            b = tf.keras.layers.Conv2D(expand, 3, padding="same", activation="relu")(y)
            x = tf.keras.layers.Concatenate()([a, b])
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(160, activation="relu")(x)
    elif architecture == "residual_small":
        x = tf.keras.layers.Conv2D(32, 3, padding="same", activation="relu")(inputs)
        for filters in (32, 64, 128, 192):
            shortcut = tf.keras.layers.Conv2D(filters, 1, strides=2, padding="same")(x)
            y = tf.keras.layers.Conv2D(filters, 3, strides=2, padding="same", activation="relu")(x)
            y = tf.keras.layers.BatchNormalization()(y)
            y = tf.keras.layers.Conv2D(filters, 3, padding="same")(y)
            x = tf.keras.layers.Activation("relu")(tf.keras.layers.Add()([shortcut, y]))
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(160, activation="relu")(x)
    elif architecture == "wide_residual_small":
        x = tf.keras.layers.Conv2D(48, 3, padding="same", activation="relu")(inputs)
        for filters in (64, 96, 160, 224):
            shortcut = tf.keras.layers.Conv2D(filters, 1, strides=2, padding="same")(x)
            y = tf.keras.layers.Conv2D(filters, 3, strides=2, padding="same", activation="relu")(x)
            y = tf.keras.layers.BatchNormalization()(y)
            y = tf.keras.layers.Conv2D(filters, 3, padding="same")(y)
            y = tf.keras.layers.BatchNormalization()(y)
            x = tf.keras.layers.Activation("relu")(tf.keras.layers.Add()([shortcut, y]))
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(192, activation="relu")(x)
    elif architecture == "inception_small":
        x = tf.keras.layers.Conv2D(32, 3, padding="same", activation="relu")(inputs)
        for filters in (32, 64, 96, 128):
            a = tf.keras.layers.Conv2D(filters, 1, padding="same", activation="relu")(x)
            b = tf.keras.layers.Conv2D(filters, 3, padding="same", activation="relu")(x)
            c = tf.keras.layers.Conv2D(filters, 5, padding="same", activation="relu")(x)
            x = tf.keras.layers.Concatenate()([a, b, c])
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(192, activation="relu")(x)
    elif architecture == "dual_kernel_cnn":
        x = inputs
        for filters in (32, 64, 128, 192):
            a = conv_block(tf, x, filters, kernel=3, batch_norm=True)
            b = conv_block(tf, x, filters, kernel=7, batch_norm=True)
            x = tf.keras.layers.Concatenate()([a, b])
            x = tf.keras.layers.Conv2D(filters, 1, padding="same", activation="relu")(x)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(192, activation="relu")(x)
    elif architecture == "attention_pool_cnn":
        x = inputs
        for filters in (32, 64, 128):
            x = conv_block(tf, x, filters, batch_norm=True)
            x = conv_block(tf, x, filters, batch_norm=True)
            x = tf.keras.layers.MaxPooling2D()(x)
        attention = tf.keras.layers.Conv2D(1, 1, padding="same", activation="sigmoid")(x)
        x = tf.keras.layers.Multiply()([x, attention])
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(192, activation="relu")(x)
    elif architecture == "convnext_tiny_scratch":
        x = tf.keras.layers.Conv2D(48, 4, strides=4, padding="same")(inputs)
        x = tf.keras.layers.LayerNormalization(epsilon=1e-6)(x)
        for filters, blocks in ((48, 2), (96, 2), (192, 3), (256, 1)):
            if x.shape[-1] != filters:
                x = tf.keras.layers.Conv2D(filters, 2, strides=2, padding="same")(x)
            for _ in range(blocks):
                x = convnext_block(tf, x, filters)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
        x = tf.keras.layers.Dense(192, activation="gelu")(x)
    elif architecture == "efficientnetb0_scratch":
        rgb = inputs if channels == 3 else tf.keras.layers.Concatenate()([inputs, inputs, inputs])
        base = tf.keras.applications.EfficientNetB0(
            input_shape=(image_size, image_size, 3),
            include_top=False,
            weights=None,
            pooling="avg",
        )
        x = base(rgb, training=True)
        x = tf.keras.layers.Dense(192, activation="relu")(x)
    else:
        raise ValueError(f"Unknown architecture: {architecture}")
    x = tf.keras.layers.Dropout(0.3)(x)
    outputs = tf.keras.layers.Dense(class_count, activation="softmax")(x)
    model = tf.keras.Model(inputs, outputs, name=f"{architecture}_{image_mode}_{image_size}")
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


def train_one(
    rows: list[dict[str, str]],
    architecture: str,
    image_size: int,
    image_mode: str,
    seed: int,
    output_root: Path,
    epochs: int,
    patience: int,
) -> dict[str, Any]:
    import numpy as np
    import tensorflow as tf
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

    tf.keras.utils.set_random_seed(seed)
    split = stratified_split(rows, seed)
    labels = sorted({row["task_label"] for row in rows})
    label_to_id = {label: index for index, label in enumerate(labels)}
    batch_size = batch_size_for(image_size, architecture)
    run_name = f"malware_family_{architecture}_{image_mode}_{image_size}_seed{seed}"
    model_dir = output_root / "models" / run_name
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / f"{run_name}.keras"
    start = time.time()
    result: dict[str, Any] = {
        "task": "malware_family",
        "architecture": architecture,
        "image_size": image_size,
        "image_mode": image_mode,
        "seed": seed,
        "class_count": len(labels),
        "classes": labels,
        "train_rows": len(split["train"]),
        "val_rows": len(split["val"]),
        "test_rows": len(split["test"]),
        "batch_size": batch_size,
        "epochs_requested": epochs,
        "patience": patience,
        "status": "running",
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        tf.keras.backend.clear_session()
        train_ds = make_tf_dataset(split["train"], label_to_id, image_size, image_mode, batch_size, seed, shuffle=True)
        val_ds = make_tf_dataset(split["val"], label_to_id, image_size, image_mode, batch_size, seed, shuffle=False)
        test_ds = make_tf_dataset(split["test"], label_to_id, image_size, image_mode, batch_size, seed, shuffle=False)
        model = build_model(architecture, image_size, image_mode, len(labels))
        result["param_count"] = int(model.count_params())
        history = model.fit(
            train_ds,
            validation_data=val_ds,
            epochs=epochs,
            verbose=2,
            class_weight=class_weight_for(split["train"], label_to_id),
            callbacks=[
                tf.keras.callbacks.EarlyStopping(
                    monitor="val_loss",
                    patience=patience,
                    restore_best_weights=True,
                )
            ],
        )
        predictions = model.predict(test_ds, verbose=0)
        y_true = np.asarray([label_to_id[row["task_label"]] for row in split["test"]], dtype=np.int64)
        y_pred = np.argmax(predictions, axis=1)
        cm = confusion_matrix(y_true, y_pred, labels=list(range(len(labels))))
        per_class = f1_score(y_true, y_pred, labels=list(range(len(labels))), average=None, zero_division=0)
        model.save(model_path)
        per_class_f1 = {label: float(per_class[index]) for index, label in enumerate(labels)}
        result.update(
            {
                "status": "completed",
                "accuracy": float(accuracy_score(y_true, y_pred)),
                "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
                "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
                "nonzero_family_f1_count": int(sum(1 for value in per_class_f1.values() if value > 0)),
                "per_class_f1": per_class_f1,
                "confusion_matrix": cm.astype(int).tolist(),
                "history": {key: [float(item) for item in values] for key, values in history.history.items()},
                "epochs_run": len(history.history.get("loss", [])),
                "model_path": str(model_path),
                "model_sha256": sha256_file(model_path),
                "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
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
        "image_mode": result.get("image_mode"),
        "seed": result.get("seed"),
        "status": result.get("status"),
        "accuracy": result.get("accuracy"),
        "macro_f1": result.get("macro_f1"),
        "weighted_f1": result.get("weighted_f1"),
        "nonzero_family_f1_count": result.get("nonzero_family_f1_count"),
        "train_rows": result.get("train_rows"),
        "val_rows": result.get("val_rows"),
        "test_rows": result.get("test_rows"),
        "class_count": result.get("class_count"),
        "param_count": result.get("param_count"),
        "batch_size": result.get("batch_size"),
        "epochs_requested": result.get("epochs_requested"),
        "epochs_run": result.get("epochs_run"),
        "patience": result.get("patience"),
        "train_seconds": result.get("train_seconds"),
        "model_path": result.get("model_path"),
        "model_sha256": result.get("model_sha256"),
        "error_type": result.get("error_type"),
        "error": result.get("error"),
    }


def aggregate_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int, str], list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        if result.get("status") == "completed":
            groups[(str(result["architecture"]), int(result["image_size"]), str(result["image_mode"]))].append(result)
    rows = []
    for (architecture, image_size, image_mode), items in sorted(groups.items()):
        macro_values = [float(row.get("macro_f1") or 0.0) for row in items]
        accuracy_values = [float(row.get("accuracy") or 0.0) for row in items]
        nonzero_values = [int(row.get("nonzero_family_f1_count") or 0) for row in items]
        rows.append(
            {
                "architecture": architecture,
                "image_size": image_size,
                "image_mode": image_mode,
                "completed_seeds": len(items),
                "accuracy_mean": mean(accuracy_values),
                "accuracy_std": pstdev(accuracy_values) if len(accuracy_values) > 1 else 0.0,
                "macro_f1_mean": mean(macro_values),
                "macro_f1_std": pstdev(macro_values) if len(macro_values) > 1 else 0.0,
                "weighted_f1_mean": mean([float(row.get("weighted_f1") or 0.0) for row in items]),
                "weighted_f1_std": pstdev([float(row.get("weighted_f1") or 0.0) for row in items]) if len(items) > 1 else 0.0,
                "nonzero_family_f1_mean": mean(nonzero_values),
                "best_seed": max(items, key=lambda row: (row.get("macro_f1") or 0.0, row.get("accuracy") or 0.0)).get("seed"),
                "best_macro_f1": max(macro_values),
                "previous_best_family_macro_f1": PREVIOUS_BEST_FAMILY_MACRO_F1,
                "improved_over_previous_best": mean(macro_values) > PREVIOUS_BEST_FAMILY_MACRO_F1,
            }
        )
    return sorted(rows, key=lambda row: (row["macro_f1_mean"], row["accuracy_mean"]), reverse=True)


def write_evidence(evidence_dir: Path, results: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    aggregates = aggregate_results(results)
    completed = [row for row in results if row.get("status") == "completed"]
    failed = [row for row in results if row.get("status") == "failed"]
    (evidence_dir / "planb_native_family_results.json").write_text(
        json.dumps({"metadata": metadata, "results": results, "aggregates": aggregates}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_csv(evidence_dir / "planb_native_family_results.csv", [safe_result_row(row) for row in results])
    write_csv(evidence_dir / "planb_native_family_leaderboard.csv", aggregates)
    confusions = {
        f"{row.get('architecture')}::{row.get('image_mode')}::{row.get('image_size')}::seed{row.get('seed')}": {
            "classes": row.get("classes"),
            "confusion_matrix": row.get("confusion_matrix"),
            "per_class_f1": row.get("per_class_f1"),
        }
        for row in completed
    }
    (evidence_dir / "planb_native_family_confusion_matrices.json").write_text(
        json.dumps(confusions, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_csv(
        evidence_dir / "planb_native_family_model_checksums.csv",
        [
            {
                "architecture": row.get("architecture"),
                "image_size": row.get("image_size"),
                "image_mode": row.get("image_mode"),
                "seed": row.get("seed"),
                "model_path": row.get("model_path"),
                "model_sha256": row.get("model_sha256"),
            }
            for row in completed
            if row.get("model_sha256")
        ],
    )
    best = aggregates[0] if aggregates else {}
    lines = [
        "# Plan B Native PNG Family CNN Experiment",
        "",
        f"- Run ID: `{metadata['run_id']}`",
        f"- Created UTC: `{metadata['created_at']}`",
        f"- Image manifest: `{metadata['image_manifest']}`",
        f"- Family rows per size/mode: `{metadata['rows_per_size_mode']}`",
        f"- Families: `{metadata['family_count']}`",
        f"- Previous family macro-F1 baseline: `{PREVIOUS_BEST_FAMILY_MACRO_F1:.4f}`",
        f"- Completed runs: `{len(completed)}`",
        f"- Failed runs: `{len(failed)}`",
        "- Raw malware, PNG images, and model binaries remain on workhorse only; repository evidence is metrics, checksums, paths, and audit metadata only.",
        "",
        "## Best Mean Result",
        "",
    ]
    if best:
        lines.extend(
            [
                f"- Architecture: `{best['architecture']}`",
                f"- Image size/mode: `{best['image_size']} {best['image_mode']}`",
                f"- Macro-F1 mean/std: `{best['macro_f1_mean']:.4f}` / `{best['macro_f1_std']:.4f}`",
                f"- Accuracy mean/std: `{best['accuracy_mean']:.4f}` / `{best['accuracy_std']:.4f}`",
                f"- Non-zero family F1 mean: `{best['nonzero_family_f1_mean']:.2f}`",
                f"- Improved over previous best: `{best['improved_over_previous_best']}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Leaderboard",
            "",
            "| Architecture | Size | Mode | Seeds | Accuracy mean | Macro-F1 mean | Macro-F1 std | Non-zero F1 mean |",
            "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in aggregates[:20]:
        lines.append(
            f"| {row['architecture']} | {row['image_size']} | {row['image_mode']} | {row['completed_seeds']} | "
            f"{row['accuracy_mean']:.4f} | {row['macro_f1_mean']:.4f} | {row['macro_f1_std']:.4f} | "
            f"{row['nonzero_family_f1_mean']:.2f} |"
        )
    (evidence_dir / "planb_native_family_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> dict[str, Any]:
    image_manifest = Path(args.image_manifest)
    run_id = args.run_id or f"planb_native_family_{utc_stamp()}"
    output_root = Path(args.output_root) / run_id
    evidence_dir = output_root / "evidence"
    output_root.mkdir(parents=True, exist_ok=True)
    image_sizes = set(args.image_sizes)
    image_modes = set(args.image_modes)
    rows = load_native_manifest(image_manifest, image_sizes, image_modes, args.target_per_family)
    family_counts = Counter(row["task_label"] for row in rows if int(row["image_size"]) == args.image_sizes[0] and row["image_mode"] == args.image_modes[0])
    metadata = {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "image_manifest": str(image_manifest),
        "output_root": str(output_root),
        "architectures": args.architectures,
        "image_sizes": args.image_sizes,
        "image_modes": args.image_modes,
        "seeds": args.seeds,
        "epochs": args.epochs,
        "patience": args.patience,
        "target_per_family": args.target_per_family,
        "family_count": len(family_counts),
        "family_counts": dict(sorted(family_counts.items())),
        "rows_per_size_mode": sum(family_counts.values()),
        "previous_best_family_macro_f1": PREVIOUS_BEST_FAMILY_MACRO_F1,
        "primary_metric": "malware_family_macro_f1_mean",
    }
    (evidence_dir / "planb_native_family_dataset_manifest.json").parent.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "planb_native_family_dataset_manifest.json").write_text(
        json.dumps({"metadata": metadata, "class_counts": metadata["family_counts"]}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    results: list[dict[str, Any]] = []
    for image_size in args.image_sizes:
        for image_mode in args.image_modes:
            current_rows = subset_rows(rows, image_size, image_mode)
            for architecture in args.architectures:
                for seed in args.seeds:
                    result = train_one(
                        current_rows,
                        architecture,
                        image_size,
                        image_mode,
                        seed,
                        output_root,
                        args.epochs,
                        args.patience,
                    )
                    results.append(result)
                    write_evidence(evidence_dir, results, metadata)
                    print(json.dumps(safe_result_row(result), sort_keys=True), flush=True)
    write_evidence(evidence_dir, results, metadata)
    completed = [row for row in results if row.get("status") == "completed"]
    aggregates = aggregate_results(results)
    summary = {
        "run_id": run_id,
        "output_root": str(output_root),
        "evidence_dir": str(evidence_dir),
        "completed": len(completed),
        "failed": len([row for row in results if row.get("status") == "failed"]),
        "best": aggregates[0] if aggregates else None,
        "results_json": str(evidence_dir / "planb_native_family_results.json"),
        "summary_md": str(evidence_dir / "planb_native_family_summary.md"),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train family-first CNNs on native Plan B byte PNGs.")
    parser.add_argument("--image-manifest", required=True)
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb/model_sweeps")
    parser.add_argument("--run-id")
    parser.add_argument("--target-per-family", type=int, default=300)
    parser.add_argument("--image-sizes", default="256,512,1024")
    parser.add_argument("--image-modes", default="gray,rgb_triplet")
    parser.add_argument("--architectures", default=",".join(DEFAULT_ARCHITECTURES))
    parser.add_argument("--seeds", default="1337,2027,4099")
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--patience", type=int, default=3)
    args = parser.parse_args()
    args.image_sizes = parse_ints(args.image_sizes)
    args.image_modes = parse_strings(args.image_modes)
    args.architectures = parse_strings(args.architectures)
    args.seeds = parse_ints(args.seeds)
    return args


if __name__ == "__main__":
    run(parse_args())
