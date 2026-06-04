#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any


BENIGN_MANIFEST = Path(
    "/home/phil/vibex_secure_dataset/release/VIBEX-50K/manifests/safe_dataset_manifest_VIBEX-50K_20260518T081144Z.csv"
)
DEFAULT_ARCHITECTURES = [
    "compact_cnn",
    "residual_small",
    "inception_small",
    "separable_extreme",
    "barcode_dilated",
    "random_reservoir",
    "patch_shuffle_cnn",
    "blurpool_cnn",
    "large_kernel_texture",
    "squeeze_excite_cnn",
    "multiscale_pyramid",
    "fixed_edge_bank",
]


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


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
            writer.writerow(
                {
                    key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value
                    for key, value in row.items()
                }
            )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_ints(value: str) -> list[int]:
    return [int(item.strip()) for item in str(value).split(",") if item.strip()]


def parse_strings(value: str) -> list[str]:
    return [item.strip() for item in str(value).split(",") if item.strip()]


def slug(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value.strip()).strip("_") or "unknown"


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


def load_native_malware(path: Path, image_size: int, image_mode: str, target_per_family: int) -> list[dict[str, str]]:
    grouped: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for row in read_csv(path):
        family = str(row.get("family") or "").strip()
        sha = str(row.get("sha256_hash") or "").lower()
        image_path = Path(str(row.get("image_path") or ""))
        if (
            family
            and len(sha) == 64
            and str(row.get("image_mode") or "") == image_mode
            and int(row.get("image_size") or 0) == image_size
            and image_path.exists()
        ):
            grouped[family][sha] = {
                "kind": "malware",
                "sha256": sha,
                "family": family,
                "class_label": family,
                "binary_label": "malware",
                "image_path": str(image_path),
                "task_label": family,
            }
    selected = []
    shortfalls = {}
    for family in sorted(grouped):
        rows = [grouped[family][sha] for sha in sorted(grouped[family])[:target_per_family]]
        if len(rows) < target_per_family:
            shortfalls[family] = target_per_family - len(rows)
        selected.extend(rows)
    if shortfalls and len(shortfalls) == len(grouped):
        raise SystemExit(f"No family met target_per_family={target_per_family}: {shortfalls}")
    return selected


def load_benign_rows(path: Path, count: int, min_class_rows: int) -> list[dict[str, str]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in read_csv(path):
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
                "kind": "benign",
                "sha256": str(row.get("raw_sha256") or ""),
                "family": "",
                "class_label": label,
                "binary_label": "benign",
                "source": source,
                "role": role,
                "image_path": str(image_path),
                "task_label": label,
            }
        )
    merged: dict[str, list[dict[str, str]]] = defaultdict(list)
    for label, rows in grouped.items():
        source = label.split("::", 1)[0]
        target = label if len(rows) >= min_class_rows else f"{source}::other"
        for row in rows:
            item = dict(row)
            item["class_label"] = target
            item["task_label"] = target
            item["role"] = target.split("::", 1)[1]
            merged[target].append(item)
    rng = random.Random(1337)
    for rows in merged.values():
        rng.shuffle(rows)
    labels = sorted(merged)
    selected: list[dict[str, str]] = []
    index = 0
    while labels and len(selected) < count:
        label = labels[index % len(labels)]
        if merged[label]:
            selected.append(merged[label].pop())
        labels = [item for item in labels if merged[item]]
        index += 1
    if len(selected) < count:
        raise SystemExit(f"Need {count} benign rows, found {len(selected)}")
    return selected


def task_rows(task: str, malware: list[dict[str, str]], benign: list[dict[str, str]]) -> list[dict[str, str]]:
    rows = []
    if task == "binary":
        for row in malware:
            item = dict(row)
            item["task_label"] = "malware"
            rows.append(item)
        for row in benign[: len(malware)]:
            item = dict(row)
            item["task_label"] = "benign"
            rows.append(item)
    elif task == "malware_family":
        rows = [dict(row, task_label=row["family"]) for row in malware]
    elif task == "mixed_multiclass":
        rows.extend(dict(row, task_label=f"malware::{row['family']}") for row in malware)
        rows.extend(dict(row, task_label=f"benign::{row['class_label']}") for row in benign[: len(malware)])
    else:
        raise ValueError(f"unknown task: {task}")
    return rows


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
            raise SystemExit(f"Class {label} has too few rows for split: {n}")
        split["test"].extend(items[:test_n])
        split["val"].extend(items[test_n : test_n + val_n])
        split["train"].extend(items[test_n + val_n :])
    for part in split.values():
        rng.shuffle(part)
    return split


def class_weight_for(rows: list[dict[str, str]], label_to_id: dict[str, int]) -> dict[int, float]:
    counts = Counter(label_to_id[row["task_label"]] for row in rows)
    total = sum(counts.values())
    classes = len(counts)
    return {label_id: total / (classes * count) for label_id, count in counts.items() if count}


def batch_size_for(image_size: int, architecture: str, task: str) -> int:
    if image_size >= 512:
        return 4
    if "inception" in architecture or "multiscale" in architecture:
        return 8
    if task == "binary":
        return 16
    return 12


def gpu_status() -> dict[str, Any]:
    try:
        output = subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,power.limit",
                "--format=csv,noheader,nounits",
            ],
            text=True,
            timeout=5,
        ).strip()
        parts = [part.strip() for part in output.split(",")]
        return {
            "temperature_c": int(float(parts[0])),
            "utilization_percent": int(float(parts[1])),
            "memory_used_mib": int(float(parts[2])),
            "memory_total_mib": int(float(parts[3])),
            "power_draw_w": float(parts[4]),
            "power_limit_w": float(parts[5]),
        }
    except Exception as exc:
        return {"error": str(exc)}


def wait_for_safe_gpu(max_temp_c: int, pause_temp_c: int, seconds: int) -> dict[str, Any]:
    status = gpu_status()
    temp = int(status.get("temperature_c") or 0)
    while temp >= pause_temp_c:
        time.sleep(seconds)
        status = gpu_status()
        temp = int(status.get("temperature_c") or 0)
    if temp >= max_temp_c:
        raise RuntimeError(f"GPU temperature too high: {temp}C")
    return status


def make_tf_dataset(
    rows: list[dict[str, str]],
    label_to_id: dict[str, int],
    image_size: int,
    architecture: str,
    batch_size: int,
    seed: int,
    shuffle: bool,
):
    import tensorflow as tf

    paths = [row["image_path"] for row in rows]
    labels = [label_to_id[row["task_label"]] for row in rows]
    dataset = tf.data.Dataset.from_tensor_slices((paths, labels))
    if shuffle:
        dataset = dataset.shuffle(buffer_size=len(rows), seed=seed, reshuffle_each_iteration=True)

    def load_image(path, label):
        image = tf.io.read_file(path)
        image = tf.image.decode_png(image, channels=1)
        image = tf.image.resize(image, [image_size, image_size], method="nearest")
        image = tf.cast(image, tf.float32) / 255.0
        if architecture == "patch_shuffle_cnn":
            tile = 16
            shape = tf.shape(image)
            h = shape[0] // tile * tile
            w = shape[1] // tile * tile
            cropped = image[:h, :w, :]
            tiles = tf.reshape(cropped, [h // tile, tile, w // tile, tile, 1])
            tiles = tf.transpose(tiles, [2, 1, 0, 3, 4])
            image = tf.reshape(tiles, [h, w, 1])
            image = tf.image.resize_with_crop_or_pad(image, image_size, image_size)
        return image, label

    return dataset.map(load_image, num_parallel_calls=tf.data.AUTOTUNE).batch(batch_size).prefetch(tf.data.AUTOTUNE)


def conv_block(tf, x, filters: int, kernel: int = 3, dilation: int = 1, separable: bool = False):
    layer = tf.keras.layers.SeparableConv2D if separable else tf.keras.layers.Conv2D
    x = layer(filters, kernel, padding="same", dilation_rate=dilation, use_bias=False)(x)
    x = tf.keras.layers.BatchNormalization()(x)
    return tf.keras.layers.Activation("relu")(x)


def squeeze_excite(tf, x, ratio: int = 8):
    channels = int(x.shape[-1])
    y = tf.keras.layers.GlobalAveragePooling2D()(x)
    y = tf.keras.layers.Dense(max(4, channels // ratio), activation="relu")(y)
    y = tf.keras.layers.Dense(channels, activation="sigmoid")(y)
    y = tf.keras.layers.Reshape((1, 1, channels))(y)
    return tf.keras.layers.Multiply()([x, y])


def build_model(architecture: str, image_size: int, class_count: int):
    import tensorflow as tf

    inputs = tf.keras.Input(shape=(image_size, image_size, 1))
    if architecture == "compact_cnn":
        x = inputs
        for filters in (24, 48, 96, 128):
            x = conv_block(tf, x, filters)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "residual_small":
        x = tf.keras.layers.Conv2D(32, 3, padding="same", activation="relu")(inputs)
        for filters in (32, 64, 128, 192):
            shortcut = tf.keras.layers.Conv2D(filters, 1, strides=2, padding="same")(x)
            y = tf.keras.layers.Conv2D(filters, 3, strides=2, padding="same", activation="relu")(x)
            y = tf.keras.layers.BatchNormalization()(y)
            y = tf.keras.layers.Conv2D(filters, 3, padding="same")(y)
            x = tf.keras.layers.Activation("relu")(tf.keras.layers.Add()([shortcut, y]))
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "inception_small":
        x = tf.keras.layers.Conv2D(32, 3, padding="same", activation="relu")(inputs)
        for filters in (32, 64, 96, 128):
            a = tf.keras.layers.Conv2D(filters, 1, padding="same", activation="relu")(x)
            b = tf.keras.layers.Conv2D(filters, 3, padding="same", activation="relu")(x)
            c = tf.keras.layers.Conv2D(filters, 5, padding="same", activation="relu")(x)
            x = tf.keras.layers.Concatenate()([a, b, c])
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "separable_extreme":
        x = inputs
        for filters in (32, 64, 96, 128, 160):
            x = conv_block(tf, x, filters, separable=True)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "barcode_dilated":
        a = tf.keras.layers.Conv2D(48, (1, 31), padding="same", activation="relu")(inputs)
        b = tf.keras.layers.Conv2D(48, (31, 1), padding="same", activation="relu")(inputs)
        x = tf.keras.layers.Concatenate()([a, b])
        for dilation in (1, 2, 4, 8):
            x = conv_block(tf, x, 64 + dilation * 8, kernel=3, dilation=dilation)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "random_reservoir":
        x = tf.keras.layers.Conv2D(
            96,
            7,
            strides=2,
            padding="same",
            activation="relu",
            trainable=False,
            kernel_initializer=tf.keras.initializers.RandomNormal(seed=17),
        )(inputs)
        x = tf.keras.layers.Conv2D(
            128,
            5,
            strides=2,
            padding="same",
            activation="relu",
            trainable=False,
            kernel_initializer=tf.keras.initializers.RandomNormal(seed=19),
        )(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "patch_shuffle_cnn":
        x = inputs
        for filters in (32, 64, 96, 128):
            x = conv_block(tf, x, filters)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "blurpool_cnn":
        x = tf.keras.layers.AveragePooling2D(pool_size=2, strides=1, padding="same")(inputs)
        for filters in (32, 64, 128, 192):
            x = conv_block(tf, x, filters)
            x = tf.keras.layers.AveragePooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "large_kernel_texture":
        x = inputs
        for kernel, filters in ((11, 32), (9, 64), (7, 96), (5, 128)):
            x = conv_block(tf, x, filters, kernel=kernel)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "squeeze_excite_cnn":
        x = inputs
        for filters in (32, 64, 128, 192):
            x = conv_block(tf, x, filters)
            x = squeeze_excite(tf, x)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    elif architecture == "multiscale_pyramid":
        branches = []
        for scale in (1, 2, 4):
            y = inputs if scale == 1 else tf.keras.layers.AveragePooling2D(scale)(inputs)
            y = conv_block(tf, y, 48)
            y = conv_block(tf, y, 96)
            y = tf.keras.layers.GlobalAveragePooling2D()(y)
            branches.append(y)
        x = tf.keras.layers.Concatenate()(branches)
    elif architecture == "fixed_edge_bank":
        def sobel_features(tensor):
            edges = tf.image.sobel_edges(tensor)
            shape = tf.shape(edges)
            return tf.reshape(edges, [shape[0], shape[1], shape[2], 2])

        x = tf.keras.layers.Lambda(sobel_features)(inputs)
        for filters in (32, 64, 96, 128):
            x = conv_block(tf, x, filters)
            x = tf.keras.layers.MaxPooling2D()(x)
        x = tf.keras.layers.GlobalAveragePooling2D()(x)
    else:
        raise ValueError(f"unknown architecture: {architecture}")
    x = tf.keras.layers.Dense(192, activation="relu")(x)
    x = tf.keras.layers.Dropout(0.3)(x)
    outputs = tf.keras.layers.Dense(class_count, activation="softmax")(x)
    model = tf.keras.Model(inputs, outputs, name=f"{architecture}_{image_size}")
    model.compile(optimizer=tf.keras.optimizers.Adam(1e-3), loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    return model


def train_one(
    rows: list[dict[str, str]],
    task: str,
    architecture: str,
    image_size: int,
    seed: int,
    output_root: Path,
    epochs: int,
    patience: int,
    max_temp_c: int,
    pause_temp_c: int,
) -> dict[str, Any]:
    import numpy as np
    import tensorflow as tf
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

    tf.keras.backend.clear_session()
    tf.keras.utils.set_random_seed(seed)
    split = stratified_split(rows, seed)
    labels = sorted({row["task_label"] for row in rows})
    label_to_id = {label: index for index, label in enumerate(labels)}
    batch_size = batch_size_for(image_size, architecture, task)
    run_name = f"{task}_{architecture}_{image_size}_seed{seed}"
    model_dir = output_root / "models" / run_name
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / f"{run_name}.keras"
    start = time.time()
    result: dict[str, Any] = {
        "task": task,
        "architecture": architecture,
        "model_name": architecture,
        "image_size": image_size,
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
        result["gpu_before"] = wait_for_safe_gpu(max_temp_c, pause_temp_c, 60)
        train_ds = make_tf_dataset(split["train"], label_to_id, image_size, architecture, batch_size, seed, True)
        val_ds = make_tf_dataset(split["val"], label_to_id, image_size, architecture, batch_size, seed, False)
        test_ds = make_tf_dataset(split["test"], label_to_id, image_size, architecture, batch_size, seed, False)
        model = build_model(architecture, image_size, len(labels))
        result["param_count"] = int(model.count_params())
        history = model.fit(
            train_ds,
            validation_data=val_ds,
            epochs=epochs,
            verbose=2,
            class_weight=class_weight_for(split["train"], label_to_id),
            callbacks=[tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=patience, restore_best_weights=True)],
        )
        probs = model.predict(test_ds, verbose=0)
        y_true = np.asarray([label_to_id[row["task_label"]] for row in split["test"]], dtype=np.int64)
        y_pred = np.argmax(probs, axis=1)
        cm = confusion_matrix(y_true, y_pred, labels=list(range(len(labels))))
        per_class = f1_score(y_true, y_pred, labels=list(range(len(labels)),), average=None, zero_division=0)
        model.save(model_path)
        per_class_f1 = {label: float(per_class[index]) for index, label in enumerate(labels)}
        result.update(
            {
                "status": "completed",
                "accuracy": float(accuracy_score(y_true, y_pred)),
                "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
                "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
                "family_macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0))
                if task == "malware_family"
                else None,
                "nonzero_class_f1_count": int(sum(1 for value in per_class_f1.values() if value > 0)),
                "per_class_f1": per_class_f1,
                "confusion_matrix": cm.astype(int).tolist(),
                "history": {key: [float(item) for item in value] for key, value in history.history.items()},
                "epochs_run": len(history.history.get("loss", [])),
                "model_path": str(model_path),
                "model_sha256": sha256_file(model_path),
                "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "gpu_after": gpu_status(),
            }
        )
        if task == "binary" and labels == ["benign", "malware"]:
            tn, fp, fn, tp = [int(value) for value in cm.ravel()]
            result["benign_false_positive_rate"] = float(fp / (fp + tn)) if (fp + tn) else 0.0
            result["confusion"] = {"tn": tn, "fp": fp, "fn": fn, "tp": tp}
    except Exception as exc:
        result.update(
            {
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc)[:1000],
                "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "gpu_after": gpu_status(),
            }
        )
    finally:
        result["train_seconds"] = round(time.time() - start, 3)
    return result


def safe_row(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "task": result.get("task"),
        "architecture": result.get("architecture"),
        "image_size": result.get("image_size"),
        "seed": result.get("seed"),
        "status": result.get("status"),
        "accuracy": result.get("accuracy"),
        "macro_f1": result.get("macro_f1"),
        "weighted_f1": result.get("weighted_f1"),
        "family_macro_f1": result.get("family_macro_f1"),
        "benign_false_positive_rate": result.get("benign_false_positive_rate"),
        "nonzero_class_f1_count": result.get("nonzero_class_f1_count"),
        "train_rows": result.get("train_rows"),
        "val_rows": result.get("val_rows"),
        "test_rows": result.get("test_rows"),
        "class_count": result.get("class_count"),
        "param_count": result.get("param_count"),
        "batch_size": result.get("batch_size"),
        "epochs_run": result.get("epochs_run"),
        "train_seconds": result.get("train_seconds"),
        "model_path": result.get("model_path"),
        "model_sha256": result.get("model_sha256"),
        "error_type": result.get("error_type"),
        "error": result.get("error"),
        "completed_at": result.get("completed_at"),
    }


def aggregate(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        if row.get("status") == "completed":
            groups[(str(row["task"]), str(row["architecture"]), int(row["image_size"]))].append(row)
    output = []
    for (task, architecture, image_size), rows in groups.items():
        macro = [float(row.get("macro_f1") or 0) for row in rows]
        accuracy = [float(row.get("accuracy") or 0) for row in rows]
        output.append(
            {
                "task": task,
                "architecture": architecture,
                "image_size": image_size,
                "completed_seeds": len(rows),
                "accuracy_mean": mean(accuracy),
                "accuracy_std": pstdev(accuracy) if len(accuracy) > 1 else 0.0,
                "macro_f1_mean": mean(macro),
                "macro_f1_std": pstdev(macro) if len(macro) > 1 else 0.0,
                "best_accuracy": max(accuracy),
                "best_macro_f1": max(macro),
                "best_seed": max(rows, key=lambda row: (float(row.get("macro_f1") or 0), float(row.get("accuracy") or 0))).get("seed"),
                "mean_benign_false_positive_rate": mean(
                    [float(row.get("benign_false_positive_rate") or 0) for row in rows if row.get("benign_false_positive_rate") is not None]
                    or [0.0]
                ),
            }
        )
    return sorted(output, key=lambda row: (row["task"], row["macro_f1_mean"], row["accuracy_mean"]), reverse=True)


def write_evidence(evidence_dir: Path, metadata: dict[str, Any], results: list[dict[str, Any]]) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    aggregates = aggregate(results)
    (evidence_dir / "planb_overnight_cnn_results.json").write_text(
        json.dumps({"metadata": metadata, "aggregates": aggregates, "results": results}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_csv(evidence_dir / "planb_overnight_cnn_results.csv", [safe_row(row) for row in results])
    write_csv(evidence_dir / "planb_overnight_cnn_leaderboard.csv", aggregates)
    completed = [row for row in results if row.get("status") == "completed"]
    confusions = {
        f"{row['task']}::{row['architecture']}::{row['image_size']}::seed{row['seed']}": {
            "classes": row.get("classes"),
            "per_class_f1": row.get("per_class_f1"),
            "confusion_matrix": row.get("confusion_matrix"),
        }
        for row in completed
    }
    (evidence_dir / "planb_overnight_cnn_confusions.json").write_text(
        json.dumps(confusions, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    best_binary = next((row for row in aggregates if row["task"] == "binary"), None)
    best_family = next((row for row in aggregates if row["task"] == "malware_family"), None)
    lines = [
        "# Plan B Overnight CNN Sweep",
        "",
        f"- Run ID: `{metadata['run_id']}`",
        f"- Created UTC: `{metadata['created_at']}`",
        f"- Malware families: `{metadata['family_count']}`",
        f"- Malware PNG rows used: `{metadata['malware_rows']}`",
        f"- Benign PNG rows used: `{metadata['benign_rows']}`",
        f"- Image size: `{metadata['image_size']}`",
        f"- Completed runs: `{len(completed)}`",
        f"- Failed runs: `{len([row for row in results if row.get('status') == 'failed'])}`",
        "- Safe evidence only; raw malware and model binaries remain on workhorse.",
        "",
        "## Presentation Summary",
        "",
    ]
    if best_binary:
        lines.append(
            f"- Best binary model: `{best_binary['architecture']}` macro-F1 `{best_binary['macro_f1_mean']:.4f}`, accuracy `{best_binary['accuracy_mean']:.4f}`."
        )
    if best_family:
        lines.append(
            f"- Best family model: `{best_family['architecture']}` macro-F1 `{best_family['macro_f1_mean']:.4f}`, accuracy `{best_family['accuracy_mean']:.4f}`."
        )
    lines.extend(
        [
            "",
            "## Leaderboard",
            "",
            "| Task | Architecture | Size | Seeds | Accuracy mean | Macro-F1 mean | Benign FP mean |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in aggregates[:40]:
        lines.append(
            f"| {row['task']} | {row['architecture']} | {row['image_size']} | {row['completed_seeds']} | "
            f"{row['accuracy_mean']:.4f} | {row['macro_f1_mean']:.4f} | {row['mean_benign_false_positive_rate']:.4f} |"
        )
    (evidence_dir / "planb_overnight_cnn_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> dict[str, Any]:
    run_id = args.run_id or f"planb_overnight_cnn_{utc_stamp()}"
    output_root = Path(args.output_root) / run_id
    evidence_dir = output_root / "evidence"
    malware = load_native_malware(Path(args.image_manifest), args.image_size, args.image_mode, args.target_per_family)
    benign = load_benign_rows(Path(args.benign_manifest), len(malware), args.min_benign_class_rows)
    metadata = {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "image_manifest": args.image_manifest,
        "benign_manifest": args.benign_manifest,
        "output_root": str(output_root),
        "image_size": args.image_size,
        "image_mode": args.image_mode,
        "target_per_family": args.target_per_family,
        "family_count": len({row["family"] for row in malware}),
        "family_counts": dict(sorted(Counter(row["family"] for row in malware).items())),
        "malware_rows": len(malware),
        "benign_rows": len(benign),
        "benign_classes": dict(sorted(Counter(row["class_label"] for row in benign).items())),
        "tasks": args.tasks,
        "architectures": args.architectures,
        "seeds": args.seeds,
        "epochs": args.epochs,
        "patience": args.patience,
        "max_temp_c": args.max_temp_c,
        "pause_temp_c": args.pause_temp_c,
    }
    results: list[dict[str, Any]] = []
    write_evidence(evidence_dir, metadata, results)
    for task in args.tasks:
        rows = task_rows(task, malware, benign)
        for architecture in args.architectures:
            for seed in args.seeds:
                result = train_one(
                    rows,
                    task,
                    architecture,
                    args.image_size,
                    seed,
                    output_root,
                    args.epochs,
                    args.patience,
                    args.max_temp_c,
                    args.pause_temp_c,
                )
                results.append(result)
                write_evidence(evidence_dir, metadata, results)
                print(json.dumps(safe_row(result), sort_keys=True), flush=True)
    write_evidence(evidence_dir, metadata, results)
    summary = {
        "run_id": run_id,
        "output_root": str(output_root),
        "evidence_dir": str(evidence_dir),
        "completed": len([row for row in results if row.get("status") == "completed"]),
        "failed": len([row for row in results if row.get("status") == "failed"]),
        "leaderboard": str(evidence_dir / "planb_overnight_cnn_leaderboard.csv"),
        "summary_md": str(evidence_dir / "planb_overnight_cnn_summary.md"),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run overnight Plan B binary/family/mixed CNN sweeps with odd CNN variants.")
    parser.add_argument("--image-manifest", required=True)
    parser.add_argument("--benign-manifest", default=str(BENIGN_MANIFEST))
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb/model_sweeps")
    parser.add_argument("--run-id")
    parser.add_argument("--target-per-family", type=int, default=500)
    parser.add_argument("--image-size", type=int, default=256)
    parser.add_argument("--image-mode", default="gray")
    parser.add_argument("--tasks", default="binary,malware_family,mixed_multiclass")
    parser.add_argument("--architectures", default=",".join(DEFAULT_ARCHITECTURES))
    parser.add_argument("--seeds", default="1337")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--min-benign-class-rows", type=int, default=50)
    parser.add_argument("--max-temp-c", type=int, default=85)
    parser.add_argument("--pause-temp-c", type=int, default=82)
    args = parser.parse_args()
    args.tasks = parse_strings(args.tasks)
    args.architectures = parse_strings(args.architectures)
    args.seeds = parse_ints(args.seeds)
    return args


if __name__ == "__main__":
    run(parse_args())
