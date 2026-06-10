#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shlex
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_ARCHITECTURES = [
    "compact_cnn",
    "residual_small",
    "inception_small",
    "convnext_tiny_scratch",
    "efficientnetb0_scratch",
]

GENERIC_HINTS = {
    "",
    "generic",
    "generickd",
    "malware",
    "trojan",
    "agent",
    "wacatac",
    "ml",
    "susgen",
    "unsafe",
    "packed",
    "selfdel",
}


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


def run_command(cmd: list[str], log_path: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {shlex.join(cmd)}\n")
            handle.write(proc.stdout or "")
            handle.write(f"\n[exit {proc.returncode}]\n")
    return proc


def send_telegram(args: argparse.Namespace, title: str, lines: list[str]) -> dict[str, Any]:
    if not args.telegram:
        return {"skipped": True}
    body = title + "\n" + "\n".join(lines)
    proc = subprocess.run(
        [
            "ssh",
            "phil@10.64.0.62",
            "sudo",
            "/usr/local/bin/vibex_send_telegram_text.py",
        ],
        input=body,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return {"returncode": proc.returncode, "stdout": proc.stdout[-500:], "stderr": proc.stderr[-500:]}


def sources_agree(hint: dict[str, str], existing_status: str, min_sources: int) -> tuple[bool, str]:
    family = hint.get("tool_hint_family", "").strip().lower()
    if family in GENERIC_HINTS:
        return False, "generic_or_blank_hint"
    if hint.get("candidate_status") != "supporting_hint":
        return False, "not_supporting_hint"
    sources = [item for item in hint.get("hint_sources", "").split(";") if item]
    defender = "defender" in sources
    static_sources = [source for source in sources if source != "defender"]
    if len(set(sources)) >= min_sources:
        return True, "multiple_sources"
    if defender and static_sources:
        return True, "defender_plus_static"
    if defender and existing_status == "labelled":
        return True, "defender_matches_existing_labelled_consensus"
    return False, "insufficient_independent_sources"


def build_augmented_rows(
    family_core: Path,
    family_extended: Path,
    sandbox_hints: Path,
    min_sources: int,
    min_family_rows: int,
) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, Any]]:
    core = read_csv(family_core)
    extended = read_csv(family_extended)
    hints = read_csv(sandbox_hints)
    extended_by_sha = {row.get("raw_sha256", "").lower(): row for row in extended}
    core_shas = {row.get("raw_sha256", "").lower() for row in core}
    rows = [dict(row) for row in core]
    decisions: list[dict[str, str]] = []
    for hint in hints:
        sha = hint.get("raw_sha256", "").lower()
        if not sha or sha in core_shas:
            continue
        ext = extended_by_sha.get(sha)
        if not ext:
            continue
        family = hint.get("tool_hint_family", "").strip().lower()
        ok, reason = sources_agree(hint, ext.get("family_label_status", ""), min_sources)
        vt_family = ext.get("consensus_family", "").strip().lower()
        if ok and vt_family and ext.get("family_label_status") == "labelled" and vt_family != family:
            ok, reason = False, f"conflicts_with_vt_consensus:{vt_family}"
        decisions.append(
            {
                "raw_sha256": sha,
                "tool_hint_family": family,
                "vt_consensus_family": vt_family,
                "family_label_status": ext.get("family_label_status", ""),
                "include_augmented": str(ok),
                "decision_reason": reason,
                "hint_sources": hint.get("hint_sources", ""),
            }
        )
        if ok:
            out = dict(ext)
            out["consensus_family"] = family
            out["family_label_status"] = "sandbox_provisional"
            out["inclusion_reason"] = "windows11_sandbox_high_confidence_hint"
            out["exclusion_reason"] = ""
            rows.append(out)
    counts = Counter(row.get("consensus_family", "").strip().lower() for row in rows)
    allowed = {family for family, count in counts.items() if family and count >= min_family_rows}
    filtered = [row for row in rows if row.get("consensus_family", "").strip().lower() in allowed]
    summary = {
        "created_utc": utc_now(),
        "family_core_rows": len(core),
        "sandbox_hint_rows": len(hints),
        "included_before_min_family_filter": sum(1 for row in decisions if row["include_augmented"] == "True"),
        "augmented_rows": len(filtered),
        "removed_by_min_family_filter": len(rows) - len(filtered),
        "family_count": len(allowed),
        "family_counts": dict(sorted(Counter(row.get("consensus_family", "").strip().lower() for row in filtered).items())),
        "canonical_manifests_changed": False,
    }
    return filtered, decisions, summary


def native_rows(rows: list[dict[str, str]], image_size: int, image_mode: str) -> list[dict[str, str]]:
    out = []
    for row in rows:
        family = row.get("consensus_family", "").strip().lower()
        sha = row.get("raw_sha256", "").strip().lower()
        image_path = row.get("dataset_image_path", "").strip()
        if not family or len(sha) != 64 or not image_path or not Path(image_path).exists():
            continue
        item = dict(row)
        item.update(
            {
                "family": family,
                "sha256_hash": sha,
                "image_path": image_path,
                "image_size": str(image_size),
                "image_mode": image_mode,
            }
        )
        out.append(item)
    return out


def benign_native_rows(release_manifest: Path, image_size: int, image_mode: str) -> list[dict[str, str]]:
    out = []
    for row in read_csv(release_manifest):
        if row.get("binary_label") != "benign":
            continue
        if row.get("file_kind", "").lower() not in {"pe", "mz"}:
            continue
        sha = row.get("raw_sha256", "").strip().lower()
        image_path = row.get("dataset_image_path", "").strip()
        if len(sha) != 64 or not image_path or not Path(image_path).exists():
            continue
        item = dict(row)
        item.update(
            {
                "family": "benign",
                "consensus_family": "benign",
                "sha256_hash": sha,
                "image_path": image_path,
                "image_size": str(image_size),
                "image_mode": image_mode,
            }
        )
        out.append(item)
    return out


def class_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    return dict(sorted(Counter(row["family"] for row in rows).items()))


def best_from_result(evidence_dir: Path) -> dict[str, Any]:
    results_path = evidence_dir / "planb_native_family_results.json"
    if not results_path.exists():
        return {}
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    results = [row for row in payload.get("results", []) if row.get("status") == "completed"]
    if not results:
        return {}
    best_seed = max(results, key=lambda row: (row.get("macro_f1") or 0.0, row.get("weighted_f1") or 0.0, row.get("accuracy") or 0.0))
    per_class = best_seed.get("per_class_f1") or {}
    weakest = sorted(per_class.items(), key=lambda item: item[1])[:5]
    aggregates = payload.get("aggregates") or []
    best_group = aggregates[0] if aggregates else {}
    return {"best_seed": best_seed, "best_group": best_group, "weakest": weakest}


def write_master_summary(run_dir: Path, group_results: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    write_json(run_dir / "overall_results.json", {"metadata": metadata, "groups": group_results})
    rows = []
    for group in group_results:
        best = group.get("best", {}).get("best_group", {})
        rows.append(
            {
                "phase": group.get("phase"),
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
    by_phase: dict[str, list[dict[str, Any]]] = {}
    for group in group_results:
        by_phase.setdefault(group["phase"], []).append(group)
    lines = [
        "# VIBEX PNG Family And Benign Model Experiment",
        "",
        f"- Run ID: `{metadata['run_id']}`",
        f"- Created UTC: `{metadata['created_utc']}`",
        f"- Models: `{', '.join(metadata['architectures'])}`",
        f"- Image setting: `{metadata['image_size']} {metadata['image_mode']}`",
        f"- Seeds: `{', '.join(str(seed) for seed in metadata['seeds'])}`",
        "",
    ]
    for phase, groups in sorted(by_phase.items()):
        completed = [group for group in groups if group.get("status") == "completed"]
        best = max(
            completed,
            key=lambda group: (group.get("best", {}).get("best_group", {}).get("macro_f1_mean") or 0.0),
            default=None,
        )
        lines.append(f"## {phase}")
        lines.append("")
        lines.append(f"- Completed model groups: `{len(completed)} / {len(groups)}`")
        if best:
            bg = best["best"]["best_group"]
            lines.append(f"- Best architecture: `{best['architecture']}`")
            lines.append(f"- Best macro-F1 mean: `{float(bg.get('macro_f1_mean') or 0):.4f}`")
            lines.append(f"- Best weighted-F1 mean: `{float(bg.get('weighted_f1_mean') or 0):.4f}`")
            lines.append(f"- Best accuracy mean: `{float(bg.get('accuracy_mean') or 0):.4f}`")
        lines.append("")
    family_best = max(
        [group for group in group_results if group.get("phase") == "malware_family_only" and group.get("status") == "completed"],
        key=lambda group: (group.get("best", {}).get("best_group", {}).get("macro_f1_mean") or 0.0),
        default=None,
    )
    benign_best = max(
        [group for group in group_results if group.get("phase") == "malware_family_plus_benign" and group.get("status") == "completed"],
        key=lambda group: (group.get("best", {}).get("best_group", {}).get("macro_f1_mean") or 0.0),
        default=None,
    )
    if family_best and benign_best:
        family_macro = float(family_best["best"]["best_group"].get("macro_f1_mean") or 0)
        benign_macro = float(benign_best["best"]["best_group"].get("macro_f1_mean") or 0)
        delta = benign_macro - family_macro
        lines.extend(
            [
                "## Benign Inclusion Comparison",
                "",
                f"- Family-only best macro-F1: `{family_macro:.4f}`",
                f"- Family-plus-benign best macro-F1: `{benign_macro:.4f}`",
                f"- Delta: `{delta:.4f}`",
                f"- Material reduction: `{delta <= -0.02}`",
                "",
            ]
        )
    (run_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def telegram_progress(args: argparse.Namespace, group_results: list[dict[str, Any]], current: str, total: int, started: float) -> None:
    completed = [group for group in group_results if group.get("status") == "completed"]
    best = max(
        completed,
        key=lambda group: (group.get("best", {}).get("best_group", {}).get("macro_f1_mean") or 0.0),
        default=None,
    )
    elapsed = time.time() - started
    per_group = elapsed / max(len(group_results), 1)
    eta = per_group * max(total - len(group_results), 0)
    lines = [
        f"Run: {args.run_id}",
        f"Completed model groups: {len(group_results)} of {total}",
        f"Current model: {current}",
    ]
    if best:
        bg = best["best"]["best_group"]
        weakest = ", ".join(f"{label}={value:.3f}" for label, value in best["best"].get("weakest", [])[:5])
        lines.extend(
            [
                f"Best so far: {best['phase']} / {best['architecture']}",
                f"Best macro-F1: {float(bg.get('macro_f1_mean') or 0):.4f}",
                f"Best weighted-F1: {float(bg.get('weighted_f1_mean') or 0):.4f}",
                f"Best accuracy: {float(bg.get('accuracy_mean') or 0):.4f}",
                f"Weakest classes: {weakest or 'not available yet'}",
            ]
        )
    lines.extend([f"Elapsed: {elapsed / 3600:.2f} hours", f"ETA: {eta / 3600:.2f} hours"])
    send_telegram(args, "VIBEX model test update", lines)


def run_native_group(
    args: argparse.Namespace,
    run_dir: Path,
    phase: str,
    manifest: Path,
    architecture: str,
) -> dict[str, Any]:
    group_run_id = f"{args.run_id}_{phase}_{architecture}"
    output_root = run_dir / "model_sweeps" / phase
    log_path = run_dir / "logs" / f"{phase}_{architecture}.log"
    cmd = [
        "python3",
        str(args.native_runner),
        "--image-manifest",
        str(manifest),
        "--output-root",
        str(output_root),
        "--run-id",
        group_run_id,
        "--architectures",
        architecture,
        "--image-sizes",
        str(args.image_size),
        "--image-modes",
        args.image_mode,
        "--seeds",
        ",".join(str(seed) for seed in args.seeds),
        "--epochs",
        str(args.epochs),
        "--patience",
        str(args.patience),
        "--target-per-family",
        str(args.target_per_class),
    ]
    started = time.time()
    proc = run_command(cmd, log_path=log_path)
    evidence_dir = output_root / group_run_id / "evidence"
    best = best_from_result(evidence_dir)
    status = "completed" if proc.returncode == 0 and best else "failed"
    return {
        "phase": phase,
        "architecture": architecture,
        "status": status,
        "returncode": proc.returncode,
        "elapsed_seconds": round(time.time() - started, 3),
        "evidence_dir": str(evidence_dir),
        "log_path": str(log_path),
        "best": best,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run VIBEX PNG family models with and without benign PNGs.")
    parser.add_argument("--run-id", default=f"vibex_png_family_benign_{utc_stamp()}")
    parser.add_argument("--output-root", default="/home/phil/vibex_secure_dataset/evidence/png_family_benign_model_runs")
    parser.add_argument("--family-core", required=True)
    parser.add_argument("--family-extended", required=True)
    parser.add_argument("--sandbox-hints", required=True)
    parser.add_argument("--release-manifest", required=True)
    parser.add_argument("--native-runner", required=True, type=Path)
    parser.add_argument("--architectures", default=",".join(DEFAULT_ARCHITECTURES))
    parser.add_argument("--image-size", type=int, default=256)
    parser.add_argument("--image-mode", default="gray")
    parser.add_argument("--seeds", default="1337,2026,4242")
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--target-per-class", type=int, default=20)
    parser.add_argument("--min-sources", type=int, default=2)
    parser.add_argument("--min-family-rows", type=int, default=20)
    parser.add_argument("--telegram", action="store_true")
    args = parser.parse_args()
    args.architectures = [item.strip() for item in args.architectures.split(",") if item.strip()]
    args.seeds = [int(item.strip()) for item in str(args.seeds).split(",") if item.strip()]

    run_dir = Path(args.output_root) / args.run_id
    input_dir = run_dir / "input"
    manifest_dir = run_dir / "manifests"
    run_dir.mkdir(parents=True, exist_ok=True)

    augmented_rows, decisions, augmented_summary = build_augmented_rows(
        Path(args.family_core),
        Path(args.family_extended),
        Path(args.sandbox_hints),
        args.min_sources,
        args.min_family_rows,
    )
    family_only_rows = native_rows(augmented_rows, args.image_size, args.image_mode)
    benign_rows = benign_native_rows(Path(args.release_manifest), args.image_size, args.image_mode)
    family_plus_benign_rows = list(family_only_rows) + benign_rows

    family_only_manifest = manifest_dir / "malware_family_only_native_manifest.csv"
    family_plus_benign_manifest = manifest_dir / "malware_family_plus_benign_native_manifest.csv"
    write_csv(family_only_manifest, family_only_rows)
    write_csv(family_plus_benign_manifest, family_plus_benign_rows)
    write_csv(manifest_dir / "sandbox_augmented_candidate_decisions.csv", decisions)
    write_json(manifest_dir / "manifest_summary.json", {
        "augmented": augmented_summary,
        "family_only_class_counts": class_counts(family_only_rows),
        "family_plus_benign_class_counts": class_counts(family_plus_benign_rows),
        "input_dir": str(input_dir),
    })

    metadata = {
        "run_id": args.run_id,
        "created_utc": utc_now(),
        "architectures": args.architectures,
        "image_size": args.image_size,
        "image_mode": args.image_mode,
        "seeds": args.seeds,
        "epochs": args.epochs,
        "patience": args.patience,
        "target_per_class": args.target_per_class,
        "canonical_manifests_changed": False,
        "raw_artifacts_in_git": False,
    }
    write_json(run_dir / "run_metadata.json", metadata)

    total_groups = len(args.architectures) * 2
    send_telegram(
        args,
        "VIBEX model test update",
        [
            f"Run: {args.run_id}",
            "Status: started",
            f"Model groups: {total_groups}",
            f"Models: {', '.join(args.architectures)}",
            f"Image setting: {args.image_size} {args.image_mode}",
            f"Family-only classes: {len(class_counts(family_only_rows))}",
            f"Family-plus-benign classes: {len(class_counts(family_plus_benign_rows))}",
        ],
    )

    group_results: list[dict[str, Any]] = []
    started = time.time()
    phases = [
        ("malware_family_only", family_only_manifest),
        ("malware_family_plus_benign", family_plus_benign_manifest),
    ]
    for phase, manifest in phases:
        for architecture in args.architectures:
            current = f"{phase} / {architecture}"
            try:
                result = run_native_group(args, run_dir, phase, manifest, architecture)
            except Exception as exc:
                result = {
                    "phase": phase,
                    "architecture": architecture,
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:1000],
                }
                send_telegram(args, "VIBEX model test update", [f"Run: {args.run_id}", f"Failure: {current}", f"Error: {result['error']}"])
            group_results.append(result)
            write_master_summary(run_dir, group_results, metadata)
            telegram_progress(args, group_results, current, total_groups, started)

    write_master_summary(run_dir, group_results, metadata)
    completed = [group for group in group_results if group.get("status") == "completed"]
    best = max(
        completed,
        key=lambda group: (group.get("best", {}).get("best_group", {}).get("macro_f1_mean") or 0.0),
        default=None,
    )
    lines = [
        f"Run: {args.run_id}",
        f"Status: complete",
        f"Completed groups: {len(completed)} of {total_groups}",
        f"Output: {run_dir}",
    ]
    if best:
        bg = best["best"]["best_group"]
        lines.extend(
            [
                f"Best: {best['phase']} / {best['architecture']}",
                f"Best macro-F1: {float(bg.get('macro_f1_mean') or 0):.4f}",
                f"Best weighted-F1: {float(bg.get('weighted_f1_mean') or 0):.4f}",
                f"Best accuracy: {float(bg.get('accuracy_mean') or 0):.4f}",
            ]
        )
    send_telegram(args, "VIBEX model test update", lines)
    return 0 if len(completed) == total_groups else 1


if __name__ == "__main__":
    raise SystemExit(main())
