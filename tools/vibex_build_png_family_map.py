#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GENERIC_OR_NONFAMILY = {
    "",
    "ambiguous",
    "generickd",
    "heur",
    "insufficient_votes",
    "malware",
    "packed",
    "packer",
    "trojan",
    "unlabelled",
    "unknown",
    "variant",
    "virus",
    "vmprotect",
    "win32",
}

HIGH_SIGNAL_FAMILIES = {
    "autorun",
    "benign",
    "bmhfbyrbndc",
    "delf",
    "dnsr",
    "expiro",
    "juko",
    "qqpass",
    "salgorea",
    "sivis",
    "strictor",
    "upantix",
    "upatre",
    "urelas",
    "vbclone",
    "zusy",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def family_value(row: dict[str, str]) -> str:
    return str(row.get("consensus_family") or row.get("family") or "").strip().lower()


def indexed(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    out = {}
    for row in rows:
        sha = str(row.get("raw_sha256") or "").strip().lower()
        if sha and sha not in out:
            out[sha] = row
    return out


def map_row(
    row: dict[str, str],
    core_by_sha: dict[str, dict[str, str]],
    extended_by_sha: dict[str, dict[str, str]],
) -> dict[str, Any]:
    sha = str(row.get("raw_sha256") or "").strip().lower()
    binary_label = str(row.get("binary_label") or "").strip().lower()
    mapped_family = ""
    mapping_status = "unmapped"
    mapping_tier = "none"
    source_family_status = ""
    source_family_confidence = ""
    source_family_votes = ""
    model_publish_tier = "not_in_family_model"

    if binary_label == "benign":
        mapped_family = "benign"
        mapping_status = "mapped_benign"
        mapping_tier = "binary_label"
        source_family_status = "benign"
        model_publish_tier = "high_signal_model"
    elif sha in core_by_sha:
        source = core_by_sha[sha]
        mapped_family = family_value(source)
        mapping_status = "mapped_family_core"
        mapping_tier = "family_core"
        source_family_status = str(source.get("family_label_status") or "")
        source_family_confidence = str(source.get("family_label_confidence") or "")
        source_family_votes = str(source.get("family_label_votes") or "")
    elif sha in extended_by_sha:
        source = extended_by_sha[sha]
        candidate = family_value(source)
        source_family_status = str(source.get("family_label_status") or "")
        source_family_confidence = str(source.get("family_label_confidence") or "")
        source_family_votes = str(source.get("family_label_votes") or "")
        if source_family_status == "labelled" and candidate not in GENERIC_OR_NONFAMILY:
            mapped_family = candidate
            mapping_status = "mapped_family_extended_labelled"
            mapping_tier = "family_extended"
        else:
            mapped_family = candidate
            mapping_status = f"needs_review_{source_family_status or 'unlabelled'}"
            mapping_tier = "family_extended_review"

    if mapped_family in HIGH_SIGNAL_FAMILIES:
        model_publish_tier = "high_signal_model"
    elif mapping_status.startswith("mapped_family"):
        model_publish_tier = "labelled_not_high_signal"

    return {
        "raw_sha256": sha,
        "image_sha256": row.get("image_sha256", ""),
        "dataset_image_path": row.get("dataset_image_path", ""),
        "split": row.get("split", ""),
        "file_kind": row.get("file_kind", ""),
        "binary_label": binary_label,
        "source": row.get("source", ""),
        "mapped_family": mapped_family,
        "mapping_status": mapping_status,
        "mapping_tier": mapping_tier,
        "model_publish_tier": model_publish_tier,
        "source_family_status": source_family_status,
        "source_family_votes": source_family_votes,
        "source_family_confidence": source_family_confidence,
    }


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# VIBEX-50K PNG Family Map",
        "",
        f"- Created UTC: `{summary['created_utc']}`",
        f"- Total PNG rows: `{summary['total_rows']}`",
        f"- Unique image SHA-256 values: `{summary['unique_image_sha256']}`",
        f"- Unique raw SHA-256 values: `{summary['unique_raw_sha256']}`",
        "",
        "## Mapping Status",
        "",
        "| Status | Rows |",
        "| --- | ---: |",
    ]
    for key, value in summary["mapping_status_counts"].items():
        lines.append(f"| `{key}` | {value} |")
    lines.extend(["", "## Model Publish Tier", "", "| Tier | Rows |", "| --- | ---: |"])
    for key, value in summary["model_publish_tier_counts"].items():
        lines.append(f"| `{key}` | {value} |")
    lines.extend(
        [
            "",
            "The high-signal model tier is the current publishable family+benign model subset. "
            "Rows marked `needs_review_*` are mapped to review status, not promoted as reliable family labels.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a safe PNG-to-family mapping for VIBEX-50K.")
    parser.add_argument("--binary-pe", default="datasets/binary_pe/manifest.csv")
    parser.add_argument("--binary-elf", default="datasets/binary_elf/manifest.csv")
    parser.add_argument("--family-core", default="datasets/family_core/manifest.csv")
    parser.add_argument("--family-extended", default="datasets/family_extended/manifest.csv")
    parser.add_argument("--output-dir", default="evidence/family_png_mapping")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    base_rows = read_csv(Path(args.binary_pe)) + read_csv(Path(args.binary_elf))
    core_by_sha = indexed(read_csv(Path(args.family_core)))
    extended_by_sha = indexed(read_csv(Path(args.family_extended)))
    mapped = [map_row(row, core_by_sha, extended_by_sha) for row in base_rows]
    output_csv = output_dir / "vibex50_png_family_map_latest.csv"
    write_csv(output_csv, mapped)
    summary = {
        "created_utc": utc_now(),
        "output_csv": str(output_csv),
        "total_rows": len(mapped),
        "unique_image_sha256": len({row["image_sha256"] for row in mapped}),
        "unique_raw_sha256": len({row["raw_sha256"] for row in mapped}),
        "binary_label_counts": dict(sorted(Counter(row["binary_label"] for row in mapped).items())),
        "mapping_status_counts": dict(sorted(Counter(row["mapping_status"] for row in mapped).items())),
        "mapping_tier_counts": dict(sorted(Counter(row["mapping_tier"] for row in mapped).items())),
        "model_publish_tier_counts": dict(sorted(Counter(row["model_publish_tier"] for row in mapped).items())),
        "mapped_family_counts": dict(sorted(Counter(row["mapped_family"] for row in mapped if row["mapped_family"]).items())),
    }
    write_json(output_dir / "vibex50_png_family_map_latest_summary.json", summary)
    write_markdown(output_dir / "vibex50_png_family_map_latest_summary.md", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
