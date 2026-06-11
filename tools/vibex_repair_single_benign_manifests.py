#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_REPRESENTATIONS = [
    "section_table_layout_64",
    "pe_header_layout_128",
    "prefix4096_64",
    "prefix8192_128_padded",
    "prefix12288_128_padded",
    "prefix16384_128",
]

BENIGN_SOURCE_FIELDS = [
    "benign_source",
    "source",
    "vibex50_source_component",
    "original_family_field",
    "family",
]


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


def is_benign(row: dict[str, str]) -> bool:
    return str(row.get("binary_label") or "").strip().lower() == "benign"


def row_sha(row: dict[str, str]) -> str:
    return str(row.get("sha256_hash") or row.get("raw_sha256") or "").strip().lower()


def benign_source(row: dict[str, str]) -> str:
    for field in BENIGN_SOURCE_FIELDS:
        value = str(row.get(field) or "").strip()
        if value and value.lower() not in {"benign", "unknown", "none"}:
            return value
    return "benign_unknown"


def source_balanced_benign(rows: list[dict[str, str]], max_rows: int) -> list[dict[str, str]]:
    if max_rows <= 0 or len(rows) <= max_rows:
        return rows

    by_source: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_source[benign_source(row)].append(row)
    for bucket in by_source.values():
        bucket.sort(key=row_sha)

    selected: list[dict[str, str]] = []
    sources = sorted(by_source)
    index = 0
    while len(selected) < max_rows and sources:
        source = sources[index % len(sources)]
        bucket = by_source[source]
        if bucket:
            selected.append(bucket.pop(0))
        sources = [item for item in sources if by_source[item]]
        index += 1
    return selected


def repaired_rows(
    rows: list[dict[str, str]],
    max_benign_rows: int,
    min_malware_family_rows: int,
    exclude_families: set[str],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    malware_rows: list[dict[str, str]] = []
    benign_rows: list[dict[str, str]] = []
    skipped = Counter()
    seen: set[str] = set()

    for original in rows:
        sha = row_sha(original)
        if not sha:
            skipped["missing_sha"] += 1
            continue
        if sha in seen:
            skipped["duplicate_sha"] += 1
            continue
        seen.add(sha)
        row = dict(original)
        if is_benign(row):
            row["family"] = "benign"
            row["consensus_family"] = "benign"
            row["family_label_status"] = "benign_single_class"
            row["dataset_mode"] = "malware_plus_single_benign"
            row["repair_note"] = "benign source family collapsed to single benign class"
            benign_rows.append(row)
            continue

        family = str(row.get("family") or row.get("consensus_family") or "").strip().lower()
        if not family:
            skipped["missing_malware_family"] += 1
            continue
        row["family"] = family
        row["dataset_mode"] = "malware_plus_single_benign"
        row["repair_note"] = "malware family preserved from defensible extended manifest"
        malware_rows.append(row)

    malware_counts = Counter(row["family"] for row in malware_rows)
    filtered_malware_rows = []
    for row in malware_rows:
        family = row["family"]
        if family in exclude_families:
            skipped["excluded_family"] += 1
            continue
        if min_malware_family_rows > 0 and malware_counts[family] < min_malware_family_rows:
            skipped["below_min_malware_family_rows"] += 1
            continue
        filtered_malware_rows.append(row)

    kept_benign = source_balanced_benign(benign_rows, max_benign_rows)
    repaired = filtered_malware_rows + kept_benign
    repaired.sort(key=lambda item: (item.get("family", ""), row_sha(item)))
    summary = {
        "input_rows": len(rows),
        "output_rows": len(repaired),
        "malware_rows_input": len(malware_rows),
        "malware_rows": len(filtered_malware_rows),
        "min_malware_family_rows": min_malware_family_rows,
        "excluded_families": sorted(exclude_families),
        "benign_rows_input": len(benign_rows),
        "benign_rows_kept": len(kept_benign),
        "max_benign_rows": max_benign_rows,
        "family_count": len({row["family"] for row in repaired}),
        "malware_family_counts_input": dict(sorted(malware_counts.items())),
        "class_counts": dict(sorted(Counter(row["family"] for row in repaired).items())),
        "benign_source_counts_input": dict(sorted(Counter(benign_source(row) for row in benign_rows).items())),
        "benign_source_counts_kept": dict(sorted(Counter(benign_source(row) for row in kept_benign).items())),
        "skipped": dict(sorted(skipped.items())),
    }
    return repaired, summary


def write_markdown(path: Path, run_summary: dict[str, Any]) -> None:
    lines = [
        "# VIBEX Single-Benign Manifest Repair",
        "",
        f"- Created UTC: `{run_summary['created_utc']}`",
        f"- Source run dir: `{run_summary['source_run_dir']}`",
        f"- Output dir: `{run_summary['output_dir']}`",
        f"- Repair rule: benign source labels are collapsed into one `benign` class; malware family labels are preserved.",
        f"- Max benign rows per representation: `{run_summary['max_benign_rows']}`",
        "",
        "## Representations",
        "",
        "| Representation | Rows | Malware | Benign | Classes | Top classes |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for rep, item in run_summary["representations"].items():
        counts = item["class_counts"]
        top = ", ".join(f"{family}:{count}" for family, count in Counter(counts).most_common(8))
        lines.append(
            f"| {rep} | {item['output_rows']} | {item['malware_rows']} | "
            f"{item['benign_rows_kept']} | {item['family_count']} | {top} |"
        )
    lines.extend(
        [
            "",
            "Raw malware, derived PNG files, and model binaries remain on secure workhorse storage. "
            "This repair output is a safe manifest/control artifact for model testing.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collapse benign source labels to a single benign class in workhorse representation manifests.")
    parser.add_argument("--source-run-dir", required=True, help="Existing AI-guided run directory containing manifests/.")
    parser.add_argument("--output-dir", required=True, help="Output directory for repaired manifests and safe summaries.")
    parser.add_argument("--representations", default=",".join(DEFAULT_REPRESENTATIONS))
    parser.add_argument("--source-mode", default="malware_plus_benign_sources")
    parser.add_argument("--max-benign-rows", type=int, default=1000)
    parser.add_argument("--min-malware-family-rows", type=int, default=20)
    parser.add_argument("--exclude-families", default="", help="Comma-separated malware families to exclude from the repaired manifest.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source_run_dir = Path(args.source_run_dir)
    output_dir = Path(args.output_dir)
    selected_reps = [item.strip() for item in args.representations.split(",") if item.strip()]

    run_summary: dict[str, Any] = {
        "created_utc": utc_now(),
        "source_run_dir": str(source_run_dir),
        "output_dir": str(output_dir),
        "source_mode": args.source_mode,
        "max_benign_rows": args.max_benign_rows,
        "min_malware_family_rows": args.min_malware_family_rows,
        "excluded_families": sorted({item.strip().lower() for item in args.exclude_families.split(",") if item.strip()}),
        "representations": {},
    }
    exclude_families = set(run_summary["excluded_families"])

    for rep in selected_reps:
        input_path = source_run_dir / "manifests" / f"{args.source_mode}_{rep}.csv"
        if not input_path.exists():
            raise SystemExit(f"missing source manifest: {input_path}")
        rows = read_csv(input_path)
        fixed, summary = repaired_rows(rows, args.max_benign_rows, args.min_malware_family_rows, exclude_families)
        output_path = output_dir / "manifests" / f"malware_plus_single_benign_{rep}.csv"
        write_csv(output_path, fixed)
        summary.update(
            {
                "representation": rep,
                "input_manifest": str(input_path),
                "output_manifest": str(output_path),
            }
        )
        run_summary["representations"][rep] = summary

    write_json(output_dir / "repair_manifest_summary.json", run_summary)
    write_markdown(output_dir / "repair_manifest_summary.md", run_summary)
    print(json.dumps(run_summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
