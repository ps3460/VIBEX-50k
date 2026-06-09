#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path


REASON_WEIGHT = {
    "excluded_ambiguous": 100,
    "excluded_unstable_family": 90,
    "excluded_generic_family": 80,
    "excluded_low_support_family": 70,
    "excluded_insufficient_votes": 60,
    "excluded_unlabelled": 30,
    "excluded_rate_limited": 20,
}


def utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def as_int(value: str) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def as_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def row_priority(row: dict[str, str], family_counts: Counter[str]) -> int:
    reason = row.get("exclusion_reason", "")
    family = row.get("consensus_family", "").strip().lower()
    votes = as_int(row.get("family_label_votes", ""))
    engines = as_int(row.get("family_label_engine_count", ""))
    confidence = as_float(row.get("family_label_confidence", ""))
    support = family_counts.get(family, 0)
    return (
        REASON_WEIGHT.get(reason, 0) * 10000
        + min(support, 999) * 10
        + min(votes, 99) * 5
        + min(engines, 99)
        + int(confidence * 100)
    )


def build_candidates(rows: list[dict[str, str]], limit: int) -> list[dict[str, object]]:
    labelled_counts = Counter(
        row.get("consensus_family", "").strip().lower()
        for row in rows
        if row.get("family_label_status") == "labelled" and row.get("consensus_family")
    )
    candidates: list[dict[str, object]] = []
    seen: set[str] = set()
    for row in rows:
        sha = row.get("raw_sha256", "").strip().lower()
        if not sha or sha in seen:
            continue
        seen.add(sha)
        if row.get("binary_label") != "malware":
            continue
        if row.get("file_kind", "").lower() not in {"pe", "mz"}:
            continue
        reason = row.get("exclusion_reason", "")
        family = row.get("consensus_family", "").strip().lower()
        status = row.get("family_label_status", "").strip()
        candidates.append(
            {
                "priority": row_priority(row, labelled_counts),
                "raw_sha256": sha,
                "split": row.get("split", ""),
                "consensus_family": family,
                "family_label_status": status,
                "exclusion_reason": reason,
                "family_label_votes": row.get("family_label_votes", ""),
                "family_label_engine_count": row.get("family_label_engine_count", ""),
                "family_label_confidence": row.get("family_label_confidence", ""),
                "family_extended_support": labelled_counts.get(family, 0),
                "vt_report_path": row.get("vt_report_path", ""),
                "dataset_image_path": row.get("dataset_image_path", ""),
                "source": row.get("source", ""),
                "original_family_field": row.get("original_family_field", ""),
                "sandbox_action": sandbox_action(reason, status, family),
            }
        )
    candidates.sort(
        key=lambda row: (
            -int(row["priority"]),
            str(row["exclusion_reason"]),
            str(row["consensus_family"]),
            str(row["raw_sha256"]),
        )
    )
    return candidates[:limit]


def sandbox_action(reason: str, status: str, family: str) -> str:
    if reason == "excluded_ambiguous":
        return "static_and_dynamic_triage_for_family_hint"
    if reason == "excluded_unstable_family":
        return "dynamic_behavior_check_against_unstable_consensus"
    if reason == "excluded_generic_family":
        return "static_strings_capa_yara_for_non_generic_hint"
    if reason == "excluded_low_support_family":
        return "confirm_low_support_family_behavior"
    if reason == "excluded_insufficient_votes":
        return "static_triage_before_any_detonation"
    if status == "unlabelled" or not family:
        return "metadata_first_then_static_triage"
    return "review_only"


def write_markdown(path: Path, report: dict[str, object], candidates: list[dict[str, object]]) -> None:
    summary = report["summary"]
    lines = [
        "# VIBEX Family Classification Status",
        "",
        f"- Created UTC: `{report['created_utc']}`",
        f"- `family_core` rows: `{summary['family_core_rows']}`",
        f"- `family_core` families: `{summary['family_core_families']}`",
        f"- `family_extended` rows: `{summary['family_extended_rows']}`",
        f"- Sandbox candidates emitted: `{len(candidates)}`",
        "",
        "## Current Classification",
        "",
        "Strict family classification remains limited to `family_core`: stable, non-generic consensus families with minimum support. Rows in `family_extended` remain supplemental/audit candidates until enough independent evidence exists.",
        "",
        "## family_extended Exclusion Counts",
        "",
    ]
    for reason, count in summary["extended_exclusion_counts"]:
        lines.append(f"- `{reason}`: {count}")
    lines.extend(["", "## Top family_core Families", ""])
    for family, count in summary["top_core_families"]:
        lines.append(f"- `{family}`: {count}")
    lines.extend(["", "## Top Sandbox Candidates", ""])
    for row in candidates[:25]:
        lines.append(
            f"- `{row['raw_sha256']}` `{row['exclusion_reason']}` "
            f"`{row['consensus_family']}` votes `{row['family_label_votes']}` "
            f"action `{row['sandbox_action']}`"
        )
    lines.extend(
        [
            "",
            "## Safety Notes",
            "",
            "- This report contains hashes and safe metadata only.",
            "- Raw binaries and full detonation artifacts must stay outside the research repo.",
            "- Sandbox output is supplemental evidence only; promotion to `family_core` still requires the existing VIBEX policy.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Select safe VIBEX family-classification sandbox candidates.")
    parser.add_argument("--family-core", default="datasets/family_core/manifest.csv")
    parser.add_argument("--family-extended", default="datasets/family_extended/manifest.csv")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    core_rows = read_csv(Path(args.family_core))
    extended_rows = read_csv(Path(args.family_extended))
    stamp = utc_stamp()
    output_dir = Path(args.output_dir) if args.output_dir else Path("evidence") / "sandbox" / f"family_classification_{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    core_family_counts = Counter(row.get("consensus_family", "").strip().lower() for row in core_rows)
    extended_reason_counts = Counter(row.get("exclusion_reason", "") for row in extended_rows)
    candidates = build_candidates(extended_rows, args.limit)

    candidate_fields = [
        "priority",
        "raw_sha256",
        "split",
        "consensus_family",
        "family_label_status",
        "exclusion_reason",
        "family_label_votes",
        "family_label_engine_count",
        "family_label_confidence",
        "family_extended_support",
        "vt_report_path",
        "dataset_image_path",
        "source",
        "original_family_field",
        "sandbox_action",
    ]
    candidates_path = output_dir / "sandbox_family_candidates.csv"
    write_csv(candidates_path, candidates, candidate_fields)

    report = {
        "created_utc": datetime.now(UTC).isoformat(),
        "summary": {
            "family_core_rows": len(core_rows),
            "family_core_families": len([family for family in core_family_counts if family]),
            "family_extended_rows": len(extended_rows),
            "extended_exclusion_counts": extended_reason_counts.most_common(),
            "top_core_families": core_family_counts.most_common(30),
        },
        "candidate_csv": str(candidates_path),
    }
    (output_dir / "family_classification_status.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_markdown(output_dir / "family_classification_status.md", report, candidates)
    print(json.dumps({"output_dir": str(output_dir), "candidates": len(candidates)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
