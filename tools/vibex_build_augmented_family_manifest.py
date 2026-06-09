#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(dict.fromkeys([key for row in rows for key in row.keys()]))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


GENERIC = {
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


def high_confidence(row: dict[str, str], existing_status: str, min_sources: int) -> tuple[bool, str]:
    family = row.get("tool_hint_family", "").strip().lower()
    if family in GENERIC:
        return False, "generic_or_blank_hint"
    sources = [item for item in row.get("hint_sources", "").split(";") if item]
    defender = "defender" in sources
    static_sources = [src for src in sources if src != "defender"]
    if len(set(sources)) >= min_sources:
        return True, "multiple_sources"
    if defender and static_sources:
        return True, "defender_plus_static"
    if defender and existing_status == "labelled":
        return True, "defender_matches_existing_labelled_consensus"
    return False, "insufficient_independent_sources"


def build(args: argparse.Namespace) -> dict[str, Any]:
    core = read_csv(Path(args.family_core))
    extended = read_csv(Path(args.family_extended))
    hints = read_csv(Path(args.hints))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    extended_by_sha = {row.get("raw_sha256", "").lower(): row for row in extended}
    core_shas = {row.get("raw_sha256", "").lower() for row in core}
    rows = [dict(row) for row in core]
    decisions: list[dict[str, Any]] = []
    for hint in hints:
        sha = hint.get("raw_sha256", "").lower()
        if not sha or sha in core_shas:
            continue
        ext = extended_by_sha.get(sha)
        if not ext:
            continue
        family = hint.get("tool_hint_family", "").strip().lower()
        ok, reason = high_confidence(hint, ext.get("family_label_status", ""), args.min_sources)
        vt_family = ext.get("consensus_family", "").strip().lower()
        if ok and vt_family and ext.get("family_label_status") == "labelled" and vt_family != family:
            ok, reason = False, f"conflicts_with_vt_consensus:{vt_family}"
        decision = {
            "raw_sha256": sha,
            "tool_hint_family": family,
            "vt_consensus_family": vt_family,
            "family_label_status": ext.get("family_label_status", ""),
            "exclusion_reason": ext.get("exclusion_reason", ""),
            "include_augmented": ok,
            "decision_reason": reason,
            "hint_sources": hint.get("hint_sources", ""),
            "defender_name": hint.get("defender_name", ""),
        }
        decisions.append(decision)
        if ok:
            out = dict(ext)
            out["consensus_family"] = family
            out["family_label_status"] = "sandbox_provisional"
            out["inclusion_reason"] = "server2025_sandbox_high_confidence_hint"
            out["exclusion_reason"] = ""
            rows.append(out)

    counts = Counter(row.get("consensus_family", "").strip().lower() for row in rows)
    allowed = {family for family, count in counts.items() if family and count >= args.min_family_rows}
    filtered = [row for row in rows if row.get("consensus_family", "").strip().lower() in allowed]
    removed = len(rows) - len(filtered)
    fields = list(dict.fromkeys([key for row in filtered for key in row.keys()]))
    write_csv(output_dir / "family_core_baseline_manifest.csv", core)
    write_csv(output_dir / "family_augmented_experimental_manifest.csv", filtered, fields)
    write_csv(output_dir / "family_augmented_candidate_decisions.csv", decisions)
    summary = {
        "created_utc": utc_now(),
        "family_core_rows": len(core),
        "hint_rows": len(hints),
        "included_before_min_family_filter": sum(1 for row in decisions if row["include_augmented"]),
        "augmented_rows": len(filtered),
        "removed_by_min_family_filter": removed,
        "family_count": len(allowed),
        "family_counts": dict(sorted(Counter(row.get("consensus_family", "").strip().lower() for row in filtered).items())),
        "canonical_manifests_changed": False,
    }
    (output_dir / "family_augmented_manifest_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Server 2025 Augmented Family Manifest",
        "",
        f"- Created UTC: `{summary['created_utc']}`",
        f"- Baseline rows: `{summary['family_core_rows']}`",
        f"- Sandbox hint rows: `{summary['hint_rows']}`",
        f"- Included before min-family filter: `{summary['included_before_min_family_filter']}`",
        f"- Augmented rows after filter: `{summary['augmented_rows']}`",
        f"- Families after filter: `{summary['family_count']}`",
        "- Canonical manifests changed: `False`",
    ]
    (output_dir / "family_augmented_manifest_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build experimental family manifest from Server 2025 sandbox hints.")
    parser.add_argument("--family-core", default="datasets/family_core/manifest.csv")
    parser.add_argument("--family-extended", default="datasets/family_extended/manifest.csv")
    parser.add_argument("--hints", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--min-sources", type=int, default=2)
    parser.add_argument("--min-family-rows", type=int, default=20)
    return parser.parse_args()


if __name__ == "__main__":
    build(parse_args())
