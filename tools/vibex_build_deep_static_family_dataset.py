#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


GENERIC_OR_NONFAMILY = {
    "",
    "agent",
    "ambiguous",
    "backdoor",
    "dropper",
    "generic",
    "generickd",
    "heur",
    "insufficient_votes",
    "malware",
    "packed",
    "packer",
    "pua",
    "riskware",
    "trojan",
    "unlabelled",
    "unknown",
    "variant",
    "virus",
    "vmprotect",
    "win32",
    "worm",
}


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_rank(value: str, seed: int) -> str:
    return hashlib.sha256(f"{seed}:{value}".encode()).hexdigest()


def clean_family(value: str) -> str:
    out = "".join(ch for ch in (value or "").strip().lower() if ch.isalnum() or ch in {"_", "-", "+"})
    return "" if out in GENERIC_OR_NONFAMILY or len(out) < 3 else out


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


def indexed(rows: list[dict[str, str]], key: str = "raw_sha256") -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for row in rows:
        sha = (row.get(key) or "").strip().lower()
        if len(sha) == 64 and sha not in out:
            out[sha] = row
    return out


def source_count(row: dict[str, str]) -> int:
    try:
        return int(float(row.get("static_hint_source_count") or 0))
    except ValueError:
        return 0


def split_sources(row: dict[str, str]) -> set[str]:
    return {item for item in (row.get("static_hint_sources") or "").split(";") if item}


def decide_static_row(
    static_row: dict[str, str],
    extended_by_sha: dict[str, dict[str, str]],
) -> dict[str, Any]:
    sha = (static_row.get("raw_sha256") or "").strip().lower()
    ext = extended_by_sha.get(sha, {})
    static_family = clean_family(static_row.get("static_hint_family") or "")
    vt_family = clean_family(ext.get("consensus_family") or "")
    vt_status = (ext.get("family_label_status") or "").strip().lower()
    n_sources = source_count(static_row)
    sources = split_sources(static_row)
    static_decision = (static_row.get("static_decision") or "").strip()

    decision = "reject"
    reason = "no_acceptable_evidence"
    accepted_family = ""

    if not static_family and vt_status == "labelled" and vt_family:
        decision = "review_only"
        reason = "vt_label_without_static_support"
        accepted_family = vt_family
    elif not static_family:
        decision = "reject"
        reason = "no_static_family"
    elif vt_status == "labelled" and vt_family and vt_family != static_family:
        decision = "review_only"
        reason = f"conflicts_with_vt:{vt_family}"
    elif vt_status == "labelled" and vt_family == static_family and n_sources >= 1:
        decision = "high_confidence"
        reason = "vt_consensus_plus_static_agreement"
        accepted_family = static_family
    elif n_sources >= 3:
        decision = "high_confidence"
        reason = "three_or_more_independent_static_sources"
        accepted_family = static_family
    elif n_sources >= 2:
        decision = "medium_confidence"
        reason = "two_independent_static_sources"
        accepted_family = static_family
    elif static_family:
        decision = "review_only"
        reason = "single_static_source"
        accepted_family = static_family

    if static_decision == "reject" and decision != "high_confidence":
        decision = "reject" if not accepted_family else "review_only"
        reason = static_row.get("static_decision_reason") or reason

    return {
        "raw_sha256": sha,
        "accepted_family": accepted_family,
        "decision": decision,
        "decision_reason": reason,
        "static_family": static_family,
        "static_sources": ";".join(sorted(sources)),
        "static_source_count": n_sources,
        "vt_family": vt_family,
        "vt_status": vt_status,
        "imphash": static_row.get("imphash", ""),
        "tlsh": static_row.get("tlsh", ""),
        "ssdeep": static_row.get("ssdeep", ""),
        "tool_status": ";".join(
            f"{name}={static_row.get(name + '_status', '')}"
            for name in ["sigcheck", "diec", "strings", "capa", "floss", "yara", "clam", "defender", "python_static"]
        ),
    }


def current_core_decisions(core_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    out = []
    for row in core_rows:
        family = clean_family(row.get("consensus_family") or "")
        sha = (row.get("raw_sha256") or "").strip().lower()
        if len(sha) != 64 or not family:
            continue
        out.append(
            {
                "raw_sha256": sha,
                "accepted_family": family,
                "decision": "high_confidence",
                "decision_reason": "existing_family_core_stable_vt_consensus",
                "static_family": "",
                "static_sources": "",
                "static_source_count": 0,
                "vt_family": family,
                "vt_status": row.get("family_label_status", ""),
                "imphash": "",
                "tlsh": "",
                "ssdeep": "",
                "tool_status": "",
            }
        )
    return out


def attach_manifest(decisions: list[dict[str, Any]], malware_by_sha: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    out = []
    seen: set[str] = set()
    for decision in decisions:
        sha = decision["raw_sha256"]
        if sha in seen:
            continue
        row = malware_by_sha.get(sha)
        if not row:
            continue
        seen.add(sha)
        item = dict(row)
        item.update(decision)
        item["binary_label"] = "malware"
        item["family"] = decision["accepted_family"]
        item["label_source"] = decision["decision_reason"]
        out.append(item)
    return out


def filter_by_support(rows: list[dict[str, Any]], min_family_rows: int) -> list[dict[str, Any]]:
    counts = Counter(row["family"] for row in rows if row.get("family"))
    allowed = {family for family, count in counts.items() if count >= min_family_rows}
    return [row for row in rows if row.get("family") in allowed]


def waterfill(rows: list[dict[str, Any]], target: int, seed: int) -> list[dict[str, Any]]:
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_family[row["family"]].append(row)
    for family_rows in by_family.values():
        family_rows.sort(key=lambda row: stable_rank(row["raw_sha256"], seed))

    selected: list[dict[str, Any]] = []
    families = sorted(by_family)
    if not families:
        return []
    quota = max(1, target // len(families))
    leftovers: list[dict[str, Any]] = []
    for family in families:
        chosen = by_family[family][:quota]
        selected.extend(chosen)
        leftovers.extend(by_family[family][quota:])
    if len(selected) < target:
        leftovers.sort(key=lambda row: stable_rank(row["raw_sha256"], seed + 1))
        selected.extend(leftovers[: target - len(selected)])
    return selected[:target]


def choose_malware(
    rows: list[dict[str, Any]],
    seed: int,
    min_family_rows: int,
    targets: list[int],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    supported = filter_by_support(rows, min_family_rows)
    total = len(supported)
    selected_target = 0
    for target in targets:
        if total >= target:
            selected_target = target
            break
    if selected_target == 0:
        selected_target = total
    selected = waterfill(supported, selected_target, seed) if selected_target else []
    return selected, {
        "eligible_rows_before_support_filter": len(rows),
        "eligible_rows_after_support_filter": total,
        "selected_target": selected_target,
        "family_counts_after_support_filter": dict(sorted(Counter(row["family"] for row in supported).items())),
        "selected_family_counts": dict(sorted(Counter(row["family"] for row in selected).items())),
    }


def choose_benign(binary_pe_rows: list[dict[str, str]], count: int, seed: int) -> list[dict[str, Any]]:
    benign = [
        dict(row)
        for row in binary_pe_rows
        if row.get("binary_label") == "benign" and (row.get("file_kind") or "").lower() in {"pe", "mz"}
    ]
    benign.sort(key=lambda row: stable_rank(row.get("raw_sha256", ""), seed))
    out = []
    for row in benign[:count]:
        item = dict(row)
        item["family"] = "benign"
        item["accepted_family"] = "benign"
        item["decision"] = "benign_balanced_pair"
        item["decision_reason"] = "binary_pe_benign_stratified_by_hash"
        item["label_source"] = item["decision_reason"]
        out.append(item)
    return out


def split_rows(rows: list[dict[str, Any]], seed: int) -> list[dict[str, Any]]:
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_family[row["family"]].append(row)
    out: list[dict[str, Any]] = []
    for family, family_rows in sorted(by_family.items()):
        family_rows.sort(key=lambda row: stable_rank(row.get("raw_sha256", ""), seed))
        n = len(family_rows)
        n_train = int(n * 0.8)
        n_val = int(n * 0.1)
        for idx, row in enumerate(family_rows):
            item = dict(row)
            if idx < n_train:
                item["v2_split"] = "train"
            elif idx < n_train + n_val:
                item["v2_split"] = "validation"
            else:
                item["v2_split"] = "test"
            out.append(item)
    out.sort(key=lambda row: (row["v2_split"], row["family"], stable_rank(row.get("raw_sha256", ""), seed)))
    return out


def build(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    core = read_csv(Path(args.family_core))
    extended = read_csv(Path(args.family_extended))
    binary_pe = read_csv(Path(args.binary_pe))
    static_rows = read_csv(Path(args.deep_static_results)) if Path(args.deep_static_results).exists() else []

    malware_by_sha = indexed(core + extended)
    extended_by_sha = indexed(extended)
    core_shas = {row["raw_sha256"] for row in current_core_decisions(core)}

    decisions = current_core_decisions(core)
    for row in static_rows:
      decision = decide_static_row(row, extended_by_sha)
      if decision["raw_sha256"] in core_shas:
          continue
      decisions.append(decision)

    decision_fields = [
        "raw_sha256",
        "accepted_family",
        "decision",
        "decision_reason",
        "static_family",
        "static_sources",
        "static_source_count",
        "vt_family",
        "vt_status",
        "imphash",
        "tlsh",
        "ssdeep",
        "tool_status",
    ]
    write_csv(output_dir / "family_label_decisions_v2.csv", decisions, decision_fields)

    high_decisions = [row for row in decisions if row["decision"] == "high_confidence" and row["accepted_family"]]
    medium_decisions = [row for row in decisions if row["decision"] == "medium_confidence" and row["accepted_family"]]
    review_decisions = [row for row in decisions if row["decision"] not in {"high_confidence", "medium_confidence"}]
    write_csv(output_dir / "family_review_v2.csv", review_decisions, decision_fields)

    high_rows = attach_manifest(high_decisions, malware_by_sha)
    high_selected, high_summary = choose_malware(high_rows, args.seed, args.min_family_rows, args.targets)

    medium_rows: list[dict[str, Any]] = []
    medium_selected: list[dict[str, Any]] = []
    medium_summary: dict[str, Any] = {}
    if args.allow_medium:
        merged = high_decisions + medium_decisions
        medium_rows = attach_manifest(merged, malware_by_sha)
        medium_selected, medium_summary = choose_malware(medium_rows, args.seed, args.min_family_rows, args.targets)

    chosen_rows = medium_selected if args.allow_medium and len(medium_selected) > len(high_selected) else high_selected
    chosen_policy = "high_plus_medium" if chosen_rows is medium_selected and args.allow_medium else "high_only"
    benign_rows = choose_benign(binary_pe, len(chosen_rows), args.seed + 20) if args.include_benign else []
    dataset_rows = split_rows(chosen_rows + benign_rows, args.seed + 40)

    write_csv(output_dir / "dataset_manifest_v2.csv", dataset_rows)
    write_csv(output_dir / "malware_manifest_v2.csv", split_rows(chosen_rows, args.seed + 40))
    write_csv(
        output_dir / "family_counts_v2.csv",
        [{"family": family, "rows": count} for family, count in sorted(Counter(row["family"] for row in chosen_rows).items())],
        ["family", "rows"],
    )

    duplicate_raw = [sha for sha, count in Counter(row.get("raw_sha256", "") for row in dataset_rows).items() if sha and count > 1]
    duplicate_img = [sha for sha, count in Counter(row.get("image_sha256", "") for row in dataset_rows).items() if sha and count > 1]
    summary = {
        "created_utc": utc_now(),
        "deep_static_results": str(args.deep_static_results),
        "allow_medium": args.allow_medium,
        "include_benign": args.include_benign,
        "chosen_policy": chosen_policy,
        "decision_counts": dict(sorted(Counter(row["decision"] for row in decisions).items())),
        "high_confidence": high_summary,
        "medium_candidate": medium_summary,
        "selected_malware_rows": len(chosen_rows),
        "selected_benign_rows": len(benign_rows),
        "dataset_rows": len(dataset_rows),
        "dataset_name": "VIBEX-30K" if len(chosen_rows) >= 15000 and len(benign_rows) >= 15000 else "deep_static_family_candidate",
        "target_25k_met": len(chosen_rows) >= 25000,
        "target_20k_met": len(chosen_rows) >= 20000,
        "target_15k_met": len(chosen_rows) >= 15000,
        "duplicate_raw_sha256": duplicate_raw,
        "duplicate_image_sha256": duplicate_img,
        "canonical_manifests_changed": False,
    }
    write_json(output_dir / "build_summary_v2.json", summary)
    report = [
        "# VIBEX Deep Static Family Dataset Candidate",
        "",
        f"- Created UTC: `{summary['created_utc']}`",
        f"- Policy: `{chosen_policy}`",
        f"- Selected malware rows: `{len(chosen_rows)}`",
        f"- Selected benign rows: `{len(benign_rows)}`",
        f"- Dataset rows: `{len(dataset_rows)}`",
        f"- Target 25k met: `{str(summary['target_25k_met']).lower()}`",
        f"- Target 15k met: `{str(summary['target_15k_met']).lower()}`",
        f"- Duplicate raw SHA-256 values: `{len(duplicate_raw)}`",
        f"- Duplicate image SHA-256 values: `{len(duplicate_img)}`",
        "- Canonical manifests changed: `false`",
    ]
    (output_dir / "build_summary_v2.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build VIBEX deep-static family candidate manifests from safe evidence.")
    parser.add_argument("--family-core", default="datasets/family_core/manifest.csv")
    parser.add_argument("--family-extended", default="datasets/family_extended/manifest.csv")
    parser.add_argument("--binary-pe", default="datasets/binary_pe/manifest.csv")
    parser.add_argument("--deep-static-results", required=True)
    parser.add_argument("--output-dir", default="evidence/deep_static_family_v2")
    parser.add_argument("--min-family-rows", type=int, default=50)
    parser.add_argument("--seed", type=int, default=20260612)
    parser.add_argument("--targets", type=int, nargs="+", default=[25000, 20000, 15000])
    parser.add_argument("--allow-medium", action="store_true")
    parser.add_argument("--include-benign", action="store_true", default=True)
    parser.add_argument("--no-benign", action="store_false", dest="include_benign")
    return parser.parse_args()


if __name__ == "__main__":
    build(parse_args())
