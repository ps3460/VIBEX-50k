#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


GENERIC_TOKENS = {
    "adware",
    "agent",
    "android",
    "application",
    "backdoor",
    "banker",
    "behaveslike",
    "bundle",
    "clicker",
    "cloud",
    "confidence",
    "crypt",
    "dangerous",
    "detected",
    "downloader",
    "dropper",
    "exploit",
    "family",
    "file",
    "generic",
    "gen",
    "grayware",
    "hacktool",
    "heur",
    "heuristic",
    "injector",
    "linux",
    "loader",
    "malicious",
    "malware",
    "misc",
    "msil",
    "packed",
    "packer",
    "pe",
    "pua",
    "pup",
    "riskware",
    "suspicious",
    "troj",
    "trojan",
    "unwanted",
    "variant",
    "virus",
    "win",
    "win32",
    "win64",
    "worm",
    "x64",
    "x86",
    "small",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def is_generic_family(name: str) -> bool:
    tokens = {token.lower() for token in name.replace("-", "_").split("_") if token}
    return bool(tokens & GENERIC_TOKENS)


def benchmark_counts(rows: list[dict[str, str]], benchmark: str) -> dict[str, object]:
    labels = Counter(row.get("binary_label", "") for row in rows)
    statuses = Counter(row.get("family_label_status", "") for row in rows if row.get("family_label_status"))
    return {
        "benchmark": benchmark,
        "total_rows": len(rows),
        "unique_raw_sha256": len({row.get("raw_sha256", "") for row in rows}),
        "unique_image_sha256": len({row.get("image_sha256", "") for row in rows}),
        "benign_rows": labels.get("benign", 0),
        "malware_rows": labels.get("malware", 0),
        "labelled_rows": statuses.get("labelled", 0),
        "ambiguous_rows": statuses.get("ambiguous", 0),
        "insufficient_vote_rows": statuses.get("insufficient_votes", 0),
        "unlabelled_rows": statuses.get("unlabelled", 0),
    }


def duplicate_rows(rows: list[dict[str, str]], key: str, benchmark: str) -> list[dict[str, object]]:
    buckets: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        value = row.get(key, "").strip()
        if value:
            buckets[value].append(row)
    duplicates: list[dict[str, object]] = []
    for value, bucket in sorted(buckets.items()):
        if len(bucket) < 2:
            continue
        for row in bucket:
            duplicates.append(
                {
                    "benchmark": benchmark,
                    "duplicate_key": key,
                    "value": value,
                    "occurrences": len(bucket),
                    "raw_sha256": row.get("raw_sha256", ""),
                    "image_sha256": row.get("image_sha256", ""),
                    "dataset_image_path": row.get("dataset_image_path", ""),
                    "binary_label": row.get("binary_label", ""),
                    "consensus_family": row.get("consensus_family", row.get("family", "")),
                }
            )
    return duplicates


def write_dataset_card(path: Path, title: str, summary_lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {title}\n\n" + "\n".join(f"- {line}" for line in summary_lines) + "\n", encoding="utf-8")


def main() -> int:
    research_root = Path.home() / "GitHub" / "VIBEX-50k"
    snapshots = research_root / "evidence" / "source_snapshots"
    safe_manifest_path = snapshots / "safe_dataset_manifest_VIBEX-50K_20260518T081144Z.csv"
    family_manifest_path = snapshots / "family_labelled_manifest_latest.csv"
    strata_path = snapshots / "family_strata_latest.json"

    safe_rows = read_csv(safe_manifest_path)
    family_rows = read_csv(family_manifest_path)
    strata_rows = json.loads(strata_path.read_text(encoding="utf-8"))

    binary_pe = [row for row in safe_rows if row.get("file_kind", "").lower() in {"pe", "mz"}]
    binary_elf = [row for row in safe_rows if row.get("file_kind", "").lower() == "elf"]

    stable_statuses = {"retired_stable", "small_stable"}
    stable_families = set()
    family_status_rows: list[dict[str, object]] = []
    for row in strata_rows:
        dominant = str(row.get("dominant_vt_family", "")).strip().lower()
        status = str(row.get("status", "")).strip()
        family_status_rows.append(row)
        if dominant and status in stable_statuses and not is_generic_family(dominant):
            stable_families.add(dominant)

    labelled_family_counts = Counter(
        row["consensus_family"].strip().lower()
        for row in family_rows
        if row.get("family_label_status") == "labelled" and row.get("consensus_family")
    )
    eligible_families = {family for family in stable_families if labelled_family_counts.get(family, 0) >= 20}

    family_core: list[dict[str, str]] = []
    family_extended: list[dict[str, str]] = []
    for row in family_rows:
        output_row = dict(row)
        output_row["benchmark_name"] = "family_core"
        output_row["inclusion_reason"] = ""
        output_row["exclusion_reason"] = ""
        family = row.get("consensus_family", "").strip().lower()
        status = row.get("family_label_status", "").strip()
        if status != "labelled":
            output_row["benchmark_name"] = "family_extended"
            output_row["exclusion_reason"] = f"excluded_{status or 'unknown_status'}"
            family_extended.append(output_row)
            continue
        if not family:
            output_row["benchmark_name"] = "family_extended"
            output_row["exclusion_reason"] = "excluded_missing_family"
            family_extended.append(output_row)
            continue
        if is_generic_family(family):
            output_row["benchmark_name"] = "family_extended"
            output_row["exclusion_reason"] = "excluded_generic_family"
            family_extended.append(output_row)
            continue
        if family not in stable_families:
            output_row["benchmark_name"] = "family_extended"
            output_row["exclusion_reason"] = "excluded_unstable_family"
            family_extended.append(output_row)
            continue
        if family not in eligible_families:
            output_row["benchmark_name"] = "family_extended"
            output_row["exclusion_reason"] = "excluded_low_support_family"
            family_extended.append(output_row)
            continue
        output_row["inclusion_reason"] = "stable_family_min_support"
        family_core.append(output_row)

    binary_pe_path = research_root / "datasets" / "binary_pe" / "manifest.csv"
    binary_elf_path = research_root / "datasets" / "binary_elf" / "manifest.csv"
    family_core_path = research_root / "datasets" / "family_core" / "manifest.csv"
    family_ext_path = research_root / "datasets" / "family_extended" / "manifest.csv"

    write_csv(binary_pe_path, binary_pe, list(binary_pe[0].keys()))
    write_csv(binary_elf_path, binary_elf, list(binary_elf[0].keys()))
    write_csv(family_core_path, family_core, list(family_core[0].keys()) if family_core else list(family_rows[0].keys()) + ["benchmark_name", "inclusion_reason", "exclusion_reason"])
    write_csv(family_ext_path, family_extended, list(family_extended[0].keys()) if family_extended else list(family_rows[0].keys()) + ["benchmark_name", "inclusion_reason", "exclusion_reason"])

    counts_manifest_rows = [
        benchmark_counts(binary_pe, "binary_pe"),
        benchmark_counts(binary_elf, "binary_elf"),
        benchmark_counts(family_core, "family_core"),
        benchmark_counts(family_extended, "family_extended"),
    ]
    write_csv(
        research_root / "evidence" / "counts_manifest_rows.csv",
        counts_manifest_rows,
        list(counts_manifest_rows[0].keys()),
    )

    counts_png_rows = []
    for name, rows in (
        ("binary_pe", binary_pe),
        ("binary_elf", binary_elf),
        ("family_core", family_core),
        ("family_extended", family_extended),
    ):
        counts_png_rows.append(
            {
                "benchmark": name,
                "png_rows_listed": len(rows),
                "unique_dataset_image_path": len({row.get("dataset_image_path", "") for row in rows if row.get("dataset_image_path")}),
                "unique_image_sha256": len({row.get("image_sha256", "") for row in rows if row.get("image_sha256")}),
            }
        )
    write_csv(
        research_root / "evidence" / "counts_png_rows.csv",
        counts_png_rows,
        list(counts_png_rows[0].keys()),
    )

    raw_duplicates = (
        duplicate_rows(binary_pe, "raw_sha256", "binary_pe")
        + duplicate_rows(binary_elf, "raw_sha256", "binary_elf")
        + duplicate_rows(family_core, "raw_sha256", "family_core")
        + duplicate_rows(family_extended, "raw_sha256", "family_extended")
    )
    png_duplicates = (
        duplicate_rows(binary_pe, "image_sha256", "binary_pe")
        + duplicate_rows(binary_elf, "image_sha256", "binary_elf")
        + duplicate_rows(family_core, "image_sha256", "family_core")
        + duplicate_rows(family_extended, "image_sha256", "family_extended")
    )
    duplicate_fields = ["benchmark", "duplicate_key", "value", "occurrences", "raw_sha256", "image_sha256", "dataset_image_path", "binary_label", "consensus_family"]
    write_csv(research_root / "evidence" / "duplicate_raw_sha256.csv", raw_duplicates, duplicate_fields)
    write_csv(research_root / "evidence" / "duplicate_png_hash.csv", png_duplicates, duplicate_fields)
    write_csv(
        research_root / "evidence" / "family_strata_status.csv",
        family_status_rows,
        ["clamav_family", "total_hashes", "queried_hashes", "labelled_hashes", "ambiguous_hashes", "dominant_vt_family", "dominant_count", "agreement_rate", "ambiguous_rate", "status", "updated_at"],
    )

    benign_rows = [row for row in safe_rows if row.get("binary_label") == "benign"]
    benign_provenance: list[dict[str, object]] = []
    grouped: dict[tuple[str, str], int] = Counter((row.get("source", ""), row.get("file_kind", "")) for row in benign_rows)
    for (source, file_kind), count in sorted(grouped.items(), key=lambda item: (-item[1], item[0])):
        benign_provenance.append(
            {
                "source": source,
                "file_kind": file_kind,
                "count": count,
            }
        )
    write_csv(research_root / "datasets" / "benign_provenance.csv", benign_provenance, ["source", "file_kind", "count"])

    write_dataset_card(
        research_root / "datasets" / "binary_pe" / "dataset_card.md",
        "binary_pe Dataset Card",
        [
            "Windows PE/MZ malware vs Windows PE/MZ benign only.",
            f"Rows: {len(binary_pe)}.",
            f"Malware rows: {sum(1 for row in binary_pe if row.get('binary_label') == 'malware')}.",
            f"Benign rows: {sum(1 for row in binary_pe if row.get('binary_label') == 'benign')}.",
        ],
    )
    write_dataset_card(
        research_root / "datasets" / "binary_elf" / "dataset_card.md",
        "binary_elf Dataset Card",
        [
            "Linux ELF malware vs Linux ELF benign only.",
            f"Rows: {len(binary_elf)}.",
            f"Malware rows: {sum(1 for row in binary_elf if row.get('binary_label') == 'malware')}.",
            f"Benign rows: {sum(1 for row in binary_elf if row.get('binary_label') == 'benign')}.",
        ],
    )
    write_dataset_card(
        research_root / "datasets" / "family_core" / "dataset_card.md",
        "family_core Dataset Card",
        [
            "Malware-only family benchmark using stable, non-generic families with at least 20 labelled rows.",
            f"Rows: {len(family_core)}.",
            f"Eligible families: {len(eligible_families)}.",
            "Unlabelled, ambiguous, insufficient-vote, generic, unstable, and low-support families are excluded.",
        ],
    )
    summary = {
        "eligible_families": sorted(eligible_families),
        "stable_family_candidates": sorted(stable_families),
        "family_core_rows": len(family_core),
        "family_extended_rows": len(family_extended),
    }
    (research_root / "evidence" / "benchmark_build_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
