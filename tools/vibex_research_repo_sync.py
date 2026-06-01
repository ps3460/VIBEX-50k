#!/usr/bin/env python3
from __future__ import annotations

import csv
import shutil
from pathlib import Path


RESEARCH_DOCS = [
    "docs/000_RESEARCH_CONTEXT.md",
    "docs/008_RESEARCH_WORKFLOW.md",
    "docs/024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md",
    "docs/025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md",
    "docs/026_VIBEX50_OVERNIGHT_MODEL_SEARCH_PLAN.md",
    "docs/027_VIBEX50_RS485_PIPELINED_BATCH_PROTOCOL.md",
    "docs/028_LAB_ACCEPTANCE_RUNNER_PLAN.md",
    "docs/029_VIBEX_HOLIDAY_RESEARCH_RUNBOOK.md",
    "docs/030_VIBEX_RESEARCH_CONTROL_PLANE.md",
    "docs/VIBEX_BUILD.md",
    "docs/VIBEX_PIPELINE_LESSONS_LEARNT.md",
    "docs/VIBEX_PROJECT.md",
    "docs/VIBEX_RESULTS.md",
]

METRIC_DOCS = [
    "docs/metrics/000_METRICS.md",
    "docs/metrics/20260517_vibex_split_dataset_pipeline.md",
    "docs/metrics/20260518_vibex50_binary_image_baselines.md",
    "docs/metrics/20260520_vibex50_bias_and_stage2_pivot.md",
    "docs/metrics/20260521_vibex50_w96_thr0145_smoke_payload.md",
    "docs/metrics/20260522_vibex50_virustotal_family_campaign.md",
    "docs/metrics/20260523_vibex50_esp32_local_csv_stage12_experiment.md",
    "docs/metrics/20260524_vibex_holiday_research_log.md",
]

RETAINED_OPS_DOCS = [
    "docs/000_ASSET_LIBRARY.md",
    "docs/001_ARCHITECTURE.md",
    "docs/002_HIGH_LEVEL_DESIGN.md",
    "docs/003_LOW_LEVEL_DESIGN.md",
    "docs/004_SETUP.md",
    "docs/005_OPERATIONS.md",
    "docs/006_HARDWARE_INVENTORY.md",
    "docs/007_DATABASE.md",
    "docs/009_TESTS_AND_AUDITS.md",
    "docs/010_PHD_RS485_BAUD_RATE_FINDINGS.md",
    "docs/011_WORKSPACE_COORDINATION.md",
    "docs/012_AI_WORKSPACE_GUIDE.md",
    "docs/014_NETWORK_GPIO_DIAGRAM.md",
    "docs/017_TELEGRAM_NOTIFICATIONS.md",
    "docs/operations/000_PROXMOX.md",
    "docs/operations/001_VAULT_APPROLE.md",
]

REFERENCE_REPOS = [
    ("Thesis", "git@github.com:ps3460/Thesis.git"),
    ("PhD_Lab", "git@github.com:ps3460/PhD_Lab.git"),
    ("malwarevision2025-detectionresearch", "git@github.com:ps3460/malwarevision2025-detectionresearch.git"),
]

GITIGNORE_TEXT = """# Raw and executable artifacts
*.bin
*.exe
*.dll
*.sys
*.so
*.dylib
*.elf
*.iso
*.img
*.zip
*.7z
*.tar
*.gz

# Model artifacts
*.keras
*.h5
*.onnx
*.tflite
*.pt
*.pth

# Large image/sample trees
*.png
*.jpg
*.jpeg
samples/
raw/
artifacts/
cache/
tmp/
"""


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def copy_file(source_root: Path, target_root: Path, rel_path: str) -> tuple[str, str]:
    src = source_root / rel_path
    dst = target_root / rel_path
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return str(src), str(dst)


def write_inventory(target_root: Path, source_root: Path) -> None:
    inventory_path = target_root / "evidence" / "document_inventory.csv"
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    all_known = sorted(set(RESEARCH_DOCS + METRIC_DOCS + RETAINED_OPS_DOCS))
    with inventory_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["source_path", "destination_path", "decision", "category", "notes"],
        )
        writer.writeheader()
        for rel_path in all_known:
            if rel_path in RESEARCH_DOCS:
                category = "research_doc"
                decision = "copied_to_research_repo"
                destination = rel_path
                notes = "Research-facing methodology or benchmark narrative."
            elif rel_path in METRIC_DOCS:
                category = "metrics_note"
                decision = "copied_to_research_repo"
                destination = rel_path
                notes = "Dated evidence or benchmark result note."
            else:
                category = "operations_doc"
                decision = "retained_in_lab_repo"
                destination = ""
                notes = "Runtime or infrastructure ownership stays with the lab repo."
            writer.writerow(
                {
                    "source_path": str(source_root / rel_path),
                    "destination_path": str(target_root / destination) if destination else "",
                    "decision": decision,
                    "category": category,
                    "notes": notes,
                }
            )


def write_references(target_root: Path) -> None:
    lines = [
        "# Reference Repositories",
        "",
        "These sibling repositories are cloned on `codex-remote` for PhD context and cross-reference.",
        "",
    ]
    for name, remote in REFERENCE_REPOS:
        lines.append(f"- `{name}`: `{remote}`")
    lines.extend(
        [
            "",
            "These references are not required for the overnight control path. They are context-only inputs.",
            "",
            "Fallback helper assets:",
            "- `VM 107` Windows 11: secondary recovery path only.",
            "- workhorse Gemma: secondary summarisation helper only.",
        ]
    )
    write_text(target_root / "references" / "README.md", "\n".join(lines) + "\n")


def write_readme(target_root: Path) -> None:
    text = """# VIBEX-50k Research Repository

This repository is the PhD-facing documentation, benchmark-manifest, and safe-evidence home for VIBEX dataset work.

It does not store:

- raw malware
- benign binaries
- PNG sample corpora
- model binaries
- VirusTotal raw JSON

The authoritative benchmark suite is:

- `datasets/binary_pe`
- `datasets/binary_elf`
- `datasets/family_core`
- `datasets/family_extended`
"""
    write_text(target_root / "README.md", text)


def main() -> int:
    source_root = Path.home() / "repos" / "ESP32-Pi-Malware-Lab"
    target_root = Path.home() / "GitHub" / "VIBEX-50k"
    target_root.mkdir(parents=True, exist_ok=True)

    copied = []
    for rel_path in RESEARCH_DOCS + METRIC_DOCS:
        copied.append(copy_file(source_root, target_root, rel_path))

    write_text(target_root / ".gitignore", GITIGNORE_TEXT)
    write_readme(target_root)
    write_references(target_root)
    write_inventory(target_root, source_root)

    split_note = """# Repository Split Note

Runtime, hardware, deployment, Proxmox, Vault, Pi/ESP32, and Telegram operations remain in the lab repo.
This research repo owns PhD-facing dataset construction, family-labelling evidence, benchmark definitions,
and safe result summaries.
"""
    write_text(target_root / "docs" / "REPO_SPLIT.md", split_note)
    print(f"copied_files={len(copied)} target={target_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
