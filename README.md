# VIBEX-50k Research Repository

This repository is the PhD-facing documentation, benchmark-manifest, and safe-evidence home for VIBEX dataset work.

It does not store:

- raw malware
- benign binaries
- PNG sample corpora
- model binaries
- VirusTotal raw JSON

If you are starting a fresh Codex project in this repository, read these files first:

1. `docs/000_START_HERE.md`
2. `docs/031_HANDOFF_STATUS_20260601.md`
3. `docs/030_VIBEX_RESEARCH_CONTROL_PLANE.md`
4. `docs/024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md`
5. `docs/025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md`

Current benchmark outputs from the first frozen-manifest rebuild:

- `binary_pe`: `49,674`
- `binary_elf`: `326`
- `family_core`: `1,267`
- `family_extended`: `21,919`

These counts are provisional benchmark counts, not a claim that the final PhD benchmark should still be called `50K`.

Repository layout:

- `datasets/`: benchmark manifests and dataset cards
- `docs/`: methodology, handoff notes, and research decisions
- `evidence/`: compact audit outputs, counts, duplicate reports, and source snapshots
- `references/`: reference-repo notes
- `tools/`: reproducibility and control-plane helper scripts

Authoritative benchmark suite:

- `datasets/binary_pe`
- `datasets/binary_elf`
- `datasets/family_core`
- `datasets/family_extended`
