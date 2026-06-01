# Start Here

This repository is the handoff point for the VIBEX dataset audit and benchmark-freeze work.

If you are a fresh Codex session, use this reading order:

1. Read `docs/031_HANDOFF_STATUS_20260601.md` for the current state, counts, caveats, and next actions.
2. Read `docs/030_VIBEX_RESEARCH_CONTROL_PLANE.md` for the overnight control-plane design and shutdown rules.
3. Read `docs/024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md` and `docs/025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md` for the benchmark-construction and family-labelling policy.
4. Inspect `evidence/counts_manifest_rows.csv`, `evidence/counts_png_rows.csv`, `evidence/duplicate_raw_sha256.csv`, `evidence/duplicate_png_hash.csv`, and `evidence/family_strata_status.csv`.
5. Only then decide whether to rebuild manifests or tighten exclusions.

## What This Repo Is

- PhD-facing documentation and evidence only.
- Safe manifests, compact CSV/JSON summaries, dataset cards, and audit outputs.
- Reproducibility scripts for rebuilding the benchmark views from frozen inputs.

## What This Repo Is Not

- Not the raw malware or benign binary store.
- Not the training-artifact store.
- Not the dashboard/runtime operations repository.
- Not the source of truth for workhorse payload files.

## Operator Environment

The benchmark work depends on a small set of named hosts. A fresh Codex session should not guess these.

- Primary control plane: `codex-remote` at `10.0.0.157`
- Main data and training host: `workhorse`
- Proxmox host: `garrison`
- Monitoring LXC: `monitoring`
- Runner LXC: `runner`
- Dashboard LXC: `dashboard`
- MariaDB LXC: `mariadb`
- Raspberry Pi 5: `pi5`

Expected SSH behavior:

- `codex-remote` is the canonical overnight host for this research repo.
- The currently reused operator key is `~/.ssh/id_ed25519_Apr25`.
- That key reuse is a temporary operational choice, not the preferred long-term machine-identity design.
- A dedicated machine key is still the preferred future state.

Expected SSH aliases on `codex-remote`:

- `workhorse`
- `garrison`
- `monitoring`
- `runner`
- `dashboard`
- `mariadb`
- `pi5`
- `github.com`

If a fresh session cannot reach those aliases, fix SSH first before touching benchmark logic.

## Current Benchmark Definitions

- `binary_pe`: Windows PE/MZ malware vs Windows PE/MZ benign
- `binary_elf`: Linux ELF malware vs Linux ELF benign
- `family_core`: malware-only stable-family benchmark
- `family_extended`: excluded or unresolved malware-family evidence retained for audit

There is no mixed PE+ELF headline benchmark.

## Current Inputs

The first rebuild uses frozen snapshots under `evidence/source_snapshots/`:

- `safe_dataset_manifest_VIBEX-50K_20260518T081144Z.csv`
- `family_labelled_manifest_latest.csv`
- `family_dataset_summary_latest.json`
- `family_strata_latest.json`

These are the inputs to treat as authoritative for the current benchmark build.

The source-of-truth runtime paths outside this repo are:

- workhorse safe manifest source: `/home/phil/vibex_secure_dataset/release/VIBEX-50K/manifests/`
- workhorse family dataset evidence: `/home/phil/vibex_secure_dataset/evidence/holiday_run_20260524_8day/family_dataset/`
- lab orchestration repo on `codex-remote`: `~/repos/ESP32-Pi-Malware-Lab`

## Rebuild Commands

Run these from the research repo host:

```bash
python3 tools/vibex_build_research_benchmarks.py
python3 tools/vibex_remote_night_check.py
```

If VirusTotal strata need a targeted refresh, export from workhorse first:

```bash
python3 tools/vibex_export_family_strata.py
```

That script is intended to run on workhorse or against the workhorse dataset tool path, then copy the JSON snapshot back into `evidence/source_snapshots/`.

## Rules That Are Already Decided

- Broad VirusTotal polling is complete by default. Only targeted follow-up is allowed.
- Dataset size must mean benchmark-included sample rows and PNG samples only.
- Every exclusion requires a reproducible reason.
- Benign stays as one binary label in the binary benchmarks, but benign provenance must remain auditable.
- Smaller and cleaner is preferred over larger and noisier.

## Immediate Next Action

Tighten the family-core exclusion logic so generic-like families cannot leak into the stable benchmark, then rebuild the manifests and recount.
