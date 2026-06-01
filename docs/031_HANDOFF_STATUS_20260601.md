# Handoff Status: 2026-06-01

This file is the short operational state for a fresh Codex session.

## Current State

- Primary control plane: `codex-remote` at `10.0.0.157`
- Data and evidence host: `workhorse`
- Proxmox host: `garrison`
- Research repository: `~/GitHub/VIBEX-50k`
- Night-check result: green
- Mac shutdown status after the check: safe

The first benchmark rebuild from frozen manifests has already been completed.

## Host and Access Notes

This work assumes the following host roles:

- `codex-remote`: orchestration, repo editing, overnight checks, benchmark rebuilds
- `workhorse`: secure dataset vault, frozen source manifests, family evidence, training host
- `garrison`: Proxmox host used for container health checks and `pct` access paths
- `monitoring`: Prometheus and metric queries
- `runner`: Telegram and unattended runner infrastructure
- `dashboard`: dashboard reachability check
- `mariadb`: database reachability check
- `pi5`: Pi thermal and SSH reachability check

SSH expectations:

- The currently reused operational key is `~/.ssh/id_ed25519_Apr25`.
- This key is intentionally reused for tonight's control plane, but that is a temporary operator convenience.
- A dedicated machine key remains the preferred future state and should be tracked as a follow-up hardening task.
- `codex-remote` should have working SSH aliases for `workhorse`, `garrison`, `monitoring`, `runner`, `dashboard`, `mariadb`, `pi5`, and `github.com`.

If those aliases fail, the control plane is not in a clean handoff state yet.

## Current Benchmark Counts

From `evidence/counts_manifest_rows.csv`:

- `binary_pe`: `49,674`
- `binary_elf`: `326`
- `family_core`: `1,267`
- `family_extended`: `21,919`

From the same build, the binary class breakdown is:

- `binary_pe`: `26,651` benign, `23,023` malware
- `binary_elf`: `163` benign, `163` malware

Treat these as the current audited working counts, not as a final public benchmark claim.

## What Was Implemented

- The research repo was populated with research-facing docs and safe evidence only.
- Frozen source snapshots were copied into `evidence/source_snapshots/`.
- Reproducibility scripts were prepared for repo sync, benchmark rebuild, family-strata export, and night checks.
- A full overnight system check was run from `codex-remote`.

Night-check artifacts:

- `evidence/night_checks/night_check_20260601T222154Z.json`
- `evidence/night_checks/night_check_20260601T222154Z.md`

The night-check reported:

- `safe_to_shutdown_mac: true`
- `blockers: []`
- `warnings: []`

## Most Important Caveat

The current `family_core` eligibility logic is not strict enough yet. The first pass still allowed `generickd` to appear in the eligible-family list because the generic-family filter is currently token-based and does not catch every generic-like family name.

This means:

- `binary_pe` and `binary_elf` are in a usable audit state.
- `family_core` is close, but should not be treated as frozen until the generic-family exclusion logic is tightened and the build is rerun.

## Recommended Reading Order

1. `docs/000_START_HERE.md`
2. `docs/030_VIBEX_RESEARCH_CONTROL_PLANE.md`
3. `docs/024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md`
4. `docs/025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md`
5. `evidence/benchmark_build_summary.json`

## Recommended Next Actions

1. Tighten generic-family exclusions in `tools/vibex_build_research_benchmarks.py`.
2. Rebuild the benchmark outputs from the frozen snapshots.
3. Recheck `evidence/counts_manifest_rows.csv`, `counts_png_rows.csv`, and `benchmark_build_summary.json`.
4. Decide whether any targeted VirusTotal follow-up is justified for unresolved families that could be promoted into `family_core`.
5. Only then declare a benchmark freeze candidate.

## What Not To Do

- Do not resume broad VirusTotal polling by default.
- Do not use workhorse as the primary documentation-control host.
- Do not claim the benchmark is still `50K` unless the frozen audited manifests really support that number.
- Do not mix PE and ELF into one headline benchmark.
