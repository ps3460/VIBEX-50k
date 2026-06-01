# Tools

These scripts exist to make the research repo reproducible without depending on hidden session context.

## Scripts

- `vibex_research_repo_sync.py`
  - Copies research-facing docs and safe metrics notes from the lab repo into the research repo.
- `vibex_build_research_benchmarks.py`
  - Builds `binary_pe`, `binary_elf`, `family_core`, and `family_extended` from frozen snapshots under `evidence/source_snapshots/`.
- `vibex_export_family_strata.py`
  - Exports the current VirusTotal family-strata state to JSON from the workhorse environment.
- `vibex_remote_night_check.py`
  - Runs the codex-remote overnight readiness check and writes JSON/Markdown reports into `evidence/night_checks/`.

## Expected Workflow

1. Refresh or verify frozen snapshots under `evidence/source_snapshots/`.
2. Run `python3 tools/vibex_build_research_benchmarks.py`.
3. Review the counts and duplicate reports in `evidence/`.
4. Run `python3 tools/vibex_remote_night_check.py` before leaving the control plane unattended.

## Important Constraint

These scripts are part of the PhD-audit trail. Prefer explicit inputs, explicit outputs, and reproducible files over convenience shortcuts.
