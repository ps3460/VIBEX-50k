# VIBEX Research Control Plane

Date: 2026-06-01

Purpose: record the overnight research-control arrangement for the VIBEX dataset
audit and documentation split.

## Primary Host

- Control plane host: `codex-remote`
- Access: `ssh phil@10.0.0.157`
- Primary role: always-on orchestration for research repo maintenance, dataset
  recounts, duplicate audits, benchmark manifest generation, and pre-shutdown
  checks.

## Access Policy

- Immediate access uses the existing operator key `id_ed25519_Apr25`.
- This key reuse is a temporary expedient, not the preferred steady-state
  machine identity model.
- Preferred later state: a dedicated LXC-specific machine key with separate
  trust and rotation policy.

## Fallback Assets

- `VM 107` Windows 11: secondary recovery path only.
- workhorse Gemma: secondary summarisation helper only.
- Neither fallback is required for the baseline overnight dataset-audit path.

## Overnight Safety Rule

- The Mac is optional once `codex-remote` has:
  - the research repo cloned,
  - SSH reachability to workhorse and required estate hosts,
  - benchmark manifests and evidence outputs materialised,
  - a passing night-check result.
