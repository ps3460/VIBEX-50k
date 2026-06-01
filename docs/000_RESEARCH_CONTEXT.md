# Research Context

Read [000_ASSET_LIBRARY.md](000_ASSET_LIBRARY.md) first in a new AI/Codex chat, then read this file and [012_AI_WORKSPACE_GUIDE.md](012_AI_WORKSPACE_GUIDE.md) before moving, creating, or renaming files.

## Current Project

This repository is now centred on VIBEX and the physical malware lab for PhD evidence.

VIBEX means **Verified Image Binary Executable**. The current public release is `VIBEX-50K`, a deterministic executable-byte-to-PNG dataset for malware-versus-benign classification. Its source components are Windows PE/MZ executable-derived images and Linux ELF executable-derived images.

The lab side remains important: ESP32 nodes, a Raspberry Pi controller, RS485 transport, dashboard exports, and SQL-backed evidence support constrained edge/fog malware detection experiments. The PhD focus is no longer a broad collection of exploratory notes; it is reproducible dataset construction, trustworthy evaluation, and hardware-grounded evidence.

## What To Open

Use this routing first:

| Need | Open |
| --- | --- |
| Asset roles, access routes, usernames, Vault, Proxmox/garrison | [000_ASSET_LIBRARY.md](000_ASSET_LIBRARY.md) |
| Project scope, history, and PhD framing | [VIBEX_PROJECT.md](VIBEX_PROJECT.md) |
| Current dataset and model results | [VIBEX_RESULTS.md](VIBEX_RESULTS.md) |
| Dataset build and release process | [VIBEX_BUILD.md](VIBEX_BUILD.md) |
| File placement and AI workspace rules | [012_AI_WORKSPACE_GUIDE.md](012_AI_WORKSPACE_GUIDE.md) |
| Secure VIBEX build protocol | [024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md](024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md) |
| Malware family enrichment | [025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md](025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md) |
| Metrics evidence index | [metrics/000_METRICS.md](metrics/000_METRICS.md) |
| Lab architecture | [001_ARCHITECTURE.md](001_ARCHITECTURE.md) |
| Hardware tests and audits | [009_TESTS_AND_AUDITS.md](009_TESTS_AND_AUDITS.md) |
| Service secrets and Vault | [operations/001_VAULT_APPROLE.md](operations/001_VAULT_APPROLE.md) |

Archived MV2025 notes are under [archive/mv2025/](archive/mv2025/). Use them only for history or to recover a specific old result; do not route new work through them.

## Current Release Position

`VIBEX-50K` was frozen on 2026-05-18:

| Dataset | Release total | Benign | Malware | Train | Test |
| --- | ---: | ---: | ---: | ---: | ---: |
| `VIBEX-50K` | 50,000 | 26,814 | 23,186 | 40,000 | 10,000 |
| Windows PE component | 46,046 | 23,023 | 23,023 | 36,836 | 9,210 |
| Linux ELF component | 326 | 163 | 163 | 260 | 66 |

The public release contains derived PNG images, manifests, hashes, split files, evidence logs, and scripts. It must not contain raw malware binaries, password-protected malware archives, API keys, credentials, browser tokens, or machine-local secrets.

## Current Result Summary

The first `VIBEX-50K` binary-image CNN baseline reached:

| Evaluation | Accuracy | Balanced accuracy | Macro-F1 | ROC AUC |
| --- | ---: | ---: | ---: | ---: |
| Random split | 0.9448 | 0.9439 | 0.9444 | 0.9860 |
| Windows Server benign holdout | 0.9099 | 0.9116 | 0.9060 | 0.9672 |
| Windows 11 benign holdout | 0.9175 | 0.9199 | 0.8813 | 0.9733 |

Interpretation: the model does not collapse under source holdout, but random split performance is optimistic. Provenance/source-holdout evaluation is therefore a required PhD benchmark, not an optional extra.

## History Summary

- Early project: malware-as-image classification on Raspberry Pi and desktop hardware, with optimizer, runtime, and deployment experiments.
- ESP32 lab phase: Tier 1 ESP32 inference, Raspberry Pi coordination, RS485 transfer checks, LCD/dashboard observability, and repeatable metrics exports.
- MV2025 phase: a feasibility branch tested 1024-byte prefix features, ESP32-safe binary gates, Pi-side checks, and Stage 2 image triage. It is now historical evidence, not the main route.
- Current VIBEX phase: secure dataset construction, `VIBEX-50K` release, malware-family labelling enrichment, source-holdout baselines, and PhD-ready evidence.

## Linked Thesis Repository

The LaTeX thesis source lives at `/Users/ps3460/GitLab/Thesis`.

- This repo owns experiments, code, raw outputs, metrics, dataset evidence, and validation records.
- The thesis repo owns `main.tex`, chapter files, Zotero bibliography, final figures/tables, and final write-up.
- Do not edit thesis files unless the user explicitly asks for thesis editing or integration.

## Hard Rules

- Keep raw malware out of Git.
- Keep credentials, Vault tokens, API keys, database passwords, Telegram bot tokens, and private keys out of Markdown, commits, Telegram, and generated reports.
- Use [operations/001_VAULT_APPROLE.md](operations/001_VAULT_APPROLE.md) before handling service secrets.
- Use [017_TELEGRAM_NOTIFICATIONS.md](017_TELEGRAM_NOTIFICATIONS.md) before starting, stopping, monitoring, or reporting lab tests.
- Put new VIBEX metrics under `docs/metrics/` with a date prefix.
- Put old MV2025 material under `docs/archive/mv2025/` unless the user explicitly asks to revive it.

## New Chat Prompt

```text
Read docs/000_ASSET_LIBRARY.md first, then docs/000_RESEARCH_CONTEXT.md and docs/012_AI_WORKSPACE_GUIDE.md. Use docs/VIBEX_PROJECT.md for scope, docs/VIBEX_RESULTS.md for current evidence, and docs/VIBEX_BUILD.md for build/release commands. Treat /Users/ps3460/GitLab/Thesis as the linked LaTeX thesis repo and do not edit it unless I explicitly ask.
```
