# VIBEX Holiday Research Runbook

Date: 2026-05-24

This runbook controls the fully remote eight-day VIBEX research run while the
operator only has phone or tablet access. The control host is the Codex LXC:

```text
ssh phil@10.0.0.157
tmux attach -t codex
```

## Non-Negotiable Rules

- No raw malware uploads.
- No labels inferred from filenames, folders, LLM output, or model predictions.
- No SD-card copy assumptions. Use only existing remote data and evidence.
- Conservative recovery only. Do not reboot Pi, workhorse, or Proxmox guests
  unless the operator explicitly approves it later.
- If hardware is blocked, continue with SQL, existing CSVs, workhorse evidence,
  and document the blocker.
- Telegram is capped at four messages per day after tonight. Tonight may send
  setup, smoke, start, and failure messages.

## Control Hosts

| Role | Target |
| --- | --- |
| Codex LXC | `phil@10.0.0.157` |
| Workhorse | `phil@10.0.0.100` / SSH alias `workhorse` |
| Proxmox | `root@10.0.0.11` |
| Monitoring LXC | VMID `670`, `10.64.0.65` |
| Runner/Telegram LXC | VMID `124`, `10.64.0.62` |
| Pi5 controller | `phil@10.64.1.102` |
| Malware dashboard backend | `http://10.64.0.87:8085` |

## Primary Outputs

- Family-labelled VIBEX malware manifest.
- Train/validation/test manifests for malware-family recognition.
- Family counts, label provenance, and ambiguity/unlabelled report.
- Malware-family folder view for CNN training.
- CNN leaderboard with reproducible model IDs, metrics, hashes, and paths.
- SQL Stage 2 queue/results written from Stage 1 rows where available.

## Evidence Locations

Use the secure workhorse vault for large/private evidence:

```text
/home/phil/vibex_secure_dataset/evidence/holiday_run_20260524_8day
/home/phil/vibex_secure_dataset/release/VIBEX-50K
/home/phil/vibex_secure_dataset/models
```

Use Git Markdown for safe summaries:

```text
docs/metrics/20260524_vibex_holiday_research_log.md
```

## Daily Remote Loop

1. Verify the LXC, workhorse, VT campaign, SQL, Prometheus, disk, and thermal
   state.
2. Continue the VirusTotal family campaign without exceeding the quota.
3. Build or refresh family-labelled manifests from saved evidence.
4. Search public family datasets for exact SHA256 overlap.
5. Train or continue CNN benchmarks when workhorse temperature is safe.
6. Build Stage 2 queues from Stage 1 SQL and run family inference where inputs
   and labels are available.
7. Append Markdown evidence before Telegram.
8. Send one concise daily Telegram summary unless an urgent event needs one of
   the four daily message slots.

## Thermal Policy

- Workhorse: do not start heavy GPU jobs above 75C; stop or pause sustained GPU
  work at 80C.
- Pi5: pause jobs above 70C; resume below 60C.
- Record every thermal pause in JSON and Markdown.

## Monitoring Smoke Baseline

The 2026-05-24 smoke found:

- Grafana `https://grafana.i.steadnet.com/` returned HTTP 200.
- Prometheus proxy `https://prometheus.i.steadnet.com/-/ready` returned HTTP
  200.
- Prometheus inside LXC 670 returned `up`, `pve_up`, `node_load1`, and
  `node_hwmon_temp_celsius`.
- Malware backend `/metrics` returned HTTP 403, so the Prometheus `malwarelab`
  job must not be added until the route is made internally readable.

## Stage 2 Definition

Stage 2 means family recognition after Stage 1 SQL detection. Stage 1 rows come
from `mv2025_lab.stage1_runs` and `mv2025_lab.stage1_results`. Stage 2 joins
those rows to the family-labelled manifest, queues samples according to the
selected policy, runs CNN family inference, and writes to `stage2_models`,
`stage2_results`, `stage2_run_summaries`, and `stage1_events`.

Ground truth labels are used only for offline evaluation and reporting, never
for live routing decisions.
