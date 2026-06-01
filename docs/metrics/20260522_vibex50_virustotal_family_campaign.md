# VIBEX-50K VirusTotal Family Verification Campaign

Date: 2026-05-22

Purpose: document the start of the 11-day VIBEX-50K VirusTotal family-verification run so the dataset paper can reconstruct how family evidence was sampled, queried, stored, and reported.

## Campaign Scope

- Campaign id: `VIBEX-50K-vt-family-20260522-20260601`
- Window: 2026-05-22 through 2026-06-01 inclusive
- Daily cap: `500` uncached VirusTotal hash-report requests
- Campaign ceiling: `5,500` uncached VirusTotal requests
- Query mode: hash lookup only
- Exclusion rule: benign hashes are not sent to VirusTotal
- Strata source: ClamAV family groups, used as sampling strata rather than final family truth
- Label evidence source: saved VirusTotal JSON reports and SQL-derived consensus fields
- Local LLM role: `ollama run gemma2:2b` may summarise reports and review weak labels, but it is not a label authority

## Frozen Inputs

The runner uses campaign-local copies so another script cannot change the manifest or family log during the run.

| Input | Path | SHA-256 | Lines |
| :--- | :--- | :--- | ---: |
| Safe manifest | `/home/phil/vibex_secure_dataset/evidence/virustotal_campaign_20260522_20260601/input/safe_dataset_manifest_VIBEX-50K_20260518T081144Z.campaign.csv` | `d7a752b2ec6607f0af899946a50091249df43afbb6d8d30d59b11bf2ffb333e5` | `50001` |
| ClamAV family log | `/home/phil/vibex_secure_dataset/evidence/virustotal_campaign_20260522_20260601/input/clamav_avclass_virusshare00499_workhorse.campaign.avclass.log` | `5d4555d6605c2375f7b3fc0a76478d6512705b9223d23784b694e94b57dfe188` | `37321` |

## Evidence Paths

- Runner: `/home/phil/vibex_secure_dataset/tools/vibex_virustotal_family_scan.py`
- VT JSON cache: `/home/phil/vibex_secure_dataset/evidence/virustotal/VIBEX-50K`
- Campaign queues: `/home/phil/vibex_secure_dataset/evidence/virustotal_campaign_20260522_20260601/queues`
- Static dashboard: `/home/phil/vibex_secure_dataset/evidence/virustotal_campaign_20260522_20260601/dashboard/index.html`
- SQL database: `mv2025_lab` on `10.64.0.98`
- Live dashboard: `https://malwarelab.i.steadnet.com/malware-database`
- Live API: `https://malwarelab.i.steadnet.com/api/vt-family-campaign`

## SQL Storage

The campaign stores audit state in SQL and keeps raw JSON reports on disk.

- `vibex_virustotal_family_results`: per-sample malware hash status, VT statistics, derived family label state, and report path.
- `vibex_virustotal_family_scan_runs`: per-run request limits, uncached request count, cached report count, status, and errors.
- `vibex_virustotal_family_gemma_reports`: saved Gemma summaries and weak-label review notes.
- `vibex_virustotal_family_strata`: per-ClamAV-stratum status, labelled count, dominant VT family, agreement rate, ambiguity rate, and retirement/review status.
- `vibex_virustotal_family_daily_quota`: daily cap, used uncached requests, cached reports read, remaining quota, and day status.

## Sampling and Retirement Rules

- Allocate daily requests across active ClamAV strata.
- Prioritise under-sampled families, then disagreement and ambiguous families.
- Keep generic groups such as `Trojan`, `Generic`, and `Agent` active as review buckets.
- Retire a non-generic family only after at least `20` VT-labelled samples, at least `90%` agreement with the dominant VT-derived family, and at most `10%` ambiguous or insufficient-label samples.
- Mark a family with fewer than `20` available samples as `small_stable` only after all available samples have been queried and the labelled evidence is stable.

## Deployment State

The previous sequential service was stopped before enabling the stratified runner so it could not spend quota outside the campaign queue.

Active workhorse units:

- `vibex-virustotal-family-scan.service`: stratified scan runner
- `vibex-virustotal-family-scan.timer`: daily run timer, next run after deployment was 2026-05-23 around 00:17 BST
- `vibex-virustotal-family-daily-report.timer`: scheduled report timer, next run after deployment was 2026-05-25 15:00 BST

Telegram reporting:

- Immediate start message when the runner switched over
- Scheduled reports at 15:00 BST on 2026-05-25, 2026-05-28, and 2026-05-31
- Final report on 2026-06-01 after the day-11 quota window completes

## Verification Evidence

Dry-run queue generation:

- Queue artifact: `/home/phil/vibex_secure_dataset/evidence/virustotal_campaign_20260522_20260601/queues/vt_stratified_queue_VIBEX-50K_2026-05-22_20260522T153749Z.csv`
- Queue rows: `370` data rows plus header
- Benign rows found in queue: `0`

Smoke run:

```text
2026-05-22T15:39:21Z stratified complete=635/23186 requests=5/5 cached=0
```

SQL state after switchover:

```text
daily quota 2026-05-22: daily_cap=500, used_requests=135, cached_reports=0, remaining=365, status=running
strata statuses: active=173, generic_needs_review=13, ambiguous_needs_review=5, exhausted_unstable=4, small_stable=2
```

Live dashboard verification from the dashboard host:

- `https://malwarelab.i.steadnet.com/malware-database` returned HTTP `200`
- The malware database page contained the `VirusTotal Family Verification` section
- The page included the malware-only notice: `Malware hashes only. Benign hashes are not sent to VirusTotal.`
- `https://malwarelab.i.steadnet.com/api/vt-family-campaign` returned `ok`
- At verification time after the dedicated malware database page was deployed, API `status_counts.ok` was `734`

Gemma verification:

- Local workhorse model `gemma2:2b` was confirmed available through Ollama.
- The confirmation response included `VIBEX_GEMMA_OK`.

## Secret Handling Note

Vault AppRole login for the campaign database path returned HTTP `403` during deployment. To keep the campaign auditable while avoiding secret material in git, a private workhorse env file was created at:

```text
/home/phil/vibex_secure_dataset/secrets/vibex-campaign-db.env
```

The file is a deployment artifact with restrictive permissions and is not committed. The runner loads it before attempting the standard Vault env path.
