# MV2025 Lab Acceptance Runner Plan

Last updated: 2026-05-22

## Current Acceptance Baseline

The acceptance runner is the dashboard-driven random-run check for the physical VIBEX-50K lab. It is intentionally separate from the hourly/full runner and must never start the Full Dataset path.

Latest known successful acceptance run:

- Artifact directory: `/var/lib/mv2025-lab-acceptance/runs/20260521_212610`
- Dashboard URL: `https://malwarelab.i.steadnet.com/`
- Mode: `random`
- Samples: `250`
- Run ID: `vibex50-dual-random250-roundrobin-20260521-212618`
- Result: `complete`
- SQL rows: `250/250`
- Node split: `ID:01=125`, `ID:02=125`
- Transfers: `250/250 completed`
- Hash matches: `250/250`
- Hash mismatches, failed, decode error, incomplete transfers: `0`

## Required Contract

The runner must keep these hard boundaries:

- Accept only bounded random runs from `100` to `500` samples.
- Default to `250` samples.
- Refuse invalid sample counts before touching the lab.
- Use `https://malwarelab.i.steadnet.com/` for local/private acceptance runs.
- Never click or trigger `Full Dataset`.
- Refuse to start when a non-stale lab run, SD payload push, or controller process is active.
- If the physical gate is locked or Random Run is unavailable, report status-only evidence rather than falling back to smoke.
- Treat LCD proof as software-level agreement: physical LCD write command succeeds, SQL `lcd_state.ID:00` updates, `/api/status` agrees, and the web mirror renders matching lines.

## Improved Overnight Test Plan

1. Preflight

- Query `/api/health`, `/api/status`, `/api/readiness`, and `/api/lab-control`.
- Save the preflight payloads before any state-changing operation.
- Confirm Random Run availability from `/api/lab-control.actions`.
- Confirm any SQL `active_run` is stale before ignoring it.

2. SQL Readiness

- Read `stage1_models`, `stage1_runs`, `stage1_results`, `stage1_transfers`, `stage1_events`, and `lcd_state`.
- Save table row counts in `sql_checks.json`.
- Fail fast if direct SQL is unavailable.

3. LCD Path

- Write four deterministic acceptance lines to the Pi LCD using the Pi virtualenv Python path.
- Upsert the same lines into SQL `lcd_state.ID:00`.
- Compare SQL, `/api/status.lcd_state.ID:00`, and the `/lab` web mirror.
- Save `lcd_write.json` and `lcd_state_check.json`.

4. Website Path

- Use Playwright to open `/lab`.
- Verify buttons render and their enabled/disabled states match `/api/lab-control`.
- Click `Refresh`.
- Click `Random Run`.
- Enter the requested sample count, default `250`.
- Accept the random-run confirmation.
- Assert that `Full Dataset` was not clicked.
- Save `lab_page_before.png`, `lab_page_after.png`, `browser_console.json`, and `browser_result.json`.

5. Runtime Evidence

- Wait for a new SQL run with `expected_samples == random_samples`.
- While active, `/api/acceptance.progress` should follow the active run, not the previous completed result.
- Detect terminal non-completed SQL states early and write `run_sql_evidence.json`.
- On completion, require `expected_samples == received_samples == random_samples`.

6. Transfer Evidence

- Require both `ID:01` and `ID:02` to have result rows.
- Require transfer count to equal sample count.
- Require completed transfers to equal transfer count.
- Require hash matches to equal transfer count.
- Require failed, decode error, incomplete, and hash mismatch counts to be `0`.

7. Reporting

- `/acceptance` must show runner state, progress percent, sample count, transfer count, latest run ID, latest report, artifacts, browser screenshots, and runner stdout/stderr.
- The final `report.md` should be concise and machine-verifiable.
- Telegram should receive only one-line start/completion/failure/stall summaries when the runner LXC notification path is reachable.

## Gaps To Close Next

- Add a Telegram bridge for dashboard-started acceptance runs without copying bot tokens onto the dashboard host. The dashboard should hand off a one-line notification request to the runner LXC or a controlled internal endpoint.
- Add a stall detector for active runs: warn when `received_samples` and latest `stage1_events.created_at` do not advance for a configured interval.
- Add a non-hardware self-test mode for `/acceptance` that validates page/API rendering against saved artifacts without starting Random Run.
- Store a compact final summary JSON that duplicates the critical fields from `run_sql_evidence.json` for easy dashboard rendering.
- Add a cleanup or archive view for old failed acceptance attempts so the successful baseline is easy to find.

## Workhorse And Gemma Review

Gemma/workhorse can be useful as an offline critique pass over `report.md`, `run_sql_evidence.json`, and the runner source, but it must not be in the runtime acceptance path. The acceptance runner is physical-lab evidence; a language model review is advisory only.

Suggested use:

- Copy only non-secret artifacts and source snippets to the workhorse review path.
- Ask Gemma for missing assertions, confusing report wording, and likely operator failure modes.
- Record useful suggestions in docs or issues.
- Do not expose database credentials, Telegram tokens, Cloudflare session material, SSH keys, malware samples, or raw private data.

## Overnight Change Made

The `/api/acceptance` progress calculation now prefers the active run artifact when an acceptance runner process is active. This prevents the page from showing the previous completed run while a new run is in progress and before `result.json` exists.
