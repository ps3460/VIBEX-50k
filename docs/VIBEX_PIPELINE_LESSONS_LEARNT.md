# VIBEX Pipeline Lessons Learned

This file records operational rules from repeated VIBEX-50K RS485, ESP32, Pi, SQL, and dashboard failures. Read it before changing the physical pipeline, dashboard controls, LCD mirrors, or run scheduler.

## Hard Rules

- The ESP32 can only speak when spoken to. No unsolicited RS485 readiness, cache, boot, model, or status messages are allowed on the shared bus.
- ID:00 owns the RS485 bus. Polls and grants must be sequential; never poll ID:01 and ID:02 in parallel.
- Before any Smoke, Random, or Full Dataset run, ID:00 must send `STATUS?` to ID:01 and ID:02 and receive valid `loaded=1` and `sd=1` responses.
- The website must mirror SQL-backed LCD state and SQL events. Do not invent separate browser-only board state when `lcd_state` or `stage1_events` already contains the truth.
- The web Lab Topology must show node poll-in state even when no sample test is running.
- Stop paths must be visible: Pi LCD, ESP32 LCDs, SQL run status, and Telegram should agree that a deliberate stop is `stopped`, not `failed`.

## Debug Before Bigger Runs

- For any scheduler, dashboard-control, firmware-protocol, or LCD change, run in debug mode first.
- Verify in this order:
  1. ID:00 can poll `ID:01 STATUS?`.
  2. ID:00 can poll `ID:02 STATUS?`.
  3. The website shows both ESP32 nodes as polled in from SQL.
  4. A small Smoke run completes.
  5. A 200-sample run checks cache/drain behaviour.
  6. Only then consider 1000, 10000, or full-dataset runs.
- If a smoke fails in preflight, do not start a larger run. Fix the poll parser, deployed script, service path, or hardware state first.

## Deployment Lessons

- Deploy to the live dashboard container, not only to the Pi source bundle.
- Live dashboard target:
  - Proxmox host: `root@10.0.0.11`
  - Container: `102` / `Vibex-100K-dashboard`
  - App root: `/opt/mv2025-dashboard`
  - Service: `mv2025-dashboard.service`
- Pi runner target:
  - Host: `phil@10.64.1.102`
  - Bundle controller: `/home/phil/vibex_pi/VIBEX-50K-stage1_PI_20260519T094500Z/controller/mv2025`
  - Working controller copy: `/home/phil/mv2025-pi-controller`
- After dashboard changes, verify:
  - `python -m py_compile dashboard.py`
  - `systemctl restart mv2025-dashboard.service`
  - `/api/status` returns `200`
  - `/lab` renders and contains the expected control text
- After Pi runner changes, sync both Pi controller locations and run `py_compile` on the Pi.

## Parser Lessons

- Status parsing must tolerate current firmware variants:
  - `ID:xx MV2025_STATUS:...loaded=1:sd=1...`
  - `ID:xx VIBEX-50K_STATUS:...loaded=1:sd=1...`
- Do not require fragile exact substrings if the protocol already contains unambiguous fields. Check node id, `STATUS:`, `loaded=1`, and `sd=1`.
- If a log shows a valid response but the script times out, the parser is wrong. Do not blame the ESP32 until the parser is inspected.
- Result parsing must tolerate the VIBEX protocol prefix. A valid `VIBEX-50K_RESULT` frame must be normalised or parsed the same way as the older `MV2025_RESULT` frame.

## Manifest And Firmware Lessons

- The Pi bundle manifests must match the SD-card manifests. If the ESP32 returns `s00000.bin` but the Pi expects an old `benign_...bin` name, the bus and firmware may be healthy while the Pi bundle is stale.
- Current physical VIBEX-50K cards use `/VIBEX-50K`, not `/mv2025`. New firmware, dashboard, and Pi runner work should not reintroduce old `/mv2025` assumptions.
- Firmware must not count the full 50K manifest before processing a small targeted run when ID:00 has supplied the display total. That silent manifest scan can exceed the Pi idle timeout and look like a transmission failure.

## Cache/Drain Lessons

- Dynamic cache drain must respect the minimum cache rule: do not drain below 10 samples except final remainder.
- Web-launched random and full physical runs should use 25-sample batches by default so normal drains stay above the minimum cache threshold.
- Cache readiness must be polled using `CACHE_STATUS?`; ESP32s must not announce readiness unsolicited.
- Drains must use `TX_CACHE_N <count>` so ID:00 controls exactly how many cached samples are transmitted.
- If a cache reports ready and a `TX_CACHE_N` drain produces zero bytes, retry the drain once before failing the run. The cached batch can still be valid even when the first drain command is missed on RS485.
- Lab Topology cache/drain counts must come from SQL events such as `esp32_cache_ready`, `cache_drain_start`, and `cache_drain_done`.

## SQL And Website Lessons

- `lcd_state` is the LCD source of truth for the web mirror.
- `stage1_events` is the operational source of truth for poll-in state, cache status, drains, stops, and failures.
- Pre-run `esp32_status_poll` events may use `run_id=NULL` so the dashboard can show board health when no test is active.
- A stale partial run can make the website look broken. The node health panel should still prefer newer poll-in events when result rows do not exist.

## Telegram Lessons

- Send Telegram for starts, completions, failures, stalls, skips, and material state changes.
- Do not spam during every poll. Use Telegram for state changes, not per-line logs.
