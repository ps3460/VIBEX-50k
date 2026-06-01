# VIBEX-50K ESP32 Local CSV Stage 1 + Stage 2 Experiment

Date: 2026-05-23

This note records a learning-stage hardware experiment, not a final production/live-system claim. The purpose was to reduce RS485 transfer overhead by letting `ID:01` run Stage 1 locally on the ESP32, write compact CSV evidence to its SD card, and send only CSV output back to the Pi. The Pi then joined predictions to the held manifest truth labels for reporting and ran the Stage 2 PNG CNN only on uncertain rows.

## Experiment Boundary

- This is experimental pipeline evidence.
- The ESP32 and Pi did not know the true labels during inference.
- True labels were joined after the run from the prepared VIBEX manifest.
- The run used the available partially staged SD-card payload, not a complete 50,000-sample SD card.
- Two sample files were missing at the end of the staged range because the earlier RS485 binary push had been interrupted.

## Method

The old slow path pushed binaries over RS485. The new path keeps binaries on the ESP32 SD card and uses RS485 for command/control plus compact CSV evidence.

Flow:

1. `ID:01` scans local `/VIBEX-50K/samples/...` `.bin` files with the ESP32 Stage 1 model.
2. `ID:01` writes `/VIBEX-50K/evidence/stage1_local_all.csv`.
3. `ID:01` writes `/VIBEX-50K/evidence/stage1_local_uncertain.csv`.
4. Pi5 fetches the compact all-results CSV over RS485.
5. Pi5 joins predictions to manifest truth labels after inference.
6. Pi5 runs Stage 2 PNG CNN only for Stage 1 probabilities in the uncertainty band.

Uncertainty band:

- Low risk: `0.01`
- High risk: `0.05`

Models:

- Stage 1 ESP32: `prefix1024_w96_d30_lr0006_wd0002`
- Stage 1 threshold: `0.145`
- Stage 2 Pi CNN: `vgg16_header_bytes_body_dual`
- Stage 2 threshold: `0.48`
- Stage 2 model SHA-256: `ac18a3312b4ccc5441ab5364b9d95b130e28d7dc43fec1d91d3ba5ee36a5eef5`

## Performance

| Item | Result |
| --- | ---: |
| Requested samples | 3,800 |
| ESP32 processed samples | 3,798 |
| Missing sample files | 2 |
| Stage 1 uncertain rows | 65 |
| ESP32 scan time | 2,079.389 seconds |
| Full CSV size | 245,086 bytes |
| Full CSV fetch time over RS485 | 46.785 seconds |

The observed ESP32 Stage 1 rate was about `0.5475` seconds per sample. A single ESP32 would therefore take roughly `7h 36m` for 50,000 samples, before overhead. A practical planning estimate is about `8h` for one ESP32, or about `3h 48m` if split evenly across two ESP32 devices.

## Results

Stage 1:

| Metric | Value |
| --- | ---: |
| Accuracy | 99.078% |
| Balanced accuracy | 99.078% |
| Macro F1 | 99.078% |
| ROC AUC | 0.999695 |
| Missed malware | 6 |
| False alarms | 29 |

Stage 1 confusion matrix:

| True benign predicted benign | True benign predicted malware | True malware predicted benign | True malware predicted malware |
| ---: | ---: | ---: | ---: |
| 1,870 | 29 | 6 | 1,893 |

Stage 2 on uncertain rows only:

| Metric | Value |
| --- | ---: |
| Rows checked | 65 |
| Accuracy | 90.769% |
| Balanced accuracy | 95.161% |
| Macro F1 | 72.458% |
| ROC AUC | 0.983871 |
| Malware recovered by Pi | 3 |
| False alarms added by Pi | 6 |
| False alarms removed by Pi | 0 |

Stage 2 uncertain-only confusion matrix:

| True benign predicted benign | True benign predicted malware | True malware predicted benign | True malware predicted malware |
| ---: | ---: | ---: | ---: |
| 56 | 6 | 0 | 3 |

Final cascade:

| Metric | Value |
| --- | ---: |
| Accuracy | 98.999% |
| Balanced accuracy | 98.999% |
| Macro F1 | 98.999% |
| ROC AUC | 0.999349 |
| Final missed malware | 3 |
| Final false alarms | 35 |

Final cascade confusion matrix:

| True benign predicted benign | True benign predicted malware | True malware predicted benign | True malware predicted malware |
| ---: | ---: | ---: | ---: |
| 1,864 | 35 | 3 | 1,896 |

## Interpretation

This experiment supports the design direction: use RS485 for commands and compact evidence, not bulk binary movement. Stage 2 recovered half of the Stage 1 missed malware in this run, reducing missed malware from `6` to `3`, but it added `6` benign false alarms. Under the project safety ranking, this is a useful trade to study further, but it is not yet a final thesis-grade cascade result.

The immediate engineering lesson is that the full SD-card payload should be prepared by direct card copy or USB mass storage, then the lab should use local ESP32 scanning plus CSV evidence transfer. Bulk `.bin` transfer over RS485 is too slow for large experimental runs.

## Evidence Paths

Pi5 evidence root:

- `/home/phil/vibex_stage2_testing/local_csv_runs/vibex50_id01_local_csv_20260523T134842Z`

Stage 2 summary:

- `/home/phil/vibex_stage2_testing/local_csv_runs/vibex50_id01_local_csv_20260523T134842Z/vibex50_stage12_uncertain_20260523T135015Z/summary.json`

Joined prediction CSV:

- `/home/phil/vibex_stage2_testing/local_csv_runs/vibex50_id01_local_csv_20260523T134842Z/vibex50_stage12_uncertain_20260523T135015Z/joined_predictions.csv`

## Full Deployable Stage 1 Baseline Launch

Later on 2026-05-23, the full `ID:01` Stage 1 baseline was prepared for an overnight LXC-run job. A first candidate package was rejected during preflight because it contained `50,000` rows but all rows were labelled `malware`; no SQL import was made from that invalid package.

The corrected package was built from the workhorse `prefix1024` matrix rather than from the rejected all-malware SD tree:

- Source manifest: `/home/phil/vibex_secure_dataset/esp32/VIBEX-50K-stage1/run_20260520T090959Z/manifests/prefix1024_manifest.csv`
- Source features: `/home/phil/vibex_secure_dataset/esp32/VIBEX-50K-stage1/run_20260520T090959Z/manifests/prefix1024_features_uint8.npy`
- Corrected package: `/mnt/data-share/vibex/physical_payloads/VIBEX-50K-stage1-ID01-prefix49674-w96-thr0145-20260523T1925Z`
- Package manifest SHA-256: `d4e41e5546612137acfe8314c3ce92d44ebecec2b3f1d6dbf9077e7e7f86a1dd`
- Prefix feature matrix SHA-256: `44c64232129f8c7b52d53bd95fb3ec74fa874403639beb8663ed2a6d1eb40d2f`
- Model SHA-256: `4da8317e432b9bab04e27497d99ac92f5ce1953ce1475e89976d6ef11cd93383`
- Deployable rows: `49,674`
- Class counts: `26,651` benign, `23,023` malware

This is the full deployable Stage 1 prefix set currently available for the ESP32 path. It is smaller than the public `50,000` PNG release because `326` public PNG rows do not have valid `1024`-byte Stage 1 prefix features in the workhorse prefix matrix. The overnight run therefore uses `49,674` as the honest expected count for Stage 1 hardware evidence.

Active LXC run:

- Run id: `vibex50-id01-stage1-local50k-20260523T183012Z`
- LXC orchestrator: `/usr/local/bin/vibex_id01_stage1_full50_lxc_orchestrator.sh`
- LXC run root: `/var/lib/malware-hourly-runner/vibex50-stage1-full50/vibex50-id01-stage1-local50k-20260523T183012Z`
- Pi evidence root: `/home/phil/vibex_stage2_testing/local_csv_runs/vibex50-id01-stage1-local50k-20260523T183012Z`
- RS485 mode: forced rewrite, `RS485_SKIP_EXISTING=0`, because the stopped invalid package used same-size sample names.
- Telegram policy: no Telegram after `21:00 Europe/London`; completion report held until `07:00 Europe/London`.
