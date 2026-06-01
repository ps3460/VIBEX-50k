# VIBEX-50K 1024 w96 Threshold 0.145 Smoke Payload - 2026-05-21

## Purpose

Prepare a physical-lab smoke payload for the current best honest offline ESP32 Stage 1 candidate:

- Candidate: `prefix1024_w96_d30_lr0006_wd0002`.
- Source run: `/home/phil/vibex_secure_dataset/esp32/VIBEX-50K-stage1/run_20260519T141704Z`.
- Input: first `1024` raw executable bytes.
- Validation-selected threshold: `0.145`.
- Float32 TFLite SHA256: `4da8317e432b9bab04e27497d99ac92f5ce1953ce1475e89976d6ef11cd93383`.

## Offline Evidence

Validation metrics at threshold `0.145`:

- Balanced accuracy: `98.809%`.
- Missed malware: `14`.
- Benign false alarms: `60`.

Test metrics at threshold `0.145`:

- Accuracy: `98.953%`.
- Balanced accuracy: `99.007%`.
- Macro F1: `98.949%`.
- ROC AUC: `99.972%`.
- Missed malware: `12`.
- Benign false alarms: `92`.

The deployed hardware baseline remains the previous 1024-byte model at threshold `0.500` until this candidate passes physical ESP32 smoke testing.

## Staged Payload

Data-share location:

```text
/mnt/data-share/vibex/physical_payloads/VIBEX-50K-stage1-w96-thr0145-smoke-20260521
```

Payload structure:

```text
ESP32_1/VIBEX-50K/
ESP32_2/VIBEX-50K/
```

Verification performed on 2026-05-21:

- Total staged sample binaries: `9,934`.
- Staged size: `47M`.
- `ESP32_1` manifest lines: `4,968` including header.
- `ESP32_2` manifest lines: `4,968` including header.
- Both node models hash to `4da8317e432b9bab04e27497d99ac92f5ce1953ce1475e89976d6ef11cd93383`.
- Both node configs use:
  - `manifest_file`: `VIBEX-50K/manifests/stage1_vibex50_manifest.csv`
  - `model_file`: `VIBEX-50K/models/stage1_current.tflite`
  - `threshold`: `0.145`

## Caveat

The source training run generated its SD-card config at threshold `0.500`. The threshold `0.145` was selected later by the validation-only threshold evaluator. This staged payload deliberately patches the config threshold to `0.145` so the physical smoke test matches the offline candidate being reported.

## Next Step

Copy the staged `ESP32_1/VIBEX-50K` and `ESP32_2/VIBEX-50K` trees to the matching ESP32 SD cards, then run a small physical smoke test before any full-run or dashboard promotion.
