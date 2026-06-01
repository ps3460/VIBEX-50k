# Research Workflow

## Research Purpose

This system supports PhD research into malware classification on constrained Edge AI hardware. The core research question is how to balance local inference on ESP32 nodes against heavier inference on a Raspberry Pi while preserving classification quality, latency, reliability, and power efficiency.

The primary focus is collecting as much useful data as possible.

## Metrics Goals

Capture metrics across both tiers:

- Tier 1 classification.
- Tier 1 confidence.
- Tier 1 inference time.
- Tier 1 memory and heap usage.
- Estimated Tier 1 power draw.
- Tier 2 classification.
- Tier 2 confidence.
- Tier 2 inference time.
- Transfer time.
- Retry attempts.
- Hash mismatch count.
- Dropped or missing files.
- Pi CPU temperature, load, and RAM.

## Model Optimization Loop

1. Deploy 24x24, 32x32, 48x48, and 64x64 models to ESP32 SD cards.
2. Run live hardware tests through the Pi master controller.
3. Persist metrics to CSV and MariaDB.
4. Use the dashboard to inspect accuracy, confidence, latency, transfer failures, and misclassifications.
5. Generate AI research prompts from aggregate error patterns.
6. Feed the prompt into an LLM or local model helper.
7. Use the output to adjust data augmentation, confidence thresholds, pruning, quantization, or architecture.
8. Retrain in the research notebooks.
9. Export new `.tflite` models.
10. Prepare SD cards and run the next hardware cycle.

## Local Research Path

Primary research/model source:

- `/Users/ps3460/GitLab/Malware-Classification-System/src/ml_pipeline/`

This directory contains training, conversion, SD-card preparation, and export helpers. Notebooks now live under `notebooks/`, datasets under `data/`, and saved model artifacts under `models/YYYYMMDD/`.

## Dashboard Research Features

Expected dashboard support:

- Test progress.
- Accuracy analytics.
- Tier 1 and Tier 2 confusion/misclassification summaries.
- Resolution-specific model performance.
- System health.
- Transfer integrity.
- SQL-backed historical analysis.
- Restart/rerun control.

## SD Card Preparation

Automated preparation script:

- `src/ml_pipeline/prepare_dual_sd.py`

Expected behavior:

- Scan `data/malware_images` for all 25 families.
- Select unique image sets per node.
- Convert images to raw UINT8 binary format for 24x24, 32x32, 48x48, and 64x64.
- Preserve original PNG files for Tier 2.
- Bundle current `.tflite` models.
- Generate `ESP32_1` and `ESP32_2` folders in `sd_card_prep/esp32_node_sets/`.
- Current generated node folders contain 125 `.bin` files per resolution per ESP32, or 500 `.bin` files per ESP32 across 24x24, 32x32, 48x48, and 64x64.

The earlier 16x16 model path is kept as ablation evidence for the final write-up, but it is not part of the current live hardware cycle.

## Documentation Rule

Keep research conclusions and durable workflow here. Put individual test runs, audits, and hardware fault investigations in [Tests and Audits](009_TESTS_AND_AUDITS.md).

Promote only genuinely paper-worthy findings to [PhD RS485 Baud Rate Findings](010_PHD_RS485_BAUD_RATE_FINDINGS.md). A finding is worth promoting when it is reproducible, measured, explains a system-level improvement or failure mode, and contains enough method/context for a later LLM or paper draft to turn it into a thesis-quality section.
