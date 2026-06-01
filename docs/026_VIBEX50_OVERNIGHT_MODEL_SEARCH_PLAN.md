# VIBEX-50K Overnight Model Search Plan

Date: 2026-05-19

## Purpose

This run searches for improved VIBEX-50K models for both deployment layers:

- ESP32 Stage 1 binary malware detector.
- Workhorse/Pi Stage 2 malware-family image model.

The experiment is intentionally broad. Most candidates are small perturbations around the strongest current models, while a smaller fraction are outlier architectures or training policies to test whether unusual model shapes offer useful gains.

## Current Baselines

ESP32 Stage 1 baseline:

- Candidate family: `prefix1024`
- Strong current candidate: `prefix1024_w96_d30_lr0006_wd0002`
- Selection priority: minimise missed malware first, then optimise balanced accuracy and benign false alarms.

Stage 2 baseline:

- Strong current family: CNN96 style image model.
- Selection priority: malware-family macro F1 and recall, while keeping inference/export practical for the Pi-side Stage 2 path.

## Search Size

Target search size:

- 2000 ESP32 Stage 1 candidates.
- 2000 Stage 2 candidates.

The run is resumable and SQL-backed. Every candidate is written to MySQL when it starts and again when it completes or fails, so the dashboard, Gemma, and later thesis analysis can inspect progress in near real time.

## Scheduling Policy

The overnight process runs as a combined scheduler on workhorse:

1. Train/evaluate one ESP32 candidate.
2. Cool down.
3. Train/evaluate one Stage 2 candidate.
4. Cool down.
5. Repeat until both targets are complete or the run is stopped.

This avoids two TensorFlow jobs competing for the same GPU and makes the cooldown meaningful.

Cooldown policy:

- Minimum sleep between candidates: 20-30 seconds.
- GPU temperature limit: 70C by default.
- If the GPU is at or above the limit, the scheduler sleeps in 180 second blocks until it cools.

## ESP32 Stage 1 Search Space

The ESP32 search tests deployable binary classifiers. The current implementation uses the existing VIBEX-50K builders, so the main supported feature families are:

- `prefix1024`
- `prefix1024_hist256_entropy16_stats8_1304`

Parameters varied:

- Width: 48, 64, 80, 96, 112, 128, 160
- Dropout: 0.05 to 0.45
- Learning rate: 1e-4 to 1.2e-3
- Weight decay: 0 to 8e-4
- Batch size: 128, 192, 256, 384
- Epoch policy: fast screening at 4-6 epochs, with periodic deeper candidates at 10-16 epochs

Ranking metrics:

1. Missed malware
2. Benign false alarms
3. Balanced accuracy
4. Macro F1
5. ROC AUC
6. TFLite size and hash/export suitability

Threshold rule:

- `prefix1024` candidates are scored with the validation-only threshold evaluator.
- The selected threshold must satisfy the configured benign false-positive cap where possible; the overnight run uses `2%` to match the strongest known offline candidate.
- Test metrics are then reported once at the validation-selected threshold.
- Default `0.5` threshold metrics are retained as secondary evidence only.

## Stage 2 Search Space

The Stage 2 search tests malware-family image classifiers on workhorse. It includes compact baselines, CNN variants near the current best, and larger outlier candidates.

Architecture families:

- Dense image baselines
- CNN
- CNN with batch normalisation
- CNN with global average pooling
- Larger CNN-GAP outliers

Parameters varied:

- Image size: 32, 48, 64, 96, 128
- Filters: `[16,32]`, `[24,48]`, `[32,64]`, `[48,96]`, `[32,64,96]`, `[32,64,128]`, `[48,96,160]`, `[64,128,192]`
- Dense head: 96, 128, 160, 192, 224, 256, 384
- Dropout: 0.05 to 0.40
- Learning rate: 2e-4 to 1e-3
- Batch size: 64, 128, 256
- Epoch policy: fast screening at 3-5 epochs, with periodic deeper candidates at 10-16 epochs

Ranking metrics:

1. Macro F1
2. Macro recall
3. Balanced accuracy
4. Top-3 accuracy
5. Weak-family recall
6. TFLite export size/hash

## SQL Evidence

The overnight run writes to MySQL tables:

- `vibex_overnight_search_status`
- `vibex_overnight_model_results`

Each candidate row records:

- Search id and model family
- Candidate index and candidate id
- Full configuration JSON
- Start/finish timestamps
- Status and error text if failed
- Confusion counts where available
- Accuracy, balanced accuracy, macro F1, ROC AUC, top-3 accuracy where available
- TFLite size, SHA256, artifact path, summary path, and log path
- A primary ranking score for live ordering

## Monitoring

The LXC monitor polls the overnight run externally. It sends Telegram alerts if:

- The workhorse process disappears before the SQL status reaches `completed`.
- The status file stops updating beyond the configured stale threshold.
- The run writes `failed` status.

This gives independent crash detection even if the workhorse-side scheduler exits unexpectedly.

## Thesis Notes

For the thesis write-up, describe this as a hardware-aware staged search rather than a brute force grid. The important methodological points are:

- The search prioritises safety first: missed malware dominates ranking.
- Candidate results are persisted immediately, preventing survivorship bias from only reporting completed full runs.
- The scheduler alternates model families to avoid thermal and GPU contention.
- Outlier candidates are included deliberately to test whether unexpected architectures improve the deployment trade-off.
- Final claims should be based on locked candidates rerun on full validation/test splits and then confirmed by physical Pi/ESP32 E2E tests.

## Annex A: Known Pre-Search Evidence

This annex records the strongest VIBEX-50K model evidence already known before the 2000-candidate overnight search. It is included so the overnight search has a clear baseline and does not rediscover context that has already been measured.

### Workhorse and Dashboard State

- Workhorse host: `phil@10.0.0.100`, SSH port `717`.
- VIBEX vault root: `/home/phil/vibex_secure_dataset`.
- Current live model dashboard: `https://lab.ps0.uk/models`.
- Dashboard host path: `/opt/mv2025-dashboard/templates/model_learning.html`.
- Dashboard service: `mv2025-dashboard.service`.
- Last checked state during the pre-search work: dashboard active and updated with the VIBEX-50K model comparison.
- Workhorse was healthy and idle at the last pre-search check: GPU `36C`, GPU utilisation `0%`, GPU memory `752 MiB / 8192 MiB`.

### Prior Search Artifacts

First focused ESP32 search batch:

- Search root: `/home/phil/vibex_secure_dataset/models/vibex50_esp32_search_4h_20260519T141410Z`.
- Status: completed.
- Threshold evaluation: `/home/phil/vibex_secure_dataset/models/vibex50_esp32_search_4h_20260519T141410Z/prefix1024_threshold_eval.json`.

Follow-up ESP32 search batch:

- Search root: `/home/phil/vibex_secure_dataset/models/vibex50_esp32_search_followup_20260519T151335Z`.
- Status: completed.
- Threshold evaluation: `/home/phil/vibex_secure_dataset/models/vibex50_esp32_search_followup_20260519T151335Z/prefix1024_threshold_eval.json`.

### Current Hardware Baseline

The current deployed hardware baseline remains the original VIBEX-50K 1024-byte prefix model until a tuned candidate passes physical ESP32 smoke testing.

- Run path: `/home/phil/vibex_secure_dataset/esp32/VIBEX-50K-stage1/run_20260519T064453Z`.
- Input: first `1024` raw bytes of the binary.
- Threshold: `0.500`.
- Test accuracy: `98.923%`.
- Test balanced accuracy: `98.962%`.
- Test macro F1: `98.918%`.
- Test ROC AUC: `99.956%`.
- Test benign false alarms: `84`.
- Test malware misses: `23`.
- Float32 TFLite size: `414,592` bytes.
- Float32 TFLite SHA256: `a77752f0e733eaeefa18f433d1777b264710aa18c74862c93551d9d110aa6b31`.

### Current Best Honest Offline Candidate

The best offline safety candidate before the 2000-candidate search is `prefix1024_w96_d30_lr0006_wd0002`, using a threshold selected only on the validation split.

- Run path: `/home/phil/vibex_secure_dataset/esp32/VIBEX-50K-stage1/run_20260519T141704Z`.
- Input: first `1024` raw bytes of the binary.
- Model width: `96`.
- Dropout: `0.30`.
- Learning rate: `6e-4`.
- Weight decay: `2e-4`.
- Validation-selected threshold: `0.145`.
- Threshold policy: choose on validation only, with a `2%` benign false-positive-rate cap; optimise for fewest missed malware first.

Validation metrics at threshold `0.145`:

- Validation balanced accuracy: `98.809%`.
- Validation missed malware: `14`.
- Validation benign false alarms: `60`.

Test metrics at threshold `0.145`:

- Test accuracy: `98.953%`.
- Test balanced accuracy: `99.007%`.
- Test macro F1: `98.949%`.
- Test ROC AUC: `99.972%`.
- Test benign false alarms: `92`.
- Test malware misses: `12`.
- Float32 TFLite size: `414,592` bytes.
- Float32 TFLite SHA256: `4da8317e432b9bab04e27497d99ac92f5ce1953ce1475e89976d6ef11cd93383`.

Interpretation:

- This candidate roughly halves test malware misses compared with the deployed baseline, from `23` to `12`.
- The trade-off is a small increase in benign false alarms, from `84` to `92`.
- It should not be promoted on offline metrics alone; it needs physical ESP32 smoke testing.

### Best Follow-Up Candidate

The strongest follow-up model reduced false alarms but did not beat the safety leader on malware misses.

- Run path: `/home/phil/vibex_secure_dataset/esp32/VIBEX-50K-stage1/run_20260519T152207Z`.
- Candidate: `prefix1024_w96_d20_lr0004_wd0001_e20`.
- Validation-selected threshold: `0.325`.
- Test balanced accuracy: `99.117%`.
- Test malware misses: `20`.
- Test benign false alarms: `71`.
- Float32 TFLite size: `414,592` bytes.
- Float32 TFLite SHA256: `b85968e3d5bc8dc7d279a3b23fec4e619f46b61f9e2cfdc752f254d275a56d19`.

Interpretation:

- This is a useful candidate if false alarms become the dominant deployment constraint.
- It is not the best safety candidate because it misses `20` malware samples compared with `12` for the current offline leader.

### 1304-Feature Evidence

The `1304` feature variant combines:

- `1024` prefix bytes.
- `256` byte-histogram features.
- `16` entropy-window features.
- `8` summary statistics.

Best observed 1304 candidate in the prior search:

- Run path: `/home/phil/vibex_secure_dataset/models/vibex50_esp32_1304/run_20260519T142301Z`.
- Candidate: `feat1304_w96_d30_lr0006_wd0002`.
- Validation-selected threshold: `0.550`.
- Test accuracy: `99.275%`.
- Test balanced accuracy: `99.258%`.
- Test macro F1: `99.271%`.
- Test ROC AUC: `99.951%`.
- Test benign false alarms: `27`.
- Test malware misses: `45`.
- Float32 TFLite size: `522,076` bytes.
- Float32 TFLite SHA256: `873ba315000185cea12cae027368fc634fc79a67d23e591720cbb20fc9d859ee`.

Interpretation:

- The 1304 feature family is strong on balanced accuracy and false alarms.
- It is not the current safety leader because the best observed 1304 model misses more malware than the tuned 1024-byte model.

### Overfitting Caveat

The leading `1024 w96` model shows mild late-epoch overfit:

- Training accuracy continued upward to about `99.544%`.
- Validation accuracy peaked around `99.312%` and later fell to about `98.977%`.
- Validation AUC also rolled off late, from a best value around `99.935%` to about `99.824%`.
- Validation loss rose late after its best point.

This does not invalidate the model because early stopping restored the best weights, but it means the overnight search should treat the current leader as a strong baseline rather than a final thesis-grade result.

### Promotion Rule

No candidate should be promoted solely because it wins an offline table. The promotion sequence should be:

1. Select threshold using validation only.
2. Report locked test metrics once.
3. Export TFLite and hash artifacts.
4. Prepare SD-card payload.
5. Run physical Pi/ESP32 smoke test.
6. Update the dashboard and documentation only after the smoke test passes.
