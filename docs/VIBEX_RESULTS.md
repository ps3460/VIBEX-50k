# VIBEX Results

Date: 2026-05-22

This is the concise results entry point. Detailed evidence stays in dated files under [metrics/](metrics/), while older MV2025 evidence is archived under [archive/mv2025/](archive/mv2025/).

## Dataset Freeze

| Dataset or component | Release total | Benign | Malware | Train | Test | Note |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `VIBEX-50K` | 50,000 | 26,814 | 23,186 | 40,000 | 10,000 | Current public release |
| Windows PE component | 46,046 | 23,023 | 23,023 | 36,836 | 9,210 | Internal component; limited by PE/MZ malware volume |
| Linux ELF component | 326 | 163 | 163 | 260 | 66 | Internal component; currently underpowered |

Evidence:

- [20260517_vibex_split_dataset_pipeline.md](metrics/20260517_vibex_split_dataset_pipeline.md)
- [024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md](024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md)
- [data/VIBEX-50K_README.md](../data/VIBEX-50K_README.md)

## Binary-Image Baselines

Model: small grayscale CNN over resized `224 x 224` PNGs.

Common settings:

- Epochs: `6`
- Batch size: `64`
- Optimizer: `AdamW`
- Loss: `BCEWithLogitsLoss`
- Seed: `20260518`
- Device: `cuda`

| Evaluation | Accuracy | Balanced accuracy | Macro-F1 | ROC AUC | Main interpretation |
| --- | ---: | ---: | ---: | ---: | --- |
| Random split | 0.9448 | 0.9439 | 0.9444 | 0.9860 | Strong first baseline, but likely optimistic |
| Windows Server benign holdout | 0.9099 | 0.9116 | 0.9060 | 0.9672 | Holds up under provenance shift with a clear drop |
| Windows 11 benign holdout | 0.9175 | 0.9199 | 0.8813 | 0.9733 | Holds up under larger benign-source shift |

Confusion matrices:

| Evaluation | True benign predicted benign | True benign predicted malware | True malware predicted benign | True malware predicted malware |
| --- | ---: | ---: | ---: | ---: |
| Random split | 5,130 | 232 | 320 | 4,318 |
| Windows Server benign holdout | 6,699 | 712 | 374 | 4,264 |
| Windows 11 benign holdout | 17,250 | 1,583 | 353 | 4,285 |

Evidence:

- [20260518_vibex50_binary_image_baselines.md](metrics/20260518_vibex50_binary_image_baselines.md)

## PhD Claim Boundary

Supported now:

- `VIBEX-50K` is reproducibly constructed from documented executable sources into deterministic `1024x1024` grayscale PNGs.
- The first binary-image baseline performs strongly on the frozen random split.
- Source-holdout results remain good but lower, showing that provenance shift matters and must be part of the thesis evaluation.
- The Linux ELF component is currently too small for strong Linux/ELF claims.

Not supported yet:

- Production malware detection claims.
- Strong malware-family classification claims.
- Strong Linux/ELF generalisation claims.
- Claims that random split accuracy alone reflects real deployment performance.

## Family-Labelling Smoke

The first ClamAV-versus-VirusTotal smoke comparison supports the family-labelling direction, but it is not yet the full release labelling pass.

| Check | Result |
| --- | ---: |
| Unique smoke detections | 11 |
| VirusTotal malware consensus supported | 11 / 11 |
| ClamAV family name supported by VirusTotal terms | 10 / 11 |

Evidence:

- [vt_smoke_compare_20260518T181121Z.summary.md](../data/evidence/vt_smoke_compare/vt_smoke_compare_20260518T181121Z.summary.md)

## Family Verification Campaign

The release family-enrichment pass is now running as an 11-day stratified VirusTotal campaign.

| Campaign | Window | Daily cap | Query rule | Dashboard |
| --- | --- | ---: | --- | --- |
| `VIBEX-50K-vt-family-20260522-20260601` | 2026-05-22 to 2026-06-01 | 500 uncached hash lookups | Malware hashes only; no uploads; no benign hashes | `https://malwarelab.i.steadnet.com/malware-database` |

Evidence:

- [20260522_vibex50_virustotal_family_campaign.md](metrics/20260522_vibex50_virustotal_family_campaign.md)
- [025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md](025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md)

## ESP32 Local CSV Cascade Experiment

This is learning-stage hardware evidence, not a production/live-system claim. The ESP32 and Pi did not know the true labels during inference; the report joins predictions to the manifest truth labels afterward.

| Run | Stage 1 rows | Stage 1 balanced accuracy | Stage 1 missed malware | Stage 2 checked | Malware recovered by Pi | Final missed malware | Final false alarms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `ID:01` local CSV, partial SD payload | 3,798 | 0.9908 | 6 | 65 | 3 | 3 | 35 |

Key engineering result: bulk `.bin` transfer over RS485 should be avoided for large experiments. The better experimental path is direct SD-card sample preparation, ESP32-local Stage 1 inference, compact CSV evidence transfer, and Pi Stage 2 only on uncertain rows.

Evidence:

- [20260523_vibex50_esp32_local_csv_stage12_experiment.md](metrics/20260523_vibex50_esp32_local_csv_stage12_experiment.md)

## MV2025 Historical Reference

MV2025 is now archived history, but a few results remain useful context:

- Best ESP32-safe Stage 1 model: `m3595_full_8_32_48`.
- Workhorse full-test balanced accuracy: `90.54%`.
- Workhorse missed malware at the selected safety gate: `0 / 1,795`.
- Physical dual-node random-50/100-sample feasibility runs showed zero missed malware in the recorded small runs, with benign false alarms reduced by Pi-side Stage 1.5 checks.
- RS485 evidence transfer reached `100 / 100` transfers and `100%` hash-match rate in the cited feasibility run.

Use the archive only when writing historical context or comparing the old prefix-feature ESP32 gate with the current VIBEX image-dataset work:

- [archive/mv2025/README.md](archive/mv2025/README.md)
- [archive/mv2025/022_MV2025_RESULTS_DOCUMENT.md](archive/mv2025/022_MV2025_RESULTS_DOCUMENT.md)

## Next Evidence To Add

- Completed VirusTotal/AVClass or AVClass2 consensus family-label counts for the released malware rows.
- Source-grouped and family-enriched evaluation tables.
- Stronger Linux/ELF release once enough ELF malware and benign executable samples are available.
- Hardware-grounded VIBEX deployment metrics that clearly separate image-dataset evaluation from ESP32 prefix-feature experiments.
