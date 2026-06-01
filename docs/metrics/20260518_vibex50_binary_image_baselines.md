# VIBEX-50K Binary Image Baselines - 2026-05-18

## Purpose

This note records the first malware-vs-benign image baselines for `VIBEX-50K`.

The experiments use the frozen `VIBEX-50K` manifest:

```text
/home/phil/vibex_secure_dataset/release/VIBEX-50K/manifests/safe_dataset_manifest_VIBEX-50K_20260518T081144Z.csv
```

Training script:

```text
/home/phil/vibex_secure_dataset/tools/vibex_train_binary_image.py
```

Repository source:

```text
src/ml_pipeline/vibex_train_binary_image.py
```

## Model

The baseline model is a small grayscale CNN trained on resized `224 x 224` PNG images.

Common run settings:

- Epochs: `6`
- Batch size: `64`
- Optimizer: `AdamW`
- Loss: `BCEWithLogitsLoss`
- Class weighting: positive malware weight derived from the active training split
- Device: `cuda`
- Seed: `20260518`

## Random Split Baseline

Run:

```text
vibex50_binary_baseline_20260518T094845Z
```

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_binary/vibex50_binary_baseline_20260518T094845Z
```

Rows:

| Split | Benign | Malware |
| --- | ---: | ---: |
| Train | 18,235 | 15,766 |
| Validation | 3,217 | 2,782 |
| Test | 5,362 | 4,638 |

Test metrics:

| Metric | Value |
| --- | ---: |
| Accuracy | 0.9448 |
| Balanced accuracy | 0.9439 |
| Macro F1 | 0.9444 |
| ROC AUC | 0.9860 |

Confusion matrix:

| True class | Predicted benign | Predicted malware |
| --- | ---: | ---: |
| Benign | 5,130 | 232 |
| Malware | 320 | 4,318 |

Largest group checks:

| Group | Count | Recall for true label |
| --- | ---: | ---: |
| Malware PE, VirusShare 00499 | 4,597 | 0.9326 |
| Benign PE, Windows 11 install WIM | 3,199 | 0.9572 |
| Benign PE, Windows Server install WIM | 1,315 | 0.9597 |

## Windows Server Benign Source Holdout

This run excludes all benign rows from `microsoft_windows_server_2025_eval_install_wim` during training and validation. The held-out Server benign rows are then evaluated with the manifest malware test rows.

Run:

```text
vibex50_binary_holdout_windows_server_install_wim_20260518T0958Z
```

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_binary/vibex50_binary_holdout_windows_server_install_wim_20260518T0958Z
```

Rows:

| Split | Benign | Malware |
| --- | ---: | ---: |
| Train | 13,238 | 15,766 |
| Validation | 2,335 | 2,782 |
| Test | 7,411 | 4,638 |

Test metrics:

| Metric | Value |
| --- | ---: |
| Accuracy | 0.9099 |
| Balanced accuracy | 0.9116 |
| Macro F1 | 0.9060 |
| ROC AUC | 0.9672 |

Confusion matrix:

| True class | Predicted benign | Predicted malware |
| --- | ---: | ---: |
| Benign | 6,699 | 712 |
| Malware | 374 | 4,264 |

Largest group checks:

| Group | Count | Recall for true label |
| --- | ---: | ---: |
| Held-out Server PE benign, Windows PE component | 6,409 | 0.9059 |
| Held-out Server PE benign, extra Windows benign component | 1,001 | 0.8911 |
| Malware PE, VirusShare 00499 | 4,597 | 0.9204 |

## Windows 11 Benign Source Holdout

This run excludes all benign rows from `microsoft_windows_11_25h2_install_wim` during training and validation. The held-out Windows 11 benign rows are then evaluated with the manifest malware test rows.

Run:

```text
vibex50_binary_holdout_windows11_install_wim_20260518T1012Z
```

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_binary/vibex50_binary_holdout_windows11_install_wim_20260518T1012Z
```

Rows:

| Split | Benign | Malware |
| --- | ---: | ---: |
| Train | 5,394 | 15,766 |
| Validation | 951 | 2,782 |
| Test | 18,833 | 4,638 |

Test metrics:

| Metric | Value |
| --- | ---: |
| Accuracy | 0.9175 |
| Balanced accuracy | 0.9199 |
| Macro F1 | 0.8813 |
| ROC AUC | 0.9733 |

Confusion matrix:

| True class | Predicted benign | Predicted malware |
| --- | ---: | ---: |
| Benign | 17,250 | 1,583 |
| Malware | 353 | 4,285 |

Largest group checks:

| Group | Count | Recall for true label |
| --- | ---: | ---: |
| Held-out Windows 11 PE benign, Windows PE component | 16,096 | 0.9162 |
| Held-out Windows 11 PE benign, extra Windows benign component | 2,544 | 0.9245 |
| Malware PE, VirusShare 00499 | 4,597 | 0.9247 |

## Interpretation

The random split baseline reaches `0.9439` balanced accuracy. The source-holdout runs drop to `0.9116` and `0.9199` balanced accuracy.

This is a useful result. The model does not collapse when a major benign provenance group is withheld, which suggests it is learning transferable binary-image signal. The drop is also large enough to show that random split performance is optimistic and that source/provenance shift must be reported as a separate benchmark.

Benign rows should therefore keep a provenance grouping field such as `source` or `benign_source_group`. These are not malware families. They are audit and evaluation labels used for stratification, held-out tests, and shortcut-learning checks.

Linux/ELF results remain underpowered because the ELF groups are very small in `VIBEX-50K`. They should not be used for strong claims until the Linux ELF component contains a much larger and more balanced sample set.
