# VIBEX-50K Bias Audit And Stage 2 Pivot - 2026-05-20

## Purpose

This note locks the evidence that caused the Stage 2 plan to change from broad malware-family model search to dataset-bias measurement and binary cascade optimisation.

The frozen dataset manifest is:

```text
/home/phil/vibex_secure_dataset/release/VIBEX-50K/manifests/safe_dataset_manifest_VIBEX-50K_20260518T081144Z.csv
```

## Current Stage 1 Evidence

The strongest overnight Stage 1 ESP32 candidate from the reduced search was:

```text
s1night_m0173_prefix1024_w96_d15_lr0.0006_wd0.0002_e6
```

Observed offline metrics:

| Metric | Value |
| --- | ---: |
| Missed malware | 13 |
| Benign false alarms | 97 |
| Balanced accuracy | 0.989487 |
| Macro F1 | 0.988881 |
| ROC AUC | 0.999440 |
| TFLite size | 414,592 bytes |

This remains offline evidence only until promoted through physical ESP32 smoke testing.

## Binary Stage 2 Evidence

The first binary Stage 2 test used no malware-family labels, only `benign` vs `malware`.

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_stage2_binary_two_models/stage2_binary_two_models_20260520
```

| Model | Balanced accuracy | Macro F1 | ROC AUC | Benign wrong | Malware wrong |
| --- | ---: | ---: | ---: | ---: | ---: |
| 3-layer CNN | 0.8534 | 0.8525 | 0.9201 | 175 | 558 |
| EfficientNetB0 | 0.9092 | 0.9092 | 0.9660 | 214 | 240 |

Interpretation: binary Stage 2 is much stronger than the previous malware-family framing, but the default EfficientNetB0 threshold still misses too many malware samples to be used as a safety gate.

## No/Few-Benign Evidence

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_stage2_binary_imbalance/stage2_binary_imbalance_20260520
```

| Model | Balanced accuracy | Macro F1 | Benign wrong | Malware wrong | Interpretation |
| --- | ---: | ---: | ---: | ---: | --- |
| Malware-only centroid | 0.4740 | 0.3292 | 1486 | 92 | Collapses toward all-malware |
| Tiny few-benign CNN | 0.6577 | 0.6512 | 309 | 718 | Too many malware misses |
| EfficientNetB0 few-benign | 0.5000 | 0.3333 | 800 | 0 | All-malware collapse |

Interpretation: removing benign does not solve Stage 2. It mostly changes the error mode.

## Malware Embedding Clustering

EfficientNetB0 malware-only embeddings were clustered with HDBSCAN as an exploratory check.

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_malware_embedding_clusters/malware_embedding_hdbscan_20260520_r2
```

Results:

| Metric | Value |
| --- | ---: |
| Malware samples | 8,000 |
| Embedding width | 1,280 |
| Clusters excluding noise | 25 |
| Clustered samples | 4,014 |
| Noise samples | 3,986 |
| Clustered-only silhouette | 0.6269 |
| PCA-50 variance retained | 0.9955 |

Interpretation: the embedding space is not random. It contains visible structure, but current labels do not prove these are malware families. They are CNN-discovered structural groups until validated by stronger labels.

## Risk Being Tested Next

The major threat to validity is provenance bias:

- Benign rows are largely coherent Windows ISO/install-image derived files.
- Malware rows are VirusShare-derived and likely mix many toolchains, packers, ages, and collection artefacts.
- A model may therefore learn source/provenance differences rather than general malware semantics.

The next implementation step is therefore:

1. Audit metadata and image-stat shortcut risk.
2. Build a PE-only matched split by raw-size decile.
3. Rerun binary Stage 2 on the matched split.
4. Evaluate Stage 1 plus binary Stage 2 as a validation-selected cascade under 1%, 2%, and 5% benign false-positive caps.

## Implemented Next-Step Results

### Dataset Bias Audit

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_bias_audit/bias_audit_20260520
```

Metadata-only shortcut baseline, excluding `source` as a feature:

| Feature set | Test AUC | Balanced accuracy | Benign wrong | Malware wrong |
| --- | ---: | ---: | ---: | ---: |
| Manifest metadata: log raw size, image dimensions, file kind | 0.7319 | 0.6461 | 1,837 | 1,694 |
| Manifest metadata plus image stats and raw entropy sample | 0.8345 | 0.7704 | 412 | 736 |

Interpretation: there is measurable non-label shortcut signal. It is not enough to explain all model performance, but it is strong enough that random split results should be treated as optimistic.

### Matched PE-Only Split

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_matched_splits/matched_pe_20260520
```

The matched split keeps PE files only and undersamples benign/malware inside each split and log-size decile bucket.

| Split | Benign | Malware |
| --- | ---: | ---: |
| Train | 13,025 | 13,025 |
| Test | 3,295 | 3,295 |

Checks:

- Selected buckets: `20 / 20`
- Train/test raw SHA overlap: `0`
- Matched rows: `32,640`

### Matched Binary Stage 2 Rerun

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_stage2_binary_matched/matched_binary_20260520
```

| Model | Balanced accuracy | Macro F1 | ROC AUC | Benign wrong | Malware wrong |
| --- | ---: | ---: | ---: | ---: | ---: |
| 3-layer CNN | 0.8390 | 0.8381 | 0.9285 | 283 | 778 |
| EfficientNetB0 | 0.8618 | 0.8617 | 0.9226 | 420 | 491 |

Interpretation: matched-split performance is materially lower than the original random binary split. This supports the provenance-bias concern and argues against more broad Stage 2 architecture search until dataset composition is improved.

### Stage 1 + Stage 2 Cascade Sweep

Artifacts:

```text
/home/phil/vibex_secure_dataset/models/vibex50_stage2_cascade/cascade_matched_20260520
```

Matched test baseline:

| Policy | Malware wrong | Benign wrong | Balanced accuracy | Stage 2 review rate |
| --- | ---: | ---: | ---: | ---: |
| Stage 1 only, threshold 0.145 | 9 | 75 | 0.9873 | 0.0000 |
| Stage 2 only, threshold 0.500 | 491 | 420 | 0.8618 | 1.0000 |

Validation-selected cascade policies:

| Policy | Cap | Cap met on validation | Malware wrong | Benign wrong | Balanced accuracy | Stage 2 review rate |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| OR gate | 1% | No | 7 | 102 | 0.9835 | 1.0000 |
| OR gate | 2% | Yes | 7 | 102 | 0.9835 | 1.0000 |
| OR gate | 5% | Yes | 7 | 102 | 0.9835 | 1.0000 |
| Uncertainty band | 1% | Yes | 16 | 46 | 0.9906 | 0.0044 |
| Uncertainty band | 2% | Yes | 16 | 46 | 0.9906 | 0.0044 |
| Uncertainty band | 5% | Yes | 16 | 46 | 0.9906 | 0.0044 |

Interpretation: the current binary Stage 2 model does not yet justify deployment as a selective cascade. The OR gate can reduce matched-test malware misses from `9` to `7`, but it requires Stage 2 on every sample and increases benign false alarms. The uncertainty-band policy is operationally cheap but misses more malware than Stage 1 alone.

Current recommendation: improve the dataset before more Stage 2 modelling. Add broader benign provenance and additional malware sources, then repeat the matched audit and cascade sweep.
