# VIBEX Build

This is the quick build entry point. The full secure protocol is [024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md](024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md).

## Security Boundary

Raw malware stays on the workhorse only:

```text
/home/phil/vibex_secure_dataset/raw/malware_quarantine
```

Git may contain documentation, scripts, manifests, hashes, and derived evidence. Git must not contain raw malware binaries, password-protected malware archives, API keys, Vault tokens, Kaggle keys, VirusTotal keys, Telegram bot tokens, database passwords, or browser session material.

## Workhorse Layout

```text
/home/phil/vibex_secure_dataset
  raw/
    malware_quarantine/
    benign_sources/
    iso/
  derived/
    images/
    manifests/
    datasets/
  release/
    VIBEX-50K/
  evidence/
```

## Conversion Rule

Locked release conversion:

```text
first_1048576_bytes_uint8_grayscale_pad_00_truncate_to_1024x1024
```

Each source file is read as bytes, padded or truncated to `1,048,576` bytes, reshaped to `1024x1024`, and saved as an unsigned 8-bit grayscale PNG.

## Core Scripts

| Script | Purpose |
| --- | --- |
| `src/ml_pipeline/vibex_dataset_builder.py` | Initialise vaults, download/extract source material, scan raw files, convert PNGs, freeze splits |
| `src/ml_pipeline/vibex_make_50k_release.py` | Build the combined `VIBEX-50K` public release |
| `src/ml_pipeline/vibex_train_binary_image.py` | Train/evaluate binary image baselines |
| `src/ml_pipeline/vibex_family_labels.py` | Export hashes, import/derive family labels, build family-enriched manifests |
| `src/ml_pipeline/vibex_clamav_avclass_log.py` | Preserve AV/family labelling evidence |
| `src/ml_pipeline/vibex_yara_family_label.py` | YARA-assisted family labelling experiments |

## Common Commands

Initialize the secure vault:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py init
```

Scan raw sources:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py scan-raw
```

Convert raw executable files to PNG images:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py convert-png \
  --raw-manifest /home/phil/vibex_secure_dataset/derived/manifests/raw_manifest_TIMESTAMP.csv
```

Freeze a Windows PE component when needed:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py freeze-split \
  --profile windows-pe \
  --dataset-name windows-pe-component \
  --image-manifest /home/phil/vibex_secure_dataset/derived/manifests/image_manifest_TIMESTAMP.csv \
  --target-total 50000
```

Freeze a Linux ELF component when needed:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py freeze-split \
  --profile linux-elf \
  --dataset-name linux-elf-component \
  --image-manifest /home/phil/vibex_secure_dataset/derived/manifests/image_manifest_TIMESTAMP.csv \
  --target-total 50000
```

Train a binary-image baseline:

```bash
python3 src/ml_pipeline/vibex_train_binary_image.py --help
```

Export malware hashes for family labelling:

```bash
python3 src/ml_pipeline/vibex_family_labels.py export-malware-hashes --help
```

## Release Checklist

Before a public release:

- Confirm raw malware is absent from the release tree.
- Confirm all PNGs are derived artifacts.
- Include source hash evidence.
- Include safe dataset manifest and split files.
- Include construction protocol and release README.
- Include scripts needed to reproduce manifest, conversion, and split decisions.
- Include counts by split, class, source, and file kind.
- Record missing or limiting classes honestly.

## Family Labels

The binary labels are the primary release labels. Malware-family labels are optional enrichment.

Preferred path:

1. Export SHA-256 hashes for released malware rows.
2. Query VirusTotal by hash only; do not upload files.
3. Run AVClass or AVClass2-style consensus labelling.
4. Import `sha256 -> family` labels.
5. Generate a family-labelled manifest and family count report.

See [025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md](025_VIBEX_MALWARE_FAMILY_LABELING_PROTOCOL.md).
