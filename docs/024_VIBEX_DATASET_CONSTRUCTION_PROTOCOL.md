# VIBEX Dataset Construction Protocol

Date: 2026-05-18

Purpose: build thesis-grade, reproducible binary-image datasets. The public release is `VIBEX-50K`, built from Windows PE/MZ and Linux ELF executable-image components. Raw binaries stay isolated on the workhorse. The public working dataset consists of PNG derivatives, manifests, hashes, split files, and evidence logs.

## Current Access Check

Workhorse:

- Host: `phil@10.0.0.100 -p 717`
- Hostname: `ps3460-desktop`
- Free space under `/home`: about `577G`
- Python: available at `/usr/bin/python3`
- `curl`: available
- Python packages checked: `Pillow 10.2.0`, `numpy 1.26.4`
- Missing optional package: `pefile`

Secure vault created:

- `/home/phil/vibex_secure_dataset`
- Permissions: `700`
- Raw malware area: `/home/phil/vibex_secure_dataset/raw/malware_quarantine`
- Benign source area: `/home/phil/vibex_secure_dataset/raw/benign_sources`
- ISO area: `/home/phil/vibex_secure_dataset/raw/iso`
- Derived safe image area: `/home/phil/vibex_secure_dataset/derived/images`
- Manifest area: `/home/phil/vibex_secure_dataset/derived/manifests`
- Evidence area: `/home/phil/vibex_secure_dataset/evidence`

Source access:

- Ubuntu 26.04 SHA256SUMS: downloaded to workhorse and hashed.
- Ubuntu 26.04 Desktop ISO: downloaded to workhorse and hashed.
- Ubuntu 26.04 Live Server ISO: downloaded to workhorse and hashed.
- Microsoft Windows 11 page: official landing page returns `403` to workhorse `curl`, but a browser-generated official direct ISO link was provided and downloaded successfully.
- Microsoft Windows Server 2025 Evaluation page: official landing page returns `403` to workhorse `curl`, but the official Eval Center `fwlink` was provided and downloaded successfully.
- VirusShare is selected as the current malware repository. Account credentials are stored only in the workhorse secure vault secret file, not in Git or documentation.
- Kaggle API access for the VIBEX public release is an operational credential. Do not copy the key into Git, Markdown, Telegram, shell logs, notebooks, dashboard output, or the Kaggle release.

Windows ISO action required: use an interactive browser against Microsoft's official pages, or provide official time-limited direct ISO URLs captured from Microsoft. Do not use unofficial mirrors.

Malware source action required: VirusShare API downloads require an API key. If the web account does not expose one automatically, add `VIRUSSHARE_APIKEY` to `/home/phil/vibex_secure_dataset/secrets/virusshare.env` with file mode `600`.

Kaggle upload action: any script that uploads `VIBEX-50K` should read the Kaggle credential from the private secret store, materialise it only into a temporary `0600` runtime file or environment variable, and delete that runtime material after upload.

## Dataset Target

The current public release is:

- `VIBEX-50K`: combined executable-image release with exactly `50,000` samples.

Supporting source components inside `VIBEX-50K` are:

- `Windows PE component`: Windows PE/MZ malware and Windows PE/MZ benign executables.
- `Linux ELF component`: Linux ELF malware and Linux ELF benign executables.

Target corpus:

- `50,000` total binary-derived PNG samples for the public release.
- Preferred split: as balanced as legally accessible source volume allows.
- Preferred image size: `1024x1024` grayscale PNG.
- Train/test split: deterministic, default `80/20`, seed `20260517`.

The final class balance depends on legally accessible source volume. If either class is short, the builder freezes the largest defensible release and records the shortfall.

Current release sizes from the 2026-05-18 freeze:

| Dataset or component | Release total | Benign | Malware | Train | Test | Limiting class |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `VIBEX-50K` | 50,000 | 26,814 | 23,186 | 40,000 | 10,000 | combined release plus Windows PE benign fill |
| Windows PE component | 46,046 | 23,023 | 23,023 | 36,836 | 9,210 | available malware PE/MZ samples |
| Linux ELF component | 326 | 163 | 163 | 260 | 66 | available malware ELF samples |

`VIBEX-50K` is the only current public dataset name. The Windows PE and Linux ELF rows above are internal components, not separate public release promises.

## Security Position

PNG files are safer ML derivatives because they are non-executable image encodings of bytes. They are not a substitute for raw-sample controls. Raw malware remains hazardous and must stay in the quarantine vault.

Rules:

- Never execute raw samples.
- Never add raw malware to Git.
- Publish only manifests, hashes, conversion scripts, split files, metrics, and derived non-executable artifacts where licensing allows.
- Keep raw files under `raw/malware_quarantine` with owner-only permissions.

## Conversion Rule

The initial fixed rule is:

`first_1048576_bytes_uint8_grayscale_pad_00_truncate_to_1024x1024`

This means:

- Read the first `1,048,576` bytes from the raw file.
- If the file is shorter, right-pad with `0x00`.
- If the file is longer, truncate to the first `1,048,576` bytes.
- Reshape to `1024x1024`.
- Save as grayscale PNG.

This rule is intentionally simple, deterministic, and easy to defend. It should be kept fixed for any locked experiment. Alternative full-file resizing can be tested only as an ablation.

## Builder

Script:

- `src/ml_pipeline/vibex_dataset_builder.py`

Initialize the vault:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py init
```

Download Ubuntu 26.04 official ISO evidence:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py download-ubuntu-2604
```

Extract an ISO, WIM, squashfs, ZIP, or other `7z`-supported archive into the raw source tree:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py extract-archive --archive /home/phil/vibex_secure_dataset/raw/iso/ubuntu_26.04/ubuntu-26.04-desktop-amd64.iso --label benign --source ubuntu_26.04_desktop_iso
```

For Windows ISOs, extract the ISO first, then extract the nested `sources/install.wim` or `sources/install.esd` using the same command with a more specific source name such as `windows_11_install_wim`.

For Ubuntu ISOs, extract the ISO first, then extract the nested squashfs image under the extracted `casper/` directory if the first pass only exposes the live filesystem container.

Download URL-listed sources:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py download-urls --source-csv configs/vibex_dataset_sources.example.csv
```

For authenticated sources, set:

```bash
export VIBEX_DOWNLOAD_AUTH_HEADER='Authorization: Bearer REPLACE_ME'
```

Download VirusShare malware by hash list:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py virusshare-download --hashes configs/vibex_virusshare_hashes.example.csv --extract
```

VirusShare API evidence rules:

- `/apiv2/quick` is checked before each download.
- Only response `1` is treated as confirmed malware/detected and eligible for download.
- `/apiv2/download` returns a password-protected ZIP.
- ZIP extraction uses the standard malware-sharing password `infected`.
- Downloaded ZIPs and extracted files stay under `raw/malware_quarantine/virusshare`.
- Each ZIP hash, extracted root, quick response, and status is recorded in `evidence/virusshare_download_log_*.csv`.

Scan raw files and hash everything:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py scan-raw
```

Convert raw files to `1024x1024` PNGs:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py convert-png --raw-manifest /home/phil/vibex_secure_dataset/derived/manifests/raw_manifest_TIMESTAMP.csv
```

Build the Windows PE/MZ image manifest:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py convert-png \
  --profile windows-pe \
  --raw-manifest /home/phil/vibex_secure_dataset/derived/manifests/raw_manifest_TIMESTAMP.csv
```

Build the Linux ELF image manifest:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py convert-png \
  --profile linux-elf \
  --raw-manifest /home/phil/vibex_secure_dataset/derived/manifests/raw_manifest_TIMESTAMP.csv
```

Freeze the balanced Windows PE component when needed:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py freeze-split \
  --profile windows-pe \
  --dataset-name windows-pe-component \
  --image-manifest /home/phil/vibex_secure_dataset/derived/manifests/image_manifest_TIMESTAMP.csv \
  --target-total 50000
```

Freeze the balanced Linux ELF component when needed:

```bash
python3 src/ml_pipeline/vibex_dataset_builder.py freeze-split \
  --profile linux-elf \
  --dataset-name linux-elf-component \
  --image-manifest /home/phil/vibex_secure_dataset/derived/manifests/image_manifest_TIMESTAMP.csv \
  --target-total 50000
```

## Dataset Selection Rules

The builder records both selected and excluded rows in the image manifest.

`Windows PE component` selection:

- Malware: `file_kind` is `pe` or `mz`.
- Benign: source begins with `microsoft_windows` or `windows_`, and `file_kind` is `pe` or `mz`.
- Excluded: ELF files, archives, ISO containers, text/configuration files, images, and unknown non-executable resources.

`Linux ELF component` selection:

- Malware: `file_kind` is `elf`.
- Benign: source begins with `ubuntu_`, `debian_`, `fedora_`, `rocky_`, `alma_`, or `linux_`, and `file_kind` is `elf`.
- Excluded: PE/MZ files, archives, ISO containers, text/configuration files, images, and unknown non-executable resources.

Class-label policy:

- The public release is organised as binary malware-versus-benign classification.
- Folder names are `train/benign`, `train/malware`, `test/benign`, and `test/malware`.
- The manifest preserves source and sample-identifier fields for provenance.
- This release must not be presented as malware-family classification until a separate AVClass or equivalent consensus-label pipeline is run and documented.

## Evidence To Preserve

For every raw file:

- SHA-256
- file size
- source
- collection date/time
- source URL or source category
- binary label
- family label if available
- file kind: PE, ELF, ISO, archive, unknown

For every PNG:

- source raw SHA-256
- image SHA-256
- conversion rule
- image width/height
- generated path
- generation date/time

For the final dataset:

- train/test split
- random seed
- class counts
- family counts
- excluded sample counts and reasons
- script hash
- OS ISO hashes and official source URLs

## Benign Data Policy

Windows benign PE files should be reported separately from Linux ELF files. Mixing Linux benign ELF files with Windows malware PE files can create an artificial shortcut where the model learns operating-system format rather than maliciousness.

Recommended benign reporting:

- Windows ISO PE-only benign subset.
- Windows Server ISO PE-only benign subset.
- Third-party Windows vendor PE benign subset.
- Ubuntu ELF benign subset as a separate cross-platform robustness experiment, not as the main Windows malware benchmark.

## Validation Questions For The Thesis

The dataset is defensible only if these questions can be answered from evidence logs:

- Which exact raw samples were used?
- What labels were assigned, and by what method?
- Which samples were excluded?
- Which exact script and conversion rule produced each image?
- Can another researcher reconstruct the dataset from hashes and source instructions?
- Are benign and malware sources comparable enough to avoid shortcut learning?
- How much of the malware set is packed or high entropy?
