# VIBEX Split Dataset Pipeline Evidence - 2026-05-17

## Decision

This note originally recorded a split-dataset build path. That naming has now been retired. The durable result is the `VIBEX-50K` release plus two internal source components:

- Windows PE component: Windows executable images.
- Linux ELF component: Linux executable images.

`VIBEX` means:

- `VI`: verified image.
- `B`: binary.
- `EX`: executable.
- `50K`: current public release scale.

The previous working dataset name is not used in the public release material.

## Workhorse State

Host: `ps3460-desktop` via SSH on port `717`.

Health snapshot before starting the pipeline:

- Load average: approximately `1.15, 1.27, 1.46`.
- RAM: `31 GiB` total, `28 GiB` available.
- Swap: `8 GiB` total, `283 MiB` used.
- `/home`: `915 GiB` total, `524 GiB` available, `40%` used.
- `/`: `229 GiB` total, `110 GiB` available, `50%` used.
- Thermal zones: approximately `27.8 C`, `47 C`, `35 C`, `40 C`.
- NVIDIA GPU: `36 C`, `0%` utilisation, `212 MiB / 8192 MiB` used.

## Secure Vault

Canonical vault path:

```text
/home/phil/vibex_secure_dataset
```

Historical component working directories:

```text
/home/phil/vibex_secure_dataset/derived/datasets/windows-pe-component
/home/phil/vibex_secure_dataset/derived/datasets/linux-elf-component
```

Public release directory:

```text
/home/phil/vibex_secure_dataset/release/VIBEX-50K
```

## Source Evidence

VirusShare source:

```text
/home/phil/vibex_secure_dataset/raw/malware_quarantine/virusshare/latest/download/VirusShare_00499.zip
```

VirusShare archive SHA-256:

```text
9ed34cd38abba38a16dd5bedf005eb8f0168141c95d99eba0c827c1d95d5cc85
```

Windows 11 ISO SHA-256:

```text
66b7b4b71763ed6f9b2ce29326ed9284544da6f5283d00329921540c01aaaeea
```

Windows Server ISO SHA-256:

```text
7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51
```

Ubuntu SHA256SUMS SHA-256:

```text
aae27c60591cec02a3d6c078c527c03aae75087428d403a98e3373febc08df4c
```

Ubuntu desktop ISO SHA-256:

```text
487f87faaf547ea30e0aba4d5b53346292571256b25333a978db1692bcee9dd2
```

Ubuntu live-server ISO SHA-256:

```text
dec49008a71f6098d0bcfc822021f4d042d5f2db279e4d75bdd981304f1ca5d9
```

## Selection Rules

`Windows PE component` includes:

- Malware candidates detected as PE/MZ executable binaries.
- Benign candidates from Microsoft Windows sources detected as PE/MZ executable binaries.

`Linux ELF component` includes:

- Malware candidates detected as ELF executable binaries.
- Benign candidates from Linux ISO sources detected as ELF executable binaries.

Rows excluded by a profile are recorded with an exclusion reason before the final split is frozen.

## Pipeline Run

Pipeline script on workhorse:

```text
/home/phil/vibex_secure_dataset/tools/vibex_workhorse_pipeline.sh
```

Dataset builder on workhorse:

```text
/home/phil/vibex_secure_dataset/tools/vibex_dataset_builder.py
```

Pipeline state file:

```text
/home/phil/vibex_secure_dataset/evidence/vibex_pipeline_state.json
```

Pipeline PID:

```text
938687
```

Initial observed pipeline state:

```json
{
  "status": "running",
  "step": "extract Windows 11 ISO",
  "log": "/home/phil/vibex_secure_dataset/evidence/vibex_pipeline_20260517T175515Z.log",
  "updated_at_utc": "2026-05-17T18:03:06.126408+00:00"
}
```

Completed steps observed:

- `extract VirusShare_00499 malware shard`
- `extract Windows 11 ISO`
- `extract Windows Server evaluation ISO`
- `extract Windows 11 install.wim`
- `extract Windows Server install.wim`
- `extract Ubuntu desktop ISO`
- `extract Ubuntu live-server ISO`
- `extract Ubuntu desktop squashfs`
- `extract Ubuntu live-server squashfs`

Recovery note:

- The first `extract Ubuntu live-server squashfs` attempt failed because `7z` returned code `2` after refusing dangerous absolute or escaping symlink/link paths inside the SquashFS.
- The archive was not treated as corrupt; `7z` extracted normal files and ignored unsafe link targets.
- The builder was updated to record this specific SquashFS condition as `ok_with_ignored_links` with `accepted_warning=True`.
- The resumed run moved on to `scan and hash raw files`.

Telegram monitor:

```text
/usr/local/bin/vibex_pipeline_telegram_monitor.py --interval 300
```

Current monitor process observed in LXC `124` (`Vibex-100K-runner`):

```text
13514 python3 /usr/local/bin/vibex_pipeline_telegram_monitor.py --interval 300 --initial-periodic-minutes 30
```

Telegram update policy:

- Send scheduled status updates every `5` minutes for the first `30` minutes after the updated monitor starts.
- After the first `30` minutes, send only milestone, completion, or failure updates.
- Include line-broken dataset stats in every update: malware file count, Windows source file counts, Ubuntu source file counts, generated PNG counts, frozen dataset PNG counts, manifest count, raw/derived sizes, disk free, and RAM available.
- Large tree counts are bounded to `8` seconds per source so Telegram updates do not stall behind a full Windows filesystem walk.

## Completion And Release Freeze

The pipeline completed on 2026-05-17 at `23:01 BST`.

Final pipeline state:

```json
{
  "status": "completed",
  "step": "pipeline_complete",
  "log": "/home/phil/vibex_secure_dataset/evidence/vibex_pipeline_20260517T190008Z.log",
  "updated_at_utc": "2026-05-17T22:01:29.124242+00:00"
}
```

The release freeze was regenerated on 2026-05-18 so the final manifests and folder trees match exactly.

Regenerated release datasets:

| Dataset | Release root | Release PNGs | Benign | Malware | Train benign | Train malware | Test benign | Test malware |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VIBEX-50K` | `/home/phil/vibex_secure_dataset/release/VIBEX-50K/data` | 50,000 | 26,814 | 23,186 | 21,452 | 18,548 | 5,362 | 4,638 |
| Windows PE component | `/home/phil/vibex_secure_dataset/derived/datasets/windows-pe-component/dataset_1024_png_seed20260517_46046` | 46,046 | 23,023 | 23,023 | 18,418 | 18,418 | 4,605 | 4,605 |
| Linux ELF component | `/home/phil/vibex_secure_dataset/derived/datasets/linux-elf-component/dataset_1024_png_seed20260517_326` | 326 | 163 | 163 | 130 | 130 | 33 | 33 |

`VIBEX-50K` combines `Windows PE component`, `Linux ELF component`, and `3,628` additional Windows PE benign samples from the same Microsoft source evidence. It has exactly `50,000` PNG files and exactly `50,000` manifest rows. It is not exactly class-balanced: `26,814` benign and `23,186` malware.

Regenerated evidence files:

```text
/home/phil/vibex_secure_dataset/evidence/dataset_counts_windows-pe-component_20260518T065555Z.csv
/home/phil/vibex_secure_dataset/evidence/dataset_counts_linux-elf-component_20260518T065607Z.csv
/home/phil/vibex_secure_dataset/derived/manifests/safe_dataset_manifest_20260518T065555Z.csv
/home/phil/vibex_secure_dataset/derived/manifests/safe_dataset_manifest_20260518T065607Z.csv
/home/phil/vibex_secure_dataset/release/VIBEX-50K/evidence/dataset_counts_VIBEX-50K_20260518T081144Z.csv
/home/phil/vibex_secure_dataset/release/VIBEX-50K/manifests/safe_dataset_manifest_VIBEX-50K_20260518T081144Z.csv
```

Manifest validation after regeneration:

- `Windows PE component`: `46,046` manifest rows and `46,046` PNG files in the release tree.
- `Linux ELF component`: `326` manifest rows and `326` PNG files in the release tree.
- `VIBEX-50K`: `50,000` manifest rows, `50,000` PNG files, `50,000` unique raw SHA-256 values, and `50,000` unique image SHA-256 values.

Research interpretation:

- The public release should now be reported as `VIBEX-50K`.
- The Windows PE and Linux ELF rows are internal source components only.
- The combined release reaches exactly `50,000` samples by adding Windows PE benign samples; class balance must be reported honestly.

## QEMU Completion Smoke Test

Because the pipeline completed before the requested morning checkpoint, the Proxmox host ran a QEMU smoke test.

Evidence file:

```text
/home/phil/vibex_secure_dataset/evidence/vibex_qemu_smoke_20260517T220138Z.txt
```

Result:

- ISO: `/tank/subvol-105-disk-0/ISO/ubuntu-26.04-live-server-amd64.iso`
- ISO SHA-256: `dec49008a71f6098d0bcfc822021f4d042d5f2db279e4d75bdd981304f1ca5d9`
- QEMU: `QEMU emulator version 10.1.2 (pve-qemu-kvm_10.1.2-7)`
- Duration: `123` seconds.
- Exit code: `124`, expected from the controlled `timeout 120s` wrapper.
- Result: `passed_alive_until_timeout`.

## Proxmox LXC Naming

Research-specific LXCs were renamed and tagged on 2026-05-17:

| VMID | Previous name | Current name | Tags added |
| ---: | --- | --- | --- |
| `102` | `Malware-Reportor-01` | `Vibex-100K-dashboard` | `vibex-100k`, `research`, `role-dashboard` |
| `124` | `malware-hourly-runner` | `Vibex-100K-runner` | `vibex-100k`, `research`, `role-runner`, `telegram-monitor` |

Shared dependency LXCs were deliberately not renamed or retagged:

- `115` MariaDB.
- `125` Vault.
