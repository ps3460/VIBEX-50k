# Metrics

This folder contains current VIBEX evidence notes. Archived MV2025 and older MalwareVision notes have been moved to [../archive/mv2025/metrics/](../archive/mv2025/metrics/).

## Current VIBEX Evidence

- [20260517_vibex_split_dataset_pipeline.md](20260517_vibex_split_dataset_pipeline.md): secure workhorse build, source hashes, release freeze counts, and pipeline evidence for `VIBEX-50K`, `Windows PE component`, and `Linux ELF component`.
- [20260518_vibex50_binary_image_baselines.md](20260518_vibex50_binary_image_baselines.md): first binary-image CNN baselines, random split result, Windows Server holdout, and Windows 11 holdout.
- [20260522_vibex50_virustotal_family_campaign.md](20260522_vibex50_virustotal_family_campaign.md): 11-day VirusTotal family-verification campaign setup, frozen inputs, SQL tables, Telegram schedule, dashboard/API evidence, and malware-only queue verification.
- [20260523_vibex50_esp32_local_csv_stage12_experiment.md](20260523_vibex50_esp32_local_csv_stage12_experiment.md): learning-stage ESP32-local Stage 1 CSV experiment, Pi Stage 2 uncertain-only cascade results, and RS485 transfer-speed evidence.

## Current Summary

| Evidence | Key result |
| --- | --- |
| `VIBEX-50K` release | 50,000 PNGs: 26,814 benign, 23,186 malware |
| Windows PE component | 46,046 PNGs: 23,023 benign, 23,023 malware |
| Linux ELF component | 326 PNGs: 163 benign, 163 malware |
| Random split CNN | 0.9439 balanced accuracy, 0.9860 ROC AUC |
| Windows Server benign holdout | 0.9116 balanced accuracy |
| Windows 11 benign holdout | 0.9199 balanced accuracy |
| VirusTotal family campaign | 2026-05-22 to 2026-06-01, 500 uncached hash lookups per day, malware hashes only |
| ESP32 local CSV cascade experiment | Learning-stage hardware result: Stage 1 0.9908 balanced accuracy, final cascade 0.9900 balanced accuracy over 3,798 processed samples |

## Where To Put New Metrics

- Add new VIBEX metrics here with a date prefix.
- Keep one metric topic per file.
- Link important new results from [../VIBEX_RESULTS.md](../VIBEX_RESULTS.md).
- If a note is only historical MV2025 material, place it under [../archive/mv2025/metrics/](../archive/mv2025/metrics/).
