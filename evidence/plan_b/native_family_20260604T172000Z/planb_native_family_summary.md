# Plan B Native PNG Family CNN Experiment

- Run ID: `planb_stagea_family_native_20260604T172000Z`
- Created UTC: `2026-06-04T16:42:43Z`
- Image manifest: `/home/phil/vibex_secure_dataset/sources/malwarebazaar_planb/planb_stagea_native_20260604T161000Z/evidence/planb_stagea_native_png_manifest.csv`
- Family rows per size/mode: `2980`
- Families: `10`
- Previous family macro-F1 baseline: `0.1716`
- Completed runs: `60`
- Failed runs: `0`
- Raw malware, PNG images, and model binaries remain on workhorse only; repository evidence is metrics, checksums, paths, and audit metadata only.

## Best Mean Result

- Architecture: `inception_small`
- Image size/mode: `512 rgb_triplet`
- Macro-F1 mean/std: `0.7889` / `0.0282`
- Accuracy mean/std: `0.7889` / `0.0252`
- Non-zero family F1 mean: `10.00`
- Improved over previous best: `True`

## Leaderboard

| Architecture | Size | Mode | Seeds | Accuracy mean | Macro-F1 mean | Macro-F1 std | Non-zero F1 mean |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| inception_small | 512 | rgb_triplet | 3 | 0.7889 | 0.7889 | 0.0282 | 10.00 |
| inception_small | 256 | gray | 3 | 0.7889 | 0.7889 | 0.0236 | 10.00 |
| inception_small | 512 | gray | 3 | 0.7726 | 0.7733 | 0.0093 | 10.00 |
| inception_small | 256 | rgb_triplet | 3 | 0.7674 | 0.7676 | 0.0061 | 10.00 |
| residual_small | 256 | gray | 3 | 0.7600 | 0.7606 | 0.0253 | 10.00 |
| residual_small | 256 | rgb_triplet | 3 | 0.7400 | 0.7433 | 0.0131 | 10.00 |
| residual_small | 512 | gray | 3 | 0.7407 | 0.7398 | 0.0507 | 10.00 |
| compact_cnn | 256 | gray | 3 | 0.7422 | 0.7384 | 0.0179 | 10.00 |
| residual_small | 512 | rgb_triplet | 3 | 0.7363 | 0.7371 | 0.0518 | 10.00 |
| compact_cnn | 256 | rgb_triplet | 3 | 0.7200 | 0.7123 | 0.0657 | 9.67 |
| compact_cnn | 512 | gray | 3 | 0.7148 | 0.7082 | 0.0068 | 10.00 |
| dense_small | 256 | rgb_triplet | 3 | 0.6830 | 0.6678 | 0.0613 | 10.00 |
| dense_small | 256 | gray | 3 | 0.6830 | 0.6658 | 0.0088 | 10.00 |
| dense_small | 512 | gray | 3 | 0.6600 | 0.6494 | 0.0479 | 10.00 |
| compact_cnn | 512 | rgb_triplet | 3 | 0.6459 | 0.6428 | 0.0132 | 10.00 |
| dense_small | 512 | rgb_triplet | 3 | 0.6356 | 0.6211 | 0.0593 | 10.00 |
| convnext_tiny_scratch | 512 | gray | 3 | 0.1007 | 0.0196 | 0.0021 | 1.33 |
| convnext_tiny_scratch | 256 | gray | 3 | 0.1000 | 0.0182 | 0.0000 | 1.00 |
| convnext_tiny_scratch | 256 | rgb_triplet | 3 | 0.1000 | 0.0182 | 0.0000 | 1.00 |
| convnext_tiny_scratch | 512 | rgb_triplet | 3 | 0.1000 | 0.0182 | 0.0000 | 1.00 |
