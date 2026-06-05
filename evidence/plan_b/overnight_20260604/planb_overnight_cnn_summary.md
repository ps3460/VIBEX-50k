# Plan B Overnight CNN Sweep

- Run ID: `planb_overnight_20260604_odd_cnn_17x500`
- Created UTC: `2026-06-04T23:09:21Z`
- Malware families: `10`
- Malware PNG rows used: `3308`
- Benign PNG rows used: `3308`
- Image size: `256`
- Completed runs: `33`
- Failed runs: `3`
- Safe evidence only; raw malware and model binaries remain on workhorse.

## Presentation Summary

- Best binary model: `compact_cnn` macro-F1 `1.0000`, accuracy `1.0000`.
- Best family model: `inception_small` macro-F1 `0.7495`, accuracy `0.7540`.

## Leaderboard

| Task | Architecture | Size | Seeds | Accuracy mean | Macro-F1 mean | Benign FP mean |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| mixed_multiclass | inception_small | 256 | 1 | 0.5489 | 0.5441 | 0.0000 |
| mixed_multiclass | separable_extreme | 256 | 1 | 0.4117 | 0.4721 | 0.0000 |
| mixed_multiclass | fixed_edge_bank | 256 | 1 | 0.4057 | 0.4534 | 0.0000 |
| mixed_multiclass | residual_small | 256 | 1 | 0.4077 | 0.4474 | 0.0000 |
| mixed_multiclass | patch_shuffle_cnn | 256 | 1 | 0.3744 | 0.4078 | 0.0000 |
| mixed_multiclass | compact_cnn | 256 | 1 | 0.4157 | 0.3936 | 0.0000 |
| mixed_multiclass | squeeze_excite_cnn | 256 | 1 | 0.4299 | 0.3838 | 0.0000 |
| mixed_multiclass | barcode_dilated | 256 | 1 | 0.3219 | 0.3274 | 0.0000 |
| mixed_multiclass | large_kernel_texture | 256 | 1 | 0.3199 | 0.2643 | 0.0000 |
| mixed_multiclass | multiscale_pyramid | 256 | 1 | 0.2129 | 0.1728 | 0.0000 |
| mixed_multiclass | random_reservoir | 256 | 1 | 0.2775 | 0.0829 | 0.0000 |
| malware_family | inception_small | 256 | 1 | 0.7540 | 0.7495 | 0.0000 |
| malware_family | separable_extreme | 256 | 1 | 0.7581 | 0.7458 | 0.0000 |
| malware_family | squeeze_excite_cnn | 256 | 1 | 0.7460 | 0.7418 | 0.0000 |
| malware_family | residual_small | 256 | 1 | 0.7298 | 0.7318 | 0.0000 |
| malware_family | patch_shuffle_cnn | 256 | 1 | 0.7278 | 0.7141 | 0.0000 |
| malware_family | compact_cnn | 256 | 1 | 0.7258 | 0.7080 | 0.0000 |
| malware_family | fixed_edge_bank | 256 | 1 | 0.7056 | 0.6940 | 0.0000 |
| malware_family | multiscale_pyramid | 256 | 1 | 0.6371 | 0.5889 | 0.0000 |
| malware_family | large_kernel_texture | 256 | 1 | 0.4819 | 0.4627 | 0.0000 |
| malware_family | barcode_dilated | 256 | 1 | 0.4093 | 0.3702 | 0.0000 |
| malware_family | random_reservoir | 256 | 1 | 0.3246 | 0.2868 | 0.0000 |
| binary | compact_cnn | 256 | 1 | 1.0000 | 1.0000 | 0.0000 |
| binary | inception_small | 256 | 1 | 1.0000 | 1.0000 | 0.0000 |
| binary | separable_extreme | 256 | 1 | 1.0000 | 1.0000 | 0.0000 |
| binary | patch_shuffle_cnn | 256 | 1 | 1.0000 | 1.0000 | 0.0000 |
| binary | squeeze_excite_cnn | 256 | 1 | 1.0000 | 1.0000 | 0.0000 |
| binary | residual_small | 256 | 1 | 0.9990 | 0.9990 | 0.0000 |
| binary | multiscale_pyramid | 256 | 1 | 0.9980 | 0.9980 | 0.0000 |
| binary | fixed_edge_bank | 256 | 1 | 0.9980 | 0.9980 | 0.0000 |
| binary | barcode_dilated | 256 | 1 | 0.9970 | 0.9970 | 0.0060 |
| binary | large_kernel_texture | 256 | 1 | 0.9960 | 0.9960 | 0.0000 |
| binary | random_reservoir | 256 | 1 | 0.9919 | 0.9919 | 0.0081 |
