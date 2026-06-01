# VIBEX Project

## Purpose

VIBEX is the current PhD-facing direction of this repository. It combines:

- a reproducible executable-image dataset release;
- baseline malware-versus-benign model evaluation;
- a constrained hardware lab using ESP32, Raspberry Pi, RS485, dashboard exports, and SQL evidence;
- a thesis evidence trail that records provenance, source shift, latency, reliability, and reproducibility.

The short form is: **build a defensible malware dataset, prove what the models can and cannot learn, then validate practical edge/fog deployment in the lab.**

## Current Research Questions

1. Can executable bytes converted into deterministic grayscale images support reliable malware-versus-benign classification?
2. How much does performance change when benign source provenance is held out?
3. Which evidence is strong enough for PhD claims: random split metrics, source-holdout metrics, hardware run metrics, or all three?
4. Which parts of the workflow can run on constrained hardware, and which must remain on the workhorse or Raspberry Pi?
5. Can malware-family labels be added as a consensus metadata layer without pretending they are raw ground truth?

## Dataset Direction

The current public release is `VIBEX-50K`.

Supporting source components:

- `Windows PE component`: Windows PE/MZ executable-derived images.
- `Linux ELF component`: Linux ELF executable-derived images.

These are components inside `VIBEX-50K`, not separate public release promises.

## Lab Direction

The lab keeps the constrained deployment story alive:

- `ID:00`: Raspberry Pi controller.
- `ID:01` and `ID:02`: ESP32 Tier 1 nodes.
- RS485: wired controller-to-node transport.
- Dashboard/API: exports metrics, lab state, and research evidence.
- Workhorse: secure dataset build, model training, model search, and vault storage.

The current PhD framing should distinguish dataset-image experiments from ESP32 feature-gate experiments. VIBEX-50K is an image dataset. The historical MV2025 ESP32 path used fixed 1024-byte prefixes and lightweight byte features for a binary gate.

## History Summary

| Phase | What Happened | Current Status |
| --- | --- | --- |
| Early malware-image work | CNN/image experiments, Raspberry Pi runtime checks, optimizer comparisons, initial lab structure | Historical background |
| ESP32/Pi lab | ESP32 nodes, Pi controller, RS485, LCD/dashboard status, SQL metrics, SD-card payloads | Still relevant lab infrastructure |
| MV2025 feasibility | ESP32-safe binary gate, Pi Stage 1.5 checks, Stage 2 image triage, RS485 batch evidence | Archived reference only |
| VIBEX dataset build | Secure workhorse vault, source hashing, deterministic PNG conversion, release manifests | Current |
| VIBEX-50K baselines | Random split and source-holdout CNN baselines | Current thesis evidence |

## What New Work Should Do

- Prefer `VIBEX-50K`, `Windows PE component`, and `Linux ELF component` naming.
- Keep `MV2025` only when referring to archived history or backward-compatible service/script names.
- Preserve source provenance fields because they are needed for source-holdout benchmarks.
- Treat family labels as an enrichment layer derived from VirusTotal/AVClass-style consensus, not as native ground truth.
- Put results into [VIBEX_RESULTS.md](VIBEX_RESULTS.md) or a dated file under [metrics/](metrics/).
- Keep build/release commands in [VIBEX_BUILD.md](VIBEX_BUILD.md) and [024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md](024_VIBEX_DATASET_CONSTRUCTION_PROTOCOL.md).

## Thesis Boundary

This repo should provide evidence that can be lifted into `/Users/ps3460/GitLab/Thesis`, but it should not edit the thesis repo unless explicitly asked. The thesis should cite this repo's frozen datasets, metrics notes, manifests, source hashes, and reproducible commands.
