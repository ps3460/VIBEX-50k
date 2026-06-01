# VIBEX-50K RS485 Pipelined Batch Protocol

Date: 2026-05-19

## Purpose

This note defines the next RS485 scheduling experiment for the dual ESP32 VIBEX-50K Stage 1 system. The current bus is reliable but underuses the two ESP32 nodes: while one node is transmitting evidence and results to the Raspberry Pi, the other node often waits for its next addressed turn. The proposed protocol keeps the Raspberry Pi as the only RS485 master, but overlaps local ESP32 scanning with bus communication.

The target behaviour is:

| Time slice | `ID:01` | `ID:02` |
|---|---|---|
| 1 | Communicate with Pi | Scan/cache next batch |
| 2 | Scan/cache next batch | Communicate with Pi |
| 3 | Communicate with Pi | Scan/cache next batch |

This preserves the half-duplex RS485 discipline while reducing idle ESP32 time.

## Baseline Evidence

The existing batch benchmark on 2026-05-15 showed that Pi-granted batches improve throughput without changing the evidence payload:

| Batch size | Rows | Duration | Rows/min | Transfer failures | Hash matches |
|---:|---:|---:|---:|---:|---:|
| 1 | `32 / 32` | `181s` | `10.61` | `0` | `32 / 32` |
| 4 | `32 / 32` | `68s` | `28.24` | `0` | `32 / 32` |
| 8 | `32 / 32` | `49s` | `39.18` | `0` | `32 / 32` |
| 16 | `32 / 32` | `39s` | `49.23` | `0` | `32 / 32` |

The per-sample evidence transfer stayed close to `401-402 ms`, and ESP32 inference stayed close to `1.55 ms`. The improvement therefore came from reducing Pi command and turn overhead.

The full physical run on 2026-05-17 used batch `16` with cache/flush overlap and completed `944 / 944` rows in `964s`, with `944 / 944` hash-matched prefix transfers and mean transfer duration `327.379 ms`.

## Physical SD Staging Constraint

The full `25,000`-sample-per-node SD payload cannot place the original long sample names directly in one FAT `samples/` directory. During ID:01 staging on 2026-05-20, the card still reported about `58 GB` free, but Linux returned `ENOSPC` around sample `9,864` while renaming files such as:

```text
malware_009864_GuLoader_9bd96a34e477_47a7f1cc510a6c93a25760aeda4fa1b3.bin
```

This is a FAT directory-entry exhaustion issue, not byte-capacity exhaustion. Long VFAT names consume multiple directory entries per file, so thousands of long filenames in one directory can fail long before the volume is full.

The physical-run payload now uses FAT-safe sample names:

```text
s00000.bin
s00001.bin
...
s24999.bin
```

The manifest preserves the original name in `original_sample_name`, while `sample_name` and `path` point to the staged short filename. The ESP32 firmware reads the first manifest column and opens `/VIBEX-50K/samples/<sample_name>`, so this change avoids a firmware change and keeps the thesis mapping reproducible through the manifest.

## Proposed Protocol

Use batch size `25` as the next operational candidate. The ESP32 firmware currently caps cached batch size at `32`, so `25` leaves memory margin while reducing the number of bus turns compared with batch `16`.

Each Pi-granted batch should have a stable token:

```text
run_id
batch_id
node_id
plan_sha256
manifest_indexes
expected_count
```

Each sample and transfer frame should carry enough ordering data for loss detection:

```text
batch_id
sample_seq
sample_name
frame_seq
frame_count
payload_sha256
```

The Pi should only acknowledge a batch after all expected sample rows, evidence frames, input hashes, and final batch markers are present and internally consistent.

## Scheduling Sequence

The Pi remains the only bus master.

```text
1. Pi -> ID:02 CACHE_FULL50_EVIDENCE_LIST batch_000 indexes[25]
2. ID:02 scans silently into RAM.
3. Pi -> ID:01 RUN_FULL50_EVIDENCE_LIST batch_000 indexes[25]
4. ID:01 scans and transmits while ID:02 is busy locally.
5. Pi -> ID:01 CACHE_FULL50_EVIDENCE_LIST batch_001 indexes[25]
6. Pi -> ID:02 TX_CACHE batch_000
7. ID:02 transmits cached evidence, input hashes, results, and LIST_DONE.
8. Pi -> ID:02 CACHE_FULL50_EVIDENCE_LIST batch_001 indexes[25]
9. Pi -> ID:01 TX_CACHE batch_001
10. Repeat until all planned batches are acknowledged.
```

The important property is that a cache command is a short addressed command, but the long work happens silently off-bus. A transmit command is the only point where the ESP32 is allowed to occupy the shared RS485 line.

## SQL Evidence Table

The existing `stage1_results`, `stage1_transfers`, and `stage1_events` tables are row- and event-oriented. Add a batch-level table so the thesis can measure scheduling efficiency directly:

```sql
CREATE TABLE IF NOT EXISTS stage1_batch_protocol_metrics (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  run_id VARCHAR(64) NOT NULL,
  batch_id VARCHAR(96) NOT NULL,
  node_id VARCHAR(8) NOT NULL,
  peer_node_id VARCHAR(8) NULL,
  scheduler_mode VARCHAR(32) NOT NULL,
  batch_size INT NOT NULL,
  expected_samples INT NOT NULL,
  received_samples INT NOT NULL DEFAULT 0,
  missing_samples INT NOT NULL DEFAULT 0,
  duplicate_samples INT NOT NULL DEFAULT 0,
  expected_frames INT NULL,
  received_frames INT NULL,
  retry_count INT NOT NULL DEFAULT 0,
  cache_requested_at DATETIME NULL,
  cache_ready_at DATETIME NULL,
  tx_started_at DATETIME NULL,
  tx_completed_at DATETIME NULL,
  acked_at DATETIME NULL,
  scan_duration_ms FLOAT NULL,
  cache_wait_ms FLOAT NULL,
  tx_duration_ms FLOAT NULL,
  bus_turnaround_ms FLOAT NULL,
  rows_per_min FLOAT NULL,
  hash_mismatches INT NOT NULL DEFAULT 0,
  status VARCHAR(32) NOT NULL DEFAULT 'started',
  plan_sha256 CHAR(64) NULL,
  metadata_json JSON NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_stage1_batch_protocol (run_id, batch_id, node_id),
  INDEX idx_stage1_batch_protocol_run (run_id),
  INDEX idx_stage1_batch_protocol_status (status),
  INDEX idx_stage1_batch_protocol_node (node_id)
);
```

This table supports four thesis-grade measurements:

- Scheduling efficiency: rows per minute, cache wait, transmit duration, and bus turnaround.
- Reliability: missing samples, duplicate samples, retry count, frame counts, and hash mismatches.
- Fairness: per-node batch timing and received sample balance.
- Reproducibility: run id, batch id, plan hash, node id, and scheduler mode.

## Test Plan

Run the tests from the Runner LXC, not the laptop, so the experiment survives local sleep.

1. Wait for the current E2E1000 Pi job to finish.
2. Run a short validation: `25` samples per node, batch `25`.
3. Run a two-batch validation: `50` samples per node, batch `25`.
4. Run the E2E1000 physical set: `500` samples on `ID:01`, `500` samples on `ID:02`, batch `25`.
5. Send the final full-run result to Telegram from the LXC.

For the current firmware build, random planning must be constrained to the ESP32-visible manifest prefix with `MV2025_MANIFEST_MAX_INDEX=1024`. The staged Pi manifest contains more rows, but the deployed ESP32 command path reports `total=1024` and returns `not_found` for requested indexes above that limit.

Pass criteria:

- `100%` expected rows received.
- `0` missing sample indexes.
- `0` duplicate sample indexes.
- `0` failed evidence transfers.
- `100%` declared SHA-256 matches for prefix evidence.
- No node monopolises the bus; both nodes complete their planned row counts.

## Thesis Claim Boundary

If the batch-25 E2E1000 run passes, the defensible thesis claim is that a Pi-mastered, tokenised, pipelined RS485 scheduler can reduce dual-node idle time while preserving deterministic bus ownership and hash-verified evidence delivery. It is not a claim that the bus is full duplex; the communication channel remains half-duplex. The improvement comes from overlapping ESP32-local compute with addressed RS485 transfer windows.
