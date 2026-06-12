# VM 107 Deep Static Classification Handoff

Status as of 2026-06-12:

- Target sandbox: Windows 11 VM `10.192.101.130`, referred to as `10130`.
- Workhorse run root: `/home/phil/vibex_secure_dataset/evidence/sandbox_drive/windows11_drive_triage_20260611`.
- Sandbox sample drive: `S:`.
- Target samples: `S:\samples`.
- Base classification input: `S:\results\windows_family_hints.csv`.
- Deep static output: `S:\results\deep_static_family_results.csv`.
- The full unattended runner failed with `System.OutOfMemoryException` after roughly `599` saved rows.
- The classifier was patched to resume from the CSV and avoid retaining all result rows in memory.
- Do not store raw malware or raw tool dumps in Git. Only safe CSV/JSON/Markdown summaries may be copied out.

## Clone Repo On VM 107

Run this from the Codex shell on VM 107:

```bash
mkdir -p ~/codex
cd ~/codex
git clone git@github.com:ps3460/VIBEX-50k.git
cd VIBEX-50k
git checkout main
git pull --ff-only
```

If SSH auth is not available on VM 107, use the HTTPS remote:

```bash
git clone https://github.com/ps3460/VIBEX-50k.git
```

## Access Pattern

VM 107 should use the same workhorse-to-sandbox route used by the current run:

```bash
RUN_ROOT=/home/phil/vibex_secure_dataset/evidence/sandbox_drive/windows11_drive_triage_20260611
SANDBOX_KEY=/home/phil/.ssh/vibex_sandbox_transfer_ed25519
JUMP_HOST=phil@10.64.0.57
SANDBOX_HOST=phil@10.192.101.130
SSH_SANDBOX=(ssh -i "$SANDBOX_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $JUMP_HOST -W %h:%p" "$SANDBOX_HOST")
SCP_SANDBOX=(scp -i "$SANDBOX_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $JUMP_HOST -W %h:%p")
```

For direct checks:

```bash
"${SSH_SANDBOX[@]}" 'powershell -NoProfile -Command "Get-ChildItem S:\results\deep_static_family* | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize"'
```

## Deploy Current Tooling

From the cloned repo on VM 107:

```bash
cd ~/codex/VIBEX-50k
RUN_ROOT=/home/phil/vibex_secure_dataset/evidence/sandbox_drive/windows11_drive_triage_20260611
SANDBOX_KEY=/home/phil/.ssh/vibex_sandbox_transfer_ed25519
JUMP_HOST=phil@10.64.0.57
SANDBOX_HOST=phil@10.192.101.130
SSH_COMMON=(-i "$SANDBOX_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $JUMP_HOST -W %h:%p")

mkdir -p "$RUN_ROOT/tools" "$RUN_ROOT/results/deep_static_family"
cp tools/vibex_workhorse_run_deep_static_classifier.sh "$RUN_ROOT/tools/"
cp tools/vibex_workhorse_deep_static_watchdog.py "$RUN_ROOT/tools/"
chmod +x "$RUN_ROOT/tools/vibex_workhorse_run_deep_static_classifier.sh" "$RUN_ROOT/tools/vibex_workhorse_deep_static_watchdog.py"

scp "${SSH_COMMON[@]}" tools/vibex_sandbox_toolchain_audit.ps1 "$SANDBOX_HOST:/S:/tools/vibex_sandbox_toolchain_audit.ps1"
scp "${SSH_COMMON[@]}" tools/vibex_sandbox_deep_static_classifier.ps1 "$SANDBOX_HOST:/S:/tools/vibex_sandbox_deep_static_classifier.ps1"
scp "${SSH_COMMON[@]}" tools/vibex_sandbox_dedupe_deep_static_results.ps1 "$SANDBOX_HOST:/S:/tools/vibex_sandbox_dedupe_deep_static_results.ps1"
```

## Clean Partial Result Before Resume

The one-row resume smoke introduced a duplicate hash. Deduplicate on the sandbox before continuing:

```bash
"${SSH_SANDBOX[@]}" 'powershell -NoProfile -ExecutionPolicy Bypass -File S:\tools\vibex_sandbox_dedupe_deep_static_results.ps1'
```

Verify no duplicate hashes:

```bash
"${SSH_SANDBOX[@]}" 'powershell -NoProfile -Command "$rows=@(Import-Csv S:/results/deep_static_family_results.csv); $dups=@($rows | Group-Object raw_sha256 | Where-Object Count -gt 1); [pscustomobject]@{rows=$rows.Count; unique=@($rows.raw_sha256 | Sort-Object -Unique).Count; duplicate_groups=$dups.Count} | ConvertTo-Json -Compress"'
```

## Codex-Managed Resume Strategy

Do not restart one unbounded full run. Have Codex on VM 107 run bounded resume chunks and inspect progress after each chunk.

Recommended chunk plan:

1. Resume to `1000` rows.
2. If stable, resume to `1500`.
3. Continue in `500` or `1000` row increments.
4. If memory remains stable for several chunks, increase to `2000` row increments.
5. After each chunk, copy safe outputs to workhorse and check duplicates, tool status counts, and decision counts.

Chunk command:

```bash
"${SSH_SANDBOX[@]}" 'powershell -NoProfile -ExecutionPolicy Bypass -File S:\tools\vibex_sandbox_deep_static_classifier.ps1 -Limit 1000'
```

Replace `1000` with the next target row count. The classifier skips hashes already present in `S:\results\deep_static_family_results.csv`.

For VM107 takeover, run the VM107 resident supervisor instead of keeping a Codex shell attached:

```powershell
cd C:\Users\phil\codex\VIBEX-50k
git pull --ff-only
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\vibex_vm107_deep_static_manager.ps1
```

For detached operation from an SSH session on VM107:

```powershell
$manager = 'C:\Users\phil\codex\VIBEX-50k\tools\vibex_vm107_deep_static_manager.ps1'
$base = 'C:\Users\phil\codex\vibex_deep_static_manager'
New-Item -ItemType Directory -Force $base | Out-Null
Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$manager) -RedirectStandardOutput "$base\manager_stdout.log" -RedirectStandardError "$base\manager_stderr.log" -WindowStyle Hidden
```

The supervisor writes:

- `C:\Users\phil\codex\vibex_deep_static_manager\manager.log`
- `C:\Users\phil\codex\vibex_deep_static_manager\manager_state.json`
- `C:\Users\phil\codex\vibex_deep_static_manager\deep_static_family_progress.live.json`

It waits if the sandbox progress file shows an active bounded chunk, starts the next chunk only at a stable chunk boundary, and stops instead of risking duplicate rows if progress is stale.

Copy safe outputs after every chunk:

```bash
mkdir -p "$RUN_ROOT/results/deep_static_family"
for name in deep_static_family_results.csv deep_static_family_summary.json deep_static_family_report.md deep_static_family_progress.json; do
  scp "${SSH_COMMON[@]}" "$SANDBOX_HOST:/S:/results/$name" "$RUN_ROOT/results/deep_static_family/$name" || true
done
```

Progress check:

```bash
"${SSH_SANDBOX[@]}" 'powershell -NoProfile -Command "if (Test-Path S:\results\deep_static_family_progress.json) { Get-Content S:\results\deep_static_family_progress.json -Raw }"'
```

## Toolchain Checks

Before resuming, confirm the sandbox still has the required deep-static tools:

```bash
"${SSH_SANDBOX[@]}" 'powershell -NoProfile -ExecutionPolicy Bypass -File S:\tools\vibex_sandbox_toolchain_audit.ps1'
```

Expected required tools:

- `sigcheck64.exe`
- `strings64.exe`
- `diec.exe`
- `yara64.exe`
- `capa.exe`
- `floss.exe`

YARA rules are optional unless curated rules have been staged under `S:\rules`.

## Acceptance Criteria

- No raw malware copied into Git.
- No raw FLOSS/capa/YARA dumps committed.
- `deep_static_family_results.csv` has no duplicate `raw_sha256`.
- Each accepted label has explicit evidence sources.
- Rejected rows have explicit `static_decision_reason`.
- Build the final manifest with `tools/vibex_build_deep_static_family_dataset.py` only after the deep-static CSV is complete or after a deliberate partial cutoff is approved.

## Final Dataset Build

After enough rows are complete and copied to workhorse:

```bash
cd ~/codex/VIBEX-50k
python3 tools/vibex_build_deep_static_family_dataset.py \
  --deep-static-results "$RUN_ROOT/results/deep_static_family/deep_static_family_results.csv" \
  --output-dir "$RUN_ROOT/results/deep_static_family_dataset_build"
```

Only use `--allow-medium` after manual review shows the medium-confidence rows are useful.
