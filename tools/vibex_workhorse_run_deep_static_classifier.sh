#!/usr/bin/env bash
set -euo pipefail

RUN_ROOT="${RUN_ROOT:-/home/phil/vibex_secure_dataset/evidence/sandbox_drive/windows11_drive_triage_20260611}"
TOOLS_DIR="$RUN_ROOT/tools"
RESULTS_DIR="$RUN_ROOT/results"
CLASSIFIER_DIR="$RESULTS_DIR/deep_static_family"
SMOKE_DIR="$RESULTS_DIR/deep_static_family_smoke"
AUDIT_DIR="$RESULTS_DIR/deep_static_toolchain"
LOG_DIR="$RUN_ROOT/logs"
mkdir -p "$CLASSIFIER_DIR" "$SMOKE_DIR" "$AUDIT_DIR" "$LOG_DIR"

SANDBOX_KEY="${SANDBOX_KEY:-/home/phil/.ssh/vibex_sandbox_transfer_ed25519}"
JUMP_HOST="${JUMP_HOST:-phil@10.64.0.57}"
SANDBOX_HOST="${SANDBOX_HOST:-phil@10.192.101.130}"
TARGET_ROWS="${TARGET_ROWS:-19324}"
ALLOW_PARTIAL_TOOLCHAIN="${ALLOW_PARTIAL_TOOLCHAIN:-0}"
RUN_DEFENDER="${RUN_DEFENDER:-0}"
RUN_CLAM="${RUN_CLAM:-0}"
LIMIT="${LIMIT:-0}"
RESUME_FULL="${RESUME_FULL:-1}"
SKIP_SMOKE="${SKIP_SMOKE:-0}"
SSH_COMMON=(-i "$SANDBOX_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $JUMP_HOST -W %h:%p")

ssh_sandbox() {
  ssh "${SSH_COMMON[@]}" "$SANDBOX_HOST" "$@"
}

scp_from_sandbox() {
  scp "${SSH_COMMON[@]}" "$SANDBOX_HOST:$1" "$2"
}

copy_safe_outputs() {
  local dest="$1"
  mkdir -p "$dest"
  for name in deep_static_family_results.csv deep_static_family_summary.json deep_static_family_report.md deep_static_family_progress.json; do
    scp_from_sandbox "/S:/results/$name" "$dest/$name" || true
  done
}

echo "[$(date -u +%FT%TZ)] deploying deep static scripts" | tee -a "$LOG_DIR/deep_static_family_runner.log"
scp "${SSH_COMMON[@]}" "$TOOLS_DIR/vibex_sandbox_toolchain_audit.ps1" "$SANDBOX_HOST:/S:/tools/vibex_sandbox_toolchain_audit.ps1"
scp "${SSH_COMMON[@]}" "$TOOLS_DIR/vibex_sandbox_deep_static_classifier.ps1" "$SANDBOX_HOST:/S:/tools/vibex_sandbox_deep_static_classifier.ps1"

echo "[$(date -u +%FT%TZ)] auditing sandbox toolchain" | tee -a "$LOG_DIR/deep_static_family_runner.log"
ssh_sandbox 'powershell -NoProfile -ExecutionPolicy Bypass -File S:\tools\vibex_sandbox_toolchain_audit.ps1' \
  2>&1 | tee -a "$LOG_DIR/deep_static_toolchain_audit.log"
scp_from_sandbox "/S:/results/deep_static_toolchain_audit.json" "$AUDIT_DIR/deep_static_toolchain_audit.json" || true
scp_from_sandbox "/S:/results/deep_static_toolchain_audit.md" "$AUDIT_DIR/deep_static_toolchain_audit.md" || true

missing="$(python3 - "$AUDIT_DIR/deep_static_toolchain_audit.json" <<'PY'
import json, sys
try:
    d=json.load(open(sys.argv[1], encoding="utf-8-sig"))
    print(",".join(d.get("required_missing") or []))
except Exception as exc:
    print(f"audit_unreadable:{exc}")
PY
)"
if [[ -n "$missing" && "$ALLOW_PARTIAL_TOOLCHAIN" != "1" ]]; then
  echo "Toolchain is incomplete: $missing" | tee -a "$LOG_DIR/deep_static_family_runner.log"
  echo "Set ALLOW_PARTIAL_TOOLCHAIN=1 to run anyway, or install missing tools first." | tee -a "$LOG_DIR/deep_static_family_runner.log"
  exit 4
fi

rows="$(ssh_sandbox 'powershell -NoProfile -Command "(Import-Csv S:\results\windows_family_hints.csv | Select-Object -ExpandProperty raw_sha256 -Unique | Measure-Object).Count"' | tr -dc '0-9')"
if [[ -z "$rows" || "$rows" -lt "$TARGET_ROWS" ]]; then
  echo "Base classification is not complete: rows=${rows:-0}, target=$TARGET_ROWS" | tee -a "$LOG_DIR/deep_static_family_runner.log"
  exit 2
fi

run_flags=()
if [[ "$RUN_DEFENDER" == "1" ]]; then run_flags+=("-RunDefender"); fi
if [[ "$RUN_CLAM" == "1" ]]; then run_flags+=("-RunClam"); fi

if [[ "$SKIP_SMOKE" != "1" ]]; then
  echo "[$(date -u +%FT%TZ)] running 20-row deep static smoke" | tee -a "$LOG_DIR/deep_static_family_runner.log"
  ssh_sandbox 'powershell -NoProfile -Command "Remove-Item S:\results\deep_static_family_* -Force -ErrorAction SilentlyContinue"'
  ssh_sandbox "powershell -NoProfile -ExecutionPolicy Bypass -File S:\\tools\\vibex_sandbox_deep_static_classifier.ps1 -Smoke ${run_flags[*]}" \
    2>&1 | tee -a "$LOG_DIR/deep_static_family_smoke.log"
  copy_safe_outputs "$SMOKE_DIR"

  smoke_rows="$(python3 - "$SMOKE_DIR/deep_static_family_summary.json" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8-sig")).get("saved_rows", 0))
except Exception:
    print(0)
PY
  )"
  if [[ "$smoke_rows" != "20" ]]; then
    echo "Smoke failed: saved_rows=${smoke_rows}/20" | tee -a "$LOG_DIR/deep_static_family_runner.log"
    exit 3
  fi
else
  echo "[$(date -u +%FT%TZ)] skipping smoke for resume" | tee -a "$LOG_DIR/deep_static_family_runner.log"
fi

echo "[$(date -u +%FT%TZ)] running full deep static classifier" | tee -a "$LOG_DIR/deep_static_family_runner.log"
if [[ "$RESUME_FULL" != "1" ]]; then
  ssh_sandbox 'powershell -NoProfile -Command "Remove-Item S:\results\deep_static_family_* -Force -ErrorAction SilentlyContinue"'
else
  echo "[$(date -u +%FT%TZ)] preserving existing deep_static_family outputs for resume" | tee -a "$LOG_DIR/deep_static_family_runner.log"
fi
limit_arg=""
if [[ "$LIMIT" != "0" ]]; then limit_arg="-Limit $LIMIT"; fi
set +e
ssh_sandbox "powershell -NoProfile -ExecutionPolicy Bypass -File S:\\tools\\vibex_sandbox_deep_static_classifier.ps1 $limit_arg ${run_flags[*]}" \
  2>&1 | tee -a "$LOG_DIR/deep_static_family_full.log"
full_status="${PIPESTATUS[0]}"
set -e
copy_safe_outputs "$CLASSIFIER_DIR"
if [[ "$full_status" -ne 0 ]]; then
  echo "[$(date -u +%FT%TZ)] deep static classifier exited non-zero: $full_status" | tee -a "$LOG_DIR/deep_static_family_runner.log"
  exit "$full_status"
fi

summary="$(python3 - "$CLASSIFIER_DIR/deep_static_family_summary.json" <<'PY'
import json, sys
try:
    d=json.load(open(sys.argv[1], encoding="utf-8-sig"))
    parts=[f"{r.get('name')}: {r.get('count')}" for r in d.get("decision_counts", [])]
    print(f"Saved rows: {d.get('saved_rows')} of {d.get('target_rows')}. " + ", ".join(parts))
except Exception as exc:
    print(f"Summary unavailable: {exc}")
PY
)"
echo "[$(date -u +%FT%TZ)] deep static classifier complete: $summary" | tee -a "$LOG_DIR/deep_static_family_runner.log"
