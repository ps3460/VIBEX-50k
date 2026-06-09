#!/usr/bin/env zsh
set -euo pipefail

cd /Users/ps3460/GitHub/VIBEX-50k

exec >> evidence/sandbox/server2025_sandbox_campaign_20260608T1830Z_fasttank500_fulltools/campaign_runner.log 2>&1
echo "=== fasttank campaign runner start $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

exec /opt/homebrew/bin/python3 tools/vibex_server2025_sandbox_campaign.py run \
  --run-id server2025_sandbox_campaign_20260608T1830Z_fasttank500_fulltools \
  --output-dir evidence/sandbox/server2025_sandbox_campaign_20260608T1830Z_fasttank500_fulltools \
  --pve root@10.0.0.11 \
  --vmid 116 \
  --snapshot pre-detonation-4core-static \
  --batch-size 500 \
  --guest-timeout 43200 \
  --iso-timeout 7200 \
  --pve-iso-storage tank-iso \
  --pve-iso-dir /tank/proxmox-iso/template/iso \
  --cdrom-slot ide0 \
  --tool-profile fast \
  --no-rollback \
  --reboot-before-batch \
  --max-consecutive-errors 0 \
  --start-batch 2
