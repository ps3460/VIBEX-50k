#!/usr/bin/env zsh
set -euo pipefail

cd /Users/ps3460/GitHub/VIBEX-50k

exec >> evidence/sandbox/server2025_sandbox_campaign_20260608T1830Z_fasttank500_fulltools/dashboard_exporter.log 2>&1

exec /opt/homebrew/bin/python3 tools/vibex_export_sandbox_campaign_dashboard_status.py \
  --campaign-dir evidence/sandbox/server2025_sandbox_campaign_20260608T1830Z_fasttank500_fulltools \
  --output /private/tmp/sandbox_campaign_status.json \
  --copy-to root@10.64.0.87:/opt/mv2025-dashboard/data/sandbox_campaign_status.json \
  --pve root@10.0.0.11 \
  --watch-seconds 60
