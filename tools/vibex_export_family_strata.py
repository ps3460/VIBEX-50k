#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SOURCE = Path("/home/phil/vibex_secure_dataset/tools/vibex_virustotal_family_scan.py")
OUTPUT = Path("/tmp/family_strata_latest.json")
DATASET = "VIBEX-50K"
CAMPAIGN = "VIBEX-50K-vt-family-20260522-20260601"


def main() -> int:
    spec = importlib.util.spec_from_file_location("vtfam", SOURCE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.load_env_files(list(module.DEFAULT_ENV_FILES))
    conn = module.connect()
    rows = module.fetch_all_strata(conn, DATASET, CAMPAIGN)
    conn.close()
    OUTPUT.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"rows={len(rows)} output={OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
