#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


APR25_KEY = str(Path.home() / ".ssh" / "id_ed25519_Apr25")
RESEARCH_ROOT = Path.home() / "GitHub" / "VIBEX-50k"
SOURCE_ROOT = Path.home() / "repos" / "ESP32-Pi-Malware-Lab"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(command: list[str], timeout: int = 30) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {"command": command, "returncode": proc.returncode, "output": proc.stdout.strip()}
    except subprocess.TimeoutExpired as exc:
        return {"command": command, "returncode": 124, "output": (exc.stdout or exc.stderr or "timeout").strip() if isinstance(exc.stdout or exc.stderr, str) else "timeout"}


def ssh(target: str, command: str, timeout: int = 30) -> dict[str, Any]:
    return run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-i", APR25_KEY, "-o", "IdentitiesOnly=yes", target, command], timeout=timeout)


def nc(host: str, port: int, timeout: int = 10) -> dict[str, Any]:
    return run(["nc", "-vz", "-w", str(timeout), host, str(port)], timeout=timeout + 2)


def check_local_commands() -> dict[str, str]:
    names = ["git", "tmux", "codex", "python3", "rg", "jq", "curl"]
    return {name: shutil.which(name) or "" for name in names}


def banned_repo_files(repo_root: Path) -> list[str]:
    banned_suffixes = {".bin", ".exe", ".dll", ".sys", ".so", ".iso", ".img", ".png", ".jpg", ".jpeg", ".keras", ".h5", ".onnx", ".tflite", ".pt", ".pth"}
    hits = []
    for path in repo_root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix.lower() in banned_suffixes:
            hits.append(str(path))
    return hits[:50]


def main() -> int:
    report: dict[str, Any] = {
        "created_utc": utc_now(),
        "checks": {},
        "blockers": [],
        "warnings": [],
    }

    report["checks"]["local_commands"] = check_local_commands()
    report["checks"]["local_paths"] = {
        "research_root_exists": RESEARCH_ROOT.exists(),
        "source_root_exists": SOURCE_ROOT.exists(),
    }
    report["checks"]["tmux_sessions"] = run(["tmux", "list-sessions"], timeout=10)
    report["checks"]["local_disk"] = run(["df", "-h", str(Path.home())], timeout=10)
    report["checks"]["research_git_remote"] = run(["git", "-C", str(RESEARCH_ROOT), "remote", "-v"], timeout=10) if RESEARCH_ROOT.exists() else {"returncode": 1, "output": "missing research repo"}
    report["checks"]["source_git_remote"] = run(["git", "-C", str(SOURCE_ROOT), "remote", "-v"], timeout=10) if SOURCE_ROOT.exists() else {"returncode": 1, "output": "missing source repo"}

    report["checks"]["workhorse_ssh"] = ssh("workhorse", "hostname; uptime", timeout=20)
    report["checks"]["workhorse_gpu"] = ssh("workhorse", "nvidia-smi --query-gpu=temperature.gpu,utilization.gpu,utilization.memory,memory.used,memory.total,power.draw --format=csv,noheader,nounits", timeout=20)
    report["checks"]["workhorse_jobs"] = ssh("workhorse", "ps -eo pid,etimes,pcpu,pmem,cmd --sort=-pcpu | egrep -i 'python|train|cnn|tensorflow|torch|ollama|virustotal' | head -n 20", timeout=20)
    report["checks"]["workhorse_qemu"] = ssh("workhorse", "for x in qemu-system-aarch64 qemu-system-arm qemu-aarch64 qemu-system-xtensa qemu-system-esp32; do command -v \"$x\" || true; done", timeout=20)
    report["checks"]["workhorse_dataset_paths"] = ssh("workhorse", "ls -ld /home/phil/vibex_secure_dataset /home/phil/vibex_secure_dataset/release/VIBEX-50K /home/phil/vibex_secure_dataset/evidence/holiday_run_20260524_8day/family_dataset /home/phil/vibex_secure_dataset/evidence/holiday_run_20260524_8day/stage2_sql_queues", timeout=20)

    report["checks"]["proxmox_ssh"] = ssh("root@10.0.0.11", "hostname; uptime", timeout=20)
    report["checks"]["monitoring_ssh"] = ssh("phil@10.64.0.65", "hostname; uptime; curl -sS http://127.0.0.1:9090/-/ready", timeout=20)
    report["checks"]["pi5_ssh"] = ssh("phil@10.64.1.102", "hostname; uptime; cat /sys/class/thermal/thermal_zone0/temp; vcgencmd measure_temp 2>/dev/null || true; ps -eo pid,etimes,pcpu,pmem,cmd --sort=-pcpu | head -n 12", timeout=20)
    report["checks"]["dashboard_http"] = nc("10.64.0.87", 8085, timeout=5)
    report["checks"]["mariadb_tcp"] = nc("10.64.0.98", 3306, timeout=5)
    report["checks"]["runner_tcp"] = nc("10.64.0.62", 22, timeout=5)

    report["checks"]["prometheus_core"] = ssh(
        "phil@10.64.0.65",
        "for q in 'up{instance=~\"10.0.0.157:9100|10.64.0.87:8085|https://prometheus.i.steadnet.com/-/ready\"}' 'pve_up{id=~\"lxc/102|lxc/124|lxc/127|lxc/670|node/pve\"}' 'node_load1{instance=~\"10.0.0.157:9100|10.64.0.87:9100|10.64.0.65:9100|10.0.0.11:9100\"}'; do curl -sS --get --data-urlencode query=\"$q\" http://127.0.0.1:9090/api/v1/query; echo; done",
        timeout=30,
    )
    report["checks"]["codex_timers"] = run(["systemctl", "--user", "list-timers", "--all"], timeout=20)
    report["checks"]["benchmark_outputs"] = {
        "binary_pe_manifest": (RESEARCH_ROOT / "datasets" / "binary_pe" / "manifest.csv").exists(),
        "binary_elf_manifest": (RESEARCH_ROOT / "datasets" / "binary_elf" / "manifest.csv").exists(),
        "family_core_manifest": (RESEARCH_ROOT / "datasets" / "family_core" / "manifest.csv").exists(),
        "family_extended_manifest": (RESEARCH_ROOT / "datasets" / "family_extended" / "manifest.csv").exists(),
        "counts_manifest_rows": (RESEARCH_ROOT / "evidence" / "counts_manifest_rows.csv").exists(),
        "counts_png_rows": (RESEARCH_ROOT / "evidence" / "counts_png_rows.csv").exists(),
        "duplicate_raw_sha256": (RESEARCH_ROOT / "evidence" / "duplicate_raw_sha256.csv").exists(),
        "duplicate_png_hash": (RESEARCH_ROOT / "evidence" / "duplicate_png_hash.csv").exists(),
        "family_strata_status": (RESEARCH_ROOT / "evidence" / "family_strata_status.csv").exists(),
    }
    report["checks"]["repo_banned_files"] = banned_repo_files(RESEARCH_ROOT) if RESEARCH_ROOT.exists() else ["missing research repo"]

    if report["checks"]["workhorse_ssh"]["returncode"] != 0:
        report["blockers"].append(
            {
                "failed_component": "workhorse_ssh",
                "impact": "No access to dataset vault, evidence, or training host.",
                "mac_shutdown_safe": False,
                "fallback": "Use VM 107 or workhorse Gemma only after restoring codex-remote to workhorse SSH.",
            }
        )
    if report["checks"]["proxmox_ssh"]["returncode"] != 0:
        report["blockers"].append(
            {
                "failed_component": "proxmox_ssh",
                "impact": "Cannot verify or recover LXC estate.",
                "mac_shutdown_safe": False,
                "fallback": "Use existing runner and monitoring hosts only if they remain reachable independently.",
            }
        )
    if report["checks"]["pi5_ssh"]["returncode"] != 0:
        report["blockers"].append(
            {
                "failed_component": "pi5_ssh",
                "impact": "Cannot validate Pi thermal state or clear stuck payload work.",
                "mac_shutdown_safe": False,
                "fallback": "Pause Pi-dependent work and operate only on dataset/documentation tasks.",
            }
        )
    if not all(report["checks"]["benchmark_outputs"].values()):
        report["blockers"].append(
            {
                "failed_component": "benchmark_outputs",
                "impact": "Research repo is not fully materialized for overnight dataset auditing.",
                "mac_shutdown_safe": False,
                "fallback": "Rebuild benchmark outputs on codex-remote before shutdown.",
            }
        )
    if report["checks"]["repo_banned_files"]:
        report["blockers"].append(
            {
                "failed_component": "research_repo_safety",
                "impact": "Unsafe binary or model artifacts are present in the research repo.",
                "mac_shutdown_safe": False,
                "fallback": "Remove or ignore the flagged files before shutdown.",
            }
        )
    if "qemu-system-aarch64" not in report["checks"]["workhorse_qemu"]["output"]:
        report["warnings"].append("Workhorse Pi/ESP32 QEMU support is not yet verified as present; emulation remains support evidence only.")
    if report["checks"]["dashboard_http"]["returncode"] != 0:
        report["warnings"].append("Dashboard TCP check failed; monitoring and Prometheus should be consulted before using the dashboard as evidence.")
    if report["checks"]["mariadb_tcp"]["returncode"] != 0:
        report["warnings"].append("MariaDB TCP check failed; dataset family status may be stale if SQL access is down.")

    report["safe_to_shutdown_mac"] = not report["blockers"]

    out_dir = RESEARCH_ROOT / "evidence" / "night_checks"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = out_dir / f"night_check_{stamp}.json"
    md_path = out_dir / f"night_check_{stamp}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# codex-remote Night Check",
        "",
        f"- Created UTC: `{report['created_utc']}`",
        f"- Safe to shut down Mac: `{report['safe_to_shutdown_mac']}`",
        f"- Blocker count: `{len(report['blockers'])}`",
        f"- Warning count: `{len(report['warnings'])}`",
        "",
        "## Blockers",
    ]
    if report["blockers"]:
        for item in report["blockers"]:
            lines.append(f"- `{item['failed_component']}`: {item['impact']} Fallback: {item['fallback']}")
    else:
        lines.append("- None.")
    lines.extend(["", "## Warnings"])
    if report["warnings"]:
        for item in report["warnings"]:
            lines.append(f"- {item}")
    else:
        lines.append("- None.")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"json_path": str(json_path), "md_path": str(md_path), "safe_to_shutdown_mac": report["safe_to_shutdown_mac"], "blockers": report["blockers"], "warnings": report["warnings"]}, indent=2))
    return 0 if report["safe_to_shutdown_mac"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
