#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shlex
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

FULL_ARCHITECTURES = [
    "compact_cnn",
    "residual_small",
    "inception_small",
    "separable_extreme",
    "separable_lite",
    "mobilenet_tiny",
    "pi_depthwise_quant_candidate",
    "barcode_dilated",
    "random_reservoir",
    "patch_shuffle_cnn",
    "blurpool_cnn",
    "large_kernel_texture",
    "squeeze_excite_cnn",
    "multiscale_pyramid",
    "fixed_edge_bank",
]


def utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def run(cmd: list[str], timeout: int | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed rc={proc.returncode}: {shlex.join(cmd)}\n{proc.stdout}\n{proc.stderr}")
    return proc


def ssh(command: str, timeout: int | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["ssh", "workhorse", command], timeout=timeout, check=check)


def scp(src: Path, dst: str) -> None:
    run(["scp", str(src), dst], check=True)


def profile_config(profile: str) -> dict[str, object]:
    if profile == "short":
        return {
            "pairs": [(512, "rgb_triplet"), (256, "gray")],
            "runs": [("inception_small", 512, "rgb_triplet"), ("residual_small", 256, "gray")],
            "seeds": "1337,2026,4242",
            "epochs": 3,
            "patience": 1,
            "target_per_family": 20,
        }
    return {
        "pairs": [(256, "gray"), (256, "rgb_triplet"), (512, "gray"), (512, "rgb_triplet"), (1024, "gray"), (1024, "rgb_triplet")],
        "runs": [(arch, size, mode) for arch in FULL_ARCHITECTURES for size, mode in [(256, "gray"), (256, "rgb_triplet"), (512, "gray"), (512, "rgb_triplet"), (1024, "gray"), (1024, "rgb_triplet")]],
        "seeds": "1337,2027,4099",
        "epochs": 12,
        "patience": 3,
        "target_per_family": 20,
    }


def workhorse_status() -> dict[str, object]:
    cmd = (
        "python3 -c 'import subprocess,json; "
        "gpu=subprocess.check_output([\"nvidia-smi\",\"--query-gpu=utilization.gpu,memory.used,memory.total\","
        "\"--format=csv,noheader,nounits\"], text=True).strip(); "
        "ps=subprocess.run(\"ps -eo pid,args | grep -F vibex_planb_weekend_feedback_loop.py | grep -v grep\", shell=True, text=True, stdout=subprocess.PIPE); "
        "print(json.dumps({\"gpu\":gpu,\"loop\":ps.stdout.strip()}))'"
    )
    payload = json.loads(ssh(cmd, timeout=30).stdout)
    util, used, total = [int(part.strip()) for part in payload["gpu"].split(",")]
    payload.update({"gpu_util": util, "gpu_memory_used_mib": used, "gpu_memory_total_mib": total})
    payload["free"] = util < 10 and used < 512 and not payload.get("loop")
    return payload


def wait_until_free(max_wait_seconds: int, poll_seconds: int) -> dict[str, object]:
    start = time.time()
    stable_since = None
    last: dict[str, object] = {}
    while time.time() - start <= max_wait_seconds:
        last = workhorse_status()
        if last["free"]:
            stable_since = stable_since or time.time()
            if time.time() - stable_since >= 600:
                return last
        else:
            stable_since = None
        time.sleep(poll_seconds)
    last["wait_timeout"] = True
    last["free"] = False
    return last


def convert_manifest(src: Path, dst: Path, pairs: list[tuple[int, str]]) -> int:
    rows = list(csv.DictReader(src.open(newline="", encoding="utf-8-sig")))
    out = []
    for row in rows:
        family = str(row.get("consensus_family") or row.get("family") or "").strip().lower()
        sha = str(row.get("raw_sha256") or row.get("sha256_hash") or "").strip().lower()
        image_path = str(row.get("dataset_image_path") or row.get("image_path") or "").strip()
        if not family or len(sha) != 64 or not image_path:
            continue
        for image_size, image_mode in pairs:
            item = dict(row)
            item.update({"sha256_hash": sha, "family": family, "image_path": image_path, "image_size": str(image_size), "image_mode": image_mode})
            out.append(item)
    dst.parent.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys(key for row in out for key in row))
    with dst.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(out)
    return len(out)


def model_command(remote_root: str, run_id: str, manifest: str, label: str, arch: str, size: int, mode: str, cfg: dict[str, object]) -> str:
    return (
        f"cd {shlex.quote(remote_root)} && "
        "python3 tools/vibex_planb_native_family_experiment.py "
        f"--image-manifest input/{shlex.quote(manifest)} "
        f"--output-root {shlex.quote(remote_root)}/model_sweeps "
        f"--run-id {shlex.quote(run_id + '_' + label + '_' + arch + '_' + str(size) + '_' + mode)} "
        f"--architectures {shlex.quote(arch)} --image-sizes {size} --image-modes {shlex.quote(mode)} "
        f"--seeds {shlex.quote(str(cfg['seeds']))} --epochs {int(cfg['epochs'])} --patience {int(cfg['patience'])} "
        f"--target-per-family {int(cfg['target_per_family'])}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Queue VIBEX baseline-vs-augmented family model runs on workhorse.")
    parser.add_argument("--baseline-manifest", required=True)
    parser.add_argument("--augmented-manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--profile", choices=["short", "full"], default="short")
    parser.add_argument("--remote-root", default="/home/phil/vibex_secure_dataset/evidence/server2025_augmented_family_model")
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--max-wait-seconds", type=int, default=86400)
    parser.add_argument("--poll-seconds", type=int, default=600)
    parser.add_argument("--background", action="store_true")
    args = parser.parse_args()

    run_id = args.run_id or f"server2025_augmented_family_{utc_stamp()}"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    status = wait_until_free(args.max_wait_seconds, args.poll_seconds) if args.wait else workhorse_status()
    (output_dir / "workhorse_free_status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not status.get("free"):
        print(json.dumps({"queued": False, "reason": "workhorse_not_free", "status": status}, indent=2, sort_keys=True))
        return 2

    cfg = profile_config(args.profile)
    remote_root = f"{args.remote_root}/{run_id}"
    baseline_csv = output_dir / "family_core_baseline_model_manifest.csv"
    augmented_csv = output_dir / "family_augmented_experimental_model_manifest.csv"
    baseline_rows = convert_manifest(Path(args.baseline_manifest), baseline_csv, cfg["pairs"])
    augmented_rows = convert_manifest(Path(args.augmented_manifest), augmented_csv, cfg["pairs"])

    ssh(f"mkdir -p {shlex.quote(remote_root)}/input {shlex.quote(remote_root)}/tools {shlex.quote(remote_root)}/logs")
    scp(baseline_csv, f"workhorse:{remote_root}/input/family_core_baseline_model_manifest.csv")
    scp(augmented_csv, f"workhorse:{remote_root}/input/family_augmented_experimental_model_manifest.csv")
    scp(ROOT / "tools" / "vibex_planb_native_family_experiment.py", f"workhorse:{remote_root}/tools/")

    commands = []
    for arch, size, mode in cfg["runs"]:
        commands.append((model_command(remote_root, run_id, "family_core_baseline_model_manifest.csv", "baseline", arch, size, mode, cfg), f"logs/baseline_{arch}_{size}_{mode}.log"))
        commands.append((model_command(remote_root, run_id, "family_augmented_experimental_model_manifest.csv", "augmented", arch, size, mode, cfg), f"logs/augmented_{arch}_{size}_{mode}.log"))
    script = "#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(f"{cmd} > {log} 2>&1" for cmd, log in commands) + "\n"
    ssh(f"cat > {shlex.quote(remote_root)}/run_model_comparison.sh <<'EOF'\n{script}EOF\nchmod +x {shlex.quote(remote_root)}/run_model_comparison.sh")
    if args.background:
        ssh(f"cd {shlex.quote(remote_root)} && nohup ./run_model_comparison.sh > logs/runner.log 2>&1 & echo $! > model_comparison.pid")
    else:
        ssh(f"cd {shlex.quote(remote_root)} && ./run_model_comparison.sh", timeout=None)

    payload = {
        "queued": args.background,
        "run_id": run_id,
        "remote_root": remote_root,
        "profile": args.profile,
        "planned_model_runs": len(commands),
        "baseline_model_rows": baseline_rows,
        "augmented_model_rows": augmented_rows,
        "started_utc": datetime.now(UTC).isoformat(),
    }
    (output_dir / "model_queue_status.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
