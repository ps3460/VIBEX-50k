#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return None


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, _ = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def csv_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def send_telegram(title: str, body: str) -> dict[str, object]:
    message = f"{title}\n\n{body}"
    proc = subprocess.run(
        ["ssh", "phil@10.64.0.62", "sudo /usr/local/bin/vibex_send_telegram_text.py"],
        input=message,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout[-1000:],
        "stderr": proc.stderr[-1000:],
    }


def load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_thresholds(total_rows: int) -> list[dict[str, int | str]]:
    raw: list[tuple[str, int, str]] = [
        ("first_100", 100, "100 samples"),
        ("first_250", 250, "250 samples"),
        ("first_500", 500, "500 samples"),
        ("halfway", (total_rows + 1) // 2, "half way"),
        ("three_quarters", (total_rows * 3 + 3) // 4, "3/4 complete"),
        ("full", total_rows, "full campaign"),
    ]
    for rows in range(1000, total_rows, 1000):
        raw.append((f"first_{rows}", rows, f"{rows:,} samples"))
    raw.sort(key=lambda item: item[1])
    seen: set[str] = set()
    out: list[dict[str, int | str]] = []
    for item in raw:
        if item[0] in seen:
            continue
        seen.add(item[0])
        out.append({"id": item[0], "rows": item[1], "label": item[2]})
    return out


def previous_thousand_time(threshold_times: dict[str, str], rows: int) -> tuple[int, datetime] | None:
    if rows % 1000 != 0 or rows <= 1000:
        return None
    previous_rows = rows - 1000
    previous_time = parse_utc(threshold_times.get(f"first_{previous_rows}", ""))
    if previous_time is None:
        return None
    return previous_rows, previous_time


def batch_number(batch_id: str) -> int | None:
    try:
        return int(str(batch_id).rsplit("_", 1)[-1])
    except (TypeError, ValueError):
        return None


def batch_label(value: int | None) -> str:
    if value is None:
        return "not known"
    return f"{value:04d}"


def result_summary(campaign_dir: Path, rows: list[dict[str, str]]) -> dict[str, object]:
    candidate_counts = Counter(row.get("candidate_status") or "blank" for row in rows)
    family_counts = Counter(
        row.get("tool_hint_family", "").strip().lower()
        for row in rows
        if row.get("tool_hint_family", "").strip()
    )
    completed_batches: list[int] = []
    for batch_csv in sorted((campaign_dir / "batches").glob("*/server2025_family_hints.csv")):
        completed = csv_count(batch_csv)
        status_path = batch_csv.parent / "server2025_batch_status.json"
        expected = None
        if status_path.exists():
            try:
                expected = int(load_json(status_path, {}).get("row_count") or 0)
            except (TypeError, ValueError):
                expected = None
        if completed and (expected is None or completed >= expected):
            number = batch_number(batch_csv.parent.name)
            if number is not None:
                completed_batches.append(number)
    latest_completed = max(completed_batches) if completed_batches else None
    current_batch = None if latest_completed is None else latest_completed + 1
    return {
        "candidate_counts": dict(candidate_counts),
        "top_families": family_counts.most_common(5),
        "latest_completed_batch": latest_completed,
        "current_batch": current_batch,
    }


def speed_summary(
    campaign_dir: Path,
    threshold_times: dict[str, str],
    new_rows: int,
    milestone_rows: int,
    now_utc: str,
) -> tuple[str, str]:
    current_time = parse_utc(now_utc)
    previous = previous_thousand_time(threshold_times, milestone_rows)
    if previous is not None and current_time is not None:
        previous_rows, previous_time = previous
        elapsed_seconds = max(1.0, (current_time - previous_time).total_seconds())
        rows_per_hour = round(1000 / (elapsed_seconds / 3600))
        return (
            f"about {rows_per_hour:,} rows/hour",
            f"The last 1,000 samples ({previous_rows:,}-{milestone_rows:,}) took {human_duration(elapsed_seconds)}.",
        )

    status_path = campaign_dir / "campaign_status.json"
    status = load_json(status_path, {})
    created = parse_utc(str(status.get("created_utc") or ""))
    if created is not None and current_time is not None:
        elapsed_seconds = max(1.0, (current_time - created).total_seconds())
        rows_per_hour = round(new_rows / (elapsed_seconds / 3600))
        return (f"about {rows_per_hour:,} rows/hour", "")
    return ("not enough data yet", "")


def simple_result_message(
    campaign_dir: Path,
    threshold: dict[str, int | str],
    thresholds: list[dict[str, int | str]],
    threshold_times: dict[str, str],
    source_rows: int,
    new_rows: int,
    combined_rows: int,
    total_rows: int,
    now_utc: str,
    rows: list[dict[str, str]],
) -> tuple[str, str]:
    summary = result_summary(campaign_dir, rows)
    counts = Counter(summary["candidate_counts"])
    useful = counts.get("supporting_hint", 0)
    no_hint = counts.get("no_hint", 0)
    conflicts = counts.get("conflict_needs_review", 0)
    errors_timeouts = counts.get("tool_timeout", 0) + counts.get("blocked_or_error", 0)
    speed, elapsed = speed_summary(campaign_dir, threshold_times, new_rows, int(threshold["rows"]), now_utc)
    next_threshold = next((item for item in thresholds if int(item["rows"]) > int(threshold["rows"])), None)
    top_families = summary["top_families"]
    if top_families:
        family_text = ", ".join(f"{name} ({count})" for name, count in top_families)
    else:
        family_text = "none yet"
    next_text = f"{int(next_threshold['rows']):,} samples" if next_threshold else "campaign complete"
    title = "VIBEX malware classification update"
    lines = [
        f"We have classified {combined_rows:,} of {total_rows:,} samples.",
        f"New Windows 11 sandbox rows: {new_rows:,}.",
        f"Earlier full-profile rows included: {source_rows:,}.",
        f"Useful family hints found: {useful:,}.",
        f"No hint: {no_hint:,}.",
        f"Conflicts needing review: {conflicts:,}.",
        f"Errors/timeouts: {errors_timeouts:,}.",
        f"Top family hints: {family_text}.",
        f"Latest completed batch: {batch_label(summary['latest_completed_batch'])}.",
        f"Current batch: {batch_label(summary['current_batch'])}.",
        f"Speed: {speed}.",
    ]
    if elapsed:
        lines.append(elapsed)
    lines.extend(
        [
            f"Next update at {next_text}.",
            f"UTC: {now_utc}",
        ]
    )
    return title, "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Send Telegram notifications at Server 2025 campaign progress thresholds.")
    parser.add_argument("--campaign-dir", required=True)
    parser.add_argument("--source-completed-rows", type=int, required=True)
    parser.add_argument("--total-rows", type=int, required=True)
    parser.add_argument("--poll-seconds", type=int, default=300)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    campaign_dir = Path(args.campaign_dir)
    hints_path = campaign_dir / "server2025_family_hints.csv"
    state_path = campaign_dir / "threshold_notifier_status.json"
    log_path = campaign_dir / "threshold_notifier.log"

    state = load_json(state_path, {"sent": [], "created_utc": utc_now()})
    sent = set(state.get("sent", []))
    threshold_times = dict(state.get("threshold_times") or {})
    thresholds = build_thresholds(args.total_rows)

    while True:
        now_utc = utc_now()
        rows = csv_rows(hints_path)
        new_rows = len(rows)
        combined_rows = args.source_completed_rows + new_rows
        crossed = [item for item in thresholds if int(item["rows"]) <= combined_rows and item["id"] not in sent]
        next_threshold = next((item for item in thresholds if item["id"] not in sent), None)
        payload = {
            "updated_utc": now_utc,
            "campaign_dir": str(campaign_dir),
            "new_completed_rows": new_rows,
            "source_completed_rows": args.source_completed_rows,
            "combined_completed_rows": combined_rows,
            "total_rows": args.total_rows,
            "sent": sorted(sent),
            "threshold_times": threshold_times,
            "next_threshold": next_threshold,
        }

        if crossed:
            for item in crossed:
                title, body = simple_result_message(
                    campaign_dir,
                    item,
                    thresholds,
                    threshold_times,
                    args.source_completed_rows,
                    new_rows,
                    combined_rows,
                    args.total_rows,
                    now_utc,
                    rows,
                )
                if args.dry_run:
                    telegram = {"returncode": 0, "stdout": body, "stderr": "", "dry_run": True}
                    print(f"{title}\n\n{body}")
                else:
                    telegram = send_telegram(title, body)
                if int(telegram.get("returncode") or 0) == 0:
                    sent.add(str(item["id"]))
                    threshold_times.setdefault(str(item["id"]), now_utc)
                payload.setdefault("telegrams", []).append({"threshold": item, "telegram": telegram})

            payload["sent"] = sorted(sent)
            payload["threshold_times"] = threshold_times
            payload["next_threshold"] = next((item for item in thresholds if item["id"] not in sent), None)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True) + "\n")

        write_json(state_path, payload)
        if args.once or combined_rows >= args.total_rows:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
