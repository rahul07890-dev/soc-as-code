#!/usr/bin/env python3
"""
check_results.py

Validates detection results from both baseline and current runs and checks for:
 - missing or malformed results
 - delta calculation (current - baseline)
 - regression detection (negative delta)

Exit codes:
    0 = OK
    1 = Hard failure (missing files / unreadable / malformed)
    2 = Regression (current detections < baseline)
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


def load_detections(path: Path, debug: bool = False) -> List[Dict[str, Any]]:
    """
    Load detections.json from a results directory.
    Supports:
      - direct list
      - object with `detections` key
    """
    file_path = path / "detections.json"
    if not file_path.exists():
        if debug:
            print(f"[DEBUG] Missing detections file: {file_path}")
        raise FileNotFoundError(f"Missing detections.json in: {path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ValueError(f"Cannot read detections.json in {path}: {e}")

    # Normalize
    if isinstance(data, list):
        return data

    if isinstance(data, dict) and "detections" in data and isinstance(data["detections"], list):
        return data["detections"]

    raise ValueError(f"Invalid detections.json format in {path}. Must be list or {{\"detections\": [...]}}.")


def summarize_detections(dets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Provide simple diagnostics for debugging top rules.
    """
    summary = {"count": len(dets), "top_rules": []}

    rule_counts = {}
    for d in dets:
        rid = d.get("rule_id") or d.get("id") or "unknown"
        rule_counts[rid] = rule_counts.get(rid, 0) + 1

    top = sorted(rule_counts.items(), key=lambda x: -x[1])[:5]
    summary["top_rules"] = top
    return summary


def main():
    parser = argparse.ArgumentParser(description="Check baseline vs current detection results")
    parser.add_argument("--baseline-results", required=True, help="Baseline results directory")
    parser.add_argument("--current-results", required=True, help="Current results directory")
    parser.add_argument("--output-report", default="", help="Path to write JSON summary")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    baseline_dir = Path(args.baseline_results)
    current_dir = Path(args.current_results)

    if args.debug:
        print(f"[DEBUG] baseline_dir={baseline_dir}")
        print(f"[DEBUG] current_dir={current_dir}")

    # Load baseline
    try:
        baseline_dets = load_detections(baseline_dir, debug=args.debug)
    except Exception as e:
        print(f"❌ ERROR loading baseline results: {e}")
        sys.exit(1)

    # Load current
    try:
        current_dets = load_detections(current_dir, debug=args.debug)
    except Exception as e:
        print(f"❌ ERROR loading current results: {e}")
        sys.exit(1)

    baseline_total = len(baseline_dets)
    current_total = len(current_dets)
    delta = current_total - baseline_total

    print("\n" + "=" * 60)
    print("RESULTS CHECK SUMMARY")
    print("=" * 60)
    print(f"Baseline detections: {baseline_total}")
    print(f"Current detections : {current_total}")
    print(f"Delta              : {delta:+d}")
    print("=" * 60)

    # Interpret delta
    if delta > 0:
        print("✅ New detections added (GOOD)")
    elif delta == 0:
        print("⚠️ No change in detections")
    else:
        print("❌ Regression detected — fewer detections than baseline")

    # Optional verbose inspection
    if args.debug:
        base_summary = summarize_detections(baseline_dets)
        curr_summary = summarize_detections(current_dets)
        print(f"[DEBUG] Baseline top rules: {base_summary['top_rules']}")
        print(f"[DEBUG] Current top rules : {curr_summary['top_rules']}")

    # Optional output report
    if args.output_report:
        report = {
            "baseline_total": baseline_total,
            "current_total": current_total,
            "delta": delta,
            "regression": delta < 0,
        }
        try:
            out_path = Path(args.output_report)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"📄 Wrote summary report → {out_path}")
        except Exception as e:
            print(f"⚠️ Failed to write summary report: {e}")

    # Exit codes:
    #  2 = regression (negative delta)
    #  1 = file/malformed error (handled above)
    #  0 = OK
    if delta < 0:
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
