#!/usr/bin/env python3
"""
check_results.py

Checks detection result artifacts produced by the SOC-as-Code pipeline.

Behavior:
- Verifies that `detections.json` exists in both baseline and current result directories.
- Loads detection lists (expects JSON array).
- Prints totals and a short comparison summary.
- Exits with code 0 on success, 1 on error (missing files), 2 on negative delta (regression).
- Supports --debug to print extra info useful in CI.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any


def load_detections(path: Path, debug: bool = False) -> List[Dict[str, Any]]:
    detections_file = path / "detections.json"
    if not detections_file.exists():
        if debug:
            print(f"[DEBUG] Missing detections file: {detections_file}")
        raise FileNotFoundError(f"Detections file not found: {detections_file}")
    with open(detections_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"Detections file does not contain a JSON list: {detections_file}")
    if debug:
        print(f"[DEBUG] Loaded {len(data)} detections from {detections_file}")
    return data


def summarize_detections(dets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a tiny summary for printing/reporting."""
    summary = {"count": len(dets)}
    # Optionally collect top rule ids (best-effort)
    rule_counts = {}
    for d in dets:
        rid = d.get("rule_id") or d.get("rule") or d.get("id") or "unknown"
        rule_counts[rid] = rule_counts.get(rid, 0) + 1
    # sort top 5
    top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:5]
    summary["top_rules"] = top_rules
    return summary


def main():
    parser = argparse.ArgumentParser(description="Validate and compare detection result artifacts")
    parser.add_argument("--baseline-results", required=True, help="Path to baseline results directory")
    parser.add_argument("--current-results", required=True, help="Path to current results directory")
    parser.add_argument("--output-report", default="", help="Optional path to write a JSON summary report")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    baseline_dir = Path(args.baseline_results)
    current_dir = Path(args.current_results)

    if args.debug:
        print(f"[DEBUG] baseline_dir={baseline_dir}")
        print(f"[DEBUG] current_dir={current_dir}")

    # Load detections
    try:
        baseline_dets = load_detections(baseline_dir, debug=args.debug)
    except Exception as e:
        print(f"❌ ERROR loading baseline detections: {e}")
        sys.exit(1)

    try:
        current_dets = load_detections(current_dir, debug=args.debug)
    except Exception as e:
        print(f"❌ ERROR loading current detections: {e}")
        sys.exit(1)

    baseline_total = len(baseline_dets)
    current_total = len(current_dets)
    delta = current_total - baseline_total

    print("\n" + "=" * 60)
    print("Results check summary")
    print("=" * 60)
    print(f"Baseline detections: {baseline_total}")
    print(f"Current detections : {current_total}")
    print(f"Delta (current - baseline): {delta:+d}")

    if delta > 0:
        print("✅ New detections introduced by current run.")
    elif delta == 0:
        print("⚠️ No net change in detections.")
    else:
        print("❌ Negative delta — current detections are fewer than baseline (regression).")

    # Optional detailed summary
    baseline_summary = summarize_detections(baseline_dets)
    current_summary = summarize_detections(current_dets)

    if args.debug:
        print(f"[DEBUG] Baseline top rules: {baseline_summary['top_rules']}")
        print(f"[DEBUG] Current top rules : {current_summary['top_rules']}")

    # Write optional JSON report
    if args.output_report:
        out = {
            "baseline_total": baseline_total,
            "current_total": current_total,
            "delta": delta,
            "baseline_top_rules": baseline_summary["top_rules"],
            "current_top_rules": current_summary["top_rules"],
        }
        try:
            out_path = Path(args.output_report)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)
            print(f"\n✅ Summary report written to: {out_path}")
        except Exception as e:
            print(f"⚠️ Failed to write summary report: {e}")
            # Not fatal; continue

    # Exit behavior:
    # - missing files -> exit 1 (handled earlier)
    # - negative delta (regression) -> exit 2 so CI can treat specially
    # - otherwise exit 0
    if delta < 0:
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
