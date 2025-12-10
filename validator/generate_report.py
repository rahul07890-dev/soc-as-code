#!/usr/bin/env python3
"""
generate_report.py

Simple report generator for SOC-as-Code pipeline.

Usage:
    python generate_report.py --input-file artifacts/classification.json --output-json artifacts/report_summary.json --output-html artifacts/report.html

Features:
- Loads a JSON report (classification/comparison output).
- Prints a concise summary to stdout.
- Optionally writes a compact JSON summary and a basic HTML report for viewing in CI artifacts.
- Supports --debug flag to print extra information.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def summarize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    summary = {
        "total_rules": 0,
        "by_grade": {},
        "average_score": None,
        "total_delta": None,
        "baseline_detections": None,
        "current_detections": None,
    }

    # Try common shapes
    if "summary" in report:
        s = report["summary"]
        summary["total_rules"] = s.get("total_rules", 0)
        summary["by_grade"] = s.get("by_grade", {})
        summary["average_score"] = s.get("average_score")
        summary["total_delta"] = s.get("total_delta") or s.get("delta") or None
        summary["baseline_detections"] = s.get("baseline_detections", None)
        summary["current_detections"] = s.get("current_detections", None)
    else:
        # Fallback: try to infer from top-level fields
        summary["total_rules"] = len(report.get("rules", []))
        # aggregate grades
        grades = {}
        total_score = 0
        count_score = 0
        for r in report.get("rules", []):
            g = r.get("classification", "UNKNOWN")
            grades[g] = grades.get(g, 0) + 1
            sc = r.get("score")
            if isinstance(sc, (int, float)):
                total_score += sc
                count_score += 1
        summary["by_grade"] = grades
        summary["average_score"] = round(total_score / count_score, 2) if count_score else None

    return summary


def print_summary(summary: Dict[str, Any]):
    print("\n" + "=" * 60)
    print("SOC-as-Code — Classification Summary")
    print("=" * 60)
    print(f"Total rules analyzed: {summary.get('total_rules')}")
    print(f"Average score: {summary.get('average_score')}")
    print(f"Total delta (if available): {summary.get('total_delta')}")
    print(f"Baseline detections: {summary.get('baseline_detections')}")
    print(f"Current detections: {summary.get('current_detections')}\n")

    by_grade = summary.get("by_grade") or {}
    if by_grade:
        print("Grade distribution:")
        for g, c in sorted(by_grade.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {g}: {c}")
    else:
        print("No grade distribution available.")
    print("=" * 60 + "\n")


def write_json_summary(path: Path, summary: Dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"✅ JSON summary written to: {path}")


def write_html_report(path: Path, full_report: Dict[str, Any], summary: Dict[str, Any]):
    """Write a minimal HTML report for quick viewing in CI artifacts."""
    path.parent.mkdir(parents=True, exist_ok=True)

    title = "SOC-as-Code — Classification Report"
    html_parts = [
        "<!doctype html>",
        "<html>",
        "<head>",
        f"<meta charset='utf-8'><title>{title}</title>",
        "<style>body{font-family:Arial,Helvetica,sans-serif;padding:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f4f4f4}</style>",
        "</head>",
        "<body>",
        f"<h1>{title}</h1>",
        f"<p><strong>Total rules:</strong> {summary.get('total_rules')}</p>",
        f"<p><strong>Average score:</strong> {summary.get('average_score')}</p>",
        "<h2>Grade distribution</h2>",
        "<ul>",
    ]

    for g, c in (summary.get("by_grade") or {}).items():
        html_parts.append(f"<li>{g}: {c}</li>")

    html_parts.extend(["</ul>", "<h2>Rule details</h2>", "<table>", "<thead><tr><th>Rule</th><th>ID</th><th>Grade</th><th>Score</th><th>Reasoning</th></tr></thead>", "<tbody>"])

    for r in full_report.get("rules", []):
        name = r.get("rule_name") or r.get("rule_path") or "unknown"
        rid = r.get("rule_id") or ""
        grade = r.get("classification") or ""
        score = r.get("score") or ""
        reasoning = (r.get("reasoning") or "")[:300].replace("<", "&lt;").replace(">", "&gt;")
        html_parts.append(f"<tr><td>{name}</td><td>{rid}</td><td>{grade}</td><td>{score}</td><td>{reasoning}</td></tr>")

    html_parts.extend(["</tbody>", "</table>", "<hr>", "<pre style='white-space:pre-wrap;max-height:400px;overflow:auto;background:#fafafa;padding:10px;border:1px solid #eee'>", "Full report (JSON):", "</pre>", "</body>", "</html>"])

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))

    print(f"✅ HTML report written to: {path}")


def main():
    parser = argparse.ArgumentParser(description="Generate human-friendly reports from classification JSON")
    parser.add_argument("--input-file", required=True, help="Path to classification JSON file")
    parser.add_argument("--output-json", default="", help="Optional compact JSON summary output path")
    parser.add_argument("--output-html", default="", help="Optional HTML report output path")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        print("[DEBUG] Debug mode enabled for generate_report.py")
        print(f"[DEBUG] input_file={args.input_file} output_json={args.output_json} output_html={args.output_html}")

    input_path = Path(args.input_file)
    try:
        report = load_json(input_path)
    except Exception as e:
        print(f"❌ Failed to load input JSON: {e}")
        sys.exit(1)

    summary = summarize_report(report)

    print_summary(summary)

    if args.output_json:
        try:
            write_json_summary(Path(args.output_json), summary)
        except Exception as e:
            print(f"❌ Failed to write JSON summary: {e}")
            sys.exit(1)

    if args.output_html:
        try:
            write_html_report(Path(args.output_html), report, summary)
        except Exception as e:
            print(f"❌ Failed to write HTML report: {e}")
            sys.exit(1)

    # Success
    sys.exit(0)


if __name__ == "__main__":
    main()
