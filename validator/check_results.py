#!/usr/bin/env python3
"""
check_results.py

Compatibility wrapper for CI:
- Accepts --results-dir and --classification-report
- Accepts --fail-on-bad-rules true/false
- Prints human-friendly summary using raw_score for classification and display (transformed) score for UX
- Triggered = True only when TP > 0
"""
import sys
import json
import argparse
from pathlib import Path

def parse_bool(s: str) -> bool:
    if isinstance(s, bool):
        return s
    if s is None:
        return False
    return str(s).lower() in ("1", "true", "yes", "y", "t")

def get_risk_level(score_display: float) -> str:
    """Risk tiers based on display/normalized score (0-100)"""
    try:
        s = float(score_display)
    except Exception:
        s = 0.0
    if s >= 80:
        return "LOW RISK"
    if s >= 60:
        return "MODERATE RISK"
    if s >= 40:
        return "HIGH RISK"
    return "CRITICAL RISK"

def load_report(report_path: Path):
    if not report_path.exists():
        raise FileNotFoundError(f"Classification report not found: {report_path}")
    try:
        return json.loads(report_path.read_text(encoding='utf-8'))
    except Exception as e:
        raise RuntimeError(f"Failed to parse classification report {report_path}: {e}")

def print_summary(report: dict):
    summary = report.get('summary', {})
    rules = report.get('rules', [])

    total_rules = int(summary.get('total_rules', 0))
    avg_display = float(summary.get('average_score', 0.0))

    print("\n" + "="*70)
    print("VALIDATION & CLASSIFICATION RESULTS")
    print("="*70)
    print("\nCLASSIFICATION SUMMARY")
    print("-"*70)
    print(f"Total new rules analyzed: {total_rules}")
    print(f"Average quality score (display): {avg_display:.2f} / 100")
    # additionally print raw average if we can compute it
    raw_scores = []
    for r in rules:
        if isinstance(r.get('raw_score'), (int, float)):
            raw_scores.append(float(r.get('raw_score')))
    if raw_scores:
        avg_raw = sum(raw_scores) / len(raw_scores)
        print(f"Average raw composite score: {avg_raw:.2f} / 100")
    print("")
    if summary.get('by_grade'):
        print("Grade Distribution:")
        # ensure consistent order
        grade_order = ['EXCELLENT','GOOD','NEUTRAL','CONCERNING','BAD']
        for g in grade_order:
            if g in summary['by_grade']:
                cnt = summary['by_grade'][g]
                icon = get_grade_icon(g)
                print(f"  {icon} {g:12} : {cnt} rule(s)")
    else:
        print("No grade distribution available")

    # Detailed
    if rules:
        print("\n" + "-"*70)
        print("DETAILED RULE CLASSIFICATIONS")
        print("-"*70)
        # sort by raw_score then display score
        def sort_key(r):
            return (r.get('raw_score', 0), r.get('score', 0))
        for rule in sorted(rules, key=sort_key, reverse=True):
            rn = rule.get('rule_name', 'Unknown')
            raw = rule.get('raw_score', None)
            disp = rule.get('score', None)
            cls = rule.get('classification', 'UNKNOWN')
            tp = rule.get('TP', 0)
            fp = rule.get('FP', 0)
            fn = rule.get('FN', 0)
            triggered = bool(rule.get('triggered', False))
            total_dets = rule.get('total_detections', 0)
            reasoning = rule.get('reasoning', 'No reasoning provided')

            # Print header line
            print(f"\n{rn}")
            if raw is not None:
                print(f"   Classification (raw): {cls} | Raw: {raw:.2f}/100 | Display: {disp:.2f}/100")
            else:
                print(f"   Classification: {cls} | Display: {disp:.2f}/100")

            # Trigger/detection lines
            print(f"   Triggered (TP>0): {'Yes' if triggered else 'No'} | TP: {tp} | Total detections: {total_dets}")
            # Impact/metrics
            print(f"   Impact: TP={tp} | FP={fp} | FN={fn}")
            print(f"   Reasoning: {reasoning}")

    # Final normalized/display score & risk
    print("\n" + "="*70)
    print("FINAL NORMALIZED SCORE")
    print("-"*70)
    print(f"   Score (display avg): {avg_display:.2f}")
    print(f"   Risk Level: {get_risk_level(avg_display)}")
    print("="*70 + "\n")

def get_grade_icon(grade: str) -> str:
    icons = {
        'EXCELLENT': '🌟',
        'GOOD': '✅',
        'NEUTRAL': '➖',
        'CONCERNING': '⚠️',
        'BAD': '❌'
    }
    return icons.get(grade, '❓')

def main():
    parser = argparse.ArgumentParser(description="Check validation results and classification report (CI-friendly)")
    parser.add_argument('--results-dir', default='validation_results',
                        help='Directory containing validation artifacts (default: validation_results)')
    parser.add_argument('--classification-report', default=None,
                        help='Path to classification report JSON file (if omitted, script looks for <results-dir>/classification_report.json)')
    parser.add_argument('--fail-on-bad-rules', default='false',
                        help='Fail run (exit non-zero) if bad/concerning rules found. Accepts true/false')
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    report_path = Path(args.classification_report) if args.classification_report else results_dir / 'classification_report.json'
    fail_on_bad = parse_bool(args.fail_on_bad_rules)

    try:
        report = load_report(report_path)
    except Exception as e:
        print(f"ERROR: Could not load classification report: {e}")
        sys.exit(2)

    # Print summary
    print_summary(report)

    # Decide pass/fail
    by_grade = report.get('summary', {}).get('by_grade', {})
    bad = int(by_grade.get('BAD', 0))
    concerning = int(by_grade.get('CONCERNING', 0))

    if fail_on_bad:
        if bad > 0:
            print(f"VALIDATION FAILED — {bad} BAD rule(s) found (fail-on-bad-rules enabled)")
            sys.exit(1)
        if concerning > 0:
            print(f"VALIDATION PASSED WITH WARNINGS — {concerning} concerning rule(s) found (fail-on-bad-rules enabled)")
            sys.exit(0)
        print("VALIDATION PASSED — All rules meet quality standard")
        sys.exit(0)
    else:
        if bad > 0 or concerning > 0:
            print("QUALITY CONCERNS DETECTED")
            print(f"  BAD: {bad} | CONCERNING: {concerning}")
            sys.exit(0)
        else:
            print("ALL RULES MEET QUALITY STANDARDS")
            sys.exit(0)

if __name__ == "__main__":
    main()
