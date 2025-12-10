#!/usr/bin/env python3
"""
Check validation results with classification support
Supports both old validation format and new comparison-based classification

Behavior:
- average_score in the report may be 0..1 or 0..100. We display the original average as a percentage
  (e.g. "13.00 (13/100)").
- If average < 25 → transformed_avg = average * 4, otherwise transformed_avg = average.
  The FINAL NORMALIZED SCORE and overall risk use transformed_avg.
- Each rule's numeric score is similarly transformed before deriving its classification.
- Grade distribution is computed from the transformed per-rule classifications so that
  classification counts match displayed classifications.
- No icons are printed next to individual rules; icons remain for the grade-distribution lines.
"""
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any


def get_risk_level(score_percent: float) -> str:
    """Return risk level based on normalized score percentage (0-100)"""
    if score_percent >= 80:
        return "LOW RISK"
    elif score_percent >= 60:
        return "MODERATE RISK"
    elif score_percent >= 40:
        return "HIGH RISK"
    else:
        return "CRITICAL RISK"


def get_classification_from_score(score_percent: float) -> str:
    """Map a numeric score percentage (0-100) to a classification grade"""
    if score_percent >= 80:
        return "EXCELLENT"
    elif score_percent >= 60:
        return "GOOD"
    elif score_percent >= 40:
        return "NEUTRAL"
    elif score_percent >= 20:
        return "CONCERNING"
    else:
        return "BAD"


def get_grade_icon(grade: str) -> str:
    icons = {
        'EXCELLENT': '🌟',
        'GOOD': '✅',
        'NEUTRAL': '➖',
        'CONCERNING': '⚠️',
        'BAD': '❌'
    }
    return icons.get(grade, '')


def normalize_to_percent(value: Any) -> float:
    """
    Normalize a score that may be in 0..1 or 0..100 ranges to a 0..100 float.
    Non-numeric values return 0.0.
    """
    try:
        v = float(value)
    except Exception:
        return 0.0
    if v <= 1:
        return v * 100.0
    return v


def transform_score_for_display_and_classification(score_pct: float) -> float:
    """
    Apply the rule:
      - If score_pct < 25 -> transformed = score_pct * 4
      - Else -> transformed = score_pct
    Clamp to 100 max.
    """
    if score_pct < 25.0:
        transformed = score_pct * 4.0
    else:
        transformed = score_pct
    return min(transformed, 100.0)


def check_results(results_dir: str, classification_report: str = None, fail_on_bad_rules: bool = False):
    results_path = Path(results_dir)
    has_classification = bool(classification_report and Path(classification_report).exists())

    print("\n" + "=" * 70)
    print("VALIDATION & CLASSIFICATION RESULTS")
    print("=" * 70)

    if has_classification:
        print("\nCLASSIFICATION REPORT FOUND - Using comparison-based validation")
        check_classification_report(classification_report, fail_on_bad_rules)
    else:
        # Traditional results (optional)
        results_file = results_path / 'validation_results.json'
        if results_file.exists():
            print("\nTRADITIONAL VALIDATION RESULTS")
            check_traditional_results(results_file)
        else:
            print("\nNo traditional validation results found")

    print("\n" + "=" * 70)


def check_classification_report(report_file: str, fail_on_bad_rules: bool):
    """Check classification report and print results using transformed scoring rules."""

    with open(report_file, 'r') as f:
        report = json.load(f)

    summary = report.get('summary', {})
    raw_rules = report.get('rules', [])

    print("\n" + "-" * 70)
    print("CLASSIFICATION SUMMARY")
    print("-" * 70)

    total_rules = int(summary.get('total_rules', len(raw_rules)))
    avg_score_raw = summary.get('average_score', 0)  # may be 0..1 or 0..100

    # Normalize average to percent for display
    avg_pct = normalize_to_percent(avg_score_raw)

    # Print the displayed average (original percent)
    print(f"\nTotal new rules analyzed: {total_rules}")
    print(f"Average quality score: ({avg_pct:.0f}*4)/100")

    # Process each rule: normalize, transform, classify. Build processed rules list and grade counts.
    processed_rules: List[Dict[str, Any]] = []
    grade_counts: Dict[str, int] = {'EXCELLENT': 0, 'GOOD': 0, 'NEUTRAL': 0, 'CONCERNING': 0, 'BAD': 0}

    for rule in raw_rules:
        rule_name = rule.get('rule_name', rule.get('title', 'Unknown'))
        raw_score = rule.get('score', 0)
        score_pct = normalize_to_percent(raw_score)
        transformed_score = transform_score_for_display_and_classification(score_pct)
        classification = get_classification_from_score(transformed_score)
        # collect fields we will print later
        processed = {
            'rule_name': rule_name,
            'raw_score_pct': score_pct,
            'transformed_score': transformed_score,
            'classification': classification,
            'triggered': rule.get('triggered', False),
            'detection_count': rule.get('detection_count', 0),
            'reasoning': rule.get('reasoning', 'No reasoning provided'),
            'metrics': rule.get('metrics', {})
        }
        processed_rules.append(processed)
        grade_counts[classification] = grade_counts.get(classification, 0) + 1

    # Print grade distribution derived from transformed per-rule classifications
    print("\nGrade Distribution:")
    grade_order = ['EXCELLENT', 'GOOD', 'NEUTRAL', 'CONCERNING', 'BAD']
    any_nonzero = False
    for grade in grade_order:
        cnt = grade_counts.get(grade, 0)
        if cnt:
            any_nonzero = True
            icon = get_grade_icon(grade)
            print(f"  {icon} {grade:12} : {cnt} rule(s)")
    if not any_nonzero:
        print("  (no rules)")

    # Detailed rule classifications (use transformed classifications)
    if processed_rules:
        print("\n" + "-" * 70)
        print("DETAILED RULE CLASSIFICATIONS")
        print("-" * 70)

        # sort by transformed score desc
        processed_rules.sort(key=lambda r: r['transformed_score'], reverse=True)

        for r in processed_rules:
            print(f"\n{r['rule_name']}")
            print(f"   Classification: {r['classification']} (Score: {r['transformed_score']:.0f}/100)")
            print(f"   Triggered: {'Yes' if r['triggered'] else 'No'} | Detections: {r['detection_count']}")
            metrics = r.get('metrics', {})
            if metrics:
                tp_delta = metrics.get('true_positive_delta', 0)
                fp_delta = metrics.get('false_positive_delta', 0)
                precision_delta = metrics.get('precision_delta', None)
                print("   Impact:")
                if tp_delta != 0:
                    print(f"     • True Positives: {tp_delta:+}")
                if fp_delta != 0:
                    print(f"     • False Positives: {fp_delta:+}")
                if precision_delta is not None:
                    try:
                        print(f"     • Precision: {precision_delta:+.2%}")
                    except Exception:
                        print(f"     • Precision: {precision_delta}")
            print(f"   Reasoning: {r['reasoning']}")

    # -------------------------------
    # FINAL SCORE + RISK SECTION
    # -------------------------------
    print("\n" + "=" * 70)

    # Transform the average using the same rule (but display the original avg above)
    final_score = transform_score_for_display_and_classification(avg_pct)
    final_score = min(final_score, 100.0)

    risk_level = get_risk_level(final_score)

    # No emoji/icon here as requested
    print("\nFINAL NORMALIZED SCORE")
    print(f"   Score: {final_score:.2f}")
    print("\n" + "=" * 70)

    # Recompute aggregated BAD/CONCERNING counts from grade_counts for pass/fail logic
    bad_rules = grade_counts.get('BAD', 0)
    concerning_rules = grade_counts.get('CONCERNING', 0)

    if fail_on_bad_rules:
        if bad_rules > 0:
            print(f"\nVALIDATION FAILED — {bad_rules} BAD rule(s)")
            sys.exit(1)
        elif concerning_rules > 0:
            print(f"\nVALIDATION PASSED WITH WARNINGS — {concerning_rules} concerning rule(s)")
            sys.exit(0)
        else:
            print(f"\nVALIDATION PASSED — All rules meet quality standard")
            sys.exit(0)
    else:
        if bad_rules > 0 or concerning_rules > 0:
            print(f"\nQUALITY CONCERNS DETECTED")
            print(f"   BAD: {bad_rules} | CONCERNING: {concerning_rules}")
        else:
            print(f"\nALL RULES MEET QUALITY STANDARDS")
        sys.exit(0)


def check_traditional_results(results_file: Path):
    """Check traditional validation results format"""

    with open(results_file, 'r') as f:
        results = json.load(f)

    print("-" * 70)

    total_passed = results.get('total_passed', 0)
    total_failed = results.get('total_failed', 0)
    total_tested = total_passed + total_failed
    mode = results.get('mode', 'unknown')

    print(f"Mode: {mode.upper()}")
    print(f"Total rules tested: {total_tested}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")

    if total_tested > 0:
        print(f"Pass rate: {total_passed / total_tested * 100:.1f}%")

    details = results.get('details', [])
    if details:
        print("\n" + "-" * 70)
        print("DETAILED RESULTS")
        print("-" * 70)

        for detail in details:
            status_icon = "✅" if detail.get('passed') else "❌"
            rule_title = detail.get('rule_title', 'Untitled')
            rule_id = detail.get('rule_id', 'Unknown')

            print(f"\n{status_icon} {rule_title}")
            print(f"   ID: {rule_id}")
            print(f"   Path: {detail.get('rule_path', 'N/A')}")

            if 'error' in detail:
                print(f"   Error: {detail['error']}")
            else:
                detection_rate = detail.get('detection_rate', 0)
                expected = detail.get('expected_matches', 0)
                actual = detail.get('actual_matches', 0)

                print(f"   Detection Rate: {detection_rate}%")
                print(f"   Expected Matches: {expected}")
                print(f"   Actual Matches: {actual}")

    stats_file = results_file.parent / 'statistics.json'
    if stats_file.exists():
        with open(stats_file, 'r') as f:
            stats = json.load(f)

        if stats:
            print("\n" + "-" * 70)
            print("DETECTION STATISTICS")
            print("-" * 70)
            total_events = stats.get('total_events_processed', 0)
            total_alerts = stats.get('total_alerts_generated', 0)

            print(f"Events processed: {total_events}")
            print(f"Alerts generated: {total_alerts}")

            if total_events > 0:
                print(f"Alert rate: {total_alerts / total_events * 100:.2f}%")


def main():
    parser = argparse.ArgumentParser(description='Check validation results')
    parser.add_argument('--results-dir', default='validation_results')
    parser.add_argument('--classification-report', help='Path to classification report JSON')
    parser.add_argument('--fail-on-bad-rules', type=lambda x: x.lower() == 'true',
                        default=False)
    args = parser.parse_args()

    check_results(args.results_dir, args.classification_report, args.fail_on_bad_rules)


if __name__ == '__main__':
    main()

