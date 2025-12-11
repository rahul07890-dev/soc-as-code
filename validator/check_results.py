#!/usr/bin/env python3
"""
Check validation results with classification support
Supports both old validation format and new comparison-based classification

Behavior:
- Accepts classification reports where scores may be 0..1 or 0..100.
- Displays the raw average (percent) in the summary (e.g. "13.00 (13/100)").
- Applies transform: if value < 25 -> value * 4, else leave as-is (clamped to 100).
  - Final normalized score and rule classifications are based on the transformed values.
- Keeps icons for the grade distribution only. No icons printed next to individual rules.
"""
import os
import sys
import json
import argparse
from pathlib import Path
from typing import Any


def clamp(n, a=0, b=100):
    return max(a, min(b, n))


def normalize_to_percent(value: Any) -> float:
    """Normalize a score that may be in 0..1 or 0..100 ranges to a 0..100 float."""
    try:
        v = float(value)
    except Exception:
        return 0.0
    if v <= 1.0:
        return v * 100.0
    return v


def transform_score(score_pct: float) -> float:
    """If score < 25 -> multiply by 4, else leave. Clamp to 100."""
    try:
        s = float(score_pct)
    except Exception:
        s = 0.0
    if s < 25.0:
        s = s * 4.0
    return clamp(round(s, 2), 0, 100)


def get_risk_level(score: float) -> str:
    """Return risk level based on normalized score (0-100)."""
    if score >= 80:
        return "LOW RISK"
    elif score >= 60:
        return "MODERATE RISK"
    elif score >= 40:
        return "HIGH RISK"
    else:
        return "CRITICAL RISK"


def get_classification_from_score(score_percent: float) -> str:
    """Map a numeric score percentage (0-100) to a classification grade.

    New requested mapping:
      - < 50  => WEAK
      - 50-79 => NEUTRAL
      - >=80  => STRONG
    """
    try:
        s = float(score_percent)
    except Exception:
        s = 0.0

    if s >= 80.0:
        return "STRONG"
    elif s >= 50.0:
        return "NEUTRAL"
    else:
        return "WEAK"


def get_grade_icon(grade: str) -> str:
    icons = {
        'STRONG': '✅',
        'NEUTRAL': '➖',
        'WEAK': '❌'
    }
    return icons.get(grade, '')


def check_results(results_dir: str, classification_report: str = None,
                  fail_on_bad_rules: bool = False):
    """Check validation results and classification report"""

    results_path = Path(results_dir)
    has_classification = bool(classification_report and Path(classification_report).exists())

    print("\n" + "=" * 70)
    print("VALIDATION & CLASSIFICATION RESULTS")
    print("=" * 70)

    if has_classification:
        print("\nCLASSIFICATION REPORT FOUND - Using comparison-based validation")
        check_classification_report(classification_report, fail_on_bad_rules)

    # Traditional results (optional)
    results_file = results_path / 'validation_results.json'
    if results_file.exists():
        print("\nTRADITIONAL VALIDATION RESULTS")
        check_traditional_results(results_file)
    else:
        print("\nNo traditional validation results found")

    print("\n" + "=" * 70)


def check_classification_report(report_file: str, fail_on_bad_rules: bool):
    """Check classification report and determine pass/fail"""

    with open(report_file, 'r', encoding='utf-8') as f:
        report = json.load(f)

    summary = report.get('summary', {})
    rules = report.get('rules', [])

    print("\n" + "-" * 70)
    print("CLASSIFICATION SUMMARY")
    print("-" * 70)

    total_rules = int(summary.get('total_rules', 0))
    raw_avg = summary.get('average_score', 0)

    # Normalize raw average to percent for display
    avg_pct = normalize_to_percent(raw_avg)

    # Compute transformed average (for final/classification use)
    final_avg = transform_score(avg_pct)

    # Attempt to use provided by_grade if it exists, otherwise compute from transformed rule scores
    provided_by_grade = summary.get('by_grade', {}) or {}

    # If rules exist, recompute per-rule transformed classifications to ensure consistency
    computed_by_grade = {'STRONG': 0, 'NEUTRAL': 0, 'WEAK': 0}
    processed_rules = []

    for rule in rules:
        rule_name = rule.get('rule_name', rule.get('title', rule.get('rule_path', 'Unknown')))
        # Prefer 'score' field (already transformed by classifier). If absent, normalize and transform.
        if 'score' in rule:
            score_val = normalize_to_percent(rule.get('score', 0))
            # the report's 'score' may already be transformed; still apply transform to be safe (idempotent)
            transformed = transform_score(score_val)
        else:
            # maybe report contains raw_score or raw composite; try to fall back
            raw_score = rule.get('raw_score', rule.get('raw', rule.get('composite', 0)))
            raw_pct = normalize_to_percent(raw_score)
            transformed = transform_score(raw_pct)

        classification = get_classification_from_score(transformed)
        triggered = rule.get('triggered', False)
        detection_count = rule.get('detection_count', 0)
        reasoning = rule.get('reasoning', 'No reasoning provided')
        metrics = rule.get('metrics', {})

        computed_by_grade[classification] = computed_by_grade.get(classification, 0) + 1

        processed_rules.append({
            'rule_name': rule_name,
            'classification': classification,
            'score': transformed,
            'triggered': triggered,
            'detection_count': detection_count,
            'reasoning': reasoning,
            'metrics': metrics
        })

    # Choose which by_grade to display: prefer computed_by_grade if rules were present, else provided_by_grade
    by_grade = computed_by_grade if processed_rules else provided_by_grade

    print(f"\nTotal new rules analyzed: {total_rules}")
    print(f"Average quality score: {avg_pct:.2f} ({avg_pct:.0f}/100)")

    if by_grade:
        print("\nGrade Distribution:")
        grade_order = ['STRONG', 'NEUTRAL', 'WEAK']
        for grade in grade_order:
            cnt = by_grade.get(grade, 0)
            if cnt:
                icon = get_grade_icon(grade)
                print(f"  {icon} {grade:12} : {cnt} rule(s)")

    # Detailed rule classifications (sorted by transformed score desc)
    if processed_rules:
        print("\n" + "-" * 70)
        print("DETAILED RULE CLASSIFICATIONS")
        print("-" * 70)

        processed_rules.sort(key=lambda r: r.get('score', 0), reverse=True)
        for r in processed_rules:
            print(f"\n{r['rule_name']}")
            print(f"   Classification: {r['classification']} (Score: {r['score']:.0f}/100)")
            print(f"   Triggered: {'Yes' if r['triggered'] else 'No'} | Detections: {r['detection_count']}")
            if r.get('metrics'):
                tp_delta = r['metrics'].get('true_positive_delta', 0)
                fp_delta = r['metrics'].get('false_positive_delta', 0)
                precision_delta = r['metrics'].get('precision_delta', None)

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

    # final_avg is the transformed average used for classification/risk
    risk_level = get_risk_level(final_avg)

    # Print final normalized score (transformed)
    print("\nFINAL SCORE")
    print(f"   Score: {final_avg:.2f}")
    print(f"   Risk Level: {risk_level}")
    print("\n" + "=" * 70)

    # Pass/fail logic based on by_grade
    weak_rules = by_grade.get('WEAK', 0)
    neutral_rules = by_grade.get('NEUTRAL', 0)

    if fail_on_bad_rules:
        if weak_rules > 0:
            print(f"\nVALIDATION FAILED — {weak_rules} WEAK rule(s)")
            sys.exit(1)
        elif neutral_rules > 0:
            print(f"\nVALIDATION PASSED WITH WARNINGS — {neutral_rules} neutral rule(s)")
            sys.exit(0)
        else:
            print(f"\nVALIDATION PASSED — All rules meet quality standard")
            sys.exit(0)

    else:
        if weak_rules > 0 or neutral_rules > 0:
            print(f"\nQUALITY CONCERNS DETECTED")
            print(f"   WEAK: {weak_rules} | NEUTRAL: {neutral_rules}")
        else:
            print(f"\nALL RULES MEET QUALITY STANDARDS")

        sys.exit(0)


def check_traditional_results(results_file: Path):
    """Check traditional validation results format"""

    with open(results_file, 'r', encoding='utf-8') as f:
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
        with open(stats_file, 'r', encoding='utf-8') as f:
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
