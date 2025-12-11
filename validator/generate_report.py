#!/usr/bin/env python3
"""
Generate human-readable summary report from classification results.

This version is robust: it will use the 'score' field from each rule in the report as the
(transformed) score if present. If only raw_score or raw composite is present, it will
recompute the transformed score using the same rule:
    if raw < 25 -> transformed = raw * 4 (clamped to 100) else transformed = raw

Grade distributions and per-rule classification are computed from the transformed scores.

Updated grading system:
  - <50 -> WEAK
  - 50-79 -> NEUTRAL
  - 80-100 -> STRONG
"""
import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Any

def clamp(n, a=0, b=100):
    return max(a, min(b, n))

def normalize_to_percent(value: Any) -> float:
    try:
        v = float(value)
    except Exception:
        return 0.0
    # Accept both 0..1 and 0..100
    if v <= 1.0:
        return v * 100.0
    return v

def transform_score(score: float) -> float:
    try:
        s = float(score)
    except Exception:
        s = 0.0
    if s < 25.0:
        s = s * 4.0
    return clamp(round(s, 2), 0, 100)

def classify_score(score_pct: float) -> str:
    # New thresholds:
    #   >=80 -> STRONG
    #   >=50 -> NEUTRAL
    #   <50  -> WEAK
    try:
        s = float(score_pct)
    except Exception:
        s = 0.0
    if s >= 80:
        return "STRONG"
    if s >= 50:
        return "NEUTRAL"
    return "WEAK"

def generate_markdown_report(classification_report: str, output_file: str):
    with open(classification_report, 'r', encoding='utf-8') as f:
        report = json.load(f)

    summary = report.get('summary', {})
    rules = report.get('rules', [])

    # Process rules: ensure each rule has a transformed score and classification
    processed_rules = []
    transformed_scores = []
    for r in rules:
        # Prefer 'score' (already transformed) if present
        if "score" in r:
            raw_trans = normalize_to_percent(r.get("score", 0))
            transformed = transform_score(raw_trans)
        else:
            # fallback: use raw_score or raw composite (raw_score field name may vary)
            if "raw_score" in r:
                raw_val = normalize_to_percent(r.get("raw_score", 0))
            else:
                raw_val = normalize_to_percent(r.get("score", r.get("raw_score", 0)))
            transformed = transform_score(raw_val)
        transformed_scores.append(transformed)
        # derive classification from transformed
        classification = classify_score(transformed)
        proc = dict(r)  # copy original
        proc["transformed_score"] = transformed
        proc["transformed_classification"] = classification
        processed_rules.append(proc)

    total_rules = int(summary.get('total_rules', len(processed_rules)))
    # If report summary average isn't transformed, recompute average from transformed_scores
    avg_transformed = sum(transformed_scores) / len(transformed_scores) if transformed_scores else 0.0

    # Build by_grade distribution from transformed classifications
    by_grade = {'STRONG': 0, 'NEUTRAL': 0, 'WEAK': 0}
    for p in processed_rules:
        g = p.get("transformed_classification")
        if not g:
            g = classify_score(p.get("transformed_score", 0))
        by_grade[g] = by_grade.get(g, 0) + 1

    # Start building markdown
    lines = []
    lines.append("# 🛡️ Security Rule Quality Assessment Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 📊 Executive Summary")
    lines.append("")
    lines.append(f"- **Total New Rules Analyzed:** {total_rules}")
    # Show original average if present in summary (but ensure percent normalization), then show transformed average
    raw_avg = summary.get('average_score', None)
    if raw_avg is not None:
        raw_avg_pct = normalize_to_percent(raw_avg)
        lines.append(f"- **Average Quality Score:** {raw_avg_pct:.1f}/100 (Transformed: {avg_transformed:.1f}/100)")
    else:
        lines.append(f"- **Average Quality Score:** {avg_transformed:.1f}/100")
    lines.append("")

    # Grade distribution
    if any(v > 0 for v in by_grade.values()):
        lines.append("### Grade Distribution")
        lines.append("")
        grade_info = {
            'STRONG': ('✅', 'Strong detection quality'),
            'NEUTRAL': ('➖', 'Neutral / needs improvement'),
            'WEAK': ('❌', 'Weak — likely to introduce noise or miss detections')
        }
        for grade in ['STRONG', 'NEUTRAL', 'WEAK']:
            count = by_grade.get(grade, 0)
            if count:
                icon, description = grade_info[grade]
                lines.append(f"- {icon} **{grade}**: {count} rule(s) - *{description}*")
        lines.append("")

    # Recommendation section (based on transformed by_grade)
    lines.append("### 🎯 Recommendation")
    lines.append("")
    weak_count = by_grade.get('WEAK', 0)
    neutral_count = by_grade.get('NEUTRAL', 0)
    strong_count = by_grade.get('STRONG', 0)
    if weak_count > 0:
        lines.append(f"⛔ **DO NOT MERGE** - {weak_count} rule(s) classified as WEAK")
        lines.append("")
        lines.append("These rules negatively impact detection quality and should be revised or rejected.")
    elif neutral_count > 0 and strong_count == 0:
        lines.append(f"⚠️ **REVIEW REQUIRED** - {neutral_count} rule(s) need attention")
        lines.append("")
        lines.append("Review the neutral rules before merging. They may need refinement.")
    elif strong_count == total_rules and total_rules > 0:
        lines.append("✅ **APPROVED FOR MERGE** - All rules classified as STRONG")
        lines.append("")
        lines.append("All new rules demonstrate strong detection capabilities.")
    else:
        lines.append("➖ **MIXED** - Some rules are STRONG, others NEUTRAL/WEAK")
        lines.append("")
        lines.append("Consider fixing the WEAK rules and re-running validation.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Detailed Rule Analysis (use transformed values)
    if processed_rules:
        lines.append("## 📋 Detailed Rule Analysis")
        lines.append("")
        # sort by transformed_score desc
        processed_rules.sort(key=lambda r: r.get("transformed_score", 0), reverse=True)
        for i, r in enumerate(processed_rules, 1):
            rule_name = r.get('rule_name', r.get('rule_path', 'Unknown'))
            classification = r.get('transformed_classification', classify_score(r.get('transformed_score', 0)))
            score = r.get('transformed_score', 0)
            triggered = r.get('triggered', False)
            detection_count = r.get('detection_count', 0)
            rule_type = r.get('rule_type', 'unknown')
            icon_map = {'STRONG': '✅','NEUTRAL':'➖','WEAK':'❌'}
            icon = icon_map.get(classification, '❓')
            lines.append(f"### {i}. {icon} {rule_name}")
            lines.append("")
            lines.append(f"**Classification:** {classification} | **Score:** {score:.0f}/100 | **Type:** {rule_type.upper()}")
            lines.append("")
            lines.append("**Detection Performance:**")
            lines.append(f"- Rule triggered: {'Yes ✓' if triggered else 'No ✗'}")
            lines.append(f"- Detection count: {detection_count}")
            lines.append("")
            metrics = r.get('metrics', {})
            if metrics:
                lines.append("**Impact Analysis:**")
                tp_delta = metrics.get('true_positive_delta', 0)
                fp_delta = metrics.get('false_positive_delta', 0)
                precision_delta = metrics.get('precision_delta', 0)
                baseline_precision = metrics.get('baseline_precision', 0)
                current_precision = metrics.get('current_precision', 0)
                if tp_delta != 0:
                    sign = '➕' if tp_delta > 0 else '➖'
                    lines.append(f"- {sign} True Positives: {tp_delta:+d}")
                if fp_delta != 0:
                    sign = '➕' if fp_delta > 0 else '➖'
                    lines.append(f"- {sign} False Positives: {fp_delta:+d}")
                if precision_delta != 0:
                    sign = '➕' if precision_delta > 0 else '➖'
                    lines.append(f"- {sign} Precision Change: {precision_delta:+.2%}")
                lines.append(f"- Baseline Precision: {baseline_precision:.2%}")
                lines.append(f"- Current Precision: {current_precision:.2%}")
                lines.append("")
            reasoning = r.get('reasoning', 'No reasoning provided')
            lines.append("**Assessment:**")
            lines.append(f"> {reasoning}")
            lines.append("")
            rule_path = r.get('rule_path', 'N/A')
            lines.append(f"*File: `{rule_path}`*")
            lines.append("")
            lines.append("---")
            lines.append("")

    # Footer
    lines.append("## 📚 Understanding the Scores")
    lines.append("")
    lines.append("### Score Breakdown (0-100 scale)")
    lines.append("")
    lines.append("- **Base Score:** 50 points")
    lines.append("- **True Positive Detection:** +10 points per detection (max +40)")
    lines.append("- **False Positive Generation:** -10 points per false positive (max -30)")
    lines.append("- **Precision Improvement:** +20 points for >10% improvement")
    lines.append("- **Precision Degradation:** -20 points for >10% degradation")
    lines.append("")
    lines.append("### Grade Thresholds")
    lines.append("")
    lines.append("- **STRONG:** 80-100 points")
    lines.append("- **NEUTRAL:** 50-79 points")
    lines.append("- **WEAK:** 0-49 points")
    lines.append("")

    # Write to file
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"[+] Generated markdown report: {output_path}")

    # Console summary: print only final transformed average score
    print("\n" + "="*70)
    print("REPORT SUMMARY")
    print("="*70)
    print(f"Total rules: {total_rules}")
    print(f"Average score: {avg_transformed:.1f} / 100")
    print("\nGrade distribution:")
    for grade, count in by_grade.items():
        if count:
            print(f"  {grade}: {count}")
    print("="*70)


def main():
    parser = argparse.ArgumentParser(description='Generate human-readable summary report from classification results')
    parser.add_argument('--classification-report', required=True, help='Path to classification report JSON file')
    parser.add_argument('--output-file', required=True, help='Output markdown file path')
    args = parser.parse_args()

    try:
        generate_markdown_report(args.classification_report, args.output_file)
        print("\n✅ Report generation completed successfully")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error generating report: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
