#!/usr/bin/env python3
"""
Generate human-readable summary report from classification results
"""
import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime


def generate_markdown_report(classification_report: str, output_file: str):
    """Generate a markdown summary report from classification results"""
    
    with open(classification_report, 'r') as f:
        report = json.load(f)
    
    summary = report.get('summary', {})
    rules = report.get('rules', [])
    
    # Start building the markdown report
    lines = []
    
    # Header
    lines.append("# 🛡️ Security Rule Quality Assessment Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Executive Summary
    lines.append("## 📊 Executive Summary")
    lines.append("")
    
    total_rules = summary.get('total_rules', 0)
    avg_score = summary.get('average_score', 0)
    by_grade = summary.get('by_grade', {})
    
    lines.append(f"- **Total New Rules Analyzed:** {total_rules}")
    lines.append(f"- **Average Quality Score:** {avg_score:.1f}/100")
    lines.append("")
    
    # Grade distribution with visual indicators
    if by_grade:
        lines.append("### Grade Distribution")
        lines.append("")
        
        grade_info = {
            'EXCELLENT': ('🌟', 'Exceptional quality - significantly improves detection'),
            'GOOD': ('✅', 'Good quality - positive impact on detection'),
            'NEUTRAL': ('➖', 'Neutral impact - no significant change'),
            'CONCERNING': ('⚠️', 'Concerning - may have issues or conflicts'),
            'BAD': ('❌', 'Poor quality - introduces problems')
        }
        
        for grade in ['EXCELLENT', 'GOOD', 'NEUTRAL', 'CONCERNING', 'BAD']:
            if grade in by_grade:
                count = by_grade[grade]
                icon, description = grade_info[grade]
                lines.append(f"- {icon} **{grade}**: {count} rule(s) - *{description}*")
        
        lines.append("")
    
    # Overall recommendation
    lines.append("### 🎯 Recommendation")
    lines.append("")
    
    bad_count = by_grade.get('BAD', 0)
    concerning_count = by_grade.get('CONCERNING', 0)
    good_count = by_grade.get('GOOD', 0) + by_grade.get('EXCELLENT', 0)
    
    if bad_count > 0:
        lines.append(f"⛔ **DO NOT MERGE** - {bad_count} rule(s) classified as BAD")
        lines.append("")
        lines.append("These rules negatively impact detection quality and should be revised or rejected.")
    elif concerning_count > 0:
        lines.append(f"⚠️ **REVIEW REQUIRED** - {concerning_count} rule(s) need attention")
        lines.append("")
        lines.append("Review the concerning rules before merging. They may need refinement.")
    elif good_count == total_rules and total_rules > 0:
        lines.append("✅ **APPROVED FOR MERGE** - All rules meet quality standards")
        lines.append("")
        lines.append("All new rules demonstrate positive or excellent detection capabilities.")
    else:
        lines.append("➖ **NEUTRAL** - Rules have minimal impact")
        lines.append("")
        lines.append("Rules may need more diverse test data or refinement to show value.")
    
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Detailed Rule Analysis
    if rules:
        lines.append("## 📋 Detailed Rule Analysis")
        lines.append("")
        
        # Sort rules by score (highest first)
        sorted_rules = sorted(rules, key=lambda r: r.get('score', 0), reverse=True)
        
        for i, rule in enumerate(sorted_rules, 1):
            rule_name = rule.get('rule_name', 'Unknown')
            classification = rule.get('classification', 'UNKNOWN')
            score = rule.get('score', 0)
            triggered = rule.get('triggered', False)
            detection_count = rule.get('detection_count', 0)
            rule_type = rule.get('rule_type', 'unknown')
            
            # Get icon for classification
            icon_map = {
                'EXCELLENT': '🌟',
                'GOOD': '✅',
                'NEUTRAL': '➖',
                'CONCERNING': '⚠️',
                'BAD': '❌'
            }
            icon = icon_map.get(classification, '❓')
            
            lines.append(f"### {i}. {icon} {rule_name}")
            lines.append("")
            lines.append(f"**Classification:** {classification} | **Score:** {score}/100 | **Type:** {rule_type.upper()}")
            lines.append("")
            
            # Detection information
            lines.append("**Detection Performance:**")
            lines.append(f"- Rule triggered: {'Yes ✓' if triggered else 'No ✗'}")
            lines.append(f"- Detection count: {detection_count}")
            lines.append("")
            
            # Impact metrics
            metrics = rule.get('metrics', {})
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
            
            # Reasoning
            reasoning = rule.get('reasoning', 'No reasoning provided')
            lines.append("**Assessment:**")
            lines.append(f"> {reasoning}")
            lines.append("")
            
            # Rule path
            rule_path = rule.get('rule_path', 'N/A')
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
    lines.append("- **EXCELLENT:** 80-100 points")
    lines.append("- **GOOD:** 65-79 points")
    lines.append("- **NEUTRAL:** 45-64 points")
    lines.append("- **CONCERNING:** 30-44 points")
    lines.append("- **BAD:** 0-29 points")
    lines.append("")
    
    # Write to file
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    print(f"[+] Generated markdown report: {output_path}")
    
    # Also print a summary to console
    print("\n" + "="*70)
    print("REPORT SUMMARY")
    print("="*70)
    print(f"Total rules: {total_rules}")
    print(f"Average score: {avg_score:.1f}/100")
    print("\nGrade distribution:")
    for grade, count in sorted(by_grade.items()):
        print(f"  {grade}: {count}")
    print("="*70)


def main():
    parser = argparse.ArgumentParser(
        description='Generate human-readable summary report from classification results'
    )
    parser.add_argument('--classification-report', required=True,
                       help='Path to classification report JSON file')
    parser.add_argument('--output-file', required=True,
                       help='Output markdown file path')
    
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