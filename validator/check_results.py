#!/usr/bin/env python3
"""
Check validation results with classification support
Supports both old validation format and new comparison-based classification
"""
import os
import sys
import json
import argparse
from pathlib import Path


def check_results(results_dir: str, classification_report: str = None, 
                 fail_on_bad_rules: bool = False):
    """Check validation results and classification report"""
    
    results_path = Path(results_dir)
    has_classification = classification_report and Path(classification_report).exists()
    
    print("\n" + "="*70)
    print("VALIDATION & CLASSIFICATION RESULTS")
    print("="*70)
    
    # Check if we have classification report (new method)
    if has_classification:
        print("\n🔍 CLASSIFICATION REPORT FOUND - Using comparison-based validation")
        check_classification_report(classification_report, fail_on_bad_rules)
    
    # Also check traditional validation results if they exist
    results_file = results_path / 'validation_results.json'
    if results_file.exists():
        print("\n📊 TRADITIONAL VALIDATION RESULTS")
        check_traditional_results(results_file)
    else:
        print("\n⚠️  No traditional validation results found")
    
    print("\n" + "="*70)


def check_classification_report(report_file: str, fail_on_bad_rules: bool):
    """Check classification report and determine pass/fail"""
    
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    summary = report.get('summary', {})
    rules = report.get('rules', [])
    
    print("\n" + "-"*70)
    print("📈 CLASSIFICATION SUMMARY")
    print("-"*70)
    
    total_rules = summary.get('total_rules', 0)
    avg_score = summary.get('average_score', 0)
    by_grade = summary.get('by_grade', {})
    
    print(f"\nTotal new rules analyzed: {total_rules}")
    print(f"Average quality score: {avg_score}/100")
    
    if by_grade:
        print("\n📊 Grade Distribution:")
        grade_order = ['EXCELLENT', 'GOOD', 'NEUTRAL', 'CONCERNING', 'BAD']
        for grade in grade_order:
            if grade in by_grade:
                count = by_grade[grade]
                icon = get_grade_icon(grade)
                print(f"  {icon} {grade:12} : {count} rule(s)")
    
    # Detailed rule results
    if rules:
        print("\n" + "-"*70)
        print("🔍 DETAILED RULE CLASSIFICATIONS")
        print("-"*70)
        
        for rule in sorted(rules, key=lambda r: r.get('score', 0), reverse=True):
            rule_name = rule.get('rule_name', 'Unknown')
            classification = rule.get('classification', 'UNKNOWN')
            score = rule.get('score', 0)
            triggered = rule.get('triggered', False)
            detection_count = rule.get('detection_count', 0)
            reasoning = rule.get('reasoning', 'No reasoning provided')
            
            icon = get_grade_icon(classification)
            
            print(f"\n{icon} {rule_name}")
            print(f"   Classification: {classification} (Score: {score}/100)")
            print(f"   Triggered: {'Yes' if triggered else 'No'} | Detections: {detection_count}")
            
            metrics = rule.get('metrics', {})
            if metrics:
                tp_delta = metrics.get('true_positive_delta', 0)
                fp_delta = metrics.get('false_positive_delta', 0)
                precision_delta = metrics.get('precision_delta', 0)
                
                print(f"   Impact:")
                if tp_delta != 0:
                    sign = '+' if tp_delta > 0 else ''
                    print(f"     • True Positives: {sign}{tp_delta}")
                if fp_delta != 0:
                    sign = '+' if fp_delta > 0 else ''
                    print(f"     • False Positives: {sign}{fp_delta}")
                if precision_delta != 0:
                    sign = '+' if precision_delta > 0 else ''
                    print(f"     • Precision: {sign}{precision_delta:.2%}")
            
            print(f"   Reasoning: {reasoning}")
    
    # Determine overall pass/fail
    bad_rules = by_grade.get('BAD', 0)
    concerning_rules = by_grade.get('CONCERNING', 0)
    
    print("\n" + "="*70)
    
    if fail_on_bad_rules:
        if bad_rules > 0:
            print(f"\n❌ VALIDATION FAILED")
            print(f"   {bad_rules} rule(s) classified as BAD")
            print(f"   These rules negatively impact detection quality")
            sys.exit(1)
        elif concerning_rules > 0:
            print(f"\n⚠️  VALIDATION PASSED WITH WARNINGS")
            print(f"   {concerning_rules} rule(s) classified as CONCERNING")
            print(f"   Review these rules for potential issues")
            sys.exit(0)
        else:
            print(f"\n✅ VALIDATION PASSED")
            print(f"   All new rules meet quality standards")
            sys.exit(0)
    else:
        # Just report, don't fail
        if bad_rules > 0 or concerning_rules > 0:
            print(f"\n⚠️  QUALITY CONCERNS DETECTED")
            print(f"   BAD: {bad_rules} | CONCERNING: {concerning_rules}")
            print(f"   (Not failing due to fail_on_bad_rules=False)")
        else:
            print(f"\n✅ ALL RULES MEET QUALITY STANDARDS")
        sys.exit(0)


def check_traditional_results(results_file: Path):
    """Check traditional validation results format"""
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    print("-"*70)
    
    total_passed = results.get('total_passed', 0)
    total_failed = results.get('total_failed', 0)
    total_tested = total_passed + total_failed
    mode = results.get('mode', 'unknown')
    
    print(f"Mode: {mode.upper()}")
    print(f"Total rules tested: {total_tested}")
    print(f"✅ Passed: {total_passed}")
    print(f"❌ Failed: {total_failed}")
    
    if total_tested > 0:
        pass_rate = (total_passed / total_tested * 100)
        print(f"Pass rate: {pass_rate:.1f}%")
    
    # Show detailed results if available
    details = results.get('details', [])
    if details:
        print("\n" + "-"*70)
        print("DETAILED RESULTS")
        print("-"*70)
        
        for detail in details:
            status_icon = "✅" if detail.get('passed') else "❌"
            rule_id = detail.get('rule_id', 'Unknown')
            rule_title = detail.get('rule_title', 'Untitled')
            
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
                
                if detection_rate < 50:
                    print(f"   ⚠️  Low detection rate - rule may need tuning")
                elif detection_rate == 100:
                    print(f"   🎯 Perfect detection!")
    
    # Check statistics
    stats_file = results_file.parent / 'statistics.json'
    if stats_file.exists():
        with open(stats_file, 'r') as f:
            stats = json.load(f)
        
        if stats:
            print("\n" + "-"*70)
            print("DETECTION STATISTICS")
            print("-"*70)
            
            total_events = stats.get('total_events_processed', 0)
            total_alerts = stats.get('total_alerts_generated', 0)
            
            print(f"Events processed: {total_events}")
            print(f"Alerts generated: {total_alerts}")
            
            if total_events > 0:
                alert_rate = (total_alerts / total_events * 100)
                print(f"Alert rate: {alert_rate:.2f}%")


def get_grade_icon(grade: str) -> str:
    """Get emoji icon for grade"""
    icons = {
        'EXCELLENT': '🌟',
        'GOOD': '✅',
        'NEUTRAL': '➖',
        'CONCERNING': '⚠️',
        'BAD': '❌'
    }
    return icons.get(grade, '❓')


def main():
    parser = argparse.ArgumentParser(description='Check validation results')
    parser.add_argument('--results-dir', default='validation_results', 
                       help='Directory containing validation results')
    parser.add_argument('--classification-report', 
                       help='Path to classification report JSON file')
    parser.add_argument('--fail-on-bad-rules', type=lambda x: x.lower() == 'true',
                       default=False,
                       help='Fail if BAD rules are detected (true/false)')
    args = parser.parse_args()
    
    check_results(args.results_dir, args.classification_report, args.fail_on_bad_rules)


if __name__ == '__main__':
    main()