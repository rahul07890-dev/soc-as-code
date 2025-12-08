#!/usr/bin/env python3
"""
Diagnostic tool to analyze why rules aren't triggering
"""
import os
import sys
import json
import yaml
import argparse
from pathlib import Path
from typing import Dict, List, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from validator.validate_rules import EnhancedLogGenerator


def analyze_rule(rule_path: str):
    """Analyze a rule and explain what logs it needs"""
    
    print(f"\n{'='*70}")
    print(f"DIAGNOSTIC ANALYSIS: {rule_path}")
    print(f"{'='*70}\n")
    
    # Load rule
    try:
        with open(rule_path, 'r') as f:
            rule = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Error loading rule: {e}")
        return
    
    # Display rule metadata
    print("📋 RULE METADATA")
    print(f"   Title: {rule.get('title', 'N/A')}")
    print(f"   ID: {rule.get('id', 'N/A')}")
    print(f"   Level: {rule.get('level', 'N/A')}")
    print(f"   Status: {rule.get('status', 'N/A')}")
    
    # Display logsource
    logsource = rule.get('logsource', {})
    print(f"\n📂 LOGSOURCE")
    for key, value in logsource.items():
        print(f"   {key}: {value}")
    
    # Display detection logic
    detection = rule.get('detection', {})
    print(f"\n🔍 DETECTION LOGIC")
    
    # Show condition
    condition = detection.get('condition', 'N/A')
    print(f"   Condition: {condition}")
    
    # Show selections
    print(f"\n   Selections:")
    for key, value in detection.items():
        if key != 'condition' and isinstance(value, dict):
            print(f"\n   {key}:")
            for field, pattern in value.items():
                print(f"      {field}: {pattern}")
    
    # Generate and show sample logs
    print(f"\n🧪 SAMPLE SYNTHETIC LOGS")
    print(f"   Generating 3 positive and 2 negative samples...\n")
    
    try:
        logs = EnhancedLogGenerator.generate_for_sigma_rule(rule, count=3)
        
        positive_logs = [l for l in logs if l.get('_match_type') == 'positive']
        negative_logs = [l for l in logs if l.get('_match_type') == 'negative']
        
        print(f"   ✅ POSITIVE SAMPLES (should match):")
        for i, log in enumerate(positive_logs[:3], 1):
            # Remove metadata for cleaner display
            clean_log = {k: v for k, v in log.items() if not k.startswith('_')}
            print(f"\n   Sample {i}:")
            print(f"   {json.dumps(clean_log, indent=6)}")
        
        print(f"\n   ❌ NEGATIVE SAMPLES (should NOT match):")
        for i, log in enumerate(negative_logs[:2], 1):
            clean_log = {k: v for k, v in log.items() if not k.startswith('_')}
            print(f"\n   Sample {i}:")
            print(f"   {json.dumps(clean_log, indent=6)}")
        
    except Exception as e:
        print(f"   ⚠️  Error generating logs: {e}")
        import traceback
        traceback.print_exc()
    
    # Provide recommendations
    print(f"\n💡 RECOMMENDATIONS")
    
    if not detection or len(detection) == 1:
        print("   ⚠️  Rule has minimal detection logic")
        print("   → Consider adding more selection criteria")
    
    if not logsource:
        print("   ⚠️  No logsource specified")
        print("   → Add logsource to clarify expected log types")
    
    selections = [v for k, v in detection.items() if k != 'condition' and isinstance(v, dict)]
    if selections:
        total_fields = sum(len(s) for s in selections)
        if total_fields < 2:
            print("   ⚠️  Very few detection fields")
            print("   → Consider adding more fields for better accuracy")
    
    print(f"\n{'='*70}\n")


def analyze_test_coverage(rules_dir: str, synthetic_logs_dir: str):
    """Analyze coverage between rules and synthetic logs"""
    
    print(f"\n{'='*70}")
    print(f"TEST COVERAGE ANALYSIS")
    print(f"{'='*70}\n")
    
    rules_path = Path(rules_dir)
    logs_path = Path(synthetic_logs_dir)
    
    # Count rules
    rule_files = list(rules_path.rglob('*.yml')) + list(rules_path.rglob('*.yaml'))
    print(f"📋 Total rule files: {len(rule_files)}")
    
    # Load and analyze logs
    all_logs = []
    if logs_path.exists():
        for log_file in logs_path.rglob('*.jsonl'):
            with open(log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        all_logs.append(json.loads(line))
    
    print(f"📊 Total synthetic logs: {len(all_logs)}")
    
    if not all_logs:
        print("\n❌ NO SYNTHETIC LOGS FOUND!")
        print("   This is why your rules are showing as NEUTRAL")
        print("   → Run: python validator/generate_logs.py --rules-dir rules/sigma --output-dir synthetic_logs")
        return
    
    # Analyze log sources
    source_rules = {}
    for log in all_logs:
        source = log.get('_source_rule_id', 'unknown')
        source_rules[source] = source_rules.get(source, 0) + 1
    
    print(f"\n📈 Logs by source rule:")
    for rule_id, count in sorted(source_rules.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {rule_id}: {count} logs")
    
    if len(source_rules) > 10:
        print(f"   ... and {len(source_rules) - 10} more rules")
    
    # Check for specific rules
    print(f"\n🔍 Coverage check:")
    for rule_file in rule_files[:5]:  # Check first 5 rules
        rule_name = rule_file.stem
        log_count = source_rules.get(rule_name, 0)
        if log_count > 0:
            print(f"   ✅ {rule_name}: {log_count} logs")
        else:
            print(f"   ❌ {rule_name}: No logs found")
    
    print(f"\n{'='*70}\n")


def test_rule_matching(rule_path: str, synthetic_logs_dir: str):
    """Test if a rule actually matches its synthetic logs"""
    
    print(f"\n{'='*70}")
    print(f"RULE MATCHING TEST: {rule_path}")
    print(f"{'='*70}\n")
    
    from test import SOCSimulator, load_sigma_rules
    
    # Load rule
    rules = load_sigma_rules(rule_path)
    if not rules:
        print("❌ Failed to load rule")
        return
    
    rule = rules[0]
    rule_name = Path(rule_path).stem
    
    # Load synthetic logs
    logs_path = Path(synthetic_logs_dir)
    all_logs = []
    
    if logs_path.exists():
        for log_file in logs_path.rglob('*.jsonl'):
            with open(log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        all_logs.append(json.loads(line))
    
    if not all_logs:
        print("❌ No synthetic logs found")
        return
    
    print(f"📊 Testing against {len(all_logs)} synthetic logs...")
    
    # Filter logs for this rule
    rule_logs = [l for l in all_logs if l.get('_source_rule_id') == rule_name]
    print(f"📋 Found {len(rule_logs)} logs specifically for this rule")
    
    if not rule_logs:
        print(f"\n⚠️  No logs found for rule '{rule_name}'")
        print("   This means synthetic logs weren't generated for this rule")
        print("   → Regenerate logs including this rule")
        return
    
    # Run simulator
    simulator = SOCSimulator(sigma_rules=rules, yara_path=None)
    simulator.process_logs(rule_logs)
    
    alerts = simulator.export_alerts()
    rule_alerts = [a for a in alerts if a.get('rule_id') == rule.get('id')]
    
    print(f"\n🎯 Results:")
    print(f"   Expected matches: {len([l for l in rule_logs if l.get('_match_type') == 'positive'])}")
    print(f"   Actual matches: {len(rule_alerts)}")
    
    if rule_alerts:
        print(f"\n   ✅ Rule IS triggering on its synthetic logs!")
        print(f"   Sample alert:")
        print(f"   {json.dumps(rule_alerts[0], indent=6)}")
    else:
        print(f"\n   ❌ Rule is NOT triggering!")
        print(f"\n   🔍 Debugging info:")
        print(f"   Sample log that should match:")
        positive_log = next((l for l in rule_logs if l.get('_match_type') == 'positive'), None)
        if positive_log:
            clean = {k: v for k, v in positive_log.items() if not k.startswith('_')}
            print(f"   {json.dumps(clean, indent=6)}")
        print(f"\n   This suggests an issue with:")
        print(f"   1. Log generator not creating correct patterns")
        print(f"   2. Sigma rule syntax/condition issues")
        print(f"   3. SOCSimulator not processing correctly")
    
    print(f"\n{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(description='Diagnose rule validation issues')
    parser.add_argument('--rule', help='Path to specific rule to analyze')
    parser.add_argument('--rules-dir', help='Directory of rules to check coverage')
    parser.add_argument('--synthetic-logs-dir', help='Directory containing synthetic logs')
    parser.add_argument('--test-matching', action='store_true', 
                       help='Test if rule matches its synthetic logs')
    
    args = parser.parse_args()
    
    if args.rule:
        analyze_rule(args.rule)
        
        if args.test_matching and args.synthetic_logs_dir:
            test_rule_matching(args.rule, args.synthetic_logs_dir)
    
    if args.rules_dir and args.synthetic_logs_dir:
        analyze_test_coverage(args.rules_dir, args.synthetic_logs_dir)
    
    if not any([args.rule, args.rules_dir]):
        parser.print_help()


if __name__ == '__main__':
    main()
