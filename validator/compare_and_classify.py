#!/usr/bin/env python3
"""
FINAL FIX: Proper classification with all 3 outcomes
- STRONG (>60): Rule adds significant detections
- NEUTRAL (40-60): Rule adds few detections or is redundant  
- WEAK (<40): Rule doesn't work or causes problems
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


class FinalFixedClassifier:
    """
    Final working classifier that produces all 3 outcomes correctly
    
    Logic:
    1. Find which rules triggered in CURRENT but not BASELINE (new rules)
    2. Count detections from each new rule
    3. Score based on actual contribution:
       - STRONG: Rule detects 10+ events (adds real value)
       - NEUTRAL: Rule detects 1-9 events (limited value) 
       - WEAK: Rule detects 0 events (not working)
    """
    
    def __init__(self, baseline_dir: Path, current_dir: Path):
        self.baseline_dir = baseline_dir
        self.current_dir = current_dir
        
        # Load detections
        self.baseline_detections = self._load_detections(baseline_dir)
        self.current_detections = self._load_detections(current_dir)
        
        # Build rule detection maps
        self.baseline_rules = self._build_rule_map(self.baseline_detections)
        self.current_rules = self._build_rule_map(self.current_detections)
        
        # Calculate totals
        self.baseline_total = len(self.baseline_detections)
        self.current_total = len(self.current_detections)
        self.delta = self.current_total - self.baseline_total
        
        print(f"\n📊 DETECTION ANALYSIS:")
        print(f"   Baseline rules: {len(self.baseline_rules)} rules -> {self.baseline_total} alerts")
        print(f"   Current rules: {len(self.current_rules)} rules -> {self.current_total} alerts")
        print(f"   Total delta: {self.delta:+d} alerts")
        print(f"\n   Baseline rule IDs: {sorted(list(self.baseline_rules.keys())[:5])}...")
        print(f"   Current rule IDs: {sorted(list(self.current_rules.keys())[:5])}...")
    
    def _load_detections(self, results_dir: Path) -> List[Dict]:
        """Load detections from results directory"""
        detections_file = results_dir / 'detections.json'
        if detections_file.exists():
            with open(detections_file, 'r') as f:
                return json.load(f)
        return []
    
    def _build_rule_map(self, detections: List[Dict]) -> Dict[str, List[Dict]]:
        """Build map of rule_id -> list of detections"""
        rule_map = defaultdict(list)
        
        for detection in detections:
            rule_id = self._extract_rule_id(detection)
            if rule_id and rule_id != 'unknown':
                rule_map[rule_id].append(detection)
        
        return dict(rule_map)
    
    def _extract_rule_id(self, detection: Dict) -> str:
        """Extract rule identifier - try multiple keys"""
        # Try standard keys
        for key in ['rule_id', 'rule_name', 'rule', 'id', 'title']:
            if key in detection and detection[key]:
                value = str(detection[key])
                # If it's a path, extract filename
                if '/' in value:
                    return Path(value).stem
                return value
        
        # Try raw data
        raw = detection.get('raw', {})
        if '_source_rule_id' in raw:
            return raw['_source_rule_id']
        
        return 'unknown'
    
    def classify_new_rule(self, rule_path: str) -> Dict:
        """
        Classify a new rule based on its actual contribution
        
        THE KEY INSIGHT:
        - New rules should appear in CURRENT but NOT in BASELINE
        - We count how many alerts this specific rule generated
        - Score based on actual value added
        """
        rule_name = Path(rule_path).stem
        
        print(f"\n🔍 ANALYZING: {rule_name}")
        print(f"   Rule path: {rule_path}")
        
        # Check presence
        in_baseline = rule_name in self.baseline_rules
        in_current = rule_name in self.current_rules
        
        print(f"   In baseline: {in_baseline}")
        print(f"   In current: {in_current}")
        
        # ERROR: Rule in baseline means it's not new!
        if in_baseline:
            baseline_count = len(self.baseline_rules[rule_name])
            current_count = len(self.current_rules.get(rule_name, []))
            
            return {
                'rule_name': rule_name,
                'rule_path': rule_path,
                'classification': 'ERROR',
                'score': 0,
                'reasoning': f'Rule exists in baseline ({baseline_count} alerts) - not a new rule! This should not happen.',
                'triggered': True,
                'detection_count': current_count,
                'metrics': {
                    'baseline_alerts': self.baseline_total,
                    'current_alerts': self.current_total,
                    'delta': self.delta,
                    'rule_baseline': baseline_count,
                    'rule_current': current_count
                }
            }
        
        # Count detections from THIS SPECIFIC RULE
        rule_detection_count = len(self.current_rules.get(rule_name, []))
        
        print(f"   Detections from this rule: {rule_detection_count}")
        print(f"   Total delta contributed: {self.delta:+d}")
        
        # SCORING LOGIC - This is the key!
        if rule_detection_count == 0:
            # Rule didn't trigger at all
            score = 25
            grade = 'WEAK'
            reasoning = 'Rule did not trigger on any logs. Either (1) log generator does not support this log source, (2) rule pattern is too specific, or (3) rule has syntax errors.'
        
        elif rule_detection_count >= 20:
            # Excellent - many detections
            score = 85
            grade = 'STRONG'
            reasoning = f'Excellent! Rule detected {rule_detection_count} events. High-value detection capability.'
        
        elif rule_detection_count >= 10:
            # Good - decent number of detections
            score = 70
            grade = 'STRONG'
            reasoning = f'Good detection capability with {rule_detection_count} alerts. Adds solid value.'
        
        elif rule_detection_count >= 5:
            # Moderate - some detections
            score = 55
            grade = 'NEUTRAL'
            reasoning = f'Moderate detection rate ({rule_detection_count} alerts). Rule works but has limited coverage.'
        
        elif rule_detection_count >= 2:
            # Low - few detections
            score = 45
            grade = 'NEUTRAL'
            reasoning = f'Low detection rate ({rule_detection_count} alerts). Rule is very narrow or test data is insufficient.'
        
        else:
            # Only 1 detection - barely working
            score = 35
            grade = 'WEAK'
            reasoning = f'Minimal detection ({rule_detection_count} alert). Rule may be too restrictive or needs refinement.'
        
        # Adjust score based on efficiency
        if rule_detection_count > 0:
            efficiency = rule_detection_count / self.current_total if self.current_total > 0 else 0
            
            if efficiency > 0.1:  # More than 10% of all alerts
                score += 10
                reasoning += f' High efficiency ({efficiency:.1%} of total alerts).'
            elif efficiency < 0.01 and rule_detection_count < 5:  # Less than 1%
                score -= 5
                reasoning += f' Low efficiency ({efficiency:.1%} of total alerts).'
        
        # Check if delta makes sense
        if rule_detection_count > 0 and self.delta == 0:
            score -= 10
            reasoning += ' Warning: Rule triggered but total alerts unchanged (possible duplicate detections).'
        
        # Clamp score
        score = max(0, min(100, score))
        
        # Re-determine grade after adjustments
        if score >= 60:
            grade = 'STRONG'
        elif score >= 40:
            grade = 'NEUTRAL'
        else:
            grade = 'WEAK'
        
        return {
            'rule_name': rule_name,
            'rule_path': rule_path,
            'classification': grade,
            'score': score,
            'reasoning': f'{grade}: {reasoning}',
            'triggered': rule_detection_count > 0,
            'detection_count': rule_detection_count,
            'metrics': {
                'baseline_total': self.baseline_total,
                'current_total': self.current_total,
                'delta': self.delta,
                'rule_contribution': rule_detection_count,
                'rule_contribution_pct': round(rule_detection_count / self.current_total * 100, 2) if self.current_total > 0 else 0
            },
            'debug_info': {
                'in_baseline': in_baseline,
                'in_current': in_current,
                'baseline_rules_count': len(self.baseline_rules),
                'current_rules_count': len(self.current_rules)
            }
        }


def parse_rule_list(rule_string: str) -> List[str]:
    """Parse comma-separated rule list"""
    if not rule_string or rule_string.strip() == '':
        return []
    return [r.strip() for r in rule_string.split(',') if r.strip()]


def main():
    parser = argparse.ArgumentParser(
        description='FINAL FIX: Proper classification with STRONG/NEUTRAL/WEAK outcomes'
    )
    parser.add_argument('--baseline-results', required=True, help='Baseline results directory')
    parser.add_argument('--current-results', required=True, help='Current results directory')
    parser.add_argument('--changed-sigma-rules', default='', help='Comma-separated Sigma rules')
    parser.add_argument('--changed-yara-rules', default='', help='Comma-separated YARA rules')
    parser.add_argument('--output-file', required=True, help='Output classification report')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    baseline_dir = Path(args.baseline_results)
    current_dir = Path(args.current_results)
    output_file = Path(args.output_file)
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Parse changed rules
    changed_sigma = parse_rule_list(args.changed_sigma_rules)
    changed_yara = parse_rule_list(args.changed_yara_rules)
    
    if not changed_sigma and not changed_yara:
        print("⚠️  No changed rules to classify")
        report = {
            'summary': {'total_rules': 0, 'by_grade': {}, 'average_score': 0},
            'rules': []
        }
    else:
        # Initialize classifier
        print("="*70)
        print("INITIALIZING CLASSIFIER")
        print("="*70)
        classifier = FinalFixedClassifier(baseline_dir, current_dir)
        
        # Classify each new rule
        classifications = []
        
        print("\n" + "="*70)
        print("CLASSIFYING NEW RULES")
        print("="*70)
        
        for rule_path in changed_sigma:
            result = classifier.classify_new_rule(rule_path)
            classifications.append(result)
            
            print(f"\n✅ RESULT: {result['classification']} (Score: {result['score']}/100)")
            print(f"   {result['reasoning']}")
        
        for rule_path in changed_yara:
            result = classifier.classify_new_rule(rule_path)
            classifications.append(result)
        
        # Generate summary
        grade_counts = defaultdict(int)
        total_score = 0
        
        for c in classifications:
            grade_counts[c['classification']] += 1
            total_score += c['score']
        
        avg_score = total_score / len(classifications) if classifications else 0
        
        report = {
            'summary': {
                'total_rules': len(classifications),
                'by_grade': dict(grade_counts),
                'average_score': round(avg_score, 2)
            },
            'rules': classifications
        }
    
    # Save report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{'='*70}")
    print("📊 FINAL CLASSIFICATION SUMMARY")
    print(f"{'='*70}")
    print(f"Total rules analyzed: {report['summary']['total_rules']}")
    print(f"Average score: {report['summary']['average_score']}/100")
    print(f"\n🎯 Grade Distribution:")
    
    grade_order = ['STRONG', 'NEUTRAL', 'WEAK', 'ERROR']
    for grade in grade_order:
        if grade in report['summary']['by_grade']:
            count = report['summary']['by_grade'][grade]
            icon = {'STRONG': '💪', 'NEUTRAL': '➖', 'WEAK': '⚠️', 'ERROR': '❌'}.get(grade, '❓')
            print(f"   {icon} {grade}: {count} rule(s)")
    
    print(f"{'='*70}")
    print(f"\n✅ Report saved to: {output_file}")
    
    # Show what would make each grade
    print(f"\n💡 SCORING GUIDE:")
    print(f"   STRONG (60-100): Rule detects 10+ events")
    print(f"   NEUTRAL (40-59): Rule detects 2-9 events") 
    print(f"   WEAK (0-39): Rule detects 0-1 events")


if __name__ == '__main__':
    main()
