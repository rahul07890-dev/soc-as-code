#!/usr/bin/env python3
"""
FIXED: Proper baseline vs current comparison
Calculates TRUE deltas and scores accurately
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


class FixedRuleClassifier:
    """Properly classifies rules by comparing baseline vs current detections"""
    
    def __init__(self, baseline_dir: Path, current_dir: Path):
        self.baseline_dir = baseline_dir
        self.current_dir = current_dir
        
        # Load results
        self.baseline_detections = self._load_detections(baseline_dir)
        self.current_detections = self._load_detections(current_dir)
        
        # Calculate metrics
        self.baseline_metrics = self._calculate_metrics(self.baseline_detections)
        self.current_metrics = self._calculate_metrics(self.current_detections)
        
        print(f"\n📊 METRICS COMPARISON:")
        print(f"   Baseline total alerts: {self.baseline_metrics['total_alerts']}")
        print(f"   Current total alerts: {self.current_metrics['total_alerts']}")
        print(f"   Delta: {self.current_metrics['total_alerts'] - self.baseline_metrics['total_alerts']}")
    
    def _load_detections(self, results_dir: Path) -> List[Dict]:
        """Load detections from results directory"""
        detections_file = results_dir / 'detections.json'
        if detections_file.exists():
            with open(detections_file, 'r') as f:
                return json.load(f)
        return []
    
    def _extract_rule_id(self, detection: Dict) -> str:
        """Extract rule identifier with multiple fallbacks"""
        # Try all possible keys
        for key in ['rule_id', 'rule_name', 'rule', 'title', 'id']:
            if key in detection and detection[key]:
                value = str(detection[key])
                # Extract filename if it's a path
                if '/' in value:
                    return Path(value).stem
                return value
        return 'unknown'
    
    def _calculate_metrics(self, detections: List[Dict]) -> Dict:
        """Calculate comprehensive metrics from detections"""
        metrics = {
            'total_alerts': len(detections),
            'rules_triggered': set(),
            'alerts_per_rule': defaultdict(int),
            'unique_events_detected': set()
        }
        
        for detection in detections:
            rule_id = self._extract_rule_id(detection)
            
            if rule_id != 'unknown':
                metrics['rules_triggered'].add(rule_id)
                metrics['alerts_per_rule'][rule_id] += 1
            
            # Track unique events (avoid counting same event multiple times)
            event_signature = json.dumps(detection.get('raw', {}), sort_keys=True)
            metrics['unique_events_detected'].add(event_signature)
        
        return metrics
    
    def classify_new_rule(self, rule_path: str) -> Dict:
        """
        Classify a NEW rule by measuring its impact
        
        Key insight: A new rule should INCREASE total alerts if it's useful
        """
        rule_name = Path(rule_path).stem
        
        print(f"\n🔍 Analyzing NEW rule: {rule_name}")
        
        # Check if rule exists in baseline (it shouldn't for new rules)
        in_baseline = rule_name in self.baseline_metrics['rules_triggered']
        in_current = rule_name in self.current_metrics['rules_triggered']
        
        print(f"   In baseline: {in_baseline}")
        print(f"   In current: {in_current}")
        
        # This is a NEW rule - it should NOT be in baseline
        if in_baseline:
            return {
                'rule_name': rule_name,
                'classification': 'ERROR',
                'score': 0,
                'reasoning': 'Rule found in baseline - not a new rule!',
                'triggered': True,
                'detection_count': self.baseline_metrics['alerts_per_rule'][rule_name]
            }
        
        # Calculate ACTUAL impact of adding this rule
        baseline_total = self.baseline_metrics['total_alerts']
        current_total = self.current_metrics['total_alerts']
        alert_delta = current_total - baseline_total
        
        # Count detections from THIS rule specifically
        rule_detection_count = self.current_metrics['alerts_per_rule'].get(rule_name, 0)
        
        print(f"   Baseline total alerts: {baseline_total}")
        print(f"   Current total alerts: {current_total}")
        print(f"   Alert delta: {alert_delta}")
        print(f"   This rule's detections: {rule_detection_count}")
        
        # SCORING LOGIC - This is the fix!
        if not in_current or rule_detection_count == 0:
            # Rule didn't trigger - could be weak or needs better test data
            return {
                'rule_name': rule_name,
                'rule_path': rule_path,
                'classification': 'WEAK',
                'score': 30,
                'reasoning': 'Rule did not trigger any alerts. Possible issues: (1) Rule logic may be too restrictive, (2) Test data insufficient, (3) Rule pattern mismatch',
                'triggered': False,
                'detection_count': 0,
                'metrics': {
                    'baseline_alerts': baseline_total,
                    'current_alerts': current_total,
                    'alert_delta': alert_delta,
                    'rule_detections': 0
                }
            }
        
        # Rule triggered! Now evaluate quality
        score = 50  # Start at neutral
        reasoning_parts = []
        
        # PRIMARY SCORING: Did this rule ADD new detections?
        if alert_delta > 0:
            # Good! Rule is detecting new threats
            contribution_score = min(40, rule_detection_count * 5)
            score += contribution_score
            reasoning_parts.append(f'Added {rule_detection_count} new detection(s) (+{contribution_score} pts)')
        elif alert_delta == 0:
            # Rule triggered but didn't increase total alerts
            # This means it's redundant with existing rules
            score -= 20
            reasoning_parts.append(f'Rule redundant - detects events already caught by other rules (-20 pts)')
        else:
            # Weird case: total alerts decreased?
            score -= 30
            reasoning_parts.append(f'Total alerts decreased - possible rule conflict (-30 pts)')
        
        # SECONDARY SCORING: Detection volume
        if rule_detection_count > 20:
            score += 10
            reasoning_parts.append(f'High detection rate: {rule_detection_count} alerts (+10 pts)')
        elif rule_detection_count > 10:
            score += 5
            reasoning_parts.append(f'Moderate detection rate (+5 pts)')
        elif rule_detection_count <= 3:
            score -= 10
            reasoning_parts.append(f'Low detection rate: only {rule_detection_count} alerts (-10 pts)')
        
        # TERTIARY SCORING: Efficiency
        if rule_detection_count > 0:
            efficiency = rule_detection_count / current_total if current_total > 0 else 0
            if efficiency > 0.5:
                score += 10
                reasoning_parts.append(f'High efficiency: {efficiency:.1%} of all alerts (+10 pts)')
            elif efficiency < 0.05:
                score -= 5
                reasoning_parts.append(f'Low efficiency: {efficiency:.1%} of all alerts (-5 pts)')
        
        # Clamp score
        score = max(0, min(100, score))
        
        # Determine grade
        if score >= 75:
            grade = 'EXCELLENT'
        elif score >= 60:
            grade = 'GOOD'
        elif score >= 45:
            grade = 'NEUTRAL'
        elif score >= 30:
            grade = 'WEAK'
        else:
            grade = 'BAD'
        
        reasoning = '; '.join(reasoning_parts) if reasoning_parts else 'No significant impact'
        
        return {
            'rule_name': rule_name,
            'rule_path': rule_path,
            'classification': grade,
            'score': score,
            'reasoning': f"{grade}: {reasoning}",
            'triggered': True,
            'detection_count': rule_detection_count,
            'metrics': {
                'baseline_alerts': baseline_total,
                'current_alerts': current_total,
                'alert_delta': alert_delta,
                'rule_detections': rule_detection_count,
                'rule_contribution_pct': round(rule_detection_count / current_total * 100, 2) if current_total > 0 else 0
            }
        }


def parse_rule_list(rule_string: str) -> List[str]:
    """Parse comma-separated rule list"""
    if not rule_string or rule_string.strip() == '':
        return []
    return [r.strip() for r in rule_string.split(',') if r.strip()]


def main():
    parser = argparse.ArgumentParser(description='FIXED: Proper baseline vs current comparison')
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
        classifier = FixedRuleClassifier(baseline_dir, current_dir)
        
        # Classify each new rule
        classifications = []
        
        for rule_path in changed_sigma:
            print(f"\n{'='*70}")
            print(f"Classifying Sigma rule: {rule_path}")
            result = classifier.classify_new_rule(rule_path)
            classifications.append(result)
            
            print(f"\n✅ Result: {result['classification']} (Score: {result['score']}/100)")
            print(f"   {result['reasoning']}")
        
        for rule_path in changed_yara:
            print(f"\nClassifying YARA rule: {rule_path}")
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
    print("📊 CLASSIFICATION SUMMARY")
    print(f"{'='*70}")
    print(f"Total rules analyzed: {report['summary']['total_rules']}")
    print(f"Average score: {report['summary']['average_score']}/100")
    print("\nGrade Distribution:")
    for grade, count in sorted(report['summary']['by_grade'].items()):
        print(f"  {grade}: {count}")
    print(f"{'='*70}")
    
    print(f"\n✅ Report saved to: {output_file}")


if __name__ == '__main__':
    main()
