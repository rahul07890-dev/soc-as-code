#!/usr/bin/env python3
"""
Compare baseline vs current rule validation results and classify new rules.
"""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


class RuleClassifier:
    """Classifies new rules based on detection performance comparison."""
    
    def __init__(self, baseline_dir: Path, current_dir: Path):
        self.baseline_dir = baseline_dir
        self.current_dir = current_dir
        self.baseline_results = self._load_results(baseline_dir)
        self.current_results = self._load_results(current_dir)
        
    def _load_results(self, results_dir: Path) -> Dict:
        """Load validation results from directory."""
        results = {
            'detections': [],
            'false_positives': [],
            'true_positives': [],
            'rule_stats': {}
        }
        
        # Load detections file
        detections_file = results_dir / 'detections.json'
        if detections_file.exists():
            with open(detections_file, 'r') as f:
                results['detections'] = json.load(f)
        
        # Load statistics file
        stats_file = results_dir / 'statistics.json'
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                results['rule_stats'] = json.load(f)
        
        # Load other result files if they exist
        for result_type in ['false_positives', 'true_positives']:
            result_file = results_dir / f'{result_type}.json'
            if result_file.exists():
                with open(result_file, 'r') as f:
                    results[result_type] = json.load(f)
        
        return results
    
    def _get_rule_name(self, rule_path: str) -> str:
        """Extract rule name from path."""
        return Path(rule_path).stem
    
    def _calculate_metrics(self, results: Dict) -> Dict:
        """Calculate detection metrics from results."""
        metrics = {
            'total_detections': len(results.get('detections', [])),
            'true_positives': len(results.get('true_positives', [])),
            'false_positives': len(results.get('false_positives', [])),
            'rules_triggered': set(),
            'rule_detection_counts': defaultdict(int)
        }
        
        # Count detections per rule
        for detection in results.get('detections', []):
            rule_name = detection.get('rule_name') or detection.get('rule')
            if rule_name:
                metrics['rules_triggered'].add(rule_name)
                metrics['rule_detection_counts'][rule_name] += 1
        
        # Calculate precision if we have the data
        if metrics['total_detections'] > 0:
            metrics['precision'] = metrics['true_positives'] / metrics['total_detections']
        else:
            metrics['precision'] = 0.0
        
        return metrics
    
    def classify_rule(self, rule_path: str, rule_type: str) -> Dict:
        """
        Classify a single rule based on comparison of baseline vs current results.
        
        Returns classification with score and reasoning.
        """
        rule_name = self._get_rule_name(rule_path)
        
        baseline_metrics = self._calculate_metrics(self.baseline_results)
        current_metrics = self._calculate_metrics(self.current_results)
        
        # Check if new rule triggered any detections
        rule_triggered = rule_name in current_metrics['rules_triggered']
        detection_count = current_metrics['rule_detection_counts'].get(rule_name, 0)
        
        # Calculate delta metrics
        tp_delta = current_metrics['true_positives'] - baseline_metrics['true_positives']
        fp_delta = current_metrics['false_positives'] - baseline_metrics['false_positives']
        precision_delta = current_metrics['precision'] - baseline_metrics['precision']
        
        # Classification logic
        classification = self._determine_classification(
            rule_triggered=rule_triggered,
            detection_count=detection_count,
            tp_delta=tp_delta,
            fp_delta=fp_delta,
            precision_delta=precision_delta
        )
        
        return {
            'rule_name': rule_name,
            'rule_path': rule_path,
            'rule_type': rule_type,
            'classification': classification['grade'],
            'score': classification['score'],
            'triggered': rule_triggered,
            'detection_count': detection_count,
            'metrics': {
                'true_positive_delta': tp_delta,
                'false_positive_delta': fp_delta,
                'precision_delta': round(precision_delta, 4),
                'baseline_precision': round(baseline_metrics['precision'], 4),
                'current_precision': round(current_metrics['precision'], 4)
            },
            'reasoning': classification['reasoning']
        }
    
    def _determine_classification(self, rule_triggered: bool, detection_count: int,
                                   tp_delta: int, fp_delta: int, precision_delta: float) -> Dict:
        """
        Determine rule classification grade and score.
        
        Grades: EXCELLENT, GOOD, NEUTRAL, CONCERNING, BAD
        Score: 0-100
        """
        
        # Rule didn't trigger - could be good (no false positives) or bad (missed detections)
        if not rule_triggered:
            if fp_delta == 0 and tp_delta == 0:
                return {
                    'grade': 'NEUTRAL',
                    'score': 50,
                    'reasoning': 'Rule did not trigger on synthetic logs. May need more diverse test data.'
                }
            else:
                return {
                    'grade': 'CONCERNING',
                    'score': 30,
                    'reasoning': 'Rule did not trigger but overall metrics changed. Investigate for conflicts.'
                }
        
        # Rule triggered - analyze impact
        score = 50  # Base score
        reasoning_parts = []
        
        # True positive impact (weight: 40 points)
        if tp_delta > 0:
            tp_score = min(40, tp_delta * 10)
            score += tp_score
            reasoning_parts.append(f'Detected {tp_delta} new true positive(s) (+{tp_score} pts)')
        elif tp_delta < 0:
            tp_penalty = min(40, abs(tp_delta) * 10)
            score -= tp_penalty
            reasoning_parts.append(f'Missed {abs(tp_delta)} true positive(s) (-{tp_penalty} pts)')
        
        # False positive impact (weight: -30 points)
        if fp_delta > 0:
            fp_penalty = min(30, fp_delta * 10)
            score -= fp_penalty
            reasoning_parts.append(f'Generated {fp_delta} false positive(s) (-{fp_penalty} pts)')
        elif fp_delta < 0:
            fp_bonus = min(20, abs(fp_delta) * 5)
            score += fp_bonus
            reasoning_parts.append(f'Reduced {abs(fp_delta)} false positive(s) (+{fp_bonus} pts)')
        
        # Precision impact (weight: 20 points)
        if precision_delta > 0.1:
            score += 20
            reasoning_parts.append(f'Improved precision by {precision_delta:.2%} (+20 pts)')
        elif precision_delta < -0.1:
            score -= 20
            reasoning_parts.append(f'Decreased precision by {abs(precision_delta):.2%} (-20 pts)')
        
        # Detection volume consideration
        if detection_count > 10:
            reasoning_parts.append(f'High detection volume: {detection_count} triggers')
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        
        # Determine grade based on score
        if score >= 80:
            grade = 'EXCELLENT'
        elif score >= 65:
            grade = 'GOOD'
        elif score >= 45:
            grade = 'NEUTRAL'
        elif score >= 30:
            grade = 'CONCERNING'
        else:
            grade = 'BAD'
        
        reasoning = f"{grade}: {'; '.join(reasoning_parts)}" if reasoning_parts else grade
        
        return {
            'grade': grade,
            'score': score,
            'reasoning': reasoning
        }


def parse_rule_list(rule_string: str) -> List[str]:
    """Parse comma-separated rule list."""
    if not rule_string or rule_string.strip() == '':
        return []
    return [r.strip() for r in rule_string.split(',') if r.strip()]


def main():
    parser = argparse.ArgumentParser(
        description='Compare baseline vs current validation results and classify new rules'
    )
    parser.add_argument('--baseline-results', required=True, help='Baseline results directory')
    parser.add_argument('--current-results', required=True, help='Current results directory')
    parser.add_argument('--changed-sigma-rules', default='', help='Comma-separated Sigma rules')
    parser.add_argument('--changed-yara-rules', default='', help='Comma-separated YARA rules')
    parser.add_argument('--output-file', required=True, help='Output classification report file')
    
    args = parser.parse_args()
    
    baseline_dir = Path(args.baseline_results)
    current_dir = Path(args.current_results)
    output_file = Path(args.output_file)
    
    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Parse changed rules
    changed_sigma = parse_rule_list(args.changed_sigma_rules)
    changed_yara = parse_rule_list(args.changed_yara_rules)
    
    if not changed_sigma and not changed_yara:
        print("No changed rules to classify")
        classification_report = {
            'summary': {
                'total_rules': 0,
                'by_grade': {},
                'average_score': 0
            },
            'rules': []
        }
    else:
        # Initialize classifier
        classifier = RuleClassifier(baseline_dir, current_dir)
        
        # Classify all changed rules
        classifications = []
        
        for rule_path in changed_sigma:
            print(f"Classifying Sigma rule: {rule_path}")
            classification = classifier.classify_rule(rule_path, 'sigma')
            classifications.append(classification)
        
        for rule_path in changed_yara:
            print(f"Classifying YARA rule: {rule_path}")
            classification = classifier.classify_rule(rule_path, 'yara')
            classifications.append(classification)
        
        # Generate summary
        grade_counts = defaultdict(int)
        total_score = 0
        
        for c in classifications:
            grade_counts[c['classification']] += 1
            total_score += c['score']
        
        avg_score = total_score / len(classifications) if classifications else 0
        
        classification_report = {
            'summary': {
                'total_rules': len(classifications),
                'by_grade': dict(grade_counts),
                'average_score': round(avg_score, 2)
            },
            'rules': classifications
        }
    
    # Write report
    with open(output_file, 'w') as f:
        json.dump(classification_report, f, indent=2)
    
    print(f"\n{'='*60}")
    print("CLASSIFICATION SUMMARY")
    print(f"{'='*60}")
    print(f"Total rules analyzed: {classification_report['summary']['total_rules']}")
    print(f"Average score: {classification_report['summary']['average_score']}/100")
    print("\nGrade distribution:")
    for grade, count in sorted(classification_report['summary']['by_grade'].items()):
        print(f"  {grade}: {count}")
    print(f"{'='*60}")
    
    # Print individual rule results
    for rule in classification_report['rules']:
        print(f"\n{rule['rule_name']}: {rule['classification']} (Score: {rule['score']}/100)")
        print(f"  {rule['reasoning']}")
    
    print(f"\nClassification report saved to: {output_file}")


if __name__ == '__main__':
    main()