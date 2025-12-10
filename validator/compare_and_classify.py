#!/usr/bin/env python3
"""
ACTUAL FIX: Extract rule IDs from YAML files, not filenames
The issue: Detection JSON has rule_id from YAML (e.g., "SIG-001234")
           But we were matching against filename (e.g., "reg")
"""

import argparse
import json
import yaml
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


class WorkingClassifier:
    """
    Classifier that correctly matches rule IDs from YAML files
    """
    
    def __init__(self, baseline_dir: Path, current_dir: Path, rules_dir: Path):
        self.baseline_dir = baseline_dir
        self.current_dir = current_dir
        self.rules_dir = rules_dir
        
        # Load detections
        self.baseline_detections = self._load_detections(baseline_dir)
        self.current_detections = self._load_detections(current_dir)
        
        # Build rule detection maps (creates both ID and title indexes)
        self.baseline_rules = self._build_rule_map(self.baseline_detections)
        self.current_rules = self._build_rule_map(self.current_detections)
        
        # Now we have:
        # - self.baseline_rules (by ID)
        # - self.rule_map_by_id (baseline and current)
        # - self.rule_map_by_title (baseline and current)
        
        # Calculate totals
        self.baseline_total = len(self.baseline_detections)
        self.current_total = len(self.current_detections)
        self.delta = self.current_total - self.baseline_total
        
        print(f"\n📊 DETECTION ANALYSIS:")
        print(f"   Baseline: {len(self.baseline_rules)} unique rule IDs -> {self.baseline_total} alerts")
        print(f"   Current: {len(self.current_rules)} unique rule IDs -> {self.current_total} alerts")
        print(f"   Delta: {self.delta:+d} alerts")
        
        # DEBUG: Show sample rule IDs and titles
        print(f"\n🔍 Sample baseline rule IDs:")
        for rid in list(self.baseline_rules.keys())[:5]:
            print(f"      - {rid} ({len(self.baseline_rules[rid])} detections)")
        
        print(f"\n🔍 Sample current rule IDs:")
        for rid in list(self.current_rules.keys())[:5]:
            print(f"      - {rid} ({len(self.current_rules[rid])} detections)")
        
        # Show NEW rule IDs (in current but not baseline)
        new_rule_ids = set(self.current_rules.keys()) - set(self.baseline_rules.keys())
        if new_rule_ids:
            print(f"\n🆕 NEW rule IDs (in current but not baseline):")
            for rid in list(new_rule_ids)[:10]:
                print(f"      - {rid} ({len(self.current_rules[rid])} detections)")
        else:
            print(f"\n⚠️  No new rule IDs detected (current and baseline have same rule IDs)")
        
        # Show all unique rule titles in current
        all_titles = set()
        for det in self.current_detections[:100]:  # Sample first 100
            if 'rule_title' in det:
                all_titles.add(det['rule_title'])
        
        if all_titles:
            print(f"\n📋 Sample rule titles found in detections:")
            for title in list(all_titles)[:10]:
                print(f"      - {title}")
    
    def _load_detections(self, results_dir: Path) -> List[Dict]:
        """Load detections from results directory"""
        detections_file = results_dir / 'detections.json'
        if detections_file.exists():
            with open(detections_file, 'r') as f:
                data = json.load(f)
                print(f"\n   Loaded {len(data)} detections from {detections_file}")
                if data:
                    print(f"   Sample detection keys: {list(data[0].keys())}")
                return data
        print(f"\n   ⚠️  No detections file found at {detections_file}")
        return []
    
    def _build_rule_map(self, detections: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Build map of rule_id -> list of detections
        Creates MULTIPLE indexes for flexible matching
        """
        rule_map_by_id = defaultdict(list)
        rule_map_by_title = defaultdict(list)
        unknown_count = 0
        
        for detection in detections:
            rule_id = self._extract_rule_id(detection)
            rule_title = detection.get('rule_title', '')
            
            if rule_id and rule_id != 'unknown':
                rule_map_by_id[rule_id].append(detection)
            else:
                unknown_count += 1
            
            # Also index by title for fallback matching
            if rule_title:
                rule_map_by_title[rule_title].append(detection)
        
        if unknown_count > 0:
            print(f"   ⚠️  {unknown_count} detections had unknown rule IDs")
        
        # Store both maps
        self.rule_map_by_id = dict(rule_map_by_id)
        self.rule_map_by_title = dict(rule_map_by_title)
        
        # Return the ID map as primary
        return self.rule_map_by_id
    
    def _extract_rule_id(self, detection: Dict) -> str:
        """Extract rule identifier from detection JSON"""
        # Strategy 1: Direct rule_id field (most common)
        if 'rule_id' in detection and detection['rule_id']:
            return str(detection['rule_id']).strip()
        
        # Strategy 2: Check raw._source_rule_id
        if 'raw' in detection and isinstance(detection['raw'], dict):
            if '_source_rule_id' in detection['raw']:
                return str(detection['raw']['_source_rule_id']).strip()
        
        # Strategy 3: rule_title as fallback
        if 'rule_title' in detection and detection['rule_title']:
            return str(detection['rule_title']).strip()
        
        # Strategy 4: Check other common fields
        for key in ['rule_name', 'rule', 'id', 'signature_id']:
            if key in detection and detection[key]:
                return str(detection[key]).strip()
        
        return 'unknown'
    
    def _extract_rule_identifiers_from_yaml(self, rule_path: str) -> Dict[str, str]:
        """
        Extract multiple identifiers from YAML file
        Returns dict with 'id', 'title', 'filename' for flexible matching
        """
        print(f"\n   📄 Reading YAML file: {rule_path}")
        
        result = {
            'id': None,
            'title': None,
            'filename': Path(rule_path).stem
        }
        
        try:
            with open(rule_path, 'r') as f:
                rule_data = yaml.safe_load(f)
                
                if not rule_data:
                    print(f"   ⚠️  Empty YAML file")
                    return result
                
                print(f"   🔍 YAML keys found: {list(rule_data.keys())}")
                
                # Extract ID
                if 'id' in rule_data:
                    result['id'] = str(rule_data['id']).strip()
                    print(f"   ✅ Found 'id': {result['id']}")
                
                # Extract title
                if 'title' in rule_data:
                    result['title'] = str(rule_data['title']).strip()
                    print(f"   ✅ Found 'title': {result['title']}")
                
                return result
                
        except Exception as e:
            print(f"   ❌ Error reading YAML: {e}")
            import traceback
            traceback.print_exc()
            return result
    
    def classify_new_rule(self, rule_path: str) -> Dict:
        """
        Classify a new rule based on its actual contribution
        FIXED: Tries multiple matching strategies (ID, title, filename)
        """
        print(f"\n{'='*70}")
        print(f"🔍 ANALYZING: {rule_path}")
        print(f"{'='*70}")
        
        # Extract identifiers from YAML
        identifiers = self._extract_rule_identifiers_from_yaml(rule_path)
        
        if not any(identifiers.values()):
            return {
                'rule_name': Path(rule_path).stem,
                'rule_path': rule_path,
                'classification': 'ERROR',
                'score': 0,
                'reasoning': 'Could not extract any identifiers from YAML file',
                'triggered': False,
                'detection_count': 0,
                'metrics': {}
            }
        
        # Try multiple matching strategies
        print(f"\n   🔎 Trying to match detections using:")
        print(f"      1. ID: {identifiers['id']}")
        print(f"      2. Title: {identifiers['title']}")
        print(f"      3. Filename: {identifiers['filename']}")
        
        # Strategy 1: Match by ID
        matched_by = None
        rule_detection_count = 0
        baseline_count_by_id = 0
        baseline_count_by_title = 0
        
        if identifiers['id']:
            # Check baseline by ID
            if identifiers['id'] in self.baseline_rules:
                baseline_count_by_id = len(self.baseline_rules[identifiers['id']])
                print(f"   ⚠️  ID exists in baseline: {identifiers['id']} ({baseline_count_by_id} alerts)")
                
                current_count = len(self.current_rules.get(identifiers['id'], []))
                
                return {
                    'rule_name': Path(rule_path).stem,
                    'rule_path': rule_path,
                    'rule_id': identifiers['id'],
                    'classification': 'ERROR',
                    'score': 0,
                    'reasoning': f'Rule ID "{identifiers["id"]}" exists in baseline ({baseline_count_by_id} alerts). Not a new rule!',
                    'triggered': True,
                    'detection_count': current_count,
                    'metrics': {
                        'baseline_alerts': self.baseline_total,
                        'current_alerts': self.current_total,
                        'delta': self.delta
                    }
                }
            
            # Check current by ID
            if identifiers['id'] in self.current_rules:
                rule_detection_count = len(self.current_rules[identifiers['id']])
                matched_by = 'ID'
                print(f"   ✅ Matched by ID: {identifiers['id']} ({rule_detection_count} detections)")
            else:
                print(f"   ❌ ID not found in current: {identifiers['id']}")
        
        # Strategy 2: Match by title (if ID didn't match)
        if rule_detection_count == 0 and identifiers['title']:
            # Check if we have the title index
            if not hasattr(self, 'rule_map_by_title'):
                print(f"   ⚠️  Title index not available")
            else:
                # Check baseline by title
                baseline_title_index = {}
                for det in self.baseline_detections:
                    title = det.get('rule_title', '')
                    if title:
                        baseline_title_index[title] = baseline_title_index.get(title, 0) + 1
                
                if identifiers['title'] in baseline_title_index:
                    baseline_count_by_title = baseline_title_index[identifiers['title']]
                    print(f"   ⚠️  Title exists in baseline: {identifiers['title']} ({baseline_count_by_title} alerts)")
                
                # Check current by title
                current_title_index = {}
                for det in self.current_detections:
                    title = det.get('rule_title', '')
                    if title:
                        current_title_index[title] = current_title_index.get(title, 0) + 1
                
                if identifiers['title'] in current_title_index:
                    rule_detection_count = current_title_index[identifiers['title']]
                    matched_by = 'Title'
                    print(f"   ✅ Matched by Title: {identifiers['title']} ({rule_detection_count} detections)")
                    
                    # If title exists in baseline too, this is an ERROR
                    if baseline_count_by_title > 0:
                        return {
                            'rule_name': Path(rule_path).stem,
                            'rule_path': rule_path,
                            'rule_id': identifiers['id'],
                            'rule_title': identifiers['title'],
                            'classification': 'ERROR',
                            'score': 0,
                            'reasoning': f'Rule title "{identifiers["title"]}" exists in baseline ({baseline_count_by_title} alerts). Not a new rule! (ID "{identifiers["id"]}" not found in detections - possible ID mismatch)',
                            'triggered': True,
                            'detection_count': rule_detection_count,
                            'metrics': {
                                'baseline_alerts': self.baseline_total,
                                'current_alerts': self.current_total,
                                'delta': self.delta
                            }
                        }
                else:
                    print(f"   ❌ Title not found in current: {identifiers['title']}")
        
        # Strategy 3: Match by filename (last resort)
        if rule_detection_count == 0:
            print(f"   Trying filename variations...")
            for key in [identifiers['filename'], identifiers['filename'].upper(), identifiers['filename'].lower()]:
                if key in self.current_rules:
                    rule_detection_count = len(self.current_rules[key])
                    matched_by = 'Filename'
                    print(f"   ✅ Matched by Filename: {key} ({rule_detection_count} detections)")
                    break
                else:
                    print(f"   ❌ Filename not found: {key}")
        
        if matched_by:
            print(f"   🎯 Match strategy: {matched_by}")
        else:
            print(f"   ❌ No matches found in current detections")
        
        # SCORING LOGIC
        if rule_detection_count == 0:
            score = 20
            grade = 'WEAK'
            reasoning = 'Rule did not trigger on any logs. Possible causes: (1) unsupported log source, (2) overly specific pattern, (3) syntax errors, (4) ID mismatch between YAML and detections.'
        
        elif rule_detection_count >= 50:
            score = 95
            grade = 'STRONG'
            reasoning = f'Excellent! Rule detected {rule_detection_count} events. Very high-value detection capability.'
        
        elif rule_detection_count >= 30:
            score = 80
            grade = 'STRONG'
            reasoning = f'Strong detection capability with {rule_detection_count} alerts. Significant value addition.'
        
        elif rule_detection_count >= 20:
            score = 70
            grade = 'STRONG'
            reasoning = f'Good detection rate ({rule_detection_count} alerts). Solid contribution.'
        
        elif rule_detection_count >= 10:
            score = 60
            grade = 'STRONG'
            reasoning = f'Decent detection rate ({rule_detection_count} alerts). Adds value.'
        
        elif rule_detection_count >= 5:
            score = 50
            grade = 'NEUTRAL'
            reasoning = f'Moderate detection ({rule_detection_count} alerts). Rule works but has limited coverage.'
        
        elif rule_detection_count >= 2:
            score = 42
            grade = 'NEUTRAL'
            reasoning = f'Low detection rate ({rule_detection_count} alerts). Very narrow scope or insufficient test data.'
        
        else:  # 1 detection
            score = 30
            grade = 'WEAK'
            reasoning = f'Minimal detection (only {rule_detection_count} alert). Rule may be too restrictive.'
        
        # Efficiency adjustment
        if rule_detection_count > 0 and self.current_total > 0:
            efficiency = rule_detection_count / self.current_total
            
            if efficiency > 0.15:  # >15% of alerts
                score += 5
                reasoning += f' High efficiency ({efficiency:.1%}).'
            elif efficiency < 0.005 and rule_detection_count < 5:  # <0.5%
                score -= 5
                reasoning += f' Low efficiency ({efficiency:.1%}).'
        
        # Delta sanity check
        if rule_detection_count > 0 and self.delta <= 0:
            score -= 10
            reasoning += ' ⚠️  Total alerts unchanged (possible duplicate detection).'
        
        # Bonus for using title match (shows system is working even if IDs don't match)
        if matched_by == 'Title' and rule_detection_count > 0:
            reasoning += f' (Matched by rule title since ID "{identifiers["id"]}" not found in detections.)'
        
        # Clamp score
        score = max(0, min(100, score))
        
        # Final grade
        if score >= 60:
            grade = 'STRONG'
        elif score >= 40:
            grade = 'NEUTRAL'
        else:
            grade = 'WEAK'
        
        result = {
            'rule_name': Path(rule_path).stem,
            'rule_path': rule_path,
            'rule_id': identifiers['id'],
            'rule_title': identifiers['title'],
            'matched_by': matched_by,
            'classification': grade,
            'score': score,
            'reasoning': reasoning,
            'triggered': rule_detection_count > 0,
            'detection_count': rule_detection_count,
            'metrics': {
                'baseline_total': self.baseline_total,
                'current_total': self.current_total,
                'delta': self.delta,
                'rule_contribution': rule_detection_count,
                'rule_contribution_pct': round(rule_detection_count / self.current_total * 100, 2) if self.current_total > 0 else 0
            }
        }
        
        print(f"\n✅ CLASSIFICATION: {grade} (Score: {score}/100)")
        print(f"   {reasoning}")
        
        return result


def parse_rule_list(rule_string: str) -> List[str]:
    """Parse comma-separated rule list"""
    if not rule_string or rule_string.strip() == '':
        return []
    return [r.strip() for r in rule_string.split(',') if r.strip()]


def main():
    parser = argparse.ArgumentParser(
        description='Fixed classifier - extracts rule IDs from YAML files'
    )
    parser.add_argument('--baseline-results', required=True)
    parser.add_argument('--current-results', required=True)
    parser.add_argument('--rules-dir', default='rules/sigma', help='Directory containing rule files (default: rules/sigma)')
    parser.add_argument('--changed-sigma-rules', default='')
    parser.add_argument('--changed-yara-rules', default='')
    parser.add_argument('--output-file', required=True)
    parser.add_argument('--debug', action='store_true')
    
    args = parser.parse_args()
    
    baseline_dir = Path(args.baseline_results)
    current_dir = Path(args.current_results)
    rules_dir = Path(args.rules_dir)
    output_file = Path(args.output_file)
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    changed_sigma = parse_rule_list(args.changed_sigma_rules)
    changed_yara = parse_rule_list(args.changed_yara_rules)
    
    if not changed_sigma and not changed_yara:
        print("⚠️  No changed rules to classify")
        report = {
            'summary': {'total_rules': 0, 'by_grade': {}, 'average_score': 0},
            'rules': []
        }
    else:
        classifier = WorkingClassifier(baseline_dir, current_dir, rules_dir)
        
        classifications = []
        
        for rule_path in changed_sigma + changed_yara:
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
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{'='*70}")
    print("📊 FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"Total rules: {report['summary']['total_rules']}")
    print(f"Average score: {report['summary']['average_score']}/100")
    print(f"\nGrade Distribution:")
    
    for grade in ['STRONG', 'NEUTRAL', 'WEAK', 'ERROR']:
        if grade in report['summary']['by_grade']:
            count = report['summary']['by_grade'][grade]
            print(f"   {grade}: {count}")
    
    print(f"\n✅ Report saved to: {output_file}")
    print(f"\n💡 SCORING GUIDE:")
    print(f"   STRONG (60-100): 10+ detections")
    print(f"   NEUTRAL (40-59): 2-9 detections")
    print(f"   WEAK (0-39): 0-1 detections")


if __name__ == '__main__':
    main()
