#!/usr/bin/env python3
"""
Enhanced Rule Validator with baseline/current mode support
FIXED: Detections file not being overwritten
"""
import os
import sys
import json
import yaml
import argparse
import re
import random
import string
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test import SOCSimulator, load_sigma_rules, SigmaRule


class EnhancedLogGenerator:
    """
    Enhanced log generator supporting all Sigma modifiers and patterns
    Based on analysis of SigmaHQ repository
    """

    @staticmethod
    def generate_for_sigma_rule(rule: Dict[str, Any], count: int = 20) -> List[Dict[str, Any]]:
        """Generate diverse logs testing all aspects of the rule"""
        logs = []
        detection = rule.get('detection', {})

        # Parse all selections
        selections = {}
        filters = {}
        for key, value in detection.items():
            if key == 'condition':
                continue
            if isinstance(value, dict):
                if key.startswith('filter'):
                    filters[key] = value
                else:
                    selections[key] = value

        if not selections:
            return logs

        # Get primary selection
        first_selection = list(selections.values())[0]
        
        # Generate POSITIVE matches
        positive_count = count
        for i in range(positive_count):
            log = {
                '_generated': True,
                '_test_id': str(i),
                '_match_type': 'positive',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
                'user': f'test-user-{i % 2}'
            }

            # Generate matching values for each field
            for field, pattern in first_selection.items():
                # Parse field with potential modifier
                field_name, modifier = EnhancedLogGenerator._parse_field_modifier(field)
                
                # Generate value based on pattern and modifier
                generated_value = EnhancedLogGenerator._generate_matching_value(
                    field_name, pattern, modifier, i, positive_count
                )
                
                # Set nested field
                if '.' in field_name:
                    EnhancedLogGenerator._set_nested_field(log, field_name, generated_value)
                else:
                    log[field_name] = generated_value
                
                if i < 3:
                    print(f"      Generated field '{field_name}' (modifier: {modifier or 'none'}) = '{generated_value}'")

            logs.append(log)

        # Generate NEGATIVE matches
        negative_count = count // 2
        for i in range(negative_count):
            log = {
                '_generated': True,
                '_test_id': f'negative-{i}',
                '_match_type': 'negative',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
                'user': f'benign-user'
            }
            
            for field, pattern in first_selection.items():
                field_name, modifier = EnhancedLogGenerator._parse_field_modifier(field)
                non_matching = EnhancedLogGenerator._generate_non_matching_value(
                    field_name, pattern, modifier, i
                )
                
                if '.' in field_name:
                    EnhancedLogGenerator._set_nested_field(log, field_name, non_matching)
                else:
                    log[field_name] = non_matching
            
            logs.append(log)

        return logs

    @staticmethod
    def _parse_field_modifier(field: str) -> Tuple[str, Optional[str]]:
        """Parse field name and optional modifier (e.g., 'field|contains')"""
        if '|' in field:
            parts = field.split('|')
            return parts[0], parts[1] if len(parts) > 1 else None
        return field, None

    @staticmethod
    def _set_nested_field(log: Dict[str, Any], field_path: str, value: Any):
        """Set value in nested dictionary structure"""
        parts = field_path.split('.')
        current = log
        
        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {}
            current = current[part]
        
        current[parts[-1]] = value

    @staticmethod
    def _generate_matching_value(field: str, pattern: Any, modifier: Optional[str], 
                                 index: int, total: int) -> Any:
        """Generate values matching the pattern with modifier support"""
        
        # Handle lists - pick different values
        if isinstance(pattern, list):
            return pattern[index % len(pattern)]

        # Handle NULL
        if pattern is None:
            return None if modifier != 'exists' else 'some_value'

        # Handle booleans
        if isinstance(pattern, bool):
            return pattern

        # Handle integers/floats
        if isinstance(pattern, (int, float)):
            if modifier in ['gt', 'gte', 'lt', 'lte']:
                # Generate values appropriate for comparison
                if modifier == 'gt':
                    return pattern + random.randint(1, 100)
                elif modifier == 'gte':
                    return pattern if index % 2 == 0 else pattern + random.randint(1, 50)
                elif modifier == 'lt':
                    return pattern - random.randint(1, 100)
                elif modifier == 'lte':
                    return pattern if index % 2 == 0 else pattern - random.randint(1, 50)
            return pattern

        pattern_str = str(pattern)

        # Handle modifiers
        if modifier == 'contains':
            variations = [
                pattern_str,
                f'prefix_{pattern_str}',
                f'{pattern_str}_suffix',
                f'pre_{pattern_str}_suf',
                f'xxx{pattern_str}yyy'
            ]
            return variations[index % len(variations)]
        
        elif modifier == 'startswith':
            suffixes = ['', '_end', '_suffix', '123', '_xyz', f'_{index}']
            return f'{pattern_str}{suffixes[index % len(suffixes)]}'
        
        elif modifier == 'endswith':
            prefixes = ['', 'start_', 'prefix_', '123', 'xyz_', f'{index}_']
            return f'{prefixes[index % len(prefixes)]}{pattern_str}'
        
        elif modifier == 'all':
            if isinstance(pattern, list):
                return ' '.join(str(p) for p in pattern)
            return pattern_str
        
        elif modifier == 're':
            return EnhancedLogGenerator._generate_from_regex(pattern_str, index, total)
        
        elif modifier == 'base64':
            import base64
            encoded = base64.b64encode(pattern_str.encode()).decode()
            return encoded
        
        elif modifier == 'base64offset':
            import base64
            offset = index % 3
            padded = ('A' * offset) + pattern_str
            encoded = base64.b64encode(padded.encode()).decode()
            return encoded[offset:] if offset > 0 else encoded
        
        elif modifier == 'cased':
            return pattern_str
        
        elif modifier == 'exists':
            return 'exists_value' if pattern else None

        # Check if pattern itself is regex or wildcard
        if EnhancedLogGenerator._is_regex_pattern(pattern_str):
            return EnhancedLogGenerator._generate_from_regex(pattern_str, index, total)
        
        if '*' in pattern_str or '?' in pattern_str:
            return EnhancedLogGenerator._generate_from_wildcard(pattern_str, index, total)

        return pattern_str

    @staticmethod
    def _generate_non_matching_value(field: str, pattern: Any, modifier: Optional[str], 
                                     index: int) -> Any:
        """Generate values that should NOT match"""
        
        if isinstance(pattern, list):
            return f"non_matching_{index}"

        if pattern is None:
            if modifier == 'exists':
                return None
            return f"not_null_{index}"

        if isinstance(pattern, bool):
            return not pattern

        if isinstance(pattern, (int, float)):
            if modifier == 'gt':
                return pattern - random.randint(1, 100)
            elif modifier == 'gte':
                return pattern - random.randint(1, 100)
            elif modifier == 'lt':
                return pattern + random.randint(1, 100)
            elif modifier == 'lte':
                return pattern + random.randint(1, 100)
            return pattern + 5000

        pattern_str = str(pattern)

        if modifier in ['contains', 'startswith', 'endswith', 'all']:
            return f"different_{index}_nomatch"
        
        if modifier == 're':
            return f"regex_nomatch_{index}"
        
        if modifier == 'base64':
            return f"notbase64_{index}"

        return f"nonmatching_{pattern_str}_{index}"

    @staticmethod
    def _is_regex_pattern(s: str) -> bool:
        """Detect regex patterns"""
        regex_indicators = ['.*', '.+', '^', '$', '[', ']', '(', ')', '|', '{', '}', 
                          '\\d', '\\w', '\\s', '\\D', '\\W', '\\S']
        return any(indicator in s for indicator in regex_indicators)

    @staticmethod
    def _generate_from_regex(pattern: str, index: int, total: int) -> str:
        """Generate strings matching regex pattern"""
        pattern = pattern.replace('^', '').replace('$', '')
        
        result = pattern
        
        if '.*' in result:
            variations = ['test', f'var{index}', 'xyz123', 'data']
            parts = result.split('.*')
            result = variations[index % len(variations)].join(parts)
        
        if '.+' in result:
            variations = ['abc', f'v{index}', 'xyz', 'data']
            parts = result.split('.+')
            result = variations[index % len(variations)].join(parts)
        
        result = re.sub(r'\\d+', lambda m: str(random.randint(100, 999)), result)
        result = re.sub(r'\\d', lambda m: str(random.randint(0, 9)), result)
        result = re.sub(r'\\w+', lambda m: ''.join(random.choices(string.ascii_letters, k=8)), result)
        result = re.sub(r'\\w', lambda m: random.choice(string.ascii_letters), result)
        
        def replace_char_class(match):
            char_class = match.group(0)
            if '[A-Za-z0-9+/]' in char_class:
                length = 20
                if '{' in pattern:
                    length_match = re.search(r'\{(\d+),?(\d+)?\}', pattern)
                    if length_match:
                        min_len = int(length_match.group(1))
                        length = min_len
                base64_chars = string.ascii_letters + string.digits + '+/'
                return ''.join(random.choices(base64_chars, k=length))
            elif '[A-Za-z0-9]' in char_class:
                return ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            return 'X'
        
        result = re.sub(r'\[[^\]]+\]\{\d+,?\d*\}', replace_char_class, result)
        result = re.sub(r'\[[^\]]+\]', replace_char_class, result)
        result = re.sub(r'\{(\d+),?\d*\}', '', result)
        result = result.replace('\\', '')
        
        return result

    @staticmethod
    def _generate_from_wildcard(pattern: str, index: int, total: int) -> str:
        """Generate strings matching wildcard patterns"""
        
        if pattern.startswith('*') and pattern.endswith('*'):
            middle = pattern.strip('*')
            if middle:
                variations = [
                    middle,
                    f"prefix_{middle}",
                    f"{middle}_suffix",
                    f"pre_{middle}_suf",
                    f"x{middle}y"
                ]
                return variations[index % len(variations)]
            return f"value_{index}"
        
        elif pattern.startswith('*'):
            suffix = pattern.lstrip('*')
            if suffix:
                prefixes = ['', 'pre_', 'prefix_', 'x', f'v{index}_']
                return f"{prefixes[index % len(prefixes)]}{suffix}"
            return f"value_{index}"
        
        elif pattern.endswith('*'):
            prefix = pattern.rstrip('*')
            if prefix:
                suffixes = ['', '_suf', '_suffix', 'x', f'_{index}']
                return f"{prefix}{suffixes[index % len(suffixes)]}"
            return f"value_{index}"
        
        if '?' in pattern:
            result = ""
            for char in pattern:
                if char == '?':
                    chars = string.ascii_lowercase + string.digits
                    result += chars[index % len(chars)]
                else:
                    result += char
            return result
        
        return pattern


class RuleValidator:
    """Validates rules with enhanced test generation and comparison support"""

    def __init__(self, output_dir: str, mode: str = 'current', synthetic_logs_dir: str = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.synthetic_logs_dir = Path(synthetic_logs_dir) if synthetic_logs_dir else None
        self.synthetic_logs = []
        
        self.results = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'mode': mode,
            'rules_tested': [],
            'total_passed': 0,
            'total_failed': 0,
            'details': [],
            'detections': [],  # This accumulates ALL detections
            'statistics': {}
        }

    def load_synthetic_logs(self):
        """Load pre-generated synthetic logs"""
        if not self.synthetic_logs_dir or not self.synthetic_logs_dir.exists():
            print("⚠️  No synthetic logs directory provided or found")
            return
        
        print(f"[+] Loading synthetic logs from: {self.synthetic_logs_dir}")
        
        for log_file in self.synthetic_logs_dir.glob('*.jsonl'):
            with open(log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        self.synthetic_logs.append(json.loads(line))
        
        print(f"    Loaded {len(self.synthetic_logs)} synthetic log events")

    def validate_all_rules(self, rules_dir: str, rule_type: str = 'sigma'):
        """Validate all rules in a directory against synthetic logs"""
        rules_path = Path(rules_dir)
        
        if not rules_path.exists():
            print(f"⚠️  Rules directory not found: {rules_dir}")
            return
        
        print(f"\n[+] Validating all {rule_type.upper()} rules in: {rules_dir}")
        
        # Find all rule files
        if rule_type == 'sigma':
            rule_files = list(rules_path.rglob('*.yml')) + list(rules_path.rglob('*.yaml'))
        elif rule_type == 'yara':
            rule_files = list(rules_path.rglob('*.yara')) + list(rules_path.rglob('*.yar'))
        else:
            rule_files = []
        
        print(f"    Found {len(rule_files)} rule files")
        
        # Load all rules
        all_rules = []
        for rule_file in rule_files:
            try:
                if rule_type == 'sigma':
                    rules = load_sigma_rules(str(rule_file))
                    all_rules.extend(rules)
            except Exception as e:
                print(f"    ⚠️  Error loading {rule_file}: {e}")
        
        print(f"    Loaded {len(all_rules)} rules total")
        
        # Run all rules against synthetic logs
        if self.synthetic_logs:
            print(f"    Running {len(all_rules)} rules against {len(self.synthetic_logs)} synthetic logs...")
            
            simulator = SOCSimulator(sigma_rules=all_rules, yara_path=None)
            simulator.process_logs(self.synthetic_logs)
            
            alerts = simulator.export_alerts()
            metrics = simulator.export_metrics()
            
            print(f"    Generated {len(alerts)} total alerts")
            
            # CRITICAL FIX: Accumulate detections, don't replace
            self.results['detections'].extend(alerts)
            self.results['statistics'] = metrics
            
            print(f"    Total accumulated detections: {len(self.results['detections'])}")

    def save_results(self):
        """Save validation results"""
        # Save main results
        results_file = self.output_dir / 'validation_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Save detections ONCE at the end
        detections_file = self.output_dir / 'detections.json'
        with open(detections_file, 'w') as f:
            json.dump(self.results['detections'], f, indent=2)
        
        print(f"    Saved {len(self.results['detections'])} detections to: {detections_file}")
        
        # Save statistics
        stats_file = self.output_dir / 'statistics.json'
        with open(stats_file, 'w') as f:
            json.dump(self.results.get('statistics', {}), f, indent=2)

        print(f"\n[+] Results saved to: {results_file}")


def main():
    parser = argparse.ArgumentParser(description='Enhanced Sigma Rule Validator')
    parser.add_argument('--all-sigma-rules', help='Directory containing all Sigma rules')
    parser.add_argument('--all-yara-rules', help='Directory containing all YARA rules')
    parser.add_argument('--synthetic-logs-dir', help='Directory containing pre-generated synthetic logs')
    parser.add_argument('--output-dir', default='validation_results', help='Output directory')
    parser.add_argument('--mode', choices=['baseline', 'current'], default='current',
                       help='Validation mode: baseline (old rules) or current (all rules)')
    args = parser.parse_args()

    validator = RuleValidator(args.output_dir, mode=args.mode, 
                             synthetic_logs_dir=args.synthetic_logs_dir)

    # Load synthetic logs if provided
    if args.synthetic_logs_dir:
        validator.load_synthetic_logs()

    # Validate all rules in directories
    if args.all_sigma_rules:
        validator.validate_all_rules(args.all_sigma_rules, rule_type='sigma')
    
    if args.all_yara_rules:
        validator.validate_all_rules(args.all_yara_rules, rule_type='yara')

    # Save results ONCE at the end
    validator.save_results()

    print(f"\n✅ Validation complete in {args.mode} mode")
    sys.exit(0)


if __name__ == '__main__':
    main()
