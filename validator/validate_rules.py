#!/usr/bin/env python3
"""
Enhanced Rule Validator with comprehensive Sigma modifier support
Based on SigmaHQ repository patterns and Sigma 2.0 specification
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
            # Generate string containing the pattern
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
            # All modifier - pattern is a list, value should contain all
            if isinstance(pattern, list):
                # Return value containing all items
                return ' '.join(str(p) for p in pattern)
            return pattern_str
        
        elif modifier == 're':
            # Regex modifier
            return EnhancedLogGenerator._generate_from_regex(pattern_str, index, total)
        
        elif modifier == 'base64':
            # Base64 encode the pattern
            import base64
            encoded = base64.b64encode(pattern_str.encode()).decode()
            return encoded
        
        elif modifier == 'base64offset':
            # Base64 with offset (3 possible offsets)
            import base64
            offset = index % 3
            padded = ('A' * offset) + pattern_str
            encoded = base64.b64encode(padded.encode()).decode()
            return encoded[offset:] if offset > 0 else encoded
        
        elif modifier == 'cased':
            # Case-sensitive - return exact case
            return pattern_str
        
        elif modifier == 'exists':
            # Field exists check
            return 'exists_value' if pattern else None

        # Check if pattern itself is regex or wildcard
        if EnhancedLogGenerator._is_regex_pattern(pattern_str):
            return EnhancedLogGenerator._generate_from_regex(pattern_str, index, total)
        
        if '*' in pattern_str or '?' in pattern_str:
            return EnhancedLogGenerator._generate_from_wildcard(pattern_str, index, total)

        # Exact match
        return pattern_str

    @staticmethod
    def _generate_non_matching_value(field: str, pattern: Any, modifier: Optional[str], 
                                     index: int) -> Any:
        """Generate values that should NOT match"""
        
        if isinstance(pattern, list):
            return f"non_matching_{index}"

        if pattern is None:
            if modifier == 'exists':
                return None  # Field shouldn't exist
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
        
        # Replace common regex patterns
        if '.*' in result:
            variations = ['test', f'var{index}', 'xyz123', 'data']
            parts = result.split('.*')
            result = variations[index % len(variations)].join(parts)
        
        if '.+' in result:
            variations = ['abc', f'v{index}', 'xyz', 'data']
            parts = result.split('.+')
            result = variations[index % len(variations)].join(parts)
        
        # Handle character classes
        result = re.sub(r'\\d+', lambda m: str(random.randint(100, 999)), result)
        result = re.sub(r'\\d', lambda m: str(random.randint(0, 9)), result)
        result = re.sub(r'\\w+', lambda m: ''.join(random.choices(string.ascii_letters, k=8)), result)
        result = re.sub(r'\\w', lambda m: random.choice(string.ascii_letters), result)
        
        # Handle character classes like [A-Za-z0-9]
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
    """Validates rules with enhanced test generation"""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'rules_tested': [],
            'total_passed': 0,
            'total_failed': 0,
            'details': []
        }

    def validate_sigma_rule(self, rule_path: str) -> Dict[str, Any]:
        """Validate a single Sigma rule"""
        print(f"\n[+] Validating Sigma rule: {rule_path}")

        rule_path = Path(rule_path)
        if not rule_path.exists():
            return self._create_error_result(str(rule_path), "Rule file not found", rule_type='sigma')

        try:
            rules = load_sigma_rules(str(rule_path))
            if not rules:
                return self._create_error_result(str(rule_path), "No rules found in file", rule_type='sigma')

            rule = rules[0]
            rule_id = rule.get('id', rule_path.stem)
            rule_title = rule.get('title', 'Untitled')

            print(f"    Rule ID: {rule_id}")
            print(f"    Title: {rule_title}")
            
            detection = rule.get('detection', {})
            print(f"    Detection config: {json.dumps(detection, indent=6)}")

            # Generate test logs
            print(f"    Generating enhanced test logs...")
            test_logs = EnhancedLogGenerator.generate_for_sigma_rule(rule, count=20)

            # Save test logs
            test_log_file = self.output_dir / f"test_logs_{rule_id}.jsonl"
            with open(test_log_file, 'w') as f:
                for log in test_logs:
                    f.write(json.dumps(log) + '\n')

            print(f"    Generated {len(test_logs)} test logs")
            
            # Run simulator
            print(f"    Running simulator...")
            simulator = SOCSimulator(sigma_rules=rules, yara_path=None)
            simulator.process_logs(test_logs)

            alerts = simulator.export_alerts()
            metrics = simulator.export_metrics()

            # Analyze results
            expected_matches = sum(
                1 for log in test_logs
                if not str(log.get('_test_id', '')).startswith('negative')
            )
            actual_matches = len([a for a in alerts if a.get('rule_id') == rule_id])

            print(f"    Expected matches: {expected_matches}")
            print(f"    Actual matches: {actual_matches}")

            detection_rate = (actual_matches / expected_matches * 100) if expected_matches > 0 else 0
            
            # Determine pass/fail
            passed = detection_rate >= 60

            result = {
                'rule_path': str(rule_path),
                'rule_id': rule_id,
                'rule_title': rule_title,
                'type': 'sigma',
                'passed': passed,
                'expected_matches': expected_matches,
                'actual_matches': actual_matches,
                'detection_rate': round(detection_rate, 2),
                'total_alerts': len(alerts),
                'metrics': metrics,
                'test_log_file': str(test_log_file)
            }

            if passed:
                print(f"    ✓ PASSED - Detection rate: {detection_rate:.1f}%")
                self.results['total_passed'] += 1
            else:
                print(f"    ✗ FAILED - Detection rate: {detection_rate:.1f}% (expected >= 60%)")
                self.results['total_failed'] += 1

            return result

        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"    ✗ ERROR - {str(e)}")
            return self._create_error_result(
                str(rule_path), 
                str(e), 
                rule_type='sigma',
                rule_title=rule.get('title') if 'rule' in locals() and isinstance(rule, dict) else None
            )

    def validate_yara_rule(self, rule_path: str) -> Dict[str, Any]:
        """Validate a single YARA rule"""
        print(f"\n[+] Validating YARA rule: {rule_path}")

        rule_path = Path(rule_path)
        if not rule_path.exists():
            return self._create_error_result(str(rule_path), "Rule file not found", rule_type='yara')

        try:
            try:
                import yara  # noqa: F401
            except ImportError:
                return self._create_error_result(str(rule_path), "yara-python not installed", rule_type='yara')

            with open(rule_path, 'r') as f:
                rule_content = f.read()

            rule_name = rule_path.stem
            print(f"    Rule: {rule_name}")

            # Generate test logs for YARA
            print(f"    Generating test logs...")
            test_logs = self._generate_yara_test_logs(rule_content, count=20)

            test_log_file = self.output_dir / f"test_logs_{rule_name}.jsonl"
            with open(test_log_file, 'w') as f:
                for log in test_logs:
                    f.write(json.dumps(log) + '\n')

            print(f"    Running simulator...")
            simulator = SOCSimulator(sigma_rules=[], yara_path=str(rule_path))
            simulator.process_logs(test_logs)

            alerts = simulator.export_alerts()
            metrics = simulator.export_metrics()

            expected_matches = sum(
                1 for log in test_logs
                if not str(log.get('_test_id', '')).startswith('negative')
            )
            actual_matches = len(alerts)

            detection_rate = (actual_matches / expected_matches * 100) if expected_matches > 0 else 0
            passed = detection_rate >= 80

            result = {
                'rule_path': str(rule_path),
                'rule_id': rule_name,
                'rule_title': f'YARA: {rule_name}',
                'type': 'yara',
                'passed': passed,
                'expected_matches': expected_matches,
                'actual_matches': actual_matches,
                'detection_rate': round(detection_rate, 2),
                'total_alerts': len(alerts),
                'metrics': metrics,
                'test_log_file': str(test_log_file)
            }

            if passed:
                print(f"    ✓ PASSED - Detection rate: {detection_rate:.1f}%")
                self.results['total_passed'] += 1
            else:
                print(f"    ✗ FAILED - Detection rate: {detection_rate:.1f}% (expected >= 80%)")
                self.results['total_failed'] += 1

            return result

        except Exception as e:
            print(f"    ✗ ERROR - {str(e)}")
            return self._create_error_result(str(rule_path), str(e), rule_type='yara')

    def _generate_yara_test_logs(self, rule_content: str, count: int = 20) -> List[Dict[str, Any]]:
        """Generate test logs for YARA rules"""
        logs = []

        # Parse YARA rule to extract strings
        strings = []
        in_strings = False
        for line in rule_content.split('\n'):
            line = line.strip()
            if line.startswith('strings:'):
                in_strings = True
                continue
            if in_strings:
                if line.startswith('condition:'):
                    break
                if '=' in line and '"' in line:
                    parts = line.split('"')
                    if len(parts) >= 2:
                        strings.append(parts[1])

        # Generate matching logs
        for i in range(count):
            log = {
                '_generated': True,
                '_test_id': str(i),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
            }

            if strings:
                variations = [
                    strings[0],
                    f'Test message containing {strings[0]}',
                    f'{strings[0]} at the start',
                    f'end with {strings[0]}',
                    f'prefix {strings[0]} suffix'
                ]
                log['message'] = variations[i % len(variations)]
                log['payload'] = ' '.join(strings[:2]) if len(strings) > 1 else strings[0]
            else:
                log['message'] = f'Generic suspicious activity {i}'

            logs.append(log)

        # Generate non-matching logs
        for i in range(count // 2):
            log = {
                '_generated': True,
                '_test_id': f'negative-{i}',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
                'message': f'Benign activity {i}',
                'payload': f'Normal data {i}'
            }
            logs.append(log)

        return logs

    def _create_error_result(self, rule_path: str, error: str, rule_type: str = "unknown", 
                            rule_title: str = None) -> Dict[str, Any]:
        """Create an error result"""
        self.results['total_failed'] += 1
        return {
            'rule_path': rule_path,
            'rule_id': Path(rule_path).stem,
            'rule_title': rule_title or Path(rule_path).stem,
            'type': rule_type,
            'passed': False,
            'error': error
        }

    def save_results(self):
        """Save validation results"""
        results_file = self.output_dir / 'validation_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        self._create_markdown_summary()
        print(f"\n[+] Results saved to: {results_file}")

    def _create_markdown_summary(self):
        """Create markdown summary"""
        summary_file = self.output_dir / 'summary.md'

        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# 🛡️ Security Rule Validation Results\n\n")

            total_tested = self.results.get('total_passed', 0) + self.results.get('total_failed', 0)
            pass_rate = (self.results.get('total_passed', 0) / total_tested * 100) if total_tested > 0 else 0

            f.write("## Summary\n\n")
            f.write(f"- **Total Rules Tested:** {total_tested}\n")
            f.write(f"- **Passed:** ✅ {self.results.get('total_passed', 0)}\n")
            f.write(f"- **Failed:** ❌ {self.results.get('total_failed', 0)}\n")
            f.write(f"- **Pass Rate:** {pass_rate:.1f}%\n\n")

            f.write("## Detailed Results\n\n")

            for detail in self.results.get('details', []):
                passed = detail.get('passed', False)
                status = "✅ PASSED" if passed else "❌ FAILED"
                rule_title = detail.get('rule_title') or detail.get('rule_id') or "Unknown"
                f.write(f"### {status} - {rule_title}\n\n")
                f.write(f"- **Rule ID:** `{detail.get('rule_id', 'unknown')}`\n")
                f.write(f"- **Type:** {str(detail.get('type', 'unknown')).upper()}\n")
                f.write(f"- **Path:** `{detail.get('rule_path', 'N/A')}`\n")

                if 'error' in detail:
                    f.write(f"- **Error:** {detail.get('error')}\n\n")
                else:
                    f.write(f"- **Detection Rate:** {detail.get('detection_rate', 0)}%\n")
                    f.write(f"- **Expected Matches:** {detail.get('expected_matches', 0)}\n")
                    f.write(f"- **Actual Matches:** {detail.get('actual_matches', 0)}\n\n")


def main():
    parser = argparse.ArgumentParser(description='Enhanced Sigma Rule Validator')
    parser.add_argument('--sigma-rules', help='Comma-separated list of Sigma rule files')
    parser.add_argument('--yara-rules', help='Comma-separated list of YARA rule files (optional)')
    parser.add_argument('--output-dir', default='validation_results', help='Output directory')
    args = parser.parse_args()

    validator = RuleValidator(args.output_dir)

    # Validate Sigma rules
    if args.sigma_rules:
        sigma_files = [f.strip() for f in args.sigma_rules.split(',') if f.strip()]
        for rule_file in sigma_files:
            result = validator.validate_sigma_rule(rule_file)
            validator.results['details'].append(result)
            validator.results['rules_tested'].append(rule_file)

    # Validate YARA rules (basic support)
    if args.yara_rules:
        yara_files = [f.strip() for f in args.yara_rules.split(',') if f.strip()]
        for rule_file in yara_files:
            result = validator.validate_yara_rule(rule_file)
            validator.results['details'].append(result)
            validator.results['rules_tested'].append(rule_file)

    validator.save_results()

    if validator.results['total_failed'] > 0:
        print(f"\n❌ Validation failed: {validator.results['total_failed']} rule(s) failed")
        sys.exit(1)
    else:
        print(f"\n✅ All {validator.results['total_passed']} rule(s) passed validation")
        sys.exit(0)


if __name__ == '__main__':
    main()
