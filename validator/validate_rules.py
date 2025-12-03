"""
Rule Validator - Automatically generates test logs based on rules and validates them
"""
import os
import sys
import json
import yaml
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime
from collections import defaultdict

# Import the SOC simulator components
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test import SOCSimulator, LogIngestor, load_sigma_rules


class LogGenerator:
    """Generates synthetic logs designed to match specific rules"""
    
    @staticmethod
    def generate_for_sigma_rule(rule: Dict[str, Any], count: int = 10) -> List[Dict[str, Any]]:
        """Generate logs that should match a Sigma rule"""
        logs = []
        detection = rule.get('detection', {})
        
        # Extract all selection criteria
        selections = {}
        for key, value in detection.items():
            if key != 'condition' and isinstance(value, dict):
                selections[key] = value
        
        if not selections:
            return logs
        
        # Generate matching logs
        for i in range(count):
            log = {'_generated': True, '_test_id': i}
            
            # Pick the first selection to generate from
            first_selection = list(selections.values())[0]
            
            for field, pattern in first_selection.items():
                log[field] = LogGenerator._generate_matching_value(pattern)
            
            # Add some context fields
            log['timestamp'] = datetime.utcnow().isoformat() + 'Z'
            log['host'] = f'test-host-{i % 3}'
            
            logs.append(log)
        
        # Also generate some non-matching logs (for false positive testing)
        for i in range(count // 2):
            log = {
                '_generated': True,
                '_test_id': f'negative-{i}',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
                'EventID': 9999,
                'ProcessName': 'benign.exe',
                'Message': 'Normal activity'
            }
            logs.append(log)
        
        return logs
    
    @staticmethod
    def _generate_matching_value(pattern: Any) -> Any:
        """Generate a value that matches the given pattern"""
        if isinstance(pattern, list):
            # Pick the first option
            pattern = pattern[0]
        
        if isinstance(pattern, (int, bool)):
            return pattern
        
        pattern_str = str(pattern)
        
        # Handle wildcards
        if '*' in pattern_str or '?' in pattern_str:
            # Replace wildcards with actual values
            result = pattern_str.replace('*', 'example').replace('?', 'X')
            return result
        
        # Handle regex patterns (simplified)
        if '.*' in pattern_str:
            result = pattern_str.replace('.*', 'matched_text')
            return result
        
        # Return as-is for exact matches
        return pattern_str
    
    @staticmethod
    def generate_for_yara_rule(rule_content: str, count: int = 10) -> List[Dict[str, Any]]:
        """Generate logs that should match a YARA rule"""
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
                    # Extract string value
                    parts = line.split('"')
                    if len(parts) >= 2:
                        strings.append(parts[1])
        
        # Generate matching logs
        for i in range(count):
            log = {
                '_generated': True,
                '_test_id': i,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
            }
            
            # Include the matched strings in message or payload
            if strings:
                log['message'] = f'Test message containing {strings[0]}'
                log['payload'] = ' '.join(strings[:2]) if len(strings) > 1 else strings[0]
            else:
                log['message'] = 'Generic suspicious activity'
            
            logs.append(log)
        
        # Generate non-matching logs
        for i in range(count // 2):
            log = {
                '_generated': True,
                '_test_id': f'negative-{i}',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
                'message': 'Benign activity',
                'payload': 'Normal data'
            }
            logs.append(log)
        
        return logs


class RuleValidator:
    """Validates rules by generating test logs and running the simulator"""
    
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
            return self._create_error_result(str(rule_path), "Rule file not found")
        
        try:
            # Load the rule
            rules = load_sigma_rules(str(rule_path))
            if not rules:
                return self._create_error_result(str(rule_path), "No rules found in file")
            
            rule = rules[0]  # Validate first rule in file
            rule_id = rule.get('id', rule_path.stem)
            rule_title = rule.get('title', 'Untitled')
            
            print(f"    Rule ID: {rule_id}")
            print(f"    Title: {rule_title}")
            
            # Generate test logs
            print(f"    Generating test logs...")
            test_logs = LogGenerator.generate_for_sigma_rule(rule, count=20)
            
            # Save test logs
            test_log_file = self.output_dir / f"test_logs_{rule_id}.jsonl"
            with open(test_log_file, 'w') as f:
                for log in test_logs:
                    f.write(json.dumps(log) + '\n')
            
            # Run simulator
            print(f"    Running simulator...")
            simulator = SOCSimulator(sigma_rules=rules, yara_path=None)
            simulator.process_logs(test_logs)
            
            alerts = simulator.export_alerts()
            metrics = simulator.export_metrics()
            
            # Analyze results
            expected_matches = sum(1 for log in test_logs if not log.get('_test_id', '').startswith('negative'))
            actual_matches = len([a for a in alerts if a['rule_id'] == rule_id])
            
            # Calculate detection rate
            detection_rate = (actual_matches / expected_matches * 100) if expected_matches > 0 else 0
            
            # Determine pass/fail
            passed = detection_rate >= 50  # At least 50% detection
            
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
                print(f"    ✗ FAILED - Detection rate: {detection_rate:.1f}% (expected >= 50%)")
                self.results['total_failed'] += 1
            
            return result
            
        except Exception as e:
            print(f"    ✗ ERROR - {str(e)}")
            return self._create_error_result(str(rule_path), str(e))
    
    def validate_yara_rule(self, rule_path: str) -> Dict[str, Any]:
        """Validate a single YARA rule"""
        print(f"\n[+] Validating YARA rule: {rule_path}")
        
        rule_path = Path(rule_path)
        if not rule_path.exists():
            return self._create_error_result(str(rule_path), "Rule file not found")
        
        try:
            # Check if yara is available
            try:
                import yara
            except ImportError:
                return self._create_error_result(str(rule_path), "yara-python not installed")
            
            # Load rule content
            with open(rule_path, 'r') as f:
                rule_content = f.read()
            
            rule_name = rule_path.stem
            print(f"    Rule: {rule_name}")
            
            # Generate test logs
            print(f"    Generating test logs...")
            test_logs = LogGenerator.generate_for_yara_rule(rule_content, count=20)
            
            # Save test logs
            test_log_file = self.output_dir / f"test_logs_{rule_name}.jsonl"
            with open(test_log_file, 'w') as f:
                for log in test_logs:
                    f.write(json.dumps(log) + '\n')
            
            # Run simulator
            print(f"    Running simulator...")
            simulator = SOCSimulator(sigma_rules=[], yara_path=str(rule_path))
            simulator.process_logs(test_logs)
            
            alerts = simulator.export_alerts()
            metrics = simulator.export_metrics()
            
            # Analyze results
            expected_matches = sum(1 for log in test_logs if not log.get('_test_id', '').startswith('negative'))
            actual_matches = len(alerts)
            
            detection_rate = (actual_matches / expected_matches * 100) if expected_matches > 0 else 0
            passed = detection_rate >= 50
            
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
                print(f"    ✗ FAILED - Detection rate: {detection_rate:.1f}% (expected >= 50%)")
                self.results['total_failed'] += 1
            
            return result
            
        except Exception as e:
            print(f"    ✗ ERROR - {str(e)}")
            return self._create_error_result(str(rule_path), str(e))
    
    def _create_error_result(self, rule_path: str, error: str) -> Dict[str, Any]:
        """Create an error result"""
        self.results['total_failed'] += 1
        return {
            'rule_path': rule_path,
            'rule_id': Path(rule_path).stem,
            'passed': False,
            'error': error
        }
    
    def save_results(self):
        """Save validation results to disk"""
        results_file = self.output_dir / 'validation_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Create a markdown summary
        self._create_markdown_summary()
        
        print(f"\n[+] Results saved to: {results_file}")
    
    def _create_markdown_summary(self):
        """Create a markdown summary for PR comments"""
        summary_file = self.output_dir / 'summary.md'
        
        with open(summary_file, 'w') as f:
            f.write("# 🛡️ Security Rule Validation Results\n\n")
            
            total_tested = self.results['total_passed'] + self.results['total_failed']
            pass_rate = (self.results['total_passed'] / total_tested * 100) if total_tested > 0 else 0
            
            # Summary stats
            f.write("## Summary\n\n")
            f.write(f"- **Total Rules Tested:** {total_tested}\n")
            f.write(f"- **Passed:** ✅ {self.results['total_passed']}\n")
            f.write(f"- **Failed:** ❌ {self.results['total_failed']}\n")
            f.write(f"- **Pass Rate:** {pass_rate:.1f}%\n\n")
            
            # Detailed results
            f.write("## Detailed Results\n\n")
            
            for detail in self.results['details']:
                status = "✅ PASSED" if detail['passed'] else "❌ FAILED"
                f.write(f"### {status} - {detail.get('rule_title', detail['rule_id'])}\n\n")
                f.write(f"- **Rule ID:** `{detail['rule_id']}`\n")
                f.write(f"- **Type:** {detail['type'].upper()}\n")
                f.write(f"- **Path:** `{detail['rule_path']}`\n")
                
                if 'error' in detail:
                    f.write(f"- **Error:** {detail['error']}\n\n")
                else:
                    f.write(f"- **Detection Rate:** {detail['detection_rate']}%\n")
                    f.write(f"- **Expected Matches:** {detail['expected_matches']}\n")
                    f.write(f"- **Actual Matches:** {detail['actual_matches']}\n")
                    f.write(f"- **Total Alerts:** {detail['total_alerts']}\n\n")


def main():
    parser = argparse.ArgumentParser(description='Validate Security Rules')
    parser.add_argument('--sigma-rules', help='Comma-separated list of Sigma rule files')
    parser.add_argument('--yara-rules', help='Comma-separated list of YARA rule files')
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
    
    # Validate YARA rules
    if args.yara_rules:
        yara_files = [f.strip() for f in args.yara_rules.split(',') if f.strip()]
        for rule_file in yara_files:
            result = validator.validate_yara_rule(rule_file)
            validator.results['details'].append(result)
            validator.results['rules_tested'].append(rule_file)
    
    # Save results
    validator.save_results()
    
    # Exit with error code if any validations failed
    if validator.results['total_failed'] > 0:
        print(f"\n❌ Validation failed: {validator.results['total_failed']} rule(s) failed")
        sys.exit(1)
    else:
        print(f"\n✅ All {validator.results['total_passed']} rule(s) passed validation")
        sys.exit(0)


if __name__ == '__main__':
    main()