#!/usr/bin/env python3
"""
Enhanced Rule Validator with Universal Log Generation
Supports: Windows, Azure, AWS, Linux, Okta, Proxy, Network logs
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


class UniversalLogGenerator:
    """Generates realistic logs for ANY Sigma rule log source"""
    
    # Log source templates for different platforms
    LOGSOURCE_TEMPLATES = {
        'azure': {
            'base_fields': ['CategoryValue', 'ResourceProviderValue', 'ResourceId', 'OperationNameValue', 'SubscriptionId'],
            'defaults': {
                'CategoryValue': 'Administrative',
                'SubscriptionId': 'sub-12345-test'
            }
        },
        'aws': {
            'base_fields': ['eventName', 'eventSource', 'awsRegion', 'userIdentity', 'requestParameters'],
            'defaults': {
                'awsRegion': 'us-east-1',
                'userIdentity': {'type': 'IAMUser', 'userName': 'test-user'}
            }
        },
        'okta': {
            'base_fields': ['eventType', 'displayMessage', 'actor', 'target', 'outcome'],
            'defaults': {
                'actor': {'alternateId': 'test@example.com', 'type': 'User'},
                'outcome': {'result': 'SUCCESS'}
            }
        },
        'linux': {
            'base_fields': ['CommandLine', 'Image', 'User', 'WorkingDirectory', 'TargetFilename'],
            'defaults': {
                'User': 'root',
                'WorkingDirectory': '/home/test'
            }
        },
        'windows': {
            'base_fields': ['EventID', 'CommandLine', 'Image', 'User', 'ParentImage', 'ProcessName'],
            'defaults': {
                'EventID': 4688,
                'User': 'SYSTEM'
            }
        },
        'proxy': {
            'base_fields': ['c-uri', 'cs-host', 'c-uri-extension', 'c-ip', 'cs-method'],
            'defaults': {
                'c-ip': '192.168.1.100',
                'cs-method': 'GET'
            }
        },
        'network': {
            'base_fields': ['DestinationIp', 'DestinationPort', 'SourceIp', 'SourcePort', 'Protocol', 'DestinationHostname'],
            'defaults': {
                'Protocol': 'tcp',
                'SourceIp': '10.0.0.1'
            }
        },
        'opencanary': {
            'base_fields': ['logtype', 'src_host', 'src_port', 'dst_host', 'dst_port'],
            'defaults': {
                'src_host': '192.168.1.50',
                'dst_host': '192.168.1.100'
            }
        }
    }
    
    @classmethod
    def generate_for_rule(cls, rule: Dict[str, Any], count: int = 20) -> List[Dict[str, Any]]:
        """Generate logs for ANY Sigma rule"""
        
        logsource = rule.get('logsource', {})
        detection = rule.get('detection', {})
        
        # Detect log source type
        log_type = cls._detect_log_type(logsource)
        
        # Get base template
        template = cls.LOGSOURCE_TEMPLATES.get(log_type, cls.LOGSOURCE_TEMPLATES['windows'])
        
        # Extract detection fields
        selections = {}
        for key, value in detection.items():
            if key != 'condition' and isinstance(value, dict):
                selections[key] = value
        
        if not selections:
            return []
        
        primary_selection = list(selections.values())[0]
        
        # Generate positive matches
        logs = []
        positive_count = int(count * 0.7)  # 70% positive
        
        for i in range(positive_count):
            log = cls._create_base_log(template, i)
            log['_match_type'] = 'positive'
            
            # Add detection fields
            for field, pattern in primary_selection.items():
                field_name = field.split('|')[0]  # Remove modifiers
                value = cls._generate_matching_value(field_name, pattern, i, log_type)
                cls._set_field(log, field_name, value)
            
            logs.append(log)
        
        # Generate negative matches
        negative_count = count - positive_count
        for i in range(negative_count):
            log = cls._create_base_log(template, i)
            log['_match_type'] = 'negative'
            
            # Add non-matching values
            for field, pattern in primary_selection.items():
                field_name = field.split('|')[0]
                value = cls._generate_non_matching_value(field_name, pattern, i)
                cls._set_field(log, field_name, value)
            
            logs.append(log)
        
        return logs
    
    @staticmethod
    def _detect_log_type(logsource: Dict[str, Any]) -> str:
        """Detect the log source type"""
        product = logsource.get('product', '').lower()
        category = logsource.get('category', '').lower()
        service = logsource.get('service', '').lower()
        
        # Product-based detection
        if 'azure' in product or 'entra' in product:
            return 'azure'
        if 'aws' in product:
            return 'aws'
        if 'okta' in product:
            return 'okta'
        if 'linux' in product:
            return 'linux'
        if 'windows' in product:
            return 'windows'
        if 'opencanary' in product:
            return 'opencanary'
        
        # Category-based detection
        if 'proxy' in category:
            return 'proxy'
        if 'network' in category or 'firewall' in category:
            return 'network'
        if 'process' in category:
            return 'windows'
        if 'file' in category:
            return 'linux' if 'linux' in product else 'windows'
        if 'application' in category:
            if 'opencanary' in product:
                return 'opencanary'
            return 'windows'
        
        # Service-based detection (Azure)
        if 'activitylogs' in service or 'pim' in service or 'azuread' in service:
            return 'azure'
        
        # Default to windows
        return 'windows'
    
    @staticmethod
    def _create_base_log(template: Dict, index: int) -> Dict[str, Any]:
        """Create base log with template defaults"""
        log = {
            '_generated': True,
            '_test_id': str(index),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'host': f'test-host-{index % 3}'
        }
        
        # Add template defaults
        defaults = template.get('defaults', {})
        for key, value in defaults.items():
            if isinstance(value, dict):
                log[key] = value.copy()
            else:
                log[key] = value
        
        return log
    
    @staticmethod
    def _set_field(log: Dict, field_path: str, value: Any):
        """Set nested field value"""
        if '.' in field_path:
            parts = field_path.split('.')
            current = log
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = value
        else:
            log[field_path] = value
    
    @classmethod
    def _generate_matching_value(cls, field: str, pattern: Any, index: int, log_type: str) -> Any:
        """Generate value matching the pattern"""
        
        # Handle lists - pick different values
        if isinstance(pattern, list):
            return pattern[index % len(pattern)]
        
        # Handle None
        if pattern is None:
            return None
        
        # Handle booleans
        if isinstance(pattern, bool):
            return pattern
        
        # Handle numbers
        if isinstance(pattern, (int, float)):
            return pattern
        
        pattern_str = str(pattern)
        
        # Special cases for common fields
        if field == 'EventID':
            return pattern if isinstance(pattern, int) else (int(pattern_str) if pattern_str.isdigit() else 4688)
        
        if field == 'logtype':
            return int(pattern_str) if pattern_str.isdigit() else 2000
        
        # Wildcard patterns
        if '*' in pattern_str:
            if pattern_str.startswith('*') and pattern_str.endswith('*'):
                core = pattern_str.strip('*')
                variations = [core, f'prefix_{core}', f'{core}_suffix', f'xxx{core}yyy', f'test{core}test']
                return variations[index % len(variations)]
            elif pattern_str.startswith('*'):
                return f'prefix_{pattern_str.lstrip("*")}'
            elif pattern_str.endswith('*'):
                suffixes = ['', '_test', '123', f'_{index}', '_suffix']
                return f'{pattern_str.rstrip("*")}{suffixes[index % len(suffixes)]}'
        
        # Regex patterns (simplified generation)
        if cls._is_regex_like(pattern_str):
            return cls._generate_from_pattern(pattern_str, index)
        
        # URLs for proxy logs
        if field in ['c-uri', 'cs-host', 'url', 'DestinationHostname']:
            if 'http' not in pattern_str.lower():
                if '.' in pattern_str:
                    return pattern_str
                return f'malicious.{pattern_str}'
            return pattern_str
        
        # File extensions
        if field == 'c-uri-extension':
            return pattern_str.lstrip('.')
        
        # IP addresses
        if field in ['DestinationIp', 'SourceIp', 'c-ip', 'dst_host', 'src_host']:
            if pattern_str.count('.') == 3:
                return pattern_str
            return f'192.168.{random.randint(1, 254)}.{random.randint(1, 254)}'
        
        # Ports
        if field in ['DestinationPort', 'SourcePort', 'dst_port', 'src_port']:
            if pattern_str.isdigit():
                return int(pattern_str)
            return random.randint(1024, 65535)
        
        # Command lines and processes
        if field in ['CommandLine', 'Image', 'ParentImage', 'ProcessName']:
            if '\\' in pattern_str or '/' in pattern_str:
                return pattern_str
            if field == 'CommandLine':
                return f'cmd.exe /c {pattern_str}'
            return f'C:\\Windows\\System32\\{pattern_str}'
        
        # File paths (Linux)
        if field == 'TargetFilename':
            if '/' in pattern_str:
                return pattern_str
            return f'/etc/{pattern_str}'
        
        # Azure-specific fields
        if field == 'ResourceProviderValue':
            return pattern_str if 'Microsoft' in pattern_str else f'Microsoft.{pattern_str}'
        
        if field == 'CategoryValue':
            return pattern_str if pattern_str else 'Administrative'
        
        if field == 'OperationNameValue':
            return pattern_str if '/' in pattern_str else f'Microsoft.Resource/{pattern_str}'
        
        if field == 'ResourceId':
            if 'providers' in pattern_str or 'subscriptions' in pattern_str:
                return pattern_str
            return f'/subscriptions/test/providers/{pattern_str}'
        
        if field == 'riskEventType':
            return pattern_str if pattern_str else 'suspiciousActivity'
        
        # Okta fields
        if field == 'eventType':
            return pattern_str if pattern_str else 'user.session.start'
        
        # AWS fields
        if field == 'eventName':
            return pattern_str if pattern_str else 'ConsoleLogin'
        
        if field == 'eventSource':
            return pattern_str if '.amazonaws.com' in pattern_str else f'{pattern_str}.amazonaws.com'
        
        # Default: return pattern as-is or with variation
        if len(pattern_str) < 3:
            return pattern_str
        
        variations = [
            pattern_str,
            pattern_str.lower(),
            pattern_str.upper(),
            f'{pattern_str}_variation'
        ]
        return variations[index % len(variations)]
    
    @classmethod
    def _generate_non_matching_value(cls, field: str, pattern: Any, index: int) -> Any:
        """Generate value that should NOT match"""
        
        if isinstance(pattern, list):
            return f'non_matching_{index}'
        
        if pattern is None:
            return f'not_null_{index}'
        
        if isinstance(pattern, bool):
            return not pattern
        
        if isinstance(pattern, (int, float)):
            return pattern + 9999
        
        pattern_str = str(pattern)
        
        # Field-specific non-matches
        if field == 'EventID':
            return 9999
        
        if field == 'logtype':
            return 9999
        
        if field in ['CommandLine', 'Image', 'ProcessName']:
            return f'benign_process_{index}.exe'
        
        if field == 'c-uri-extension':
            return 'txt'
        
        if field in ['DestinationHostname', 'cs-host']:
            return f'safe-domain-{index}.com'
        
        if field == 'CategoryValue':
            return 'Informational'
        
        if field == 'riskEventType':
            return 'normalActivity'
        
        # Generic non-match
        return f'non_matching_{field}_{index}'
    
    @staticmethod
    def _is_regex_like(pattern: str) -> bool:
        """Check if pattern looks like regex"""
        regex_indicators = ['.*', '.+', '[', ']', '(', ')', '^', '$', '\\d', '\\w', '\\s']
        return any(indicator in pattern for indicator in regex_indicators)
    
    @staticmethod
    def _generate_from_pattern(pattern: str, index: int) -> str:
        """Generate string from complex pattern"""
        result = pattern.replace('^', '').replace('$', '')
        result = result.replace('.*', f'test{index}')
        result = result.replace('.+', f'var{index}')
        result = re.sub(r'\\d+', lambda m: str(random.randint(100, 999)), result)
        result = re.sub(r'\\d', lambda m: str(random.randint(0, 9)), result)
        result = re.sub(r'\\w+', lambda m: ''.join(random.choices(string.ascii_letters, k=8)), result)
        result = re.sub(r'\[[^\]]+\]', 'X', result)
        result = result.replace('\\', '')
        return result


# Backward compatibility wrapper
class EnhancedLogGenerator:
    """Wrapper for backward compatibility"""
    
    @staticmethod
    def generate_for_sigma_rule(rule: Dict[str, Any], count: int = 20) -> List[Dict[str, Any]]:
        """Generate logs using Universal generator"""
        return UniversalLogGenerator.generate_for_rule(rule, count)


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
            'detections': [],
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
            
            # Accumulate detections
            self.results['detections'].extend(alerts)
            self.results['statistics'] = metrics
            
            print(f"    Total accumulated detections: {len(self.results['detections'])}")

    def save_results(self):
        """Save validation results"""
        # Save main results
        results_file = self.output_dir / 'validation_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Save detections
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

    # Save results
    validator.save_results()

    print(f"\n✅ Validation complete in {args.mode} mode")
    sys.exit(0)


if __name__ == '__main__':
    main()
