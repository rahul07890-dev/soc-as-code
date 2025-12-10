#!/usr/bin/env python3
"""
COMPLETE FIXED VALIDATOR - Generator with conservative selector-field enabling

Key change:
- If a Sigma rule is NOT considered complex (heuristic), the generator will allow
  top-level selector field names referenced by the rule to be populated in synthetic logs.
  This helps cloud and custom-rule selectors (e.g., OperationNameValue, TargetRole)
  produce matching synthetic logs while avoiding fabricating fields for complex rules.

Other behavior is kept as before (logsource templates, field-specific value generation,
positive/negative split, SOCSimulator-driven rule validation).
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
from test import SOCSimulator, load_sigma_rules


def rule_is_complex(rule: Dict[str, Any]) -> bool:
    """
    Heuristic to decide if a rule is 'complex' and should not have arbitrary selector
    fields auto-populated. Complex rules include regex usage, many selection blocks,
    correlation keywords, or mixed and/or conditions.
    """
    detection = rule.get("detection", {}) or {}
    cond = detection.get("condition", "") if isinstance(detection, dict) else ""
    serialized = json.dumps(detection, default=str)

    # Indicators of complexity / regex use
    if any(x in serialized for x in ("re:", "regexp", ".*", "\\d", "\\w")):
        return True

    # Too many selection blocks
    if isinstance(detection, dict):
        selection_blocks = [k for k in detection.keys() if k != "condition"]
        if len(selection_blocks) > 4:
            return True

    # Mixed and/or correlation
    if isinstance(cond, str) and (" and " in cond.lower() and " or " in cond.lower()):
        return True

    correlation_keywords = ["near", "sequence", "count", "within", "pipeline", "correlation"]
    if any(k in str(cond).lower() for k in correlation_keywords):
        return True

    return False


class UniversalLogGenerator:
    """Generates logs for ANY Sigma rule - conservative selector-field support"""

    LOGSOURCE_TEMPLATES = {
        'azure': {
            'defaults': {
                'CategoryValue': 'Administrative',
                'SubscriptionId': 'sub-12345-test',
                'TenantId': 'tenant-67890',
                # keep defaults minimal — selector fields may be added via allowed_fields logic
            }
        },
        'aws': {
            'defaults': {
                'awsRegion': 'us-east-1',
                'userIdentity': {'type': 'IAMUser', 'userName': 'test-user'},
                'eventVersion': '1.05'
            }
        },
        'okta': {
            'defaults': {
                'actor': {'alternateId': 'test@example.com', 'type': 'User', 'displayName': 'Test User'},
                'outcome': {'result': 'SUCCESS'},
                'client': {'userAgent': {'rawUserAgent': 'Mozilla/5.0'}}
            }
        },
        'onelogin': {
            'defaults': {
                'account_id': 12345,
                'actor_system': 'OneLogin Portal',
                'app_id': None,
                'user_name': 'test@example.com',
                'event_type_id': 5
            }
        },
        'linux': {
            'defaults': {
                'User': 'root',
                'WorkingDirectory': '/home/test',
                'ProcessId': 1234
            }
        },
        'windows': {
            'defaults': {
                'EventID': 4688,
                'User': 'SYSTEM',
                'ProcessId': 1234
            }
        },
        'proxy': {
            'defaults': {
                'c-ip': '192.168.1.100',
                'cs-method': 'GET',
                'sc-status': 200
            }
        },
        'network': {
            'defaults': {
                'Protocol': 'tcp',
                'SourceIp': '10.0.0.1',
                'SourcePort': 51234
            }
        },
        'opencanary': {
            'defaults': {
                'src_host': '192.168.1.50',
                'dst_host': '192.168.1.100'
            }
        },
        'm365': {
            'defaults': {
                'Workload': 'Exchange',
                'Operation': 'MailItemsAccessed',
                'UserId': 'test@example.com',
                'OrganizationId': 'org-123'
            }
        },
        'google_workspace': {
            'defaults': {
                'actor': {'email': 'test@example.com'},
                'kind': 'admin#reports#activity',
                'id': {'applicationName': 'admin'}
            }
        }
    }

    # Minimal internal metadata always allowed
    INTERNAL_META_FIELDS = {
        "_synthetic_id",
        "_origin",
        "_source_rule_id",
        "_source_rule_title",
        "_logsource",
        "_match_type",
    }

    @classmethod
    def generate_for_rule(cls, rule: Dict[str, Any], count: int = 20) -> List[Dict[str, Any]]:
        """
        Generate logs for a sigma rule.

        Behavior:
        - Determine template based on rule logsource.
        - Build allowed_fields from template defaults and internal meta.
        - If the rule is not complex, also add top-level selector field names referenced by the rule.
        - Generate positive/negative logs but only populate fields present in allowed_fields.
        """
        logsource = rule.get('logsource', {}) or {}
        detection = rule.get('detection', {}) or {}

        log_type = cls._detect_log_type(logsource)
        template = cls.LOGSOURCE_TEMPLATES.get(log_type, cls.LOGSOURCE_TEMPLATES['windows'])
        template_defaults = template.get('defaults', {}) if isinstance(template, dict) else {}

        # Build allowed fields conservatively (top-level keys)
        allowed_fields = set()
        if isinstance(template_defaults, dict):
            allowed_fields.update(template_defaults.keys())
        allowed_fields.update(cls.INTERNAL_META_FIELDS)

        # NEW: if rule is not complex, add top-level selection fields referenced by the rule
        try:
            if not rule_is_complex(rule):
                # collect field names from selection blocks (top-level part only)
                selection_blocks = [k for k in detection.keys() if k != 'condition' and isinstance(detection.get(k), dict)]
                sel_fields = set()
                for sel in selection_blocks:
                    block = detection.get(sel, {}) or {}
                    if isinstance(block, dict):
                        for fld in block.keys():
                            # field may have modifiers like "CommandLine|contains" or dotted paths
                            base = fld.split('|')[0].split('.')[0]
                            if base:
                                sel_fields.add(base)
                # conservative: only add if reasonable (alpha/underscore characters)
                for f in sel_fields:
                    if re.match(r'^[A-Za-z0-9_\-]+$', f):
                        allowed_fields.add(f)
        except Exception:
            # fall back to strict allowed_fields if anything goes wrong
            pass

        # Only proceed if there is at least one selection block (otherwise nothing to match)
        selections = {}
        for key, value in detection.items():
            if key != 'condition' and isinstance(value, dict):
                selections[key] = value
        if not selections:
            return []

        primary_selection = list(selections.values())[0]

        logs = []
        positive_count = max(15, int(count * 0.75))

        def is_field_allowed(field_name: str) -> bool:
            top = field_name.split('.')[0]
            # strip modifier part if present
            top = top.split('|')[0]
            return top in allowed_fields

        # POSITIVE matches
        for i in range(positive_count):
            log = cls._create_base_log(template, i, log_type)
            log['_match_type'] = 'positive'
            for field, pattern in primary_selection.items():
                field_name = field.split('|')[0]
                if not is_field_allowed(field_name):
                    # skip populating disallowed selector fields
                    continue
                value = cls._generate_matching_value(field_name, pattern, i, log_type)
                cls._set_field(log, field_name, value)
            logs.append(log)

        # NEGATIVE matches
        negative_count = count - positive_count
        for i in range(negative_count):
            log = cls._create_base_log(template, i, log_type)
            log['_match_type'] = 'negative'
            for field, pattern in primary_selection.items():
                field_name = field.split('|')[0]
                if not is_field_allowed(field_name):
                    continue
                value = cls._generate_non_matching_value(field_name, pattern, i, log_type)
                cls._set_field(log, field_name, value)
            logs.append(log)

        return logs

    @staticmethod
    def _detect_log_type(logsource: Dict[str, Any]) -> str:
        product = (logsource.get('product') or '').lower()
        category = (logsource.get('category') or '').lower()
        service = (logsource.get('service') or '').lower()

        if 'onelogin' in product:
            return 'onelogin'
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
        if 'm365' in product or 'office365' in product or 'microsoft365' in product:
            return 'm365'
        if 'google' in product or 'workspace' in product:
            return 'google_workspace'

        if 'proxy' in category or 'web' in category:
            return 'proxy'
        if 'network' in category or 'firewall' in category:
            return 'network'
        if 'process' in category:
            return 'windows'
        if 'file' in category:
            return 'linux' if 'linux' in product else 'windows'

        if 'onelogin' in service:
            return 'onelogin'
        if 'activitylogs' in service or 'pim' in service:
            return 'azure'
        return 'windows'

    @staticmethod
    def _create_base_log(template: Dict, index: int, log_type: str) -> Dict[str, Any]:
        log = {
            '_generated': True,
            '_test_id': str(index),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'host': f'test-host-{index % 3}'
        }
        defaults = template.get('defaults', {}) if isinstance(template, dict) else {}
        for key, value in defaults.items():
            if isinstance(value, dict):
                log[key] = value.copy()
            elif isinstance(value, list):
                log[key] = value.copy()
            else:
                log[key] = value
        return log

    @staticmethod
    def _set_field(log: Dict, field_path: str, value: Any):
        if '.' in field_path:
            parts = field_path.split('.')
            current = log
            for part in parts[:-1]:
                if part not in current or not isinstance(current[part], dict):
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = value
        else:
            log[field_path] = value

    @classmethod
    def _generate_matching_value(cls, field: str, pattern: Any, index: int, log_type: str) -> Any:
        if isinstance(pattern, list):
            return pattern[index % len(pattern)]
        if pattern is None:
            return None
        if isinstance(pattern, bool):
            return pattern
        if isinstance(pattern, (int, float)):
            return pattern
        pattern_str = str(pattern)

        if field in ['EventID', 'event_type_id', 'logtype']:
            if pattern_str.isdigit():
                return int(pattern_str)
            return 4688

        if field == 'event_type_id':
            return int(pattern_str) if pattern_str.isdigit() else 5

        if field == 'user_name':
            return pattern_str if '@' in pattern_str else f'{pattern_str}@example.com'

        if field == 'actor_system':
            return pattern_str if pattern_str else 'OneLogin Portal'

        if field == 'CategoryValue':
            return pattern_str if pattern_str else 'Administrative'

        if field == 'ResourceProviderValue':
            if 'Microsoft' in pattern_str:
                return pattern_str
            return f'Microsoft.{pattern_str}' if pattern_str else 'Microsoft.Resource'

        if field == 'OperationNameValue':
            if '/' in pattern_str:
                return pattern_str
            return f'Microsoft.Resource/{pattern_str}' if pattern_str else 'Microsoft.Authorization/roleAssignments/write'

        if field == 'ResourceId':
            if 'subscriptions' in pattern_str or 'providers' in pattern_str:
                return pattern_str
            return f'/subscriptions/test/providers/Microsoft.Resource/{pattern_str}'

        if field == 'riskEventType':
            return pattern_str if pattern_str else 'suspiciousActivity'

        if field == 'eventName':
            return pattern_str if pattern_str else 'ConsoleLogin'

        if field == 'eventSource':
            if '.amazonaws.com' in pattern_str:
                return pattern_str
            return f'{pattern_str}.amazonaws.com' if pattern_str else 's3.amazonaws.com'

        if field == 'eventType':
            return pattern_str if pattern_str else 'user.session.start'

        if field == 'Workload':
            return pattern_str if pattern_str else 'Exchange'

        if field == 'Operation':
            return pattern_str if pattern_str else 'MailItemsAccessed'

        if '*' in pattern_str:
            if pattern_str.startswith('*') and pattern_str.endswith('*'):
                core = pattern_str.strip('*')
                variations = [core, f'pre_{core}', f'{core}_suf', f'x{core}y']
                return variations[index % len(variations)]
            elif pattern_str.startswith('*'):
                return f'prefix_{pattern_str.lstrip("*")}'
            elif pattern_str.endswith('*'):
                suffixes = ['', '_test', '123', f'_{index}']
                return f'{pattern_str.rstrip("*")}{suffixes[index % len(suffixes)]}'

        if cls._is_regex_like(pattern_str):
            return cls._generate_from_pattern(pattern_str, index)

        if field in ['c-uri', 'cs-host', 'url', 'DestinationHostname']:
            if 'http' not in pattern_str.lower():
                if '.' in pattern_str:
                    return pattern_str
                return f'malicious.{pattern_str}.com'
            return pattern_str

        if field == 'c-uri-extension':
            return pattern_str.lstrip('.')

        if field in ['DestinationIp', 'SourceIp', 'c-ip', 'dst_host', 'src_host']:
            if pattern_str.count('.') == 3:
                return pattern_str
            return f'192.168.{random.randint(1,254)}.{random.randint(1,254)}'

        if field in ['DestinationPort', 'SourcePort', 'dst_port', 'src_port']:
            if pattern_str.isdigit():
                return int(pattern_str)
            return random.randint(1024, 65535)

        if field in ['CommandLine', 'Image', 'ParentImage', 'ProcessName']:
            if '\\' in pattern_str or '/' in pattern_str:
                return pattern_str
            if field == 'CommandLine':
                return f'cmd.exe /c {pattern_str}'
            return f'C:\\Windows\\System32\\{pattern_str}'

        if field == 'TargetFilename':
            if '/' in pattern_str:
                return pattern_str
            return f'/etc/{pattern_str}'

        if len(pattern_str) < 3:
            return pattern_str

        variations = [pattern_str, pattern_str.lower(), f'{pattern_str}_test']
        return variations[index % len(variations)]

    @classmethod
    def _generate_non_matching_value(cls, field: str, pattern: Any, index: int, log_type: str) -> Any:
        if isinstance(pattern, list):
            return f'nomatch_{index}'
        if pattern is None:
            return f'notnull_{index}'
        if isinstance(pattern, bool):
            return not pattern
        if isinstance(pattern, (int, float)):
            return pattern + 9999

        if field in ['EventID', 'event_type_id', 'logtype']:
            return 9999

        if field in ['CommandLine', 'Image', 'ProcessName']:
            return f'benign_{index}.exe'

        if field == 'c-uri-extension':
            return 'txt'

        if field in ['DestinationHostname', 'cs-host']:
            return f'safe-{index}.com'

        if field == 'user_name':
            return f'normal_user_{index}@safe.com'

        return f'nomatch_{field}_{index}'

    @staticmethod
    def _is_regex_like(s: str) -> bool:
        indicators = ['.*', '.+', '[', ']', '(', ')', '^', '$', '\\d', '\\w']
        return any(ind in s for ind in indicators)

    @staticmethod
    def _generate_from_pattern(pattern: str, index: int) -> str:
        result = pattern.replace('^', '').replace('$', '')
        result = result.replace('.*', f'test{index}')
        result = result.replace('.+', f'var{index}')
        result = re.sub(r'\\d+', str(random.randint(100, 999)), result)
        result = re.sub(r'\\d', str(random.randint(0, 9)), result)
        result = re.sub(r'\\w+', ''.join(random.choices(string.ascii_letters, k=8)), result)
        result = re.sub(r'\[[^\]]+\]', 'X', result)
        result = result.replace('\\', '')
        return result


class EnhancedLogGenerator:
    """Compatibility wrapper"""
    @staticmethod
    def generate_for_sigma_rule(rule: Dict[str, Any], count: int = 20) -> List[Dict[str, Any]]:
        return UniversalLogGenerator.generate_for_rule(rule, count)


class RuleValidator:
    """Rule validator with universal log generation"""
    def __init__(self, output_dir: str, mode: str = 'current', synthetic_logs_dir: str = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.synthetic_logs_dir = Path(synthetic_logs_dir) if synthetic_logs_dir else None
        self.synthetic_logs = []

        self.results = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'mode': mode,
            'detections': [],
            'statistics': {}
        }

    def load_synthetic_logs(self):
        if not self.synthetic_logs_dir or not self.synthetic_logs_dir.exists():
            return

        print(f"[+] Loading synthetic logs from: {self.synthetic_logs_dir}")

        for log_file in self.synthetic_logs_dir.glob('*.jsonl'):
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        self.synthetic_logs.append(json.loads(line))

        print(f"    Loaded {len(self.synthetic_logs)} logs")

    def validate_all_rules(self, rules_dir: str, rule_type: str = 'sigma'):
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            return

        print(f"\n[+] Validating {rule_type.upper()} rules in: {rules_dir}")

        if rule_type == 'sigma':
            rule_files = list(rules_path.rglob('*.yml')) + list(rules_path.rglob('*.yaml'))
        else:
            rule_files = list(rules_path.rglob('*.yara')) + list(rules_path.rglob('*.yar'))

        print(f"    Found {len(rule_files)} files")

        all_rules = []
        for rule_file in rule_files:
            try:
                if rule_type == 'sigma':
                    all_rules.extend(load_sigma_rules(str(rule_file)))
            except Exception as e:
                print(f"    Error loading {rule_file}: {e}")

        print(f"    Loaded {len(all_rules)} rules")

        if self.synthetic_logs:
            print(f"    Running against {len(self.synthetic_logs)} logs...")

            simulator = SOCSimulator(sigma_rules=all_rules, yara_path=None)
            simulator.process_logs(self.synthetic_logs)

            alerts = simulator.export_alerts()
            metrics = simulator.export_metrics()

            print(f"    Generated {len(alerts)} alerts")

            self.results['detections'].extend(alerts)
            self.results['statistics'] = metrics

    def save_results(self):
        results_file = self.output_dir / 'validation_results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)

        detections_file = self.output_dir / 'detections.json'
        with open(detections_file, 'w', encoding='utf-8') as f:
            json.dump(self.results['detections'], f, indent=2)

        print(f"    Saved {len(self.results['detections'])} detections")

        stats_file = self.output_dir / 'statistics.json'
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(self.results.get('statistics', {}), f, indent=2)


def main():
    parser = argparse.ArgumentParser(description='Universal Rule Validator (strict but selector-friendly)')
    parser.add_argument('--all-sigma-rules', help='Sigma rules directory')
    parser.add_argument('--all-yara-rules', help='YARA rules directory')
    parser.add_argument('--synthetic-logs-dir', help='Synthetic logs directory')
    parser.add_argument('--output-dir', default='validation_results', help='Output directory')
    parser.add_argument('--mode', choices=['baseline', 'current'], default='current')
    args = parser.parse_args()

    validator = RuleValidator(args.output_dir, mode=args.mode, synthetic_logs_dir=args.synthetic_logs_dir)

    if args.synthetic_logs_dir:
        validator.load_synthetic_logs()

    if args.all_sigma_rules:
        validator.validate_all_rules(args.all_sigma_rules, rule_type='sigma')

    if args.all_yara_rules:
        validator.validate_all_rules(args.all_yara_rules, rule_type='yara')

    validator.save_results()
    print(f"\n✅ Validation complete ({args.mode} mode)")


if __name__ == '__main__':
    main()
