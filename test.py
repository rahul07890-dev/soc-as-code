"""
SOC Simulator (SOC-as-Code) - Fixed version with corrected wildcard matching

Key fix: Wildcard patterns (* and ?) are now checked BEFORE regex patterns
to prevent misinterpreting wildcards as regex metacharacters.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from random import choice, randint, randrange
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Optional dependencies
try:
    import yaml
except Exception:
    yaml = None

try:
    import yara
except Exception:
    yara = None


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    severity: str
    timestamp: str
    host: Optional[str]
    matched_fields: Dict[str, Any]
    raw: Dict[str, Any]


class LogIngestor:
    """Loads JSON logs from files (one JSON object per line or a JSON array/file)."""

    def __init__(self, paths: Iterable[str]):
        self.paths = list(paths)

    def iter_logs(self):
        for p in self.paths:
            if os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for f in files:
                        full = os.path.join(root, f)
                        yield from self._read_file(full)
            else:
                yield from self._read_file(p)

    def _read_file(self, path: str):
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                text = fh.read()
                text = text.strip()
                if not text:
                    return
                try:
                    doc = json.loads(text)
                    if isinstance(doc, list):
                        for item in doc:
                            yield item
                    elif isinstance(doc, dict):
                        yield doc
                    else:
                        raise ValueError
                except Exception:
                    fh.seek(0)
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except Exception:
                            continue
        except FileNotFoundError:
            print(f"[warn] file not found: {path}")


class SigmaRule:
    """Improved simplified Sigma rule evaluator that supports multiple named selections and conditions."""

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.title = raw.get('title') or raw.get('name') or 'Unnamed rule'
        self.id = raw.get('id') or raw.get('rule_id') or self.title
        self.level = str(raw.get('level') or raw.get('severity') or 'unknown').lower()
        self.detection = raw.get('detection') or {}
        self.selections = self._parse_selections(self.detection)
        self.condition = self._parse_condition(self.detection)

    @staticmethod
    def _parse_selections(detection: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        if 'selection' in detection and isinstance(detection['selection'], dict):
            out['selection'] = detection['selection']
        for k, v in detection.items():
            if k in ('selection', 'condition'):
                continue
            if isinstance(v, dict):
                out[k] = v
        return out

    @staticmethod
    def _parse_condition(detection: Dict[str, Any]) -> Optional[str]:
        cond = detection.get('condition')
        if cond is None and 'selection' in detection:
            return 'selection'
        return cond

    @staticmethod
    def _get_value_by_path(doc: Dict[str, Any], path: str) -> Tuple[bool, Any]:
        parts = path.split('.')
        cur = doc
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return False, None
        return True, cur

    @staticmethod
    def _is_regex_pattern(s: str) -> bool:
        """Detect actual regex patterns (not wildcards)"""
        if not isinstance(s, str):
            return False
        
        # If it ONLY has simple wildcards and no regex chars, it's NOT regex
        # But if it has wildcards AND regex chars, it IS regex
        has_simple_wildcard = '*' in s or '?' in s
        
        # Check for actual regex metacharacters used in regex syntax
        regex_indicators = [
            '.*',      # Any character repeated
            '.+',      # One or more any character
            '^',       # Start anchor
            '

    @classmethod
    def _match_value(cls, pattern: Any, value: Any) -> bool:
        # support list of patterns
        if isinstance(pattern, list):
            return any(cls._match_value(p, value) for p in pattern)

        # numbers and bools
        if isinstance(pattern, (int, float, bool)):
            return pattern == value
        if isinstance(value, (int, float, bool)) and not isinstance(value, str):
            return str(pattern) == str(value)

        val = '' if value is None else str(value)
        patt = '' if pattern is None else str(pattern)

        # CRITICAL: Check for REGEX FIRST (before wildcards)
        # If pattern contains regex metacharacters like [, ], {, }, ., +, etc., treat as regex
        if cls._is_regex_pattern(patt):
            try:
                return re.search(patt, val, flags=re.IGNORECASE) is not None
            except re.error:
                # If regex fails, fall back to literal match
                return patt.lower() == val.lower()

        # WILDCARDS: Check wildcards AFTER regex check
        # Simple wildcards (* and ?) without regex chars
        if '*' in patt or '?' in patt:
            # This is a pure wildcard pattern - convert to regex
            # Use re.escape to handle all special chars, then replace escaped wildcards
            re_p = '^' + re.escape(patt).replace(r'\*', '.*').replace(r'\?', '.') + '

    @classmethod
    def matches_selection(cls, selection: Dict[str, Any], log: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        matched: Dict[str, Any] = {}
        for key, pattern in selection.items():
            found, value = cls._get_value_by_path(log, key)
            if not found:
                return False, {}
            if cls._match_value(pattern, value):
                matched[key] = value
            else:
                return False, {}
        return True, matched

    def matches(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.selections:
            return None
        sel_results: Dict[str, Tuple[bool, Dict[str, Any]]] = {}
        for name, sel in self.selections.items():
            sel_results[name] = self.matches_selection(sel, log)

        cond = self.condition or 'selection'
        bool_map = {name: res[0] for name, res in sel_results.items()}
        cond_eval = self._render_condition(cond, bool_map)
        try:
            result = eval(cond_eval, {"__builtins__": None}, {})
        except Exception:
            return None

        if result:
            merged: Dict[str, Any] = {}
            for name, (ok, fields) in sel_results.items():
                if ok:
                    merged.update(fields)
            return merged
        return None

    @staticmethod
    def _render_condition(condition: str, bool_map: Dict[str, bool]) -> str:
        token_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b|\(|\)")

        def repl(m):
            tok = m.group(0)
            if tok.lower() in ('and', 'or', 'not', 'true', 'false'):
                return tok.lower()
            if tok in bool_map:
                return 'True' if bool_map[tok] else 'False'
            return 'False'

        rendered = token_re.sub(repl, condition)
        return rendered


class YaraEngine:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path
        self.compiled = None
        if yara and rules_path:
            try:
                self.compiled = yara.compile(filepath=rules_path)
            except Exception as e:
                print(f"[warn] failed to compile YARA: {e}")
                self.compiled = None

    def match(self, text: str) -> List[Dict[str, Any]]:
        if not self.compiled:
            return []
        try:
            matches = self.compiled.match(data=text)
            out: List[Dict[str, Any]] = []
            for m in matches:
                out.append({'rule': m.rule, 'tags': getattr(m, 'tags', []), 'meta': getattr(m, 'meta', {})})
            return out
        except Exception as e:
            print(f"[warn] yara match failed: {e}")
            return []


class RuleEngine:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.sigma_rules: List[SigmaRule] = [SigmaRule(r) for r in (sigma_rules or [])]
        self.yara_engine = YaraEngine(yara_path) if yara_path else None

    def eval_log(self, log: Dict[str, Any]) -> List[Alert]:
        alerts: List[Alert] = []
        for r in self.sigma_rules:
            matched_fields = r.matches(log)
            if matched_fields is not None:
                alerts.append(Alert(
                    rule_id=r.id,
                    rule_title=r.title,
                    severity=r.level,
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields=matched_fields,
                    raw=log,
                ))

        if self.yara_engine and self.yara_engine.compiled:
            try:
                raw_text = json.dumps(log)
            except Exception:
                raw_text = str(log)
            matches = self.yara_engine.match(raw_text)
            for m in matches:
                alerts.append(Alert(
                    rule_id=m.get('rule', 'yara'),
                    rule_title='YARA:' + m.get('rule', 'yara'),
                    severity='medium',
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields={'yara_tags': m.get('tags'), 'yara_meta': m.get('meta')},
                    raw=log,
                ))
        return alerts

    @staticmethod
    def _get_host(log: Dict[str, Any]) -> Optional[str]:
        for k in ('host', 'hostname', 'agent', 'source'):
            if k in log:
                v = log.get(k)
                if isinstance(v, dict):
                    return v.get('name')
                return v
        return None


class MetricsCollector:
    def __init__(self):
        self.total_logs = 0
        self.logs_per_host = defaultdict(int)
        self.alerts_per_rule = defaultdict(int)
        self.alerts_per_severity = defaultdict(int)
        self.alerts_per_host = defaultdict(int)

    def ingest_log(self, log: Dict[str, Any]):
        self.total_logs += 1
        host = log.get('host') or log.get('hostname') or 'unknown'
        if isinstance(host, dict):
            host = host.get('name', 'unknown')
        self.logs_per_host[host] += 1

    def record_alert(self, alert: Alert):
        self.alerts_per_rule[alert.rule_id] += 1
        self.alerts_per_severity[alert.severity] += 1
        host = alert.host or 'unknown'
        self.alerts_per_host[host] += 1

    def snapshot(self):
        return {
            'total_logs': self.total_logs,
            'logs_per_host': dict(self.logs_per_host),
            'alerts_per_rule': dict(self.alerts_per_rule),
            'alerts_per_severity': dict(self.alerts_per_severity),
            'alerts_per_host': dict(self.alerts_per_host),
        }


class SOCSimulator:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.rule_engine = RuleEngine(sigma_rules, yara_path)
        self.metrics = MetricsCollector()
        self.alerts: List[Alert] = []

    def process_logs(self, logs: Iterable[Dict[str, Any]]):
        for log in logs:
            self.metrics.ingest_log(log)
            alerts = self.rule_engine.eval_log(log)
            for a in alerts:
                self.alerts.append(a)
                self.metrics.record_alert(a)

    def export_alerts(self) -> List[Dict[str, Any]]:
        return [asdict(a) for a in self.alerts]

    def export_metrics(self) -> Dict[str, Any]:
        return self.metrics.snapshot()


def load_sigma_rules(path: str) -> List[Dict[str, Any]]:
    if not yaml:
        raise RuntimeError("PyYAML is required to load sigma rules. Install with: pip install pyyaml")
    with open(path, 'r', encoding='utf-8') as fh:
        docs = list(yaml.safe_load_all(fh))
        out: List[Dict[str, Any]] = []
        for d in docs:
            if d is None:
                continue
            if isinstance(d, list):
                out.extend(d)
            else:
                out.append(d)
        return out


def collect_log_files_from_dir(path: str) -> List[str]:
    files: List[str] = []
    if os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for f in filenames:
                files.append(os.path.join(root, f))
    elif os.path.isfile(path):
        files.append(path)
    return files


def _write_file(path: str, data: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(data)


def generate_sample_workspace(base_dir: str):
    logs_dir = os.path.join(base_dir, 'logs')
    rules_dir = os.path.join(base_dir, 'rules')
    yara_dir = os.path.join(base_dir, 'yara')
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(rules_dir, exist_ok=True)
    os.makedirs(yara_dir, exist_ok=True)

    log1 = {
        'host': 'host1',
        'EventID': 4688,
        'NewProcessName': r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'CommandLine': 'powershell -nop -w hidden -c IEX ...'
    }
    log2 = {
        'host': 'host2',
        'HttpMethod': 'POST',
        'RequestUri': '/upload.php?cmd=whoami',
        'UserAgent': 'curl/7.x'
    }
    log3 = {
        'host': 'host3',
        'message': 'This contains MALICIOUS_SIGNATURE inside payload',
        'some_field': 'some value'
    }

    for i, log in enumerate((log1, log2, log3), start=1):
        _write_file(os.path.join(logs_dir, f'log{i}.json'), json.dumps(log) + '\n')

    sigma_rules_yaml = """
- title: "Suspicious PowerShell"
  id: "SIG-0001"
  level: high
  detection:
    selection:
      EventID: 4688
      NewProcessName: ".*powershell.*"
    condition: selection

- title: "Possible Webshell POST"
  id: "SIG-0002"
  level: medium
  detection:
    post_req:
      HttpMethod: POST
      RequestUri: "*cmd=*"
    condition: post_req
"""
    _write_file(os.path.join(rules_dir, 'sigma_rules.yml'), sigma_rules_yaml)

    yara_rule = """
rule MaliciousSignature
{
    strings:
        $a = "MALICIOUS_SIGNATURE"
    condition:
        $a
}
"""
    _write_file(os.path.join(yara_dir, 'malicious.yar'), yara_rule)

    return {
        'logs_dir': logs_dir,
        'sigma_path': os.path.join(rules_dir, 'sigma_rules.yml'),
        'yara_path': os.path.join(yara_dir, 'malicious.yar')
    }


def generate_synthetic_workspace(base_dir: str, count: int = 100, include_yara: bool = True, include_sigma: bool = True):
    logs_dir = os.path.join(base_dir, 'logs')
    rules_dir = os.path.join(base_dir, 'rules')
    yara_dir = os.path.join(base_dir, 'yara')
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(rules_dir, exist_ok=True)
    if include_yara:
        os.makedirs(yara_dir, exist_ok=True)

    hosts = [f'host{i}' for i in range(1, 11)]
    processes = ['cmd.exe', 'powershell.exe', 'notepad.exe', 'python.exe']
    uris = ['/index.html', '/login', '/upload.php?cmd=whoami', '/api/data']

    path = os.path.join(logs_dir, 'synthetic.jsonl')
    with open(path, 'w', encoding='utf-8') as fh:
        for _ in range(count):
            t = randint(1, 3)
            if t == 1:
                log = {
                    'host': choice(hosts),
                    'EventID': 4688,
                    'NewProcessName': choice(processes),
                    'CommandLine': ' '.join(['-'.join([choice(['-nop','-w','-c']), '...'])])
                }
            elif t == 2:
                log = {
                    'host': choice(hosts),
                    'HttpMethod': choice(['GET', 'POST']),
                    'RequestUri': choice(uris),
                    'UserAgent': choice(['curl/7.64', 'Mozilla/5.0', 'python-requests/2.x'])
                }
            else:
                msg = 'normal message'
                if randrange(20) == 0:
                    msg = 'contains MALICIOUS_SIGNATURE in payload'
                log = {
                    'host': choice(hosts),
                    'message': msg,
                    'random_field': randint(0, 1000)
                }
            fh.write(json.dumps(log) + '\n')

    if include_sigma:
        sigma_rules_yaml = """
- title: "Synthetic Suspicious PowerShell"
  id: "SIG-SYN-001"
  level: high
  detection:
    selection:
      EventID: 4688
      NewProcessName: ".*powershell.*"
    condition: selection

- title: "Synthetic Web POST with cmd"
  id: "SIG-SYN-002"
  level: medium
  detection:
    post_req:
      HttpMethod: POST
      RequestUri: "*cmd=*"
    condition: post_req
"""
        _write_file(os.path.join(rules_dir, 'sigma_synthetic.yml'), sigma_rules_yaml)

    if include_yara:
        yara_rule = """
rule SyntheticMalicious
{
    strings:
        $a = "MALICIOUS_SIGNATURE"
    condition:
        $a
}
"""
        _write_file(os.path.join(yara_dir, 'synthetic.yar'), yara_rule)

    return {
        'logs_dir': logs_dir,
        'sigma_path': os.path.join(rules_dir, 'sigma_synthetic.yml') if include_sigma else None,
        'yara_path': os.path.join(yara_dir, 'synthetic.yar') if include_yara else None
    }


def run_sample_tests(verbose: bool = True) -> int:
    tmp = tempfile.mkdtemp(prefix='soc_sim_sample_')
    try:
        paths = generate_sample_workspace(tmp)

        if verbose:
            print(f"Generated sample workspace at: {tmp}")
            print(json.dumps(paths, indent=2))

        if not yaml:
            print("ERROR: PyYAML is required to load the sample Sigma rules. Install with: pip install pyyaml")
            return 3
        sigma_rules = load_sigma_rules(paths['sigma_path'])

        yara_path = paths['yara_path'] if yara else None
        if yara_path and not yara:
            print("Note: yara-python not installed; YARA tests will be skipped.")

        log_files = collect_log_files_from_dir(paths['logs_dir'])
        ingestor = LogIngestor(log_files)
        sim = SOCSimulator(sigma_rules=sigma_rules, yara_path=yara_path)
        sim.process_logs(ingestor.iter_logs())

        alerts = sim.export_alerts()
        metrics = sim.export_metrics()

        if verbose:
            print('\n--- Alerts (JSON) ---')
            print(json.dumps(alerts, indent=2))
            print('\n--- Metrics ---')
            print(json.dumps(metrics, indent=2))

        errors: List[str] = []
        if metrics.get('total_logs') != 3:
            errors.append(f"expected total_logs==3, got {metrics.get('total_logs')}")

        sigma_alerts = [a for a in alerts if not a['rule_id'].lower().startswith('yara')]
        if len(sigma_alerts) < 2:
            errors.append(f"expected >=2 sigma alerts, got {len(sigma_alerts)}")

        if yara and yara_path:
            yara_alerts = [a for a in alerts if a['rule_id'].lower().startswith('malicioussignature') or a['rule_title'].lower().startswith('yara:')]
            if len(yara_alerts) < 1:
                errors.append(f"expected >=1 yara alerts, got {len(yara_alerts)}")

        if errors:
            print('\n*** Sample tests FAILED ***')
            for e in errors:
                print(' -', e)
            return 2

        print('\n*** Sample tests PASSED')
        return 0
    finally:
        try:
            shutil.rmtree(tmp)
        except Exception:
            pass


def main_cli(argv=None):
    p = argparse.ArgumentParser(description='SOC Simulator - ingest logs, run Sigma/YARA rules, export alerts/metrics')
    p.add_argument('--logs', required=False, help='Path to log file or directory containing logs (JSON)')
    p.add_argument('--sigma', required=False, help='Path to Sigma YAML file (supports multi-doc or list)')
    p.add_argument('--yara', required=False, help='Path to YARA rules file (.yar or .yara)')
    p.add_argument('--out', required=False, help='Write alerts JSON to this file (default: alerts.json)', default='alerts.json')
    p.add_argument('--metrics', required=False, help='Write metrics JSON to this file (default: metrics.json)', default='metrics.json')
    p.add_argument('--fail-on-severity', required=False, choices=['low', 'medium', 'high', 'critical'],
                   help='Exit with code 2 if an alert of this severity or higher is produced (CI/CD friendly)')
    p.add_argument('--run-samples', action='store_true', help='Generate sample logs and rules and run built-in tests')
    p.add_argument('--generate-synthetic', nargs='?', const='synthetic_workspace', help='Generate a synthetic workspace. Provide base dir or omit to use ./synthetic_workspace')
    p.add_argument('--count', type=int, default=100, help='Count of synthetic logs to generate when using --generate-synthetic')
    p.add_argument('--yara-generate', action='store_true', help='When generating synthetic, also create a yara file')
    args = p.parse_args(argv)

    if args.run_samples:
        rc = run_sample_tests(verbose=True)
        return rc

    if args.generate_synthetic is not None:
        base = args.generate_synthetic or 'synthetic_workspace'
        base = os.path.abspath(base)
        print(f"Generating synthetic workspace at: {base} (count={args.count}, yara={args.yara_generate})")
        out = generate_synthetic_workspace(base, count=args.count, include_yara=args.yara_generate, include_sigma=True)
        print(json.dumps(out, indent=2))
        print("Done. Inspect the generated files under the workspace and run the simulator with --logs and --sigma.")
        return 0

    if not args.logs:
        print('Either --logs, --run-samples or --generate-synthetic must be provided')
        return 1

    sigma_rules: List[Dict[str, Any]] = []
    if args.sigma:
        try:
            sigma_rules = load_sigma_rules(args.sigma)
            print(f"Loaded {len(sigma_rules)} sigma rules from {args.sigma}")
        except Exception as e:
            print(f"Failed to load sigma rules: {e}")
            return 1

    paths = collect_log_files_from_dir(args.logs)
    if not paths:
        print("No log files found")
        return 1

    ingestor = LogIngestor(paths)
    simulator = SOCSimulator(sigma_rules, yara_path=args.yara)

    simulator.process_logs(ingestor.iter_logs())

    alerts = simulator.export_alerts()
    metrics = simulator.export_metrics()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.metrics) or ".", exist_ok=True)

    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump({'alerts': alerts}, fh, indent=2)
    with open(args.metrics, 'w', encoding='utf-8') as fh:
        json.dump({'metrics': metrics}, fh, indent=2)

    print(f"Processed logs. Alerts: {len(alerts)}. Metrics: {json.dumps(metrics)}")

    if args.fail_on_severity and alerts:
        level_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threshold = level_order.get(args.fail_on_severity, 2)
        for a in alerts:
            sev = a['severity'].lower() if isinstance(a.get('severity'), str) else 'medium'
            if level_order.get(sev, 2) >= threshold:
                print(f"Failing because alert {a['rule_id']} severity={a['severity']}")
                return 2

    return 0


if __name__ == '__main__':
    rc = main_cli()
    sys.exit(rc)
,       # End anchor (but not $ as last char only)
            '[',       # Character class
            ']',       # Character class end
            '(',       # Grouping
            '|',       # Alternation
            '{',       # Quantifier
            '}',       # Quantifier end
            '\\d',     # Digit
            '\\w',     # Word character
            '\\s',     # Whitespace
        ]
        
        has_regex = any(indicator in s for indicator in regex_indicators)
        
        # If it has regex indicators, it's regex (even if it also has wildcards)
        if has_regex:
            return True
        
        # If it ONLY has wildcards and no regex chars, it's a wildcard pattern
        if has_simple_wildcard and not has_regex:
            return False
        
        return False

    @classmethod
    def _match_value(cls, pattern: Any, value: Any) -> bool:
        # support list of patterns
        if isinstance(pattern, list):
            return any(cls._match_value(p, value) for p in pattern)

        # numbers and bools
        if isinstance(pattern, (int, float, bool)):
            return pattern == value
        if isinstance(value, (int, float, bool)) and not isinstance(value, str):
            return str(pattern) == str(value)

        val = '' if value is None else str(value)
        patt = '' if pattern is None else str(pattern)

        # CRITICAL FIX: Check wildcards BEFORE regex
        # Wildcard patterns (* or ?) are common in Sigma rules and should be handled first
        if '*' in patt or '?' in patt:
            # This is a wildcard pattern - convert to regex
            # Use re.escape to handle all special chars, then replace escaped wildcards
            re_p = '^' + re.escape(patt).replace(r'\*', '.*').replace(r'\?', '.') + '$'
            try:
                return re.search(re_p, val, flags=re.IGNORECASE) is not None
            except re.error:
                return patt.lower() == val.lower()

        # regex (only if it looks like actual regex syntax)
        if cls._is_regex_pattern(patt):
            try:
                return re.search(patt, val, flags=re.IGNORECASE) is not None
            except re.error:
                return patt.lower() == val.lower()

        # plain equality (case-insensitive)
        return patt.lower() == val.lower()

    @classmethod
    def matches_selection(cls, selection: Dict[str, Any], log: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        matched: Dict[str, Any] = {}
        for key, pattern in selection.items():
            found, value = cls._get_value_by_path(log, key)
            if not found:
                return False, {}
            if cls._match_value(pattern, value):
                matched[key] = value
            else:
                return False, {}
        return True, matched

    def matches(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.selections:
            return None
        sel_results: Dict[str, Tuple[bool, Dict[str, Any]]] = {}
        for name, sel in self.selections.items():
            sel_results[name] = self.matches_selection(sel, log)

        cond = self.condition or 'selection'
        bool_map = {name: res[0] for name, res in sel_results.items()}
        cond_eval = self._render_condition(cond, bool_map)
        try:
            result = eval(cond_eval, {"__builtins__": None}, {})
        except Exception:
            return None

        if result:
            merged: Dict[str, Any] = {}
            for name, (ok, fields) in sel_results.items():
                if ok:
                    merged.update(fields)
            return merged
        return None

    @staticmethod
    def _render_condition(condition: str, bool_map: Dict[str, bool]) -> str:
        token_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b|\(|\)")

        def repl(m):
            tok = m.group(0)
            if tok.lower() in ('and', 'or', 'not', 'true', 'false'):
                return tok.lower()
            if tok in bool_map:
                return 'True' if bool_map[tok] else 'False'
            return 'False'

        rendered = token_re.sub(repl, condition)
        return rendered


class YaraEngine:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path
        self.compiled = None
        if yara and rules_path:
            try:
                self.compiled = yara.compile(filepath=rules_path)
            except Exception as e:
                print(f"[warn] failed to compile YARA: {e}")
                self.compiled = None

    def match(self, text: str) -> List[Dict[str, Any]]:
        if not self.compiled:
            return []
        try:
            matches = self.compiled.match(data=text)
            out: List[Dict[str, Any]] = []
            for m in matches:
                out.append({'rule': m.rule, 'tags': getattr(m, 'tags', []), 'meta': getattr(m, 'meta', {})})
            return out
        except Exception as e:
            print(f"[warn] yara match failed: {e}")
            return []


class RuleEngine:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.sigma_rules: List[SigmaRule] = [SigmaRule(r) for r in (sigma_rules or [])]
        self.yara_engine = YaraEngine(yara_path) if yara_path else None

    def eval_log(self, log: Dict[str, Any]) -> List[Alert]:
        alerts: List[Alert] = []
        for r in self.sigma_rules:
            matched_fields = r.matches(log)
            if matched_fields is not None:
                alerts.append(Alert(
                    rule_id=r.id,
                    rule_title=r.title,
                    severity=r.level,
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields=matched_fields,
                    raw=log,
                ))

        if self.yara_engine and self.yara_engine.compiled:
            try:
                raw_text = json.dumps(log)
            except Exception:
                raw_text = str(log)
            matches = self.yara_engine.match(raw_text)
            for m in matches:
                alerts.append(Alert(
                    rule_id=m.get('rule', 'yara'),
                    rule_title='YARA:' + m.get('rule', 'yara'),
                    severity='medium',
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields={'yara_tags': m.get('tags'), 'yara_meta': m.get('meta')},
                    raw=log,
                ))
        return alerts

    @staticmethod
    def _get_host(log: Dict[str, Any]) -> Optional[str]:
        for k in ('host', 'hostname', 'agent', 'source'):
            if k in log:
                v = log.get(k)
                if isinstance(v, dict):
                    return v.get('name')
                return v
        return None


class MetricsCollector:
    def __init__(self):
        self.total_logs = 0
        self.logs_per_host = defaultdict(int)
        self.alerts_per_rule = defaultdict(int)
        self.alerts_per_severity = defaultdict(int)
        self.alerts_per_host = defaultdict(int)

    def ingest_log(self, log: Dict[str, Any]):
        self.total_logs += 1
        host = log.get('host') or log.get('hostname') or 'unknown'
        if isinstance(host, dict):
            host = host.get('name', 'unknown')
        self.logs_per_host[host] += 1

    def record_alert(self, alert: Alert):
        self.alerts_per_rule[alert.rule_id] += 1
        self.alerts_per_severity[alert.severity] += 1
        host = alert.host or 'unknown'
        self.alerts_per_host[host] += 1

    def snapshot(self):
        return {
            'total_logs': self.total_logs,
            'logs_per_host': dict(self.logs_per_host),
            'alerts_per_rule': dict(self.alerts_per_rule),
            'alerts_per_severity': dict(self.alerts_per_severity),
            'alerts_per_host': dict(self.alerts_per_host),
        }


class SOCSimulator:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.rule_engine = RuleEngine(sigma_rules, yara_path)
        self.metrics = MetricsCollector()
        self.alerts: List[Alert] = []

    def process_logs(self, logs: Iterable[Dict[str, Any]]):
        for log in logs:
            self.metrics.ingest_log(log)
            alerts = self.rule_engine.eval_log(log)
            for a in alerts:
                self.alerts.append(a)
                self.metrics.record_alert(a)

    def export_alerts(self) -> List[Dict[str, Any]]:
        return [asdict(a) for a in self.alerts]

    def export_metrics(self) -> Dict[str, Any]:
        return self.metrics.snapshot()


def load_sigma_rules(path: str) -> List[Dict[str, Any]]:
    if not yaml:
        raise RuntimeError("PyYAML is required to load sigma rules. Install with: pip install pyyaml")
    with open(path, 'r', encoding='utf-8') as fh:
        docs = list(yaml.safe_load_all(fh))
        out: List[Dict[str, Any]] = []
        for d in docs:
            if d is None:
                continue
            if isinstance(d, list):
                out.extend(d)
            else:
                out.append(d)
        return out


def collect_log_files_from_dir(path: str) -> List[str]:
    files: List[str] = []
    if os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for f in filenames:
                files.append(os.path.join(root, f))
    elif os.path.isfile(path):
        files.append(path)
    return files


def _write_file(path: str, data: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(data)


def generate_sample_workspace(base_dir: str):
    logs_dir = os.path.join(base_dir, 'logs')
    rules_dir = os.path.join(base_dir, 'rules')
    yara_dir = os.path.join(base_dir, 'yara')
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(rules_dir, exist_ok=True)
    os.makedirs(yara_dir, exist_ok=True)

    log1 = {
        'host': 'host1',
        'EventID': 4688,
        'NewProcessName': r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'CommandLine': 'powershell -nop -w hidden -c IEX ...'
    }
    log2 = {
        'host': 'host2',
        'HttpMethod': 'POST',
        'RequestUri': '/upload.php?cmd=whoami',
        'UserAgent': 'curl/7.x'
    }
    log3 = {
        'host': 'host3',
        'message': 'This contains MALICIOUS_SIGNATURE inside payload',
        'some_field': 'some value'
    }

    for i, log in enumerate((log1, log2, log3), start=1):
        _write_file(os.path.join(logs_dir, f'log{i}.json'), json.dumps(log) + '\n')

    sigma_rules_yaml = """
- title: "Suspicious PowerShell"
  id: "SIG-0001"
  level: high
  detection:
    selection:
      EventID: 4688
      NewProcessName: ".*powershell.*"
    condition: selection

- title: "Possible Webshell POST"
  id: "SIG-0002"
  level: medium
  detection:
    post_req:
      HttpMethod: POST
      RequestUri: "*cmd=*"
    condition: post_req
"""
    _write_file(os.path.join(rules_dir, 'sigma_rules.yml'), sigma_rules_yaml)

    yara_rule = """
rule MaliciousSignature
{
    strings:
        $a = "MALICIOUS_SIGNATURE"
    condition:
        $a
}
"""
    _write_file(os.path.join(yara_dir, 'malicious.yar'), yara_rule)

    return {
        'logs_dir': logs_dir,
        'sigma_path': os.path.join(rules_dir, 'sigma_rules.yml'),
        'yara_path': os.path.join(yara_dir, 'malicious.yar')
    }


def generate_synthetic_workspace(base_dir: str, count: int = 100, include_yara: bool = True, include_sigma: bool = True):
    logs_dir = os.path.join(base_dir, 'logs')
    rules_dir = os.path.join(base_dir, 'rules')
    yara_dir = os.path.join(base_dir, 'yara')
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(rules_dir, exist_ok=True)
    if include_yara:
        os.makedirs(yara_dir, exist_ok=True)

    hosts = [f'host{i}' for i in range(1, 11)]
    processes = ['cmd.exe', 'powershell.exe', 'notepad.exe', 'python.exe']
    uris = ['/index.html', '/login', '/upload.php?cmd=whoami', '/api/data']

    path = os.path.join(logs_dir, 'synthetic.jsonl')
    with open(path, 'w', encoding='utf-8') as fh:
        for _ in range(count):
            t = randint(1, 3)
            if t == 1:
                log = {
                    'host': choice(hosts),
                    'EventID': 4688,
                    'NewProcessName': choice(processes),
                    'CommandLine': ' '.join(['-'.join([choice(['-nop','-w','-c']), '...'])])
                }
            elif t == 2:
                log = {
                    'host': choice(hosts),
                    'HttpMethod': choice(['GET', 'POST']),
                    'RequestUri': choice(uris),
                    'UserAgent': choice(['curl/7.64', 'Mozilla/5.0', 'python-requests/2.x'])
                }
            else:
                msg = 'normal message'
                if randrange(20) == 0:
                    msg = 'contains MALICIOUS_SIGNATURE in payload'
                log = {
                    'host': choice(hosts),
                    'message': msg,
                    'random_field': randint(0, 1000)
                }
            fh.write(json.dumps(log) + '\n')

    if include_sigma:
        sigma_rules_yaml = """
- title: "Synthetic Suspicious PowerShell"
  id: "SIG-SYN-001"
  level: high
  detection:
    selection:
      EventID: 4688
      NewProcessName: ".*powershell.*"
    condition: selection

- title: "Synthetic Web POST with cmd"
  id: "SIG-SYN-002"
  level: medium
  detection:
    post_req:
      HttpMethod: POST
      RequestUri: "*cmd=*"
    condition: post_req
"""
        _write_file(os.path.join(rules_dir, 'sigma_synthetic.yml'), sigma_rules_yaml)

    if include_yara:
        yara_rule = """
rule SyntheticMalicious
{
    strings:
        $a = "MALICIOUS_SIGNATURE"
    condition:
        $a
}
"""
        _write_file(os.path.join(yara_dir, 'synthetic.yar'), yara_rule)

    return {
        'logs_dir': logs_dir,
        'sigma_path': os.path.join(rules_dir, 'sigma_synthetic.yml') if include_sigma else None,
        'yara_path': os.path.join(yara_dir, 'synthetic.yar') if include_yara else None
    }


def run_sample_tests(verbose: bool = True) -> int:
    tmp = tempfile.mkdtemp(prefix='soc_sim_sample_')
    try:
        paths = generate_sample_workspace(tmp)

        if verbose:
            print(f"Generated sample workspace at: {tmp}")
            print(json.dumps(paths, indent=2))

        if not yaml:
            print("ERROR: PyYAML is required to load the sample Sigma rules. Install with: pip install pyyaml")
            return 3
        sigma_rules = load_sigma_rules(paths['sigma_path'])

        yara_path = paths['yara_path'] if yara else None
        if yara_path and not yara:
            print("Note: yara-python not installed; YARA tests will be skipped.")

        log_files = collect_log_files_from_dir(paths['logs_dir'])
        ingestor = LogIngestor(log_files)
        sim = SOCSimulator(sigma_rules=sigma_rules, yara_path=yara_path)
        sim.process_logs(ingestor.iter_logs())

        alerts = sim.export_alerts()
        metrics = sim.export_metrics()

        if verbose:
            print('\n--- Alerts (JSON) ---')
            print(json.dumps(alerts, indent=2))
            print('\n--- Metrics ---')
            print(json.dumps(metrics, indent=2))

        errors: List[str] = []
        if metrics.get('total_logs') != 3:
            errors.append(f"expected total_logs==3, got {metrics.get('total_logs')}")

        sigma_alerts = [a for a in alerts if not a['rule_id'].lower().startswith('yara')]
        if len(sigma_alerts) < 2:
            errors.append(f"expected >=2 sigma alerts, got {len(sigma_alerts)}")

        if yara and yara_path:
            yara_alerts = [a for a in alerts if a['rule_id'].lower().startswith('malicioussignature') or a['rule_title'].lower().startswith('yara:')]
            if len(yara_alerts) < 1:
                errors.append(f"expected >=1 yara alerts, got {len(yara_alerts)}")

        if errors:
            print('\n*** Sample tests FAILED ***')
            for e in errors:
                print(' -', e)
            return 2

        print('\n*** Sample tests PASSED')
        return 0
    finally:
        try:
            shutil.rmtree(tmp)
        except Exception:
            pass


def main_cli(argv=None):
    p = argparse.ArgumentParser(description='SOC Simulator - ingest logs, run Sigma/YARA rules, export alerts/metrics')
    p.add_argument('--logs', required=False, help='Path to log file or directory containing logs (JSON)')
    p.add_argument('--sigma', required=False, help='Path to Sigma YAML file (supports multi-doc or list)')
    p.add_argument('--yara', required=False, help='Path to YARA rules file (.yar or .yara)')
    p.add_argument('--out', required=False, help='Write alerts JSON to this file (default: alerts.json)', default='alerts.json')
    p.add_argument('--metrics', required=False, help='Write metrics JSON to this file (default: metrics.json)', default='metrics.json')
    p.add_argument('--fail-on-severity', required=False, choices=['low', 'medium', 'high', 'critical'],
                   help='Exit with code 2 if an alert of this severity or higher is produced (CI/CD friendly)')
    p.add_argument('--run-samples', action='store_true', help='Generate sample logs and rules and run built-in tests')
    p.add_argument('--generate-synthetic', nargs='?', const='synthetic_workspace', help='Generate a synthetic workspace. Provide base dir or omit to use ./synthetic_workspace')
    p.add_argument('--count', type=int, default=100, help='Count of synthetic logs to generate when using --generate-synthetic')
    p.add_argument('--yara-generate', action='store_true', help='When generating synthetic, also create a yara file')
    args = p.parse_args(argv)

    if args.run_samples:
        rc = run_sample_tests(verbose=True)
        return rc

    if args.generate_synthetic is not None:
        base = args.generate_synthetic or 'synthetic_workspace'
        base = os.path.abspath(base)
        print(f"Generating synthetic workspace at: {base} (count={args.count}, yara={args.yara_generate})")
        out = generate_synthetic_workspace(base, count=args.count, include_yara=args.yara_generate, include_sigma=True)
        print(json.dumps(out, indent=2))
        print("Done. Inspect the generated files under the workspace and run the simulator with --logs and --sigma.")
        return 0

    if not args.logs:
        print('Either --logs, --run-samples or --generate-synthetic must be provided')
        return 1

    sigma_rules: List[Dict[str, Any]] = []
    if args.sigma:
        try:
            sigma_rules = load_sigma_rules(args.sigma)
            print(f"Loaded {len(sigma_rules)} sigma rules from {args.sigma}")
        except Exception as e:
            print(f"Failed to load sigma rules: {e}")
            return 1

    paths = collect_log_files_from_dir(args.logs)
    if not paths:
        print("No log files found")
        return 1

    ingestor = LogIngestor(paths)
    simulator = SOCSimulator(sigma_rules, yara_path=args.yara)

    simulator.process_logs(ingestor.iter_logs())

    alerts = simulator.export_alerts()
    metrics = simulator.export_metrics()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.metrics) or ".", exist_ok=True)

    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump({'alerts': alerts}, fh, indent=2)
    with open(args.metrics, 'w', encoding='utf-8') as fh:
        json.dump({'metrics': metrics}, fh, indent=2)

    print(f"Processed logs. Alerts: {len(alerts)}. Metrics: {json.dumps(metrics)}")

    if args.fail_on_severity and alerts:
        level_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threshold = level_order.get(args.fail_on_severity, 2)
        for a in alerts:
            sev = a['severity'].lower() if isinstance(a.get('severity'), str) else 'medium'
            if level_order.get(sev, 2) >= threshold:
                print(f"Failing because alert {a['rule_id']} severity={a['severity']}")
                return 2

    return 0


if __name__ == '__main__':
    rc = main_cli()
    sys.exit(rc)

            try:
                return re.search(re_p, val, flags=re.IGNORECASE) is not None
            except re.error:
                return patt.lower() == val.lower()

        # plain equality (case-insensitive)
        return patt.lower() == val.lower()

    @classmethod
    def matches_selection(cls, selection: Dict[str, Any], log: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        matched: Dict[str, Any] = {}
        for key, pattern in selection.items():
            found, value = cls._get_value_by_path(log, key)
            if not found:
                return False, {}
            if cls._match_value(pattern, value):
                matched[key] = value
            else:
                return False, {}
        return True, matched

    def matches(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.selections:
            return None
        sel_results: Dict[str, Tuple[bool, Dict[str, Any]]] = {}
        for name, sel in self.selections.items():
            sel_results[name] = self.matches_selection(sel, log)

        cond = self.condition or 'selection'
        bool_map = {name: res[0] for name, res in sel_results.items()}
        cond_eval = self._render_condition(cond, bool_map)
        try:
            result = eval(cond_eval, {"__builtins__": None}, {})
        except Exception:
            return None

        if result:
            merged: Dict[str, Any] = {}
            for name, (ok, fields) in sel_results.items():
                if ok:
                    merged.update(fields)
            return merged
        return None

    @staticmethod
    def _render_condition(condition: str, bool_map: Dict[str, bool]) -> str:
        token_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b|\(|\)")

        def repl(m):
            tok = m.group(0)
            if tok.lower() in ('and', 'or', 'not', 'true', 'false'):
                return tok.lower()
            if tok in bool_map:
                return 'True' if bool_map[tok] else 'False'
            return 'False'

        rendered = token_re.sub(repl, condition)
        return rendered


class YaraEngine:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path
        self.compiled = None
        if yara and rules_path:
            try:
                self.compiled = yara.compile(filepath=rules_path)
            except Exception as e:
                print(f"[warn] failed to compile YARA: {e}")
                self.compiled = None

    def match(self, text: str) -> List[Dict[str, Any]]:
        if not self.compiled:
            return []
        try:
            matches = self.compiled.match(data=text)
            out: List[Dict[str, Any]] = []
            for m in matches:
                out.append({'rule': m.rule, 'tags': getattr(m, 'tags', []), 'meta': getattr(m, 'meta', {})})
            return out
        except Exception as e:
            print(f"[warn] yara match failed: {e}")
            return []


class RuleEngine:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.sigma_rules: List[SigmaRule] = [SigmaRule(r) for r in (sigma_rules or [])]
        self.yara_engine = YaraEngine(yara_path) if yara_path else None

    def eval_log(self, log: Dict[str, Any]) -> List[Alert]:
        alerts: List[Alert] = []
        for r in self.sigma_rules:
            matched_fields = r.matches(log)
            if matched_fields is not None:
                alerts.append(Alert(
                    rule_id=r.id,
                    rule_title=r.title,
                    severity=r.level,
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields=matched_fields,
                    raw=log,
                ))

        if self.yara_engine and self.yara_engine.compiled:
            try:
                raw_text = json.dumps(log)
            except Exception:
                raw_text = str(log)
            matches = self.yara_engine.match(raw_text)
            for m in matches:
                alerts.append(Alert(
                    rule_id=m.get('rule', 'yara'),
                    rule_title='YARA:' + m.get('rule', 'yara'),
                    severity='medium',
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields={'yara_tags': m.get('tags'), 'yara_meta': m.get('meta')},
                    raw=log,
                ))
        return alerts

    @staticmethod
    def _get_host(log: Dict[str, Any]) -> Optional[str]:
        for k in ('host', 'hostname', 'agent', 'source'):
            if k in log:
                v = log.get(k)
                if isinstance(v, dict):
                    return v.get('name')
                return v
        return None


class MetricsCollector:
    def __init__(self):
        self.total_logs = 0
        self.logs_per_host = defaultdict(int)
        self.alerts_per_rule = defaultdict(int)
        self.alerts_per_severity = defaultdict(int)
        self.alerts_per_host = defaultdict(int)

    def ingest_log(self, log: Dict[str, Any]):
        self.total_logs += 1
        host = log.get('host') or log.get('hostname') or 'unknown'
        if isinstance(host, dict):
            host = host.get('name', 'unknown')
        self.logs_per_host[host] += 1

    def record_alert(self, alert: Alert):
        self.alerts_per_rule[alert.rule_id] += 1
        self.alerts_per_severity[alert.severity] += 1
        host = alert.host or 'unknown'
        self.alerts_per_host[host] += 1

    def snapshot(self):
        return {
            'total_logs': self.total_logs,
            'logs_per_host': dict(self.logs_per_host),
            'alerts_per_rule': dict(self.alerts_per_rule),
            'alerts_per_severity': dict(self.alerts_per_severity),
            'alerts_per_host': dict(self.alerts_per_host),
        }


class SOCSimulator:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.rule_engine = RuleEngine(sigma_rules, yara_path)
        self.metrics = MetricsCollector()
        self.alerts: List[Alert] = []

    def process_logs(self, logs: Iterable[Dict[str, Any]]):
        for log in logs:
            self.metrics.ingest_log(log)
            alerts = self.rule_engine.eval_log(log)
            for a in alerts:
                self.alerts.append(a)
                self.metrics.record_alert(a)

    def export_alerts(self) -> List[Dict[str, Any]]:
        return [asdict(a) for a in self.alerts]

    def export_metrics(self) -> Dict[str, Any]:
        return self.metrics.snapshot()


def load_sigma_rules(path: str) -> List[Dict[str, Any]]:
    if not yaml:
        raise RuntimeError("PyYAML is required to load sigma rules. Install with: pip install pyyaml")
    with open(path, 'r', encoding='utf-8') as fh:
        docs = list(yaml.safe_load_all(fh))
        out: List[Dict[str, Any]] = []
        for d in docs:
            if d is None:
                continue
            if isinstance(d, list):
                out.extend(d)
            else:
                out.append(d)
        return out


def collect_log_files_from_dir(path: str) -> List[str]:
    files: List[str] = []
    if os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for f in filenames:
                files.append(os.path.join(root, f))
    elif os.path.isfile(path):
        files.append(path)
    return files


def _write_file(path: str, data: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(data)


def generate_sample_workspace(base_dir: str):
    logs_dir = os.path.join(base_dir, 'logs')
    rules_dir = os.path.join(base_dir, 'rules')
    yara_dir = os.path.join(base_dir, 'yara')
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(rules_dir, exist_ok=True)
    os.makedirs(yara_dir, exist_ok=True)

    log1 = {
        'host': 'host1',
        'EventID': 4688,
        'NewProcessName': r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'CommandLine': 'powershell -nop -w hidden -c IEX ...'
    }
    log2 = {
        'host': 'host2',
        'HttpMethod': 'POST',
        'RequestUri': '/upload.php?cmd=whoami',
        'UserAgent': 'curl/7.x'
    }
    log3 = {
        'host': 'host3',
        'message': 'This contains MALICIOUS_SIGNATURE inside payload',
        'some_field': 'some value'
    }

    for i, log in enumerate((log1, log2, log3), start=1):
        _write_file(os.path.join(logs_dir, f'log{i}.json'), json.dumps(log) + '\n')

    sigma_rules_yaml = """
- title: "Suspicious PowerShell"
  id: "SIG-0001"
  level: high
  detection:
    selection:
      EventID: 4688
      NewProcessName: ".*powershell.*"
    condition: selection

- title: "Possible Webshell POST"
  id: "SIG-0002"
  level: medium
  detection:
    post_req:
      HttpMethod: POST
      RequestUri: "*cmd=*"
    condition: post_req
"""
    _write_file(os.path.join(rules_dir, 'sigma_rules.yml'), sigma_rules_yaml)

    yara_rule = """
rule MaliciousSignature
{
    strings:
        $a = "MALICIOUS_SIGNATURE"
    condition:
        $a
}
"""
    _write_file(os.path.join(yara_dir, 'malicious.yar'), yara_rule)

    return {
        'logs_dir': logs_dir,
        'sigma_path': os.path.join(rules_dir, 'sigma_rules.yml'),
        'yara_path': os.path.join(yara_dir, 'malicious.yar')
    }


def generate_synthetic_workspace(base_dir: str, count: int = 100, include_yara: bool = True, include_sigma: bool = True):
    logs_dir = os.path.join(base_dir, 'logs')
    rules_dir = os.path.join(base_dir, 'rules')
    yara_dir = os.path.join(base_dir, 'yara')
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(rules_dir, exist_ok=True)
    if include_yara:
        os.makedirs(yara_dir, exist_ok=True)

    hosts = [f'host{i}' for i in range(1, 11)]
    processes = ['cmd.exe', 'powershell.exe', 'notepad.exe', 'python.exe']
    uris = ['/index.html', '/login', '/upload.php?cmd=whoami', '/api/data']

    path = os.path.join(logs_dir, 'synthetic.jsonl')
    with open(path, 'w', encoding='utf-8') as fh:
        for _ in range(count):
            t = randint(1, 3)
            if t == 1:
                log = {
                    'host': choice(hosts),
                    'EventID': 4688,
                    'NewProcessName': choice(processes),
                    'CommandLine': ' '.join(['-'.join([choice(['-nop','-w','-c']), '...'])])
                }
            elif t == 2:
                log = {
                    'host': choice(hosts),
                    'HttpMethod': choice(['GET', 'POST']),
                    'RequestUri': choice(uris),
                    'UserAgent': choice(['curl/7.64', 'Mozilla/5.0', 'python-requests/2.x'])
                }
            else:
                msg = 'normal message'
                if randrange(20) == 0:
                    msg = 'contains MALICIOUS_SIGNATURE in payload'
                log = {
                    'host': choice(hosts),
                    'message': msg,
                    'random_field': randint(0, 1000)
                }
            fh.write(json.dumps(log) + '\n')

    if include_sigma:
        sigma_rules_yaml = """
- title: "Synthetic Suspicious PowerShell"
  id: "SIG-SYN-001"
  level: high
  detection:
    selection:
      EventID: 4688
      NewProcessName: ".*powershell.*"
    condition: selection

- title: "Synthetic Web POST with cmd"
  id: "SIG-SYN-002"
  level: medium
  detection:
    post_req:
      HttpMethod: POST
      RequestUri: "*cmd=*"
    condition: post_req
"""
        _write_file(os.path.join(rules_dir, 'sigma_synthetic.yml'), sigma_rules_yaml)

    if include_yara:
        yara_rule = """
rule SyntheticMalicious
{
    strings:
        $a = "MALICIOUS_SIGNATURE"
    condition:
        $a
}
"""
        _write_file(os.path.join(yara_dir, 'synthetic.yar'), yara_rule)

    return {
        'logs_dir': logs_dir,
        'sigma_path': os.path.join(rules_dir, 'sigma_synthetic.yml') if include_sigma else None,
        'yara_path': os.path.join(yara_dir, 'synthetic.yar') if include_yara else None
    }


def run_sample_tests(verbose: bool = True) -> int:
    tmp = tempfile.mkdtemp(prefix='soc_sim_sample_')
    try:
        paths = generate_sample_workspace(tmp)

        if verbose:
            print(f"Generated sample workspace at: {tmp}")
            print(json.dumps(paths, indent=2))

        if not yaml:
            print("ERROR: PyYAML is required to load the sample Sigma rules. Install with: pip install pyyaml")
            return 3
        sigma_rules = load_sigma_rules(paths['sigma_path'])

        yara_path = paths['yara_path'] if yara else None
        if yara_path and not yara:
            print("Note: yara-python not installed; YARA tests will be skipped.")

        log_files = collect_log_files_from_dir(paths['logs_dir'])
        ingestor = LogIngestor(log_files)
        sim = SOCSimulator(sigma_rules=sigma_rules, yara_path=yara_path)
        sim.process_logs(ingestor.iter_logs())

        alerts = sim.export_alerts()
        metrics = sim.export_metrics()

        if verbose:
            print('\n--- Alerts (JSON) ---')
            print(json.dumps(alerts, indent=2))
            print('\n--- Metrics ---')
            print(json.dumps(metrics, indent=2))

        errors: List[str] = []
        if metrics.get('total_logs') != 3:
            errors.append(f"expected total_logs==3, got {metrics.get('total_logs')}")

        sigma_alerts = [a for a in alerts if not a['rule_id'].lower().startswith('yara')]
        if len(sigma_alerts) < 2:
            errors.append(f"expected >=2 sigma alerts, got {len(sigma_alerts)}")

        if yara and yara_path:
            yara_alerts = [a for a in alerts if a['rule_id'].lower().startswith('malicioussignature') or a['rule_title'].lower().startswith('yara:')]
            if len(yara_alerts) < 1:
                errors.append(f"expected >=1 yara alerts, got {len(yara_alerts)}")

        if errors:
            print('\n*** Sample tests FAILED ***')
            for e in errors:
                print(' -', e)
            return 2

        print('\n*** Sample tests PASSED')
        return 0
    finally:
        try:
            shutil.rmtree(tmp)
        except Exception:
            pass


def main_cli(argv=None):
    p = argparse.ArgumentParser(description='SOC Simulator - ingest logs, run Sigma/YARA rules, export alerts/metrics')
    p.add_argument('--logs', required=False, help='Path to log file or directory containing logs (JSON)')
    p.add_argument('--sigma', required=False, help='Path to Sigma YAML file (supports multi-doc or list)')
    p.add_argument('--yara', required=False, help='Path to YARA rules file (.yar or .yara)')
    p.add_argument('--out', required=False, help='Write alerts JSON to this file (default: alerts.json)', default='alerts.json')
    p.add_argument('--metrics', required=False, help='Write metrics JSON to this file (default: metrics.json)', default='metrics.json')
    p.add_argument('--fail-on-severity', required=False, choices=['low', 'medium', 'high', 'critical'],
                   help='Exit with code 2 if an alert of this severity or higher is produced (CI/CD friendly)')
    p.add_argument('--run-samples', action='store_true', help='Generate sample logs and rules and run built-in tests')
    p.add_argument('--generate-synthetic', nargs='?', const='synthetic_workspace', help='Generate a synthetic workspace. Provide base dir or omit to use ./synthetic_workspace')
    p.add_argument('--count', type=int, default=100, help='Count of synthetic logs to generate when using --generate-synthetic')
    p.add_argument('--yara-generate', action='store_true', help='When generating synthetic, also create a yara file')
    args = p.parse_args(argv)

    if args.run_samples:
        rc = run_sample_tests(verbose=True)
        return rc

    if args.generate_synthetic is not None:
        base = args.generate_synthetic or 'synthetic_workspace'
        base = os.path.abspath(base)
        print(f"Generating synthetic workspace at: {base} (count={args.count}, yara={args.yara_generate})")
        out = generate_synthetic_workspace(base, count=args.count, include_yara=args.yara_generate, include_sigma=True)
        print(json.dumps(out, indent=2))
        print("Done. Inspect the generated files under the workspace and run the simulator with --logs and --sigma.")
        return 0

    if not args.logs:
        print('Either --logs, --run-samples or --generate-synthetic must be provided')
        return 1

    sigma_rules: List[Dict[str, Any]] = []
    if args.sigma:
        try:
            sigma_rules = load_sigma_rules(args.sigma)
            print(f"Loaded {len(sigma_rules)} sigma rules from {args.sigma}")
        except Exception as e:
            print(f"Failed to load sigma rules: {e}")
            return 1

    paths = collect_log_files_from_dir(args.logs)
    if not paths:
        print("No log files found")
        return 1

    ingestor = LogIngestor(paths)
    simulator = SOCSimulator(sigma_rules, yara_path=args.yara)

    simulator.process_logs(ingestor.iter_logs())

    alerts = simulator.export_alerts()
    metrics = simulator.export_metrics()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.metrics) or ".", exist_ok=True)

    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump({'alerts': alerts}, fh, indent=2)
    with open(args.metrics, 'w', encoding='utf-8') as fh:
        json.dump({'metrics': metrics}, fh, indent=2)

    print(f"Processed logs. Alerts: {len(alerts)}. Metrics: {json.dumps(metrics)}")

    if args.fail_on_severity and alerts:
        level_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threshold = level_order.get(args.fail_on_severity, 2)
        for a in alerts:
            sev = a['severity'].lower() if isinstance(a.get('severity'), str) else 'medium'
            if level_order.get(sev, 2) >= threshold:
                print(f"Failing because alert {a['rule_id']} severity={a['severity']}")
                return 2

    return 0


if __name__ == '__main__':
    rc = main_cli()
    sys.exit(rc)
,       # End anchor (but not $ as last char only)
            '[',       # Character class
            ']',       # Character class end
            '(',       # Grouping
            '|',       # Alternation
            '{',       # Quantifier
            '}',       # Quantifier end
            '\\d',     # Digit
            '\\w',     # Word character
            '\\s',     # Whitespace
        ]
        
        has_regex = any(indicator in s for indicator in regex_indicators)
        
        # If it has regex indicators, it's regex (even if it also has wildcards)
        if has_regex:
            return True
        
        # If it ONLY has wildcards and no regex chars, it's a wildcard pattern
        if has_simple_wildcard and not has_regex:
            return False
        
        return False

    @classmethod
    def _match_value(cls, pattern: Any, value: Any) -> bool:
        # support list of patterns
        if isinstance(pattern, list):
            return any(cls._match_value(p, value) for p in pattern)

        # numbers and bools
        if isinstance(pattern, (int, float, bool)):
            return pattern == value
        if isinstance(value, (int, float, bool)) and not isinstance(value, str):
            return str(pattern) == str(value)

        val = '' if value is None else str(value)
        patt = '' if pattern is None else str(pattern)

        # CRITICAL FIX: Check wildcards BEFORE regex
        # Wildcard patterns (* or ?) are common in Sigma rules and should be handled first
        if '*' in patt or '?' in patt:
            # This is a wildcard pattern - convert to regex
            # Use re.escape to handle all special chars, then replace escaped wildcards
            re_p = '^' + re.escape(patt).replace(r'\*', '.*').replace(r'\?', '.') + '$'
            try:
                return re.search(re_p, val, flags=re.IGNORECASE) is not None
            except re.error:
                return patt.lower() == val.lower()

        # regex (only if it looks like actual regex syntax)
        if cls._is_regex_pattern(patt):
            try:
                return re.search(patt, val, flags=re.IGNORECASE) is not None
            except re.error:
                return patt.lower() == val.lower()

        # plain equality (case-insensitive)
        return patt.lower() == val.lower()

    @classmethod
    def matches_selection(cls, selection: Dict[str, Any], log: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        matched: Dict[str, Any] = {}
        for key, pattern in selection.items():
            found, value = cls._get_value_by_path(log, key)
            if not found:
                return False, {}
            if cls._match_value(pattern, value):
                matched[key] = value
            else:
                return False, {}
        return True, matched

    def matches(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.selections:
            return None
        sel_results: Dict[str, Tuple[bool, Dict[str, Any]]] = {}
        for name, sel in self.selections.items():
            sel_results[name] = self.matches_selection(sel, log)

        cond = self.condition or 'selection'
        bool_map = {name: res[0] for name, res in sel_results.items()}
        cond_eval = self._render_condition(cond, bool_map)
        try:
            result = eval(cond_eval, {"__builtins__": None}, {})
        except Exception:
            return None

        if result:
            merged: Dict[str, Any] = {}
            for name, (ok, fields) in sel_results.items():
                if ok:
                    merged.update(fields)
            return merged
        return None

    @staticmethod
    def _render_condition(condition: str, bool_map: Dict[str, bool]) -> str:
        token_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b|\(|\)")

        def repl(m):
            tok = m.group(0)
            if tok.lower() in ('and', 'or', 'not', 'true', 'false'):
                return tok.lower()
            if tok in bool_map:
                return 'True' if bool_map[tok] else 'False'
            return 'False'

        rendered = token_re.sub(repl, condition)
        return rendered


class YaraEngine:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path
        self.compiled = None
        if yara and rules_path:
            try:
                self.compiled = yara.compile(filepath=rules_path)
            except Exception as e:
                print(f"[warn] failed to compile YARA: {e}")
                self.compiled = None

    def match(self, text: str) -> List[Dict[str, Any]]:
        if not self.compiled:
            return []
        try:
            matches = self.compiled.match(data=text)
            out: List[Dict[str, Any]] = []
            for m in matches:
                out.append({'rule': m.rule, 'tags': getattr(m, 'tags', []), 'meta': getattr(m, 'meta', {})})
            return out
        except Exception as e:
            print(f"[warn] yara match failed: {e}")
            return []


class RuleEngine:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.sigma_rules: List[SigmaRule] = [SigmaRule(r) for r in (sigma_rules or [])]
        self.yara_engine = YaraEngine(yara_path) if yara_path else None

    def eval_log(self, log: Dict[str, Any]) -> List[Alert]:
        alerts: List[Alert] = []
        for r in self.sigma_rules:
            matched_fields = r.matches(log)
            if matched_fields is not None:
                alerts.append(Alert(
                    rule_id=r.id,
                    rule_title=r.title,
                    severity=r.level,
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields=matched_fields,
                    raw=log,
                ))

        if self.yara_engine and self.yara_engine.compiled:
            try:
                raw_text = json.dumps(log)
            except Exception:
                raw_text = str(log)
            matches = self.yara_engine.match(raw_text)
            for m in matches:
                alerts.append(Alert(
                    rule_id=m.get('rule', 'yara'),
                    rule_title='YARA:' + m.get('rule', 'yara'),
                    severity='medium',
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields={'yara_tags': m.get('tags'), 'yara_meta': m.get('meta')},
                    raw=log,
                ))
        return alerts

    @staticmethod
    def _get_host(log: Dict[str, Any]) -> Optional[str]:
        for k in ('host', 'hostname', 'agent', 'source'):
            if k in log:
                v = log.get(k)
                if isinstance(v, dict):
                    return v.get('name')
                return v
        return None


class MetricsCollector:
    def __init__(self):
        self.total_logs = 0
        self.logs_per_host = defaultdict(int)
        self.alerts_per_rule = defaultdict(int)
        self.alerts_per_severity = defaultdict(int)
        self.alerts_per_host = defaultdict(int)

    def ingest_log(self, log: Dict[str, Any]):
        self.total_logs += 1
        host = log.get('host') or log.get('hostname') or 'unknown'
        if isinstance(host, dict):
            host = host.get('name', 'unknown')
        self.logs_per_host[host] += 1

    def record_alert(self, alert: Alert):
        self.alerts_per_rule[alert.rule_id] += 1
        self.alerts_per_severity[alert.severity] += 1
        host = alert.host or 'unknown'
        self.alerts_per_host[host] += 1

    def snapshot(self):
        return {
            'total_logs': self.total_logs,
            'logs_per_host': dict(self.logs_per_host),
            'alerts_per_rule': dict(self.alerts_per_rule),
            'alerts_per_severity': dict(self.alerts_per_severity),
            'alerts_per_host': dict(self.alerts_per_host),
        }


class SOCSimulator:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.rule_engine = RuleEngine(sigma_rules, yara_path)
        self.metrics = MetricsCollector()
        self.alerts: List[Alert] = []

    def process_logs(self, logs: Iterable[Dict[str, Any]]):
        for log in logs:
            self.metrics.ingest_log(log)
            alerts = self.rule_engine.eval_log(log)
            for a in alerts:
                self.alerts.append(a)
                self.metrics.record_alert(a)

    def export_alerts(self) -> List[Dict[str, Any]]:
        return [asdict(a) for a in self.alerts]

    def export_metrics(self) -> Dict[str, Any]:
        return self.metrics.snapshot()


def load_sigma_rules(path: str) -> List[Dict[str, Any]]:
    if not yaml:
        raise RuntimeError("PyYAML is required to load sigma rules. Install with: pip install pyyaml")
    with open(path, 'r', encoding='utf-8') as fh:
        docs = list(yaml.safe_load_all(fh))
        out: List[Dict[str, Any]] = []
        for d in docs:
            if d is None:
                continue
            if isinstance(d, list):
                out.extend(d)
            else:
                out.append(d)
        return out


def collect_log_files_from_dir(path: str) -> List[str]:
    files: List[str] = []
    if os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for f in filenames:
                files.append(os.path.join(root, f))
    elif os.path.isfile(path):
        files.append(path)
    return files


def _write_file(path: str, data: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(data)


def generate_sample_workspace(base_dir: str):
    logs_dir = os.path.join(base_dir, 'logs')
    rules_dir = os.path.join(base_dir, 'rules')
    yara_dir = os.path.join(base_dir, 'yara')
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(rules_dir, exist_ok=True)
    os.makedirs(yara_dir, exist_ok=True)

    log1 = {
        'host': 'host1',
        'EventID': 4688,
        'NewProcessName': r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'CommandLine': 'powershell -nop -w hidden -c IEX ...'
    }
    log2 = {
        'host': 'host2',
        'HttpMethod': 'POST',
        'RequestUri': '/upload.php?cmd=whoami',
        'UserAgent': 'curl/7.x'
    }
    log3 = {
        'host': 'host3',
        'message': 'This contains MALICIOUS_SIGNATURE inside payload',
        'some_field': 'some value'
    }

    for i, log in enumerate((log1, log2, log3), start=1):
        _write_file(os.path.join(logs_dir, f'log{i}.json'), json.dumps(log) + '\n')

    sigma_rules_yaml = """
- title: "Suspicious PowerShell"
  id: "SIG-0001"
  level: high
  detection:
    selection:
      EventID: 4688
      NewProcessName: ".*powershell.*"
    condition: selection

- title: "Possible Webshell POST"
  id: "SIG-0002"
  level: medium
  detection:
    post_req:
      HttpMethod: POST
      RequestUri: "*cmd=*"
    condition: post_req
"""
    _write_file(os.path.join(rules_dir, 'sigma_rules.yml'), sigma_rules_yaml)

    yara_rule = """
rule MaliciousSignature
{
    strings:
        $a = "MALICIOUS_SIGNATURE"
    condition:
        $a
}
"""
    _write_file(os.path.join(yara_dir, 'malicious.yar'), yara_rule)

    return {
        'logs_dir': logs_dir,
        'sigma_path': os.path.join(rules_dir, 'sigma_rules.yml'),
        'yara_path': os.path.join(yara_dir, 'malicious.yar')
    }


def generate_synthetic_workspace(base_dir: str, count: int = 100, include_yara: bool = True, include_sigma: bool = True):
    logs_dir = os.path.join(base_dir, 'logs')
    rules_dir = os.path.join(base_dir, 'rules')
    yara_dir = os.path.join(base_dir, 'yara')
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(rules_dir, exist_ok=True)
    if include_yara:
        os.makedirs(yara_dir, exist_ok=True)

    hosts = [f'host{i}' for i in range(1, 11)]
    processes = ['cmd.exe', 'powershell.exe', 'notepad.exe', 'python.exe']
    uris = ['/index.html', '/login', '/upload.php?cmd=whoami', '/api/data']

    path = os.path.join(logs_dir, 'synthetic.jsonl')
    with open(path, 'w', encoding='utf-8') as fh:
        for _ in range(count):
            t = randint(1, 3)
            if t == 1:
                log = {
                    'host': choice(hosts),
                    'EventID': 4688,
                    'NewProcessName': choice(processes),
                    'CommandLine': ' '.join(['-'.join([choice(['-nop','-w','-c']), '...'])])
                }
            elif t == 2:
                log = {
                    'host': choice(hosts),
                    'HttpMethod': choice(['GET', 'POST']),
                    'RequestUri': choice(uris),
                    'UserAgent': choice(['curl/7.64', 'Mozilla/5.0', 'python-requests/2.x'])
                }
            else:
                msg = 'normal message'
                if randrange(20) == 0:
                    msg = 'contains MALICIOUS_SIGNATURE in payload'
                log = {
                    'host': choice(hosts),
                    'message': msg,
                    'random_field': randint(0, 1000)
                }
            fh.write(json.dumps(log) + '\n')

    if include_sigma:
        sigma_rules_yaml = """
- title: "Synthetic Suspicious PowerShell"
  id: "SIG-SYN-001"
  level: high
  detection:
    selection:
      EventID: 4688
      NewProcessName: ".*powershell.*"
    condition: selection

- title: "Synthetic Web POST with cmd"
  id: "SIG-SYN-002"
  level: medium
  detection:
    post_req:
      HttpMethod: POST
      RequestUri: "*cmd=*"
    condition: post_req
"""
        _write_file(os.path.join(rules_dir, 'sigma_synthetic.yml'), sigma_rules_yaml)

    if include_yara:
        yara_rule = """
rule SyntheticMalicious
{
    strings:
        $a = "MALICIOUS_SIGNATURE"
    condition:
        $a
}
"""
        _write_file(os.path.join(yara_dir, 'synthetic.yar'), yara_rule)

    return {
        'logs_dir': logs_dir,
        'sigma_path': os.path.join(rules_dir, 'sigma_synthetic.yml') if include_sigma else None,
        'yara_path': os.path.join(yara_dir, 'synthetic.yar') if include_yara else None
    }


def run_sample_tests(verbose: bool = True) -> int:
    tmp = tempfile.mkdtemp(prefix='soc_sim_sample_')
    try:
        paths = generate_sample_workspace(tmp)

        if verbose:
            print(f"Generated sample workspace at: {tmp}")
            print(json.dumps(paths, indent=2))

        if not yaml:
            print("ERROR: PyYAML is required to load the sample Sigma rules. Install with: pip install pyyaml")
            return 3
        sigma_rules = load_sigma_rules(paths['sigma_path'])

        yara_path = paths['yara_path'] if yara else None
        if yara_path and not yara:
            print("Note: yara-python not installed; YARA tests will be skipped.")

        log_files = collect_log_files_from_dir(paths['logs_dir'])
        ingestor = LogIngestor(log_files)
        sim = SOCSimulator(sigma_rules=sigma_rules, yara_path=yara_path)
        sim.process_logs(ingestor.iter_logs())

        alerts = sim.export_alerts()
        metrics = sim.export_metrics()

        if verbose:
            print('\n--- Alerts (JSON) ---')
            print(json.dumps(alerts, indent=2))
            print('\n--- Metrics ---')
            print(json.dumps(metrics, indent=2))

        errors: List[str] = []
        if metrics.get('total_logs') != 3:
            errors.append(f"expected total_logs==3, got {metrics.get('total_logs')}")

        sigma_alerts = [a for a in alerts if not a['rule_id'].lower().startswith('yara')]
        if len(sigma_alerts) < 2:
            errors.append(f"expected >=2 sigma alerts, got {len(sigma_alerts)}")

        if yara and yara_path:
            yara_alerts = [a for a in alerts if a['rule_id'].lower().startswith('malicioussignature') or a['rule_title'].lower().startswith('yara:')]
            if len(yara_alerts) < 1:
                errors.append(f"expected >=1 yara alerts, got {len(yara_alerts)}")

        if errors:
            print('\n*** Sample tests FAILED ***')
            for e in errors:
                print(' -', e)
            return 2

        print('\n*** Sample tests PASSED')
        return 0
    finally:
        try:
            shutil.rmtree(tmp)
        except Exception:
            pass


def main_cli(argv=None):
    p = argparse.ArgumentParser(description='SOC Simulator - ingest logs, run Sigma/YARA rules, export alerts/metrics')
    p.add_argument('--logs', required=False, help='Path to log file or directory containing logs (JSON)')
    p.add_argument('--sigma', required=False, help='Path to Sigma YAML file (supports multi-doc or list)')
    p.add_argument('--yara', required=False, help='Path to YARA rules file (.yar or .yara)')
    p.add_argument('--out', required=False, help='Write alerts JSON to this file (default: alerts.json)', default='alerts.json')
    p.add_argument('--metrics', required=False, help='Write metrics JSON to this file (default: metrics.json)', default='metrics.json')
    p.add_argument('--fail-on-severity', required=False, choices=['low', 'medium', 'high', 'critical'],
                   help='Exit with code 2 if an alert of this severity or higher is produced (CI/CD friendly)')
    p.add_argument('--run-samples', action='store_true', help='Generate sample logs and rules and run built-in tests')
    p.add_argument('--generate-synthetic', nargs='?', const='synthetic_workspace', help='Generate a synthetic workspace. Provide base dir or omit to use ./synthetic_workspace')
    p.add_argument('--count', type=int, default=100, help='Count of synthetic logs to generate when using --generate-synthetic')
    p.add_argument('--yara-generate', action='store_true', help='When generating synthetic, also create a yara file')
    args = p.parse_args(argv)

    if args.run_samples:
        rc = run_sample_tests(verbose=True)
        return rc

    if args.generate_synthetic is not None:
        base = args.generate_synthetic or 'synthetic_workspace'
        base = os.path.abspath(base)
        print(f"Generating synthetic workspace at: {base} (count={args.count}, yara={args.yara_generate})")
        out = generate_synthetic_workspace(base, count=args.count, include_yara=args.yara_generate, include_sigma=True)
        print(json.dumps(out, indent=2))
        print("Done. Inspect the generated files under the workspace and run the simulator with --logs and --sigma.")
        return 0

    if not args.logs:
        print('Either --logs, --run-samples or --generate-synthetic must be provided')
        return 1

    sigma_rules: List[Dict[str, Any]] = []
    if args.sigma:
        try:
            sigma_rules = load_sigma_rules(args.sigma)
            print(f"Loaded {len(sigma_rules)} sigma rules from {args.sigma}")
        except Exception as e:
            print(f"Failed to load sigma rules: {e}")
            return 1

    paths = collect_log_files_from_dir(args.logs)
    if not paths:
        print("No log files found")
        return 1

    ingestor = LogIngestor(paths)
    simulator = SOCSimulator(sigma_rules, yara_path=args.yara)

    simulator.process_logs(ingestor.iter_logs())

    alerts = simulator.export_alerts()
    metrics = simulator.export_metrics()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.metrics) or ".", exist_ok=True)

    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump({'alerts': alerts}, fh, indent=2)
    with open(args.metrics, 'w', encoding='utf-8') as fh:
        json.dump({'metrics': metrics}, fh, indent=2)

    print(f"Processed logs. Alerts: {len(alerts)}. Metrics: {json.dumps(metrics)}")

    if args.fail_on_severity and alerts:
        level_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threshold = level_order.get(args.fail_on_severity, 2)
        for a in alerts:
            sev = a['severity'].lower() if isinstance(a.get('severity'), str) else 'medium'
            if level_order.get(sev, 2) >= threshold:
                print(f"Failing because alert {a['rule_id']} severity={a['severity']}")
                return 2

    return 0


if __name__ == '__main__':
    rc = main_cli()
    sys.exit(rc)
