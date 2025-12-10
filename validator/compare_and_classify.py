#!/usr/bin/env python3
"""
compare_and_classify.py

Usage:
  python compare_and_classify.py \
      --baseline <path/to/baseline.json_or_dir> \
      --current <path/to/current.json_or_dir> \
      --changed-rules rule1.yml,rule2.yml \
      --output report.json

This script:
 - Loads baseline and current validation outputs (file or directory of JSON files)
 - Derives:
     baseline_total = total detections from all old rules (baseline)
     current_total  = total detections from old + new rules (current)
 - For each changed/new rule, computes rule-specific detection_count in current set
 - Computes delta = current_total - baseline_total
 - Classifies each changed rule as STRONG / NEUTRAL / WEAK / CONCERNING based on delta and per-rule contribution
 - Writes a JSON report with metrics and reasoning
"""

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

# -----------------------
# Tunable thresholds
# -----------------------
STRONG_DELTA = 10         # if total alerts increase by >= STRONG_DELTA -> STRONG
MIN_RULE_CONTRIBUTION = 3 # rule must contribute at least this many detections to be considered meaningful
NEUTRAL_UPPER = STRONG_DELTA - 1  # anything between 1 and STRONG_DELTA-1 considered NEUTRAL (subject to per-rule contrib)
# -----------------------

def read_json_file(path: Path) -> Any:
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)

def load_results(path_str: str) -> List[Dict]:
    """
    Accept either:
      - a single JSON file containing either a list of results or a dict (wrap into list),
      - or a directory containing JSON files (will read all .json files).
    Returns a list of parsed JSON objects.
    """
    p = Path(path_str)
    results = []
    if p.is_file():
        data = read_json_file(p)
        if isinstance(data, list):
            results.extend(data)
        else:
            results.append(data)
    elif p.is_dir():
        for child in sorted(p.iterdir()):
            if child.suffix.lower() == '.json' and child.is_file():
                try:
                    data = read_json_file(child)
                    if isinstance(data, list):
                        results.extend(data)
                    else:
                        results.append(data)
                except Exception as e:
                    print(f"Warning: failed to load {child}: {e}")
    else:
        raise FileNotFoundError(f"Path not found: {path_str}")
    return results

def extract_detection_count(item: Dict) -> int:
    """
    Heuristics to extract a detection count from a validation result item.
    Checks common fields; falls back to 0.
    Priority:
     - 'detection_count' (explicit)
     - 'total_detections'
     - 'matched' -> boolean (True counts as 1)
     - 'matches' -> number or list
     - 'detections' -> number
     - 'count' -> number
    """
    if not isinstance(item, dict):
        return 0
    # check common numeric fields
    for key in ('detection_count', 'total_detections', 'detections', 'matches', 'count', 'hits'):
        if key in item:
            val = item[key]
            if isinstance(val, int):
                return val
            # sometimes 'matches' can be list
            if isinstance(val, list):
                return len(val)
            try:
                # try convert numeric strings
                return int(val)
            except Exception:
                pass
    # boolean matched -> count as 1
    if item.get('matched') is True:
        # if there is a 'matched_count' use it
        if 'matched_count' in item and isinstance(item['matched_count'], int):
            return item['matched_count']
        return 1
    # try nested structure: maybe item['results'] is list
    if 'results' in item and isinstance(item['results'], list):
        return len(item['results'])
    # fallback
    return 0

def sum_total_detections(items: List[Dict]) -> int:
    return sum(extract_detection_count(it) for it in items)

def find_rule_detection_in_results(rule_identifier: str, results: List[Dict]) -> int:
    """
    Try to attribute detections to a particular rule identifier.
    'rule_identifier' can be a filename (rule.yml) or a rule id string.
    Heuristic:
     - look for 'rule_id', 'id' fields matching the identifier.
     - look for 'rule_path' or 'rule_name' or filename match.
     - if identifier is a filename, compare suffixes and stems.
     - fallback: try substring match in 'rule_title' or 'rule_path'
    Returns aggregated detection_count for matching entries.
    """
    total = 0
    id_norm = rule_identifier.strip()
    id_stem = Path(id_norm).stem
    for item in results:
        if not isinstance(item, dict):
            continue
        # possible fields to check
        checks = []
        for k in ('rule_id', 'id', 'rule_name', 'rule_title', 'rule_path', 'path', 'name'):
            if k in item and item[k] is not None:
                checks.append(str(item[k]))
        matched = False
        for val in checks:
            if not val:
                continue
            # exact id match
            if val == id_norm or val == id_stem:
                matched = True
                break
            # substring match
            if id_norm in val or id_stem in val:
                matched = True
                break
        if matched:
            total += extract_detection_count(item)
            continue
        # last resort: check json content stringified for the identifier
        try:
            s = json.dumps(item)
            if id_norm in s or id_stem in s:
                total += extract_detection_count(item)
        except Exception:
            pass
    return total

def classify_rule(baseline_total: int, current_total: int, rule_detection_count: int) -> Tuple[str,int,str]:
    """
    Returns (grade, score, reasoning)
    grade in {'STRONG','NEUTRAL','WEAK','CONCERNING'}
    """
    delta = current_total - baseline_total

    metrics_msg = f"(baseline_total={baseline_total}, current_total={current_total}, delta={delta}, rule_contrib={rule_detection_count})"

    if delta < 0:
        grade = 'CONCERNING'
        score = 20
        reasoning = f'Total alerts decreased by {abs(delta)} after adding the new rule. Investigate possible deduplication or incorrect logic. {metrics_msg}'
    elif delta == 0:
        grade = 'WEAK'
        score = 25
        reasoning = f'No change in total alerts after adding the new rule. {metrics_msg}'
    else:
        # delta > 0
        if delta >= STRONG_DELTA:
            # large positive improvement
            if rule_detection_count >= MIN_RULE_CONTRIBUTION:
                grade = 'STRONG'
                score = 90
                reasoning = f'Rule materially increased total alerts by {delta} and contributed {rule_detection_count} detections. {metrics_msg}'
            else:
                grade = 'NEUTRAL'
                score = 60
                reasoning = f'Total alerts increased by {delta}, but this specific rule contributed only {rule_detection_count} detections. Consider review. {metrics_msg}'
        else:
            # small positive improvement -> neutral if rule contributes decently, else weak
            if rule_detection_count >= MIN_RULE_CONTRIBUTION:
                grade = 'NEUTRAL'
                score = 50
                reasoning = f'Minor increase in total alerts (delta={delta}). Rule contributes {rule_detection_count} detections — neutral. {metrics_msg}'
            else:
                grade = 'WEAK'
                score = 35
                reasoning = f'Minor total alert increase (delta={delta}) but rule contributes only {rule_detection_count} detections. {metrics_msg}'

    # clamp score
    score = max(0, min(100, score))
    return grade, score, reasoning

def build_report(baseline_results: List[Dict], current_results: List[Dict], changed_rules: List[str]) -> Dict:
    baseline_total = sum_total_detections(baseline_results)
    current_total = sum_total_detections(current_results)
    delta = current_total - baseline_total

    # prepare baseline+current metrics summary
    summary = {
        'baseline_total': baseline_total,
        'current_total': current_total,
        'delta': delta,
        'num_baseline_items': len(baseline_results),
        'num_current_items': len(current_results),
    }

    per_rule_reports = []
    for rule in changed_rules:
        rule_det_current = find_rule_detection_in_results(rule, current_results)
        grade, score, reasoning = classify_rule(baseline_total, current_total, rule_det_current)
        per_rule_reports.append({
            'rule_identifier': rule,
            'rule_detection_count': rule_det_current,
            'classification': grade,
            'score': score,
            'reasoning': reasoning
        })

    return {
        'summary': summary,
        'per_rule': per_rule_reports
    }

def parse_changed_rules(arg: str) -> List[str]:
    if not arg:
        return []
    # accept comma separated or newline separated
    parts = []
    for part in arg.split(','):
        part = part.strip()
        if not part:
            continue
        parts.append(part)
    return parts

def main():
    parser = argparse.ArgumentParser(description="Compare baseline vs current validation results and classify changed rules by delta logic.")
    parser.add_argument('--baseline', '-b', required=True, help="Path to baseline results (json file or directory of json files)")
    parser.add_argument('--current', '-c', required=True, help="Path to current results (json file or directory of json files)")
    parser.add_argument('--changed-rules', '-r', default='', help="Comma-separated list of changed/new rule filenames or ids (e.g. rules/foo.yml,rule-id-123)")
    parser.add_argument('--output', '-o', required=True, help="Output JSON file path for classification report")
    parser.add_argument('--strong-delta', type=int, default=STRONG_DELTA, help="Threshold for STRONG classification (default: {})".format(STRONG_DELTA))
    parser.add_argument('--min-rule-contrib', type=int, default=MIN_RULE_CONTRIBUTION, help="Minimum per-rule detections to be considered meaningful (default: {})".format(MIN_RULE_CONTRIBUTION))

    args = parser.parse_args()

    # allow overriding thresholds from CLI
    global STRONG_DELTA, MIN_RULE_CONTRIBUTION
    STRONG_DELTA = int(args.strong_delta)
    MIN_RULE_CONTRIBUTION = int(args.min_rule_contrib)
    NEUTRAL_UPPER = STRONG_DELTA - 1

    try:
        baseline_results = load_results(args.baseline)
    except Exception as e:
        print(f"ERROR: Could not load baseline results from {args.baseline}: {e}")
        return

    try:
        current_results = load_results(args.current)
    except Exception as e:
        print(f"ERROR: Could not load current results from {args.current}: {e}")
        return

    changed_rules = parse_changed_rules(args.changed_rules)
    if not changed_rules:
        print("Warning: no changed-rules provided. The script will still compute baseline/current totals and delta, but per-rule classification will be empty.")

    report = build_report(baseline_results, current_results, changed_rules)

    # add runtime metadata
    report_meta = {
        'thresholds': {
            'STRONG_DELTA': STRONG_DELTA,
            'MIN_RULE_CONTRIBUTION': MIN_RULE_CONTRIBUTION
        }
    }
    report['meta'] = report_meta

    outp = Path(args.output)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with outp.open('w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    # print summary
    s = report['summary']
    print("\n=== Classification Summary ===")
    print(f"Baseline total detections : {s['baseline_total']}")
    print(f"Current total detections  : {s['current_total']}")
    print(f"Delta (current - baseline) : {s['delta']}")
    print(f"Wrote classification report to: {outp.resolve()}")
    if report['per_rule']:
        print("\nPer-rule classifications:")
        for pr in report['per_rule']:
            print(f" - {pr['rule_identifier']}: {pr['classification']} (score={pr['score']}, detections={pr['rule_detection_count']})")
    else:
        print("No changed rules to classify (empty list).")

if __name__ == '__main__':
    main()

