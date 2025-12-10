#!/usr/bin/env python3
import json, sys, argparse
from pathlib import Path

def get_risk(score):
    s = float(score)
    if s >= 80: return "LOW RISK"
    if s >= 60: return "MODERATE RISK"
    if s >= 40: return "HIGH RISK"
    return "CRITICAL RISK"

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--classification-report', required=True)
    args = p.parse_args()
    path = Path(args.classification_report)
    if not path.exists():
        print("No classification report found.")
        sys.exit(1)
    j = json.loads(path.read_text(encoding='utf-8'))
    summary = j.get('summary', {})
    rules = j.get('rules', [])
    print("\n" + "="*70)
    print("CLASSIFICATION SUMMARY")
    print("="*70)
    print(f"Total new rules analyzed: {summary.get('total_rules',0)}")
    print(f"Average quality score (display): {summary.get('average_score',0)}")
    print("")
    if rules:
        print("-"*70)
        print("DETAILED RULE CLASSIFICATIONS")
        print("-"*70)
        for r in rules:
            name = r.get('rule_name')
            raw = r.get('raw_score', 0)
            disp = r.get('score', 0)
            cls = r.get('classification')
            tp = r.get('TP',0)
            total = r.get('total_detections',0)
            triggered = r.get('triggered', False)
            print(f"\n{name}")
            print(f"  Classification (raw): {cls} (raw: {raw:.2f}/100, display: {disp:.2f}/100)")
            print(f"  Triggered (TP>0): {'Yes' if triggered else 'No'} | TP: {tp} | Total detections: {total}")
            print(f"  Reasoning: {r.get('reasoning')}")
    print("\n" + "="*70)
    # final normalized score show display average
    avg = summary.get('average_score',0)
    print("\nFINAL SCORE")
    print(f"  Score: {avg:.2f}")
    print(f"  Risk Level: {get_risk(avg)}")
    print("\n" + "="*70)

if __name__=='__main__':
    main()
