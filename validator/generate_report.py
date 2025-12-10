#!/usr/bin/env python3
"""
generate_report.py - SOC-friendly markdown report using raw_score for grading.
"""
import json
from pathlib import Path
from datetime import datetime
import argparse

def clamp(n, a=0, b=100):
    try:
        n = float(n)
    except Exception:
        return a
    return max(a, min(b, n))

def classify_from_raw(raw):
    raw = clamp(raw)
    if raw >= 75:
        return "EXCELLENT"
    if raw >= 60:
        return "GOOD"
    if raw >= 40:
        return "NEUTRAL"
    if raw >= 25:
        return "CONCERNING"
    return "BAD"

def generate_markdown_report(classification_report: str, output_file: str):
    j = json.loads(Path(classification_report).read_text(encoding='utf-8'))
    summary = j.get('summary', {})
    rules = j.get('rules', [])

    processed = []
    trans_scores = []
    for r in rules:
        raw = r.get('raw_score')
        if raw is None:
            sc = r.get('score', 0)
            raw = sc if sc >= 25 else sc / 4.0
        raw = float(raw)
        trans = float(r.get('score', 0))
        trans_scores.append(trans)
        cls = classify_from_raw(raw)
        r['_raw_score'] = raw
        r['_transformed_score'] = trans
        r['_class_from_raw'] = cls
        processed.append(r)

    total = len(processed)
    avg_trans = sum(trans_scores)/len(trans_scores) if trans_scores else 0.0

    by_grade = {"EXCELLENT":0,"GOOD":0,"NEUTRAL":0,"CONCERNING":0,"BAD":0}
    for p in processed:
        by_grade[p.get('_class_from_raw','BAD')] += 1

    lines=[]
    lines.append("# 🛡️ Security Rule Quality Assessment")
    lines.append("")
    lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total rules: {total}")
    lines.append(f"- Average (display): {avg_trans:.2f}/100")
    lines.append("")
    lines.append("### Grade distribution (from raw composite)")
    lines.append("")
    for g in ["EXCELLENT","GOOD","NEUTRAL","CONCERNING","BAD"]:
        if by_grade[g]:
            lines.append(f"- {g}: {by_grade[g]} rule(s)")
    lines.append("")
    lines.append("---")
    lines.append("")
    if processed:
        lines.append("## Detailed Results")
        lines.append("")
        processed.sort(key=lambda x: x.get('_raw_score',0), reverse=True)
        for i,r in enumerate(processed,1):
            lines.append(f"### {i}. {r.get('rule_name')}")
            lines.append("")
            lines.append(f"- Raw score: {r.get('_raw_score'):.2f}/100")
            lines.append(f"- Display score: {r.get('_transformed_score'):.2f}/100")
            lines.append(f"- Classification (raw): {r.get('_class_from_raw')}")
            lines.append(f"- Triggered (TP>0): {'Yes' if r.get('triggered') else 'No'}")
            lines.append(f"- TP: {r.get('TP')} | FP: {r.get('FP')} | FN: {r.get('FN')}")
            lines.append(f"- Detections (TP): {r.get('detection_count')} | Total detections: {r.get('total_detections')}")
            lines.append("")
            lines.append("**Reasoning:**")
            lines.append(f"> {r.get('reasoning')}")
            lines.append("")
            lines.append("---")
            lines.append("")

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    Path(output_file).write_text("\n".join(lines), encoding='utf-8')
    print(f"[+] Wrote markdown -> {output_file}")

if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--classification-report', required=True)
    parser.add_argument('--output-file', required=True)
    args = parser.parse_args()
    generate_markdown_report(args.classification_report, args.output_file)
