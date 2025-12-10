#!/usr/bin/env python3
"""
compare_and_classify.py (improved)

- Reads baseline/current detection outputs (detections.json)
- Reads synthetic_logs/combined/all_logs.jsonl to map synthetic log IDs -> origin/source_rule
- For each changed rule (YAML path list), computes:
    TP = detections on synthetic logs that were generated FOR that rule (origin=new)
    FP = detections on synthetic logs NOT generated for that rule (origin=baseline OR other new)
    FN = synthetic logs generated for that rule (origin=new) that produced NO detection
- Calculates Precision / Recall / F1 and a composite score that includes structure/complexity penalty.
- Produces classification JSON report (compatible with your workflow)
"""

import argparse
import json
import yaml
from pathlib import Path
from collections import defaultdict
from typing import Dict, Any, List, Tuple
from datetime import datetime
import math

# ---------- helpers ----------
def load_json(path: Path):
    if not path.exists():
        return []
    return json.loads(path.read_text())

def load_synthetic_logs(path: Path) -> List[Dict[str,Any]]:
    logs = []
    if not path.exists():
        return logs
    with open(path, 'r') as fh:
        for line in fh:
            line=line.strip()
            if not line:
                continue
            try:
                logs.append(json.loads(line))
            except Exception:
                continue
    return logs

def extract_rule_identifiers_from_yaml(path: Path) -> Dict[str,str]:
    res = {"id": None, "title": None, "filename": path.stem}
    try:
        y = yaml.safe_load(path.read_text())
        if isinstance(y, dict):
            res["id"] = str(y.get("id")).strip() if y.get("id") else None
            res["title"] = str(y.get("title")).strip() if y.get("title") else None
    except Exception:
        pass
    return res

def clamp(n, a=0, b=100):
    return max(a, min(b, n))

def structure_score_for_rule(rule_path: Path) -> int:
    # Heuristics: penalize regex/heavy ORs and reward ANDs and multi-field use
    try:
        y = yaml.safe_load(rule_path.read_text())
    except Exception:
        return 0
    detection = y.get("detection", {}) if isinstance(y, dict) else {}
    cond = detection.get("condition", "") if isinstance(detection, dict) else ""
    serialized = json.dumps(detection, default=str)

    score = 50
    if "re:" in serialized or "regexp" in serialized or ".*" in serialized:
        score -= 20
    selections = [k for k in detection.keys() if k != "condition"] if isinstance(detection, dict) else []
    if len(selections) <= 1:
        score -= 10
    if " or " in str(cond).lower() and " and " not in str(cond).lower():
        score -= 15
    if " and " in str(cond).lower():
        score += 10
    # more fields used -> better
    field_count = 0
    for sel in selections:
        block = detection.get(sel, {})
        if isinstance(block, dict):
            field_count += len(block.keys())
    score += min(20, field_count * 3)
    return clamp(score, 0, 100)

# ---------- main classifier ----------
class Classifier:
    def __init__(self, baseline_dir: Path, current_dir: Path, synthetic_combined_file: Path):
        self.baseline_dets = load_json(baseline_dir / "detections.json") if baseline_dir else []
        self.current_dets = load_json(current_dir / "detections.json") if current_dir else []
        self.synthetic_logs = load_synthetic_logs(synthetic_combined_file)
        # map synthetic_id -> log
        self.synthetic_map = {}
        for l in self.synthetic_logs:
            sid = l.get("_synthetic_id")
            if sid:
                self.synthetic_map[sid] = l
        # pre-index detections by synthetic id if present
        # Many detectors include 'raw' that contains the original synthetic log (depending on your SOCSimulator).
        self.indexed_current = defaultdict(list)
        for det in self.current_dets:
            # detection may hold raw with _synthetic_id or _source_rule_id
            raw = det.get("raw") or det.get("log") or det.get("_raw") or det.get("original_event") or {}
            sid = None
            if isinstance(raw, dict):
                sid = raw.get("_synthetic_id") or raw.get("_syntheticId") or raw.get("_syntheticID")
            if not sid:
                # sometimes the synthetic_id got placed at top-level
                sid = det.get("_synthetic_id") or det.get("synthetic_id")
            if sid:
                self.indexed_current[sid].append(det)

    def classify_rule(self, rule_path: Path) -> Dict[str,Any]:
        ids = extract_rule_identifiers_from_yaml(rule_path)
        rid = ids.get("id")
        title = ids.get("title")
        name = rule_path.stem

        # Gather synthetic logs generated "for" this rule (origin=new)
        logs_for_rule = [l for l in self.synthetic_logs if l.get("_origin") == "new" and l.get("_source_rule_id") in {rid, name, title}]
        # fallback: match by filename if id/title missing
        if not logs_for_rule:
            logs_for_rule = [l for l in self.synthetic_logs if l.get("_origin") == "new" and l.get("_source_rule_id") in {name, title}]

        generated_count = len(logs_for_rule)

        # Detections that map to synthetic logs: gather SIDs that matched at least once
        matched_sids = set()
        # also collect detections that reference source_rule_id in raw (older flow)
        detected_source_rule_ids = defaultdict(int)

        for det in self.current_dets:
            # attempt to find synthetic id in detection.raw
            raw = det.get("raw") or det.get("log") or det.get("_raw") or det.get("original_event") or {}
            sid = None
            if isinstance(raw, dict):
                sid = raw.get("_synthetic_id") or raw.get("_syntheticId") or raw.get("_syntheticID")
                src_rid = raw.get("_source_rule_id") or raw.get("source_rule_id")
                if src_rid:
                    detected_source_rule_ids[str(src_rid)] += 1
            else:
                # sometimes raw is dumped as string; try naive substring
                try:
                    if isinstance(raw, str) and "_synthetic_id" in raw:
                        # naive parse - not perfect, but helpful
                        # find pattern like "_synthetic_id\": \"<uuid>\""
                        import re
                        m = re.search(r'"_synthetic_id"\s*:\s*"([^"]+)"', raw)
                        if m:
                            sid = m.group(1)
                except Exception:
                    pass

            if sid:
                matched_sids.add(sid)

        # True Positives: matched sids that belong to this rule (source_rule_id == rid)
        tp_sids = set()
        fp_sids = set()
        for sid in matched_sids:
            log = self.synthetic_map.get(sid)
            if not log:
                # no synthetic log present for that SID - treat as ambiguous (count toward FP)
                fp_sids.add(sid)
                continue
            # if synthetic log origin is "new"
            if log.get("_origin") == "new":
                if log.get("_source_rule_id") in {rid, name, title}:
                    tp_sids.add(sid)
                else:
                    # matched a different new rule's synthetic log -> FP for this rule
                    fp_sids.add(sid)
            else:
                # matched a baseline synthetic log -> FP
                fp_sids.add(sid)

        TP = len(tp_sids)
        FP = len(fp_sids)
        FN = max(0, generated_count - TP)

        # Precision / Recall / F1 (safe)
        precision = (TP / (TP + FP)) if (TP + FP) > 0 else 0.0
        recall = (TP / (TP + FN)) if (TP + FN) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        # Structural score from heuristics
        struct_score = structure_score_for_rule(rule_path)

        # Noise penalty: fraction of detections that were FP among all matched_sids
        noise_ratio = (FP / (TP + FP)) if (TP + FP) > 0 else 0.0

        # Composite scoring:
        #  - 50% weight to detection quality (F1)
        #  - 30% weight to noise-resistance (1 - noise_ratio)
        #  - 20% weight to structural score normalized
        composite = (f1 * 100) * 0.5 + (1 - noise_ratio) * 100 * 0.3 + (struct_score) * 0.2
        composite = clamp(round(composite), 0, 100)

        # Reasoning summary
        reasoning = []
        reasoning.append(f"Generated synthetic logs for rule: {generated_count}")
        reasoning.append(f"TP={TP}, FP={FP}, FN={FN}")
        reasoning.append(f"Precision={precision:.2f}, Recall={recall:.2f}, F1={f1:.2f}")
        reasoning.append(f"Structure score: {struct_score}/100")
        reasoning.append(f"Noise ratio: {noise_ratio:.2%}")
        if generated_count == 0:
            reasoning.append("No synthetic 'new' logs found for this rule. If you expected generation, check generator complexity/skipping.")
        if noise_ratio > 0.1:
            reasoning.append("High false-positive rate against baseline/other synthetic logs -> rule likely noisy.")

        # classification thresholds (tunable)
        if composite >= 70 and precision >= 0.8 and recall >= 0.5:
            grade = "STRONG"
        elif composite >= 45:
            grade = "NEUTRAL"
        else:
            grade = "WEAK"

        result = {
            "rule_name": name,
            "rule_path": str(rule_path),
            "rule_id": rid,
            "rule_title": title,
            "generated_count": generated_count,
            "TP": TP,
            "FP": FP,
            "FN": FN,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "structure_score": struct_score,
            "noise_ratio": round(noise_ratio, 3),
            "score": composite,
            "classification": grade,
            "reasoning": " | ".join(reasoning),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        return result

# ---------- CLI ----------
def parse_list(s: str):
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]

def main():
    parser = argparse.ArgumentParser(description="Compare baseline and current detections and classify changed rules")
    parser.add_argument("--baseline-results", required=True)
    parser.add_argument("--current-results", required=True)
    parser.add_argument("--changed-sigma-rules", default="")
    parser.add_argument("--changed-yara-rules", default="")
    parser.add_argument("--synthetic-logs", default="synthetic_logs/combined/all_logs.jsonl")
    parser.add_argument("--output-file", required=True)
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    baseline = Path(args.baseline_results)
    current = Path(args.current_results)
    synthetic = Path(args.synthetic_logs)

    changed = parse_list(args.changed_sigma_rules) + parse_list(args.changed_yara_rules)
    changed = [Path(p) for p in changed if p]

    if not changed:
        print("No changed rules provided; exiting with minimal report")
        report = {"summary": {"total_rules": 0, "average_score": 0}, "rules": []}
    else:
        cls = Classifier(baseline, current, synthetic)
        results = []
        for rp in changed:
            if not Path(rp).exists():
                print(f"Warning: changed rule file not found: {rp}")
                continue
            res = cls.classify_rule(Path(rp))
            results.append(res)

        avg = sum(r["score"] for r in results) / len(results) if results else 0
        by_grade = {}
        for r in results:
            by_grade[r["classification"]] = by_grade.get(r["classification"], 0) + 1

        report = {
            "summary": {
                "total_rules": len(results),
                "average_score": round(avg, 2),
                "by_grade": by_grade
            },
            "rules": results
        }

    outp = Path(args.output_file)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(report, indent=2))
    print(f"Wrote classification report -> {outp}")

if __name__ == "__main__":
    main()

