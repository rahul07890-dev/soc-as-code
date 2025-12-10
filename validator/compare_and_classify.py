#!/usr/bin/env python3
"""
compare_and_classify.py (A+B+threshold applied)

- Strict TP attribution: SID counted TP only if at least one detection for that SID
  has an alert name that matches the rule filename, id or title.
- Triggered: TP >= trigger_threshold (default 3).
- Raw composite used for classification; transformed display score produced.
- Accepts --debug for diagnostics.
"""
import argparse
import json
import yaml
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import re

# ---------- helpers ----------
def load_json(path: Path):
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return []

def load_synthetic_logs(path: Path):
    logs = []
    if not path.exists():
        return logs
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            line=line.strip()
            if not line:
                continue
            try:
                logs.append(json.loads(line))
            except Exception:
                continue
    return logs

def extract_rule_identifiers_from_yaml(path: Path):
    res = {"id": None, "title": None, "filename": path.stem}
    try:
        y = yaml.safe_load(path.read_text(encoding='utf-8'))
        if isinstance(y, dict):
            res["id"] = str(y.get("id")).strip() if y.get("id") else None
            res["title"] = str(y.get("title")).strip() if y.get("title") else None
    except Exception:
        pass
    return res

def clamp(n, a=0, b=100):
    try:
        n = float(n)
    except Exception:
        return a
    return max(a, min(b, n))

def structure_score_for_rule(rule_path: Path):
    try:
        y = yaml.safe_load(rule_path.read_text(encoding='utf-8'))
    except Exception:
        return 0
    detection = y.get("detection", {}) if isinstance(y, dict) else {}
    cond = detection.get("condition", "") if isinstance(detection, dict) else ""
    serialized = json.dumps(detection, default=str)

    score = 50
    if "re:" in serialized or "regexp" in serialized or ".*" in serialized or "\\d" in serialized:
        score -= 25
    selections = [k for k in detection.keys() if k != "condition"] if isinstance(detection, dict) else []
    if len(selections) <= 1:
        score -= 15
    if " or " in str(cond).lower() and " and " not in str(cond).lower():
        score -= 10
    if " and " in str(cond).lower():
        score += 10
    field_count = 0
    for sel in selections:
        block = detection.get(sel, {})
        if isinstance(block, dict):
            field_count += len(block.keys())
    score += min(25, field_count * 4)
    return int(clamp(score, 0, 100))

def transform_score(score: float) -> float:
    try:
        s = float(score)
    except Exception:
        s = 0.0
    if s < 25.0:
        s = s * 4.0
    return float(clamp(round(s, 2), 0, 100))

def classify_from_raw(raw_pct: float) -> str:
    if raw_pct >= 75:
        return "EXCELLENT"
    if raw_pct >= 60:
        return "GOOD"
    if raw_pct >= 40:
        return "NEUTRAL"
    if raw_pct >= 25:
        return "CONCERNING"
    return "BAD"

# ---------- Classifier ----------
class Classifier:
    def __init__(self, baseline_dir: Path, current_dir: Path, synthetic_combined_file: Path, debug: bool = False):
        self.debug = debug
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
        self.indexed_current = defaultdict(list)
        for det in self.current_dets:
            raw = det.get("raw") or det.get("log") or det.get("_raw") or det.get("original_event") or {}
            sid = None
            if isinstance(raw, dict):
                sid = raw.get("_synthetic_id") or raw.get("_syntheticId") or raw.get("_syntheticID")
            if not sid:
                sid = det.get("_synthetic_id") or det.get("synthetic_id")
            if sid:
                self.indexed_current[sid].append(det)

        if self.debug:
            print(f"[DEBUG] Loaded baseline={len(self.baseline_dets)} current={len(self.current_dets)} synthetic={len(self.synthetic_logs)}")

    @staticmethod
    def _detection_names_for_det(det: dict):
        """Return possible detection alert names from a detection object"""
        names = set()
        for k in ('rule_name', 'rule', 'alert_name', 'signature'):
            v = det.get(k)
            if v:
                names.add(str(v))
        # sometimes detection contains a 'rule_id'
        if det.get('rule_id'):
            names.add(str(det.get('rule_id')))
        return names

    def classify_rule(self, rule_path: Path, trigger_threshold: int = 3):
        ids = extract_rule_identifiers_from_yaml(rule_path)
        rid = ids.get("id")
        title = ids.get("title")
        name = rule_path.stem

        # Gather synthetic logs generated "for" this rule (origin=new)
        logs_for_rule = [l for l in self.synthetic_logs if l.get("_origin") == "new" and l.get("_source_rule_id") in {rid, name, title}]
        if not logs_for_rule:
            logs_for_rule = [l for l in self.synthetic_logs if l.get("_origin") == "new" and l.get("_source_rule_id") in {name, title}]
        generated_count = len(logs_for_rule)

        # Detections mapping and attribution
        matched_sids = set()
        detections_for_rule = []

        for det in self.current_dets:
            raw = det.get("raw") or det.get("log") or det.get("_raw") or det.get("original_event") or {}
            sid = None
            src_rid = None
            if isinstance(raw, dict):
                sid = raw.get("_synthetic_id") or raw.get("_syntheticId") or raw.get("_syntheticID")
                src_rid = raw.get("_source_rule_id") or raw.get("source_rule_id")
            else:
                try:
                    # naive string parsing fallback
                    if isinstance(raw, str) and "_synthetic_id" in raw:
                        m = re.search(r'"_synthetic_id"\s*:\s*"([^"]+)"', raw)
                        if m:
                            sid = m.group(1)
                    if isinstance(raw, str) and "_source_rule_id" in raw:
                        m2 = re.search(r'"_source_rule_id"\s*:\s*"([^"]+)"', raw)
                        if m2:
                            src_rid = m2.group(1)
                except Exception:
                    pass

            if sid:
                matched_sids.add(sid)
                detections_for_rule.append(det)
            elif src_rid and str(src_rid) in {rid, name, title}:
                detections_for_rule.append(det)
            else:
                # ambiguous/other detections are not attributed here
                pass

        if self.debug:
            print(f"[DEBUG] Rule {name}: generated_count={generated_count}, matched_sids={len(matched_sids)}, detections_for_rule={len(detections_for_rule)}")

        # True Positives and False Positives (based on synthetic map)
        tp_sids = set()
        fp_sids = set()
        for sid in matched_sids:
            log = self.synthetic_map.get(sid)
            if not log:
                fp_sids.add(sid)
                continue

            # Only consider as TP if SID belongs to this rule AND at least one detection for that SID
            # has a detection name matching rule id/name/title.
            dets_for_sid = self.indexed_current.get(sid, [])
            # gather possible detection names from detections for this sid
            det_names = set()
            for d in dets_for_sid:
                det_names.update(self._detection_names_for_det(d))

            expected_names = {s for s in (rid, name, title) if s}
            matched_by_name = bool(det_names.intersection(expected_names))

            if log.get("_origin") == "new" and log.get("_source_rule_id") in {rid, name, title}:
                if matched_by_name:
                    tp_sids.add(sid)
                else:
                    # If there are no detection names matching expected, treat as FP (avoid cross-attribution)
                    fp_sids.add(sid)
            else:
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

        # Composite scoring (raw composite)
        composite = (f1 * 100.0) * 0.60 + (1 - noise_ratio) * 100.0 * 0.25 + (struct_score) * 0.15
        composite = clamp(round(composite, 2), 0, 100)

        transformed_score = transform_score(composite)

        # detection_count and triggered (threshold applied)
        detection_count_tp = TP
        total_detections = len(detections_for_rule)
        triggered_flag = TP >= int(trigger_threshold_value) if 'trigger_threshold_value' in globals() else TP >= trigger_threshold

        # Reasoning summary
        reasoning = []
        reasoning.append(f"Generated synthetic logs for rule: {generated_count}")
        reasoning.append(f"TP={TP}, FP={FP}, FN={FN}")
        reasoning.append(f"Precision={precision:.2f}, Recall={recall:.2f}, F1={f1:.2f}")
        reasoning.append(f"Structure score: {struct_score}/100")
        reasoning.append(f"Noise ratio: {noise_ratio:.2%}")
        if generated_count == 0:
            reasoning.append("No synthetic 'new' logs found for this rule.")
        if noise_ratio > 0.1:
            reasoning.append("High false-positive rate -> noisy rule.")

        grade = classify_from_raw(composite)

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
            "raw_score": composite,
            "score": transformed_score,
            "classification": grade,
            "reasoning": " | ".join(reasoning),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "detection_count": detection_count_tp,
            "total_detections": total_detections,
            "triggered": triggered_flag,
            "metrics": {
                "true_positive_delta": TP,
                "false_positive_delta": FP,
                "precision_delta": round(precision, 3)
            }
        }

        if self.debug:
            print(f"[DEBUG] Rule {name} result: TP={TP}, FP={FP}, raw={composite}, transformed={transformed_score}, triggered={triggered_flag}, grade={grade}")

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
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--trigger-threshold", type=int, default=3,
                        help="Minimum TP required to mark rule as triggered (default: 3)")
    args = parser.parse_args()

    baseline = Path(args.baseline_results)
    current = Path(args.current_results)
    synthetic = Path(args.synthetic_logs)

    # Make global trigger_threshold available inside classify_rule closure (used for compatibility)
    global trigger_threshold_value
    trigger_threshold_value = int(args.trigger_threshold)

    changed = parse_list(args.changed_sigma_rules) + parse_list(args.changed_yara_rules)
    changed = [Path(p) for p in changed if p]

    if not changed:
        print("No changed rules provided; exiting with minimal report")
        report = {"summary": {"total_rules": 0, "average_score": 0}, "rules": []}
    else:
        cls = Classifier(baseline, current, synthetic, debug=args.debug)
        results = []
        for rp in changed:
            if not Path(rp).exists():
                print(f"Warning: changed rule file not found: {rp}")
                continue
            res = cls.classify_rule(Path(rp), trigger_threshold=args.trigger_threshold)
            results.append(res)

        # average of transformed (display) scores kept for UX/backwards compatibility
        avg_transformed = sum(r["score"] for r in results) / len(results) if results else 0.0

        # by_grade derived from RAW composite classifications
        by_grade = {}
        for r in results:
            g = r.get("classification", "UNKNOWN")
            by_grade[g] = by_grade.get(g, 0) + 1

        report = {
            "summary": {
                "total_rules": len(results),
                "average_score": round(avg_transformed, 2),
                "by_grade": by_grade
            },
            "rules": results
        }

    outp = Path(args.output_file)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f"Wrote classification report -> {outp}")

if __name__ == "__main__":
    main()
