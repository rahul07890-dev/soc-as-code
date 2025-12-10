#!/usr/bin/env python3
"""
generate_logs.py

Generates synthetic logs for sigma rules. Key behavior:
- Adds _synthetic_id, _origin, _source_rule_id, _source_rule_title.
- Does NOT fabricate arbitrary selector fields: only populates fields the generator knows.
- Option --mark-all-new: useful when testing an entire ruleset as 'new'.
"""
import os, sys, json, argparse
from pathlib import Path
from datetime import datetime
from hashlib import sha256
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from validator.validate_rules import EnhancedLogGenerator
    from test import load_sigma_rules
except Exception:
    from validate_rules import EnhancedLogGenerator
    from test import load_sigma_rules

def rule_is_complex(rule: dict) -> bool:
    detection = rule.get("detection", {})
    cond = detection.get("condition", "") if isinstance(detection, dict) else ""
    serialized = json.dumps(detection, default=str)
    if "re:" in serialized or "regexp" in serialized or "\\d" in serialized or ".*" in serialized:
        return True
    if isinstance(detection, dict):
        selection_blocks = [k for k in detection.keys() if k != "condition"]
        if len(selection_blocks) > 4:
            return True
    if isinstance(cond, str) and (" and " in cond.lower() and " or " in cond.lower()):
        return True
    correlation_keywords = ["near", "sequence", "count", "within", "pipeline"]
    if any(k in str(cond).lower() for k in correlation_keywords):
        return True
    return False

def is_new_rule(rule_id: str) -> bool:
    if not rule_id:
        return False
    return str(rule_id).startswith("SIG-900") or str(rule_id).upper().startswith("TEST-")

def generate_synthetic_logs(rules_dir: str, output_dir: str, log_count: int = 200, mark_all_new: bool = False):
    rules_path = Path(rules_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"[+] Generating synthetic logs from Sigma rules")
    rule_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
    print(f"[+] Found {len(rule_files)} rule files")

    all_rules = []
    rules_metadata = {}
    for rf in rule_files:
        try:
            rules = load_sigma_rules(str(rf))
            for r in rules:
                rid = r.get("id", rf.stem)
                all_rules.append(r)
                rules_metadata[rid] = {
                    "path": str(rf),
                    "title": r.get("title", "Untitled"),
                    "id": rid,
                    "complex_rule": rule_is_complex(r),
                    "skipped": False,
                    "generation_error": None,
                    "detection_hash": None,
                    "origin": "unknown",
                    "generated_logs": 0,
                    "positive_count": 0,
                    "negative_count": 0,
                }
        except Exception as e:
            print(f"⚠️ Error loading {rf}: {e}")

    print(f"[+] Total parsed rules: {len(all_rules)}")
    if len(all_rules) == 0:
        print("No rules found - exiting.")
        return {}

    per_rule_default = max(10, log_count // max(1, len(all_rules)))

    all_logs = []
    logs_per_rule = {}

    rules_dir_name = rules_path.name.lower()
    heuristically_new_dir = any(x in rules_dir_name for x in ("new", "new_rules", "new_rules_temp", "added"))

    for i, rule in enumerate(all_rules):
        rid = rule.get("id", f"rule_{i}")
        title = rule.get("title", "Untitled")
        detection = rule.get("detection", {})

        print(f"\n[{i+1}/{len(all_rules)}] Processing rule: {title} ({rid})")

        try:
            rules_metadata[rid]["detection_hash"] = sha256(
                json.dumps(detection, sort_keys=True).encode()
            ).hexdigest()
        except Exception:
            rules_metadata[rid]["detection_hash"] = None

        if mark_all_new or heuristically_new_dir:
            origin = "new"
        else:
            origin = "new" if is_new_rule(rid) else "baseline"
        rules_metadata[rid]["origin"] = origin

        if origin == "new" and rules_metadata[rid].get("complex_rule", False):
            print("  → New rule marked complex: skipping synthetic generation (metadata flagged).")
            logs = []
            rules_metadata[rid]["skipped"] = True
            rules_metadata[rid]["generated_logs"] = 0
            logs_per_rule[rid] = 0
            continue

        try:
            rule_log_count = per_rule_default
            # Use EnhancedLogGenerator but the generator itself must be conservative:
            logs = EnhancedLogGenerator.generate_for_sigma_rule(rule, count=rule_log_count) or []
        except Exception as e:
            print(f"  ⚠️ Generation error for {rid}: {e}")
            logs = []
            rules_metadata[rid]["skipped"] = True
            rules_metadata[rid]["generation_error"] = str(e)

        pos = 0
        neg = 0
        # Tag logs
        for l in logs:
            if not isinstance(l, dict):
                continue
            sid = str(uuid4())
            l["_synthetic_id"] = sid
            l["_origin"] = origin
            l["_source_rule_id"] = rid
            l["_source_rule_title"] = title
            l.setdefault("_logsource", rule.get("logsource", {}))
            if "_match_type" not in l:
                l["_match_type"] = l.get("_match_type", "positive")
            if l["_match_type"] == "positive":
                pos += 1
            elif l["_match_type"] == "negative":
                neg += 1

        rules_metadata[rid]["positive_count"] = pos
        rules_metadata[rid]["negative_count"] = neg
        rules_metadata[rid]["generated_logs"] = len(logs)
        rules_metadata[rid]["skipped"] = False if logs else rules_metadata[rid]["skipped"]

        all_logs.extend(logs)
        logs_per_rule[rid] = len(logs)

        print(f"  → Generated {len(logs)} logs (pos={pos}, neg={neg}) - origin={origin}")

    master_file = Path(output_path) / "synthetic_logs_master.jsonl"
    with open(master_file, "w", encoding="utf-8") as f:
        for e in all_logs:
            f.write(json.dumps(e) + "\n")
    print(f"[+] Wrote master logs ({len(all_logs)}) -> {master_file}")

    combined_file = Path(output_path) / "all_logs.jsonl"
    with open(combined_file, "w", encoding="utf-8") as f:
        for e in all_logs:
            f.write(json.dumps(e) + "\n")

    meta = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_logs": len(all_logs),
        "total_rules": len(all_rules),
        "logs_per_rule": logs_per_rule,
        "rules_metadata": rules_metadata,
    }
    meta_file = Path(output_path) / "metadata.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"[+] Wrote metadata -> {meta_file}")

    total_pos = sum(1 for l in all_logs if l.get("_match_type") == "positive")
    total_neg = sum(1 for l in all_logs if l.get("_match_type") == "negative")
    print("\n" + "=" * 60)
    print("SYNTHETIC LOG GENERATION SUMMARY")
    print("=" * 60)
    print(f"Total rules processed: {len(all_rules)}")
    print(f"Total logs generated: {len(all_logs)}")
    print(f"  • Positive: {total_pos}")
    print(f"  • Negative: {total_neg}")
    print("=" * 60)

    return meta

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic logs from Sigma rules")
    parser.add_argument("--rules-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--log-count", type=int, default=200)
    parser.add_argument("--mark-all-new", action="store_true",
                        help="Treat all rules in rules-dir as NEW (sets _origin='new').")
    args = parser.parse_args()

    try:
        generate_synthetic_logs(args.rules_dir, args.output_dir, args.log_count, mark_all_new=args.mark_all_new)
    except Exception as e:
        print(f"ERROR: {e}")
        raise

if __name__ == "__main__":
    main()
