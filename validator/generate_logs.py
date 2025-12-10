#!/usr/bin/env python3
"""
generate_logs.py (improved)

- Adds _synthetic_id (UUID) to each synthetic log
- Adds _origin: "baseline" or "new" to each log
- Adds _source_rule_id and _logsource to each log
- Attempts safe generation for new rules, skips complex ones
- Writes synthetic_logs_master.jsonl and metadata.json (compatible)
- New: option/heuristics to treat rules in a 'new' rules directory as new (fixes cases where rule id is a UUID)
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from hashlib import sha256
from uuid import uuid4

# Put repo root on path so validator.* imports still work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # your project-specific generator; kept for compatibility
    from validator.validate_rules import EnhancedLogGenerator
    from test import load_sigma_rules
except Exception:
    from validate_rules import EnhancedLogGenerator
    from test import load_sigma_rules


def rule_is_complex(rule: dict) -> bool:
    """Heuristic to decide if rule is too complex to safely synthesize"""
    detection = rule.get("detection", {})
    cond = detection.get("condition", "") if isinstance(detection, dict) else ""

    serialized = json.dumps(detection, default=str)
    # regexes, re: or regexp are risky
    if "re:" in serialized or "regexp" in serialized or "\\d" in serialized or ".*" in serialized:
        return True

    # Too many selection blocks leads to explosion
    if isinstance(detection, dict):
        selection_blocks = [k for k in detection.keys() if k != "condition"]
        if len(selection_blocks) > 4:
            return True

    # Mixed and/or heavy correlation
    if isinstance(cond, str) and (" and " in cond.lower() and " or " in cond.lower()):
        return True

    correlation_keywords = ["near", "sequence", "count", "within", "pipeline"]
    if any(k in str(cond).lower() for k in correlation_keywords):
        return True

    return False


def is_new_rule(rule_id: str) -> bool:
    """Simple new-rule detector (same as your workflow). Update if you use a different convention."""
    if not rule_id:
        return False
    return str(rule_id).startswith("SIG-900") or str(rule_id).upper().startswith("TEST-")


def generate_synthetic_logs(rules_dir: str, output_dir: str, log_count: int = 100, mark_all_new: bool = False):
    rules_path = Path(rules_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"[+] Generating synthetic logs from Sigma rules")
    print(f"    rules_dir: {rules_dir}")
    print(f"    output_dir: {output_dir}")
    print(f"    target log_count (total): {log_count}")

    rule_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
    print(f"[+] Found {len(rule_files)} rule files")

    all_rules = []
    rules_by_id = {}
    rules_metadata = {}

    for rf in rule_files:
        try:
            rules = load_sigma_rules(str(rf))
            for r in rules:
                # Use rule id if present, otherwise synthesize an id from filename
                rid = r.get("id", rf.stem)
                all_rules.append(r)
                rules_by_id[rid] = r
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

    # decide distribution: logs per rule (minimum 10)
    per_rule_default = max(10, log_count // max(1, len(all_rules)))

    all_logs = []
    logs_per_rule = {}

    # Infer whether the rules_dir looks like a 'new' rules directory (heuristic)
    rules_dir_name = rules_path.name.lower()
    heuristically_new_dir = any(x in rules_dir_name for x in ("new", "new_rules", "new_rules_temp", "added"))

    for i, rule in enumerate(all_rules):
        rid = rule.get("id", f"rule_{i}")
        title = rule.get("title", "Untitled")
        detection = rule.get("detection", {})

        print(f"\n[{i+1}/{len(all_rules)}] Processing rule: {title} ({rid})")

        # compute detection hash for metadata
        try:
            rules_metadata[rid]["detection_hash"] = sha256(
                json.dumps(detection, sort_keys=True).encode()
            ).hexdigest()
        except Exception:
            # keep safe - not fatal
            rules_metadata[rid]["detection_hash"] = None

        # determine origin
        # Priority:
        # 1) If caller asked to mark all rules as new (explicit flag)
        # 2) Heuristic based on rules_dir name (e.g., "new_rules_temp")
        # 3) is_new_rule() detection based on rule id/title
        if mark_all_new or heuristically_new_dir:
            origin = "new"
        else:
            origin = "new" if is_new_rule(rid) else "baseline"

        rules_metadata[rid]["origin"] = origin

        # skip generation for complex new rules
        if origin == "new" and rules_metadata[rid].get("complex_rule", False):
            print("  → New rule marked complex: skipping synthetic generation (metadata flagged).")
            logs = []
            rules_metadata[rid]["skipped"] = True
            rules_metadata[rid]["generated_logs"] = 0
            logs_per_rule[rid] = 0
            continue

        # Attempt generation (wrap in try to avoid breaking pipeline)
        try:
            rule_log_count = per_rule_default
            logs = EnhancedLogGenerator.generate_for_sigma_rule(rule, count=rule_log_count) or []
        except Exception as e:
            print(f"  ⚠️ Generation error for {rid}: {e}")
            logs = []
            rules_metadata[rid]["skipped"] = True
            rules_metadata[rid]["generation_error"] = str(e)

        # Tag logs (required fields so downstream code can map alerts -> synthetic logs)
        pos = 0
        neg = 0
        for l in logs:
            # ensure we have a dict
            if not isinstance(l, dict):
                continue
            # unique synthetic id to tie detection -> exact synthetic log
            sid = str(uuid4())
            l["_synthetic_id"] = sid
            # IMPORTANT: ensure origin properly set to "new" for new rules
            l["_origin"] = origin
            l["_source_rule_id"] = rid
            l["_source_rule_title"] = title
            # ensure _logsource exists
            l.setdefault("_logsource", rule.get("logsource", {}))
            # ensure _match_type exists (positive/negative)
            if "_match_type" not in l:
                # guess positive if fields match detection heuristics (keep safe: default positive)
                l["_match_type"] = l.get("_match_type", "positive")
            if l["_match_type"] == "positive":
                pos += 1
            elif l["_match_type"] == "negative":
                neg += 1

        # metadata
        rules_metadata[rid]["positive_count"] = pos
        rules_metadata[rid]["negative_count"] = neg
        rules_metadata[rid]["generated_logs"] = len(logs)
        rules_metadata[rid]["skipped"] = False if logs else rules_metadata[rid]["skipped"]

        all_logs.extend(logs)
        logs_per_rule[rid] = len(logs)

        print(f"  → Generated {len(logs)} logs (pos={pos}, neg={neg}) - origin={origin}")

    # write master jsonl (backwards compatible file name)
    master_file = Path(output_path) / "synthetic_logs_master.jsonl"
    with open(master_file, "w", encoding="utf-8") as f:
        for e in all_logs:
            f.write(json.dumps(e) + "\n")
    print(f"[+] Wrote master logs ({len(all_logs)}) -> {master_file}")

    # Also write a separate "combined" single-line-per-log file to match your workflow
    combined_dir = Path(output_path)
    combined_file = combined_dir / "all_logs.jsonl"
    with open(combined_file, "w", encoding="utf-8") as f:
        for e in all_logs:
            f.write(json.dumps(e) + "\n")

    # metadata
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

    # summary prints (friendly)
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
                        help="Treat all rules in rules-dir as NEW (sets _origin='new'). Useful when rules_dir contains new rules.")
    args = parser.parse_args()

    try:
        generate_synthetic_logs(args.rules_dir, args.output_dir, args.log_count, mark_all_new=args.mark_all_new)
    except Exception as e:
        print(f"ERROR: {e}")
        raise


if __name__ == "__main__":
    main()
