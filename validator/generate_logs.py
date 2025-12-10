#!/usr/bin/env python3
"""
Generate synthetic logs from Sigma rules for testing.

Improved Version:
 - Safe generation for new rules (attempt only if rule is simple enough)
 - Prevents synthetic detections for new rules when rule is too complex
 - Adds deeper metadata to support classification later
 - Computes detection hash for change detection
 - Tracks rule complexity
 - Tracks generation errors
 - Adds _logsource to logs
 - Does not break any existing CI workflow behavior
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from hashlib import sha256

# Import the log generator from validate_rules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from validator.validate_rules import EnhancedLogGenerator
    from test import load_sigma_rules
except ImportError:
    from validate_rules import EnhancedLogGenerator
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from test import load_sigma_rules


# -------------------------------------------------------------------------
# Utility: Detect whether rule is too complex for synthetic generation
# -------------------------------------------------------------------------
def rule_is_complex(rule: dict) -> bool:
    """
    A rule is considered complex if:
      - It has regex operators
      - It contains more than 3 selection blocks
      - It uses nested OR conditions
      - It uses lists inside lists
      - It uses correlation keywords (near, count, sequence)
    """
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")

    # Regex operator is typically too hard to synthesize properly
    serialized = json.dumps(detection, default=str)
    if "regexp" in serialized or "re:" in serialized:
        return True

    # Too many selections?
    if isinstance(detection, dict):
        selection_blocks = [k for k in detection.keys() if k.startswith("selection")]
        if len(selection_blocks) > 3:
            return True

    # Nested ORs make combination explosion
    if " or " in condition.lower() and " and " in condition.lower():
        return True

    # Correlation keywords
    correlation_keywords = ["near", "sequence", "count", "within", "pipeline"]
    if any(x in condition.lower() for x in correlation_keywords):
        return True

    return False


# -------------------------------------------------------------------------
# MAIN SYNTHETIC LOG GEN FUNCTION
# -------------------------------------------------------------------------
def generate_synthetic_logs(rules_dir: str, output_dir: str, log_count: int = 100):
    rules_path = Path(rules_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"\n[+] Generating synthetic logs from Sigma rules")
    print(f"    Rules directory: {rules_dir}")
    print(f"    Output directory: {output_dir}")
    print(f"    Logs per rule: {log_count}")

    # Load all rule files
    rule_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
    print(f"\n[+] Found {len(rule_files)} Sigma rule files")

    all_rules = []
    rule_metadata = {}

    for rule_file in rule_files:
        try:
            rules = load_sigma_rules(str(rule_file))
            for rule in rules:
                rule_id = rule.get("id", rule_file.stem)
                all_rules.append(rule)

                # Store base metadata
                rule_metadata[rule_id] = {
                    "path": str(rule_file),
                    "title": rule.get("title", "Untitled"),
                    "id": rule_id,
                    "skipped": False,
                    "generation_error": None,
                    "complex_rule": rule_is_complex(rule),
                }
        except Exception as e:
            print(f"    ⚠️ Error loading {rule_file}: {e}")

    print(f"[+] Successfully loaded {len(all_rules)} rules")

    if len(all_rules) == 0:
        print("⚠️ No rules found. Exiting.")
        return {}

    # Logic to classify new rules
    def is_new_rule(rule_id: str) -> bool:
        return rule_id.startswith("SIG-900")

    # Begin generation
    all_logs = []
    logs_per_rule = {}

    print(f"\n[+] Generating synthetic logs...")

    for i, rule in enumerate(all_rules):
        rule_id     = rule.get("id", f"rule_{i}")
        rule_title  = rule.get("title", "Untitled")
        detection   = rule.get("detection", {})

        print(f"    [{i+1}/{len(all_rules)}] Processing: {rule_title} ({rule_id})")

        try:
            rule_log_count = max(10, log_count // len(all_rules))

            # Compute detection hash (helps compare rule changes)
            rule_metadata[rule_id]["detection_hash"] = sha256(
                json.dumps(detection, sort_keys=True).encode()
            ).hexdigest()

            # NEW RULE HANDLING LOGIC:
            # --------------------------------------------------------------
            # OPTION A — New rule but complex → SKIP
            # OPTION B — New rule & simple → try generating logs
            # --------------------------------------------------------------
            if is_new_rule(rule_id):
                if rule_metadata[rule_id]["complex_rule"]:
                    print(f"        → New rule is too complex. Synthetic logs disabled.")
                    logs = []
                    rule_metadata[rule_id]["skipped"] = True
                else:
                    print(f"        → New rule is simple. Attempting safe generation...")
                    try:
                        logs = EnhancedLogGenerator.generate_for_sigma_rule(
                            rule, count=rule_log_count
                        )
                    except Exception as gen_err:
                        print(f"        → Generation failed. Rule will be skipped: {gen_err}")
                        logs = []
                        rule_metadata[rule_id]["skipped"] = True
                        rule_metadata[rule_id]["generation_error"] = str(gen_err)

            # OLD RULE HANDLING
            else:
                logs = EnhancedLogGenerator.generate_for_sigma_rule(rule, count=rule_log_count)

            # Tag logs
            for log in logs:
                log["_source_rule_id"]    = rule_id
                log["_source_rule_title"] = rule_title
                log["_logsource"]         = rule.get("logsource", {})

            # Attach positive/negative summary
            positives = sum(1 for l in logs if l.get("_match_type") == "positive")
            negatives = sum(1 for l in logs if l.get("_match_type") == "negative")

            rule_metadata[rule_id]["positive_count"] = positives
            rule_metadata[rule_id]["negative_count"] = negatives
            rule_metadata[rule_id]["generated_logs"] = len(logs)

            all_logs.extend(logs)
            logs_per_rule[rule_id] = len(logs)

            print(f"        Generated {len(logs)} logs (Pos: {positives}, Neg: {negatives})")

        except Exception as e:
            print(f"        ⚠️ Error generating logs for {rule_title}: {e}")
            rule_metadata[rule_id]["generation_error"] = str(e)
            rule_metadata[rule_id]["generated_logs"]   = 0
            continue

    print(f"\n[+] Generated {len(all_logs)} total synthetic log events")

    # Save master log file
    master_log_file = output_path / "synthetic_logs_master.jsonl"
    with open(master_log_file, "w") as f:
        for log in all_logs:
            f.write(json.dumps(log) + "\n")

    print(f"[+] Saved master log file: {master_log_file}")

    # Save metadata
    metadata = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_logs": len(all_logs),
        "total_rules": len(all_rules),
        "logs_per_rule": logs_per_rule,
        "rules_metadata": rule_metadata,
    }

    metadata_file = output_path / "metadata.json"
    with open(metadata_file, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Saved metadata: {metadata_file}")

    # Summary
    positive_logs = sum(1 for log in all_logs if log.get("_match_type") == "positive")
    negative_logs = sum(1 for log in all_logs if log.get("_match_type") == "negative")

    print("\n" + "=" * 60)
    print("SYNTHETIC LOG GENERATION SUMMARY")
    print("=" * 60)
    print(f"Total rules processed: {len(all_rules)}")
    print(f"Total logs generated: {len(all_logs)}")
    print(f"  • Positive (should match): {positive_logs}")
    print(f"  • Negative (should not): {negative_logs}")
    print("=" * 60)

    return metadata


# -------------------------------------------------------------------------
# MAIN ENTRYPOINT
# -------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Generate synthetic logs from Sigma rules")
    parser.add_argument("--rules-dir", required=True, help="Directory containing Sigma rules")
    parser.add_argument("--output-dir", required=True, help="Output directory for synthetic logs")
    parser.add_argument("--log-count", type=int, default=100, help="Total logs to generate")

    args = parser.parse_args()

    try:
        generate_synthetic_logs(args.rules_dir, args.output_dir, args.log_count)
        print("\n✅ Synthetic log generation completed successfully")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error generating synthetic logs: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
