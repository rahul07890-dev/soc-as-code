#!/usr/bin/env python3
"""
Generate synthetic logs from Sigma rules for testing
Fully fixed version:
 - Prevents synthetic detections for new rules
 - Ensures new rules produce zero logs unless they truly match
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Import the log generator from validate_rules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from validator.validate_rules import EnhancedLogGenerator
    from test import load_sigma_rules
except ImportError:
    from validate_rules import EnhancedLogGenerator
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from test import load_sigma_rules


def generate_synthetic_logs(rules_dir: str, output_dir: str, log_count: int = 100):
    rules_path = Path(rules_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"\n[+] Generating synthetic logs from Sigma rules")
    print(f"    Rules directory: {rules_dir}")
    print(f"    Output directory: {output_dir}")
    print(f"    Logs per rule: {log_count}")

    # Load all rule files
    rule_files = list(rules_path.rglob('*.yml')) + list(rules_path.rglob('*.yaml'))
    print(f"\n[+] Found {len(rule_files)} Sigma rule files")

    all_rules = []
    rule_metadata = {}

    for rule_file in rule_files:
        try:
            rules = load_sigma_rules(str(rule_file))
            for rule in rules:
                rule_id = rule.get('id', rule_file.stem)
                all_rules.append(rule)
                rule_metadata[rule_id] = {
                    "path": str(rule_file),
                    "title": rule.get("title", "Untitled"),
                    "id": rule_id,
                }
        except Exception as e:
            print(f"    ⚠️ Error loading {rule_file}: {e}")

    print(f"[+] Successfully loaded {len(all_rules)} rules")

    # Detect NEW rules by checking if they're prefixed with "SIG-900"
    # You can change this to ANY detection logic if needed.
    def is_new_rule(rule_id: str) -> bool:
        return rule_id.startswith("SIG-900")

    # Begin generation
    all_logs = []
    logs_per_rule = {}

    print(f"\n[+] Generating synthetic logs...")

    for i, rule in enumerate(all_rules):
        rule_id = rule.get("id", f"rule_{i}")
        rule_title = rule.get("title", "Untitled")

        print(f"    [{i+1}/{len(all_rules)}] Processing: {rule_title} ({rule_id})")

        try:
            # Distribute logs evenly (for OLD rules only)
            rule_log_count = max(10, log_count // len(all_rules))

            # -------------------------------
            # 🚨 FIX: DO NOT GENERATE LOGS FOR NEW RULES
            # -------------------------------
            if is_new_rule(rule_id):
                print(f"        → New rule detected. Synthetic logs disabled.")
                logs = []
            else:
                logs = EnhancedLogGenerator.generate_for_sigma_rule(
                    rule, count=rule_log_count
                )

            # Tag (only if logs exist)
            for log in logs:
                log["_source_rule_id"] = rule_id
                log["_source_rule_title"] = rule_title

            all_logs.extend(logs)
            logs_per_rule[rule_id] = len(logs)

            print(f"        Generated {len(logs)} logs")

        except Exception as e:
            print(f"        ⚠️ Error generating logs for {rule_title}: {e}")
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
