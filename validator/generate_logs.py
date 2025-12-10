#!/usr/bin/env python3
"""
Generate synthetic logs from Sigma rules for testing (robusted imports)

This script:
 - Loads Sigma rules from a rules directory (YAML files)
 - Uses the project's EnhancedLogGenerator to create synthetic logs
 - Writes master JSONL and metadata files to output directory
 - Avoids importing stdlib `test` by ensuring repo root is first on sys.path
 - Supports --debug for verbose output
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Ensure repo root is on sys.path so we import project-local modules (not stdlib 'test')
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Try imports in an order that prefers package layout if available
try:
    # Prefer package import (validator.validate_rules)
    from validator.validate_rules import EnhancedLogGenerator
except Exception:
    # Fallback to top-level module
    try:
        from validate_rules import EnhancedLogGenerator  # type: ignore
    except Exception:
        EnhancedLogGenerator = None

# load_sigma_rules usually lives in repo root test.py
try:
    # Prefer top-level repo test.py
    import importlib

    test_mod = importlib.import_module("test")
    load_sigma_rules = getattr(test_mod, "load_sigma_rules")
except Exception:
    # Fallback: try validator.test
    try:
        test_mod = importlib.import_module("validator.test")
        load_sigma_rules = getattr(test_mod, "load_sigma_rules")
    except Exception:
        load_sigma_rules = None

if EnhancedLogGenerator is None or load_sigma_rules is None:
    missing = []
    if EnhancedLogGenerator is None:
        missing.append("EnhancedLogGenerator (from validate_rules)")
    if load_sigma_rules is None:
        missing.append("load_sigma_rules (from test.py)")
    raise ImportError(
        "Missing project imports: {}. Ensure 'validate_rules.py' and 'test.py' exist in the repo root "
        "or 'validator' package and define these symbols.".format(", ".join(missing))
    )


def is_new_rule(rule_id: str) -> bool:
    """
    Heuristic for marking a rule as 'new' (no synthetic logs).
    Adjust this as needed for your workflow.
    """
    if not isinstance(rule_id, str):
        return False
    return rule_id.startswith("SIG-900") or rule_id.lower().startswith("new-")


def generate_synthetic_logs(rules_dir: str, output_dir: str, log_count: int = 100, debug: bool = False):
    rules_path = Path(rules_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if debug:
        print(f"[DEBUG] rules_dir={rules_dir}")
        print(f"[DEBUG] output_dir={output_dir}")
        print(f"[DEBUG] log_count={log_count}")

    print(f"\n[+] Generating synthetic logs from Sigma rules")
    print(f"    Rules directory: {rules_dir}")
    print(f"    Output directory: {output_dir}")
    print(f"    Logs per rule (target): {log_count}")

    # Collect rule files
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
                rule_metadata[rule_id] = {
                    "path": str(rule_file),
                    "title": rule.get("title", "Untitled"),
                    "id": rule_id,
                }
        except Exception as e:
            print(f"    ⚠️ Error loading {rule_file}: {e}")
            if debug:
                import traceback
                traceback.print_exc()

    print(f"[+] Successfully loaded {len(all_rules)} rules")

    # Generation loop
    all_logs = []
    logs_per_rule = {}

    print(f"\n[+] Generating synthetic logs...")

    total_rules = max(1, len(all_rules))
    for i, rule in enumerate(all_rules):
        rule_id = rule.get("id", f"rule_{i}")
        rule_title = rule.get("title", "Untitled")
        if debug:
            print(f"[DEBUG] Processing rule {i+1}/{total_rules}: {rule_title} ({rule_id})")

        try:
            # Distribute requested logs (avoid huge per-rule counts)
            rule_log_count = max(10, int(log_count // total_rules))

            # DO NOT GENERATE LOGS FOR NEW RULES (heuristic)
            if is_new_rule(str(rule_id)):
                if debug:
                    print(f"    → Skipping synthetic log generation for new rule: {rule_id}")
                logs = []
            else:
                # Use the project's EnhancedLogGenerator to create logs
                logs = EnhancedLogGenerator.generate_for_sigma_rule(rule, count=rule_log_count) or []

            # Annotate logs with source metadata
            for log in logs:
                log["_source_rule_id"] = rule_id
                log["_source_rule_title"] = rule_title

            all_logs.extend(logs)
            logs_per_rule[rule_id] = len(logs)

            print(f"    [{i+1}/{total_rules}] {rule_title} ({rule_id}) → Generated {len(logs)} logs")
        except Exception as e:
            print(f"        ⚠️ Error generating logs for {rule_title}: {e}")
            if debug:
                import traceback
                traceback.print_exc()
            logs_per_rule[rule_id] = 0
            continue

    print(f"\n[+] Generated {len(all_logs)} total synthetic log events")

    # Save master log file (JSONL)
    master_log_file = output_path / "synthetic_logs_master.jsonl"
    with open(master_log_file, "w", encoding="utf-8") as f:
        for log in all_logs:
            f.write(json.dumps(log) + "\n")
    print(f"[+] Saved master log file: {master_log_file}")

    # Also save a simple one-file named "synthetic_logs.jsonl" for CI steps that expect this path
    simple_log_file = output_path / "synthetic_logs.jsonl"
    with open(simple_log_file, "w", encoding="utf-8") as f:
        for log in all_logs:
            f.write(json.dumps(log) + "\n")
    if debug:
        print(f"[DEBUG] Also wrote simple logs file: {simple_log_file}")

    # Save metadata
    metadata = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_logs": len(all_logs),
        "total_rules": len(all_rules),
        "logs_per_rule": logs_per_rule,
        "rules_metadata": rule_metadata,
    }

    metadata_file = output_path / "metadata.json"
    with open(metadata_file, "w", encoding="utf-8") as f:
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
    parser.add_argument("--output-dir", required=True, help="Directory to write synthetic logs and metadata")
    parser.add_argument("--log-count", type=int, default=100, help="Target total logs (approx)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    generate_synthetic_logs(args.rules_dir, args.output_dir, log_count=args.log_count, debug=args.debug)


if __name__ == "__main__":
    main()
