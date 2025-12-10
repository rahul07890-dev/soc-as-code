#!/usr/bin/env python3
"""
validate_rules.py

Lightweight Sigma/YAML rule validator used by the SOC-as-Code pipeline.

Features:
- Validate all rules in a directory, or a comma-separated list of changed rules.
- Checks for presence of common keys: id, title, logsource, detection.
- Optional --debug flag to print extra information in CI.
- Exits with code 0 on success, 1 on any validation errors (good for CI).
"""

import argparse
import sys
import yaml
from pathlib import Path
from typing import List, Dict, Tuple


REQUIRED_TOP_LEVEL_KEYS = ["id", "title", "logsource", "detection"]


def load_yaml(path: Path) -> Tuple[bool, Dict]:
    """Load YAML and return (success, data_or_error)"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return True, data
    except Exception as e:
        return False, {"error": str(e)}


def validate_rule_structure(data: Dict, path: Path) -> List[str]:
    """Return a list of validation error strings (empty if ok)"""
    errors = []

    if not isinstance(data, dict):
        errors.append("Rule file does not contain a YAML mapping at top level.")
        return errors

    for k in REQUIRED_TOP_LEVEL_KEYS:
        if k not in data:
            errors.append(f"Missing required key: '{k}'")

    # logsource should contain either category or product
    logsource = data.get("logsource")
    if isinstance(logsource, dict):
        if not (logsource.get("category") or logsource.get("product")):
            errors.append("logsource must include at least 'category' or 'product' field.")
    else:
        errors.append("logsource must be a mapping with 'category' or 'product'.")

    # detection should be a mapping with at least one selection
    detection = data.get("detection")
    if not isinstance(detection, dict) or len(detection) == 0:
        errors.append("detection must be a mapping with at least one selection block.")

    # optional: id should be non-empty string
    rid = data.get("id")
    if rid is None or (isinstance(rid, str) and rid.strip() == ""):
        errors.append("id is empty or missing.")

    # optional: title should be non-empty
    title = data.get("title")
    if title is None or (isinstance(title, str) and title.strip() == ""):
        errors.append("title is empty or missing.")

    return errors


def collect_rule_paths(rules_dir: Path, changed_list: List[str]) -> List[Path]:
    """Return list of rule paths to validate. If changed_list provided, resolve them."""
    if changed_list:
        # Accept absolute paths or paths relative to repo root (rules_dir parent)
        resolved = []
        for r in changed_list:
            p = Path(r)
            if not p.is_absolute():
                # try relative to rules_dir (and to current working dir)
                candidate = rules_dir / p
                if candidate.exists():
                    resolved.append(candidate)
                else:
                    rwd = Path.cwd() / p
                    if rwd.exists():
                        resolved.append(rwd)
                    else:
                        # Try as-is (maybe user provided full path)
                        if p.exists():
                            resolved.append(p)
                        else:
                            # keep as Path for error reporting; will fail load later
                            resolved.append(p)
            else:
                resolved.append(p)
        return resolved
    else:
        # walk rules_dir and include .yml/.yaml files
        if not rules_dir.exists():
            return []
        return sorted([p for p in rules_dir.rglob("*.yml")] + [p for p in rules_dir.rglob("*.yaml")])


def main():
    parser = argparse.ArgumentParser(description="Validate Sigma YAML rule files")
    parser.add_argument("--rules-dir", default="rules/sigma", help="Directory containing sigma rules")
    parser.add_argument(
        "--changed-sigma-rules",
        default="",
        help="Comma-separated list of changed rule paths (relative or absolute). If empty, validates all rules in --rules-dir",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        print("[DEBUG] Debug mode enabled for validate_rules.py")
        print(f"[DEBUG] rules_dir={args.rules_dir}")
        print(f"[DEBUG] changed_sigma_rules={args.changed_sigma_rules}")

    rules_dir = Path(args.rules_dir)

    changed_list = [s.strip() for s in args.changed_sigma_rules.split(",") if s.strip()]
    rule_paths = collect_rule_paths(rules_dir, changed_list)

    if not rule_paths:
        if changed_list:
            print("❌ No rule files found for the provided changed paths.")
            sys.exit(1)
        else:
            print(f"⚠️ No rule files found in {rules_dir}")
            sys.exit(1)

    total = 0
    failures = 0
    detailed_errors = []

    for rp in rule_paths:
        total += 1
        if args.debug:
            print(f"[DEBUG] Validating {rp}")
        ok, data_or_err = load_yaml(rp)
        if not ok:
            failures += 1
            err = data_or_err.get("error", "Unknown YAML load error")
            detailed_errors.append((str(rp), f"YAML_PARSE_ERROR: {err}"))
            if args.debug:
                print(f"[DEBUG] YAML load failed for {rp}: {err}")
            continue

        data = data_or_err
        errs = validate_rule_structure(data, rp)
        if errs:
            failures += 1
            detailed_errors.append((str(rp), "; ".join(errs)))
            if args.debug:
                print(f"[DEBUG] Validation errors for {rp}: {errs}")

    # Summary
    print("\n" + "=" * 60)
    print(f"Validated rules: {total}")
    if failures == 0:
        print("✅ All rules passed basic validation.")
    else:
        print(f"❌ Failed rules: {failures}")
        print("\nDetails:")
        for path, msg in detailed_errors:
            print(f" - {path}: {msg}")

    # Exit code: non-zero if any failures
    if failures > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
