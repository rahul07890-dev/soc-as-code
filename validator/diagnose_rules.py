#!/usr/bin/env python3
"""
diagnose_rules.py

Diagnose a single Sigma YAML rule file.

Behavior:
- Loads the YAML file and checks for parse errors.
- Runs a set of common structural and semantic checks:
  - required top-level keys (id, title, logsource, detection)
  - logsource contains 'category' or 'product'
  - detection is a mapping with at least one selection
  - checks for suspicious field names (common typos)
- Prints clear suggestions via suggest_fixes() when issues are found.
- Returns exit code 0 when rule passes basic diagnostics, 1 otherwise.

Usage:
    python diagnose_rules.py /path/to/rule.yml [--debug]
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import yaml
import re

REQUIRED_KEYS = ["id", "title", "logsource", "detection"]
COMMON_FIELD_NAME_HINTS = {
    "ProcessName": ["processname", "process_name", "Process_Name"],
    "CommandLine": ["commandline", "command_line", "cmdline"],
    "Image": ["image", "file_name", "exe"],
    "SourceIp": ["src_ip", "source_ip", "SourceIP"],
    "DestinationIp": ["dst_ip", "dest_ip", "destination_ip"],
}


def load_yaml(path: Path) -> Tuple[bool, Dict]:
    """Load YAML rule file. Returns (ok, data_or_error_dict)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return True, data
    except Exception as e:
        return False, {"error": str(e)}


def find_similar_field(wrong: str, candidates: List[str]) -> List[str]:
    """Return candidate names that look similar to 'wrong' (case-insensitive substring match)."""
    wrong_l = wrong.lower()
    matches = []
    for c in candidates:
        if wrong_l in c.lower() or c.lower() in wrong_l:
            matches.append(c)
    return matches


def basic_checks(data: Dict, path: Path, debug: bool = False) -> List[str]:
    """Run basic checks and return a list of error messages (empty if no errors)."""
    errors = []

    if not isinstance(data, dict):
        errors.append("Top-level YAML is not a mapping/dictionary.")
        return errors

    # Required keys
    for k in REQUIRED_KEYS:
        if k not in data:
            errors.append(f"Missing required top-level key: '{k}'")

    # logsource checks
    logsource = data.get("logsource")
    if isinstance(logsource, dict):
        if not (logsource.get("category") or logsource.get("product")):
            errors.append("logsource found but missing both 'category' and 'product'.")
    else:
        errors.append("logsource must be a mapping with 'category' or 'product'.")

    # detection checks
    detection = data.get("detection")
    if not isinstance(detection, dict) or len(detection) == 0:
        errors.append("detection must be a mapping with at least one selection block.")

    # verify each selection block looks like a mapping of fields -> values
    if isinstance(detection, dict):
        for sel_name, sel_body in detection.items():
            if sel_name.lower() in ("condition", "timeframe"):
                # skip non-selection keys some authors add
                continue
            if not isinstance(sel_body, dict):
                errors.append(f"detection selection '{sel_name}' is not a mapping.")
            else:
                # look for suspicious field names
                for field in sel_body.keys():
                    if not isinstance(field, str):
                        continue
                    # crude check: fields that look like integers are suspicious
                    if re.fullmatch(r"\d+", field):
                        errors.append(f"Field name '{field}' in selection '{sel_name}' looks like a numeric key (typo?).")

                    # check against common hints
                    for canonical, hints in COMMON_FIELD_NAME_HINTS.items():
                        for hint in hints:
                            if field.lower() == hint.lower():
                                errors.append(
                                    f"Field name '{field}' in selection '{sel_name}' may be a typo. Did you mean '{canonical}'?"
                                )

    # optional: id/title non-empty
    rid = data.get("id")
    if rid is None or (isinstance(rid, str) and rid.strip() == ""):
        errors.append("Rule 'id' is missing or empty.")

    title = data.get("title")
    if title is None or (isinstance(title, str) and title.strip() == ""):
        errors.append("Rule 'title' is missing or empty.")

    if debug:
        print(f"[DEBUG] basic_checks: found {len(errors)} issues for {path}")

    return errors


def suggest_fixes(path: Path, errors: List[str]) -> None:
    """Print actionable suggestions based on found errors."""
    print("\nSuggestions & possible fixes:")
    for err in errors:
        print(f" - {err}")
        # heuristic suggestions
        if "Missing required top-level key" in err:
            missing = re.findall(r"'([^']+)'", err)
            if missing:
                k = missing[0]
                if k == "logsource":
                    print("   -> Add a 'logsource' mapping with at least 'category' or 'product'. Example:\n      logsource:\n        category: process\n        product: windows")
                elif k == "detection":
                    print("   -> Add a 'detection' block with named selections (selection1, selection2). Example:\n      detection:\n        selection1:\n          ProcessName: suspicious.exe\n        condition: selection1")
                elif k == "id":
                    print("   -> Add a unique 'id' field (e.g. SIG-2025-0001).")
                elif k == "title":
                    print("   -> Add a human-friendly 'title' field describing the detection.")
        if "may be a typo" in err:
            m = re.search(r"Did you mean '([^']+)'", err)
            if m:
                print(f"   -> Consider renaming the field to '{m.group(1)}' (or map fields in your ingestion).")
        if "Top-level YAML is not a mapping" in err:
            print("   -> Ensure the rule file contains a YAML mapping (key: value pairs) at the top level, not a list.")
        if "yaml" in err.lower() or "parse" in err.lower():
            print("   -> Check YAML syntax: proper indentation, colons, and quoting; run 'yamllint' if available.")
        if "numeric key" in err:
            print("   -> Replace numeric keys with proper field names (e.g., ProcessName, CommandLine).")

    print("\nRun 'validate_rules.py --changed-sigma-rules <this-file>' for a quick re-check after edits.")


def diagnose_rule(path: Path, debug: bool = False) -> bool:
    """Load and run diagnostics on a single rule file. Returns True if passes, False otherwise."""
    ok, data_or_err = load_yaml(path)
    if not ok:
        err = data_or_err.get("error", "Unknown error while parsing YAML")
        print(f"❌ YAML parse error in {path}: {err}")
        if debug:
            print(f"[DEBUG] full parse error: {err}")
        return False

    data = data_or_err
    errors = basic_checks(data, path, debug=debug)

    if errors:
        print(f"\n❌ DIAGNOSIS: {len(errors)} issue(s) found in {path}")
        suggest_fixes(path, errors)
        return False

    # Passed checks
    print(f"\n✅ DIAGNOSIS OK: {path} passed basic diagnostics")
    # Extra helpful output: show top-level id/title/logsource summary
    rid = data.get("id", "")
    title = data.get("title", "")
    logsource = data.get("logsource", {})
    print(f" - id: {rid}")
    print(f" - title: {title}")
    if isinstance(logsource, dict):
        print(f" - logsource: {logsource}")
    else:
        print(" - logsource: (unexpected format)")

    # Optionally show detection summary
    det = data.get("detection", {})
    if isinstance(det, dict):
        selections = [k for k in det.keys() if k.lower() != "condition"]
        print(f" - selection blocks: {len(selections)} ({', '.join(selections)})" if selections else " - selection blocks: 0")

    return True


def main():
    parser = argparse.ArgumentParser(description="Diagnose a single Sigma rule file")
    parser.add_argument("rule_path", help="Path to the Sigma YAML rule file to diagnose")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    rule_path = Path(args.rule_path)

    if args.debug:
        print("[DEBUG] Debug mode enabled for diagnose_rules.py")
        print(f"[DEBUG] rule_path={rule_path}")

    if not rule_path.exists():
        print(f"❌ ERROR: Rule file not found: {rule_path}")
        sys.exit(1)

    ok = diagnose_rule(rule_path, debug=args.debug)

    if not ok:
        print("\nExiting with failure (1) — fix the issues above and re-run.")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
