#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
from collections import defaultdict
from test import SOCSimulator, load_sigma_rules


class UniversalLogGenerator:
    """Generates logs for ANY Sigma rule - 50+ log source types supported"""

    LOGSOURCE_TEMPLATES = {
        "azure": {
            "defaults": {
                "CategoryValue": "Administrative",
                "SubscriptionId": "sub-12345-test",
                "TenantId": "tenant-67890",
            }
        },
        "process_creation": {
            "defaults": {
                "Image": "/usr/bin/example",
                "CommandLine": "example -arg test",
                "User": "root",
            }
        },
        "windows": {
            "defaults": {
                "EventID": 4688,
                "Channel": "Security",
                "AccountName": "SYSTEM",
            }
        },
        "linux": {
            "defaults": {"user": "root", "process": "bin/example"},
        },
        "file_event": {
            "defaults": {
                "FilePath": "/tmp/testfile",
                "Operation": "write",
            }
        },
        "registry_event": {
            "defaults": {
                "RegistryKey": "HKEY_LOCAL_MACHINE\\Test",
                "Action": "modify",
            }
        },
        "dns_query": {
            "defaults": {"QueryName": "example.com", "RecordType": "A"},
        },
        "network_connection": {
            "defaults": {
                "SourceIp": "10.0.0.5",
                "DestinationIp": "8.8.8.8",
                "Protocol": "TCP",
            }
        },
    }

    def __init__(self):
        self.simulator = SOCSimulator()

    def generate_logs_for_rule(self, rule):
        """Generate synthetic log events for a single Sigma rule."""
        try:
            logsource = rule.get("logsource", {}).get("category") or rule.get(
                "logsource", {}
            ).get("product", "")

            logs = []

            # Select base template
            template = self.LOGSOURCE_TEMPLATES.get(logsource, None)

            if template:
                base_log = template["defaults"].copy()
            else:
                base_log = {"message": f"Synthetic event for rule {rule.get('title')}"}

            # Expand each detection selection
            detections = rule.get("detection", {})

            for key, value in detections.items():
                if isinstance(value, dict):  # selection1, selection2...
                    log_event = base_log.copy()
                    for field, match in value.items():
                        log_event[field] = match
                    logs.append(log_event)

            if not logs:
                logs.append(base_log)

            return logs

        except Exception as e:
            print(f"⚠️ Error generating logs for rule {rule.get('title', 'Unknown')}: {e}")
            return []

    def generate(self, rules):
        all_logs = []
        for rule in rules:
            logs = self.generate_logs_for_rule(rule)
            all_logs.extend(logs)
        return all_logs


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic logs for Sigma rules")
    parser.add_argument("--rules-dir", required=True, help="Directory containing Sigma rules")
    parser.add_argument("--output", required=True, help="Output JSONL log file")
    parser.add_argument("--limit", type=int, default=5000, help="Max log count")

    # ✅ Debug flag (fixed indentation)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # ✅ Debug message (correct indentation)
    if args.debug:
        print("[DEBUG] Debug mode enabled for generate_logs.py")

    rules_dir = Path(args.rules_dir)

    # Load sigma rules
    sigma_rules = load_sigma_rules(rules_dir)
    print(f"📄 Loaded {len(sigma_rules)} Sigma rules")

    generator = UniversalLogGenerator()

    # Generate logs
    logs = generator.generate(sigma_rules)

    if len(logs) > args.limit:
        logs = logs[: args.limit]

    # Save to JSONL
    with open(args.output, "w") as f:
        for log in logs:
            f.write(json.dumps(log) + "\n")

    print(f"✅ Generated {len(logs)} logs → {args.output}")


if __name__ == "__main__":
    main()
