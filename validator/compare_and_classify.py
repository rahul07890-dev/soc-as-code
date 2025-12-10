#!/usr/bin/env python3
"""
DELTA-BASED CLASSIFICATION
Compares total detection counts between baseline (old rules) and current (old + new rules)
Classification based on the DIFFERENCE in detection counts
"""

import argparse
import json
import yaml
from pathlib import Path
from typing import Dict, List
from collections import defaultdict


class DeltaBasedClassifier:
    """
    Simplified classifier that uses detection count deltas instead of rule ID matching

    Logic:
    1. Baseline detections = running OLD rules only
    2. Current detections = running OLD + NEW rules
    3. Delta = Current - Baseline = contribution of new rules
    4. Classification based on delta magnitude
    """

    def __init__(self, baseline_dir: Path, current_dir: Path, rules_dir: Path):
        self.baseline_dir = baseline_dir
        self.current_dir = current_dir
        self.rules_dir = rules_dir

        # Load detection counts
        self.baseline_detections = self._load_detections(baseline_dir)
        self.current_detections = self._load_detections(current_dir)

        # Calculate totals
        self.baseline_total = len(self.baseline_detections)
        self.current_total = len(self.current_detections)
        self.total_delta = self.current_total - self.baseline_total

        print("\n📊 DELTA-BASED DETECTION ANALYSIS:")
        print(f"   Baseline (old rules only): {self.baseline_total} detections")
        print(f"   Current (old + new rules): {self.current_total} detections")
        print(f"   Total Delta: {self.total_delta:+d} detections")

        if self.total_delta > 0:
            print(f"   ✅ New rules added {self.total_delta} detections")
        elif self.total_delta == 0:
            print("   ⚠️ No new detections from new rules")
        else:
            print("   ❌ Negative delta - something is wrong!")

    def _load_detections(self, results_dir: Path) -> List[Dict]:
        """Load detections from results directory"""
        detections_file = results_dir / "detections.json"
        if detections_file.exists():
            with open(detections_file, "r") as f:
                data = json.load(f)
                print(f"   Loaded {len(data)} detections from {detections_file}")
                return data
        print(f"   ⚠️ No detections file found at {detections_file}")
        return []

    def _extract_rule_info_from_yaml(self, rule_path: str) -> Dict[str, str]:
        """Extract rule ID and title from YAML file"""
        result = {"id": None, "title": None, "filename": Path(rule_path).stem}

        try:
            with open(rule_path, "r") as f:
                rule_data = yaml.safe_load(f)

                if rule_data:
                    if "id" in rule_data:
                        result["id"] = str(rule_data["id"]).strip()

                    if "title" in rule_data:
                        result["title"] = str(rule_data["title"]).strip()

        except Exception as e:
            print(f"   ⚠️ Error reading YAML: {e}")

        return result

    def classify_new_rules(self, new_rule_paths: List[str], total_new_rules: int) -> Dict:
        print("\n" + "=" * 70)
        print(f"🔍 CLASSIFYING {total_new_rules} NEW RULES")
        print("=" * 70)

        if total_new_rules == 0:
            print("   ⚠️ No new rules to classify")
            return {
                "summary": {"total_rules": 0, "by_grade": {}, "average_score": 0},
                "rules": [],
            }

        avg_delta_per_rule = self.total_delta / total_new_rules

        print("\n   📊 Delta Analysis:")
        print(f"      Total delta: {self.total_delta}")
        print(f"      New rules: {total_new_rules}")
        print(f"      Avg delta per rule: {avg_delta_per_rule:.1f}")

        score, grade, reasoning = self._classify_by_delta(avg_delta_per_rule, self.total_delta)

        print(f"\n   🎯 Classification: {grade} (Score: {score}/100)")
        print(f"   📝 Reasoning: {reasoning}")

        classifications = []

        for rule_path in new_rule_paths:
            rule_info = self._extract_rule_info_from_yaml(rule_path)

            classification = {
                "rule_name": rule_info["filename"],
                "rule_path": rule_path,
                "rule_id": rule_info["id"],
                "rule_title": rule_info["title"],
                "classification": grade,
                "score": score,
                "reasoning": reasoning,
                "triggered": self.total_delta > 0,
                "detection_count": round(avg_delta_per_rule),
                "metrics": {
                    "baseline_total": self.baseline_total,
                    "current_total": self.current_total,
                    "total_delta": self.total_delta,
                    "avg_delta_per_rule": round(avg_delta_per_rule, 2),
                    "total_new_rules": total_new_rules,
                },
            }

            classifications.append(classification)

            print(f"\n   📄 {rule_info['filename']}")
            print(f"      ID: {rule_info['id']}")
            print(f"      Title: {rule_info['title']}")
            print(f"      Estimated contribution: ~{round(avg_delta_per_rule)} detections")

        grade_counts = {grade: total_new_rules}

        report = {
            "summary": {
                "total_rules": total_new_rules,
                "by_grade": grade_counts,
                "average_score": score,
                "total_delta": self.total_delta,
                "baseline_detections": self.baseline_total,
                "current_detections": self.current_total,
                "classification_method": "delta_based",
            },
            "rules": classifications,
        }

        return report

    def _classify_by_delta(self, avg_delta: float, total_delta: int) -> tuple:
        if avg_delta >= 50:
            return (
                95,
                "STRONG",
                f"Excellent! New rules added {total_delta} detections (~{avg_delta:.0f} per rule).",
            )

        if avg_delta >= 30:
            return (
                85,
                "STRONG",
                f"Strong performance with {total_delta} detections (~{avg_delta:.0f} per rule).",
            )

        if avg_delta >= 20:
            return (
                75,
                "STRONG",
                f"Good detection increase: {total_delta} detections (~{avg_delta:.0f} per rule).",
            )

        if avg_delta >= 10:
            return (
                65,
                "STRONG",
                f"Decent improvement: {total_delta} detections (~{avg_delta:.0f} per rule).",
            )

        if avg_delta >= 5:
            return (
                55,
                "NEUTRAL",
                f"Moderate increase: {total_delta} detections (~{avg_delta:.0f} per rule).",
            )

        if avg_delta >= 2:
            return (
                45,
                "NEUTRAL",
                f"Low detection increase: {total_delta} (~{avg_delta:.0f} per rule).",
            )

        if avg_delta >= 1:
            return (
                35,
                "WEAK",
                f"Very low detection: {total_delta} detections (~{avg_delta:.1f} per rule).",
            )

        if total_delta == 0:
            return (
                20,
                "WEAK",
                "No detections. Rule may not match logs / incorrect fields / too restrictive.",
            )

        return (
            0,
            "ERROR",
            f"Negative delta ({total_delta}) → indicates broken rules, conflicts, or log generation failure.",
        )


def parse_rule_list(rule_string: str) -> List[str]:
    if not rule_string or rule_string.strip() == "":
        return []
    return [r.strip() for r in rule_string.split(",") if r.strip()]


def main():
    parser = argparse.ArgumentParser(description="Delta-based classifier")
    parser.add_argument("--baseline-results", required=True)
    parser.add_argument("--current-results", required=True)
    parser.add_argument("--rules-dir", default="rules/sigma")
    parser.add_argument("--changed-sigma-rules", default="")
    parser.add_argument("--changed-yara-rules", default="")
    parser.add_argument("--output-file", required=True)

    # ✅ PROPER debug support
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        print("[DEBUG] Debug mode enabled for compare_and_classify.py")

    baseline_dir = Path(args.baseline_results)
    current_dir = Path(args.current_results)
    rules_dir = Path(args.rules_dir)
    output_file = Path(args.output_file)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    changed_sigma = parse_rule_list(args.changed_sigma_rules)
    changed_yara = parse_rule_list(args.changed_yara_rules)
    all_new_rules = changed_sigma + changed_yara

    if not all_new_rules:
        print("⚠️ No changed rules to classify")
        report = {"summary": {"total_rules": 0, "by_grade": {}, "average_score": 0}, "rules": []}
    else:
        classifier = DeltaBasedClassifier(baseline_dir, current_dir, rules_dir)
        report = classifier.classify_new_rules(all_new_rules, len(all_new_rules))

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 70)
    print("📊 FINAL SUMMARY")
    print("=" * 70)
    print(f"Total rules: {report['summary']['total_rules']}")
    print(f"Average score: {report['summary']['average_score']}/100")

    by_grade = report["summary"]["by_grade"]
    if by_grade:
        print("\nGrade Distribution:")
        for grade in ["STRONG", "NEUTRAL", "WEAK", "ERROR"]:
            if grade in by_grade:
                print(f"   {grade}: {by_grade[grade]}")

    print(f"\n✅ Report saved to: {output_file}")
    print("\n💡 CLASSIFICATION METHOD: delta-based")


if __name__ == "__main__":
    main()
