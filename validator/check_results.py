"""
Check validation results and provide detailed output
"""
import os
import sys
import json
import argparse
from pathlib import Path


def check_results(results_dir: str):
    """Check validation results and exit with appropriate code"""
    results_file = Path(results_dir) / 'validation_results.json'
    
    if not results_file.exists():
        print("❌ Validation results file not found")
        sys.exit(1)
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    print("\n" + "="*60)
    print("VALIDATION RESULTS SUMMARY")
    print("="*60)
    
    total_passed = results.get('total_passed', 0)
    total_failed = results.get('total_failed', 0)
    total_tested = total_passed + total_failed
    
    print(f"\nTotal rules tested: {total_tested}")
    print(f"✅ Passed: {total_passed}")
    print(f"❌ Failed: {total_failed}")
    
    if total_tested > 0:
        pass_rate = (total_passed / total_tested * 100)
        print(f"Pass rate: {pass_rate:.1f}%")
    
    # Show detailed results
    print("\n" + "-"*60)
    print("DETAILED RESULTS")
    print("-"*60)
    
    for detail in results.get('details', []):
        status_icon = "✅" if detail.get('passed') else "❌"
        rule_id = detail.get('rule_id', 'Unknown')
        rule_title = detail.get('rule_title', 'Untitled')
        
        print(f"\n{status_icon} {rule_title}")
        print(f"   ID: {rule_id}")
        print(f"   Path: {detail.get('rule_path', 'N/A')}")
        
        if 'error' in detail:
            print(f"   Error: {detail['error']}")
        else:
            detection_rate = detail.get('detection_rate', 0)
            expected = detail.get('expected_matches', 0)
            actual = detail.get('actual_matches', 0)
            
            print(f"   Detection Rate: {detection_rate}%")
            print(f"   Expected Matches: {expected}")
            print(f"   Actual Matches: {actual}")
            
            if detection_rate < 50:
                print(f"   ⚠️  Low detection rate - rule may need tuning")
            elif detection_rate == 100:
                print(f"   🎯 Perfect detection!")
    
    print("\n" + "="*60)
    
    # Exit with appropriate code
    if total_failed > 0:
        print(f"\n❌ VALIDATION FAILED - {total_failed} rule(s) need attention")
        sys.exit(1)
    else:
        print(f"\n✅ VALIDATION PASSED - All {total_passed} rule(s) validated successfully")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description='Check validation results')
    parser.add_argument('--results-dir', default='validation_results', 
                       help='Directory containing validation results')
    args = parser.parse_args()
    
    check_results(args.results_dir)


if __name__ == '__main__':
    main()