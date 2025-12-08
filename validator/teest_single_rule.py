#!/usr/bin/env python3
"""
Quick test script to verify your EXACT rule works with the EXACT validator code
Run this locally BEFORE committing to GitHub
"""
import os
import sys
import json
import yaml
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_complete_flow(rule_path: str):
    """Test the complete flow: generate logs -> validate -> classify"""
    
    print(f"\n{'='*70}")
    print(f"COMPLETE FLOW TEST: {rule_path}")
    print(f"{'='*70}\n")
    
    rule_name = Path(rule_path).stem
    
    # Step 1: Show rule content
    print("=" * 70)
    print("STEP 1: Your Rule Content")
    print("=" * 70)
    with open(rule_path, 'r') as f:
        rule_content = f.read()
    print(rule_content)
    print()
    
    # Step 2: Generate synthetic logs
    print("=" * 70)
    print("STEP 2: Generating Synthetic Logs")
    print("=" * 70)
    
    # Create temp directory
    import tempfile
    import shutil
    temp_dir = tempfile.mkdtemp()
    
    try:
        from validator.generate_logs import generate_synthetic_logs
        from test import load_sigma_rules
        
        # Copy rule to temp directory
        rule_dir = os.path.join(temp_dir, 'rules')
        os.makedirs(rule_dir)
        shutil.copy(rule_path, rule_dir)
        
        # Generate logs
        logs_dir = os.path.join(temp_dir, 'logs')
        generate_synthetic_logs(rule_dir, logs_dir, log_count=30)
        
        # Show generated logs
        master_log = os.path.join(logs_dir, 'synthetic_logs_master.jsonl')
        with open(master_log, 'r') as f:
            logs = [json.loads(line) for line in f if line.strip()]
        
        print(f"\n✅ Generated {len(logs)} logs")
        print(f"\nSample log (positive):")
        positive = next((l for l in logs if l.get('_match_type') == 'positive'), None)
        if positive:
            clean = {k: v for k, v in positive.items() if not k.startswith('_')}
            print(json.dumps(clean, indent=2))
        
        # Step 3: Validate
        print("\n" + "=" * 70)
        print("STEP 3: Running Validation")
        print("=" * 70)
        
        from validator.validate_rules import RuleValidator
        
        results_dir = os.path.join(temp_dir, 'results')
        validator = RuleValidator(results_dir, mode='current', synthetic_logs_dir=logs_dir)
        validator.load_synthetic_logs()
        validator.validate_all_rules(rule_dir, rule_type='sigma')
        validator.save_results()
        
        # Check detections
        detections_file = os.path.join(results_dir, 'detections.json')
        with open(detections_file, 'r') as f:
            detections = json.load(f)
        
        print(f"\n✅ Total detections: {len(detections)}")
        
        if detections:
            print(f"\n📊 Detection breakdown:")
            
            # Show what identifiers are in detections
            sample_detection = detections[0]
            print(f"\nSample detection keys: {list(sample_detection.keys())}")
            print(f"\nSample detection:")
            print(json.dumps(sample_detection, indent=2))
            
            # Check if our rule triggered
            rule_detections = []
            for d in detections:
                # Check multiple possible identifiers
                for key in ['rule_name', 'rule', 'rule_id', 'title']:
                    if key in d:
                        identifier = d[key]
                        if rule_name in str(identifier) or identifier in rule_name:
                            rule_detections.append(d)
                            break
            
            print(f"\n🎯 Detections for '{rule_name}': {len(rule_detections)}")
            
            if rule_detections:
                print(f"\n✅ SUCCESS: Your rule IS triggering!")
                print(f"   It detected {len(rule_detections)} events")
                return True
            else:
                print(f"\n❌ PROBLEM: Your rule is NOT triggering")
                print(f"\n🔍 Available rule identifiers in detections:")
                rule_ids = set()
                for d in detections:
                    for key in ['rule_name', 'rule', 'rule_id', 'title']:
                        if key in d and d[key]:
                            rule_ids.add(f"{key}: {d[key]}")
                for rid in sorted(rule_ids):
                    print(f"   - {rid}")
                
                print(f"\n   Expected to find: '{rule_name}'")
                return False
        else:
            print(f"\n❌ CRITICAL: No detections generated at all!")
            print(f"\n   This means:")
            print(f"   1. Logs were generated but don't match the rule")
            print(f"   2. SOCSimulator isn't processing correctly")
            print(f"   3. Rule syntax might be invalid")
            
            # Show what's in the logs
            print(f"\n   Generated log fields:")
            if logs:
                sample_log = logs[0]
                for field in sorted(sample_log.keys()):
                    if not field.startswith('_'):
                        print(f"      - {field}")
            
            # Show what rule expects
            print(f"\n   Rule expects these fields:")
            with open(rule_path, 'r') as f:
                rule = yaml.safe_load(f)
            detection = rule.get('detection', {})
            for key, value in detection.items():
                if key != 'condition' and isinstance(value, dict):
                    print(f"      Selection '{key}':")
                    for field in value.keys():
                        print(f"         - {field}")
            
            return False
    
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    print(f"\n{'='*70}\n")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python test_single_rule.py <rule_file>")
        print("Example: python test_single_rule.py rules/sigma/sustld.yml")
        sys.exit(1)
    
    rule_path = sys.argv[1]
    
    if not os.path.exists(rule_path):
        print(f"Error: Rule file not found: {rule_path}")
        sys.exit(1)
    
    print("\n" + "🔬" * 35)
    print(" LOCAL VALIDATION TEST - Run this BEFORE committing!")
    print("🔬" * 35)
    
    success = test_complete_flow(rule_path)
    
    print("\n" + "=" * 70)
    if success:
        print("✅ RESULT: Your rule is working correctly!")
        print("   Your GitHub Actions workflow should work now.")
        print("\n💡 Next steps:")
        print("   1. Commit your rule")
        print("   2. Push to GitHub")
        print("   3. Watch the Actions run")
    else:
        print("❌ RESULT: Your rule has issues")
        print("   Fix the issues shown above before committing.")
        print("\n💡 Common fixes:")
        print("   1. Check field names in your rule match generated logs")
        print("   2. Verify rule syntax is valid YAML")
        print("   3. Ensure detection conditions are correct")
        print("   4. Try simplifying the rule to isolate the issue")
    print("=" * 70 + "\n")
    
    sys.exit(0 if success else 1)
