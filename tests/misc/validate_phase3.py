#!/usr/bin/env python3
"""
Phase 3 CBOM Validator
Validates key material components against CycloneDX CBOM requirements

Usage: python3 validate_phase3.py <cbom.json>
"""

import json
import sys
from typing import Dict, List, Tuple

class Phase3Validator:
    def __init__(self, cbom_path: str):
        with open(cbom_path) as f:
            self.cbom = json.load(f)
        
        self.errors = []
        self.warnings = []
        self.info = []
        
    def find_key_components(self) -> List[Dict]:
        """Find all key material components"""
        keys = []
        for comp in self.cbom.get("components", []):
            if comp.get("type") != "cryptographic-asset":
                continue
            
            crypto_props = comp.get("cryptoProperties", {})
            asset_type = crypto_props.get("assetType", "")
            
            # Only include actual key material, not protocols, algorithms, or certificates
            if asset_type == "related-crypto-material":
                # Additional check: ensure it has relatedCryptoMaterialProperties
                # This filters out misclassified components
                if "relatedCryptoMaterialProperties" in crypto_props:
                    keys.append(comp)
        
        return keys
    
    def validate_structure(self, component: Dict) -> Tuple[bool, List[str]]:
        """Validate component uses correct structure"""
        issues = []
        
        crypto_props = component.get("cryptoProperties", {})
        
        if crypto_props.get("assetType") != "related-crypto-material":
            issues.append("Must use assetType: 'related-crypto-material'")
        
        if "relatedCryptoMaterialProperties" not in crypto_props:
            issues.append("Missing 'relatedCryptoMaterialProperties' wrapper")
            return False, issues
        
        return True, issues
    
    def validate_required_fields(self, component: Dict) -> List[str]:
        """Validate all required fields are present"""
        issues = []
        
        props = component.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
        
        required_fields = {
            "type": "Key type (private-key, public-key, secret-key)",
            "state": "Key state (active, deactivated, etc.)",
            "size": "Key size in bits",
            "format": "Key format (PEM, PKCS#8, DER)",
            "algorithmRef": "Reference to algorithm component"
        }
        
        for field, description in required_fields.items():
            if field not in props:
                issues.append(f"Missing required field '{field}' ({description})")
            elif props[field] is None:
                issues.append(f"Field '{field}' is null")
        
        return issues
    
    def validate_type_field(self, component: Dict) -> List[str]:
        """Validate 'type' field has correct value"""
        issues = []
        
        props = component.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
        key_type = props.get("type")
        
        valid_types = ["private-key", "public-key", "secret-key"]
        
        if key_type and key_type not in valid_types:
            issues.append(f"Invalid type '{key_type}'. Must be one of: {', '.join(valid_types)}")
        
        return issues
    
    def validate_state_field(self, component: Dict) -> List[str]:
        """Validate 'state' field has correct value"""
        issues = []
        
        props = component.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
        state = props.get("state")
        
        valid_states = [
            "pre-activation", "active", "suspended", 
            "deactivated", "compromised", "destroyed"
        ]
        
        if state and state not in valid_states:
            issues.append(f"Invalid state '{state}'. Must be one of: {', '.join(valid_states)}")
        
        return issues
    
    def validate_size_field(self, component: Dict) -> List[str]:
        """Validate 'size' field is a positive integer"""
        issues = []
        
        props = component.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
        size = props.get("size")
        
        if size is not None:
            if not isinstance(size, int):
                issues.append(f"Size must be an integer, got {type(size).__name__}")
            elif size <= 0:
                issues.append(f"Size must be positive, got {size}")
            elif size < 128:
                self.warnings.append(f"Key size {size} is very small (security concern)")
        
        return issues
    
    def validate_algorithm_ref(self, component: Dict) -> List[str]:
        """Validate algorithmRef points to an existing component"""
        issues = []
        
        props = component.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
        algo_ref = props.get("algorithmRef")
        
        if algo_ref:
            # Check if referenced algorithm exists
            algo_exists = any(
                c.get("bom-ref") == algo_ref or c.get("name") == algo_ref
                for c in self.cbom.get("components", [])
                if c.get("cryptoProperties", {}).get("assetType") == "algorithm"
            )
            
            if not algo_exists:
                self.warnings.append(
                    f"Algorithm reference '{algo_ref}' not found in CBOM components"
                )
        
        return issues
    
    def validate_secured_by(self, component: Dict) -> List[str]:
        """Validate securedBy field for encrypted keys"""
        issues = []
        
        props = component.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
        secured_by = props.get("securedBy")
        
        # Check if key name suggests encryption
        name = component.get("name", "").lower()
        is_likely_encrypted = "encrypted" in name or "enc" in name
        
        if is_likely_encrypted and not secured_by:
            self.warnings.append(
                f"Key '{component.get('name')}' appears encrypted but has no 'securedBy' field"
            )
        
        if secured_by:
            if "mechanism" not in secured_by:
                issues.append("securedBy missing 'mechanism' field")
            
            if "algorithmRef" in secured_by:
                # Verify encryption algorithm exists
                enc_algo_ref = secured_by["algorithmRef"]
                algo_exists = any(
                    c.get("bom-ref") == enc_algo_ref or c.get("name") == enc_algo_ref
                    for c in self.cbom.get("components", [])
                    if c.get("cryptoProperties", {}).get("assetType") == "algorithm"
                )
                
                if not algo_exists:
                    self.warnings.append(
                        f"Encryption algorithm '{enc_algo_ref}' not found in CBOM"
                    )
        
        return issues
    
    def validate_component(self, component: Dict, index: int) -> Dict:
        """Validate a single key component"""
        result = {
            "name": component.get("name", f"Component {index}"),
            "bom-ref": component.get("bom-ref", "N/A"),
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        # Validate structure
        valid_structure, structure_issues = self.validate_structure(component)
        if not valid_structure:
            result["valid"] = False
            result["errors"].extend(structure_issues)
            return result  # Can't continue without proper structure
        
        # Validate required fields
        result["errors"].extend(self.validate_required_fields(component))
        
        # Validate field values
        result["errors"].extend(self.validate_type_field(component))
        result["errors"].extend(self.validate_state_field(component))
        result["errors"].extend(self.validate_size_field(component))
        result["errors"].extend(self.validate_algorithm_ref(component))
        result["errors"].extend(self.validate_secured_by(component))
        
        if result["errors"]:
            result["valid"] = False
        
        return result
    
    def generate_report(self) -> Dict:
        """Generate validation report"""
        keys = self.find_key_components()
        
        # Also count other component types for informational purposes
        all_components = self.cbom.get("components", [])
        component_breakdown = {}
        for comp in all_components:
            if comp.get("type") == "cryptographic-asset":
                asset_type = comp.get("cryptoProperties", {}).get("assetType", "unknown")
                component_breakdown[asset_type] = component_breakdown.get(asset_type, 0) + 1
        
        if not keys:
            return {
                "status": "NO_KEYS",
                "message": "No key material components found in CBOM",
                "total_keys": 0,
                "valid_keys": 0,
                "conformance": 0.0,
                "component_breakdown": component_breakdown
            }
        
        results = []
        for i, key in enumerate(keys):
            result = self.validate_component(key, i)
            results.append(result)
        
        valid_count = sum(1 for r in results if r["valid"])
        conformance = (valid_count / len(results)) * 100
        
        return {
            "status": "COMPLETE" if conformance >= 95 else "PARTIAL",
            "total_keys": len(results),
            "valid_keys": valid_count,
            "invalid_keys": len(results) - valid_count,
            "conformance": round(conformance, 1),
            "results": results,
            "global_warnings": self.warnings,
            "component_breakdown": component_breakdown
        }

def print_report(report: Dict):
    """Print validation report"""
    print("=" * 80)
    print("PHASE 3 VALIDATION REPORT")
    print("=" * 80)
    print()
    
    if report["status"] == "NO_KEYS":
        print("❌ NO KEY MATERIAL FOUND")
        print(f"   {report['message']}")
        print()
        
        # Show what was found instead
        if report.get("component_breakdown"):
            print("📊 COMPONENTS FOUND (by assetType):")
            for asset_type, count in sorted(report["component_breakdown"].items()):
                print(f"  • {asset_type}: {count}")
            print()
        
        print("💡 To test Phase 3:")
        print("   1. Generate test keys (see Phase_3_Testing_Guide.md)")
        print("   2. Run cbom-generator on key directory")
        print("   3. Re-run this validator")
        return
    
    # Show component breakdown if available
    if report.get("component_breakdown"):
        print(f"📦 COMPONENT BREAKDOWN")
        for asset_type, count in sorted(report["component_breakdown"].items()):
            icon = "🔑" if asset_type == "related-crypto-material" else "📋"
            print(f"  {icon} {asset_type}: {count}")
        print()
    
    print(f"📊 KEY MATERIAL SUMMARY")
    print(f"  Total Keys: {report['total_keys']}")
    print(f"  Valid Keys: {report['valid_keys']}")
    print(f"  Invalid Keys: {report['invalid_keys']}")
    print(f"  Conformance: {report['conformance']}%")
    print()
    
    # Overall status
    if report["conformance"] >= 95:
        print("✅ PHASE 3 COMPLETE - Key material fully conformant!")
    elif report["conformance"] >= 60:
        print("⚠️  PHASE 3 PARTIAL - Key material partially conformant")
    else:
        print("❌ PHASE 3 NOT STARTED - Key material needs implementation")
    
    print()
    print("=" * 80)
    print("DETAILED VALIDATION RESULTS")
    print("=" * 80)
    print()
    
    # Group by valid/invalid
    valid_keys = [r for r in report["results"] if r["valid"]]
    invalid_keys = [r for r in report["results"] if not r["valid"]]
    
    if valid_keys:
        print(f"✅ VALID KEYS ({len(valid_keys)})")
        print()
        for i, result in enumerate(valid_keys[:5], 1):  # Show first 5
            print(f"  {i}. {result['name']}")
            print(f"     bom-ref: {result['bom-ref']}")
        
        if len(valid_keys) > 5:
            print(f"  ... and {len(valid_keys) - 5} more")
        print()
    
    if invalid_keys:
        print(f"❌ INVALID KEYS ({len(invalid_keys)})")
        print()
        for i, result in enumerate(invalid_keys, 1):
            print(f"  {i}. {result['name']}")
            print(f"     bom-ref: {result['bom-ref']}")
            print(f"     Errors:")
            for error in result["errors"]:
                print(f"       • {error}")
            print()
    
    if report.get("global_warnings"):
        print("⚠️  WARNINGS")
        print()
        for warning in report["global_warnings"]:
            print(f"  • {warning}")
        print()
    
    print("=" * 80)
    print("CONFORMANCE CHECKLIST")
    print("=" * 80)
    print()
    
    # Calculate checklist based on first valid key (if any)
    if valid_keys:
        sample = report["results"][0]
        
        # Assume we have structure if there are valid keys
        checklist = {
            "Uses 'related-crypto-material' assetType": True,
            "Uses 'relatedCryptoMaterialProperties' structure": True,
            "Has 'type' field": not any("type" in e for r in report["results"] for e in r["errors"]),
            "Has 'state' field": not any("state" in e for r in report["results"] for e in r["errors"]),
            "Has 'size' field": not any("size" in e for r in report["results"] for e in r["errors"]),
            "Has 'format' field": not any("format" in e for r in report["results"] for e in r["errors"]),
            "Has 'algorithmRef' field": not any("algorithmRef" in e for r in report["results"] for e in r["errors"]),
            "Has 'securedBy' for encrypted keys": "securedBy" not in str(report.get("global_warnings", []))
        }
        
        for item, status in checklist.items():
            icon = "✅" if status else "❌"
            print(f"  {icon} {item}")
        
        print()
    
    print("=" * 80)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 validate_phase3.py <cbom.json>")
        sys.exit(1)
    
    cbom_path = sys.argv[1]
    
    try:
        validator = Phase3Validator(cbom_path)
        report = validator.generate_report()
        print_report(report)
        
        # Exit code based on conformance
        if report["status"] == "NO_KEYS":
            sys.exit(2)  # No keys found
        elif report["conformance"] >= 95:
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Partial/incomplete
    
    except FileNotFoundError:
        print(f"❌ Error: File not found: {cbom_path}")
        sys.exit(3)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in {cbom_path}")
        print(f"   {e}")
        sys.exit(3)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(3)

if __name__ == "__main__":
    main()