#!/usr/bin/env python3
"""
Phase 4 CBOM Validator
Validates protocol cipher suites and dependency 'provides' relationships

Usage: python3 validate_phase4.py <cbom.json>
"""

import json
import sys
from typing import Dict, List

class Phase4Validator:
    def __init__(self, cbom_path: str):
        with open(cbom_path) as f:
            self.cbom = json.load(f)
        
        self.errors = []
        self.warnings = []
    
    def find_protocol_components(self) -> List[Dict]:
        """Find all protocol components"""
        protocols = []
        for comp in self.cbom.get("components", []):
            if comp.get("type") != "cryptographic-asset":
                continue
            
            crypto_props = comp.get("cryptoProperties", {})
            if crypto_props.get("assetType") == "protocol":
                protocols.append(comp)
        
        return protocols
    
    def validate_protocol_cipher_suites(self, protocol: Dict) -> Dict:
        """Validate protocol has cipherSuites array"""
        result = {
            "name": protocol.get("name", "unnamed"),
            "bom-ref": protocol.get("bom-ref", "N/A"),
            "valid": True,
            "errors": [],
            "warnings": [],
            "cipher_suite_count": 0
        }
        
        proto_props = protocol.get("cryptoProperties", {}).get("protocolProperties", {})
        
        # Check for cipherSuites
        if "cipherSuites" not in proto_props:
            result["errors"].append("Missing 'cipherSuites' array")
            result["valid"] = False
            return result
        
        cipher_suites = proto_props["cipherSuites"]
        
        if not isinstance(cipher_suites, list):
            result["errors"].append("cipherSuites must be an array")
            result["valid"] = False
            return result
        
        if len(cipher_suites) == 0:
            result["warnings"].append("cipherSuites array is empty")
            result["valid"] = False
            return result
        
        result["cipher_suite_count"] = len(cipher_suites)
        
        # Validate each cipher suite
        for i, cs in enumerate(cipher_suites):
            cs_name = cs.get("name", f"Suite-{i}")
            
            if "name" not in cs:
                result["errors"].append(f"Cipher suite {i} missing 'name'")
                result["valid"] = False
            
            if "algorithms" not in cs:
                result["errors"].append(f"Cipher suite '{cs_name}' missing 'algorithms' array")
                result["valid"] = False
            elif not isinstance(cs["algorithms"], list):
                result["errors"].append(f"Cipher suite '{cs_name}' algorithms must be array")
                result["valid"] = False
            elif len(cs["algorithms"]) == 0:
                result["warnings"].append(f"Cipher suite '{cs_name}' has empty algorithms array")
            
            if "identifiers" not in cs:
                result["warnings"].append(f"Cipher suite '{cs_name}' missing IANA identifiers (recommended)")
        
        return result
    
    def validate_dependencies(self) -> Dict:
        """Validate dependency relationships"""
        result = {
            "total_deps": 0,
            "with_provides": 0,
            "with_depends_on": 0,
            "provides_total_count": 0,
            "errors": [],
            "warnings": [],
            "examples": []
        }
        
        dependencies = self.cbom.get("dependencies", [])
        result["total_deps"] = len(dependencies)
        
        if result["total_deps"] == 0:
            result["warnings"].append("No dependencies found in CBOM")
            return result
        
        for dep in dependencies:
            dep_ref = dep.get("ref", "unknown")
            
            if "dependsOn" in dep:
                result["with_depends_on"] += 1
            
            if "provides" in dep:
                result["with_provides"] += 1
                
                # Validate provides structure
                if not isinstance(dep["provides"], list):
                    result["errors"].append(f"Dependency '{dep_ref}' has non-array 'provides'")
                else:
                    provides_count = len(dep["provides"])
                    result["provides_total_count"] += provides_count
                    
                    # Save example
                    if len(result["examples"]) < 3:
                        result["examples"].append({
                            "ref": dep_ref,
                            "provides_count": provides_count,
                            "sample_provides": dep["provides"][:3]
                        })
        
        return result
    
    def get_component_breakdown(self) -> Dict:
        """Get breakdown of all component types"""
        breakdown = {}
        for comp in self.cbom.get("components", []):
            if comp.get("type") == "cryptographic-asset":
                asset_type = comp.get("cryptoProperties", {}).get("assetType", "unknown")
                breakdown[asset_type] = breakdown.get(asset_type, 0) + 1
        return breakdown
    
    def generate_report(self) -> Dict:
        """Generate Phase 4 validation report"""
        protocols = self.find_protocol_components()
        
        protocol_results = []
        for protocol in protocols:
            result = self.validate_protocol_cipher_suites(protocol)
            protocol_results.append(result)
        
        dep_validation = self.validate_dependencies()
        component_breakdown = self.get_component_breakdown()
        
        valid_protocols = sum(1 for r in protocol_results if r["valid"])
        protocol_conformance = (valid_protocols / len(protocol_results) * 100) if protocol_results else 0
        
        dep_conformance = (dep_validation["with_provides"] / dep_validation["total_deps"] * 100) if dep_validation["total_deps"] > 0 else 0
        
        overall_conformance = (protocol_conformance + dep_conformance) / 2 if protocol_results or dep_validation["total_deps"] > 0 else 0
        
        return {
            "status": "COMPLETE" if overall_conformance >= 95 else ("PARTIAL" if overall_conformance >= 50 else "NOT_STARTED"),
            "protocol_count": len(protocol_results),
            "valid_protocols": valid_protocols,
            "protocol_conformance": round(protocol_conformance, 1),
            "protocol_results": protocol_results,
            "dependency_validation": dep_validation,
            "dependency_conformance": round(dep_conformance, 1),
            "overall_conformance": round(overall_conformance, 1),
            "component_breakdown": component_breakdown
        }

def print_report(report: Dict):
    """Print Phase 4 validation report"""
    print("=" * 80)
    print("PHASE 4 VALIDATION REPORT")
    print("=" * 80)
    print()
    
    # Component breakdown
    if report.get("component_breakdown"):
        print("📦 COMPONENT BREAKDOWN")
        for asset_type, count in sorted(report["component_breakdown"].items()):
            icon = {"algorithm": "🔐", "certificate": "📜", "related-crypto-material": "🔑", 
                   "protocol": "📡"}.get(asset_type, "📋")
            print(f"  {icon} {asset_type}: {count}")
        print()
    
    # Protocol validation
    print("=" * 80)
    print("📡 PROTOCOL COMPONENTS")
    print("=" * 80)
    print(f"  Total Protocols: {report['protocol_count']}")
    print(f"  Valid Protocols: {report['valid_protocols']}")
    print(f"  Conformance: {report['protocol_conformance']}%")
    print()
    
    if report['protocol_count'] == 0:
        print("  ℹ️  No protocol components found in CBOM")
        print("     Protocol detection may not be implemented yet")
        print()
    elif report['protocol_results']:
        valid = [r for r in report['protocol_results'] if r['valid']]
        invalid = [r for r in report['protocol_results'] if not r['valid']]
        
        if valid:
            print(f"✅ VALID PROTOCOLS ({len(valid)})")
            for r in valid[:5]:
                cs_count = r.get('cipher_suite_count', 0)
                print(f"  • {r['name']} ({cs_count} cipher suites)")
                print(f"    bom-ref: {r['bom-ref']}")
            if len(valid) > 5:
                print(f"  ... and {len(valid) - 5} more")
            print()
        
        if invalid:
            print(f"❌ INVALID PROTOCOLS ({len(invalid)})")
            for r in invalid:
                print(f"  • {r['name']} (bom-ref: {r['bom-ref']})")
                for error in r['errors']:
                    print(f"    ✗ {error}")
                for warning in r['warnings']:
                    print(f"    ⚠ {warning}")
            print()
    
    # Dependency validation
    print("=" * 80)
    print("🔗 DEPENDENCY RELATIONSHIPS")
    print("=" * 80)
    dep_val = report['dependency_validation']
    print(f"  Total Dependencies: {dep_val['total_deps']}")
    print(f"  With 'dependsOn': {dep_val['with_depends_on']}")
    print(f"  With 'provides': {dep_val['with_provides']}")
    
    if dep_val['with_provides'] > 0:
        print(f"  Total 'provides' entries: {dep_val['provides_total_count']}")
    
    print(f"  Conformance: {report['dependency_conformance']}%")
    print()
    
    if dep_val['total_deps'] == 0:
        print("  ℹ️  No dependencies found in CBOM")
        print()
    elif dep_val['with_provides'] == 0:
        print("  ⚠️  No dependencies use 'provides' relationship")
        print("     This is a Phase 4 enhancement")
        print()
    else:
        print("✅ DEPENDENCY EXAMPLES WITH 'PROVIDES'")
        for example in dep_val['examples']:
            print(f"  • {example['ref']}")
            print(f"    Provides {example['provides_count']} algorithms:")
            for algo in example['sample_provides']:
                print(f"      - {algo}")
        print()
    
    if dep_val['errors']:
        print("❌ DEPENDENCY ERRORS")
        for error in dep_val['errors']:
            print(f"  • {error}")
        print()
    
    if dep_val['warnings']:
        print("⚠️  DEPENDENCY WARNINGS")
        for warning in dep_val['warnings']:
            print(f"  • {warning}")
        print()
    
    # Overall conformance
    print("=" * 80)
    print("PHASE 4 CONFORMANCE CHECKLIST")
    print("=" * 80)
    print()
    
    has_protocols = report['protocol_count'] > 0
    has_valid_protocols = report['valid_protocols'] > 0
    has_deps = dep_val['total_deps'] > 0
    has_provides = dep_val['with_provides'] > 0
    
    checklist = {
        "Protocol components detected": has_protocols,
        "Protocols have 'cipherSuites' array": has_valid_protocols,
        "Cipher suites have 'name' field": has_valid_protocols,
        "Cipher suites have 'algorithms' array": has_valid_protocols,
        "Cipher suites have 'identifiers' (IANA codes)": has_valid_protocols,
        "Dependencies exist in CBOM": has_deps,
        "Dependencies use 'provides' relationship": has_provides,
    }
    
    for item, status in checklist.items():
        icon = "✅" if status else "❌"
        print(f"  {icon} {item}")
    
    print()
    print(f"📊 Overall Phase 4 Conformance: {report['overall_conformance']}%")
    print()
    
    if report['status'] == "COMPLETE":
        print("✅ PHASE 4 COMPLETE - Protocols and dependencies fully conformant!")
    elif report['status'] == "PARTIAL":
        print("⚠️  PHASE 4 PARTIAL - Implementation in progress")
        print()
        print("Missing:")
        if not has_valid_protocols:
            print("  • Protocol components need 'cipherSuites' arrays")
        if not has_provides:
            print("  • Dependencies need 'provides' relationships")
    else:
        print("❌ PHASE 4 NOT STARTED")
        print()
        print("To implement Phase 4:")
        print("  1. Add cipher suite detection for protocols (TLS, SSH, etc.)")
        print("  2. Map cipher suites to algorithm components")
        print("  3. Add 'provides' relationships to dependencies")
        print("  4. Link libraries to algorithms they provide")
    
    print("=" * 80)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 validate_phase4.py <cbom.json>")
        sys.exit(1)
    
    try:
        validator = Phase4Validator(sys.argv[1])
        report = validator.generate_report()
        print_report(report)
        
        if report['status'] == "COMPLETE":
            sys.exit(0)
        elif report['status'] == "PARTIAL":
            sys.exit(1)
        else:
            sys.exit(2)
    
    except FileNotFoundError:
        print(f"❌ Error: File not found: {sys.argv[1]}")
        sys.exit(3)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON: {e}")
        sys.exit(3)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(3)

if __name__ == "__main__":
    main()