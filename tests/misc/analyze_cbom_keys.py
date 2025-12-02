#!/usr/bin/env python3
"""
Analyzes CBOM for key material components to assess Phase 3 readiness
"""

import json
import sys
from collections import defaultdict

def analyze_keys(cbom_path):
    with open(cbom_path) as f:
        cbom = json.load(f)
    
    print("=" * 80)
    print("PHASE 3: KEY MATERIAL ANALYSIS")
    print("=" * 80)
    print()
    
    # Find all key-related components
    key_components = []
    related_crypto_material = []
    
    for component in cbom.get("components", []):
        if component.get("type") != "cryptographic-asset":
            continue
        
        crypto_props = component.get("cryptoProperties", {})
        asset_type = crypto_props.get("assetType", "")
        
        # Look for keys in various forms
        if "key" in asset_type.lower():
            key_components.append(component)
        
        if asset_type == "related-crypto-material":
            related_crypto_material.append(component)
    
    print(f"📊 KEY COMPONENT SUMMARY")
    print(f"  Total cryptographic assets: {len([c for c in cbom.get('components', []) if c.get('type') == 'cryptographic-asset'])}")
    print(f"  Components with 'key' in assetType: {len(key_components)}")
    print(f"  Components using 'related-crypto-material': {len(related_crypto_material)}")
    print()
    
    if not key_components and not related_crypto_material:
        print("❌ NO KEY COMPONENTS FOUND")
        print("   This CBOM doesn't appear to have discovered any key material.")
        print("   Phase 3 testing requires a CBOM with actual keys detected.")
        print()
        print("💡 To generate keys for testing:")
        print("   1. Create test keys: ssh-keygen -t rsa -b 2048 -f /tmp/test_key")
        print("   2. Create encrypted key: openssl genrsa -aes256 -out /tmp/enc_key.pem 2048")
        print("   3. Scan directory: ./cbom-generator --input /tmp --output cbom.json")
        print()
        return False
    
    print("=" * 80)
    print("DETAILED KEY ANALYSIS")
    print("=" * 80)
    print()
    
    # Analyze structure of key components
    if related_crypto_material:
        print("✅ FOUND COMPONENTS USING 'related-crypto-material' (Phase 3 compliant)")
        print()
        for i, comp in enumerate(related_crypto_material[:3], 1):  # Show first 3
            print(f"Example {i}: {comp.get('name', 'unnamed')}")
            print(f"  bom-ref: {comp.get('bom-ref', 'N/A')}")
            
            props = comp.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
            print(f"  Structure Check:")
            print(f"    ✓ Uses relatedCryptoMaterialProperties: Yes")
            print(f"    - type: {props.get('type', 'MISSING')}")
            print(f"    - state: {props.get('state', 'MISSING')}")
            print(f"    - size: {props.get('size', 'MISSING')}")
            print(f"    - format: {props.get('format', 'MISSING')}")
            print(f"    - algorithmRef: {props.get('algorithmRef', 'MISSING')}")
            
            if 'securedBy' in props:
                print(f"    - securedBy: Present")
                print(f"      - mechanism: {props['securedBy'].get('mechanism', 'N/A')}")
                print(f"      - algorithmRef: {props['securedBy'].get('algorithmRef', 'N/A')}")
            else:
                print(f"    - securedBy: Not present (key not encrypted)")
            
            print()
    
    if key_components and not related_crypto_material:
        print("⚠️  FOUND KEY COMPONENTS BUT NOT USING PHASE 3 STRUCTURE")
        print()
        for i, comp in enumerate(key_components[:3], 1):
            print(f"Example {i}: {comp.get('name', 'unnamed')}")
            crypto_props = comp.get("cryptoProperties", {})
            print(f"  Current assetType: {crypto_props.get('assetType')}")
            print(f"  Current structure: {list(crypto_props.keys())}")
            print()
            print("  ❌ Phase 3 Requirements NOT MET:")
            print("     - Should use assetType: 'related-crypto-material'")
            print("     - Should use 'relatedCryptoMaterialProperties' wrapper")
            print()
    
    print("=" * 80)
    print("PHASE 3 CONFORMANCE CHECKLIST")
    print("=" * 80)
    print()
    
    checklist = {
        "Uses 'related-crypto-material' assetType": len(related_crypto_material) > 0,
        "Uses 'relatedCryptoMaterialProperties' structure": False,
        "Has 'type' field (public-key/private-key/secret-key)": False,
        "Has 'state' field": False,
        "Has 'size' field": False,
        "Has 'format' field (PEM/PKCS#8/DER)": False,
        "Has 'algorithmRef' field": False,
        "Has 'securedBy' for encrypted keys": False,
    }
    
    if related_crypto_material:
        sample = related_crypto_material[0]
        props = sample.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
        
        if props:
            checklist["Uses 'relatedCryptoMaterialProperties' structure"] = True
            checklist["Has 'type' field (public-key/private-key/secret-key)"] = 'type' in props
            checklist["Has 'state' field"] = 'state' in props
            checklist["Has 'size' field"] = 'size' in props
            checklist["Has 'format' field (PEM/PKCS#8/DER)"] = 'format' in props
            checklist["Has 'algorithmRef' field"] = 'algorithmRef' in props
            checklist["Has 'securedBy' for encrypted keys"] = any(
                'securedBy' in c.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
                for c in related_crypto_material
            )
    
    for item, status in checklist.items():
        icon = "✅" if status else "❌"
        print(f"  {icon} {item}")
    
    print()
    conformance_score = (sum(checklist.values()) / len(checklist)) * 100
    print(f"📊 Phase 3 Conformance Score: {conformance_score:.1f}%")
    print()
    
    if conformance_score >= 95:
        print("✅ PHASE 3 COMPLETE - Key material fully conformant!")
    elif conformance_score >= 60:
        print("⚠️  PHASE 3 PARTIAL - Key material partially conformant")
    else:
        print("❌ PHASE 3 NOT STARTED - Key material needs restructuring")
    
    print()
    return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: analyze_cbom_keys.py <cbom.json>")
        sys.exit(1)
    
    analyze_keys(sys.argv[1])