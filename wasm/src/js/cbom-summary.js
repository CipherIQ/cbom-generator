/**
 * CBOM summary extraction module.
 *
 * Parses a raw CycloneDX CBOM JSON object and returns a structured summary
 * suitable for rendering in the scanner web UI — component counts, PQC
 * readiness breakdown, and a flat component list for tables.
 *
 * @module cbom-summary
 */

// ── PQC classification extraction ───────────────────────────────────

/**
 * Extract PQC classification from a component's properties.
 *
 * Looks for cbom:pqc:status in component.properties[], falling back
 * to nistQuantumSecurityLevel in algorithmProperties.
 *
 * @param {Object} component - CycloneDX component
 * @returns {'SAFE'|'TRANSITIONAL'|'UNSAFE'|'DEPRECATED'|null}
 */
function extractPqcStatus(component) {
    for (const p of (component.properties || [])) {
        if (p.name === 'cbom:pqc:status') {
            return p.value;
        }
    }
    const nistLevel = component.cryptoProperties?.algorithmProperties?.nistQuantumSecurityLevel;
    if (nistLevel !== undefined) {
        return nistLevel >= 1 ? 'SAFE' : 'UNSAFE';
    }
    return null;
}

/**
 * Extract a named property value from component.properties[].
 * @param {Object} component
 * @param {string} name
 * @returns {string|null}
 */
function getProperty(component, name) {
    for (const p of (component.properties || [])) {
        if (p.name === name) return p.value;
    }
    return null;
}

// ── Main summary extraction ─────────────────────────────────────────

/**
 * Extract structured summary from a CycloneDX CBOM JSON object.
 *
 * @param {Object} cbom - Raw CycloneDX CBOM JSON
 * @returns {Object} Structured summary for UI rendering
 */
export function extractCbomSummary(cbom) {
    const components = cbom.components || [];

    // ── Count by component type and crypto assetType ─────────────
    let applications = 0;
    let libraries = 0;
    let certificates = 0;
    let algorithms = 0;
    let protocols = 0;
    let keys = 0;
    let services = 0;

    for (const c of components) {
        if (c.type === 'application') { applications++; continue; }
        if (c.type === 'library') { libraries++; continue; }
        if (c.type === 'service') { services++; continue; }
        if (c.type === 'cryptographic-asset') {
            const at = c.cryptoProperties?.assetType;
            if (at === 'certificate') certificates++;
            else if (at === 'algorithm') algorithms++;
            else if (at === 'protocol') protocols++;
            else if (at === 'related-crypto-material') keys++;
        }
    }

    // ── PQC readiness from per-component properties ──────────────
    let safe = 0;
    let transitional = 0;
    let unsafe = 0;
    let deprecated = 0;

    for (const c of components) {
        const status = extractPqcStatus(c);
        if (status === 'SAFE') safe++;
        else if (status === 'TRANSITIONAL') transitional++;
        else if (status === 'UNSAFE') unsafe++;
        else if (status === 'DEPRECATED') deprecated++;
    }

    const pqcTotal = safe + transitional + unsafe + deprecated;

    // Score: SAFE=1.0, TRANSITIONAL=0.5, DEPRECATED/UNSAFE=0
    const score = pqcTotal > 0
        ? Math.round(((safe + transitional * 0.5) / pqcTotal) * 100 * 10) / 10
        : 0;

    // Check if metadata has an authoritative score from the C scanner
    let metadataScore = null;
    for (const p of (cbom.metadata?.properties || [])) {
        if (p.name === 'cbom:pqc:readiness_score') {
            metadataScore = parseFloat(p.value);
            break;
        }
    }

    const pqcReadiness = {
        score: metadataScore !== null ? metadataScore : score,
        safe,
        transitional,
        unsafe,
        deprecated,
        total: pqcTotal,
    };

    // ── Flat component list for table rendering ──────────────────
    const componentList = components.map(c => ({
        name: c.name,
        type: c.type,
        assetType: c.cryptoProperties?.assetType || null,
        bomRef: c['bom-ref'],
        pqcStatus: extractPqcStatus(c),
        pqcMigrationUrgency: getProperty(c, 'cbom:pqc:migration_urgency'),
        pqcAlternative: getProperty(c, 'cbom:pqc:alternative'),
        algorithmFamily: c.cryptoProperties?.algorithmProperties?.algorithmFamily || null,
        primitive: c.cryptoProperties?.algorithmProperties?.primitive || null,
        keySize: getProperty(c, 'cbom:cert:key_size')
            || c.cryptoProperties?.algorithmProperties?.parameterSetIdentifier
            || null,
    }));

    return {
        totalComponents: components.length,
        applications,
        certificates,
        algorithms,
        protocols,
        libraries,
        keys,
        services,
        pqcReadiness,
        componentList,
    };
}
