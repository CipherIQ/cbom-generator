/**
 * Integration bridge between WASM scanner and cbom-explorer.
 *
 * Two modes:
 * A) Embedded in cbom-explorer: scanner runs as a tab, CBOM is passed
 *    in-memory to the explorer's existing visualization pipeline.
 * B) Standalone: scanner runs independently, "Explore" button opens
 *    cbom-explorer in a new tab with the CBOM data via sessionStorage.
 *
 * @module explorer-integration
 */

/**
 * Check if we're running inside cbom-explorer.
 * cbom-explorer sets window.__CBOM_EXPLORER__ during initialization.
 * @returns {boolean}
 */
export function isInsideExplorer() {
    return typeof window !== 'undefined' &&
        !!(window.__CBOM_EXPLORER__ || document.getElementById('cbom-explorer-root'));
}

/**
 * Load a CBOM into the explorer (embedded mode).
 * Calls the explorer's loadCbom() API to render all visualization tabs,
 * then switches to the Dashboard tab.
 *
 * @param {Object} cbom - CycloneDX CBOM JSON object from scanner
 * @returns {boolean} true if successfully loaded, false if explorer API not available
 */
export function loadCbomIntoExplorer(cbom) {
    if (window.__CBOM_EXPLORER__?.loadCbom) {
        window.__CBOM_EXPLORER__.loadCbom(cbom);
        window.__CBOM_EXPLORER__.switchTab?.('dashboard');
        return true;
    }
    return false;
}

/**
 * Open cbom-explorer in a new tab with the CBOM (standalone mode).
 * Uses sessionStorage for the handoff — works for any CBOM size and
 * doesn't require the explorer to be on the same origin.
 *
 * @param {Object} cbom - CycloneDX CBOM JSON object
 * @param {string} [explorerUrl] - URL to cbom-explorer (default: auto-detect)
 * @returns {boolean} true if window opened, false if blocked or unavailable
 */
export function openInExplorer(cbom, explorerUrl) {
    // Auto-detect explorer URL relative to this script's location
    if (!explorerUrl) {
        explorerUrl = '../../explorer/cbom-viz.html';
    }

    try {
        const key = 'cbom-scanner-result-' + Date.now();
        sessionStorage.setItem(key, JSON.stringify(cbom));
        const win = window.open(`${explorerUrl}?import=${encodeURIComponent(key)}`, '_blank');
        return !!win;
    } catch {
        return false;
    }
}
