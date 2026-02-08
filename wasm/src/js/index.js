/**
 * High-level API for cbom-generator WASM scanner.
 *
 * Re-exports the core scanner from wasm-bridge.js and provides
 * platform presets for common firmware targets.
 *
 * @module cbom-generator-wasm
 */

export { initScanner } from './wasm-bridge.js';

/**
 * @typedef {Object} ScanOptions
 * @property {string} [specVersion='1.7'] - CycloneDX spec version: '1.6' or '1.7'
 * @property {string} [pluginSet='embedded'] - Plugin set: 'ubuntu' or 'embedded'
 * @property {string} [registry='yocto'] - Crypto registry: 'ubuntu', 'yocto', 'openwrt', 'alpine'
 * @property {boolean} [discoverServices=true] - Enable config-only service discovery
 * @property {string[]} [scanPaths] - Override auto-detected scan directories (advanced)
 * @property {function} [onProgress] - Progress callback ({phase, filesMounted, totalFiles, currentFile})
 */

/**
 * Platform presets that set pluginSet + registry together.
 *
 * Usage:
 *   import { initScanner, PLATFORMS } from './index.js';
 *   const scanner = await initScanner();
 *   const { cbom } = await scanner.scan(files, certData, {
 *       ...PLATFORMS.yocto,
 *       onProgress: console.log,
 *   });
 *
 * @type {Object<string, {pluginSet: string, registry: string}>}
 */
export const PLATFORMS = {
    'ubuntu':    { pluginSet: 'ubuntu',   registry: 'ubuntu' },
    'debian':    { pluginSet: 'ubuntu',   registry: 'ubuntu' },
    'yocto':     { pluginSet: 'embedded', registry: 'yocto' },
    'buildroot': { pluginSet: 'embedded', registry: 'yocto' },
    'openwrt':   { pluginSet: 'embedded', registry: 'openwrt' },
    'alpine':    { pluginSet: 'ubuntu',   registry: 'alpine' },
    'docker':    { pluginSet: 'ubuntu',   registry: 'alpine' },
};
