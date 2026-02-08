/**
 * TypeScript definitions for cbom-generator WASM scanner.
 */

export interface ScanOptions {
    /** CycloneDX spec version: '1.6' or '1.7' (default: '1.7') */
    specVersion?: '1.6' | '1.7';
    /** Plugin set: 'ubuntu' or 'embedded' (default: 'embedded') */
    pluginSet?: 'ubuntu' | 'embedded';
    /** Crypto registry (default: 'yocto') */
    registry?: 'ubuntu' | 'yocto' | 'openwrt' | 'alpine';
    /** Enable config-only service discovery (default: true) */
    discoverServices?: boolean;
    /** Override auto-detected scan directories */
    scanPaths?: string[];
    /** Symlinks from archive extraction (path -> target) */
    symlinks?: Map<string, string>;
    /** Progress callback */
    onProgress?: (info: ProgressInfo) => void;
}

export interface ProgressInfo {
    phase: 'mounting' | 'scanning' | 'reading-output';
    filesMounted?: number;
    totalFiles?: number;
    currentFile?: string;
}

export interface PqcReadiness {
    /** PQC readiness score (0-100, higher = more quantum-safe) */
    score: number;
    /** Components classified as quantum-safe */
    safe: number;
    /** Components using transitional algorithms (e.g. AES-256, X25519) */
    transitional: number;
    /** Components using quantum-vulnerable algorithms (e.g. RSA, DH) */
    unsafe: number;
    /** Components using deprecated algorithms (e.g. MD5, DES) */
    deprecated: number;
    /** Total components with a PQC classification */
    total: number;
}

export interface ComponentListItem {
    name: string;
    type: string;
    assetType: string | null;
    bomRef: string;
    pqcStatus: 'SAFE' | 'TRANSITIONAL' | 'UNSAFE' | 'DEPRECATED' | null;
    pqcMigrationUrgency: string | null;
    pqcAlternative: string | null;
    algorithmFamily: string | null;
    primitive: string | null;
    keySize: string | null;
}

export interface CbomSummary {
    totalComponents: number;
    applications: number;
    certificates: number;
    algorithms: number;
    protocols: number;
    libraries: number;
    keys: number;
    services: number;
    pqcReadiness: PqcReadiness;
    componentList: ComponentListItem[];
}

export interface ScanResult {
    cbom: CycloneDXBom;
    summary: CbomSummary;
    warnings: string[];
    scanTimeMs: number;
}

export interface CycloneDXBom {
    bomFormat: 'CycloneDX';
    specVersion: string;
    metadata?: Record<string, unknown>;
    components?: Array<Record<string, unknown>>;
    [key: string]: unknown;
}

export interface CertData {
    certs: Array<Record<string, unknown>>;
    keys: Array<Record<string, unknown>>;
    warnings: string[];
}

export interface InitScannerOptions {
    /** Path or URL to cbom-generator.js glue code */
    wasmUrl?: string;
    /** Callback for stdout lines */
    onStdout?: (line: string) => void;
    /** Callback for stderr lines */
    onStderr?: (line: string) => void;
}

export declare class WasmScanner {
    scan(
        files: Map<string, Uint8Array>,
        certData: CertData | null,
        options?: ScanOptions
    ): Promise<ScanResult>;

    reset(): void;

    getModule(): object | null;
}

export declare function initScanner(
    options?: InitScannerOptions
): Promise<WasmScanner>;

export declare function extractCbomSummary(cbom: CycloneDXBom): CbomSummary;

export type Platform = 'ubuntu' | 'debian' | 'yocto' | 'buildroot' | 'openwrt' | 'alpine' | 'docker';

export declare const PLATFORMS: Record<
    Platform,
    { pluginSet: 'ubuntu' | 'embedded'; registry: 'ubuntu' | 'yocto' | 'openwrt' | 'alpine' }
>;
