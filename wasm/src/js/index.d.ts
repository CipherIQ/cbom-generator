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
    /** Progress callback */
    onProgress?: (info: ProgressInfo) => void;
}

export interface ProgressInfo {
    phase: 'mounting' | 'scanning' | 'reading-output';
    filesMounted?: number;
    totalFiles?: number;
    currentFile?: string;
}

export interface ScanResult {
    cbom: CycloneDXBom;
    warnings: string[];
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

export type Platform = 'ubuntu' | 'debian' | 'yocto' | 'buildroot' | 'openwrt' | 'alpine' | 'docker';

export declare const PLATFORMS: Record<
    Platform,
    { pluginSet: 'ubuntu' | 'embedded'; registry: 'ubuntu' | 'yocto' | 'openwrt' | 'alpine' }
>;
