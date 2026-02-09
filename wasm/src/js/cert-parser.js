/**
 * Certificate and key parsing module for cbom-generator WASM edition.
 *
 * Scans extracted files for X.509 certificates and cryptographic keys,
 * parses them using pkijs (pure JavaScript), and produces metadata JSON
 * matching the C-side crypto_parsed_cert_t / crypto_parsed_key_t structures.
 *
 * @module cert-parser
 */

import { Certificate, PrivateKeyInfo, ECPrivateKey, RSAPrivateKey, BasicConstraints } from 'pkijs';
import * as asn1js from 'asn1js';
import { sha256 } from '@noble/hashes/sha256';

// ── OID mappings ─────────────────────────────────────────────────────

/** Signature and public key algorithm OID → human-readable name */
const ALGORITHM_OID_MAP = {
    // RSA signature algorithms
    '1.2.840.113549.1.1.2':  'md2WithRSAEncryption',
    '1.2.840.113549.1.1.4':  'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5':  'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.113549.1.1.14': 'sha224WithRSAEncryption',
    // RSA-PSS
    '1.2.840.113549.1.1.10': 'rsaPSS',
    // RSA encryption (public key identifier)
    '1.2.840.113549.1.1.1':  'RSA',
    // ECDSA signature algorithms
    '1.2.840.10045.4.1':     'ecdsa-with-SHA1',
    '1.2.840.10045.4.3.1':   'ecdsa-with-SHA224',
    '1.2.840.10045.4.3.2':   'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3':   'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4':   'ecdsa-with-SHA512',
    // EC public key identifier
    '1.2.840.10045.2.1':     'EC',
    // EdDSA
    '1.3.101.112':           'Ed25519',
    '1.3.101.113':           'Ed448',
    // DSA
    '1.2.840.10040.4.1':     'DSA',
    '1.2.840.10040.4.3':     'dsaWithSHA1',
    '2.16.840.1.101.3.4.3.2': 'dsaWithSHA256',
};

/** EC named curve OID → human-readable name */
const CURVE_OID_MAP = {
    '1.2.840.10045.3.1.7': 'P-256',
    '1.3.132.0.34':        'P-384',
    '1.3.132.0.35':        'P-521',
    '1.3.132.0.10':        'secp256k1',
    '1.3.101.112':         'Ed25519',
    '1.3.101.113':         'Ed448',
    '1.3.101.110':         'X25519',
    '1.3.101.111':         'X448',
};

/** X.500 attribute type OID → short name */
const DN_OID_MAP = {
    '2.5.4.3':  'CN',
    '2.5.4.6':  'C',
    '2.5.4.7':  'L',
    '2.5.4.8':  'ST',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '2.5.4.5':  'serialNumber',
    '2.5.4.12': 'title',
    '2.5.4.42': 'GN',
    '2.5.4.4':  'SN',
    '1.2.840.113549.1.9.1': 'emailAddress',
    '0.9.2342.19200300.100.1.25': 'DC',
};

// ── Detection heuristics ─────────────────────────────────────────────

const CRYPTO_EXTENSIONS = new Set([
    '.pem', '.crt', '.cer', '.der', '.key', '.pub',
    '.p12', '.pfx', '.jks',
]);

const CRYPTO_PATH_PATTERNS = [
    '/ssl/', '/certs/', '/pki/', '/ssh/', '/tls/',
    '/certificates/', '/private/',
];

const PEM_HEADERS = [
    '-----BEGIN CERTIFICATE-----',
    '-----BEGIN PRIVATE KEY-----',
    '-----BEGIN RSA PRIVATE KEY-----',
    '-----BEGIN EC PRIVATE KEY-----',
    '-----BEGIN PUBLIC KEY-----',
    '-----BEGIN ENCRYPTED PRIVATE KEY-----',
    '-----BEGIN X509 CERTIFICATE-----',
];

/**
 * Determine if a file is likely a certificate or key based on path and content.
 * @param {string} path - File path
 * @param {Uint8Array} data - File content
 * @returns {boolean}
 */
export function isCryptoFile(path, data) {
    // Check file extension
    const lowerPath = path.toLowerCase();
    const lastDot = lowerPath.lastIndexOf('.');
    if (lastDot >= 0) {
        const ext = lowerPath.substring(lastDot);
        if (CRYPTO_EXTENSIONS.has(ext)) return true;
    }

    // Check path patterns
    for (const pattern of CRYPTO_PATH_PATTERNS) {
        if (lowerPath.includes(pattern)) return true;
    }

    // Check PEM headers (first 40 bytes is enough)
    if (data.length >= 11) {
        const header = new TextDecoder().decode(data.subarray(0, Math.min(data.length, 64)));
        for (const pemHeader of PEM_HEADERS) {
            if (header.startsWith(pemHeader)) return true;
        }
    }

    // Check DER magic bytes: ASN.1 SEQUENCE with 2-byte length (0x30 0x82)
    if (data.length >= 4 && data[0] === 0x30 && data[1] === 0x82) {
        return true;
    }

    return false;
}

// ── PEM helpers ──────────────────────────────────────────────────────

/**
 * Convert a single PEM block to DER bytes.
 * @param {string} pem - PEM-encoded data (with or without headers)
 * @returns {Uint8Array} DER bytes
 */
function pemToDer(pem) {
    const b64 = pem
        .split('\n')
        .filter(line => !line.startsWith('-----') && line.trim().length > 0)
        .join('');
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Split a PEM file that may contain multiple PEM blocks (certificate chain,
 * or mixed certs and keys) into individual PEM blocks.
 * @param {string} text - PEM file content
 * @returns {Array<{type: string, pem: string}>} Array of {type, pem} objects
 */
function splitPemBlocks(text) {
    const blocks = [];
    const regex = /(-----BEGIN ([^-]+)-----[\s\S]*?-----END \2-----)/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
        blocks.push({
            type: match[2].trim(),
            pem: match[1],
        });
    }
    return blocks;
}

/**
 * Check if raw data starts with a PEM header.
 * @param {Uint8Array} data
 * @returns {boolean}
 */
function isPem(data) {
    if (data.length < 11) return false;
    return data[0] === 0x2d && data[1] === 0x2d && data[2] === 0x2d &&
           data[3] === 0x2d && data[4] === 0x2d && data[5] === 0x42; // "-----B"
}

// ── DN formatting ────────────────────────────────────────────────────

/**
 * Convert a pkijs RelativeDistinguishedNames to a one-line DN string.
 * Output format: "CN=example.com, O=Example Corp, C=US"
 * @param {import('pkijs').RelativeDistinguishedNames} rdnSeq
 * @returns {string}
 */
function dnToString(rdnSeq) {
    if (!rdnSeq || !rdnSeq.typesAndValues || rdnSeq.typesAndValues.length === 0) {
        return '';
    }

    return rdnSeq.typesAndValues
        .map(tv => {
            const name = DN_OID_MAP[tv.type] || tv.type;
            const value = tv.value?.valueBlock?.value ?? '';
            return `${name}=${value}`;
        })
        .join(', ');
}

// ── Algorithm name resolution ────────────────────────────────────────

/**
 * Resolve an OID to a human-readable algorithm name.
 * @param {string} oid
 * @returns {string}
 */
function oidToName(oid) {
    return ALGORITHM_OID_MAP[oid] || oid;
}

/**
 * Resolve an OID to a curve name.
 * @param {string} oid
 * @returns {string}
 */
function oidToCurveName(oid) {
    return CURVE_OID_MAP[oid] || oid;
}

/**
 * Get the public key algorithm family name (RSA, EC, Ed25519, etc.)
 * from the SubjectPublicKeyInfo algorithm OID.
 * @param {string} oid
 * @returns {string}
 */
function pubkeyAlgorithmFamily(oid) {
    switch (oid) {
        case '1.2.840.113549.1.1.1': return 'RSA';
        case '1.2.840.10045.2.1':    return 'EC';
        case '1.3.101.112':          return 'Ed25519';
        case '1.3.101.113':          return 'Ed448';
        case '1.2.840.10040.4.1':    return 'DSA';
        default:                     return oidToName(oid);
    }
}

// ── Fingerprint ──────────────────────────────────────────────────────

/**
 * Compute SHA-256 fingerprint of DER-encoded data.
 * Returns colon-separated hex string (e.g., "ab:cd:ef:...")
 * @param {Uint8Array} derBytes
 * @returns {string}
 */
function sha256Hex(derBytes) {
    const hash = sha256(derBytes);
    return Array.from(hash)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(':');
}

// ── Key size extraction ──────────────────────────────────────────────

/**
 * Extract the public key size in bits from a certificate's SubjectPublicKeyInfo.
 * @param {import('pkijs').Certificate} cert
 * @returns {number} Key size in bits, or 0 if unknown
 */
function getPublicKeySize(cert) {
    const spki = cert.subjectPublicKeyInfo;
    const algOid = spki.algorithm.algorithmId;

    // RSA: modulus length from parsed key
    if (algOid === '1.2.840.113549.1.1.1' && spki.parsedKey?.modulus) {
        const modulusHex = spki.parsedKey.modulus.valueBlock.valueHexView;
        // Strip leading zero byte if present (ASN.1 integer sign padding)
        let bitLen = modulusHex.length * 8;
        if (modulusHex.length > 0 && modulusHex[0] === 0) {
            bitLen -= 8;
        }
        return bitLen;
    }

    // EC: derive from named curve
    if (algOid === '1.2.840.10045.2.1') {
        const curveOid = getCurveOid(cert);
        switch (curveOid) {
            case '1.2.840.10045.3.1.7': return 256;  // P-256
            case '1.3.132.0.34':        return 384;  // P-384
            case '1.3.132.0.35':        return 521;  // P-521
            case '1.3.132.0.10':        return 256;  // secp256k1
        }
    }

    // Ed25519
    if (algOid === '1.3.101.112') return 256;
    // Ed448
    if (algOid === '1.3.101.113') return 448;
    // DSA: from public key bit string length
    if (algOid === '1.2.840.10040.4.1') {
        return spki.subjectPublicKey.valueBlock.valueHexView.length * 8;
    }

    return 0;
}

/**
 * Get the EC named curve OID from a certificate's SubjectPublicKeyInfo.
 * @param {import('pkijs').Certificate} cert
 * @returns {string} Curve OID or empty string
 */
function getCurveOid(cert) {
    const params = cert.subjectPublicKeyInfo.algorithm.algorithmParams;
    if (params instanceof asn1js.ObjectIdentifier) {
        return params.valueBlock.toString();
    }
    return '';
}

// ── Certificate parsing ──────────────────────────────────────────────

/**
 * Parse a single DER-encoded certificate and extract metadata.
 * @param {Uint8Array} derBytes - DER-encoded certificate
 * @param {string} filePath - Original file path (for metadata)
 * @returns {Object} CertMetadata or null on failure
 */
function parseSingleCert(derBytes, filePath) {
    const cert = Certificate.fromBER(derBytes);

    const sigAlgOid = cert.signatureAlgorithm.algorithmId;
    const pubkeyAlgOid = cert.subjectPublicKeyInfo.algorithm.algorithmId;
    const curveOid = getCurveOid(cert);

    // Check BasicConstraints for CA flag
    let isCa = false;
    const bcExt = cert.extensions?.find(e => e.extnID === '2.5.29.19');
    if (bcExt && bcExt.parsedValue) {
        isCa = !!bcExt.parsedValue.cA;
    }

    // Self-signed: subject equals issuer
    const isSelfSigned = cert.subject.isEqual(cert.issuer);

    return {
        filePath,
        subject: dnToString(cert.subject),
        issuer: dnToString(cert.issuer),
        serialNumber: Array.from(cert.serialNumber.valueBlock.valueHexView)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('').toUpperCase(),
        notBefore: cert.notBefore.value.toISOString(),
        notAfter: cert.notAfter.value.toISOString(),
        signatureAlgorithm: oidToName(sigAlgOid),
        signatureAlgorithmOid: sigAlgOid,
        publicKeyAlgorithm: pubkeyAlgorithmFamily(pubkeyAlgOid),
        publicKeyAlgorithmOid: pubkeyAlgOid,
        publicKeySize: getPublicKeySize(cert),
        namedCurve: curveOid ? oidToCurveName(curveOid) : '',
        fingerprintSha256: sha256Hex(derBytes),
        isCa,
        isSelfSigned,
    };
}

// ── Key parsing ──────────────────────────────────────────────────────

/**
 * Parse a single DER-encoded key and extract metadata.
 * @param {Uint8Array} derBytes - DER-encoded key data
 * @param {string} filePath - Original file path
 * @param {string} format - "PEM" or "DER"
 * @param {string} pemType - PEM block type (e.g., "PRIVATE KEY", "RSA PRIVATE KEY")
 * @returns {Object} KeyMetadata or null on failure
 */
function parseSingleKey(derBytes, filePath, format, pemType) {
    // Try PKCS#8 (PrivateKeyInfo) first — this is the standard format
    if (pemType === 'PRIVATE KEY' || pemType === '' || pemType === 'PUBLIC KEY') {
        try {
            const keyInfo = PrivateKeyInfo.fromBER(derBytes);
            const algOid = keyInfo.privateKeyAlgorithm.algorithmId;
            const family = pubkeyAlgorithmFamily(algOid);

            let keySize = 0;
            let namedCurve = '';

            if (family === 'RSA' && keyInfo.parsedKey?.modulus) {
                const modulusHex = keyInfo.parsedKey.modulus.valueBlock.valueHexView;
                keySize = modulusHex.length * 8;
                if (modulusHex.length > 0 && modulusHex[0] === 0) keySize -= 8;
            } else if (family === 'EC') {
                // Curve OID from algorithm params
                const params = keyInfo.privateKeyAlgorithm.algorithmParams;
                if (params instanceof asn1js.ObjectIdentifier) {
                    const curveOid = params.valueBlock.toString();
                    namedCurve = oidToCurveName(curveOid);
                    switch (curveOid) {
                        case '1.2.840.10045.3.1.7': keySize = 256; break;
                        case '1.3.132.0.34':        keySize = 384; break;
                        case '1.3.132.0.35':        keySize = 521; break;
                        case '1.3.132.0.10':        keySize = 256; break;
                    }
                }
            } else if (family === 'Ed25519') {
                keySize = 256;
            } else if (family === 'Ed448') {
                keySize = 448;
            }

            return {
                filePath,
                algorithm: family,
                algorithmOid: algOid,
                keySize,
                namedCurve,
                format,
            };
        } catch {
            // Not PKCS#8 — fall through to legacy formats
        }
    }

    // Legacy RSA private key (PKCS#1)
    if (pemType === 'RSA PRIVATE KEY' || pemType === '') {
        try {
            const rsaKey = RSAPrivateKey.fromBER(derBytes);
            const modulusHex = rsaKey.modulus.valueBlock.valueHexView;
            let keySize = modulusHex.length * 8;
            if (modulusHex.length > 0 && modulusHex[0] === 0) keySize -= 8;

            return {
                filePath,
                algorithm: 'RSA',
                algorithmOid: '1.2.840.113549.1.1.1',
                keySize,
                namedCurve: '',
                format,
            };
        } catch {
            // Not PKCS#1 RSA — fall through
        }
    }

    // Legacy EC private key (SEC1)
    if (pemType === 'EC PRIVATE KEY' || pemType === '') {
        try {
            const ecKey = ECPrivateKey.fromBER(derBytes);
            const curveOid = ecKey.namedCurve || '';
            const namedCurve = curveOid ? oidToCurveName(curveOid) : '';
            let keySize = 0;
            switch (curveOid) {
                case '1.2.840.10045.3.1.7': keySize = 256; break;
                case '1.3.132.0.34':        keySize = 384; break;
                case '1.3.132.0.35':        keySize = 521; break;
                case '1.3.132.0.10':        keySize = 256; break;
            }

            return {
                filePath,
                algorithm: 'EC',
                algorithmOid: '1.2.840.10045.2.1',
                keySize,
                namedCurve,
                format,
            };
        } catch {
            // Not SEC1 EC — fall through
        }
    }

    // OpenSSH private key format (not ASN.1 — custom binary)
    if (pemType === 'OPENSSH PRIVATE KEY') {
        try {
            return parseOpenSSHKey(derBytes, filePath);
        } catch {
            // Failed to parse OpenSSH format
        }
    }

    return null;
}

/**
 * Parse an OpenSSH private key (binary format, not ASN.1).
 *
 * Format: "openssh-key-v1\0" magic, followed by:
 *   string cipher, string kdf, string kdf_options, uint32 nkeys,
 *   string[] public_keys, string encrypted_section
 *
 * The public key string contains the key type and parameters we need.
 *
 * @param {Uint8Array} data - Base64-decoded key bytes
 * @param {string} filePath
 * @returns {Object|null} KeyMetadata
 */
function parseOpenSSHKey(data, filePath) {
    const MAGIC = 'openssh-key-v1\0';
    const header = new TextDecoder().decode(data.subarray(0, MAGIC.length));
    if (header !== MAGIC) return null;

    let offset = MAGIC.length;

    // Read a uint32 (big-endian)
    function readUint32() {
        if (offset + 4 > data.length) throw new Error('truncated');
        const val = (data[offset] << 24) | (data[offset+1] << 16) |
                    (data[offset+2] << 8) | data[offset+3];
        offset += 4;
        return val >>> 0;
    }

    // Read a length-prefixed string/bytes
    function readString() {
        const len = readUint32();
        if (offset + len > data.length) throw new Error('truncated');
        const val = data.subarray(offset, offset + len);
        offset += len;
        return val;
    }

    // Skip: cipher, kdf, kdf_options
    readString(); // cipher
    readString(); // kdf
    readString(); // kdf_options

    const nkeys = readUint32();
    if (nkeys < 1) return null;

    // Read first public key
    const pubKeyBlob = readString();

    // Parse public key type from the blob
    let pkOffset = 0;
    function readPkUint32() {
        const val = (pubKeyBlob[pkOffset] << 24) | (pubKeyBlob[pkOffset+1] << 16) |
                    (pubKeyBlob[pkOffset+2] << 8) | pubKeyBlob[pkOffset+3];
        pkOffset += 4;
        return val >>> 0;
    }
    function readPkString() {
        const len = readPkUint32();
        const val = pubKeyBlob.subarray(pkOffset, pkOffset + len);
        pkOffset += len;
        return val;
    }

    const keyTypeBytes = readPkString();
    const keyType = new TextDecoder().decode(keyTypeBytes);

    if (keyType === 'ssh-rsa') {
        const e = readPkString(); // public exponent
        const n = readPkString(); // modulus
        let keySize = n.length * 8;
        if (n.length > 0 && n[0] === 0) keySize -= 8;

        return {
            filePath,
            algorithm: 'RSA',
            algorithmOid: '1.2.840.113549.1.1.1',
            keySize,
            namedCurve: '',
            format: 'OpenSSH',
        };
    }

    if (keyType.startsWith('ecdsa-sha2-')) {
        const curveId = new TextDecoder().decode(readPkString());
        let keySize = 0;
        let namedCurve = curveId;
        switch (curveId) {
            case 'nistp256': keySize = 256; namedCurve = 'P-256'; break;
            case 'nistp384': keySize = 384; namedCurve = 'P-384'; break;
            case 'nistp521': keySize = 521; namedCurve = 'P-521'; break;
        }

        return {
            filePath,
            algorithm: 'EC',
            algorithmOid: '1.2.840.10045.2.1',
            keySize,
            namedCurve,
            format: 'OpenSSH',
        };
    }

    if (keyType === 'ssh-ed25519') {
        return {
            filePath,
            algorithm: 'Ed25519',
            algorithmOid: '1.3.101.112',
            keySize: 256,
            namedCurve: '',
            format: 'OpenSSH',
        };
    }

    if (keyType === 'ssh-ed448') {
        return {
            filePath,
            algorithm: 'Ed448',
            algorithmOid: '1.3.101.113',
            keySize: 448,
            namedCurve: '',
            format: 'OpenSSH',
        };
    }

    if (keyType === 'ssh-dss') {
        return {
            filePath,
            algorithm: 'DSA',
            algorithmOid: '1.2.840.10040.4.1',
            keySize: 1024,
            namedCurve: '',
            format: 'OpenSSH',
        };
    }

    return null;
}

// ── Main export ──────────────────────────────────────────────────────

/**
 * Scan extracted files for certificates and keys, parse them with pkijs.
 * @param {Map<string, Uint8Array>} files - From archive extraction (path → content)
 * @param {Object} [options]
 * @param {function} [options.onProgress] - Callback: ({certsFound, keysFound, currentFile})
 * @returns {Promise<{certs: Object[], keys: Object[], warnings: string[]}>}
 */
export async function parseCryptoAssets(files, options = {}) {
    const { onProgress = null } = options;

    const certs = [];
    const keys = [];
    const warnings = [];

    for (const [path, data] of files) {
        if (!isCryptoFile(path, data)) continue;

        try {
            if (isPem(data)) {
                // PEM file — may contain multiple blocks (cert chain, mixed certs+keys)
                const text = new TextDecoder().decode(data);
                const blocks = splitPemBlocks(text);

                if (blocks.length === 0) {
                    // PEM-like but no valid blocks found
                    warnings.push(`${path}: no valid PEM blocks found`);
                    continue;
                }

                for (const block of blocks) {
                    try {
                        const derBytes = pemToDer(block.pem);
                        processBlock(derBytes, path, 'PEM', block.type, certs, keys, warnings);
                    } catch (err) {
                        warnings.push(`${path}: failed to parse PEM block (${block.type}): ${err.message}`);
                    }
                }
            } else {
                // DER or unknown binary format
                processBlock(data, path, 'DER', '', certs, keys, warnings);
            }
        } catch (err) {
            warnings.push(`${path}: ${err.message}`);
        }

        if (onProgress) {
            onProgress({
                certsFound: certs.length,
                keysFound: keys.length,
                currentFile: path,
            });
        }
    }

    return { certs, keys, warnings };
}

/**
 * Process a single DER block — try as certificate first, then as key.
 * @param {Uint8Array} derBytes
 * @param {string} filePath
 * @param {string} format - "PEM" or "DER"
 * @param {string} pemType - PEM header type
 * @param {Object[]} certs - accumulator
 * @param {Object[]} keys - accumulator
 * @param {string[]} warnings - accumulator
 */
function processBlock(derBytes, filePath, format, pemType, certs, keys, warnings) {
    const isCertType = pemType === 'CERTIFICATE' || pemType === 'X509 CERTIFICATE';
    const isKeyType = pemType.includes('PRIVATE KEY') || pemType === 'PUBLIC KEY';
    const isEncrypted = pemType === 'ENCRYPTED PRIVATE KEY';

    if (isEncrypted) {
        warnings.push(`${filePath}: encrypted private key, cannot parse without password`);
        return;
    }

    // Try certificate first (unless PEM type says it's a key)
    if (!isKeyType) {
        try {
            const certMeta = parseSingleCert(derBytes, filePath);
            if (certMeta) {
                certs.push(certMeta);
                return;
            }
        } catch {
            // Not a certificate — try key if PEM type is ambiguous
            if (isCertType) {
                warnings.push(`${filePath}: failed to parse as certificate`);
                return;
            }
        }
    }

    // Try key
    if (!isCertType) {
        const keyMeta = parseSingleKey(derBytes, filePath, format, pemType);
        if (keyMeta) {
            keys.push(keyMeta);
            return;
        }
    }

    // Neither cert nor key
    if (pemType) {
        warnings.push(`${filePath}: unrecognized PEM type "${pemType}"`);
    }
}
