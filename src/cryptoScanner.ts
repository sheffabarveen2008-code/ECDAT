import { CryptoFinding, CryptoRule } from './types';

export const ALLOWED_EXTENSIONS = [
  '.java', '.py', '.js', '.ts', '.go', '.c', '.h', '.pem', '.key', '.crt',
  '.xml', '.json', '.gradle', '.properties', '.yml', '.yaml', 'dockerfile'
];

export const CRYPTO_RULES: CryptoRule[] = [
  {
    id: 'RSA-2048',
    algo: 'RSA-2048 / RSA Asymmetric',
    type: 'Algorithm',
    regex: /BEGIN RSA PRIVATE KEY|RSA\.generateKeyPair|RSA.*2048|KeyPairGenerator.*RSA/gi,
    risk: 100,
    pqcTarget: 'ML-KEM-768 (NIST FIPS 203) / ML-DSA-65 (NIST FIPS 204)',
    quantumVuln: true
  },
  {
    id: 'ECDSA-P256',
    algo: 'ECDSA P-256 / Elliptic Curve Signature',
    type: 'Algorithm',
    regex: /ecdsa|prime256v1|secp256r1|secp384r1|BEGIN EC PRIVATE KEY/gi,
    risk: 100,
    pqcTarget: 'ML-DSA-65 / ML-DSA-87 (NIST FIPS 204) or SLH-DSA (FIPS 205)',
    quantumVuln: true
  },
  {
    id: 'ECDH-DH',
    algo: 'ECDH / Diffie-Hellman Key Agreement',
    type: 'Algorithm',
    regex: /ECDH|DiffieHellman/gi,
    risk: 100,
    pqcTarget: 'ML-KEM-768 (NIST FIPS 203) / Hybrid KEM (X25519MLKEM768)',
    quantumVuln: true
  },
  {
    id: 'TLS-WEAK',
    algo: 'Legacy TLS (v1.0 / v1.1)',
    type: 'Protocol',
    regex: /TLSv1\.0|TLSv1\.1|PROTOCOL_TLSv1/gi,
    risk: 90,
    pqcTarget: 'TLS 1.3 with Hybrid Post-Quantum Key Exchange',
    quantumVuln: true
  },
  {
    id: 'SHA1-MD5',
    algo: 'Weak Hash Function (SHA-1 / MD5)',
    type: 'Algorithm',
    regex: /SHA1\(|hashlib\.sha1|MD5/gi,
    risk: 85,
    pqcTarget: 'SHA-256 / SHA-3 / SHAKE-256 (NIST FIPS 202)',
    quantumVuln: false
  },
  {
    id: 'BOUNCY-CASTLE',
    algo: 'BouncyCastle Cryptographic Provider',
    type: 'Library',
    regex: /BouncyCastle|bcprov/gi,
    risk: 60,
    pqcTarget: 'BouncyCastle PQC Edition (LTS with ML-KEM/ML-DSA)',
    quantumVuln: true
  },
  {
    id: 'OPENSSL',
    algo: 'OpenSSL Crypto Engine',
    type: 'Library',
    regex: /OpenSSL\s+\d+\.\d+/gi,
    risk: 80,
    pqcTarget: 'OpenSSL 3.4+ / OQS Post-Quantum Provider (liboqs)',
    quantumVuln: true
  },
  {
    id: 'JCA-JCE',
    algo: 'Java Cryptography Architecture (Cipher/KeyGen)',
    type: 'Library',
    regex: /Cipher\.getInstance|KeyPairGenerator/gi,
    risk: 50,
    pqcTarget: 'JDK 24+ PQC Security Providers / JCA PQC Plugins',
    quantumVuln: true
  },
  {
    id: 'CRYPTO-IMPORT',
    algo: 'Cryptographic Module / Dependency Import',
    type: 'Dependency',
    regex: /jsonwebtoken|bcrypt|node-forge|require\('crypto'\)/gi,
    risk: 50,
    pqcTarget: 'Quantum-resilient cryptographic wrapper',
    quantumVuln: false
  },
  {
    id: 'X509-CERT',
    algo: 'X.509 Public Key Certificate',
    type: 'Certificate',
    regex: /BEGIN CERTIFICATE/gi,
    risk: 70,
    pqcTarget: 'Composite X.509 or ML-DSA Certificate Hierarchy',
    quantumVuln: true
  }
];

export function isAllowedCodeFile(filename: string): boolean {
  const lower = filename.toLowerCase();
  return ALLOWED_EXTENSIONS.some(ext => lower.endsWith(ext)) || lower.includes('dockerfile');
}

export function scanCodeContent(filename: string, content: string): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  if (!isAllowedCodeFile(filename)) return findings;

  CRYPTO_RULES.forEach((rule, idx) => {
    const regex = new RegExp(rule.regex.source, 'gi');
    let match: RegExpExecArray | null;
    let count = 0;

    while ((match = regex.exec(content)) !== null && count < 3) {
      count++;
      const start = Math.max(0, match.index - 30);
      const end = Math.min(content.length, match.index + match[0].length + 60);
      const snippet = content.substring(start, end).replace(/[\r\n]+/g, ' ').trim();

      let risk = rule.risk;
      let algoName = rule.algo;
      if (rule.id === 'OPENSSL' && /1\.1\.1[a-k]/i.test(content)) {
        risk = 95;
        algoName = 'OpenSSL (Legacy Vulnerable 1.1.1)';
      }

      findings.push({
        id: `${rule.id}-${filename}-${idx}-${count}-${Date.now()}`,
        file: filename,
        algo: algoName,
        type: rule.type,
        risk,
        evidence: snippet,
        pqcTarget: rule.pqcTarget,
        quantumVuln: rule.quantumVuln
      });
    }
  });

  return findings;
}
