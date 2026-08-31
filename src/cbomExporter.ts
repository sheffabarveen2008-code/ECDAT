import { CryptoFinding, MoscaCalculation, MoscaParams } from './types';

export function calculateMoscaTheorem(params: MoscaParams): MoscaCalculation {
  const x = Number(params.x) || 0;
  const y = Number(params.y) || 0;
  const z = Number(params.z) || 0;

  const requiredYears = x + y;
  const isAtRisk = requiredYears > z;
  const delta = Math.abs(Math.round((requiredYears - z) * 10) / 10);

  return {
    x,
    y,
    z,
    requiredYears,
    isAtRisk,
    delta,
    status: isAtRisk ? 'AT RISK' : 'SAFE',
    threatModel: isAtRisk
      ? 'Harvest Now, Decrypt Later (HNDL) Threat Active'
      : 'Compliant Post-Quantum Migration Window',
    recommendation: isAtRisk
      ? `CRITICAL: Data confidentiality lifespan extends ${delta} years beyond the projected arrival of Cryptanalytically Relevant Quantum Computers (CRQC). Encrypted communications captured today can be stored by adversaries and broken immediately upon quantum arrival. Rapid deployment of NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) is mandatory.`
      : `Migration timeframe (${y} yrs) fits within the quantum threshold (${z} yrs). Maintain cryptographic discovery posture and enforce Post-Quantum CBOM compliance across development pipelines.`
  };
}

export function generateCycloneDXCBOM(findings: CryptoFinding[], projectName: string = 'ECDAT Cryptographic Scan') {
  const timestamp = new Date().toISOString();

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${crypto.randomUUID ? crypto.randomUUID() : 'ecdat-cbom-1'}`,
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: [
          {
            type: 'application',
            name: 'ECDAT - Enterprise Cryptographic Discovery & Analysis Tool',
            version: '1.0.0',
            vendor: 'Enterprise Post-Quantum Security'
          }
        ]
      },
      component: {
        type: 'application',
        name: projectName,
        version: '1.0.0'
      }
    },
    components: findings.map((f, i) => ({
      'bom-ref': `crypto-asset-${i + 1}`,
      type: 'cryptographic-asset',
      name: f.algo,
      version: '1.0',
      description: `Cryptographic artifact detected in ${f.file}`,
      cryptoProperties: {
        assetType: f.type.toLowerCase(),
        algorithmProperties: {
          name: f.algo,
          parameterSetIdentifier: f.risk >= 90 ? 'Classical / Asymmetric' : 'Standard',
          nistQuantumSecurityLevel: f.quantumVuln ? 0 : 5
        },
        detectionEvidence: {
          filePath: f.file,
          snippet: f.evidence,
          riskScore: f.risk,
          sha256: f.sha256
        },
        pqcRemediationTarget: f.pqcTarget || 'NIST FIPS 203/204/205 Standards'
      }
    }))
  };
}

export function exportJsonFile(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportCsvFile(findings: CryptoFinding[], filename: string) {
  const headers = ['File', 'Algorithm', 'Type', 'Risk', 'Evidence', 'PQC_Target', 'SHA256'];
  const rows = findings.map(f => [
    `"${(f.file || '').replace(/"/g, '""')}"`,
    `"${(f.algo || '').replace(/"/g, '""')}"`,
    `"${(f.type || '').replace(/"/g, '""')}"`,
    f.risk,
    `"${(f.evidence || '').replace(/"/g, '""')}"`,
    `"${(f.pqcTarget || '').replace(/"/g, '""')}"`,
    `"${(f.sha256 || '').replace(/"/g, '""')}"`
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
