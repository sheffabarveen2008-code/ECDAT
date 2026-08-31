export interface CryptoFinding {
  id: string;
  file: string;
  algo: string;
  type: 'Algorithm' | 'Certificate' | 'Library' | 'Protocol' | 'Dependency';
  risk: number;
  evidence: string;
  pqcTarget: string;
  quantumVuln: boolean;
  sha256?: string;
}

export interface CryptoRule {
  id: string;
  algo: string;
  type: 'Algorithm' | 'Certificate' | 'Library' | 'Protocol' | 'Dependency';
  regex: RegExp;
  risk: number;
  pqcTarget: string;
  quantumVuln: boolean;
}

export interface ScanStats {
  totalAssets: number;
  quantumVuln: number;
  critical: number;
  pqcReady: number;
  filesScanned: number;
}

export interface MoscaParams {
  x: number; // Shelf-life in years
  y: number; // Migration time in years
  z: number; // CRQC arrival in years
}

export interface MoscaCalculation {
  x: number;
  y: number;
  z: number;
  requiredYears: number;
  isAtRisk: boolean;
  delta: number;
  status: 'AT RISK' | 'SAFE';
  threatModel: string;
  recommendation: string;
}
