import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  FolderOpen,
  FileCode,
  Binary,
  Layers,
  FileSpreadsheet,
  FileText,
  RefreshCw,
  Terminal,
  AlertTriangle,
  KeyRound,
  Download,
  Printer,
  ChevronRight,
  ExternalLink,
  Shield,
  Clock,
  Sparkles,
  Info,
  CheckCircle2,
  XCircle,
  Database
} from 'lucide-react';
import { CryptoFinding, MoscaParams, MoscaCalculation } from './types';
import { ALLOWED_EXTENSIONS, scanCodeContent } from './cryptoScanner';
import {
  calculateMoscaTheorem,
  generateCycloneDXCBOM,
  exportJsonFile,
  exportCsvFile
} from './cbomExporter';

const BACKEND_URL = 'http://localhost:8000';

export default function App() {
  // CRITICAL REQUIREMENT 1: NO AUTO-LOAD / START AT ZERO
  const [findings, setFindings] = useState<CryptoFinding[]>([]);
  const [logs, setLogs] = useState<string[]>([
    `[${new Date().toLocaleTimeString()}] System initialized. Awaiting user scan command...`
  ]);
  const [filterQuery, setFilterQuery] = useState('');
  
  // GitHub Scanner State
  const [githubUrl, setGithubUrl] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [showTokenInput, setShowTokenInput] = useState(false);
  const [isScanningGithub, setIsScanningGithub] = useState(false);
  const [githubStatus, setGithubStatus] = useState('Ready to scan. Enter a repository URL.');

  // Local Scanners State
  const [folderStatus, setFolderStatus] = useState('No folder selected.');
  const [forensicStatus, setForensicStatus] = useState('Forensic engine standing by.');
  const [isProcessingLocal, setIsProcessingLocal] = useState(false);

  // Backend connection status
  const [backendConnected, setBackendConnected] = useState<boolean | null>(null);

  // Mosca Calculator State
  const [moscaParams, setMoscaParams] = useState<MoscaParams>({
    x: 10, // Data shelf life (yrs)
    y: 5,  // Migration time (yrs)
    z: 8   // CRQC arrival (yrs)
  });

  useEffect(()=>{
    setMoscaResult(calculateMoscaTheorem(moscaParams));
  }, [moscaParams]);
  const [moscaResult, setMoscaResult] = useState<MoscaCalculation>(() =>
    calculateMoscaTheorem(moscaParams)
  );

  // Log container auto-scroll ref
  const logsContainerRef = useRef<HTMLDivElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const binaryInputRef = useRef<HTMLInputElement>(null);
  const depInputRef = useRef<HTMLInputElement>(null);

  // Check FastAPI backend on mount
  useEffect(() => {
    async function checkBackend() {
      try {
        const res = await fetch(`${BACKEND_URL}/`, {
          method: 'GET',
          signal: AbortSignal.timeout(1500)
        });
        if (res.ok) {
          setBackendConnected(true);
          appendLog('FastAPI Backend detected at http://localhost:8000 (Connected)');
          return;
        }
      } catch {
        // Standalone client mode
      }
      setBackendConnected(false);
      appendLog('Operating in Client Standalone Mode (Direct GitHub API & WebCrypto)');
    }
    checkBackend();
  }, []);

  // Update Mosca whenever inputs change
  useEffect(() => {
    setMoscaResult(calculateMoscaTheorem(moscaParams));
  }, [moscaParams]);

  // Append a message to the logs
  const appendLog = (msg: string) => {
    const timestamp = new Date().toLocaleTimeString();
    const entry = `[${timestamp}] ${msg}`;
    setLogs(prev => [...prev, entry]);
    setTimeout(() => {
      if (logsContainerRef.current) {
        logsContainerRef.current.scrollTop = logsContainerRef.current.scrollHeight;
      }
    }, 50);
  };

  const clearLogs = () => {
    setLogs([]);
  };

  // Clear all findings and reset to initial zero state
  const handleClearAll = () => {
    setFindings([]);
    setGithubStatus('Ready to scan. Enter a repository URL.');
    setFolderStatus('No folder selected.');
    setForensicStatus('Forensic engine standing by.');
    clearLogs();
    appendLog('System state cleared. Ready for fresh discovery.');
  };

  // -------------------------------------------------------------
  // GITHUB SCANNER LOGIC (Real API + Backend Integration)
  // -------------------------------------------------------------
  const handleGithubScan = async () => {
    const rawUrl = githubUrl.trim();
    if (!rawUrl) {
      alert('Please enter a valid GitHub repository URL (e.g., https://github.com/sigstore/cosign or https://github.com/openssl/openssl)');
      return;
    }

    setIsScanningGithub(true);
    setGithubStatus('Connecting to repository...');
    appendLog(`[*] Commencing discovery scan for: ${rawUrl}`);

    // Option A: Try FastAPI Backend if available
    if (backendConnected) {
      try {
        setGithubStatus('Scanning via FastAPI Backend...');
        const res = await fetch(`${BACKEND_URL}/api/scan/github`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            repo_url: rawUrl,
            token: githubToken.trim() || null
          })
        });

        if (res.ok) {
          const data = await res.json();
          if (data.logs && Array.isArray(data.logs)) {
            data.logs.forEach((l: string) => appendLog(l));
          }
          const scannedFindings: CryptoFinding[] = (data.findings || []).map((f: any, idx: number) => ({
            id: `be-${idx}-${Date.now()}`,
            file: f.file,
            algo: f.algo,
            type: f.type,
            risk: f.risk,
            evidence: f.evidence,
            pqcTarget: f.pqc_target || 'NIST FIPS 203/204/205',
            quantumVuln: f.quantum_vuln ?? true,
            sha256: f.sha256
          }));
          setFindings(scannedFindings);
          setGithubStatus(`Done! Discovered ${scannedFindings.length} artifacts in ${data.total_files_scanned} files.`);
          setIsScanningGithub(false);
          return;
        }
      } catch (e: any) {
        appendLog(`[WARN] Backend scan request failed (${e.message}), failing over to client GitHub API...`);
      }
    }

    // Option B: Client-Side GitHub API Scanning
    try {
      const cleaned = rawUrl
        .replace('https://github.com/', '')
        .replace('http://github.com/', '')
        .replace(/\/$/, '');
      const parts = cleaned.split('/');
      if (parts.length < 2) {
        throw new Error('Invalid repository format. Expected: https://github.com/owner/repo');
      }

      const owner = parts[0];
      const repo = parts[1].replace('.git', '');

      const headers: Record<string, string> = {
        Accept: 'application/vnd.github.v3+json'
      };
      if (githubToken.trim()) {
        headers['Authorization'] = `token ${githubToken.trim()}`;
      }

      appendLog(`[*] Fetching GitHub repository metadata for ${owner}/${repo}...`);
      const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });

      if (repoRes.status === 403) {
        throw new Error('GitHub API rate limit exceeded (60 req/hr unauthenticated). Please provide a personal GitHub Token in the box above.');
      }
      if (repoRes.status === 404) {
        throw new Error(`Repository '${owner}/${repo}' was not found or is private.`);
      }
      if (!repoRes.ok) {
        throw new Error(`GitHub API error: status ${repoRes.status}`);
      }

      const repoData = await repoRes.json();
      const defaultBranch = repoData.default_branch || 'main';
      appendLog(`[+] Repository identified: ${owner}/${repo} (Default Branch: ${defaultBranch}, Stars: ${repoData.stargazers_count})`);

      setGithubStatus(`Fetching git tree from '${defaultBranch}'...`);
      let treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`, { headers });
      
      if (!treeRes.ok && defaultBranch === 'main') {
        appendLog(`[*] Retrying git tree fetch on 'master' branch...`);
        treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/master?recursive=1`, { headers });
      }

      if (!treeRes.ok) {
        throw new Error(`Unable to fetch git tree for repository (${treeRes.status})`);
      }

      const treeData = await treeRes.json();
      const blobs = (treeData.tree || []).filter((item: any) => {
        if (item.type !== 'blob') return false;
        const p = (item.path || '').toLowerCase();
        if (p.includes('node_modules/') || p.includes('.git/') || p.includes('vendor/') || p.includes('dist/')) {
          return false;
        }
        return ALLOWED_EXTENSIONS.some(ext => p.endsWith(ext)) || p.includes('dockerfile');
      });

      appendLog(`[+] Discovered ${blobs.length} candidate code files in git tree.`);
      // Slicing top 70 files to protect user rate limits
      const candidateFiles = blobs.slice(0, 70);
      if (blobs.length > 70) {
        appendLog(`[!] Scanning capped at top 70 code files to prevent client rate limit exhaustion.`);
      }

      let scannedCount = 0;
      const discoveredFindings: CryptoFinding[] = [];

      for (const item of candidateFiles) {
        const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${item.path}`;
        try {
          const rawRes = await fetch(rawUrl);
          if (rawRes.ok) {
            const contentText = await rawRes.text();
            const matches = scanCodeContent(item.path, contentText);
            if (matches.length > 0) {
              discoveredFindings.push(...matches);
              appendLog(`[FOUND] ${matches.length} cryptographic artifact(s) in ${item.path}`);
            }
            scannedCount++;
          }
        } catch {
          // Continue scanning next files
        }
      }

      appendLog(`[+] Discovery complete: ${scannedCount} files scanned, ${discoveredFindings.length} cryptographic items discovered.`);
      setFindings(discoveredFindings);
      setGithubStatus(`Done! ${discoveredFindings.length} artifacts discovered in ${scannedCount} files.`);

    } catch (err: any) {
      appendLog(`[ERROR] ${err.message}`);
      setGithubStatus(`Error: ${err.message}`);
    } finally {
      setIsScanningGithub(false);
    }
  };

  // -------------------------------------------------------------
  // LOCAL FOLDER SCANNER
  // -------------------------------------------------------------
  const handleFolderScan = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setIsProcessingLocal(true);
    setFolderStatus(`Scanning ${files.length} files in local directory...`);
    appendLog(`[*] Analyzing local folder containing ${files.length} selected files...`);

    const newFindings: CryptoFinding[] = [];
    let scanned = 0;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const relPath = file.webkitRelativePath || file.name;
      const lower = relPath.toLowerCase();

      // Skip large files (>1MB), node_modules, .git, images
      if (file.size > 1024 * 1024) continue;
      if (
        lower.includes('node_modules/') ||
        lower.includes('.git/') ||
        lower.endsWith('.png') ||
        lower.endsWith('.jpg') ||
        lower.endsWith('.gif') ||
        lower.endsWith('.pdf')
      ) {
        continue;
      }

      try {
        const text = await file.text();
        const matches = scanCodeContent(relPath, text);
        if (matches.length > 0) {
          newFindings.push(...matches);
          appendLog(`[LOCAL] Found ${matches.length} artifact(s) in ${relPath}`);
        }
        scanned++;
      } catch {
        // ignore unreadable file
      }
    }

    appendLog(`[+] Local scan complete: ${scanned} files inspected, ${newFindings.length} findings catalogued.`);
    setFindings(prev => [...prev, ...newFindings]);
    setFolderStatus(`Local Scan Complete: ${newFindings.length} findings across ${scanned} files.`);
    setIsProcessingLocal(false);
  };

  // -------------------------------------------------------------
  // BINARY & DEPENDENCY FORENSICS
  // -------------------------------------------------------------
  const handleBinaryScan = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setForensicStatus(`Analyzing ${files.length} binary files...`);
    const binaryFindings: CryptoFinding[] = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      appendLog(`[*] Computing SHA-256 digest & extracting strings for: ${file.name}`);

      try {
        const buffer = await file.arrayBuffer();

        // Calculate SHA-256 using Web Crypto
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Decode first 800k bytes as text
        const slice = buffer.slice(0, 800000);
        const text = new TextDecoder('utf-8', { fatal: false }).decode(slice);

        // Check for OpenSSL or libcrypto embedded symbols
        if (text.includes('OpenSSL') || text.includes('libcrypto') || text.includes('libssl')) {
          binaryFindings.push({
            id: `bin-openssl-${i}-${Date.now()}`,
            file: file.name,
            algo: 'OpenSSL Native Shared Object / Library Linked',
            type: 'Library',
            risk: 80,
            evidence: `SHA256: ${hashHex} | Embedded strings match libcrypto/OpenSSL symbols`,
            pqcTarget: 'OpenSSL 3.4+ with liboqs PQC Provider',
            quantumVuln: true,
            sha256: hashHex
          });
        }

        const matches = scanCodeContent(file.name, text);
        matches.forEach(m => {
          m.sha256 = hashHex;
          m.evidence = `SHA256: ${hashHex.substring(0, 16)}... | ${m.evidence}`;
          binaryFindings.push(m);
        });

      } catch (err: any) {
        appendLog(`[WARN] Failed to analyze binary ${file.name}: ${err.message}`);
      }
    }

    appendLog(`[+] Binary forensics completed: ${binaryFindings.length} items logged.`);
    setFindings(prev => [...prev, ...binaryFindings]);
    setForensicStatus(`Binary Analysis Done: ${binaryFindings.length} items logged.`);
  };

  const handleDependencyScan = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setForensicStatus(`Parsing ${files.length} dependency manifests...`);
    const depFindings: CryptoFinding[] = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      appendLog(`[*] Parsing dependency manifest: ${file.name}`);

      try {
        const text = await file.text();

        if (file.name.includes('package.json')) {
          try {
            const pkg = JSON.parse(text);
            const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
            for (const [depName, version] of Object.entries(allDeps)) {
              if (/jsonwebtoken|node-forge|bcrypt|crypto-js|elliptic|secp256k1/i.test(depName)) {
                depFindings.push({
                  id: `dep-pkg-${depName}-${Date.now()}`,
                  file: file.name,
                  algo: `Node Package: ${depName} (${version})`,
                  type: 'Dependency',
                  risk: 65,
                  evidence: `"${depName}": "${version}" in package.json`,
                  pqcTarget: 'Quantum-safe cryptographic wrapper / PQC library',
                  quantumVuln: true
                });
              }
            }
          } catch {
            // Json parse fail
          }
        } else if (file.name.includes('pom.xml')) {
          if (text.includes('bouncycastle') || text.includes('bcprov')) {
            depFindings.push({
              id: `dep-pom-bc-${Date.now()}`,
              file: file.name,
              algo: 'Maven: BouncyCastle Provider Dependency',
              type: 'Dependency',
              risk: 60,
              evidence: 'Maven dependency artifact: bcprov in pom.xml',
              pqcTarget: 'Bouncy Castle LTS PQC edition',
              quantumVuln: true
            });
          }
        } else if (file.name.includes('requirements.txt')) {
          const lines = text.split('\n');
          lines.forEach((line, idx) => {
            const clean = line.trim();
            if (/cryptography|pyopenssl|pyjwt|rsa|ecdsa/i.test(clean)) {
              depFindings.push({
                id: `dep-py-${idx}-${Date.now()}`,
                file: file.name,
                algo: `Python Library: ${clean}`,
                type: 'Dependency',
                risk: 60,
                evidence: clean,
                pqcTarget: 'liboqs-python or PQC-enabled cryptography library',
                quantumVuln: true
              });
            }
          });
        }
      } catch {
        // Read fail
      }
    }

    appendLog(`[+] Dependency manifest scan complete: ${depFindings.length} libraries flagged.`);
    setFindings(prev => [...prev, ...depFindings]);
    setForensicStatus(`Manifests Parsed: ${depFindings.length} dependencies catalogued.`);
  };

  // -------------------------------------------------------------
  // EXPORT HANDLERS
  // -------------------------------------------------------------
  const handleExportJSON = () => {
    if (findings.length === 0) {
      alert('No findings to export. Please run a scan first.');
      return;
    }
    const cbom = generateCycloneDXCBOM(findings, githubUrl || 'ECDAT Local Scan');
    exportJsonFile(cbom, `ecdat-cbom-cyclonedx-1.6-${Date.now()}.json`);
    appendLog(`[+] Exported CycloneDX 1.6 CBOM JSON (${findings.length} components)`);
  };

  const handleExportCSV = () => {
    if (findings.length === 0) {
      alert('No findings to export. Please run a scan first.');
      return;
    }
    exportCsvFile(findings, `ecdat-crypto-inventory-${Date.now()}.csv`);
    appendLog(`[+] Exported Cryptographic Inventory CSV (${findings.length} rows)`);
  };

  const handleExportPDF = () => {
    if (findings.length === 0) {
      alert('No findings to export. Please run a scan first.');
      return;
    }
    window.print();
  };

  // Filter findings for CBOM Table
  const filteredFindings = findings.filter(f => {
    const q = filterQuery.toLowerCase().trim();
    if (!q) return true;
    return (
      f.file.toLowerCase().includes(q) ||
      f.algo.toLowerCase().includes(q) ||
      f.type.toLowerCase().includes(q) ||
      f.evidence.toLowerCase().includes(q)
    );
  });

  // Calculate dynamic KPIs
  const totalAssets = findings.length;
  const quantumVuln = findings.filter(f => f.quantumVuln || f.risk >= 80).length;
  const critical = findings.filter(f => f.risk >= 90).length;
  const pqcReady = findings.filter(f => f.algo.toLowerCase().includes('pqc') || f.risk === 0).length;

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 font-sans antialiased selection:bg-cyan-500 selection:text-white">

      {/* HEADER */}
      <header id="main-header" className="border-b border-slate-800 bg-[#0c1222]/90 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          
          {/* Logo & Title */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-black text-lg tracking-wider text-white">ECDAT</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30 tracking-wide">
                  PQC READY
                </span>
              </div>
              <p className="text-[11px] text-slate-400 uppercase tracking-wider font-mono">
                ENTERPRISE CRYPTOGRAPHIC DISCOVERY &amp; ANALYSIS TOOL
              </p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center gap-6 text-xs font-medium text-slate-300">
            <a href="#discovery-section" className="hover:text-cyan-400 transition-colors">DISCOVERY</a>
            <a href="#cbom-section" className="hover:text-cyan-400 transition-colors">CBOM INVENTORY</a>
            <a href="#risk-section" className="hover:text-cyan-400 transition-colors">RISK</a>
            <a href="#migration-section" className="hover:text-cyan-400 transition-colors">PQC MIGRATION</a>
          </nav>

          {/* Standards & Backend Badge */}
          <div className="flex items-center gap-3">
            <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              NIST FIPS 203/204/205
            </span>
            <div className={`text-[11px] px-2.5 py-1 rounded border font-mono flex items-center gap-1.5 ${
              backendConnected
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
            }`}>
              <Database className="w-3 h-3" />
              <span>{backendConnected ? 'FastAPI Backend' : 'Client Mode'}</span>
            </div>
          </div>

        </div>
      </header>

      {/* HERO SECTION */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6 pb-4">
        <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-xl p-6 relative overflow-hidden">
          <div className="absolute right-0 top-0 w-96 h-full bg-cyan-500/5 blur-3xl pointer-events-none"></div>

          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
            <div className="space-y-2 max-w-3xl">
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
                Post-Quantum Preparedness Dashboard
              </h1>
              <p className="text-sm text-slate-300 leading-relaxed">
                Scan source code repositories, binaries, libraries, and containers to catalogue cryptographic assets into CycloneDX 1.6 CBOM. 
                Quantify your Harvest Now, Decrypt Later (HNDL) exposure with Mosca's Theorem (<span className="font-mono text-cyan-300">X + Y &gt; Z</span>) and map classical algorithms to NIST Post-Quantum Standards.
              </p>

              <div className="flex flex-wrap gap-2 pt-2">
                <span className="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1.5">
                  <ExternalLink className="w-3.5 h-3.5 text-cyan-400" /> Real GitHub API
                </span>
                <span className="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1.5">
                  <Binary className="w-3.5 h-3.5 text-cyan-400" /> Binary Forensics
                </span>
                <span className="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1.5">
                  <FileSpreadsheet className="w-3.5 h-3.5 text-cyan-400" /> CycloneDX CBOM
                </span>
                <span className="text-xs px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 font-semibold font-mono">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" /> 8 yrs CRQC ETA
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 self-start lg:self-center">
              <button
                id="btn-clear-all"
                onClick={handleClearAll}
                className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Clear All Data
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* KPI ROW */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          
          {/* TOTAL ASSETS */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">TOTAL ASSETS</p>
              <p id="kpi-total" className="text-3xl font-black text-white mt-1 font-mono">{totalAssets}</p>
              <p className="text-[11px] text-slate-500 mt-0.5">Discovered crypto instances</p>
            </div>
            <div className="w-11 h-11 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
              <Layers className="w-5 h-5" />
            </div>
          </div>

          {/* QUANTUM-VULN */}
          <div className="bg-slate-900 border border-red-900/30 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-red-400 uppercase tracking-wider">QUANTUM-VULN</p>
              <p id="kpi-vuln" className="text-3xl font-black text-red-400 mt-1 font-mono">{quantumVuln}</p>
              <p className="text-[11px] text-red-400/70 mt-0.5">Shor's Algorithm Breakable</p>
            </div>
            <div className="w-11 h-11 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>

          {/* CRITICAL */}
          <div className="bg-slate-900 border border-amber-900/30 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-amber-400 uppercase tracking-wider">CRITICAL</p>
              <p id="kpi-critical" className="text-3xl font-black text-amber-400 mt-1 font-mono">{critical}</p>
              <p className="text-[11px] text-amber-400/70 mt-0.5">Risk score &ge; 90 / 100</p>
            </div>
            <div className="w-11 h-11 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>

          {/* PQC READY */}
          <div className="bg-slate-900 border border-emerald-900/30 rounded-xl p-4 flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-emerald-400 uppercase tracking-wider">PQC READY</p>
              <p id="kpi-ready" className="text-3xl font-black text-emerald-400 mt-1 font-mono">{pqcReady}</p>
              <p className="text-[11px] text-emerald-400/70 mt-0.5">ML-KEM / ML-DSA / SLH</p>
            </div>
            <div className="w-11 h-11 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>

        </div>
      </section>

      {/* MAIN DUAL-COLUMN WORKSPACE */}
      <main id="discovery-section" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

          {/* LEFT COLUMN (5 cols): 3 DISCOVERY ENGINES & MONOSPACE LOGS */}
          <div className="lg:col-span-5 space-y-6">

            {/* 1. GITHUB REPOSITORY SCANNER */}
            <div id="github-scanner-card" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-white font-semibold text-sm">
                  <span className="w-6 h-6 rounded bg-cyan-500/10 text-cyan-400 flex items-center justify-center text-xs font-mono">1</span>
                  <span>GITHUB REPOSITORY SCANNER</span>
                </div>
                <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">API v3 + Raw</span>
              </div>

              <div className="space-y-3 pt-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Target Repository URL</label>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <span className="absolute inset-y-0 left-0 pl-2.5 flex items-center text-slate-500 text-xs">
                        <Search className="w-3.5 h-3.5" />
                      </span>
                      <input
                        id="github-url-input"
                        type="text"
                        value={githubUrl}
                        onChange={e => setGithubUrl(e.target.value)}
                        placeholder="https://github.com/openssl/openssl"
                        className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-8 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                      />
                    </div>
                    <button
                      id="btn-github-scan"
                      onClick={handleGithubScan}
                      disabled={isScanningGithub}
                      className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-xs flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(6,182,212,0.25)] whitespace-nowrap cursor-pointer disabled:opacity-50"
                    >
                      {isScanningGithub ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Scanning...
                        </>
                      ) : (
                        <>
                          <Search className="w-3.5 h-3.5" /> Scan
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Optional GitHub Token */}
                <div>
                  <button
                    onClick={() => setShowTokenInput(!showTokenInput)}
                    className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    <KeyRound className="w-3 h-3" />
                    <span>{showTokenInput ? 'Hide GitHub Token input' : 'Optional GitHub Token (for high rate limits / private repos)'}</span>
                  </button>
                  {showTokenInput && (
                    <div className="mt-1.5">
                      <input
                        id="github-token-input"
                        type="password"
                        value={githubToken}
                        onChange={e => setGithubToken(e.target.value)}
                        placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                        className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                  )}
                </div>

                {/* Status Indicator */}
                <div id="github-status-box" className="text-xs text-slate-400 bg-slate-950/60 border border-slate-800 rounded-lg p-2.5 flex items-center justify-between">
                  <span>{githubStatus}</span>
                  {isScanningGithub && (
                    <span className="text-cyan-400">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    </span>
                  )}
                </div>

                {/* Scan Log Console */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                      <Terminal className="w-3 h-3" /> REAL-TIME DISCOVERY LOGS
                    </label>
                    <button onClick={clearLogs} className="text-[10px] text-slate-500 hover:text-slate-300 cursor-pointer">
                      Clear
                    </button>
                  </div>
                  <div
                    id="scan-logs"
                    ref={logsContainerRef}
                    className="bg-black/90 border border-slate-800 rounded-lg p-2.5 font-mono text-[11px] text-emerald-400 h-36 overflow-y-auto custom-scrollbar leading-relaxed whitespace-pre-wrap"
                  >
                    {logs.join('\n')}
                  </div>
                </div>
              </div>
            </div>

            {/* 2. LOCAL CODEBASE SCAN */}
            <div id="local-codebase-card" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-white font-semibold text-sm">
                  <span className="w-6 h-6 rounded bg-cyan-500/10 text-cyan-400 flex items-center justify-center text-xs font-mono">2</span>
                  <span>LOCAL CODEBASE SCAN</span>
                </div>
                <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">Directory Picker</span>
              </div>

              <div className="space-y-3 pt-3">
                <div
                  id="folder-drop-zone"
                  onClick={() => folderInputRef.current?.click()}
                  className="border-2 border-dashed border-slate-700 hover:border-cyan-500/70 bg-slate-950/40 rounded-xl p-6 text-center cursor-pointer transition-colors group"
                >
                  <FolderOpen className="w-8 h-8 text-slate-500 group-hover:text-cyan-400 transition-colors mx-auto mb-2" />
                  <p className="text-xs font-semibold text-slate-300 group-hover:text-cyan-300">Browse or Drop Code Folder</p>
                  <p className="text-[11px] text-slate-500 mt-1">Select any project folder containing .java, .py, .go, .js, .pem, etc.</p>
                  <input
                    ref={folderInputRef}
                    id="folder-input"
                    type="file"
                    // @ts-ignore
                    webkitdirectory="true"
                    directory="true"
                    multiple
                    className="hidden"
                    onChange={handleFolderScan}
                  />
                </div>
                <div className="text-xs text-slate-400 bg-slate-950/60 border border-slate-800 rounded-lg p-2">
                  <span>{folderStatus}</span>
                </div>
              </div>
            </div>

            {/* 3. BINARY & DEPENDENCY FORENSICS */}
            <div id="binary-forensics-card" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-white font-semibold text-sm">
                  <span className="w-6 h-6 rounded bg-cyan-500/10 text-cyan-400 flex items-center justify-center text-xs font-mono">3</span>
                  <span>BINARY &amp; DEPENDENCY FORENSICS</span>
                </div>
                <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">SHA-256 + Manifests</span>
              </div>

              <div className="space-y-3 pt-3">
                {/* Binary Files */}
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Binary &amp; Compiled Objects <span className="text-slate-500 font-normal">(.so, .dll, .bin, .pem, .key)</span>
                  </label>
                  <input
                    ref={binaryInputRef}
                    id="binary-input"
                    type="file"
                    multiple
                    onChange={handleBinaryScan}
                    className="w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-400 hover:file:bg-slate-700 cursor-pointer bg-slate-950 border border-slate-800 rounded-lg p-1"
                  />
                </div>

                {/* Dependency Manifests */}
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Dependency Manifests <span className="text-slate-500 font-normal">(package.json, pom.xml, requirements.txt)</span>
                  </label>
                  <input
                    ref={depInputRef}
                    id="dep-input"
                    type="file"
                    multiple
                    onChange={handleDependencyScan}
                    className="w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-400 hover:file:bg-slate-700 cursor-pointer bg-slate-950 border border-slate-800 rounded-lg p-1"
                  />
                </div>

                <div className="text-xs text-slate-400 bg-slate-950/60 border border-slate-800 rounded-lg p-2">
                  <span>{forensicStatus}</span>
                </div>
              </div>
            </div>

          </div>

          {/* RIGHT COLUMN (7 cols): CBOM INVENTORY, RISK ASSESSMENT, PQC ROADMAP, EXPORTS */}
          <div className="lg:col-span-7 space-y-6">

            {/* CBOM RESULTS INVENTORY */}
            <div id="cbom-section" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                <div>
                  <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-cyan-400" />
                    <span>CRYPTOGRAPHIC BILL OF MATERIALS (CBOM)</span>
                  </h2>
                  <p className="text-xs text-slate-400">CycloneDX 1.6 cryptographic asset inventory</p>
                </div>

                <div className="flex items-center gap-2">
                  <div className="relative">
                    <input
                      id="cbom-filter-input"
                      type="text"
                      value={filterQuery}
                      onChange={e => setFilterQuery(e.target.value)}
                      placeholder="Filter findings..."
                      className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-white placeholder-slate-500 w-44 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>
              </div>

              {/* Table Container */}
              <div className="mt-3 overflow-x-auto max-h-80 custom-scrollbar border border-slate-800 rounded-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 font-mono uppercase text-[11px] sticky top-0 z-10 border-b border-slate-800">
                    <tr>
                      <th className="px-3 py-2.5">File / Target</th>
                      <th className="px-3 py-2.5">Algorithm</th>
                      <th className="px-3 py-2.5">Type</th>
                      <th className="px-3 py-2.5 text-center">Risk</th>
                      <th className="px-3 py-2.5">CBOM</th>
                      <th className="px-3 py-2.5">Mosca Risk</th>
                      <th className="px-3 py-2.5">Evidence Snippet</th>
                    </tr>
                  </thead>
                  <tbody id="findings-table-body" className="divide-y divide-slate-800 font-sans">
                    {filteredFindings.length === 0 ? (
                      <tr id="empty-row">
                        <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                          <Layers className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                          No cryptographic findings discovered yet.<br />
                          <span className="text-[11px]">Enter a GitHub URL or select a local code folder to begin discovery.</span>
                        </td>
                      </tr>
                    ) : (
                      filteredFindings.map(item => {
                        let badgeColor = 'bg-blue-500/10 text-blue-400 border-blue-500/30';
                        if (item.risk >= 90) badgeColor = 'bg-red-500/10 text-red-400 border-red-500/30';
                        else if (item.risk >= 60) badgeColor = 'bg-amber-500/10 text-amber-400 border-amber-500/30';

                        return (
                          <tr key={item.id} className="hover:bg-slate-800/50 transition-colors">
                            <td className="px-3 py-2 font-mono text-[11px] text-slate-300 truncate max-w-[150px]" title={item.file}>
                              {item.file}
                            </td>
                            <td className="px-3 py-2 font-medium text-white">{item.algo}</td>
                            <td className="px-3 py-2 text-slate-400">{item.type}</td>
                            <td className="px-3 py-2 text-center">
                              <span className={`px-2 py-0.5 rounded border text-[11px] font-bold font-mono ${badgeColor}`}>
                                {item.risk}
                              </span>
                            </td>
                             <td className="px-3 py-2 text-slate-300 font-mono text-[11px]">
                              Crypto Asset
                              </td>
                            <td className="px-3 py-2 text-center">
                            <span className={`px-2 py-0.5 rounded border text-[11px] font-bold ${
                              moscaResult.isAtRisk
                              ? 'bg-red-500/10 text-red-400 border-red-500/30'
                              : 'bg-emarald-500/10 text-emarald-400 border-emarald-500/30'
                            }'}>
                              {moscaResult.status}
                            </span>
                          </td>
                            <td className="px-3 py-2 text-slate-300 font-mono text-[11px] truncate max-w-[200px]" title={item.evidence}>
                              <code>{item.evidence}</code>
                               </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* Export Buttons */}
              <div className="mt-4 pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
                <span id="findings-count-label" className="text-xs text-slate-400 font-mono">
                  {findings.length} items catalogued
                </span>
                <div className="flex items-center gap-2">
                  <button
                    id="btn-export-json"
                    onClick={handleExportJSON}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" /> Export JSON (CycloneDX 1.6)
                  </button>
                  <button
                    id="btn-export-csv"
                    onClick={handleExportCSV}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer"
                  >
                    <FileSpreadsheet className="w-3.5 h-3.5" /> Export CSV
                  </button>
                  <button
                    id="btn-export-pdf"
                    onClick={handleExportPDF}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer"
                  >
                    <Printer className="w-3.5 h-3.5" /> Export PDF
                  </button>
                </div>
              </div>
            </div>

            {/* RISK ASSESSMENT & MOSCA'S THEOREM */}
            <div id="risk-section" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="pb-3 border-b border-slate-800 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span>QUANTUM RISK ASSESSMENT &amp; MOSCA'S THEOREM</span>
                  </h2>
                  <p className="text-xs text-slate-400">
                    Evaluate Harvest Now, Decrypt Later (HNDL) exposure via <span className="font-mono text-cyan-300">X + Y &gt; Z</span>
                  </p>
                </div>
                <span
                  id="mosca-badge"
                  className={
                    moscaResult.isAtRisk
                      ? 'bg-red-500/10 text-red-400 border-red-500/30'
                      : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  }
                >
                  {moscaResult.status}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3">
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <label className="block text-xs text-slate-300 font-medium mb-1">
                    Data Shelf-Life (<span className="font-mono text-cyan-400">X</span>)
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      id="mosca-x-input"
                      type="number"
                      min={1}
                      max={100}
                      value={moscaParams.x}
                      onChange={e => setMoscaParams({ ...moscaParams, x: Number(e.target.value) })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                    />
                    <span className="text-xs text-slate-400">yrs</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">Time data must remain confidential</p>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <label className="block text-xs text-slate-300 font-medium mb-1">
                    Migration Time (<span className="font-mono text-cyan-400">Y</span>)
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      id="mosca-y-input"
                      type="number"
                      min={1}
                      max={100}
                      value={moscaParams.y}
                      onChange={e => setMoscaParams({ ...moscaParams, y: Number(e.target.value) })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                    />
                    <span className="text-xs text-slate-400">yrs</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">Time required to migrate to PQC</p>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <label className="block text-xs text-slate-300 font-medium mb-1">
                    CRQC Arrival (<span className="font-mono text-cyan-400">Z</span>)
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      id="mosca-z-input"
                      type="number"
                      min={1}
                      max={100}
                      value={moscaParams.z}
                      onChange={e => setMoscaParams({ ...moscaParams, z: Number(e.target.value) })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                    />
                    <span className="text-xs text-slate-400">yrs</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">Estimated quantum computer ETA</p>
                </div>
              </div>

              {/* Mosca Result Explanation Box */}
              <div id="mosca-result-box" className="mt-3 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs flex items-start gap-3">
                <div className={"text-xl mt-0.5 " + (moscaResult.isAtRisk ? "text-red-400" : "text-emerald-400")}>
                  {moscaResult.isAtRisk ? <AlertTriangle className="w-5 h-5" /> : <CheckCircle2 className="w-5 h-5" />}
                </div>
                <div>
                  <p id="mosca-equation" className="font-mono font-bold text-white">
                    X ({moscaParams.x}) + Y ({moscaParams.y}) = {moscaParams.x + moscaParams.y} yrs {moscaResult.isAtRisk ? '>' : '≤'} Z ({moscaParams.z} yrs) &rarr;{' '}
                    <span className={moscaResult.isAtRisk ? 'text-red-400' : 'text-emerald-400'}>
                      {moscaResult.status} {moscaResult.isAtRisk ? `(${moscaResult.delta} yrs deficit)` : `(${moscaResult.delta} yrs buffer)`}
                    </span>
                  </p>
                  <p id="mosca-explanation" className="text-slate-300 mt-0.5 leading-relaxed">
                    {moscaResult.recommendation}
                  </p>
                </div>
              </div>
            </div>

            {/* PQC MIGRATION ROADMAP */}
            <div id="migration-section" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="pb-3 border-b border-slate-800 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    <span>POST-QUANTUM CRYPTOGRAPHY (PQC) MIGRATION MAP</span>
                  </h2>
                  <p className="text-xs text-slate-400">Target replacements according to NIST FIPS 203, 204, 205 Standards</p>
                </div>
              </div>

              <div className="mt-3 space-y-2 text-xs">
                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div>
                    <span className="font-mono font-bold text-red-400">RSA-2048 / 3072 / 4096</span>
                    <p className="text-[11px] text-slate-400">Vulnerable to Shor's integer factorization</p>
                  </div>
                  <div className="text-right">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-mono font-semibold">
                      ML-KEM-768 / 1024 (FIPS 203)
                    </span>
                    <p className="text-[10px] text-slate-400">Module-Lattice KEM (Kyber)</p>
                  </div>
                </div>

                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div>
                    <span className="font-mono font-bold text-red-400">ECDSA (P-256 / secp256r1)</span>
                    <p className="text-[11px] text-slate-400">Vulnerable to Shor's discrete logarithm</p>
                  </div>
                  <div className="text-right">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-mono font-semibold">
                      ML-DSA-65 / 87 (FIPS 204)
                    </span>
                    <p className="text-[10px] text-slate-400">Module-Lattice Digital Signatures</p>
                  </div>
                </div>

                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div>
                    <span className="font-mono font-bold text-amber-400">Legacy TLS (1.0 / 1.1 / 1.2)</span>
                    <p className="text-[11px] text-slate-400">Weak key exchange &amp; ciphers</p>
                  </div>
                  <div className="text-right">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-mono font-semibold">
                      TLS 1.3 + Hybrid X25519MLKEM768
                    </span>
                    <p className="text-[10px] text-slate-400">Draft-ietf-tls-hybrid-design</p>
                  </div>
                </div>

                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div>
                    <span className="font-mono font-bold text-amber-400">SHA-1 / MD5</span>
                    <p className="text-[11px] text-slate-400">Collision vulnerability</p>
                  </div>
                  <div className="text-right">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-mono font-semibold">
                      SHA-3 / SHAKE-256 (FIPS 202)
                    </span>
                    <p className="text-[10px] text-slate-400">Keccak Permutation Family</p>
                  </div>
                </div>
              </div>
            </div>

          </div>

        </div>
      </main>

      {/* FOOTER */}
      <footer className="border-t border-slate-800 bg-[#0c1222] mt-8 py-6 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-200">ECDAT</span>
            <span>&bull; NIST Post-Quantum Cryptography Migration Framework</span>
          </div>
          <div className="flex items-center gap-4 text-[11px]">
            <span>FIPS 203 (ML-KEM)</span>
            <span>FIPS 204 (ML-DSA)</span>
            <span>FIPS 205 (SLH-DSA)</span>
            <span>CycloneDX CBOM 1.6</span>
          </div>
        </div>
      </footer>

    </div>
  );
}
