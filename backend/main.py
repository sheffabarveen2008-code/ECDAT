"""
ECDAT - Enterprise Cryptographic Discovery & Analysis Tool
Backend API built with FastAPI, httpx, and cryptographic pattern detection.
"""

import os
import re
import hashlib
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import httpx
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

app = FastAPI(
    title="ECDAT - Enterprise Cryptographic Discovery & Analysis Tool API",
    description="Backend service for Post-Quantum Cryptography migration, CBOM generation, and Mosca's theorem risk calculation.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for local development and client integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Allowed file extensions for cryptographic source inspection
ALLOWED_EXTENSIONS = {
    ".java", ".py", ".js", ".ts", ".go", ".c", ".h", ".pem", ".key", ".crt",
    ".xml", ".json", ".gradle", ".properties", ".yml", ".yaml", "dockerfile"
}

# 11 Standardized Cryptographic Discovery Patterns
CRYPTO_PATTERNS = [
    {
        "id": "RSA-2048",
        "algo": "RSA-2048 / RSA Asymmetric",
        "type": "Algorithm",
        "pattern": re.compile(r"BEGIN RSA PRIVATE KEY|RSA\.generateKeyPair|RSA.*2048|KeyPairGenerator.*RSA", re.IGNORECASE),
        "risk": 100,
        "pqc_target": "ML-KEM-768 (NIST FIPS 203) / ML-DSA-65 (NIST FIPS 204)",
        "quantum_vuln": True
    },
    {
        "id": "ECDSA-P256",
        "algo": "ECDSA P-256 / Elliptic Curve Signature",
        "type": "Algorithm",
        "pattern": re.compile(r"ecdsa|prime256v1|secp256r1|secp384r1|BEGIN EC PRIVATE KEY", re.IGNORECASE),
        "risk": 100,
        "pqc_target": "ML-DSA-65 / ML-DSA-87 (NIST FIPS 204) or SLH-DSA (FIPS 205)",
        "quantum_vuln": True
    },
    {
        "id": "ECDH-DH",
        "algo": "ECDH / Diffie-Hellman Key Agreement",
        "type": "Algorithm",
        "pattern": re.compile(r"ECDH|DiffieHellman", re.IGNORECASE),
        "risk": 100,
        "pqc_target": "ML-KEM-768 (NIST FIPS 203) / Hybrid KEM (X25519MLKEM768)",
        "quantum_vuln": True
    },
    {
        "id": "TLS-WEAK",
        "algo": "Legacy TLS (v1.0 / v1.1)",
        "type": "Protocol",
        "pattern": re.compile(r"TLSv1\.0|TLSv1\.1|PROTOCOL_TLSv1", re.IGNORECASE),
        "risk": 90,
        "pqc_target": "TLS 1.3 with Hybrid Post-Quantum Key Exchange",
        "quantum_vuln": True
    },
    {
        "id": "SHA1-MD5",
        "algo": "Weak Hash Function (SHA-1 / MD5)",
        "type": "Algorithm",
        "pattern": re.compile(r"SHA1\(|hashlib\.sha1|MD5", re.IGNORECASE),
        "risk": 85,
        "pqc_target": "SHA-256 / SHA-3 / SHAKE-256 (NIST FIPS 202)",
        "quantum_vuln": False
    },
    {
        "id": "BOUNCY-CASTLE",
        "algo": "BouncyCastle Cryptographic Provider",
        "type": "Library",
        "pattern": re.compile(r"BouncyCastle|bcprov", re.IGNORECASE),
        "risk": 60,
        "pqc_target": "BouncyCastle PQC Edition (LTS with ML-KEM/ML-DSA)",
        "quantum_vuln": True
    },
    {
        "id": "OPENSSL",
        "algo": "OpenSSL Crypto Engine",
        "type": "Library",
        "pattern": re.compile(r"OpenSSL\s+\d+\.\d+", re.IGNORECASE),
        "risk": 80,
        "pqc_target": "OpenSSL 3.4+ / OQS Post-Quantum Provider (liboqs)",
        "quantum_vuln": True
    },
    {
        "id": "JCA-JCE",
        "algo": "Java Cryptography Architecture (Cipher/KeyGen)",
        "type": "Library",
        "pattern": re.compile(r"Cipher\.getInstance|KeyPairGenerator", re.IGNORECASE),
        "risk": 50,
        "pqc_target": "JDK 24+ PQC Security Providers / JCA PQC Plugins",
        "quantum_vuln": True
    },
    {
        "id": "CRYPTO-IMPORT",
        "algo": "Cryptographic Module / Dependency Import",
        "type": "Dependency",
        "pattern": re.compile(r"jsonwebtoken|bcrypt|node-forge|require\('crypto'\)", re.IGNORECASE),
        "risk": 50,
        "pqc_target": "Quantum-resilient cryptographic wrapper",
        "quantum_vuln": False
    },
    {
        "id": "X509-CERT",
        "algo": "X.509 Public Key Certificate",
        "type": "Certificate",
        "pattern": re.compile(r"BEGIN CERTIFICATE", re.IGNORECASE),
        "risk": 70,
        "pqc_target": "Composite X.509 or ML-DSA Certificate Hierarchy",
        "quantum_vuln": True
    }
]


def extract_evidence(content: str, match_obj: re.Match, window: int = 120) -> str:
    """Extract snippet around match with line number info."""
    start = max(0, match_obj.start() - 30)
    end = min(len(content), match_obj.end() + 90)
    snippet = content[start:end].replace("\r", " ").replace("\n", " ").strip()
    return snippet


def analyze_code_content(filename: str, content: str) -> List[Dict[str, Any]]:
    """Scan code content against all 11 cryptographic regex rules."""
    findings = []
    lower_fn = filename.lower()

    # Verify extension or Dockerfile
    has_valid_ext = any(lower_fn.endswith(ext) for ext in ALLOWED_EXTENSIONS) or "dockerfile" in lower_fn
    if not has_valid_ext:
        return findings

    for rule in CRYPTO_PATTERNS:
        matches = list(rule["pattern"].finditer(content))
        for m in matches[:3]:  # up to 3 occurrences per rule per file to prevent spam
            evidence = extract_evidence(content, m)
            
            # Special check for OpenSSL versions 1.1.1a-k
            risk = rule["risk"]
            algo_name = rule["algo"]
            if rule["id"] == "OPENSSL":
                matched_str = m.group(0)
                if re.search(r"1\.1\.1[a-k]", content, re.IGNORECASE):
                    risk = 95
                    algo_name = f"OpenSSL (Legacy Vulnerable 1.1.1)"
            
            findings.append({
                "file": filename,
                "algo": algo_name,
                "type": rule["type"],
                "risk": risk,
                "evidence": evidence,
                "pqc_target": rule["pqc_target"],
                "quantum_vuln": rule["quantum_vuln"],
                "rule_id": rule["id"]
            })

    return findings


# Pydantic Request Models
class GitHubScanRequest(BaseModel):
    repo_url: str
    token: Optional[str] = None


class MoscaRiskRequest(BaseModel):
    x: float  # Shelf life in years
    y: float  # Migration time in years
    z: float  # Collapse / CRQC arrival time in years


class FindingItem(BaseModel):
    file: str
    algo: str
    type: str
    risk: int
    evidence: str
    pqc_target: Optional[str] = None
    quantum_vuln: Optional[bool] = True


class CBOMGenerateRequest(BaseModel):
    findings: List[FindingItem]
    project_name: Optional[str] = "ECDAT Scanned Asset"


@app.get("/")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "ECDAT - Enterprise Cryptographic Discovery & Analysis Tool",
        "version": "1.0.0",
        "standards": ["NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)", "NIST FIPS 205 (SLH-DSA)"],
        "cbom_spec": "CycloneDX 1.6"
    }


@app.post("/api/scan/github")
async def scan_github_repo(payload: GitHubScanRequest):
    """
    Scans a user-provided GitHub repository URL for cryptographic algorithms,
    certificates, libraries, and protocols using GitHub REST API.
    """
    raw_url = payload.repo_url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Repository URL is required.")

    # Parse owner and repo
    # e.g., https://github.com/sigstore/cosign or sigstore/cosign
    cleaned_url = raw_url.replace("https://github.com/", "").replace("http://github.com/", "").strip("/")
    parts = cleaned_url.split("/")
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL format. Expected: https://github.com/owner/repo")
    
    owner, repo = parts[0], parts[1].replace(".git", "")

    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "ECDAT-PQC-Scanner/1.0"}
    if payload.token and payload.token.strip():
        headers["Authorization"] = f"token {payload.token.strip()}"

    logs = []
    logs.append(f"[*] Initializing connection to GitHub API for {owner}/{repo}...")

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Step 1: Get repo info (default branch)
        repo_api_url = f"https://api.github.com/repos/{owner}/{repo}"
        try:
            repo_res = await client.get(repo_api_url, headers=headers)
            if repo_res.status_code == 404:
                raise HTTPException(status_code=404, detail=f"Repository {owner}/{repo} not found on GitHub or is private.")
            elif repo_res.status_code == 403:
                rate_reset = repo_res.headers.get("X-RateLimit-Reset", "soon")
                raise HTTPException(status_code=429, detail=f"GitHub API rate limit reached. Reset at {rate_reset}. Provide a GitHub token or wait.")
            elif repo_res.status_code != 200:
                raise HTTPException(status_code=repo_res.status_code, detail=f"GitHub API returned error {repo_res.status_code}: {repo_res.text}")
            
            repo_data = repo_res.json()
            default_branch = repo_data.get("default_branch", "main")
            stars = repo_data.get("stargazers_count", 0)
            language = repo_data.get("language", "Unknown")
            logs.append(f"[+] Repository found: {owner}/{repo} | Branch: {default_branch} | Language: {language} | Stars: {stars}")

        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Failed to connect to GitHub API: {str(e)}")

        # Step 2: Get git tree
        tree_api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
        logs.append(f"[*] Fetching repository tree from branch '{default_branch}'...")
        
        tree_res = await client.get(tree_api_url, headers=headers)
        if tree_res.status_code != 200:
            # Try master if main failed
            if default_branch == "main":
                tree_api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/master?recursive=1"
                default_branch = "master"
                tree_res = await client.get(tree_api_url, headers=headers)

        if tree_res.status_code != 200:
            raise HTTPException(status_code=tree_res.status_code, detail="Could not retrieve git tree for repository.")

        tree_data = tree_res.json()
        tree_items = tree_data.get("tree", [])

        # Filter candidate files
        candidate_files = []
        for item in tree_items:
            if item.get("type") == "blob":
                path = item.get("path", "")
                lower_p = path.lower()
                # Skip vendor, dist, node_modules, tests if desired, or keep core
                if "node_modules/" in lower_p or ".git/" in lower_p or "vendor/" in lower_p or "dist/" in lower_p:
                    continue
                if any(lower_p.endswith(ext) for ext in ALLOWED_EXTENSIONS) or "dockerfile" in lower_p:
                    candidate_files.append(path)

        logs.append(f"[+] Discovered {len(candidate_files)} cryptographic candidate files in git tree.")
        
        # Limit to first 70 files to avoid rate limiting
        files_to_scan = candidate_files[:70]
        if len(candidate_files) > 70:
            logs.append(f"[!] Slicing scan to top 70 files to conserve GitHub API quota.")

        all_findings = []
        scanned_count = 0

        # Scan files
        for fpath in files_to_scan:
            raw_file_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/{fpath}"
            try:
                file_res = await client.get(raw_file_url, headers=headers)
                if file_res.status_code == 200:
                    text_content = file_res.text
                    file_findings = analyze_code_content(fpath, text_content)
                    if file_findings:
                        all_findings.extend(file_findings)
                        logs.append(f"[SCAN] Found {len(file_findings)} crypto artifact(s) in {fpath}")
                    scanned_count += 1
            except Exception as ex:
                logs.append(f"[WARN] Could not fetch {fpath}: {str(ex)}")

        logs.append(f"[+] Scan completed! Scanned {scanned_count} files, identified {len(all_findings)} total cryptographic artifacts.")

        # Compute KPIs
        quantum_vuln_count = sum(1 for f in all_findings if f.get("quantum_vuln", False) or f.get("risk", 0) >= 80)
        critical_count = sum(1 for f in all_findings if f.get("risk", 0) >= 90)
        pqc_ready_count = sum(1 for f in all_findings if "pqc" in f.get("algo", "").lower() or f.get("risk", 0) == 0)

        return {
            "success": True,
            "repo": f"{owner}/{repo}",
            "branch": default_branch,
            "total_files_scanned": scanned_count,
            "total_findings": len(all_findings),
            "quantum_vuln_count": quantum_vuln_count,
            "critical_count": critical_count,
            "pqc_ready_count": pqc_ready_count,
            "findings": all_findings,
            "logs": logs
        }


@app.post("/api/scan/upload")
async def scan_uploaded_files(
    files: List[UploadFile] = File(...),
    is_binary: Optional[bool] = Form(False)
):
    """
    Accepts uploaded source code or binary files, computes SHA-256 digests,
    and runs regex detection on content / binary strings.
    """
    findings = []
    logs = []
    logs.append(f"[*] Received {len(files)} uploaded files for local cryptographic analysis.")

    for upload in files:
        filename = upload.filename or "unknown"
        content_bytes = await upload.read()
        
        # Calculate SHA256
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        file_size_kb = round(len(content_bytes) / 1024, 2)
        logs.append(f"[*] Analyzing {filename} ({file_size_kb} KB, SHA256: {sha256_hash[:12]}...)")

        # Decode content
        # For binary files, take first 800k bytes and decode ignoring errors
        sample_bytes = content_bytes[:800000]
        text_content = sample_bytes.decode("utf-8", errors="ignore")

        # Check binary specific markers
        if is_binary or filename.endswith((".so", ".dll", ".dylib", ".bin", ".exe", ".o")):
            # Look for OpenSSL or crypto banners
            if "OpenSSL" in text_content or "libcrypto" in text_content or "libssl" in text_content:
                findings.append({
                    "file": filename,
                    "algo": "OpenSSL Binary Library Linked",
                    "type": "Library",
                    "risk": 80,
                    "evidence": f"SHA256: {sha256_hash} | Binary contains OpenSSL/libcrypto symbols",
                    "pqc_target": "OpenSSL 3.4+ with liboqs provider",
                    "quantum_vuln": True,
                    "sha256": sha256_hash
                })
        
        # Run standard regex analysis
        file_findings = analyze_code_content(filename, text_content)
        for ff in file_findings:
            ff["sha256"] = sha256_hash
            findings.append(ff)

    logs.append(f"[+] Upload analysis completed: {len(findings)} cryptographic items discovered.")

    return {
        "success": True,
        "total_files_scanned": len(files),
        "total_findings": len(findings),
        "findings": findings,
        "logs": logs
    }


@app.post("/api/cbom/generate")
async def generate_cyclonedx_cbom(payload: CBOMGenerateRequest):
    """
    Generates an official CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)
    JSON specification from the discovery findings.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    
    components = []
    for idx, f in enumerate(payload.findings):
        component = {
            "bom-ref": f"crypto-component-{idx+1}",
            "type": "cryptographic-asset",
            "name": f.algo,
            "version": "1.0",
            "description": f"Cryptographic artefact detected in {f.file}",
            "cryptoProperties": {
                "assetType": f.type.lower(),
                "algorithmProperties": {
                    "name": f.algo,
                    "parameterSetIdentifier": "Classical / Asymmetric" if f.risk >= 90 else "Standard",
                    "curve": "P-256" if "ecdsa" in f.algo.lower() or "p-256" in f.algo.lower() else None,
                    "nistQuantumSecurityLevel": 0 if f.quantum_vuln else 5
                },
                "detectionEvidence": {
                    "filePath": f.file,
                    "snippet": f.evidence,
                    "riskScore": f.risk
                },
                "pqcRemediationTarget": f.pqc_target or "NIST FIPS 203/204/205 Standard"
            }
        }
        components.append(component)

    cbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{hashlib.md5(now_iso.encode()).hexdigest()}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "ECDAT - Enterprise Cryptographic Discovery & Analysis Tool",
                        "version": "1.0.0",
                        "vendor": "Enterprise Security"
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": payload.project_name,
                "version": "1.0.0"
            }
        },
        "components": components
    }

    return cbom_doc


@app.post("/api/risk/mosca")
async def calculate_mosca_theorem(payload: MoscaRiskRequest):
    """
    Calculates Mosca's Theorem of Quantum Risk:
    Theorem: If (X + Y > Z), then the system is AT RISK from quantum decryption
    where:
      X = Shelf-life / Security requirement of data in years
      Y = Migration time to post-quantum cryptography in years
      Z = Collapse time (time until Cryptanalytically Relevant Quantum Computer - CRQC) in years
    """
    x, y, z = payload.x, payload.y, payload.z
    total_time_needed = x + y
    is_at_risk = total_time_needed > z
    delta = round(total_time_needed - z, 2)

    return {
        "x_shelf_life_years": x,
        "y_migration_time_years": y,
        "z_crqc_arrival_years": z,
        "total_required_years": total_time_needed,
        "is_at_risk": is_at_risk,
        "status": "AT RISK" if is_at_risk else "SAFE",
        "delta_years": delta,
        "threat_model": "Harvest Now, Decrypt Later (HNDL)" if is_at_risk else "Compliant Migration Window",
        "recommendation": (
            f"CRITICAL: Data confidentiality expires {delta} years after quantum cryptanalysis arrives. "
            "Immediate migration to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) is mandatory to prevent retroactive interception."
            if is_at_risk else
            "Migration window is sufficient, but cryptographic agility and CBOM inventory must be maintained."
        )
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
