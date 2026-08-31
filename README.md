# ECDAT - Enterprise Cryptographic Discovery & Analysis Tool

**ECDAT** is a full-stack Post-Quantum Cryptography (PQC) migration, cryptographic inventory discovery, and risk assessment platform. It automatically catalogues cryptographic assets into CycloneDX 1.6 Cryptographic Bill of Materials (CBOM), evaluates quantum decryption threats using **Mosca's Theorem** ($X + Y > Z$), and provides migration mapping to **NIST Post-Quantum Cryptography Standards (FIPS 203, FIPS 204, FIPS 205)**.

---

## 🔒 Key Features

1. **Zero Preloaded Data on Boot**:
   - Initialized with **0 assets, empty findings table, and clear discovery logs**.
   - Scans only the exact GitHub repository URL or uploaded local codebase selected by the user.

2. **Real Cryptographic Detection (11 Regex Patterns)**:
   - **RSA-2048 / Asymmetric**: Classical RSA key generation and PKCS#1 padding.
   - **ECDSA P-256 / secp256r1**: Elliptic Curve digital signatures vulnerable to Shor's algorithm.
   - **ECDH / Diffie-Hellman**: Ephemeral and static key agreement protocols.
   - **Legacy TLS (v1.0 / v1.1)**: Deprecated protocol configurations.
   - **Weak Hashes (SHA-1 / MD5)**: Cryptographic collision vulnerabilities.
   - **BouncyCastle Provider**: Java cryptography library imports and providers.
   - **OpenSSL Engine**: OpenSSL symbols and vulnerable version tags (e.g. `1.1.1a-k`).
   - **Java Cryptography Architecture (JCA/JCE)**: `Cipher.getInstance`, `KeyPairGenerator`.
   - **Cryptographic Dependencies**: `jsonwebtoken`, `bcrypt`, `node-forge`, `crypto-js`.
   - **X.509 Certificates**: `BEGIN CERTIFICATE` blocks.
   - **Extensible File Coverage**: `.java`, `.py`, `.js`, `.ts`, `.go`, `.c`, `.h`, `.pem`, `.key`, `.crt`, `.xml`, `.json`, `.gradle`, `.properties`, `.yml`, `.yaml`, `Dockerfile`.

3. **Binary Forensics & Manifest Analysis**:
   - Computes **SHA-256** checksums of binary objects using Web Crypto / hashlib.
   - Inspects compiled symbols and strings (`libcrypto`, `libssl`, `OpenSSL`).
   - Parses `package.json`, `pom.xml`, and `requirements.txt`.

4. **Mosca's Theorem of Quantum Risk**:
   - Evaluates the inequality:
     $$\text{If } X + Y > Z \implies \textbf{AT RISK}$$
     - **$X$ (Shelf Life)**: Years data must remain confidential.
     - **$Y$ (Migration Time)**: Years required to migrate systems to PQC.
     - **$Z$ (CRQC Arrival)**: Estimated time until a Cryptanalytically Relevant Quantum Computer exists.
   - Explains "Harvest Now, Decrypt Later" (HNDL) attack surface.

5. **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)**:
   - Exports valid CycloneDX 1.6 CBOM JSON specification.
   - Exports CSV cryptographic inventories and executive PDF reports.

---

## 🛠️ Project Structure

```text
├── backend/
│   ├── main.py              # FastAPI backend API with CORS and GitHub/Upload endpoints
│   └── requirements.txt     # Python backend dependencies (fastapi, uvicorn, httpx)
├── frontend/
│   └── index.html           # Standalone single-file frontend (Tailwind CSS CDN, Vanilla JS)
├── src/
│   ├── App.tsx              # React Enterprise Dark Dashboard
│   ├── cryptoScanner.ts     # 11 Cryptographic discovery rules engine
│   ├── cbomExporter.ts      # CycloneDX 1.6 CBOM JSON & CSV exporters, Mosca calculator
│   └── types.ts             # TypeScript interfaces
├── sample-vulnerable-app/   # Test suite files containing sample vulnerable crypto
│   ├── JwtService.java      # RSA-2048 & JCA Cipher
│   ├── crypto_service.py    # ECDSA & SHA-1
│   ├── tls_config.go        # Weak TLS 1.0/1.1
│   ├── package.json         # Crypto npm packages
│   ├── requirements.txt     # Python crypto dependencies
│   ├── pom.xml              # BouncyCastle Maven dependency
│   ├── server.cert.pem      # X.509 certificate
│   ├── rsa_private.key      # RSA private key
│   └── Dockerfile           # OpenSSL container definition
└── README.md
```

---

## 🚀 Running the Application

### 1. Python FastAPI Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be available at `http://localhost:8000/docs`.

### 2. Frontend Development Server (React / Vite)
```bash
npm install
npm run dev
```
Open `http://localhost:3000` in your browser.

### 3. Standalone Single-File Frontend
Open `frontend/index.html` directly in any modern browser. It automatically detects if the Python backend is active on port 8000, and gracefully falls back to client-side GitHub API + WebCrypto if standalone.

---

## 📜 NIST Post-Quantum Standards Reference

| Classical Cryptographic Primitive | NIST PQC Standard | Specification Target |
| :--- | :--- | :--- |
| **RSA / Diffie-Hellman / ECDH** | **NIST FIPS 203** | ML-KEM-768 / ML-KEM-1024 (Module-Lattice KEM) |
| **ECDSA (P-256 / secp256r1)** | **NIST FIPS 204** | ML-DSA-65 / ML-DSA-87 (Module-Lattice Digital Signatures) |
| **Ed25519 / Statefull Signatures** | **NIST FIPS 205** | SLH-DSA (Stateless Hash-Based Signatures) |
| **SHA-1 / MD5** | **NIST FIPS 202** | SHA-3 / SHAKE-256 (Keccak Permutations) |
| **Legacy TLS 1.0 / 1.1 / 1.2** | **IETF Hybrid PQC** | TLS 1.3 with X25519MLKEM768 Key Exchange |
