# TruDok — Comprehensive Project Overview & System Specification Report

## Document Information
- **Project Name:** TruDok AI (AI-Based Fake Identity & Document Screening System)
- **Problem Statement ID:** SIH26188
- **Target Organization / Ministry:** Ministry of Home Affairs / Sashastra Seema Bal (SSB), Police II Division
- **Live Frontend Application:** [https://verilens-nu.vercel.app](https://verilens-nu.vercel.app)
- **Live Backend API Service:** [https://trudok-backend.onrender.com](https://trudok-backend.onrender.com)
- **GitHub Source Code Repository:** [https://github.com/lasyachowdaryvadlamudi-source/trudok-backend](https://github.com/lasyachowdaryvadlamudi-source/trudok-backend)

---

## 1. Executive Summary & Objective

In high-throughput border corridors, airports, and transport terminals, security personnel manually inspect hundreds of thousands of identity documents daily. Counterfeit credentials, manipulated dates, swapped photographs, and presentation attack spoofing present critical national security vulnerabilities. 

**TruDok** is an automated, zero-trust AI screening ecosystem designed to assist border security officers (such as SSB personnel at Checkpoint Alpha / Indo-Nepal border) by executing multi-modal forensic evaluation in under 2 seconds.

### Key Objectives
1. **Accurate Optical Character Recognition (OCR):** Ingest and extract identity parameters (Names, Document IDs, DOB, Expiry, Nationality, Gender, MRZ check digits) from live images across 5 major document classes.
2. **Real-time Digital Tampering Detection:** Detect compression boundary variations, localized image splicing, font anomalies, and forged administrative stamps via Error Level Analysis (ELA).
3. **Biometric Face Verification & Anti-Spoofing:** Verify live traveler identity against document portraits using OpenCV facial geometry and Laplacian texture variance to thwart presentation attacks (screens, paper prints, cutouts).
4. **Authoritative Registry Cross-Checking:** Match extracted document parameters against official databases to flag unregistered, revoked, or watchlisted individuals.
5. **Secure Digital Audit Ledger:** Maintain a tamper-evident investigation trail with field-level access logs and Fernet AES-128-CBC encryption at rest.

---

## 2. System Architecture & End-to-End Workflow

`
+--------------------------------------------------------------------------------------------------+
|                                    TRUDOK ARCHITECTURAL DIAGRAM                                  |
+--------------------------------------------------------------------------------------------------+
|                                                                                                  |
|   +------------------------------------------------------------------------------------------+   |
|   |                        CLIENT LAYER (React 18 + Vite + Tailwind CSS)                     |   |
|   |  - Viewfinder & Camera Stream (getUserMedia + WebRTC)                                    |   |
|   |  - Client-Side WASM OCR Engine (Tesseract.js v7.0)                                       |   |
|   |  - Interactive ELA Heatmap Canvas Renderer                                               |   |
|   |  - Cold-Start Wakeup Ping Loop (ensureBackendAwake)                                      |   |
|   +------------------------------------------------------------------------------------------+   |
|                                                |                                                 |
|                                       (TLS 1.3 / HTTPS POST)                                     |
|                                                v                                                 |
|   +------------------------------------------------------------------------------------------+   |
|   |                        API & SECURITY LAYER (FastAPI + SlowAPI + Python)                 |   |
|   |  - X-API-Key Authentication & Rate Limiting (10 req/min per IP)                          |   |
|   |  - In-Memory Binary Validation (MIME & 5MB Limit, Zero-Disk RAM Footprint)               |   |
|   |  - Salted SHA-256 Client IP Anonymization                                                |   |
|   +------------------------------------------------------------------------------------------+   |
|                                                |                                                 |
|                                                v                                                 |
|   +------------------------------------------------------------------------------------------+   |
|   |                         CORE FORENSIC SCREENING ENGINES                                  |   |
|   |                                                                                          |   |
|   |   1. OCR & REGEX PARSER       2. ELA TAMPER DETECTOR       3. BIOMETRIC 1:1 FACE MATCH   |   |
|   |   - Multi-pattern Regex       - 95% JPEG Recompression     - Dermal Texture Variance     |   |
|   |   - ICAO 9303 7-3-1 Weight    - Delta Matrix Heatmap       - Blink/Motion Challenge      |   |
|   |                                                                                          |   |
|   |   4. STAMP/SEAL VERIFIER      5. REFERENCE DB CHECK        6. WATCHLIST/INTERPOL         |   |
|   |   - Edge Sharpness Analysis   - Field-by-Field Mismatch    - Red Notice Matching         |   |
|   |   - Hue Discontinuity Scan    - Registry Hash Lookup       - Collision Scorer            |   |
|   +------------------------------------------------------------------------------------------+   |
|                                                |                                                 |
|                                                v                                                 |
|   +------------------------------------------------------------------------------------------+   |
|   |                      STORAGE & INVESTIGATION AUDIT LEDGER (SQLite)                       |   |
|   |  - Fernet AES-128-CBC Encrypted PII Fields (Holder Name, Document Number)                |   |
|   |  - Immutable Audit Event Stream (audit.log)                                              |   |
|   |  - Searchable Investigation View (GET /api/audit-search)                                 |   |
|   +------------------------------------------------------------------------------------------+   |
+--------------------------------------------------------------------------------------------------+
`

---

## 3. Supported Document Classes & Extraction Schema

| Document Class | Standards Covered | Key Extracted & Verified Fields |
| :--- | :--- | :--- |
| **International Passport** | ICAO Doc 9303 (TD3) | Passport No, Full Legal Name, Nationality, DOB, Expiry Date, Gender, MRZ Line 1, MRZ Line 2, Check Digits |
| **National ID / Aadhaar** | UIDAI / National Registry | 12-Digit UID (XXXX XXXX XXXX), Full Legal Name, DOB, Gender, Address, UIDAI Issuer |
| **Driving License** | Motor Vehicle Dept / RTA | DL Number (DL-XXXXXXXXXXXX), Vehicle Categories (MCWG, LMV), Validity Period, RTA Office |
| **Consular Visa** | Entry Visas (Sticker) | Visa Number, Entry Authorization (Multiple / Single), Visa Category (T-1 / Tourist), Stay Window |
| **Cross-Border Permit** | Transit Authorization | Permit Number, Authorized Carrier, Route Corridor Sector, Validity Window |

---

## 4. Cybersecurity, Privacy & Data Protection

1. **Zero-Disk Processing (Data Minimization):** Uploaded binary image buffers are processed purely in volatile RAM and dereferenced immediately post-analysis.
2. **Encryption at Rest:** Sensitive identity fields are stored as ciphertext using cryptography.fernet.Fernet (symmetric AES-128-CBC with PKCS7 padding and HMAC authentication).
3. **Anonymized Audit Trails:** Officer and client IPs are recorded as salted SHA-256 hashes (hash_client_ip), shielding officer identity while preserving forensic non-repudiation.
4. **Transport Security & Anti-Indexing:** All HTTP traffic is protected by TLS/HTTPS with headers X-Robots-Tag: noindex, nofollow and X-Frame-Options: DENY.

---

## 5. Verification & Automated Test Coverage

The system passes **100% of 14 security and integration unit tests** and full automated headless browser flows:

1. Root & Anti-Indexing Security Headers (GET /)
2. Health & DB Probe Connectivity (GET /api/health)
3. Bcrypt >72-byte SHA-256 Pre-hashing Validation
4. Reference Database Record Exact Matching (POST /api/db-verify)
5. Reference Database Tampering & Discrepancy Detection
6. OpenCV Laplacian Texture Anti-Spoofing (\sigma^2 > 80.0)
7. Fernet PII Encryption at Rest Verification
8. Unified Multi-Modal Screening Pipeline (POST /api/analyze)
9. SQLite Database Persistence with Field-Level Access Tracking
10. Dashboard Statistical Aggregation (GET /api/dashboard-stats)
11. EXIF Image Metadata Anomaly Scanner (POST /api/tamper-check)
12. Stamp & Seal Forgery Edge Discontinuity Analyzer (POST /api/stamp-check)
13. Document-Specific Structured OCR Extraction (POST /api/extract)
14. Searchable Encrypted Audit Trail Query Engine (GET /api/audit-search)

---

## 6. Live Links Summary

- **Web Application:** [https://verilens-nu.vercel.app](https://verilens-nu.vercel.app)
- **Backend API:** [https://trudok-backend.onrender.com](https://trudok-backend.onrender.com)
- **API Health:** [https://trudok-backend.onrender.com/api/health](https://trudok-backend.onrender.com/api/health)
- **GitHub Repository:** [https://github.com/lasyachowdaryvadlamudi-source/trudok-backend](https://github.com/lasyachowdaryvadlamudi-source/trudok-backend)
