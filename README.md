# TruDok AI — AI-Based Fake Identity & Document Screening System

[![Vercel Live App](https://img.shields.io/badge/Frontend-Vercel%20Live-brightgreen?logo=vercel)](https://verilens-nu.vercel.app)
[![Render Backend](https://img.shields.io/badge/Backend-Render%20Production-blue?logo=render)](https://trudok-backend.onrender.com/api/health)
[![Security Standards](https://img.shields.io/badge/Security-AES--128--CBC%20%7C%20Zero--Disk-red)](https://github.com/lasyachowdaryvadlamudi-source/trudok-backend)
[![Compliance](https://img.shields.io/badge/SIH-Problem%20ID%2026188-orange)](https://github.com/lasyachowdaryvadlamudi-source/trudok-backend)

**TruDok** is an enterprise-grade AI-powered Identity & Document Screening System built for border checkpoint personnel, law enforcement, and immigration officers under the **Ministry of Home Affairs / Sashastra Seema Bal (SSB), Police II Division (Problem ID: 26188)**.

---

## 🌐 Live System Deployments & Links

| Component | Platform | Direct Link | Status |
| :--- | :--- | :--- | :--- |
| **Live Working Web Application** | **Vercel** | [https://verilens-nu.vercel.app](https://verilens-nu.vercel.app) | 🟢 **Active & Live** |
| **Backend REST API Engine** | **Render** | [https://trudok-backend.onrender.com](https://trudok-backend.onrender.com) | 🟢 **Active & Live** |
| **Health Check & DB Probe** | **Render API** | [https://trudok-backend.onrender.com/api/health](https://trudok-backend.onrender.com/api/health) | 🟢 **200 OK** |
| **Interactive API Documentation** | **FastAPI Swagger** | [https://trudok-backend.onrender.com/docs](https://trudok-backend.onrender.com/docs) | 🟢 **Available** |
| **Detailed Project Overview Report** | **GitHub** | [PROJECT_OVERVIEW.md](./PROJECT_OVERVIEW.md) | 📄 **Full Spec** |

---

## 📌 Executive Summary & Problem Description

### The Challenge
Border control units and security checkpoints process thousands of identity credentials daily across high-traffic border crossings (such as the Indo-Nepal corridor). Fraudulent actors exploit sophisticated physical and digital alterations:
- **Photo Substitution**: Replacing physical or printed facial portraits while preserving holograms.
- **Micro-Text & Date Forgery**: Digitally altering Dates of Birth (DOB) and Expiry Dates using non-standard fonts.
- **Counterfeit Stamps & Seals**: Using desktop digital publishing tools to superimpose fake consular stamps.
- **Biometric Presentation Attacks (Spoofing)**: Presenting high-resolution tablets, smartphone screen replays, or paper cutouts instead of live human subjects.

### The Solution: TruDok
TruDok combines **in-browser WebAssembly optical extraction (WASM OCR)**, **Error Level Analysis (ELA)**, **OpenCV Presentation Attack Detection (PAD)**, and **cryptographic zero-disk PII encryption** to screen identity documents in under 2 seconds.

```
+-----------------------------------------------------------------------------------+
|                            TRUDOK SCREENING PIPELINE                              |
+-----------------------------------------------------------------------------------+
|  [Document Upload / Camera]  ---> [In-Browser WASM OCR / Pre-processing]          |
|                                                  |                                |
|                                                  v                                |
|  [FastAPI Backend Engine] <--- [FormData Multi-Modal Secure Payload]             |
|          |                                                                        |
|          +---> 1. Optical Regex Parsing (Name, Number, DOB, Expiry, MRZ Checksums)|
|          +---> 2. Error Level Analysis (Pixel Recompression Heatmap & Anomaly Map)|
|          +---> 3. Stamp & Seal Image-Forensic Edge Discontinuity Detector         |
|          +---> 4. Biometric 1:1 Face Match & Laplacian Liveness Variance Check    |
|          +---> 5. Simulated Government Registry Cross-Check & Interpol Alert      |
|          |                                                                        |
|          v                                                                        |
|  [Encrypted SQLite Ledger]  <--- Fernet AES-128-CBC Encrypted PII Fields          |
|          |                                                                        |
|          v                                                                        |
|  [Officer Forensic Dossier] ---> Unified Visual Risk Gauge, Findings, & Trail    |
+-----------------------------------------------------------------------------------+
```

---

## ⚡ Core Modules & Technical Capabilities

### 1. Multi-Format Optical Character Recognition (OCR)
- **Supported Documents**:
  - **Passports**: ICAO Doc 9303 MRZ Line 1 & Line 2 (`P<...`), 7-3-1 weight check-digit verification.
  - **National ID / Aadhaar**: 12-digit format (`\d{4} \d{4} \d{4}`), Full Legal Name, DOB, Address, and UIDAI issuer.
  - **Driving Licenses**: Motor vehicle class endorsements (`MCWG, LMV`), license number (`DL-\d+`), validity period.
  - **Consular Visas**: Visa number, entry category (`T-1 / Multiple`), stay duration, and issuing consulate.
  - **Commercial Transit Permits**: Route sector corridors, carrier details, and commercial validity windows.
- **Hybrid Architecture**: Real-time client-side extraction with `tesseract.js` paired with server-side multi-pass regex normalization.

### 2. Forensic Tampering Detection (Error Level Analysis - ELA)
- Analyzes JPEG re-compression rate variances between altered text/portrait areas and the original document substrate.
- Generates visual color-coded thermal anomaly heatmaps where high-frequency compression boundaries identify digital tampering.

### 3. Biometric Verification & Presentation Attack Detection (PAD)
- **1:1 Face Matching**: Compares portrait crop from identity document with live traveler camera stream.
- **Anti-Spoofing Liveness**: Evaluates Laplacian texture variance ($\sigma^2 > 80.0$) and real-time head motion/blink challenge to thwart 2D photo prints, screen replays, and cutouts.

### 4. Searchable Digital Investigation Trail
- Complete audit ledger recording officer actions, timestamps, and document metadata.
- Enables intelligence officers to search historical scans by name, document number, or risk category.

---

## 🔒 Cybersecurity & Data Protection Compliance

| Security Requirement | TruDok Implementation |
| :--- | :--- |
| **Data Minimization** | In-memory stream processing with zero permanent image disk footprint. |
| **Encryption at Rest** | Sensitive PII (Holder Name, Document Number) encrypted using **Fernet AES-128-CBC**. |
| **Audit Log Integrity** | Salted cryptographic SHA-256 client IP hashing prevents officer identity leakage. |
| **API Transport Security** | Strict `X-API-Key` headers, production HTTPS enforcement, and anti-indexing headers (`X-Robots-Tag: noindex`). |
| **Abuse Prevention** | `slowapi` rate limiting (10 requests/minute per client IP). |

---

## 📊 API Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Service uptime, DB probe, and environment status | `X-API-Key` |
| `POST` | `/api/analyze` | Unified screening pipeline (OCR, ELA, Face, DB, Watchlist) | `X-API-Key` |
| `POST` | `/api/extract` | Document-type structured OCR extraction | `X-API-Key` |
| `POST` | `/api/tamper-check` | Error Level Analysis (ELA) heatmap generation | `X-API-Key` |
| `POST` | `/api/face-match` | 1:1 Face match with Laplacian anti-spoofing | `X-API-Key` |
| `POST` | `/api/db-verify` | Reference registry cross-check | `X-API-Key` |
| `GET` | `/api/dashboard-stats` | Real-time screening metrics and risk aggregations | `X-API-Key` |
| `GET` | `/api/audit-search` | Searchable historical investigation trail | `X-API-Key` |
| `GET` | `/api/scans/{id}` | Direct retrieval of encrypted scan dossier | `X-API-Key` |

---

## 🛠️ Local Development & Quickstart

```bash
# 1. Clone repository
git clone https://github.com/lasyachowdaryvadlamudi-source/trudok-backend.git
cd trudok-backend

# 2. Setup Virtual Environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install Dependencies
pip install -r requirements.txt

# 4. Start Development Server
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 🏆 Project Information
- **Problem Statement**: AI-Based Fake Identity & Document Screening System (SIH26188)
- **Target Organization**: Ministry of Home Affairs / Sashastra Seema Bal (SSB)
- **Repository**: [lasyachowdaryvadlamudi-source/trudok-backend](https://github.com/lasyachowdaryvadlamudi-source/trudok-backend)

