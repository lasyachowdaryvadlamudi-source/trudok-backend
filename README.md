# TruDok Backend — AI-Based Fake Identity & Document Screening System (SIH26188)

Production-ready FastAPI backend powering **TruDok**, built for the Ministry of Home Affairs / Sashastra Seema Bal (SSB), Police II Division.

---

## ⚡ Features

1. **Optical Character Recognition (OCR)** (`POST /api/extract`): Extracts raw text and regex-parses structured identity fields (Name, Document Number, DOB, Expiry, Country, MRZ check digits).
2. **Error Level Analysis (ELA) Tampering Detection** (`POST /api/tamper-check`): Real compression artifact gradient analysis generating a pixel-level difference heatmap and 0-100 tamper score.
3. **Facial Biometric Matching** (`POST /api/face-match`): Compares document photo with live selfie using OpenCV feature analysis and similarity scoring.
4. **Government Database Cross-Check** (`POST /api/db-verify`): Simulated registry verification comparing document fields against authoritative records.
5. **Unified Multi-Modal Screening** (`POST /api/analyze`): End-to-end composite evaluation returning the exact JSON structure required by the React frontend.
6. **Cybersecurity & Privacy**:
   - 5MB file upload limit
   - JPEG/PNG MIME validation
   - `slowapi` rate limiting (10 req/min per IP)
   - In-memory processing (data minimization — no permanent image storage)
   - Privacy-preserving digital audit log (`audit.log`)
   - `X-API-Key` authentication middleware
   - Health check endpoint (`GET /api/health`)

---

## 🚀 Local Development Setup

### Prerequisites
- Python 3.10+ (Python 3.11 recommended)
- `uv` (recommended) or `pip`

### 1. Install Dependencies
```bash
# Using uv (fastest)
uv venv --python 3.11
uv pip install -r requirements.txt

# Or using standard pip
python -m venv .venv
source .venv/bin/activate # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the Development Server
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

The API will be available at:
- **Interactive OpenAPI Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check:** [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

## ☁️ Deployment on Render.com (Free Tier)

1. Create a new **Web Service** on [Render.com](https://render.com).
2. Connect the repository and select the `trudok-backend` root.
3. Set the **Build Command**: `pip install -r requirements.txt`
4. Set the **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Copy the generated public URL (`https://trudok-backend.onrender.com`) and set it as `VITE_API_URL` in the frontend Vercel environment variables.
