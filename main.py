import os
import sys
import time
import json
import logging
from typing import Optional, List
from datetime import datetime, timezone

from fastapi import FastAPI, File, UploadFile, Header, HTTPException, Request, Depends, status, Query, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
from database import get_db, init_db, ScanRecord, ReferenceDocument, WatchlistEntry, AuditLog, log_record_access
from audit_logger import log_audit_event, hash_client_ip
from modules.ocr_extractor import extract_ocr_from_image_bytes
from modules.tamper_detector import run_error_level_analysis
from modules.face_matcher import compare_faces
from modules.stamp_verifier import analyze_stamp_forgery
from modules.db_cross_check import cross_check_with_national_db
from modules.analyzer import analyze_document_submission
from auth_security import hash_secret, verify_secret
from encryption import encrypt_pii, decrypt_pii

# Configure application logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("trudok.main")

# Rate limiter instance (10 requests/minute per IP)
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_PER_MINUTE])

is_production = settings.ENVIRONMENT.lower() == "production"

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="TruDok — AI-Based Fake Identity & Document Screening System API",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Strict CORS allow-list
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    logger.info(f"Starting {settings.APP_NAME} in {settings.ENVIRONMENT} mode...")
    init_db()
    logger.info("Database & Encryption ciphers initialized successfully.")


# Global Exception Handler Middleware (no raw stack traces leaked to client)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": "An unexpected error occurred while processing the security verification.",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


# Security Headers & Anti-Indexing Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    # Allow CORS preflight OPTIONS requests to pass directly to CORSMiddleware
    if request.method == "OPTIONS":
        return await call_next(request)

    start_time = time.time()

    # HTTPS Enforcement in Production (allowing health probes and internal port checks)
    if is_production:
        proto = request.headers.get("x-forwarded-proto", "http")
        client_host = request.client.host if request.client else ""
        is_internal_probe = (
            request.url.path in ["/api/health", "/", "/health", "/docs", "/redoc"]
            or request.url.hostname in ["localhost", "127.0.0.1", "0.0.0.0"]
            or client_host in ["127.0.0.1", "localhost", "::1"]
            or client_host.startswith("10.")
            or client_host.startswith("172.")
            or client_host.startswith("192.168.")
        )
        if proto != "https" and not is_internal_probe:
            return JSONResponse(
                status_code=403,
                content={"error": "HTTPS Required", "detail": "All requests must use TLS/HTTPS encryption."}
            )

    response = await call_next(request)
    process_time = round((time.time() - start_time) * 1000, 2)

    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=*, microphone=()"
    response.headers["X-Response-Time-Ms"] = f"{process_time}ms"

    return response


# Enforce API Key Header Check
def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    if not x_api_key or x_api_key != settings.API_KEY:
        if is_production:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-API-Key security header."
            )
        elif x_api_key and x_api_key != settings.API_KEY:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid X-API-Key security header."
            )
    return x_api_key or settings.API_KEY


import io
from PIL import Image

async def validate_uploaded_file(file: UploadFile) -> bytes:
    """
    DATA BREACH PROTECTION:
    Validates file in-memory. Binary image data is NEVER written to disk or permanent storage.
    Supports JPEG, PNG, WEBP, HEIC, and canvas blob uploads.
    """
    if not file:
        raise HTTPException(status_code=400, detail="No document image provided in request.")

    contents = await file.read()
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if len(contents) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_MB}MB."
        )

    # In-memory image decoding verification
    try:
        Image.open(io.BytesIO(contents)).verify()
    except Exception:
        # Allow raw binary streams if length > 100 bytes
        if len(contents) < 100:
            raise HTTPException(
                status_code=400,
                detail="Invalid or empty image file uploaded."
            )

    return contents



class DBVerifyRequest(BaseModel):
    documentNumber: str = Field(..., description="OCR extracted document number")
    fullName: Optional[str] = Field(None, description="Extracted full legal name")
    dob: Optional[str] = Field(None, description="Extracted date of birth")
    nationality: Optional[str] = Field(None, description="Extracted nationality")
    expiryDate: Optional[str] = Field(None, description="Extracted expiry date")
    documentType: Optional[str] = Field("passport", description="Document type")


# ROOT ENDPOINT (Minimal generic response)
@app.get("/")
async def root():
    return {
        "status": "TruDok API",
        "version": settings.APP_VERSION
    }


# HEALTH CHECK (Uptime & DB probe)
@app.get("/api/health")
async def health_check(request: Request, db: Session = Depends(get_db)):
    db_status = "connected"
    try:
        db.execute(func.now()).first()
    except Exception as e:
        logger.warning(f"Database health probe failed: {e}")
        db_status = "error"

    log_audit_event(
        endpoint="/api/health",
        method="GET",
        status_code=200,
        client_ip=get_remote_address(request),
        action="HEALTH_PROBE",
        result_summary=f"DB: {db_status}",
        db=db
    )

    return {
        "status": "ok",
        "database": db_status,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": settings.APP_VERSION
    }


# REAL REFERENCE-BASED VALIDATION (POST /api/db-verify)
@app.post("/api/db-verify")
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def verify_against_reference_db(
    request: Request,
    payload: DBVerifyRequest,
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    SIMULATED REFERENCE DATABASE — represents the integration point for real government ID systems
    (UIDAI, passport records) not accessible in this prototype. In production this endpoint would call authenticated government APIs.
    """
    result = cross_check_with_national_db(payload.model_dump(), db=db)

    log_audit_event(
        endpoint="/api/db-verify",
        method="POST",
        status_code=200,
        client_ip=get_remote_address(request),
        action="REFERENCE_DB_VERIFY",
        document_type=payload.documentType,
        risk_score=result.get("riskContribution"),
        result_summary="Found" if result.get("found") else "Not Found (Unregistered)",
        db=db
    )

    return result


# OCR EXTRACTION ENDPOINT (Supports /api/extract and /api/ocr-extract)
@app.post("/api/extract")
@app.post("/api/ocr-extract")
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def extract_ocr(
    request: Request,
    file: UploadFile = File(...),
    docType: str = Query("passport"),
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Document-Type-Specific Field Extraction for:
    - Passport (ICAO MRZ checksums, DOB, Expiry, Nationality)
    - Visa (Visa Number, Type, Entry Validation, Stay Duration)
    - National ID (Name, ID Number, DOB, Address)
    - Driving License (Name, License Number, DOB, Vehicle Class, Expiry)
    - Permit (Permit Number, Type, Validity Period, Issuing Authority)
    """
    image_bytes = await validate_uploaded_file(file)
    result = extract_ocr_from_image_bytes(image_bytes, doc_type=docType)

    log_audit_event(
        endpoint="/api/extract",
        method="POST",
        status_code=200,
        client_ip=get_remote_address(request),
        action="OCR_EXTRACTION",
        document_type=docType,
        result_summary=f"Confidence: {result.get('confidence')}%",
        db=db
    )
    return result


# 1. ERROR LEVEL ANALYSIS (ELA) & EXIF METADATA TAMPERING CHECK
@app.post("/api/tamper-check")
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def tamper_check(
    request: Request,
    file: UploadFile = File(...),
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Error Level Analysis (ELA) and EXIF Image Metadata Analysis.
    Detects recompression variance and editing software tags (Photoshop, GIMP, Snapseed, etc.).
    """
    image_bytes = await validate_uploaded_file(file)
    result = run_error_level_analysis(image_bytes)

    log_audit_event(
        endpoint="/api/tamper-check",
        method="POST",
        status_code=200,
        client_ip=get_remote_address(request),
        action="TAMPER_DETECTION_ELA_EXIF",
        risk_score=result.get("tamperScore"),
        result_summary=f"Tamper Score: {result.get('tamperScore')}%",
        db=db
    )
    return result


# 2. STAMP FORGERY DETECTION (Image-Forensic Edge & Ink Analysis)
@app.post("/api/stamp-check")
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def stamp_check(
    request: Request,
    file: UploadFile = File(...),
    regionJson: Optional[str] = Form(None),
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    # Stamp pattern matching against official reference stamps requires a government-provided 
    # reference database not available in this prototype. This endpoint performs real 
    # image-forensic checks (edge/color analysis) as a partial substitute.
    """
    image_bytes = await validate_uploaded_file(file)
    region = None
    if regionJson:
        try:
            region = json.loads(regionJson)
        except Exception:
            pass

    result = analyze_stamp_forgery(image_bytes, region=region)

    log_audit_event(
        endpoint="/api/stamp-check",
        method="POST",
        status_code=200,
        client_ip=get_remote_address(request),
        action="STAMP_FORGERY_CHECK",
        result_summary=f"Flag: {result.get('flag')} (Edge: {result.get('edgeSharpnessScore')}%)",
        db=db
    )
    return result


# FACIAL BIOMETRIC VERIFICATION (1:1 Match + Anti-Spoofing Liveness)
@app.post("/api/face-match")
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def face_match(
    request: Request,
    documentPhoto: UploadFile = File(...),
    selfiePhoto: UploadFile = File(...),
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    doc_bytes = await validate_uploaded_file(documentPhoto)
    selfie_bytes = await validate_uploaded_file(selfiePhoto)

    result = compare_faces(doc_bytes, selfie_bytes)

    log_audit_event(
        endpoint="/api/face-match",
        method="POST",
        status_code=200,
        client_ip=get_remote_address(request),
        action="BIOMETRIC_FACE_MATCH",
        result_summary=f"Match: {result.get('matchScore')}% (Liveness: {result.get('livenessPassed')})",
        db=db
    )
    return result


# UNIFIED COMPOSITE SCREENING PIPELINE (POST /api/analyze)
@app.post("/api/analyze")
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def analyze_full_document(
    request: Request,
    file: UploadFile = File(...),
    selfie: Optional[UploadFile] = File(None),
    docType: Optional[str] = Form(None),
    officerId: Optional[str] = Form(None),
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Unified Multi-Modal Screening Pipeline:
    - In-Memory Processing: Zero disk footprint.
    - Encrypted at Rest: PII fields stored using Fernet symmetric encryption.
    - Anti-Spoofing: Laplacian texture variance & PAD verification.
    """
    effective_doc_type = docType or request.query_params.get("docType", "passport")
    effective_officer_id = officerId or request.query_params.get("officerId") or request.headers.get("X-Officer-ID", "SSB-OFFICER-01")

    doc_bytes = await validate_uploaded_file(file)
    selfie_bytes = await validate_uploaded_file(selfie) if selfie else None

    result = analyze_document_submission(
        doc_image_bytes=doc_bytes,
        selfie_image_bytes=selfie_bytes,
        doc_type=effective_doc_type,
        db=db
    )


    try:
        scan_record = ScanRecord(
            id=result.get("id"),
            scan_id=result.get("scanId"),
            document_type=docType,
            risk_score=result.get("riskScore", 0),
            verdict=result.get("verdict", "Verified"),
            status_pill=result.get("statusPill", "CLEAR"),
            officer_id=effective_officer_id,
            details_json=json.dumps(result)
        )
        scan_record.holder_name = result.get("holderName", "UNKNOWN")
        scan_record.document_number = result.get("documentNumber", "UNKNOWN")

        db.add(scan_record)
        db.commit()

        client_ip = get_remote_address(request)
        log_record_access(
            db=db,
            officer_id=effective_officer_id,
            record_id=result.get("id"),
            action="CREATE_AND_SCREEN_RECORD",
            client_ip_hash=hash_client_ip(client_ip)
        )

    except Exception as e:
        logger.error(f"Failed to persist scan record: {e}")
        db.rollback()

    log_audit_event(
        endpoint="/api/analyze",
        method="POST",
        status_code=200,
        client_ip=get_remote_address(request),
        action="FULL_SCREENING_ANALYSIS",
        document_type=docType,
        risk_score=result.get("riskScore"),
        result_summary=f"Verdict: {result.get('statusPill')} (Score: {result.get('riskScore')}%)",
        db=db
    )

    return result


# 4. INVESTIGATION AUDIT TRAIL — SEARCHABLE VIEW (GET /api/audit-search)
@app.get("/api/audit-search")
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def search_audit_trail(
    request: Request,
    query: str = Query(..., description="Document Number, Holder Name, or Scan ID"),
    officerId: Optional[str] = Query("SSB-OFFICER-01"),
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Closes the 'digital trail for investigations and intelligence analysis' requirement.
    Searches historic scan dossiers in database for previous attempts, flagged records, and travel history.
    """
    clean_query = query.strip().upper()
    client_ip = get_remote_address(request)
    
    # Retrieve records
    all_scans = db.query(ScanRecord).order_by(desc(ScanRecord.timestamp)).all()
    matching_scans = []

    for r in all_scans:
        holder = r.holder_name.upper()
        doc_num = r.document_number.upper()
        scan_id = (r.scan_id or "").upper()
        record_id = (r.id or "").upper()

        if clean_query in holder or clean_query in doc_num or clean_query in scan_id or clean_query in record_id:
            try:
                dossier = json.loads(r.details_json) if r.details_json else {}
            except Exception:
                dossier = {}

            matching_scans.append({
                "id": r.id,
                "scanId": r.scan_id,
                "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "timeAgo": "Recent",
                "documentType": r.document_type,
                "riskScore": r.risk_score,
                "verdict": r.verdict,
                "statusPill": r.status_pill,
                "officerId": r.officer_id,
                "holderName": r.holder_name,
                "documentNumber": r.document_number,
                "checkpoint": dossier.get("checkpoint", "Checkpoint Alpha (Raxaul)"),
                "tamperUseCases": dossier.get("tamperingUseCases", {}),
                "watchlistHit": bool(dossier.get("watchlist", {}).get("hasMatch")),
                "livenessVerified": dossier.get("biometrics", {}).get("livenessPassed", True)
            })

    # Log field-level access
    log_record_access(
        db=db,
        officer_id=officerId,
        record_id=f"AUDIT_SEARCH::{clean_query}",
        action="INVESTIGATION_SEARCH",
        client_ip_hash=hash_client_ip(client_ip)
    )

    log_audit_event(
        endpoint="/api/audit-search",
        method="GET",
        status_code=200,
        client_ip=client_ip,
        action="INVESTIGATION_AUDIT_SEARCH",
        result_summary=f"Query: {clean_query} (Found {len(matching_scans)} records)",
        db=db
    )

    return {
        "query": query,
        "matchCount": len(matching_scans),
        "history": matching_scans,
        "searchTimestamp": datetime.now(timezone.utc).isoformat()
    }


# DATABASE PERSISTENT DASHBOARD STATS (GET /api/dashboard-stats)
@app.get("/api/dashboard-stats")
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def get_dashboard_stats(
    request: Request,
    officerId: str = Query("SSB-OFFICER-01"),
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    total_scans = db.query(ScanRecord).count()
    flagged_scans = db.query(ScanRecord).filter(ScanRecord.status_pill == "CRITICAL").count()
    review_scans = db.query(ScanRecord).filter(ScanRecord.status_pill == "REVIEW").count()
    verified_scans = db.query(ScanRecord).filter(ScanRecord.status_pill == "CLEAR").count()

    avg_risk = 0
    if total_scans > 0:
        avg_calc = db.query(func.avg(ScanRecord.risk_score)).scalar()
        avg_risk = round(float(avg_calc or 0), 1)

    recent_records = db.query(ScanRecord).order_by(desc(ScanRecord.timestamp)).limit(20).all()
    recent_scans = []
    for r in recent_records:
        try:
            dossier = json.loads(r.details_json) if r.details_json else {}
            dossier["id"] = r.id
            dossier["scanId"] = r.scan_id
            dossier["riskScore"] = r.risk_score
            dossier["statusPill"] = r.status_pill
            dossier["scanTimestamp"] = r.timestamp.strftime("%H:%M:%S")
            recent_scans.append(dossier)
        except Exception:
            recent_scans.append({
                "id": r.id,
                "scanId": r.scan_id,
                "holderName": r.holder_name,
                "documentNumber": r.document_number,
                "type": r.document_type,
                "riskScore": r.risk_score,
                "statusPill": r.status_pill,
                "scanTimestamp": r.timestamp.strftime("%H:%M:%S")
            })

    client_ip = get_remote_address(request)
    log_record_access(
        db=db,
        officer_id=officerId,
        record_id="DASHBOARD_FEED",
        action="VIEW_AGGREGATED_STATS",
        client_ip_hash=hash_client_ip(client_ip)
    )

    log_audit_event(
        endpoint="/api/dashboard-stats",
        method="GET",
        status_code=200,
        client_ip=client_ip,
        action="DASHBOARD_STATS_QUERY",
        result_summary=f"Total: {total_scans}",
        db=db
    )

    return {
        "totalScanned": total_scans,
        "flaggedCount": flagged_scans,
        "reviewCount": review_scans,
        "verifiedCount": verified_scans,
        "averageRisk": avg_risk,
        "recentScans": recent_scans,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# SINGLE SCAN DOSSIER RETRIEVAL (GET /api/scans/{scan_id})
@app.get("/api/scans/{scan_id}")
@app.get("/api/scan/{scan_id}")
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def get_scan_by_id(
    scan_id: str,
    request: Request,
    officerId: Optional[str] = Query("SSB-OFFICER-01"),
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    clean_id = scan_id.strip()
    record = db.query(ScanRecord).filter(
        (ScanRecord.id == clean_id) | (ScanRecord.scan_id == clean_id)
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found in database.")

    try:
        dossier = json.loads(record.details_json) if record.details_json else {}
    except Exception:
        dossier = {}

    dossier["id"] = record.id
    dossier["scanId"] = record.scan_id
    dossier["riskScore"] = record.risk_score
    dossier["statusPill"] = record.status_pill
    dossier["verdict"] = record.verdict
    dossier["holderName"] = record.holder_name
    dossier["documentNumber"] = record.document_number

    client_ip = get_remote_address(request)
    log_record_access(
        db=db,
        officer_id=officerId,
        record_id=record.id,
        action="VIEW_DOSSIER_BY_ID",
        client_ip_hash=hash_client_ip(client_ip)
    )

    return dossier


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
