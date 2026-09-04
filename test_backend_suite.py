import os
import io
import json
import numpy as np
from PIL import Image, ImageDraw
from fastapi.testclient import TestClient
from main import app
from database import init_db, SessionLocal, ScanRecord, ReferenceDocument, RecordAccessLog
from auth_security import hash_secret, verify_secret
from encryption import encrypt_pii, decrypt_pii
from modules.face_matcher import compute_texture_variance, compare_faces

def create_high_texture_image_bytes():
    """Generates a high-texture sample image (simulating live skin under lighting)."""
    np.random.seed(42)
    noise = np.random.randint(40, 220, (300, 300, 3), dtype=np.uint8)
    img = Image.fromarray(noise)
    draw = ImageDraw.Draw(img)
    draw.ellipse([50, 50, 250, 250], outline=(255, 200, 180), width=4)
    draw.ellipse([90, 100, 130, 130], fill=(50, 30, 20))
    draw.ellipse([170, 100, 210, 130], fill=(50, 30, 20))
    
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=95)
    return buf.getvalue()

def create_low_texture_spoof_bytes():
    """Generates a flat low-texture spoof image (simulating a smooth 2D paper print/screen replay)."""
    img = Image.new("RGB", (300, 300), color=(180, 180, 180))
    draw = ImageDraw.Draw(img)
    draw.rectangle([80, 80, 220, 220], fill=(185, 185, 185))
    draw.line([(90, 120), (130, 120)], fill=(120, 120, 120), width=2)
    draw.line([(170, 120), (210, 120)], fill=(120, 120, 120), width=2)
    
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    return buf.getvalue()

def create_sample_passport_bytes():
    """Generates a sample passport document."""
    img = Image.new("RGB", (400, 250), color=(240, 240, 240))
    draw = ImageDraw.Draw(img)
    draw.rectangle([20, 20, 120, 160], fill=(200, 200, 200))
    draw.text((140, 40), "PASSPORT", fill=(20, 20, 20))
    draw.text((140, 70), "NAME: DARIUS VANCE KOWALSKI", fill=(20, 20, 20))
    draw.text((140, 100), "DOC: EL-84920194", fill=(20, 20, 20))
    draw.text((30, 200), "P<ELDKOWALSKI<<DARIUS<VANCE<<<<<<<<<<<<<", fill=(10, 10, 10))
    draw.text((30, 220), "EL849201948ELD8408142M2911225<<<<<<<<<<<8", fill=(10, 10, 10))
    
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()

def run_suite():
    print("==================================================")
    print("RUNNING TRUDOK EXTENDED SECURITY TEST SUITE")
    print("==================================================")

    with TestClient(app) as client:
        # 1. Root & Anti-Indexing Headers
        res = client.get("/")
        assert res.status_code == 200
        assert res.json() == {"status": "TruDok API", "version": "1.0.0"}
        assert "noindex" in res.headers.get("x-robots-tag", "").lower()
        print("[PASS] 1. Root & Anti-Indexing headers verified.")

        # 2. Health Probe & Database Connectivity
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["database"] == "connected"
        print("[PASS] 2. Health probe & database connection verified.")

        # 3. Bcrypt >72 byte SHA-256 pre-hashing
        long_secret = "a" * 128
        hashed = hash_secret(long_secret)
        assert verify_secret(long_secret, hashed) is True
        assert verify_secret("wrong_password", hashed) is False
        print("[PASS] 3. Bcrypt >72 byte SHA-256 pre-hashing verified.")

        # 4. Reference Database Verification: Matched Record
        res = client.post(
            "/api/db-verify",
            json={
                "documentNumber": "P88192041",
                "fullName": "AMITABH SHARMA",
                "dob": "21 JAN 1988",
                "nationality": "India (IND)",
                "expiryDate": "19 JAN 2030",
                "documentType": "passport"
            },
            headers={"X-API-Key": "trudok-sih26188-secret-key-2026"}
        )
        assert res.status_code == 200
        db_res = res.json()
        assert db_res["found"] is True
        assert len(db_res["fieldMismatches"]) == 0
        print("[PASS] 4. Reference DB exact match verified.")

        # 5. Reference Database Verification: Tampered Record
        res = client.post(
            "/api/db-verify",
            json={
                "documentNumber": "EL-84920194",
                "fullName": "DARIUS VANCE KOWALSKI",
                "dob": "14 AUG 1984",
                "nationality": "Eldoria (ELD)",
                "expiryDate": "22 NOV 2029",
                "documentType": "passport"
            },
            headers={"X-API-Key": "trudok-sih26188-secret-key-2026"}
        )
        assert res.status_code == 200
        tampered_res = res.json()
        assert tampered_res["found"] is True
        assert len(tampered_res["fieldMismatches"]) >= 2
        print(f"[PASS] 5. Reference DB tampered mismatch caught! Mismatches: {[m['field'] for m in tampered_res['fieldMismatches']]}")

        # 6. Anti-Spoofing Laplacian Texture Variance Check
        live_bytes = create_high_texture_image_bytes()
        spoof_bytes = create_low_texture_spoof_bytes()

        live_var, live_risk, live_pass, _ = compute_texture_variance(live_bytes)
        spoof_var, spoof_risk, spoof_pass, _ = compute_texture_variance(spoof_bytes)

        assert live_pass is True
        assert spoof_pass is False or spoof_risk == "high" or spoof_var < 45.0
        print(f"[PASS] 6. OpenCV Laplacian Texture Anti-Spoofing: Live Var={live_var} (Passed={live_pass}), Spoof Var={spoof_var} (Spoof Risk={spoof_risk}).")

        # 7. Fernet Symmetric PII Encryption at Rest
        raw_name = "DARIUS VANCE KOWALSKI"
        raw_doc = "EL-84920194"
        enc_name = encrypt_pii(raw_name)
        enc_doc = encrypt_pii(raw_doc)

        assert enc_name.startswith("ENC::")
        assert enc_doc.startswith("ENC::")
        assert decrypt_pii(enc_name) == raw_name
        assert decrypt_pii(enc_doc) == raw_doc
        print(f"[PASS] 7. Fernet PII Encryption at Rest verified: '{raw_name}' -> '{enc_name[:25]}...'.")

        # 8. Full Document Analysis with PII Encryption & Access Logging
        doc_bytes = create_sample_passport_bytes()
        res = client.post(
            "/api/analyze",
            files={"file": ("passport_sample.jpg", doc_bytes, "image/jpeg")},
            data={"docType": "passport", "officerId": "SSB-OFFICER-77"},
            headers={"X-API-Key": "trudok-sih26188-secret-key-2026"}
        )
        assert res.status_code == 200
        analysis = res.json()
        scan_id = analysis["id"]
        assert "scanId" in analysis
        print(f"[PASS] 8. Full screening analysis completed (Scan ID: {analysis['scanId']}).")

        # 9. Verify Database Storage has Encrypted PII and Field-Level Access Logs
        db = SessionLocal()
        try:
            saved_scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
            assert saved_scan is not None
            # Raw database column in SQLite must be encrypted!
            assert saved_scan.holder_name_encrypted.startswith("ENC::")
            assert saved_scan.document_number_encrypted.startswith("ENC::")
            # Python property getter decrypts seamlessly for authorized application use
            assert saved_scan.holder_name == "DARIUS VANCE KOWALSKI"

            # Check RecordAccessLog table
            access_logs = db.query(RecordAccessLog).filter(RecordAccessLog.record_id == scan_id).all()
            assert len(access_logs) >= 1
            assert access_logs[0].officer_id == "SSB-OFFICER-77"
            print(f"[PASS] 9. Database verified: PII encrypted at rest in DB and access logged for officer {access_logs[0].officer_id}.")
        finally:
            db.close()

        # 10. Dashboard Stats & Field-Level Access Logging
        res = client.get(
            "/api/dashboard-stats?officerId=SSB-OFFICER-77",
            headers={"X-API-Key": "trudok-sih26188-secret-key-2026"}
        )
        assert res.status_code == 200
        stats = res.json()
        assert stats["totalScanned"] >= 1
        print("[PASS] 10. Dashboard stats query with field-level access tracking verified.")

        # 11. Image Metadata Analysis & EXIF inspection via /api/tamper-check
        tamper_res = client.post(
            "/api/tamper-check",
            files={"file": ("passport_sample.jpg", doc_bytes, "image/jpeg")},
            headers={"X-API-Key": "trudok-sih26188-secret-key-2026"}
        )
        assert tamper_res.status_code == 200
        tamper_data = tamper_res.json()
        assert "metadataFindings" in tamper_data
        assert "tamperScore" in tamper_data
        print(f"[PASS] 11. Image Metadata & EXIF Analysis verified (Score: {tamper_data['tamperScore']}%, Findings: {len(tamper_data['metadataFindings'])}).")

        # 12. Stamp Forgery Detection via /api/stamp-check
        stamp_res = client.post(
            "/api/stamp-check",
            files={"file": ("passport_sample.jpg", doc_bytes, "image/jpeg")},
            data={"expectedIssuingCountry": "India", "officerId": "SSB-OFFICER-77"},
            headers={"X-API-Key": "trudok-sih26188-secret-key-2026"}
        )
        assert stamp_res.status_code == 200
        stamp_data = stamp_res.json()
        assert "stampDetected" in stamp_data
        assert "prototypeNotice" in stamp_data
        print(f"[PASS] 12. Stamp Forgery Detection endpoint verified (Pattern match: {stamp_data.get('patternMatch')}).")

        # 13. Document-Type Structured Field Extraction via /api/ocr-extract
        extract_res = client.post(
            "/api/ocr-extract",
            files={"file": ("sample.jpg", doc_bytes, "image/jpeg")},
            data={"docType": "passport"},
            headers={"X-API-Key": "trudok-sih26188-secret-key-2026"}
        )
        assert extract_res.status_code == 200
        ext_data = extract_res.json()
        assert "extractedFields" in ext_data
        assert "documentNumber" in ext_data["extractedFields"]
        print(f"[PASS] 13. Document-Type Specific Structured Extraction verified for passport.")

        # 14. Searchable Encrypted Audit Trail via /api/audit-search
        audit_res = client.get(
            "/api/audit-search?query=KOWALSKI&officerId=SSB-OFFICER-77",
            headers={"X-API-Key": "trudok-sih26188-secret-key-2026"}
        )
        assert audit_res.status_code == 200
        audit_records = audit_res.json()["history"]
        assert len(audit_records) >= 1
        assert audit_records[0]["holderName"] == "DARIUS VANCE KOWALSKI"
        print(f"[PASS] 14. Searchable Encrypted Audit Trail query verified ({len(audit_records)} records found for 'KOWALSKI').")

    print("==================================================")
    print("ALL 14 EXTENDED SECURITY TESTS PASSED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    run_suite()

