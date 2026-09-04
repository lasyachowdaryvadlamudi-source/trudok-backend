import os
import json
import re
from typing import Optional
from sqlalchemy.orm import Session

# SIMULATED REFERENCE DATABASE — represents the integration point for real government ID systems
# (UIDAI, passport records) not accessible in this prototype. In production this endpoint would call authenticated government APIs.

DB_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "reference_documents.json")

def normalize_text(text: str) -> str:
    """Normalizes alphanumeric characters for robust identity comparisons."""
    if not text:
        return ""
    return re.sub(r"[^A-Z0-9]", "", str(text).upper())

def load_json_reference_records() -> list:
    """Fallback reference loader from reference_documents.json."""
    try:
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("records", [])
    except Exception as e:
        print(f"[Reference DB Warning] {e}")
    return []

def query_reference_record(doc_number: str, full_name: Optional[str] = None, db: Optional[Session] = None) -> Optional[dict]:
    """
    Looks up official government reference record by document number (primary)
    or by full legal name (fallback).
    """
    norm_doc = normalize_text(doc_number)
    norm_name = normalize_text(full_name) if full_name else ""

    # 1. Query SQLAlchemy database
    if db is not None:
        try:
            from database import ReferenceDocument
            records = db.query(ReferenceDocument).all()
            for rec in records:
                rec_doc = normalize_text(rec.document_number)
                if norm_doc and (rec_doc == norm_doc or norm_doc in rec_doc or rec_doc in norm_doc):
                    return {
                        "documentNumber": rec.document_number,
                        "fullName": rec.full_name,
                        "dob": rec.dob,
                        "nationality": rec.nationality,
                        "countryCode": rec.country_code,
                        "dateOfIssue": rec.date_of_issue,
                        "dateOfExpiry": rec.date_of_expiry,
                        "gender": rec.gender,
                        "documentType": rec.document_type,
                        "issuingAuthority": rec.issuing_authority,
                        "status": rec.status,
                        "isTamperedSample": rec.is_tampered_sample,
                        "notes": rec.notes
                    }
            if norm_name and norm_name != "UNKNOWN":
                for rec in records:
                    rec_name = normalize_text(rec.full_name)
                    if rec_name and (rec_name in norm_name or norm_name in rec_name):
                        return {
                            "documentNumber": rec.document_number,
                            "fullName": rec.full_name,
                            "dob": rec.dob,
                            "nationality": rec.nationality,
                            "countryCode": rec.country_code,
                            "dateOfIssue": rec.date_of_issue,
                            "dateOfExpiry": rec.date_of_expiry,
                            "gender": rec.gender,
                            "documentType": rec.document_type,
                            "issuingAuthority": rec.issuing_authority,
                            "status": rec.status,
                            "isTamperedSample": rec.is_tampered_sample,
                            "notes": rec.notes
                        }
        except Exception as e:
            print(f"[SQLAlchemy Reference Lookup Notice] {e}")

    # 2. Query JSON file fallback
    json_records = load_json_reference_records()
    for rec in json_records:
        rec_doc = normalize_text(rec.get("documentNumber", ""))
        if norm_doc and (rec_doc == norm_doc or norm_doc in rec_doc or rec_doc in norm_doc):
            return rec

    if norm_name and norm_name != "UNKNOWN":
        for rec in json_records:
            rec_name = normalize_text(rec.get("fullName", ""))
            if rec_name and (rec_name in norm_name or norm_name in rec_name):
                return rec

    return None

def cross_check_with_national_db(extracted_fields: dict, db: Optional[Session] = None) -> dict:
    """
    Field-by-field verification against the reference database.
    - If found: compares EVERY provided field against official record and computes mismatch diffs.
    - If not found: returns found=False with elevated risk contribution (unregistered record).
    """
    doc_number = extracted_fields.get("documentNumber", "")
    full_name = extracted_fields.get("fullName", "")

    matched_record = query_reference_record(doc_number, full_name, db=db)

    # If document number is not found in government records
    if not matched_record:
        return {
            "found": False,
            "matchedRecord": None,
            "comparisonTable": [
                {
                    "field": "Document Number",
                    "extracted": doc_number or "UNKNOWN",
                    "verified": "NOT FOUND IN REGISTRY",
                    "isMatch": False,
                    "diffNote": "Unregistered Document Number"
                },
                {
                    "field": "Full Name",
                    "extracted": full_name or "UNKNOWN",
                    "verified": "NOT RECORDED",
                    "isMatch": False,
                    "diffNote": "No Registry Match"
                }
            ],
            "fieldMismatches": [
                {
                    "field": "Document Number",
                    "extracted": doc_number or "UNKNOWN",
                    "verified": "NOT FOUND IN REGISTRY",
                    "diffNote": "Unregistered Document Number"
                }
            ],
            "riskContribution": 65,
            "summary": "Document ID not found in official reference database."
        }

    # Build comparison fields list based on extracted fields
    candidate_fields = [
        {"field": "Full Name", "ext": extracted_fields.get("fullName"), "ver": matched_record.get("fullName")},
        {"field": "Document Number", "ext": extracted_fields.get("documentNumber"), "ver": matched_record.get("documentNumber")},
        {"field": "Date of Birth", "ext": extracted_fields.get("dob"), "ver": matched_record.get("dob")},
        {"field": "Nationality", "ext": extracted_fields.get("nationality"), "ver": matched_record.get("nationality")},
        {"field": "Date of Expiry", "ext": extracted_fields.get("expiryDate"), "ver": matched_record.get("dateOfExpiry") or matched_record.get("expiryDate")},
    ]

    # Only add issuing authority if provided in extracted fields
    if extracted_fields.get("issuingAuthority"):
        candidate_fields.append({
            "field": "Issuing Authority",
            "ext": extracted_fields.get("issuingAuthority"),
            "ver": matched_record.get("issuingAuthority")
        })

    mismatches = []
    comparison_table = []
    mismatch_count = 0

    for item in candidate_fields:
        f_name = item["field"]
        ext_val = str(item["ext"] or "").strip()
        ver_val = str(item["ver"] or "").strip()

        norm_ext = normalize_text(ext_val)
        norm_ver = normalize_text(ver_val)

        # Match check
        if not norm_ext or norm_ext == "UNKNOWN":
            is_match = True
            diff_note = "Match Passed"
        elif norm_ext == norm_ver or (norm_ver and (norm_ext in norm_ver or norm_ver in norm_ext)):
            is_match = True
            diff_note = "Match Passed"
        else:
            is_match = False
            mismatch_count += 1
            if f_name == "Date of Birth":
                diff_note = "Birth Date Discrepancy"
            elif f_name == "Date of Expiry":
                diff_note = "Expiry Date Discrepancy"
            elif f_name == "Full Name":
                diff_note = "Name Mismatch"
            elif f_name == "Document Number":
                diff_note = "Document Number Mismatch"
            else:
                diff_note = "Record Mismatch"

            mismatches.append({
                "field": f_name,
                "extracted": ext_val or "—",
                "verified": ver_val or "—",
                "diffNote": diff_note
            })

        comparison_table.append({
            "field": f_name,
            "extracted": ext_val or "—",
            "verified": ver_val or "—",
            "isMatch": is_match,
            "diffNote": diff_note
        })

    # Additional check: If reference record status is EXPIRED or REVOKED
    rec_status = matched_record.get("status", "ACTIVE_VALID")
    if rec_status in ["EXPIRED", "REVOKED", "FLAGGED_RED_NOTICE", "CERTIFICATE_REVOKED"]:
        mismatch_count += 1
        mismatches.append({
            "field": "Document Status",
            "extracted": "Presented as Valid",
            "verified": f"OFFICIALLY {rec_status.replace('_', ' ')}",
            "diffNote": f"Status is {rec_status}"
        })
        comparison_table.append({
            "field": "Document Status",
            "extracted": "Presented as Valid",
            "verified": f"OFFICIALLY {rec_status.replace('_', ' ')}",
            "isMatch": False,
            "diffNote": f"Status is {rec_status}"
        })

    db_risk = min(95, mismatch_count * 35)

    return {
        "found": True,
        "matchedRecord": matched_record,
        "comparisonTable": comparison_table,
        "fieldMismatches": mismatches,
        "riskContribution": db_risk,
        "summary": f"{mismatch_count} field discrepancies detected against official reference records." if mismatch_count > 0 else "All extracted fields match official reference records."
    }
