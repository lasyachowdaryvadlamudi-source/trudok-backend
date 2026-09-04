import os
import sys
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

# Configure stdout logging for Render and cloud log aggregators
logger = logging.getLogger("trudok.audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [AUDIT] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

LOG_FILE = os.path.join(os.path.dirname(__file__), "audit.log")

def hash_client_ip(client_ip: str) -> str:
    """Hashes client IP to ensure privacy while maintaining audit traceability."""
    if not client_ip:
        return "unknown"
    return hashlib.sha256(client_ip.encode("utf-8")).hexdigest()[:12]

def log_audit_event(
    endpoint: str,
    method: str,
    status_code: int,
    client_ip: str,
    action: str,
    document_type: Optional[str] = None,
    risk_score: Optional[int] = None,
    result_summary: Optional[str] = None,
    db: Optional[Session] = None
):
    """
    Records an immutable audit trail for security compliance and investigation.
    DATA MINIMIZATION RULE: Raw images, biometric binaries, full names, or document numbers
    are NEVER logged to disk or stdout.
    """
    ip_hash = hash_client_ip(client_ip)
    timestamp_iso = datetime.now(timezone.utc).isoformat()

    log_entry = {
        "timestamp": timestamp_iso,
        "method": method,
        "endpoint": endpoint,
        "status_code": status_code,
        "client_hash": ip_hash,
        "action": action,
        "document_type": document_type,
        "risk_score": risk_score,
        "result": result_summary
    }

    # 1. Output sanitized JSON to stdout (Render log stream)
    logger.info(json.dumps(log_entry))

    # 2. Append to local audit.log file
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[Audit File Warning] {e}")

    # 3. Persist to database AuditLog table if session provided
    if db is not None:
        try:
            from database import AuditLog
            db_log = AuditLog(
                endpoint=endpoint,
                method=method,
                status_code=status_code,
                client_ip_hash=ip_hash,
                action=action,
                document_type=document_type,
                risk_score=risk_score,
                result_summary=result_summary
            )
            db.add(db_log)
            db.commit()
        except Exception as db_err:
            print(f"[Audit DB Warning] {db_err}")
            db.rollback()
