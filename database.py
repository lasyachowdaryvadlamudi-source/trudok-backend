import os
import json
import logging
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from config import settings
from encryption import encrypt_pii, decrypt_pii

logger = logging.getLogger("trudok.database")

# SIMULATED REFERENCE DATABASE — represents the integration point for real government ID systems
# (UIDAI, passport records) not accessible in this prototype. In production this endpoint would call authenticated government APIs.

DATABASE_URL = settings.DATABASE_URL
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Enforce TLS/SSL connection parameters for PostgreSQL
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
elif DATABASE_URL.startswith("postgresql"):
    # Ensure sslmode=require for secure cloud database connections
    if "sslmode=" not in DATABASE_URL:
        separator = "&" if "?" in DATABASE_URL else "?"
        DATABASE_URL = f"{DATABASE_URL}{separator}sslmode=require"

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, index=True)
    scan_id = Column(String(64), index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    document_type = Column(String(32), default="passport", index=True)
    risk_score = Column(Integer, default=0)
    verdict = Column(String(64), default="Verified")
    status_pill = Column(String(32), default="CLEAR")
    officer_id = Column(String(64), default="SSB-OFFICER-01")
    
    # Encrypted PII Fields at Rest
    holder_name_encrypted = Column(String(256), default="UNKNOWN")
    document_number_encrypted = Column(String(256), index=True)
    details_json = Column(Text, default="{}")

    @property
    def holder_name(self) -> str:
        return decrypt_pii(self.holder_name_encrypted)

    @holder_name.setter
    def holder_name(self, value: str):
        self.holder_name_encrypted = encrypt_pii(value)

    @property
    def document_number(self) -> str:
        return decrypt_pii(self.document_number_encrypted)

    @document_number.setter
    def document_number(self, value: str):
        self.document_number_encrypted = encrypt_pii(value)


class ReferenceDocument(Base):
    __tablename__ = "reference_documents"

    id = Column(String(64), primary_key=True)
    document_number = Column(String(64), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=False)
    dob = Column(String(32), nullable=False)
    nationality = Column(String(64), nullable=False)
    country_code = Column(String(16), default="")
    date_of_issue = Column(String(32), default="")
    date_of_expiry = Column(String(32), default="")
    gender = Column(String(8), default="M")
    document_type = Column(String(32), default="passport")
    issuing_authority = Column(String(128), default="")
    status = Column(String(64), default="ACTIVE_VALID")
    is_tampered_sample = Column(Boolean, default=False)
    notes = Column(Text, default="")


class WatchlistEntry(Base):
    __tablename__ = "watchlist"

    id = Column(String(64), primary_key=True)
    category = Column(String(64), nullable=False)
    severity = Column(String(32), default="CRITICAL")
    target_name = Column(String(128), nullable=False)
    target_doc_number = Column(String(64), index=True)
    nationality = Column(String(64), default="")
    wanted_for = Column(Text, default="")
    issuing_agency = Column(String(128), default="")
    action_directive = Column(Text, default="")
    directive_code = Column(String(64), default="")
    collision_confidence = Column(Float, default=90.0)
    aliases_json = Column(Text, default="[]")
    matching_entities_json = Column(Text, default="[]")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    endpoint = Column(String(128), nullable=False)
    method = Column(String(16), nullable=False)
    status_code = Column(Integer, nullable=False)
    client_ip_hash = Column(String(64), default="unknown")
    action = Column(String(64), nullable=False)
    document_type = Column(String(32), nullable=True)
    risk_score = Column(Integer, nullable=True)
    result_summary = Column(String(256), nullable=True)


class RecordAccessLog(Base):
    """
    Field-level access log for breach forensics:
    Records WHO accessed WHAT document record and WHEN, without storing raw PII in logs.
    """
    __tablename__ = "record_access_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    officer_id = Column(String(64), nullable=False, index=True)
    record_id = Column(String(64), nullable=False, index=True)
    action = Column(String(64), default="VIEW_DOSSIER")
    client_ip_hash = Column(String(64), default="unknown")


def log_record_access(db: Session, officer_id: str, record_id: str, action: str, client_ip_hash: str):
    """Logs field-level record access for audit compliance and forensics."""
    try:
        log_entry = RecordAccessLog(
            officer_id=officer_id or "ANONYMOUS_OFFICER",
            record_id=record_id,
            action=action,
            client_ip_hash=client_ip_hash
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        logger.warning(f"Failed to record access log: {e}")
        db.rollback()


def init_db():
    """Initializes tables and seeds reference documents & watchlist."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        ref_count = db.query(ReferenceDocument).count()
        if ref_count == 0:
            json_path = os.path.join(os.path.dirname(__file__), "data", "reference_documents.json")
            if os.path.exists(json_path):
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    records = data.get("records", [])
                    for r in records:
                        doc = ReferenceDocument(
                            id=r.get("id", f"REF-{r.get('documentNumber')}"),
                            document_number=r.get("documentNumber"),
                            full_name=r.get("fullName"),
                            dob=r.get("dob"),
                            nationality=r.get("nationality"),
                            country_code=r.get("countryCode", ""),
                            date_of_issue=r.get("dateOfIssue", ""),
                            date_of_expiry=r.get("dateOfExpiry", ""),
                            gender=r.get("gender", "M"),
                            document_type=r.get("documentType", "passport"),
                            issuing_authority=r.get("issuingAuthority", ""),
                            status=r.get("status", "ACTIVE_VALID"),
                            is_tampered_sample=r.get("isTamperedSample", False),
                            notes=r.get("notes", "")
                        )
                        db.merge(doc)
                db.commit()
                logger.info(f"Seeded {len(records)} reference documents into database.")

        w_count = db.query(WatchlistEntry).count()
        if w_count == 0:
            from modules.watchlist_checker import WATCHLIST_REGISTRY
            for w in WATCHLIST_REGISTRY:
                entry = WatchlistEntry(
                    id=w.get("id"),
                    category=w.get("category"),
                    severity=w.get("severity", "CRITICAL"),
                    target_name=w.get("targetName"),
                    target_doc_number=w.get("targetDocNumber"),
                    nationality=w.get("nationality", ""),
                    wanted_for=w.get("wantedFor", ""),
                    issuing_agency=w.get("issuingCountry", ""),
                    action_directive=w.get("actionDirective", ""),
                    directive_code=w.get("directiveCode", ""),
                    collision_confidence=w.get("collisionConfidence", 90.0),
                    aliases_json=json.dumps(w.get("aliases", [])),
                    matching_entities_json=json.dumps(w.get("matchingEntities", []))
                )
                db.merge(entry)
            db.commit()
            logger.info("Seeded watchlist records into database.")

    except Exception as e:
        logger.error(f"Error during database initialization/seeding: {e}")
        db.rollback()
    finally:
        db.close()


init_db()


def get_db():
    """FastAPI Dependency for database session management."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
