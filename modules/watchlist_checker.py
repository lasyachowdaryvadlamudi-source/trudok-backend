import re
from datetime import datetime

# SIMULATED INTERNATIONAL WATCHLIST DATABASE
# Integration point for INTERPOL I-24/7, SLTD (Stolen & Lost Travel Documents), and UN Sanctions.
WATCHLIST_REGISTRY = [
    {
        "id": "WLIST-INT-9921",
        "category": "INTERPOL_RED_NOTICE",
        "severity": "CRITICAL",
        "targetName": "DARIUS VANCE KOWALSKI",
        "aliases": ["Arthur P. Morrison", "Aleksander Novak", "Darius Vance"],
        "targetDocNumber": "EL-84920194",
        "nationality": "Eldoria (ELD)",
        "wantedFor": "Transnational Financial Fraud & Identity Forgery",
        "issuingCountry": "Interpol Lyon / SSB Joint Taskforce",
        "actionDirective": "HOLD SUBJECT IMMEDIATELY — Escort to Secondary Interview Facility and notify SSB Command.",
        "directiveCode": "DIRECTIVE #MHA-7719",
        "collisionConfidence": 94.8,
        "matchingEntities": [
            {
                "id": "COLL-01",
                "docNumber": "PASSPORT-EL-84920194",
                "nameOnDoc": "Darius Vance Kowalski",
                "nationality": "Eldoria (ELD)",
                "issueDate": "2019-11-22",
                "interpolWatchlist": "RED NOTICE #8849-A"
            },
            {
                "id": "COLL-02",
                "docNumber": "PASSPORT-CAN-77401928",
                "nameOnDoc": "Richard Vance Thorne",
                "nationality": "Canada (CAN)",
                "issueDate": "2021-03-12",
                "interpolWatchlist": "RED NOTICE #8849-B"
            }
        ]
    },
    {
        "id": "WLIST-INT-4412",
        "category": "INTERPOL_RED_NOTICE",
        "severity": "CRITICAL",
        "targetName": "RICHARD VANCE THORNE",
        "aliases": ["Arthur Morrison", "Richard Thorne"],
        "targetDocNumber": "NAT-77401928",
        "nationality": "Canada (CAN)",
        "wantedFor": "Passport Cloning & International Money Laundering",
        "issuingCountry": "RCMP / Interpol Ottawa",
        "actionDirective": "DETAIN SUBJECT — Immediate notification to Ministry of External Affairs.",
        "directiveCode": "DIRECTIVE #MHA-9902",
        "collisionConfidence": 91.2,
        "matchingEntities": [
            {
                "id": "COLL-03",
                "docNumber": "PASSPORT-NAT-77401928",
                "nameOnDoc": "Richard Vance Thorne",
                "nationality": "Canada (CAN)",
                "issueDate": "2021-03-12",
                "interpolWatchlist": "RED NOTICE #8849-B"
            }
        ]
    },
    {
        "id": "WLIST-SLTD-8819",
        "category": "STOLEN_LOST_TRAVEL_DOCUMENT",
        "severity": "CRITICAL",
        "targetName": "TARIQ AL-MANSOOR",
        "aliases": [],
        "targetDocNumber": "VIS-8819204",
        "nationality": "United Arab Emirates (ARE)",
        "wantedFor": "Revoked Visa Certificate & Reported Stolen Blank Substrate",
        "issuingCountry": "Consular Affairs Division",
        "actionDirective": "CONFISCATE DOCUMENT — Revocation verified in SLTD database.",
        "directiveCode": "DIRECTIVE #SLTD-4419",
        "collisionConfidence": 88.0,
        "matchingEntities": []
    },
    {
        "id": "WLIST-UN-5520",
        "category": "UN_SANCTIONS_LIST",
        "severity": "HIGH",
        "targetName": "RAJESH KUMAR SHRESTHA",
        "aliases": ["Rajesh Shrestha"],
        "targetDocNumber": "PRM-5520918",
        "nationality": "Nepal (NPL)",
        "wantedFor": "Cross-Border Smuggling Investigation",
        "issuingCountry": "Border Security Taskforce",
        "actionDirective": "FLAG FOR SECONDARY INSPECTION — Document validity year discrepancy.",
        "directiveCode": "DIRECTIVE #SSB-1082",
        "collisionConfidence": 82.5,
        "matchingEntities": []
    }
]

def normalize_str(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"[^A-Z0-9]", "", text.upper())

def check_watchlists(extracted_fields: dict) -> dict:
    """
    Checks extracted identity data against INTERPOL Red Notices, SLTD Stolen Document records,
    and multi-identity collision registries.
    """
    doc_num = normalize_str(extracted_fields.get("documentNumber", ""))
    full_name = normalize_str(extracted_fields.get("fullName", ""))

    matched_watchlist = None

    for item in WATCHLIST_REGISTRY:
        target_doc = normalize_str(item["targetDocNumber"])
        target_name = normalize_str(item["targetName"])
        
        # 1. Match by document number
        if doc_num and target_doc and (doc_num == target_doc or doc_num in target_doc or target_doc in doc_num):
            matched_watchlist = item
            break

        # 2. Match by target name
        if full_name and target_name and (full_name == target_name or full_name in target_name or target_name in full_name):
            matched_watchlist = item
            break

        # 3. Match against aliases
        if full_name:
            for alias in item.get("aliases", []):
                alias_norm = normalize_str(alias)
                if alias_norm and (alias_norm in full_name or full_name in alias_norm):
                    matched_watchlist = item
                    break
        if matched_watchlist:
            break

    if matched_watchlist:
        return {
            "hasMatch": True,
            "category": matched_watchlist["category"],
            "severity": matched_watchlist["severity"],
            "targetName": matched_watchlist["targetName"],
            "wantedFor": matched_watchlist["wantedFor"],
            "issuingAgency": matched_watchlist["issuingCountry"],
            "actionDirective": matched_watchlist["actionDirective"],
            "directiveCode": matched_watchlist["directiveCode"],
            "collisionConfidence": matched_watchlist.get("collisionConfidence", 90.0),
            "matchingEntities": matched_watchlist.get("matchingEntities", []),
            "riskElevation": 50
        }

    return {
        "hasMatch": False,
        "category": "CLEAR",
        "severity": "LOW",
        "targetName": None,
        "wantedFor": None,
        "issuingAgency": None,
        "actionDirective": "Standard border screening protocol",
        "directiveCode": "STANDARD-PASS",
        "collisionConfidence": 0.0,
        "matchingEntities": [],
        "riskElevation": 0
    }
