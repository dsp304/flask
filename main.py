import os
import hashlib
import logging
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("contract_watchdog")

# Local application imports
from db import (
    init_db,
    get_workspace_vertical,
    check_duplicate_fingerprint,
    insert_contract,
    encrypt_token,
    decrypt_token,
)
from parser import parse_inbound_email
from extractor import extract_contract_from_text, ContractExtractionResult

app = Flask(__name__)

# Initialize database tables on application start
try:
    init_db()
except Exception as e:
    logger.error(f"Failed to initialize database tables on startup: {e}")


@app.route("/")
def index():
    """Default landing / status page."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint for deployment monitoring."""
    return jsonify({
        "status": "healthy",
        "service": "contract-renewal-watchdog",
        "gemini_configured": bool(os.environ.get("GEMINI_API_KEY")),
        "mysql_configured": bool(os.environ.get("MYSQLHOST") or os.environ.get("MYSQL_URL")),
    }), 200


@app.route("/api/webhooks/inbound-email", methods=["POST"])
def inbound_email_webhook():
    """
    Inbound Email Webhook endpoint accepting Postmark-style JSON payloads.
    
    Workflow:
    1. Resolve workspace_id from MailboxHash, headers, or query parameters.
    2. Clean HTML email body, strip reply chains, and extract attachments (PDF/DOCX).
    3. Look up workspace's vertical_id for vertical-specific extraction guidelines.
    4. Extract structured contract metadata using Gemini 3.5 Flash-Lite.
    5. Compute a SHA-256 fingerprint_hash from (workspace_id, vendor_name/sender, contract_title/subject, content_hash)
       to enforce deduplication via uq_workspace_fingerprint.
    6. Set status to 'needs_review' if confidence_score < 0.85 (or 'active' otherwise).
    7. Persist contract record into MySQL.
    """
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    # 1. Resolve workspace_id (Postmark MailboxHash is standard for routing)
    workspace_id = (
        payload.get("MailboxHash")
        or request.args.get("workspace_id")
        or request.headers.get("X-Workspace-Id")
        or payload.get("workspace_id")
        or os.environ.get("DEFAULT_WORKSPACE_ID", "ws_default")
    ).strip()

    # 2. Parse email body and attachments
    try:
        parsed = parse_inbound_email(payload)
    except Exception as e:
        logger.exception("Failed to parse inbound email payload")
        return jsonify({"error": f"Payload parsing failed: {str(e)}"}), 422

    combined_text = parsed.get("combined_text", "").strip()
    if not combined_text:
        logger.warning(f"Inbound email from {parsed.get('sender_email')} contained no readable text or attachments.")
        return jsonify({
            "status": "skipped",
            "message": "Email contained no readable text body or supported attachments (PDF/DOCX)."
        }), 200

    # 3. Retrieve workspace vertical
    vertical_id = get_workspace_vertical(workspace_id)

    # 4. Extract structured metadata using Gemini 3.5 Flash-Lite
    try:
        extraction: ContractExtractionResult = extract_contract_from_text(
            raw_text=combined_text,
            vertical_id=vertical_id,
        )
    except Exception as e:
        logger.exception(f"Gemini extraction failed for workspace {workspace_id}")
        return jsonify({"error": f"LLM contract extraction failed: {str(e)}"}), 502

    # 5. Compute SHA-256 fingerprint_hash:
    # (workspace_id, vendor_name/sender, contract_title/subject, content_hash)
    vendor_key = (extraction.vendor_name or parsed["sender_email"] or "unknown_vendor").strip().lower()
    title_key = (extraction.contract_title or parsed["subject"] or "untitled_contract").strip().lower()
    content_hash = parsed["content_hash"]

    fingerprint_raw = f"{workspace_id}|{vendor_key}|{title_key}|{content_hash}"
    fingerprint_hash = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()

    # 6. Deduplication check against uq_workspace_fingerprint
    if check_duplicate_fingerprint(workspace_id, fingerprint_hash):
        logger.info(f"Duplicate contract detected for workspace {workspace_id} (hash: {fingerprint_hash})")
        return jsonify({
            "status": "duplicate",
            "message": "Contract already processed (uq_workspace_fingerprint)",
            "workspace_id": workspace_id,
            "fingerprint_hash": fingerprint_hash,
            "vendor_name": extraction.vendor_name,
            "contract_title": extraction.contract_title,
        }), 200

    # 7. Determine contract status
    # Set status to 'needs_review' if confidence_score < 0.85 (or 'active' otherwise)
    if not extraction.is_valid_contract_or_renewal:
        status = "needs_review"
    elif extraction.confidence_score is not None and extraction.confidence_score < 0.85:
        status = "needs_review"
    else:
        status = "active"

    # 8. Persist to MySQL database
    try:
        record = insert_contract(
            workspace_id=workspace_id,
            fingerprint_hash=fingerprint_hash,
            status=status,
            extraction=extraction,
            raw_content=combined_text,
            sender_email=parsed["sender_email"],
            email_subject=parsed["subject"],
        )
    except Exception as e:
        # Handle concurrent insert race condition gracefully
        if "uq_workspace_fingerprint" in str(e) or "Duplicate entry" in str(e):
            logger.info(f"Handled concurrent duplicate insert for {fingerprint_hash}")
            return jsonify({
                "status": "duplicate",
                "message": "Contract already processed (uq_workspace_fingerprint)",
                "workspace_id": workspace_id,
                "fingerprint_hash": fingerprint_hash,
            }), 200
        logger.exception("Failed to insert contract into database")
        return jsonify({"error": f"Database insertion failed: {str(e)}"}), 500

    logger.info(
        f"Successfully processed contract {record.get('id')} for workspace {workspace_id}: "
        f"vendor='{extraction.vendor_name}', status='{status}', confidence={extraction.confidence_score}"
    )

    return jsonify({
        "status": "success",
        "contract_id": record.get("id"),
        "workspace_id": workspace_id,
        "contract_status": status,
        "fingerprint_hash": fingerprint_hash,
        "vendor_name": extraction.vendor_name,
        "contract_title": extraction.contract_title,
        "category": extraction.category,
        "confidence_score": extraction.confidence_score,
        "expiration_or_renewal_date": extraction.expiration_or_renewal_date,
        "calculated_cancellation_deadline": extraction.calculated_cancellation_deadline,
        "notice_period_days": extraction.notice_period_days,
        "auto_renewal_term_months": extraction.auto_renewal_term_months,
        "annual_spend_estimate": extraction.annual_spend_estimate,
        "currency": extraction.currency,
        "key_risk_flags": extraction.key_risk_flags,
        "source_evidence_quote": extraction.source_evidence_quote,
        "is_valid_contract_or_renewal": extraction.is_valid_contract_or_renewal,
    }), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)

"""
=============================================================================
ENVIRONMENT VARIABLES (.env) GUIDE
=============================================================================

# --- MySQL Connection Settings ---
MYSQLHOST=autorack.proxy.rlwy.net
MYSQLPORT=43095
MYSQLUSER=root
MYSQLDATABASE=railway
MYSQLPASSWORD=your_mysql_password
# Or full connection URL:
# MYSQL_URL=mysql://root:password@autorack.proxy.rlwy.net:43095/railway

# --- Google Gemini AI Studio API Key ---
GEMINI_API_KEY=AIzaSy...

# --- Fernet Encryption Key for OAuth Tokens ---
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
TOKEN_ENCRYPTION_KEY=aHthFn88pEWsLtc9towSCa-o6IUoQ5VFimL17KVred0=

# --- Workspace & Pooling Config ---
DEFAULT_WORKSPACE_ID=ws_default
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_RECYCLE=1800

=============================================================================
QUICK CURL TEST EXAMPLE
=============================================================================

# Test 1: Health check
curl -X GET http://localhost:5000/api/health

# Test 2: Inbound Email Webhook (Property Management Vertical Renewal Notice)
curl -X POST http://localhost:5000/api/webhooks/inbound-email \
  -H "Content-Type: application/json" \
  -d '{
    "From": "billing@waste-management-services.com",
    "FromName": "WM Customer Care",
    "FromFull": {
      "Email": "billing@waste-management-services.com",
      "Name": "WM Customer Care"
    },
    "To": "watchdog+ws_default@inbound.contractwatchdog.com",
    "MailboxHash": "ws_default",
    "Subject": "Upcoming Commercial Waste Agreement Renewal - Notice of CPI Adjustment",
    "TextBody": "Dear Property Manager,\n\nYour 36-month Commercial Waste Hauling Agreement #WM-88219 is scheduled to auto-renew on 2027-04-30.\nPer Section 8.2 of your service terms, written notice of cancellation must be submitted at least 60 days prior to the expiration date via certified mail (deadline: 2027-03-01), otherwise the agreement will automatically extend for an additional 24 months.\nAn annual CPI price adjustment of 4.5% will be applied starting on the renewal date. Current estimated annual spend is $14,400.00 USD.\n\nThank you,\nWM Operations",
    "HtmlBody": "<p>Dear Property Manager,</p><p>Your 36-month Commercial Waste Hauling Agreement #WM-88219 is scheduled to auto-renew on <strong>2027-04-30</strong>.<br>Per Section 8.2 of your service terms, written notice of cancellation must be submitted at least <strong>60 days</strong> prior to the expiration date via certified mail (deadline: <strong>2027-03-01</strong>), otherwise the agreement will automatically extend for an additional 24 months.<br>An annual CPI price adjustment of 4.5% will be applied starting on the renewal date. Current estimated annual spend is $14,400.00 USD.</p><p>Thank you,<br>WM Operations</p>",
    "Attachments": []
  }'

# Test 3: Re-sending the exact same payload will trigger duplicate detection:
# Response: {"status": "duplicate", "message": "Contract already processed (uq_workspace_fingerprint)", ...}
=============================================================================
"""
