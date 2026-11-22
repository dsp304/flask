import os
import re
import json
import hashlib
import logging
from datetime import datetime, date
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("contract_watchdog")

# Local application imports
from db import (
    init_db,
    list_workspaces,
    get_workspace,
    create_workspace,
    get_workspace_vertical,
    get_dashboard_contracts,
    get_contract,
    approve_and_update_contract,
    check_duplicate_fingerprint,
    insert_contract,
    encrypt_token,
    decrypt_token,
)
from parser import parse_inbound_email
from extractor import extract_contract_from_text, ContractExtractionResult
from verticals import VERTICAL_CONFIGS

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("TOKEN_ENCRYPTION_KEY") or "watchdog_secret_2026"

# Initialize database tables on application start
try:
    init_db()
except Exception as e:
    logger.error(f"Failed to initialize database tables on startup: {e}")


def format_search_query_string(keywords: list) -> str:
    """Format keywords into a clean copy-pasteable Gmail/M365 search query."""
    terms = []
    for kw in keywords:
        clean = kw.strip()
        if " " in clean:
            terms.append(f'"{clean}"')
        else:
            terms.append(clean)
    return " OR ".join(terms)


def render_vertical_landing(vertical_id: str):
    """Render tailored vertical landing page with headline, subheadline, ROI hook, and trust strip."""
    if vertical_id not in VERTICAL_CONFIGS:
        vertical_id = "general_b2b"
    vertical = VERTICAL_CONFIGS[vertical_id]
    all_workspaces = list_workspaces()
    return render_template(
        "landing.html",
        active_nav="landing",
        vertical_id=vertical_id,
        vertical=vertical,
        all_workspaces=all_workspaces,
    )


# ---------------------------------------------------------------------------
# Task 5 Landing Page Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def landing_general_b2b():
    """General Business landing page (vertical_id='general_b2b')."""
    return render_vertical_landing("general_b2b")


@app.route("/property-management", methods=["GET"])
def landing_property_management():
    """Property Management landing page (vertical_id='property_mgmt')."""
    return render_vertical_landing("property_mgmt")


@app.route("/dental-clinics", methods=["GET"])
def landing_dental_clinics():
    """Dental & Medical Clinics landing page (vertical_id='dental_medical')."""
    return render_vertical_landing("dental_medical")


@app.route("/msp", methods=["GET"])
def landing_msp():
    """MSPs & IT Agencies landing page (vertical_id='msp_it')."""
    return render_vertical_landing("msp_it")


@app.route("/logistics", methods=["GET"])
def landing_logistics():
    """Logistics & Light Manufacturing landing page (vertical_id='logistics_mfg')."""
    return render_vertical_landing("logistics_mfg")


# ---------------------------------------------------------------------------
# Dashboard Route
# ---------------------------------------------------------------------------
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """
    Dashboard route:
    Displays active contracts ordered by calculated_cancellation_deadline ASC,
    plus a separate 'Needs Review' section for contracts with status = 'needs_review'
    or confidence_score < 0.85.
    """
    all_workspaces = list_workspaces()
    
    # Resolve requested workspace_id (prefer DEFAULT_WORKSPACE_ID or ws_default if not explicitly given)
    requested_ws_id = request.args.get("workspace_id")
    if not requested_ws_id:
        default_candidate = os.environ.get("DEFAULT_WORKSPACE_ID", "ws_default")
        if any(ws["id"] == default_candidate for ws in all_workspaces):
            requested_ws_id = default_candidate
        elif all_workspaces:
            requested_ws_id = all_workspaces[0]["id"]
        else:
            requested_ws_id = default_candidate

    # Fetch workspace metadata
    current_workspace = get_workspace(requested_ws_id)
    if not current_workspace:
        # Create default workspace if none exists
        current_workspace = create_workspace(requested_ws_id, f"Workspace {requested_ws_id}", "general_b2b")
        all_workspaces = list_workspaces()

    vertical_id = current_workspace.get("vertical_id") or "general_b2b"
    vertical_info = VERTICAL_CONFIGS.get(vertical_id, VERTICAL_CONFIGS["general_b2b"])

    # Fetch active and needs-review contracts
    active_contracts, review_contracts = get_dashboard_contracts(requested_ws_id)

    # Compute quick stats
    total_spend = sum(
        float(c.get("annual_spend_estimate") or 0.0)
        for c in active_contracts
    )
    
    critical_deadlines = sum(
        1 for c in active_contracts
        if c.get("days_left") is not None and c.get("days_left") <= 45
    )

    # Combine all contracts into JSON string for client-side modal hydration
    combined_contracts = []
    for c in (review_contracts + active_contracts):
        c_copy = dict(c)
        # Convert date objects to ISO strings and Decimals to floats/strings for JSON serialization
        for k in ("expiration_or_renewal_date", "calculated_cancellation_deadline", "coi_or_compliance_expiry", "created_at", "updated_at"):
            if c_copy.get(k) is not None:
                c_copy[k] = str(c_copy[k])
        if c_copy.get("annual_spend_estimate") is not None:
            try:
                c_copy["annual_spend_estimate"] = float(c_copy["annual_spend_estimate"])
            except Exception:
                c_copy["annual_spend_estimate"] = str(c_copy["annual_spend_estimate"])
        combined_contracts.append(c_copy)

    return render_template(
        "dashboard.html",
        active_nav="dashboard",
        current_workspace=current_workspace,
        all_workspaces=all_workspaces,
        vertical_info=vertical_info,
        active_contracts=active_contracts,
        review_contracts=review_contracts,
        all_contracts_json=json.dumps(combined_contracts, default=str),
        total_spend=total_spend,
        critical_deadlines=critical_deadlines,
    )


# ---------------------------------------------------------------------------
# Contract Review & Approval Route
# ---------------------------------------------------------------------------
@app.route("/contracts/<int:contract_id>/approve", methods=["POST"])
def approve_contract(contract_id: int):
    """
    Approve & Update Route:
    Updates extracted fields (vendor_name, expiration_or_renewal_date,
    notice_period_days, calculated_cancellation_deadline, annual_spend_estimate)
    and sets status = 'active'.
    """
    workspace_id = request.args.get("workspace_id") or request.form.get("workspace_id") or "ws_default"

    # Support JSON payload or Form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    success = approve_and_update_contract(contract_id, data)

    if not success:
        if request.is_json:
            return jsonify({"error": f"Failed to approve contract {contract_id}"}), 400
        flash(f"Error: Could not update contract #{contract_id}.", "error")
        return redirect(url_for("dashboard", workspace_id=workspace_id))

    vendor = data.get("vendor_name") or f"Contract #{contract_id}"
    logger.info(f"Approved contract {contract_id} for vendor '{vendor}' in workspace {workspace_id}")

    if request.is_json:
        return jsonify({
            "status": "success",
            "contract_id": contract_id,
            "message": f"Contract for {vendor} approved and set to active.",
        }), 200

    flash(f"Contract for '{vendor}' has been approved and activated in watchdog alerts.", "success")
    return redirect(url_for("dashboard", workspace_id=workspace_id))


# ---------------------------------------------------------------------------
# Onboarding Routes
# ---------------------------------------------------------------------------
@app.route("/onboarding", methods=["GET", "POST"])
def onboarding():
    """
    Onboarding Route:
    Lets a user pick one of the 5 verticals from VERTICAL_CONFIGS,
    creates a workspaces row, and displays their dedicated inbound email address
    plus copy-pasteable Gmail/M365 filter keywords for that vertical.
    """
    all_workspaces = list_workspaces()
    requested_vertical = (request.args.get("vertical") or "general_b2b").strip()
    if requested_vertical not in VERTICAL_CONFIGS:
        requested_vertical = "general_b2b"

    if request.method == "GET":
        return render_template(
            "onboarding.html",
            active_nav="onboarding",
            verticals=VERTICAL_CONFIGS,
            selected_vertical_id=requested_vertical,
            all_workspaces=all_workspaces,
            created_workspace=None,
        )

    # Handle POST
    name = (request.form.get("name") or "").strip()
    raw_id = (request.form.get("workspace_id") or "").strip()
    vertical_id = (request.form.get("vertical_id") or "general_b2b").strip()

    if vertical_id not in VERTICAL_CONFIGS:
        vertical_id = "general_b2b"

    # Auto-generate clean slug if missing
    if not raw_id:
        clean_slug = re.sub(r"[^a-zA-Z0-9]+", "_", name.lower()).strip("_")
        raw_id = f"ws_{clean_slug}" if clean_slug else f"ws_{int(datetime.now().timestamp())}"
    else:
        raw_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", raw_id.lower()).strip("_")

    if not name:
        name = f"Workspace {raw_id}"

    # Persist workspace to database
    created_ws = create_workspace(raw_id, name, vertical_id)
    selected_vertical = VERTICAL_CONFIGS.get(vertical_id, VERTICAL_CONFIGS["general_b2b"])
    search_query_string = format_search_query_string(selected_vertical.get("search_keywords", []))

    flash(f"Workspace '{name}' created with vertical '{selected_vertical['display_name']}'!", "success")

    return render_template(
        "onboarding.html",
        active_nav="onboarding",
        verticals=VERTICAL_CONFIGS,
        all_workspaces=list_workspaces(),
        created_workspace=created_ws,
        selected_vertical=selected_vertical,
        search_query_string=search_query_string,
    )


# ---------------------------------------------------------------------------
# Health Check Route
# ---------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint for deployment monitoring."""
    return jsonify({
        "status": "healthy",
        "service": "contract-renewal-watchdog",
        "gemini_configured": bool(os.environ.get("GEMINI_API_KEY")),
        "mysql_configured": bool(os.environ.get("MYSQLHOST") or os.environ.get("MYSQL_URL")),
    }), 200


# ---------------------------------------------------------------------------
# Inbound Webhook Endpoint (Postmark-compatible)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Task 6 Alert Scanner & Worker Trigger Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/alerts/run", methods=["POST", "GET"])
def trigger_alert_scan():
    """
    Trigger daily contract cancellation deadline alert scan via API or Cron.
    Queries contracts within vertical lead windows and records alerts into alert_logs.
    """
    from alerts import run_alert_scan
    workspace_id = request.args.get("workspace_id")
    dry_run = request.args.get("dry_run", "").lower() in ("true", "1")
    force = request.args.get("force", "").lower() in ("true", "1")

    result = run_alert_scan(workspace_id=workspace_id, dry_run=dry_run, force=force)
    return jsonify(result), 200


@app.route("/api/alerts/history", methods=["GET"])
def alert_history():
    """Retrieve audit trail of dispatched contract cancellation alerts."""
    from db import get_alert_logs
    workspace_id = request.args.get("workspace_id")
    limit = int(request.args.get("limit", 50))
    logs = get_alert_logs(workspace_id=workspace_id, limit=limit)
    return jsonify({
        "workspace_id": workspace_id or "all",
        "total_alerts": len(logs),
        "alerts": logs,
    }), 200


@app.route("/api/worker/backfill", methods=["POST"])
def trigger_worker_backfill():
    """
    Trigger historical connector backfill (Microsoft Graph or Google Workspace).
    """
    from worker import MicrosoftGraphConnector, GoogleWorkspaceConnector, ingest_normalized_message
    data = request.get_json(silent=True) or request.args.to_dict()
    workspace_id = data.get("workspace_id") or "ws_default"
    connector_type = (data.get("connector") or "all").lower()
    vertical_id = get_workspace_vertical(workspace_id)

    results = []

    if connector_type in ("microsoft", "all"):
        ms_conn = MicrosoftGraphConnector(workspace_id)
        messages = ms_conn.fetch_historical_messages(vertical_id)
        for m in messages:
            res = ingest_normalized_message(workspace_id, m)
            results.append({"connector": "microsoft_graph", "result": res})

    if connector_type in ("google", "all"):
        g_conn = GoogleWorkspaceConnector(workspace_id)
        messages = g_conn.fetch_historical_messages(vertical_id)
        for m in messages:
            res = ingest_normalized_message(workspace_id, m)
            results.append({"connector": "google_workspace", "result": res})

    return jsonify({
        "workspace_id": workspace_id,
        "vertical_id": vertical_id,
        "processed_count": len(results),
        "items": results,
    }), 200


@app.route("/api/connectors/test", methods=["GET"])
def test_connectors():
    """
    Test mailbox connectivity for Microsoft Graph and Google Workspace.
    Verifies that access tokens are valid and reports the authenticated mailbox email address.
    """
    from worker import MicrosoftGraphConnector, GoogleWorkspaceConnector
    workspace_id = request.args.get("workspace_id") or "ws_default"
    provider = (request.args.get("provider") or "all").lower()
    token = request.args.get("token")
    vertical_id = get_workspace_vertical(workspace_id)

    results = {}

    if provider in ("microsoft", "all"):
        ms = MicrosoftGraphConnector(workspace_id, access_token=token)
        results["microsoft"] = ms.test_connection()
        results["microsoft"]["query_preview"] = ms.build_24_month_search_query(vertical_id)

    if provider in ("google", "all"):
        g = GoogleWorkspaceConnector(workspace_id, access_token=token)
        results["google"] = g.test_connection()
        results["google"]["query_preview"] = g.build_24_month_search_query(vertical_id)

    return jsonify({
        "workspace_id": workspace_id,
        "vertical_id": vertical_id,
        "connectors": results,
    }), 200


@app.route("/api/connectors/save", methods=["POST"])
def save_connector_token():
    """
    Store or update an encrypted OAuth connection for a workspace.
    """
    from db import save_oauth_connection
    data = request.get_json(silent=True) or request.form.to_dict()
    workspace_id = (data.get("workspace_id") or "ws_default").strip()
    provider = (data.get("provider") or "microsoft").strip().lower()
    email = (data.get("email") or "").strip()
    access_token = (data.get("access_token") or "").strip()
    refresh_token = (data.get("refresh_token") or "").strip()
    scopes = (data.get("scopes") or ("Mail.Read" if provider == "microsoft" else "https://www.googleapis.com/auth/gmail.readonly")).strip()

    if not access_token:
        return jsonify({"error": "access_token is required"}), 400

    conn_id = save_oauth_connection(
        workspace_id=workspace_id,
        provider=provider,
        email=email,
        access_token=access_token,
        refresh_token=refresh_token,
        scopes=scopes,
    )

    return jsonify({
        "status": "success",
        "connection_id": conn_id,
        "workspace_id": workspace_id,
        "provider": provider,
        "email": email,
        "message": f"Successfully saved and encrypted OAuth credentials for {provider} ({email}).",
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
