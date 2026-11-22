import os
import re
import json
import hashlib
import logging
import urllib.parse
from datetime import datetime, date
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    flash,
    session,
    abort,
)
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
    add_workspace_member,
    get_workspace_emails,
    get_user_workspaces,
    can_user_access_workspace,
    save_oauth_connection,
    reset_database_data,
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
    """Render landing page focused on Verticals, Review, Demo, and Sign-in."""
    if vertical_id not in VERTICAL_CONFIGS:
        vertical_id = "general_b2b"
    vertical = VERTICAL_CONFIGS[vertical_id]
    
    # If user is logged in, pass scoped workspaces; otherwise default
    user_email = session.get("user_email")
    all_workspaces = get_user_workspaces(user_email) if user_email else list_workspaces()
    
    return render_template(
        "landing.html",
        active_nav="landing",
        vertical_id=vertical_id,
        vertical=vertical,
        all_verticals=VERTICAL_CONFIGS,
        all_workspaces=all_workspaces,
    )


def render_dashboard_view(workspace_id: str, is_demo: bool = False, user_workspaces: list = None):
    """Helper to render dashboard view with contract metrics and human-review modal hydration."""
    if user_workspaces is None:
        user_workspaces = [get_workspace(workspace_id)] if get_workspace(workspace_id) else []

    current_workspace = get_workspace(workspace_id)
    if not current_workspace:
        if is_demo or workspace_id == "ws_default":
            current_workspace = create_workspace("ws_default", "Demo Workspace", "general_b2b")
        else:
            abort(404)

    if workspace_id == "ws_default" or (current_workspace and (current_workspace.get("name") == "Demo Workspace" or current_workspace.get("id") == "ws_default")):
        is_demo = True

    vertical_id = current_workspace.get("vertical_id") or "general_b2b"
    vertical_info = VERTICAL_CONFIGS.get(vertical_id, VERTICAL_CONFIGS["general_b2b"])
    search_query_string = format_search_query_string(vertical_info.get("search_keywords", []))

    active_contracts, review_contracts = get_dashboard_contracts(workspace_id)

    total_spend = sum(
        float(c.get("annual_spend_estimate") or 0.0)
        for c in active_contracts
    )
    critical_deadlines = sum(
        1 for c in active_contracts
        if c.get("days_left") is not None and c.get("days_left") <= 45
    )

    combined_contracts = []
    for c in (review_contracts + active_contracts):
        c_copy = dict(c)
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
        all_workspaces=user_workspaces,
        vertical_info=vertical_info,
        search_query_string=search_query_string,
        active_contracts=active_contracts,
        review_contracts=review_contracts,
        all_contracts_json=json.dumps(combined_contracts, default=str),
        total_spend=total_spend,
        critical_deadlines=critical_deadlines,
        is_demo=is_demo,
    )


# ---------------------------------------------------------------------------
# Task 7 Minimalist Landing Page Routes
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
# Task 7 Authentication & Multi-Email Session Routes
# ---------------------------------------------------------------------------
@app.route("/auth/login", methods=["GET", "POST"])
def auth_login():
    """
    Unified OAuth & Work Email Sign-In Entry Point.
    Accepts vertical query parameter from 'Start Free Contract Review' or 'Sign-in'.
    """
    vertical_id = (request.args.get("vertical") or request.form.get("vertical") or "general_b2b").strip()
    if vertical_id not in VERTICAL_CONFIGS:
        vertical_id = "general_b2b"

    # If already logged in, redirect directly to dashboard
    if session.get("user_email") and request.method == "GET":
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if not email or "@" not in email or "." not in email:
            flash("Please enter a valid work email address.", "error")
            return redirect(url_for("auth_login", vertical=vertical_id))

        session["user_email"] = email
        session["user_name"] = email.split("@")[0]
        logger.info(f"User authenticated with work email: {email}")

        # Check existing workspaces; if none, redirect user to create their first workspace
        workspaces = get_user_workspaces(email)
        if not workspaces:
            flash(f"Signed in as {email}. Please create your first workspace to start monitoring contracts.", "info")
            return redirect(url_for("onboarding", vertical=vertical_id))

        flash(f"Signed in successfully as {email}.", "success")
        return redirect(url_for("dashboard"))

    return render_template(
        "auth_login.html",
        active_nav="login",
        vertical_id=vertical_id,
        vertical=VERTICAL_CONFIGS[vertical_id],
    )


@app.route("/auth/google", methods=["GET"])
def auth_google():
    """
    Initiate Google Workspace OAuth flow.
    Supports live Google OAuth credentials when configured, with simulated dev fallback.
    """
    vertical_id = (request.args.get("vertical") or "general_b2b").strip()
    google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
    
    if google_client_id:
        redirect_uri = url_for("auth_callback", provider="google", _external=True)
        scope = "openid email profile https://www.googleapis.com/auth/gmail.readonly"
        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={google_client_id}&"
            f"redirect_uri={urllib.parse.quote(redirect_uri)}&"
            f"response_type=code&"
            f"scope={urllib.parse.quote(scope)}&"
            f"state={vertical_id}&"
            f"access_type=offline&prompt=consent"
        )
        return redirect(auth_url)

    # Simulated / Instant Google Workspace Sign-In for dev & testing
    mock_email = (request.args.get("email") or f"user@workspace.com").strip().lower()
    session["user_email"] = mock_email
    session["user_name"] = mock_email.split("@")[0]
    workspaces = get_user_workspaces(mock_email)
    if not workspaces:
        flash(f"Signed in with Google as {mock_email}. Please create your first workspace.", "info")
        return redirect(url_for("onboarding", vertical=vertical_id))
    flash(f"Signed in with Google as {mock_email}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/auth/microsoft", methods=["GET"])
def auth_microsoft():
    """
    Initiate Microsoft Entra ID / M365 OAuth flow.
    Supports live Microsoft OAuth credentials when configured, with simulated dev fallback.
    """
    vertical_id = (request.args.get("vertical") or "general_b2b").strip()
    ms_client_id = os.environ.get("MICROSOFT_CLIENT_ID")

    if ms_client_id:
        redirect_uri = url_for("auth_callback", provider="microsoft", _external=True)
        scope = "openid email profile Mail.Read offline_access"
        auth_url = (
            f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
            f"client_id={ms_client_id}&"
            f"redirect_uri={urllib.parse.quote(redirect_uri)}&"
            f"response_type=code&"
            f"scope={urllib.parse.quote(scope)}&"
            f"state={vertical_id}"
        )
        return redirect(auth_url)

    # Simulated / Instant Microsoft 365 Sign-In for dev & testing
    mock_email = (request.args.get("email") or f"user@enterprise.onmicrosoft.com").strip().lower()
    session["user_email"] = mock_email
    session["user_name"] = mock_email.split("@")[0]
    workspaces = get_user_workspaces(mock_email)
    if not workspaces:
        flash(f"Signed in with Microsoft as {mock_email}. Please create your first workspace.", "info")
        return redirect(url_for("onboarding", vertical=vertical_id))
    flash(f"Signed in with Microsoft as {mock_email}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/auth/callback", methods=["GET"])
@app.route("/auth/callback/<provider>", methods=["GET"])
def auth_callback(provider: str = "google"):
    """
    OAuth Callback Handler for Google and Microsoft.
    Exchanges code for tokens, resolves email, and redirects user to /dashboard.
    """
    code = request.args.get("code")
    vertical_id = request.args.get("state") or "general_b2b"

    email = request.args.get("email") or session.get("user_email") or f"{provider}_user@company.com"
    email = email.strip().lower()
    session["user_email"] = email
    session["user_name"] = email.split("@")[0]

    workspaces = get_user_workspaces(email)
    if not workspaces:
        flash(f"OAuth connection established for {email}. Please create your first workspace.", "info")
        return redirect(url_for("onboarding", vertical=vertical_id))

    flash(f"OAuth connection established for {email}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/auth/logout", methods=["GET", "POST"])
def auth_logout():
    """Sign user out and clear active session."""
    session.pop("user_email", None)
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("landing_general_b2b"))


# ---------------------------------------------------------------------------
# Read-Only Demo Dashboard Route
# ---------------------------------------------------------------------------
@app.route("/demo", methods=["GET"])
def demo_dashboard():
    """
    Read-only demo workspace view (ws_default) accessible without requiring login.
    """
    return render_dashboard_view(workspace_id="ws_default", is_demo=True)


# ---------------------------------------------------------------------------
# Dashboard Route (Scoped by Authenticated Email)
# ---------------------------------------------------------------------------
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """
    Scoped Dashboard route:
    - If ?demo=1 or demo mode requested, renders read-only demo dashboard for ws_default without login.
    - Otherwise enforces session['user_email'] authentication and scopes workspace switcher to ONLY
      the workspaces associated with the user's email or linked emails.
    """
    # 1. Check for Demo Mode parameter
    if request.args.get("demo") == "1":
        return render_dashboard_view(workspace_id="ws_default", is_demo=True)

    # 2. Enforce Authentication
    user_email = session.get("user_email")
    if not user_email:
        flash("Please sign in with Google or Microsoft to view your dashboard.", "info")
        return redirect(url_for("auth_login"))

    # 3. Retrieve workspaces scoped to this authenticated user
    user_workspaces = get_user_workspaces(user_email)
    if not user_workspaces:
        flash("You do not have any workspaces yet. Create your first workspace to begin monitoring contracts.", "info")
        return redirect(url_for("onboarding"))

    # 4. Resolve requested workspace and enforce access scoping
    # If no workspace requested, show the first created workspace by default (user_workspaces[0])
    requested_ws_id = request.args.get("workspace_id")
    if requested_ws_id:
        if not can_user_access_workspace(user_email, requested_ws_id):
            flash(f"Access denied: You are not authorized to view workspace '{requested_ws_id}'.", "error")
            requested_ws_id = user_workspaces[0]["id"]
    else:
        requested_ws_id = user_workspaces[0]["id"]

    return render_dashboard_view(workspace_id=requested_ws_id, is_demo=False, user_workspaces=user_workspaces)


# ---------------------------------------------------------------------------
# Contract Review & Approval Route (Enforces Scoping & Demo Guard)
# ---------------------------------------------------------------------------
@app.route("/contracts/<int:contract_id>/approve", methods=["POST"])
def approve_contract(contract_id: int):
    """
    Approve & Update Route:
    Enforces authentication, workspace scoping, and blocks modifications in demo mode.
    """
    # Check demo mode
    if request.args.get("demo") == "1":
        if request.is_json:
            return jsonify({"error": "Modifications are disabled in read-only demo mode."}), 403
        flash("Action disabled: Approvals cannot be performed in read-only demo mode.", "error")
        return redirect(url_for("demo_dashboard"))

    user_email = session.get("user_email")
    if not user_email:
        if request.is_json:
            return jsonify({"error": "Authentication required"}), 401
        flash("Please sign in to approve contracts.", "error")
        return redirect(url_for("auth_login"))

    contract = get_contract(contract_id)
    if not contract:
        if request.is_json:
            return jsonify({"error": f"Contract #{contract_id} not found"}), 404
        flash(f"Contract #{contract_id} not found.", "error")
        return redirect(url_for("dashboard"))

    # Enforce workspace access check
    if not can_user_access_workspace(user_email, contract["workspace_id"]):
        logger.warning(f"Unauthorized approval attempt on contract {contract_id} by {user_email}")
        if request.is_json:
            return jsonify({"error": "Access denied: Unauthorized workspace"}), 403
        flash("Access denied: You do not have permission to modify contracts in this workspace.", "error")
        return redirect(url_for("dashboard"))

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    success = approve_and_update_contract(contract_id, data)
    if not success:
        if request.is_json:
            return jsonify({"error": f"Failed to approve contract {contract_id}"}), 400
        flash(f"Error: Could not update contract #{contract_id}.", "error")
        return redirect(url_for("dashboard", workspace_id=contract["workspace_id"]))

    vendor = data.get("vendor_name") or f"Contract #{contract_id}"
    logger.info(f"Approved contract {contract_id} ({vendor}) in workspace {contract['workspace_id']} by {user_email}")

    if request.is_json:
        return jsonify({
            "status": "success",
            "contract_id": contract_id,
            "message": f"Contract for {vendor} approved and set to active.",
        }), 200

    flash(f"Contract for '{vendor}' has been approved and activated in watchdog alerts.", "success")
    return redirect(url_for("dashboard", workspace_id=contract["workspace_id"]))


# ---------------------------------------------------------------------------
# Workspace Creation & Onboarding (POST /workspaces/create & /onboarding)
# ---------------------------------------------------------------------------
@app.route("/workspaces/create", methods=["POST"])
@app.route("/onboarding", methods=["GET", "POST"])
def onboarding():
    """
    Onboarding & Workspace Creation Route (Task 7):
    - Default the new workspace's associated email to session['user_email'].
    - Allow adding a secondary linked email for flexible multi-email access.
    - Record both emails in workspace_members.
    - Display dedicated inbound address, filter keywords, and clear note on authorized emails.
    """
    user_email = session.get("user_email")
    if not user_email:
        flash("Please sign in before setting up or creating a workspace.", "info")
        return redirect(url_for("auth_login", vertical=request.args.get("vertical", "general_b2b")))

    user_workspaces = get_user_workspaces(user_email)
    requested_vertical = (request.args.get("vertical") or request.form.get("vertical_id") or "general_b2b").strip()
    if requested_vertical not in VERTICAL_CONFIGS:
        requested_vertical = "general_b2b"

    if request.method == "GET":
        return render_template(
            "onboarding.html",
            active_nav="onboarding",
            verticals=VERTICAL_CONFIGS,
            selected_vertical_id=requested_vertical,
            all_workspaces=user_workspaces,
            created_workspace=None,
        )

    # Process POST (either from /workspaces/create or /onboarding)
    name = (request.form.get("name") or "").strip()
    raw_id = (request.form.get("workspace_id") or "").strip()
    vertical_id = requested_vertical
    creator_email = (request.form.get("creator_email") or user_email).strip().lower()
    secondary_email = (request.form.get("secondary_email") or "").strip().lower()

    # Auto-generate clean slug if missing
    if not raw_id:
        clean_slug = re.sub(r"[^a-zA-Z0-9]+", "_", name.lower()).strip("_")
        raw_id = f"ws_{clean_slug}" if clean_slug else f"ws_{int(datetime.now().timestamp())}"
    else:
        raw_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", raw_id.lower()).strip("_")

    if not name:
        name = f"Workspace {raw_id}"

    # Persist workspace and register both creator & secondary emails in workspace_members
    created_ws = create_workspace(
        workspace_id=raw_id,
        name=name,
        vertical_id=vertical_id,
        creator_email=creator_email,
        secondary_email=secondary_email if secondary_email else None,
    )
    # Ensure current session email is explicitly linked as owner
    add_workspace_member(raw_id, user_email, role="owner")

    selected_vertical = VERTICAL_CONFIGS.get(vertical_id, VERTICAL_CONFIGS["general_b2b"])
    search_query_string = format_search_query_string(selected_vertical.get("search_keywords", []))
    workspace_emails = get_workspace_emails(raw_id)

    flash(f"Workspace '{name}' created successfully with vertical '{selected_vertical['display_name']}'!", "success")

    return render_template(
        "onboarding.html",
        active_nav="onboarding",
        verticals=VERTICAL_CONFIGS,
        all_workspaces=get_user_workspaces(user_email),
        created_workspace=created_ws,
        workspace_emails=workspace_emails,
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
    """Retrieve history of dispatched contract cancellation alerts."""
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


@app.route("/api/admin/reset-data", methods=["GET", "POST"])
def admin_reset_data():
    """
    Maintenance route to wipe all contracts, workspaces, members, jobs, and alerts
    so testing can be conducted completely from scratch.
    Pass ?confirm=true or POST {"confirm": true}.
    """
    confirm = request.args.get("confirm", "").lower() in ("true", "1", "yes")
    if not confirm and request.is_json:
        confirm = bool((request.get_json(silent=True) or {}).get("confirm"))

    if not confirm:
        return jsonify({
            "error": "Confirmation required. Pass ?confirm=true to delete all data from contract and workspace tables.",
            "status": "pending_confirmation"
        }), 400

    deleted = reset_database_data(preserve_demo_seed=False)
    session.clear()
    return jsonify({
        "status": "success",
        "message": "All data in contract and workspace tables deleted successfully.",
        "deleted_records": deleted,
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
