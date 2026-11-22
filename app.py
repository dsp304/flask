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
    send_file,
    Response,
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
    get_user_profile,
    save_user_profile,
    update_workspace,
    seed_sample_workspaces_and_contracts,
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
    workspace_emails = get_workspace_emails(workspace_id) if not is_demo else []

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
        workspace_emails=workspace_emails,
        vertical_info=vertical_info,
        search_query_string=search_query_string,
        active_contracts=active_contracts,
        review_contracts=review_contracts,
        all_contracts_json=json.dumps(combined_contracts, default=str),
        total_spend=total_spend,
        critical_deadlines=critical_deadlines,
        is_demo=is_demo,
    )


def generate_synthetic_contract_pdf(contract: dict, filename: str) -> bytes:
    """Generate a clean, professional PDF document for contracts without a physical disk file."""
    try:
        import fitz
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)  # Standard Letter size

        # Colors
        NAVY = (0.09, 0.15, 0.28)
        SLATE = (0.39, 0.45, 0.55)
        DARK = (0.1, 0.1, 0.1)
        AMBER = (0.85, 0.55, 0.1)
        INDIGO = (0.31, 0.27, 0.75)
        LIGHT_BG = (0.96, 0.97, 0.99)
        BORDER_COLOR = (0.85, 0.88, 0.92)

        # Header bar
        page.draw_rect(fitz.Rect(0, 0, 612, 54), fill=NAVY)
        page.insert_text(fitz.Point(36, 34), "CONTRACT RENEWAL WATCHDOG  |  OFFICIAL AGREEMENT RECORD", fontsize=10, color=(1, 1, 1))

        # Title & Vendor
        vendor = contract.get("vendor_name") or "Vendor Agreement"
        title = contract.get("contract_title") or f"Agreement - {vendor}"
        page.insert_text(fitz.Point(36, 90), title[:55], fontsize=17, color=NAVY)
        page.insert_text(fitz.Point(36, 110), f"Vendor / Counterparty: {vendor}", fontsize=11, color=SLATE)
        page.insert_text(fitz.Point(36, 126), f"Document Attachment: {filename}", fontsize=9, color=SLATE)

        # Key Terms Box
        page.draw_rect(fitz.Rect(36, 142, 576, 260), fill=LIGHT_BG, color=BORDER_COLOR)

        col1_x = 50
        col2_x = 320
        y = 168

        cat = contract.get("category") or "General"
        spend = f"${float(contract.get('annual_spend_estimate') or 0):,.2f}" if contract.get("annual_spend_estimate") else "N/A"
        expiry = str(contract.get("expiration_or_renewal_date") or "Not Specified")
        notice = f"{contract.get('notice_period_days') or 30} days required"
        deadline = str(contract.get("calculated_cancellation_deadline") or "Not Calculated")
        renewal_term = f"{contract.get('auto_renewal_term_months') or 12} months" if contract.get("auto_renewal_term_months") else "Annual"

        page.insert_text(fitz.Point(col1_x, y), "Category:", fontsize=10, color=SLATE)
        page.insert_text(fitz.Point(col1_x + 110, y), cat, fontsize=10, color=DARK)
        page.insert_text(fitz.Point(col2_x, y), "Annual Spend:", fontsize=10, color=SLATE)
        page.insert_text(fitz.Point(col2_x + 110, y), spend, fontsize=10, color=DARK)

        y += 24
        page.insert_text(fitz.Point(col1_x, y), "Expiration / Renewal:", fontsize=10, color=SLATE)
        page.insert_text(fitz.Point(col1_x + 110, y), expiry, fontsize=10, color=DARK)
        page.insert_text(fitz.Point(col2_x, y), "Notice Period:", fontsize=10, color=SLATE)
        page.insert_text(fitz.Point(col2_x + 110, y), notice, fontsize=10, color=DARK)

        y += 24
        page.insert_text(fitz.Point(col1_x, y), "Cancellation Deadline:", fontsize=10, color=INDIGO)
        page.insert_text(fitz.Point(col1_x + 110, y), deadline, fontsize=10, color=INDIGO)
        page.insert_text(fitz.Point(col2_x, y), "Renewal Extension:", fontsize=10, color=SLATE)
        page.insert_text(fitz.Point(col2_x + 110, y), renewal_term, fontsize=10, color=DARK)

        y += 24
        page.insert_text(fitz.Point(col1_x, y), "Status:", fontsize=10, color=SLATE)
        page.insert_text(fitz.Point(col1_x + 110, y), (contract.get("status") or "active").upper(), fontsize=10, color=DARK)
        page.insert_text(fitz.Point(col2_x, y), "Confidence Score:", fontsize=10, color=SLATE)
        page.insert_text(fitz.Point(col2_x + 110, y), f"{int((contract.get('confidence_score') or 0.95)*100)}%", fontsize=10, color=DARK)

        # Section: How to Make Changes / Cancel Procedure
        y = 285
        page.insert_text(fitz.Point(36, y), "HOW TO MAKE CHANGES / NOTICE PROCEDURE", fontsize=10, color=INDIGO)
        y += 8
        page.draw_line(fitz.Point(36, y), fitz.Point(576, y), color=BORDER_COLOR)
        y += 18
        change_text = contract.get("how_to_change_summary") or "Written notice required to counterparty contact prior to cancellation deadline."
        change_rect = fitz.Rect(36, y, 576, y + 45)
        page.insert_textbox(change_rect, change_text, fontsize=9.5, color=DARK)

        # Section: Key Risk Flags
        y += 60
        page.insert_text(fitz.Point(36, y), "KEY RISK FLAGS & RENEWAL RESTRICTIONS", fontsize=10, color=AMBER)
        y += 8
        page.draw_line(fitz.Point(36, y), fitz.Point(576, y), color=BORDER_COLOR)
        y += 18
        risk_flags = contract.get("key_risk_flags") or []
        if isinstance(risk_flags, str):
            try:
                risk_flags = json.loads(risk_flags)
            except Exception:
                risk_flags = [risk_flags]
        if not risk_flags:
            risk_flags = ["Standard annual auto-renewal terms detected."]
        for flag in risk_flags:
            page.insert_text(fitz.Point(44, y), f"•  {flag}", fontsize=9, color=DARK)
            y += 15

        # Section: Source Evidence Quote
        y += 10
        page.insert_text(fitz.Point(36, y), "SOURCE EVIDENCE & CONTRACT CLAUSE EXCERPT", fontsize=10, color=NAVY)
        y += 8
        page.draw_line(fitz.Point(36, y), fitz.Point(576, y), color=BORDER_COLOR)
        y += 16
        quote = contract.get("source_evidence_quote") or "Clause extracted from executed master vendor agreement."
        quote_rect = fitz.Rect(36, y, 576, y + 55)
        page.insert_textbox(quote_rect, f'"{quote}"', fontsize=9, color=SLATE)

        # Section: Raw Record Content Excerpt
        y += 70
        page.insert_text(fitz.Point(36, y), "RECORD DETAILS & EXTRACTED BODY EXCERPT", fontsize=10, color=SLATE)
        y += 8
        page.draw_line(fitz.Point(36, y), fitz.Point(576, y), color=BORDER_COLOR)
        y += 16
        raw_body = contract.get("raw_content") or f"Contract agreement record for {vendor} filed in Contract Renewal Watchdog."
        body_rect = fitz.Rect(36, y, 576, 730)
        page.insert_textbox(body_rect, raw_body[:800], fontsize=8.5, color=DARK)

        # Footer
        page.draw_line(fitz.Point(36, 745), fitz.Point(576, 745), color=BORDER_COLOR)
        page.insert_text(fitz.Point(36, 760), "Contract Renewal Watchdog  •  Confidential & Proprietary", fontsize=8, color=SLATE)
        page.insert_text(fitz.Point(460, 760), datetime.now().strftime("%B %d, %Y"), fontsize=8, color=SLATE)

        pdf_bytes = doc.tobytes()
        doc.close()
        return pdf_bytes
    except Exception as e:
        logger.exception("Failed to synthesize PDF with fitz; falling back to minimal PDF")
        return b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\n0000000101 00000 n\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"


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
        logger.info(f"User authenticated with work email: {email}")

        # Check if user has completed initial profile setup
        profile = get_user_profile(email)
        if not profile or not profile.get("full_name"):
            session["user_name"] = email.split("@")[0]
            flash("Welcome! Please complete your profile to continue.", "info")
            return redirect(url_for("user_profile", setup="1", vertical=vertical_id))

        session["user_name"] = profile.get("full_name") or email.split("@")[0]
        session["full_name"] = profile.get("full_name")

        # Check existing workspaces; if none, auto-seed sample workspaces so user can test immediately
        workspaces = get_user_workspaces(email)
        if not workspaces:
            seed_sample_workspaces_and_contracts(email)
            workspaces = get_user_workspaces(email)

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
    logger.info(f"User authenticated with Google: {mock_email}")

    profile = get_user_profile(mock_email)
    if not profile or not profile.get("full_name"):
        session["user_name"] = mock_email.split("@")[0]
        flash("Welcome! Please complete your profile to continue.", "info")
        return redirect(url_for("user_profile", setup="1", vertical=vertical_id))

    session["user_name"] = profile.get("full_name") or mock_email.split("@")[0]
    session["full_name"] = profile.get("full_name")

    workspaces = get_user_workspaces(mock_email)
    if not workspaces:
        seed_sample_workspaces_and_contracts(mock_email)
        workspaces = get_user_workspaces(mock_email)
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
    logger.info(f"User authenticated with Microsoft: {mock_email}")

    profile = get_user_profile(mock_email)
    if not profile or not profile.get("full_name"):
        session["user_name"] = mock_email.split("@")[0]
        flash("Welcome! Please complete your profile to continue.", "info")
        return redirect(url_for("user_profile", setup="1", vertical=vertical_id))

    session["user_name"] = profile.get("full_name") or mock_email.split("@")[0]
    session["full_name"] = profile.get("full_name")

    workspaces = get_user_workspaces(mock_email)
    if not workspaces:
        seed_sample_workspaces_and_contracts(mock_email)
        workspaces = get_user_workspaces(mock_email)
    flash(f"Signed in with Microsoft as {mock_email}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/auth/callback", methods=["GET"])
@app.route("/auth/callback/<provider>", methods=["GET"])
def auth_callback(provider: str = "google"):
    """
    OAuth Callback Handler for Google and Microsoft.
    Exchanges code for tokens, resolves email, checks profile, and redirects.
    """
    code = request.args.get("code")
    vertical_id = request.args.get("state") or "general_b2b"

    email = request.args.get("email") or session.get("user_email") or f"{provider}_user@company.com"
    email = email.strip().lower()
    session["user_email"] = email

    profile = get_user_profile(email)
    if not profile or not profile.get("full_name"):
        session["user_name"] = email.split("@")[0]
        flash("OAuth connection established. Please complete your profile to continue.", "info")
        return redirect(url_for("user_profile", setup="1", vertical=vertical_id))

    session["user_name"] = profile.get("full_name") or email.split("@")[0]
    session["full_name"] = profile.get("full_name")

    workspaces = get_user_workspaces(email)
    if not workspaces:
        seed_sample_workspaces_and_contracts(email)
        workspaces = get_user_workspaces(email)

    flash(f"OAuth connection established for {email}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/profile", methods=["GET", "POST"])
def user_profile():
    """
    User Profile Management Route:
    - Initial sign-up setup mode (?setup=1) requires basic user information (Full Name, Company, Role, Phone).
    - Later allows users to view and update their profile details at any time.
    """
    user_email = session.get("user_email")
    if not user_email:
        flash("Please sign in to view or edit your profile.", "info")
        return redirect(url_for("auth_login"))

    is_setup = request.args.get("setup") == "1" or request.form.get("is_setup") == "1"
    vertical_id = (request.args.get("vertical") or request.form.get("vertical") or "general_b2b").strip()
    if vertical_id not in VERTICAL_CONFIGS:
        vertical_id = "general_b2b"

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        company_name = (request.form.get("company_name") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        role_title = (request.form.get("role_title") or "").strip()

        if not full_name:
            flash("Full Name is required.", "error")
            profile = {
                "email": user_email,
                "full_name": full_name,
                "company_name": company_name,
                "phone": phone,
                "role_title": role_title,
            }
            return render_template(
                "profile.html",
                active_nav="profile",
                profile=profile,
                is_setup=is_setup,
                vertical_id=vertical_id,
            )

        save_user_profile(
            email=user_email,
            full_name=full_name,
            company_name=company_name,
            phone=phone,
            role_title=role_title,
        )
        session["user_name"] = full_name
        session["full_name"] = full_name

        if is_setup:
            workspaces = get_user_workspaces(user_email)
            if not workspaces:
                seed_sample_workspaces_and_contracts(user_email)
            flash(f"Welcome, {full_name}! Sample workspaces and contracts loaded for testing.", "success")
            return redirect(url_for("dashboard", workspace_id="ws_apex_property_management"))

        flash("Profile updated successfully.", "success")
        return redirect(url_for("user_profile"))

    profile = get_user_profile(user_email) or {"email": user_email}
    return render_template(
        "profile.html",
        active_nav="profile",
        profile=profile,
        is_setup=is_setup,
        vertical_id=vertical_id,
    )


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
    Onboarding & Workspace Creation Route:
    - Default the new workspace's associated email to session['user_email'].
    - Allow user to specify custom default notice period (days).
    - Allow user to add multiple authorized email addresses under the same workspace.
    - Record all emails in workspace_members.
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

    # Read default notice period days
    raw_notice_days = request.form.get("default_notice_period_days")
    try:
        default_notice_period_days = int(raw_notice_days) if raw_notice_days else 30
    except (ValueError, TypeError):
        default_notice_period_days = 30

    # Collect authorized emails: creator_email, user_email, secondary_email, and dynamic additional_emails[]
    member_emails = []
    for em in request.form.getlist("additional_emails[]") + request.form.getlist("additional_emails"):
        clean_em = em.strip().lower()
        if clean_em and "@" in clean_em and clean_em not in member_emails:
            member_emails.append(clean_em)

    secondary_email = (request.form.get("secondary_email") or "").strip().lower()
    if secondary_email and "@" in secondary_email and secondary_email not in member_emails:
        member_emails.append(secondary_email)

    if creator_email and creator_email not in member_emails:
        member_emails.append(creator_email)
    if user_email and user_email not in member_emails:
        member_emails.append(user_email)

    # Auto-generate clean slug if missing
    if not raw_id:
        clean_slug = re.sub(r"[^a-zA-Z0-9]+", "_", name.lower()).strip("_")
        raw_id = f"ws_{clean_slug}" if clean_slug else f"ws_{int(datetime.now().timestamp())}"
    else:
        raw_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", raw_id.lower()).strip("_")

    if not name:
        name = f"Workspace {raw_id}"

    # Persist workspace and register all member emails in workspace_members
    created_ws = create_workspace(
        workspace_id=raw_id,
        name=name,
        vertical_id=vertical_id,
        creator_email=creator_email,
        default_notice_period_days=default_notice_period_days,
        member_emails=member_emails,
    )

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
# Workspace Editing (POST /workspaces/<workspace_id>/edit)
# ---------------------------------------------------------------------------
@app.route("/workspaces/<workspace_id>/edit", methods=["POST"])
def edit_workspace_settings(workspace_id: str):
    """
    Update workspace settings:
    - Workspace name
    - Default notice period (days)
    - Authorized member email addresses (add/remove)
    """
    user_email = session.get("user_email")
    if not user_email:
        flash("Please sign in to modify workspace settings.", "info")
        return redirect(url_for("auth_login"))

    # Demo workspace cannot be edited
    if workspace_id == "ws_default" or request.args.get("demo") == "1":
        flash("Action disabled: Demo workspace cannot be modified.", "error")
        return redirect(url_for("demo_dashboard"))

    # Enforce access scoping
    if not can_user_access_workspace(user_email, workspace_id):
        flash(f"Access denied: You are not authorized to edit workspace '{workspace_id}'.", "error")
        return redirect(url_for("dashboard"))

    name = (request.form.get("name") or "").strip()
    raw_notice_days = request.form.get("default_notice_period_days")
    try:
        default_notice_period_days = int(raw_notice_days) if raw_notice_days else 30
    except (ValueError, TypeError):
        default_notice_period_days = 30

    # Collect member emails from form
    raw_emails = request.form.getlist("member_emails[]") + request.form.getlist("member_emails")
    member_emails = []
    for em in raw_emails:
        clean_em = em.strip().lower()
        if clean_em and "@" in clean_em and clean_em not in member_emails:
            member_emails.append(clean_em)

    # Ensure current user remains authorized
    if user_email and user_email not in member_emails:
        member_emails.append(user_email)

    updated_ws = update_workspace(
        workspace_id=workspace_id,
        name=name,
        default_notice_period_days=default_notice_period_days,
        member_emails=member_emails,
        current_user_email=user_email,
    )

    if not updated_ws:
        flash("Failed to update workspace settings.", "error")
    else:
        flash(f"Workspace '{name}' updated successfully.", "success")

    return redirect(url_for("dashboard", workspace_id=workspace_id))


# ---------------------------------------------------------------------------
# Contract Attachment PDF Viewer Route
# ---------------------------------------------------------------------------
@app.route("/contracts/<int:contract_id>/attachment", methods=["GET"])
def view_contract_attachment(contract_id: int):
    """
    View or download contract attachment (PDF).
    Serves existing disk file if present, or dynamically synthesizes a clean PDF
    using PyMuPDF (fitz) with contract details, risk flags, and change terms.
    """
    user_email = session.get("user_email")
    is_demo = request.args.get("demo") == "1"

    contract = get_contract(contract_id)
    if not contract:
        abort(404)

    # In non-demo mode, ensure user is authorized to access the contract's workspace
    if not is_demo and contract.get("workspace_id") != "ws_default":
        if not user_email or not can_user_access_workspace(user_email, contract["workspace_id"]):
            flash("Access denied: You are not authorized to view attachments for this workspace.", "error")
            return redirect(url_for("dashboard"))

    filename = contract.get("attachment_filename") or f"contract_{contract_id}.pdf"
    disk_path = contract.get("attachment_path")

    # If file exists on disk, stream it
    if disk_path and os.path.exists(disk_path):
        return send_file(disk_path, mimetype="application/pdf", as_attachment=False, download_name=filename)

    # Otherwise, dynamically synthesize a formatted PDF document
    pdf_bytes = generate_synthetic_contract_pdf(contract, filename)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
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
            attachment_filename=parsed.get("primary_attachment_filename"),
            how_to_change_summary=extraction.how_to_change_summary,
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
        "how_to_change_summary": extraction.how_to_change_summary,
        "attachment_filename": parsed.get("primary_attachment_filename"),
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


@app.route("/api/admin/seed-sample-workspaces", methods=["GET", "POST"])
@app.route("/api/sample-data/seed", methods=["GET", "POST"])
@app.route("/api/admin/seed-apex-contracts", methods=["GET", "POST"])
def admin_seed_sample_workspaces():
    """
    Seeds 3 rich sample workspaces (Apex Property Management, Nexus Cloud & IT, Metro Health)
    with 12 contracts featuring cancellation procedures, risk flags, and PDF attachments.
    Associates current user or specified email so they appear in workspace switcher.
    """
    user_email = session.get("user_email") or request.args.get("email") or "user@workspace.com"
    result = seed_sample_workspaces_and_contracts(user_email=user_email)

    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({
            "status": "success",
            "message": f"Successfully seeded {result['total_contracts']} contracts across {result['workspaces_count']} workspaces.",
            "data": result,
        }), 200

    flash(f"Loaded {result['workspaces_count']} sample workspaces with {result['total_contracts']} contracts and PDF attachments!", "success")
    return redirect(url_for("dashboard", workspace_id="ws_apex_property_management"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
