import os
import json
import logging
import urllib.parse
from datetime import datetime, date, timedelta
from typing import Optional, Dict, Any, List, Tuple

from sqlalchemy import create_engine, text, Table, MetaData
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import IntegrityError, OperationalError
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fernet Token Encryption Helpers
# ---------------------------------------------------------------------------
DEV_FALLBACK_KEY = b"aHthFn88pEWsLtc9towSCa-o6IUoQ5VFimL17KVred0="

def get_fernet() -> Fernet:
    """
    Instantiate a Fernet cipher instance using TOKEN_ENCRYPTION_KEY from env.
    Falls back to a valid development key with a warning if not configured.
    """
    key_str = os.environ.get("TOKEN_ENCRYPTION_KEY")
    if not key_str:
        logger.warning(
            "TOKEN_ENCRYPTION_KEY is not set in environment. "
            "Falling back to development key. DO NOT USE IN PRODUCTION."
        )
        return Fernet(DEV_FALLBACK_KEY)
    
    key_bytes = key_str.strip().encode("utf-8")
    try:
        return Fernet(key_bytes)
    except Exception as e:
        logger.error(f"Invalid TOKEN_ENCRYPTION_KEY provided: {e}")
        raise ValueError(
            "Invalid TOKEN_ENCRYPTION_KEY. Ensure it is a 32-byte url-safe base64-encoded string."
        ) from e


def encrypt_token(raw_token: Optional[str]) -> Optional[str]:
    """Encrypt a plaintext OAuth token using Fernet."""
    if not raw_token:
        return None
    f = get_fernet()
    return f.encrypt(raw_token.encode("utf-8")).decode("utf-8")


def decrypt_token(encrypted_token: Optional[str]) -> Optional[str]:
    """Decrypt a Fernet-encrypted OAuth token back to plaintext."""
    if not encrypted_token:
        return None
    f = get_fernet()
    return f.decrypt(encrypted_token.encode("utf-8")).decode("utf-8")


# ---------------------------------------------------------------------------
# Database Connection URL & Pool Setup
# ---------------------------------------------------------------------------
def build_database_url() -> str:
    """
    Construct a MySQL connection URI using PyMySQL with utf8mb4 encoding.
    Supports MYSQL_URL, DATABASE_URL, or discrete MYSQL* variables from .env.
    """
    raw_url = os.environ.get("DATABASE_URL") or os.environ.get("MYSQL_URL")
    if raw_url and "<MYSQLPASSWORD>" not in raw_url:
        # Standardize dialect prefix to mysql+pymysql
        if raw_url.startswith("mysql://"):
            url = "mysql+pymysql://" + raw_url[len("mysql://"):]
        elif raw_url.startswith("mysql+pymysql://"):
            url = raw_url
        else:
            url = raw_url
        
        # Ensure utf8mb4 charset parameter
        if "charset=" not in url:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}charset=utf8mb4"
        return url

    # Fall back to discrete environment variables
    user = os.environ.get("MYSQLUSER", "root")
    password = os.environ.get("MYSQLPASSWORD", "")
    host = os.environ.get("MYSQLHOST", "localhost")
    port = os.environ.get("MYSQLPORT", "3306")
    database = os.environ.get("MYSQLDATABASE", "railway")

    # URL-encode password in case of special characters
    safe_password = urllib.parse.quote_plus(password)
    safe_user = urllib.parse.quote_plus(user)

    return f"mysql+pymysql://{safe_user}:{safe_password}@{host}:{port}/{database}?charset=utf8mb4"


# Initialize SQLAlchemy Engine with Connection Pooling and utf8mb4 support
DATABASE_URL = build_database_url()

engine = create_engine(
    DATABASE_URL,
    pool_size=int(os.environ.get("DB_POOL_SIZE", 10)),
    max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", 20)),
    pool_recycle=int(os.environ.get("DB_POOL_RECYCLE", 1800)),
    pool_pre_ping=True,  # Test connections for liveness before checkout
    connect_args={
        "charset": "utf8mb4",
        "use_unicode": True,
    },
)

# Thread-safe scoped session factory
session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Session = scoped_session(session_factory)


# ---------------------------------------------------------------------------
# Database Initialization / Migrations
# ---------------------------------------------------------------------------
def init_db():
    """
    Idempotently initialize required database tables:
    - workspaces
    - contracts (with uq_workspace_fingerprint constraint)
    - oauth_connections (stores encrypted access/refresh tokens)
    """
    create_workspaces_sql = """
    CREATE TABLE IF NOT EXISTS workspaces (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(255) NOT NULL DEFAULT 'Default Workspace',
        vertical_id VARCHAR(64) NOT NULL DEFAULT 'general_b2b',
        inbound_email_slug VARCHAR(64) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_workspaces_vertical (vertical_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """

    create_contracts_sql = """
    CREATE TABLE IF NOT EXISTS contracts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        workspace_id VARCHAR(64) NOT NULL,
        fingerprint_hash VARCHAR(64) NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'active',
        vendor_name VARCHAR(255) NULL,
        contract_title VARCHAR(255) NULL,
        category VARCHAR(128) NULL,
        expiration_or_renewal_date DATE NULL,
        notice_period_days INT NULL,
        calculated_cancellation_deadline DATE NULL,
        auto_renewal_term_months INT NULL,
        annual_spend_estimate DECIMAL(12, 2) NULL,
        currency VARCHAR(10) DEFAULT 'USD',
        price_escalation_summary TEXT NULL,
        coi_or_compliance_expiry DATE NULL,
        key_risk_flags JSON NULL,
        source_evidence_quote TEXT NULL,
        confidence_score DECIMAL(4, 3) NULL,
        is_valid_contract_or_renewal BOOLEAN DEFAULT TRUE,
        sender_email VARCHAR(255) NULL,
        email_subject VARCHAR(500) NULL,
        raw_content LONGTEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT uq_workspace_fingerprint UNIQUE (workspace_id, fingerprint_hash),
        INDEX idx_contracts_workspace (workspace_id),
        INDEX idx_contracts_status (status),
        INDEX idx_contracts_expiry (expiration_or_renewal_date),
        INDEX idx_contracts_deadline (calculated_cancellation_deadline)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """

    create_oauth_connections_sql = """
    CREATE TABLE IF NOT EXISTS oauth_connections (
        id INT AUTO_INCREMENT PRIMARY KEY,
        workspace_id VARCHAR(64) NOT NULL,
        provider VARCHAR(64) NOT NULL,
        email VARCHAR(255) NULL,
        encrypted_access_token TEXT NULL,
        encrypted_refresh_token TEXT NULL,
        token_expiry TIMESTAMP NULL,
        scopes TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_oauth_ws_provider (workspace_id, provider)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """

    create_alert_logs_sql = """
    CREATE TABLE IF NOT EXISTS alert_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        contract_id INT NOT NULL,
        workspace_id VARCHAR(64) NOT NULL,
        alert_type VARCHAR(64) NOT NULL DEFAULT 'deadline_warning',
        calculated_cancellation_deadline DATE NULL,
        days_left INT NULL,
        lead_days_window INT NOT NULL,
        recipient_email VARCHAR(255) NULL,
        alert_summary TEXT NULL,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uq_contract_alert UNIQUE (contract_id, calculated_cancellation_deadline, alert_type),
        INDEX idx_alert_contract (contract_id),
        INDEX idx_alert_workspace (workspace_id),
        INDEX idx_alert_sent_at (sent_at),
        FOREIGN KEY (contract_id) REFERENCES contracts(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """

    create_ingestion_jobs_sql = """
    CREATE TABLE IF NOT EXISTS ingestion_jobs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        workspace_id VARCHAR(64) NOT NULL,
        job_type VARCHAR(64) NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'pending',
        payload JSON NULL,
        messages_found INT DEFAULT 0,
        contracts_extracted INT DEFAULT 0,
        duplicates_skipped INT DEFAULT 0,
        error_message TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_job_ws (workspace_id),
        INDEX idx_job_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """

    create_workspace_members_sql = """
    CREATE TABLE IF NOT EXISTS workspace_members (
        id INT AUTO_INCREMENT PRIMARY KEY,
        workspace_id VARCHAR(64) NOT NULL,
        email VARCHAR(255) NOT NULL,
        role VARCHAR(32) NOT NULL DEFAULT 'owner',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uq_workspace_member_email UNIQUE (workspace_id, email),
        INDEX idx_wm_email (email),
        INDEX idx_wm_workspace (workspace_id),
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """

    create_user_profiles_sql = """
    CREATE TABLE IF NOT EXISTS user_profiles (
        email VARCHAR(255) PRIMARY KEY,
        full_name VARCHAR(255) NOT NULL,
        company_name VARCHAR(255) NULL,
        phone VARCHAR(64) NULL,
        role_title VARCHAR(128) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_user_profiles_company (company_name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """

    # Seed default workspace if absent
    seed_default_workspace_sql = """
    INSERT IGNORE INTO workspaces (id, name, vertical_id, default_notice_period_days)
    VALUES ('ws_default', 'Default Business Workspace', 'general_b2b', 30);
    """

    seed_workspace_members_sql = """
    INSERT IGNORE INTO workspace_members (workspace_id, email, role)
    VALUES 
        ('ws_default', 'demo@contractwatchdog.com', 'owner'),
        ('ws_default', 'admin@contractwatchdog.com', 'owner');
    """

    try:
        # 1. Create tables if not exist
        with engine.begin() as conn:
            conn.execute(text(create_workspaces_sql))
            conn.execute(text(create_contracts_sql))
            conn.execute(text(create_oauth_connections_sql))
            conn.execute(text(create_alert_logs_sql))
            conn.execute(text(create_ingestion_jobs_sql))
            conn.execute(text(create_workspace_members_sql))
            conn.execute(text(create_user_profiles_sql))

        # 2. Automated safe column migrations
        try:
            with engine.begin() as conn:
                ws_cols = [r[0].lower() for r in conn.execute(text("SHOW COLUMNS FROM workspaces")).fetchall()]
                if "default_notice_period_days" not in ws_cols:
                    conn.execute(text("ALTER TABLE workspaces ADD COLUMN default_notice_period_days INT NOT NULL DEFAULT 30;"))
        except Exception as ex:
            logger.warning(f"workspaces migration notice: {ex}")

        try:
            with engine.begin() as conn:
                c_cols = [r[0].lower() for r in conn.execute(text("SHOW COLUMNS FROM contracts")).fetchall()]
                if "attachment_filename" not in c_cols:
                    conn.execute(text("ALTER TABLE contracts ADD COLUMN attachment_filename VARCHAR(255) NULL;"))
                if "attachment_path" not in c_cols:
                    conn.execute(text("ALTER TABLE contracts ADD COLUMN attachment_path VARCHAR(500) NULL;"))
                if "how_to_change_summary" not in c_cols:
                    conn.execute(text("ALTER TABLE contracts ADD COLUMN how_to_change_summary TEXT NULL;"))
        except Exception as ex:
            logger.warning(f"contracts migration notice: {ex}")

        # 3. Seed default workspace and members after columns are guaranteed to exist
        with engine.begin() as conn:
            conn.execute(text(seed_default_workspace_sql))
            conn.execute(text(seed_workspace_members_sql))

        logger.info("Database initialized successfully with utf8mb4 support and dynamic migrations.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")


# ---------------------------------------------------------------------------
# Workspace Query Operations
# ---------------------------------------------------------------------------
def list_workspaces() -> List[Dict[str, Any]]:
    """List all available workspaces."""
    query = text("SELECT id, name, vertical_id, created_at FROM workspaces ORDER BY created_at ASC")
    try:
        with engine.connect() as conn:
            rows = conn.execute(query).mappings().all()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error listing workspaces: {e}")
        return [{"id": "ws_default", "name": "Default Workspace", "vertical_id": "general_b2b"}]


def get_workspace(workspace_id: str) -> Optional[Dict[str, Any]]:
    """Fetch details for a specific workspace."""
    if not workspace_id:
        return None
    query = text("SELECT id, name, vertical_id, default_notice_period_days, created_at FROM workspaces WHERE id = :workspace_id LIMIT 1")
    try:
        with engine.connect() as conn:
            row = conn.execute(query, {"workspace_id": workspace_id}).mappings().first()
            if not row:
                return None
            res = dict(row)
            if res.get("default_notice_period_days") is None:
                res["default_notice_period_days"] = 30
            return res
    except Exception as e:
        logger.error(f"Error getting workspace {workspace_id}: {e}")
        return None


def create_workspace(
    workspace_id: str,
    name: str,
    vertical_id: str = "general_b2b",
    creator_email: Optional[str] = None,
    secondary_email: Optional[str] = None,
    default_notice_period_days: int = 30,
    member_emails: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Create or update a workspace and record creator and member emails in workspace_members.
    """
    clean_id = workspace_id.strip().lower()
    clean_name = name.strip() or f"Workspace {clean_id}"
    notice_days = int(default_notice_period_days or 30)
    
    query = text("""
        INSERT INTO workspaces (id, name, vertical_id, default_notice_period_days)
        VALUES (:id, :name, :vertical_id, :default_notice_period_days)
        ON DUPLICATE KEY UPDATE 
            name = :name, 
            vertical_id = :vertical_id, 
            default_notice_period_days = :default_notice_period_days,
            updated_at = CURRENT_TIMESTAMP
    """)
    with engine.begin() as conn:
        conn.execute(query, {
            "id": clean_id,
            "name": clean_name,
            "vertical_id": vertical_id,
            "default_notice_period_days": notice_days
        })

    emails_to_add = set()
    if creator_email and creator_email.strip():
        emails_to_add.add(creator_email.strip().lower())
    if secondary_email and secondary_email.strip():
        emails_to_add.add(secondary_email.strip().lower())
    if member_emails:
        for em in member_emails:
            if em and "@" in em:
                emails_to_add.add(em.strip().lower())

    for em in emails_to_add:
        add_workspace_member(clean_id, em, role="owner")

    associated_emails = get_workspace_emails(clean_id)
    return {
        "id": clean_id,
        "name": clean_name,
        "vertical_id": vertical_id,
        "default_notice_period_days": notice_days,
        "emails": associated_emails,
    }


def update_workspace(
    workspace_id: str,
    name: str,
    default_notice_period_days: int = 30,
    member_emails: Optional[List[str]] = None,
    current_user_email: Optional[str] = None,
) -> bool:
    """
    Updates workspace name, default notice period days, and synchronizes member emails.
    """
    clean_id = workspace_id.strip().lower()
    clean_name = name.strip() or f"Workspace {clean_id}"
    notice_days = int(default_notice_period_days or 30)

    try:
        with engine.begin() as conn:
            conn.execute(text("""
                UPDATE workspaces 
                SET name = :name, 
                    default_notice_period_days = :default_notice_period_days, 
                    updated_at = CURRENT_TIMESTAMP 
                WHERE id = :id
            """), {
                "id": clean_id,
                "name": clean_name,
                "default_notice_period_days": notice_days,
            })

            if member_emails is not None:
                cleaned_emails = {em.strip().lower() for em in member_emails if em and "@" in em}
                if current_user_email and current_user_email.strip():
                    cleaned_emails.add(current_user_email.strip().lower())

                # Upsert all specified member emails
                for em in cleaned_emails:
                    conn.execute(text("""
                        INSERT INTO workspace_members (workspace_id, email, role)
                        VALUES (:ws_id, :email, 'owner')
                        ON DUPLICATE KEY UPDATE role = 'owner'
                    """), {"ws_id": clean_id, "email": em})

                # Delete members that were removed (except preserve current_user_email)
                if cleaned_emails:
                    existing_members = conn.execute(
                        text("SELECT email FROM workspace_members WHERE workspace_id = :ws_id"),
                        {"ws_id": clean_id}
                    ).fetchall()
                    for row in existing_members:
                        em = row[0].strip().lower()
                        if em not in cleaned_emails:
                            conn.execute(text("""
                                DELETE FROM workspace_members 
                                WHERE workspace_id = :ws_id AND LOWER(email) = :email
                            """), {"ws_id": clean_id, "email": em})
        logger.info(f"Workspace {clean_id} updated successfully (name: {clean_name}, notice: {notice_days}d)")
        return True
    except Exception as e:
        logger.error(f"Error updating workspace {clean_id}: {e}")
        return False


# ---------------------------------------------------------------------------
# User Profile Operations
# ---------------------------------------------------------------------------
def get_user_profile(email: str) -> Optional[Dict[str, Any]]:
    """Retrieve user profile by email."""
    if not email:
        return None
    clean_email = email.strip().lower()
    query = text("""
        SELECT email, full_name, company_name, phone, role_title, created_at, updated_at
        FROM user_profiles
        WHERE LOWER(email) = :email
        LIMIT 1
    """)
    try:
        with engine.connect() as conn:
            row = conn.execute(query, {"email": clean_email}).mappings().first()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching profile for {clean_email}: {e}")
        return None


def save_user_profile(
    email: str,
    full_name: str,
    company_name: str = "",
    phone: str = "",
    role_title: str = "",
) -> bool:
    """Create or update a user profile."""
    if not email or not full_name:
        return False
    clean_email = email.strip().lower()
    clean_name = full_name.strip()
    clean_company = (company_name or "").strip()
    clean_phone = (phone or "").strip()
    clean_role = (role_title or "").strip()

    query = text("""
        INSERT INTO user_profiles (email, full_name, company_name, phone, role_title)
        VALUES (:email, :full_name, :company_name, :phone, :role_title)
        ON DUPLICATE KEY UPDATE
            full_name = :full_name,
            company_name = :company_name,
            phone = :phone,
            role_title = :role_title,
            updated_at = CURRENT_TIMESTAMP
    """)
    try:
        with engine.begin() as conn:
            conn.execute(query, {
                "email": clean_email,
                "full_name": clean_name,
                "company_name": clean_company,
                "phone": clean_phone,
                "role_title": clean_role,
            })
        logger.info(f"Saved profile for {clean_email}")
        return True
    except Exception as e:
        logger.error(f"Error saving profile for {clean_email}: {e}")
        return False


def add_workspace_member(workspace_id: str, email: str, role: str = "owner") -> bool:
    """Associate an authorized email with a workspace."""
    if not workspace_id or not email:
        return False
    clean_ws = workspace_id.strip().lower()
    clean_email = email.strip().lower()
    query = text("""
        INSERT INTO workspace_members (workspace_id, email, role)
        VALUES (:workspace_id, :email, :role)
        ON DUPLICATE KEY UPDATE role = :role
    """)
    try:
        with engine.begin() as conn:
            conn.execute(query, {
                "workspace_id": clean_ws,
                "email": clean_email,
                "role": role,
            })
        return True
    except Exception as e:
        logger.error(f"Failed to add member {clean_email} to workspace {clean_ws}: {e}")
        return False


def get_workspace_emails(workspace_id: str) -> List[str]:
    """Retrieve all authorized emails for a given workspace."""
    if not workspace_id:
        return []
    query = text("""
        SELECT email FROM workspace_members
        WHERE workspace_id = :workspace_id
        GROUP BY email
        ORDER BY MIN(created_at) ASC
    """)
    try:
        with engine.connect() as conn:
            rows = conn.execute(query, {"workspace_id": workspace_id.strip().lower()}).fetchall()
            return [r[0] for r in rows if r[0]]
    except Exception as e:
        logger.error(f"Error fetching emails for workspace {workspace_id}: {e}")
        return []


def get_user_workspaces(email: str) -> List[Dict[str, Any]]:
    """
    Retrieve workspaces that the given user email is authorized to access.
    Joins workspaces and workspace_members on lowercase email.
    """
    if not email:
        return []
    clean_email = email.strip().lower()
    query = text("""
        SELECT DISTINCT w.id, w.name, w.vertical_id, w.default_notice_period_days, w.created_at
        FROM workspaces w
        JOIN workspace_members wm ON w.id = wm.workspace_id
        WHERE LOWER(wm.email) = :email
        ORDER BY w.created_at ASC
    """)
    try:
        with engine.connect() as conn:
            rows = conn.execute(query, {"email": clean_email}).mappings().all()
            workspaces = [dict(r) for r in rows]

            # If user is admin/demo and ws_default isn't returned, ensure it is added
            if clean_email in ("admin@contractwatchdog.com", "demo@contractwatchdog.com"):
                if not any(ws["id"] == "ws_default" for ws in workspaces):
                    default_ws = get_workspace("ws_default")
                    if default_ws:
                        workspaces.insert(0, default_ws)

            return workspaces
    except Exception as e:
        logger.error(f"Error fetching workspaces for user {clean_email}: {e}")
        return []


def can_user_access_workspace(email: str, workspace_id: str) -> bool:
    """
    Enforce multi-email workspace access control.
    Returns True if the email is registered in workspace_members for workspace_id,
    or if user is demo/admin on ws_default.
    """
    if not email or not workspace_id:
        return False
    clean_email = email.strip().lower()
    clean_ws = workspace_id.strip().lower()

    # Built-in demo/admin access for default workspace
    if clean_ws == "ws_default" and clean_email in ("admin@contractwatchdog.com", "demo@contractwatchdog.com"):
        return True

    query = text("""
        SELECT 1 FROM workspace_members
        WHERE workspace_id = :workspace_id AND LOWER(email) = :email
        LIMIT 1
    """)
    try:
        with engine.connect() as conn:
            row = conn.execute(query, {
                "workspace_id": clean_ws,
                "email": clean_email
            }).fetchone()
            return row is not None
    except Exception as e:
        logger.error(f"Error checking access for {clean_email} to {clean_ws}: {e}")
        return False


def get_workspace_vertical(workspace_id: str) -> str:
    """
    Fetch the vertical_id configured for a given workspace.
    If the workspace doesn't exist, create it with 'general_b2b' and return.
    """
    if not workspace_id:
        workspace_id = "ws_default"

    query = text("SELECT vertical_id FROM workspaces WHERE id = :workspace_id LIMIT 1")
    try:
        with engine.connect() as conn:
            result = conn.execute(query, {"workspace_id": workspace_id}).fetchone()
            if result and result[0]:
                return result[0]
            
            # Auto-provision workspace with default general_b2b
            insert_query = text("""
                INSERT INTO workspaces (id, name, vertical_id)
                VALUES (:workspace_id, :name, 'general_b2b')
                ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP
            """)
            conn.execute(insert_query, {
                "workspace_id": workspace_id,
                "name": f"Workspace {workspace_id}"
            })
            conn.commit()
            return "general_b2b"
    except Exception as e:
        logger.warning(f"Error fetching vertical_id for workspace {workspace_id}: {e}")
        return "general_b2b"


def check_duplicate_fingerprint(workspace_id: str, fingerprint_hash: str) -> bool:
    """
    Check if a contract with (workspace_id, fingerprint_hash) already exists.
    """
    query = text("""
        SELECT 1 FROM contracts 
        WHERE workspace_id = :workspace_id AND fingerprint_hash = :fingerprint_hash 
        LIMIT 1
    """)
    try:
        with engine.connect() as conn:
            row = conn.execute(query, {
                "workspace_id": workspace_id,
                "fingerprint_hash": fingerprint_hash
            }).fetchone()
            return row is not None
    except Exception as e:
        logger.warning(f"Error checking duplicate fingerprint: {e}")
        return False


def sanitize_date_str(val: Optional[str]) -> Optional[str]:
    """Ensure date is a clean YYYY-MM-DD or None for MySQL DATE column."""
    if not val:
        return None
    val = str(val).strip()
    if len(val) >= 10 and val[4] == "-" and val[7] == "-":
        return val[:10]
    return None


def insert_contract(
    workspace_id: str,
    fingerprint_hash: str,
    status: str,
    extraction: Any,
    raw_content: str = "",
    sender_email: str = "",
    email_subject: str = "",
    attachment_filename: Optional[str] = None,
    attachment_path: Optional[str] = None,
    how_to_change_summary: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Insert an extracted contract into the contracts table.
    Enforces uq_workspace_fingerprint constraint.
    """
    # Safe field resolution from Pydantic model or dict
    if hasattr(extraction, "model_dump"):
        data = extraction.model_dump()
    elif isinstance(extraction, dict):
        data = extraction
    else:
        data = vars(extraction)

    att_file = attachment_filename or data.get("attachment_filename")
    att_path = attachment_path or data.get("attachment_path")
    how_change = how_to_change_summary or data.get("how_to_change_summary")

    insert_sql = text("""
    INSERT INTO contracts (
        workspace_id,
        fingerprint_hash,
        status,
        vendor_name,
        contract_title,
        category,
        expiration_or_renewal_date,
        notice_period_days,
        calculated_cancellation_deadline,
        auto_renewal_term_months,
        annual_spend_estimate,
        currency,
        price_escalation_summary,
        how_to_change_summary,
        attachment_filename,
        attachment_path,
        coi_or_compliance_expiry,
        key_risk_flags,
        source_evidence_quote,
        confidence_score,
        is_valid_contract_or_renewal,
        sender_email,
        email_subject,
        raw_content
    ) VALUES (
        :workspace_id,
        :fingerprint_hash,
        :status,
        :vendor_name,
        :contract_title,
        :category,
        :expiration_or_renewal_date,
        :notice_period_days,
        :calculated_cancellation_deadline,
        :auto_renewal_term_months,
        :annual_spend_estimate,
        :currency,
        :price_escalation_summary,
        :how_to_change_summary,
        :attachment_filename,
        :attachment_path,
        :coi_or_compliance_expiry,
        :key_risk_flags,
        :source_evidence_quote,
        :confidence_score,
        :is_valid_contract_or_renewal,
        :sender_email,
        :email_subject,
        :raw_content
    )
    """)

    params = {
        "workspace_id": workspace_id,
        "fingerprint_hash": fingerprint_hash,
        "status": status,
        "vendor_name": data.get("vendor_name"),
        "contract_title": data.get("contract_title"),
        "category": data.get("category"),
        "expiration_or_renewal_date": sanitize_date_str(data.get("expiration_or_renewal_date")),
        "notice_period_days": data.get("notice_period_days"),
        "calculated_cancellation_deadline": sanitize_date_str(data.get("calculated_cancellation_deadline")),
        "auto_renewal_term_months": data.get("auto_renewal_term_months"),
        "annual_spend_estimate": data.get("annual_spend_estimate"),
        "currency": data.get("currency") or "USD",
        "price_escalation_summary": data.get("price_escalation_summary"),
        "how_to_change_summary": how_change,
        "attachment_filename": att_file,
        "attachment_path": att_path,
        "coi_or_compliance_expiry": sanitize_date_str(data.get("coi_or_compliance_expiry")),
        "key_risk_flags": json.dumps(data.get("key_risk_flags") or []),
        "source_evidence_quote": data.get("source_evidence_quote"),
        "confidence_score": data.get("confidence_score"),
        "is_valid_contract_or_renewal": data.get("is_valid_contract_or_renewal", True),
        "sender_email": sender_email[:255] if sender_email else None,
        "email_subject": email_subject[:500] if email_subject else None,
        "raw_content": raw_content,
    }

    with engine.begin() as conn:
        result = conn.execute(insert_sql, params)
        contract_id = result.lastrowid

    return {
        "id": contract_id,
        "workspace_id": workspace_id,
        "fingerprint_hash": fingerprint_hash,
        "status": status,
    }


def _hydrate_contract_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to format dates, parse JSON risk flags, and compute urgency badges."""
    item = dict(record)
    
    # Parse risk flags JSON
    if item.get("key_risk_flags"):
        if isinstance(item["key_risk_flags"], str):
            try:
                item["key_risk_flags"] = json.loads(item["key_risk_flags"])
            except Exception:
                item["key_risk_flags"] = []
    else:
        item["key_risk_flags"] = []

    # Calculate deadline countdown and urgency level
    today = date.today()
    deadline = item.get("calculated_cancellation_deadline")
    
    # Handle string or date objects
    if isinstance(deadline, str):
        try:
            deadline = datetime.strptime(deadline[:10], "%Y-%m-%d").date()
        except ValueError:
            deadline = None

    if deadline:
        days_left = (deadline - today).days
        item["days_left"] = days_left
        if days_left < 0:
            item["urgency"] = "overdue"
            item["badge_text"] = f"OVERDUE ({abs(days_left)}d ago)"
            item["badge_class"] = "bg-rose-50 text-rose-700 border-rose-300 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-800"
        elif days_left <= 15:
            item["urgency"] = "critical"
            item["badge_text"] = f"{days_left}d left · Critical"
            item["badge_class"] = "bg-red-50 text-red-700 border-red-300 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800"
        elif days_left <= 45:
            item["urgency"] = "warning"
            item["badge_text"] = f"{days_left}d left · Action Soon"
            item["badge_class"] = "bg-amber-50 text-amber-700 border-amber-300 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800"
        else:
            item["urgency"] = "normal"
            item["badge_text"] = f"{days_left}d left"
            item["badge_class"] = "bg-emerald-50 text-emerald-700 border-emerald-300 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800"
    else:
        item["days_left"] = None
        item["urgency"] = "nodate"
        item["badge_text"] = "No Deadline Stated"
        item["badge_class"] = "bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700"

    return item


def get_dashboard_contracts(workspace_id: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Fetch active contracts and needs-review contracts for a workspace.
    
    Active: status = 'active' and confidence_score >= 0.85
      Ordered by calculated_cancellation_deadline ASC (nulls last), expiration date ASC.
    Needs Review: status = 'needs_review' OR confidence_score < 0.85
      Ordered by created_at DESC.
    """
    active_query = text("""
        SELECT * FROM contracts
        WHERE workspace_id = :workspace_id
          AND status = 'active'
          AND (confidence_score >= 0.85 OR confidence_score IS NULL)
        ORDER BY
          CASE WHEN calculated_cancellation_deadline IS NULL THEN 1 ELSE 0 END,
          calculated_cancellation_deadline ASC,
          expiration_or_renewal_date ASC
    """)

    needs_review_query = text("""
        SELECT * FROM contracts
        WHERE workspace_id = :workspace_id
          AND (status = 'needs_review' OR confidence_score < 0.85)
        ORDER BY created_at DESC
    """)

    active_items: List[Dict[str, Any]] = []
    review_items: List[Dict[str, Any]] = []

    try:
        with engine.connect() as conn:
            active_rows = conn.execute(active_query, {"workspace_id": workspace_id}).mappings().all()
            for r in active_rows:
                active_items.append(_hydrate_contract_record(dict(r)))

            review_rows = conn.execute(needs_review_query, {"workspace_id": workspace_id}).mappings().all()
            for r in review_rows:
                review_items.append(_hydrate_contract_record(dict(r)))
    except Exception as e:
        logger.error(f"Error fetching dashboard contracts for workspace {workspace_id}: {e}")

    return active_items, review_items


def get_contract(contract_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve single contract by ID."""
    query = text("SELECT * FROM contracts WHERE id = :contract_id LIMIT 1")
    try:
        with engine.connect() as conn:
            row = conn.execute(query, {"contract_id": contract_id}).mappings().first()
            if not row:
                return None
            return _hydrate_contract_record(dict(row))
    except Exception as e:
        logger.error(f"Error fetching contract {contract_id}: {e}")
        return None


def approve_and_update_contract(contract_id: int, updates: Dict[str, Any]) -> bool:
    """
    Update human-reviewed fields and promote contract to status = 'active'.
    Recalculates cancellation deadline if expiration date and notice days are specified.
    Preserves existing values when partial updates are supplied.
    """
    existing = get_contract(contract_id)
    if not existing:
        logger.warning(f"Contract {contract_id} not found for approval")
        return False

    vendor_name = updates.get("vendor_name")
    if vendor_name is None:
        vendor_name = existing.get("vendor_name")
    vendor_name = str(vendor_name or "").strip()

    contract_title = updates.get("contract_title")
    if contract_title is None:
        contract_title = existing.get("contract_title")

    category = updates.get("category")
    if category is None:
        category = existing.get("category")

    if "expiration_or_renewal_date" in updates:
        exp_date = sanitize_date_str(updates.get("expiration_or_renewal_date"))
    else:
        exp_date = sanitize_date_str(existing.get("expiration_or_renewal_date"))

    if "notice_period_days" in updates:
        val = updates.get("notice_period_days")
        try:
            notice_days = int(val) if val not in (None, "") else None
        except (ValueError, TypeError):
            notice_days = None
    else:
        notice_days = existing.get("notice_period_days")

    if "calculated_cancellation_deadline" in updates:
        cancellation_deadline = sanitize_date_str(updates.get("calculated_cancellation_deadline"))
    else:
        cancellation_deadline = sanitize_date_str(existing.get("calculated_cancellation_deadline"))

    # Auto-calculate deadline if unstated but expiration and notice days are present
    if not cancellation_deadline and exp_date and notice_days is not None:
        try:
            exp_dt = datetime.strptime(exp_date, "%Y-%m-%d").date()
            cancellation_deadline = (exp_dt - timedelta(days=notice_days)).strftime("%Y-%m-%d")
        except Exception:
            cancellation_deadline = None

    if "annual_spend_estimate" in updates:
        val = updates.get("annual_spend_estimate")
        try:
            spend_estimate = float(val) if val not in (None, "") else None
        except (ValueError, TypeError):
            spend_estimate = None
    else:
        spend_estimate = existing.get("annual_spend_estimate")

    if "auto_renewal_term_months" in updates:
        val = updates.get("auto_renewal_term_months")
        try:
            auto_renewal_term_months = int(val) if val not in (None, "") else None
        except (ValueError, TypeError):
            auto_renewal_term_months = None
    else:
        auto_renewal_term_months = existing.get("auto_renewal_term_months")

    if "how_to_change_summary" in updates:
        how_to_change_summary = updates.get("how_to_change_summary")
    else:
        how_to_change_summary = existing.get("how_to_change_summary")

    update_sql = text("""
        UPDATE contracts SET
            vendor_name = COALESCE(NULLIF(:vendor_name, ''), vendor_name),
            contract_title = COALESCE(NULLIF(:contract_title, ''), contract_title),
            category = COALESCE(NULLIF(:category, ''), category),
            expiration_or_renewal_date = :exp_date,
            notice_period_days = :notice_days,
            calculated_cancellation_deadline = :cancellation_deadline,
            annual_spend_estimate = :spend_estimate,
            auto_renewal_term_months = :auto_renewal_term_months,
            how_to_change_summary = :how_to_change_summary,
            status = 'active',
            confidence_score = 1.0,
            is_valid_contract_or_renewal = 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = :contract_id
    """)

    params = {
        "contract_id": contract_id,
        "vendor_name": vendor_name,
        "contract_title": contract_title,
        "category": category,
        "exp_date": exp_date,
        "notice_days": notice_days,
        "cancellation_deadline": cancellation_deadline,
        "spend_estimate": spend_estimate,
        "auto_renewal_term_months": auto_renewal_term_months,
        "how_to_change_summary": how_to_change_summary,
    }

    try:
        with engine.begin() as conn:
            result = conn.execute(update_sql, params)
            return result.rowcount > 0
    except Exception as e:
        logger.error(f"Error approving contract {contract_id}: {e}")
        return False


# ---------------------------------------------------------------------------
# OAuth Connection Token Store Helpers
# ---------------------------------------------------------------------------
def save_oauth_connection(
    workspace_id: str,
    provider: str,
    email: Optional[str],
    access_token: str,
    refresh_token: Optional[str] = None,
    token_expiry: Optional[datetime] = None,
    scopes: Optional[str] = None,
) -> int:
    """
    Encrypt access/refresh tokens and persist into oauth_connections.
    """
    enc_access = encrypt_token(access_token)
    enc_refresh = encrypt_token(refresh_token)

    query = text("""
        INSERT INTO oauth_connections (
            workspace_id, provider, email,
            encrypted_access_token, encrypted_refresh_token,
            token_expiry, scopes
        ) VALUES (
            :workspace_id, :provider, :email,
            :encrypted_access_token, :encrypted_refresh_token,
            :token_expiry, :scopes
        )
    """)

    with engine.begin() as conn:
        res = conn.execute(query, {
            "workspace_id": workspace_id,
            "provider": provider,
            "email": email,
            "encrypted_access_token": enc_access,
            "encrypted_refresh_token": enc_refresh,
            "token_expiry": token_expiry,
            "scopes": scopes,
        })
        return res.lastrowid


def get_oauth_connection(workspace_id: str, provider: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve and decrypt tokens for a workspace's OAuth connection.
    """
    query = text("""
        SELECT id, workspace_id, provider, email,
               encrypted_access_token, encrypted_refresh_token,
               token_expiry, scopes
        FROM oauth_connections
        WHERE workspace_id = :workspace_id AND provider = :provider
        ORDER BY id DESC LIMIT 1
    """)

    with engine.connect() as conn:
        row = conn.execute(query, {
            "workspace_id": workspace_id,
            "provider": provider
        }).mappings().first()

        if not row:
            return None

        conn_dict = dict(row)
        conn_dict["access_token"] = decrypt_token(conn_dict.get("encrypted_access_token"))
        conn_dict["refresh_token"] = decrypt_token(conn_dict.get("encrypted_refresh_token"))
        return conn_dict


# ---------------------------------------------------------------------------
# Task 6 Alert History & Dispatch Database Helpers
# ---------------------------------------------------------------------------
def check_alert_already_sent(contract_id: int, deadline: str, alert_type: str = "deadline_warning") -> bool:
    """
    Check if an alert has already been logged for this contract, deadline, and alert_type.
    Enforces idempotency and prevents spamming duplicate notifications.
    """
    query = text("""
        SELECT 1 FROM alert_logs
        WHERE contract_id = :contract_id
          AND calculated_cancellation_deadline = :deadline
          AND alert_type = :alert_type
        LIMIT 1
    """)
    try:
        with engine.connect() as conn:
            row = conn.execute(query, {
                "contract_id": contract_id,
                "deadline": deadline,
                "alert_type": alert_type,
            }).fetchone()
            return row is not None
    except Exception as e:
        logger.warning(f"Error checking alert log existence for contract {contract_id}: {e}")
        return False


def record_alert_log(
    contract_id: int,
    workspace_id: str,
    calculated_cancellation_deadline: str,
    days_left: int,
    lead_days_window: int,
    alert_summary: str,
    alert_type: str = "deadline_warning",
    recipient_email: Optional[str] = None,
) -> bool:
    """
    Persist dispatched alert to alert_logs for history tracking and idempotency.
    """
    insert_sql = text("""
        INSERT INTO alert_logs (
            contract_id,
            workspace_id,
            alert_type,
            calculated_cancellation_deadline,
            days_left,
            lead_days_window,
            recipient_email,
            alert_summary
        ) VALUES (
            :contract_id,
            :workspace_id,
            :alert_type,
            :calculated_cancellation_deadline,
            :days_left,
            :lead_days_window,
            :recipient_email,
            :alert_summary
        )
        ON DUPLICATE KEY UPDATE sent_at = CURRENT_TIMESTAMP
    """)
    params = {
        "contract_id": contract_id,
        "workspace_id": workspace_id,
        "alert_type": alert_type,
        "calculated_cancellation_deadline": calculated_cancellation_deadline,
        "days_left": days_left,
        "lead_days_window": lead_days_window,
        "recipient_email": recipient_email,
        "alert_summary": alert_summary,
    }
    try:
        with engine.begin() as conn:
            conn.execute(insert_sql, params)
            return True
    except Exception as e:
        logger.error(f"Failed to record alert log for contract {contract_id}: {e}")
        return False


def get_active_contracts_for_alert_scan(workspace_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Fetch active contracts with calculated cancellation deadlines.
    Joins with workspaces to retrieve each workspace's vertical_id and default alert lead days.
    """
    query_str = """
        SELECT 
            c.*,
            w.vertical_id,
            w.name AS workspace_name
        FROM contracts c
        JOIN workspaces w ON c.workspace_id = w.id
        WHERE c.status = 'active'
          AND c.calculated_cancellation_deadline IS NOT NULL
    """
    params = {}
    if workspace_id:
        query_str += " AND c.workspace_id = :workspace_id"
        params["workspace_id"] = workspace_id
    query_str += " ORDER BY c.calculated_cancellation_deadline ASC"

    try:
        with engine.connect() as conn:
            rows = conn.execute(text(query_str), params).mappings().all()
            return [_hydrate_contract_record(dict(r)) for r in rows]
    except Exception as e:
        logger.error(f"Error querying contracts for alert scan: {e}")
        return []


def get_alert_logs(workspace_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve history of dispatched alerts."""
    query_str = """
        SELECT 
            a.*,
            c.vendor_name,
            c.contract_title
        FROM alert_logs a
        LEFT JOIN contracts c ON a.contract_id = c.id
    """
    params = {"limit": limit}
    if workspace_id:
        query_str += " WHERE a.workspace_id = :workspace_id"
        params["workspace_id"] = workspace_id
    query_str += " ORDER BY a.sent_at DESC LIMIT :limit"

    try:
        with engine.connect() as conn:
            rows = conn.execute(text(query_str), params).mappings().all()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error retrieving alert logs: {e}")
        return []


# ---------------------------------------------------------------------------
# Task 6 Ingestion Job Queue Database Helpers
# ---------------------------------------------------------------------------
def create_ingestion_job(workspace_id: str, job_type: str, payload: Optional[Dict[str, Any]] = None) -> int:
    """Create an asynchronous mailbox ingestion job."""
    insert_sql = text("""
        INSERT INTO ingestion_jobs (workspace_id, job_type, status, payload)
        VALUES (:workspace_id, :job_type, 'pending', :payload)
    """)
    params = {
        "workspace_id": workspace_id,
        "job_type": job_type,
        "payload": json.dumps(payload or {}),
    }
    with engine.begin() as conn:
        res = conn.execute(insert_sql, params)
        return res.lastrowid


def get_pending_ingestion_jobs(limit: int = 10) -> List[Dict[str, Any]]:
    """Fetch next batch of pending ingestion jobs."""
    query = text("""
        SELECT * FROM ingestion_jobs
        WHERE status = 'pending'
        ORDER BY created_at ASC
        LIMIT :limit
    """)
    try:
        with engine.connect() as conn:
            rows = conn.execute(query, {"limit": limit}).mappings().all()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error fetching pending ingestion jobs: {e}")
        return []


def update_ingestion_job(
    job_id: int,
    status: str,
    messages_found: int = 0,
    contracts_extracted: int = 0,
    duplicates_skipped: int = 0,
    error_message: Optional[str] = None,
) -> bool:
    """Update ingestion job progress and state."""
    update_sql = text("""
        UPDATE ingestion_jobs SET
            status = :status,
            messages_found = :messages_found,
            contracts_extracted = :contracts_extracted,
            duplicates_skipped = :duplicates_skipped,
            error_message = :error_message,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = :job_id
    """)
    params = {
        "job_id": job_id,
        "status": status,
        "messages_found": messages_found,
        "contracts_extracted": contracts_extracted,
        "duplicates_skipped": duplicates_skipped,
        "error_message": error_message,
    }
    try:
        with engine.begin() as conn:
            conn.execute(update_sql, params)
            return True
    except Exception as e:
        logger.error(f"Error updating ingestion job {job_id}: {e}")
        return False


def reset_database_data(preserve_demo_seed: bool = False) -> Dict[str, Any]:
    """
    Delete all rows from contracts, alert_logs, ingestion_jobs, oauth_connections,
    workspace_members, and workspaces tables so the user can test completely from scratch.
    """
    counts = {}
    with engine.begin() as conn:
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
        for table in ["alert_logs", "contracts", "ingestion_jobs", "oauth_connections", "workspace_members", "workspaces"]:
            try:
                row_count = conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()
                conn.execute(text(f"DELETE FROM {table};"))
                counts[table] = int(row_count or 0)
            except Exception as ex:
                logger.warning(f"Could not clear table {table}: {ex}")
                counts[table] = f"error: {str(ex)}"

        if preserve_demo_seed:
            conn.execute(text("INSERT IGNORE INTO workspaces (id, name, vertical_id) VALUES ('ws_default', 'Default Business Workspace', 'general_b2b');"))
            conn.execute(text("INSERT IGNORE INTO workspace_members (workspace_id, email, role) VALUES ('ws_default', 'demo@contractwatchdog.com', 'owner'), ('ws_default', 'admin@contractwatchdog.com', 'owner');"))

        conn.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))
    logger.info(f"Database reset executed: {counts}")
    return counts


def seed_apex_property_management_contracts(user_email: Optional[str] = None) -> Dict[str, Any]:
    """
    Creates or updates 'Apex Property Management' workspace and seeds realistic dummy contracts
    tailored to the Property Management vertical (elevator maintenance, waste hauling, HVAC,
    commercial landscaping/snow removal, and fire alarm monitoring).
    Associates user_email and any existing workspace members to ensure access.
    """
    import hashlib
    today = date.today()

    with engine.begin() as conn:
        # 1. Find or create Apex Property Management workspace
        existing = conn.execute(
            text("SELECT id, name, vertical_id FROM workspaces WHERE LOWER(name) LIKE '%apex property management%' OR id = 'ws_apex_property_management' LIMIT 1")
        ).mappings().first()

        if existing:
            ws_id = existing["id"]
            conn.execute(
                text("UPDATE workspaces SET name = 'Apex Property Management', vertical_id = 'property_mgmt', default_notice_period_days = 45 WHERE id = :id"),
                {"id": ws_id}
            )
        else:
            ws_id = "ws_apex_property_management"
            conn.execute(
                text("INSERT INTO workspaces (id, name, vertical_id, default_notice_period_days, inbound_email_slug) VALUES (:id, 'Apex Property Management', 'property_mgmt', 45, 'apex-property-management')"),
                {"id": ws_id}
            )

        # 2. Add members: user_email, and all distinct emails currently in workspace_members
        emails_to_add = set()
        if user_email and user_email.strip():
            emails_to_add.add(user_email.strip().lower())

        member_rows = conn.execute(text("SELECT DISTINCT email FROM workspace_members")).fetchall()
        for r in member_rows:
            if r[0] and "@" in r[0]:
                emails_to_add.add(r[0].strip().lower())

        emails_to_add.add("admin@contractwatchdog.com")
        emails_to_add.add("demo@contractwatchdog.com")

        for em in emails_to_add:
            conn.execute(
                text("INSERT INTO workspace_members (workspace_id, email, role) VALUES (:ws_id, :email, 'owner') ON DUPLICATE KEY UPDATE role = 'owner'"),
                {"ws_id": ws_id, "email": em}
            )

        # 3. Define the dummy contracts
        contracts_data = [
            {
                "vendor_name": "Schindler Elevator Corporation",
                "contract_title": "Elevator Preventive Maintenance & Safety Inspection",
                "category": "Elevator & Fire Safety",
                "status": "active",
                "notice_period_days": 60,
                "expiration_or_renewal_date": today + timedelta(days=68),
                "calculated_cancellation_deadline": today + timedelta(days=8),
                "auto_renewal_term_months": 12,
                "annual_spend_estimate": 18600.00,
                "currency": "USD",
                "price_escalation_summary": "Annual 5.0% price escalator or CPI, applied automatically upon anniversary date.",
                "how_to_change_summary": "Changes, scope reductions, or contract termination require written notice submitted via certified mail (return receipt requested) to Schindler Elevator Corp, Attn: Regional Contract Administration, 20 Whippany Rd, Morristown, NJ 07960, exactly 60 days prior to contract anniversary date.",
                "attachment_filename": "Schindler_Elevator_Service_Agreement_2026.pdf",
                "coi_or_compliance_expiry": today + timedelta(days=90),
                "key_risk_flags": ["Certified mail required for cancellation", "60-day strict notice window", "5% annual compound escalator"],
                "source_evidence_quote": "This Agreement shall automatically renew for successive one (1) year terms unless either party gives written notice of non-renewal by certified mail at least sixty (60) days prior to the expiration date.",
                "confidence_score": 0.980,
                "sender_email": "renewals@schindler-us.com",
                "email_subject": "Schindler Elevator Agreement #ELEV-7821-PM - Renewal Notice",
            },
            {
                "vendor_name": "Waste Management Inc",
                "contract_title": "Commercial Compactor & Solid Waste Hauling Agreement",
                "category": "Waste & Recycling",
                "status": "needs_review",
                "notice_period_days": 90,
                "expiration_or_renewal_date": today + timedelta(days=125),
                "calculated_cancellation_deadline": today + timedelta(days=35),
                "auto_renewal_term_months": 36,
                "annual_spend_estimate": 28400.00,
                "currency": "USD",
                "price_escalation_summary": "Uncapped quarterly fuel surcharge and environmental regulatory recovery fee adjustments.",
                "how_to_change_summary": "To cancel or renegotiate pickup frequency, written notification must be transmitted via certified mail to Waste Management Contract Services (Attn: Commercial Accounts) at least 90 days before the 36-month term expiration. Surcharges cannot be modified mid-term without a formal addendum signed by VP of Commercial Ops.",
                "attachment_filename": "WM_Commercial_Waste_Compactor_Agreement.pdf",
                "coi_or_compliance_expiry": today + timedelta(days=15),
                "key_risk_flags": ["36-month evergreen lock-in trap", "90-day certified mail notice required", "Uncapped fuel surcharges", "Expiring COI within 15 days"],
                "source_evidence_quote": "Customer agrees that unless written notice of cancellation is received via certified mail at least 90 days prior to expiration, this agreement auto-renews for an additional 36-month term.",
                "confidence_score": 0.965,
                "sender_email": "contracts@wm.com",
                "email_subject": "Commercial Waste Service Agreement #WM-90241 - Terms & Rate Schedule",
            },
            {
                "vendor_name": "Trane Commercial Systems",
                "contract_title": "HVAC Chillers & Rooftop Package Maintenance",
                "category": "HVAC & Mechanical",
                "status": "active",
                "notice_period_days": 30,
                "expiration_or_renewal_date": today + timedelta(days=80),
                "calculated_cancellation_deadline": today + timedelta(days=50),
                "auto_renewal_term_months": 12,
                "annual_spend_estimate": 21500.00,
                "currency": "USD",
                "price_escalation_summary": "Annual rate adjustment pegged to CPI, capped at maximum 3.5% annually.",
                "how_to_change_summary": "Service frequency adjustments, equipment additions/removals, or notice of termination must be sent in writing 30 days prior to annual renewal to service@tranecommercial.com or submitted through the Trane Connect portal referencing Agreement #TR-4402.",
                "attachment_filename": "Trane_HVAC_Chiller_Service_Plan.pdf",
                "coi_or_compliance_expiry": today + timedelta(days=180),
                "key_risk_flags": ["30-day notice cutoff", "After-hours emergency labor surcharges"],
                "source_evidence_quote": "Preventive HVAC maintenance services renew annually unless written notice of termination is provided 30 days prior to expiration.",
                "confidence_score": 0.990,
                "sender_email": "service@tranecommercial.com",
                "email_subject": "Trane Comprehensive HVAC Service Agreement #TR-4402",
            },
            {
                "vendor_name": "BrightView Commercial Landscapes",
                "contract_title": "Grounds Maintenance & Seasonal Snow Removal Services",
                "category": "Landscaping & Snow Removal",
                "status": "active",
                "notice_period_days": 45,
                "expiration_or_renewal_date": today + timedelta(days=105),
                "calculated_cancellation_deadline": today + timedelta(days=60),
                "auto_renewal_term_months": 12,
                "annual_spend_estimate": 15200.00,
                "currency": "USD",
                "price_escalation_summary": "Fixed seasonal rate; salt, calcium chloride, and emergency push events billed separately per incident.",
                "how_to_change_summary": "Winter storm response thresholds and seasonal turf care amendments must be agreed upon in writing by November 1st. Non-renewal requires 45 days written notice directed to commercial@brightview.com.",
                "attachment_filename": "BrightView_Grounds_Snow_Service_Contract.pdf",
                "coi_or_compliance_expiry": today + timedelta(days=40),
                "key_risk_flags": ["Seasonal snow removal clause", "45-day cancellation notice"],
                "source_evidence_quote": "Agreement auto-renews for successive 1-year terms unless either party gives written notice 45 days prior to November 30.",
                "confidence_score": 0.950,
                "sender_email": "commercial@brightview.com",
                "email_subject": "BrightView Landscape & Snow Agreement #BV-1108",
            },
            {
                "vendor_name": "Johnson Controls Life Safety",
                "contract_title": "Fire Alarm Central Monitoring & Sprinkler Flow Testing",
                "category": "Elevator & Fire Safety",
                "status": "active",
                "notice_period_days": 60,
                "expiration_or_renewal_date": today + timedelta(days=180),
                "calculated_cancellation_deadline": today + timedelta(days=120),
                "auto_renewal_term_months": 24,
                "annual_spend_estimate": 8900.00,
                "currency": "USD",
                "price_escalation_summary": "4.0% annual compounding rate adjustment on monitoring fees.",
                "how_to_change_summary": "Emergency contact list updates, inspection rescheduling, or cancellation requests require 60 days advance written notice to lifesafety@jci.com. System disconnection requires local Fire Marshal sign-off certification.",
                "attachment_filename": "JohnsonControls_Fire_Alarm_Monitoring_Agreement.pdf",
                "coi_or_compliance_expiry": today + timedelta(days=240),
                "key_risk_flags": ["24-month multi-year rollover", "Municipal fire code compliance requirement"],
                "source_evidence_quote": "Central station monitoring and life-safety inspection shall renew for additional 24-month periods unless terminated 60 days before contract anniversary.",
                "confidence_score": 0.975,
                "sender_email": "lifesafety@jci.com",
                "email_subject": "Johnson Controls Central Monitoring Agreement #JCI-88301",
            },
        ]

        # 4. Insert contracts
        inserted_contracts = []
        for c in contracts_data:
            fp_raw = f"{ws_id}_{c['vendor_name']}_{c['expiration_or_renewal_date'].isoformat()}"
            fp_hash = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()[:32]

            insert_sql = text("""
                INSERT INTO contracts (
                    workspace_id, fingerprint_hash, status, vendor_name, contract_title,
                    category, expiration_or_renewal_date, notice_period_days,
                    calculated_cancellation_deadline, auto_renewal_term_months,
                    annual_spend_estimate, currency, price_escalation_summary,
                    how_to_change_summary, attachment_filename,
                    coi_or_compliance_expiry, key_risk_flags, source_evidence_quote,
                    confidence_score, is_valid_contract_or_renewal, sender_email,
                    email_subject, raw_content
                ) VALUES (
                    :workspace_id, :fingerprint_hash, :status, :vendor_name, :contract_title,
                    :category, :expiration_or_renewal_date, :notice_period_days,
                    :calculated_cancellation_deadline, :auto_renewal_term_months,
                    :annual_spend_estimate, :currency, :price_escalation_summary,
                    :how_to_change_summary, :attachment_filename,
                    :coi_or_compliance_expiry, :key_risk_flags, :source_evidence_quote,
                    :confidence_score, 1, :sender_email,
                    :email_subject, :raw_content
                )
                ON DUPLICATE KEY UPDATE
                    status = VALUES(status),
                    contract_title = VALUES(contract_title),
                    category = VALUES(category),
                    expiration_or_renewal_date = VALUES(expiration_or_renewal_date),
                    notice_period_days = VALUES(notice_period_days),
                    calculated_cancellation_deadline = VALUES(calculated_cancellation_deadline),
                    auto_renewal_term_months = VALUES(auto_renewal_term_months),
                    annual_spend_estimate = VALUES(annual_spend_estimate),
                    price_escalation_summary = VALUES(price_escalation_summary),
                    how_to_change_summary = VALUES(how_to_change_summary),
                    attachment_filename = VALUES(attachment_filename),
                    coi_or_compliance_expiry = VALUES(coi_or_compliance_expiry),
                    key_risk_flags = VALUES(key_risk_flags),
                    source_evidence_quote = VALUES(source_evidence_quote),
                    updated_at = CURRENT_TIMESTAMP
            """)

            conn.execute(insert_sql, {
                "workspace_id": ws_id,
                "fingerprint_hash": fp_hash,
                "status": c["status"],
                "vendor_name": c["vendor_name"],
                "contract_title": c["contract_title"],
                "category": c["category"],
                "expiration_or_renewal_date": c["expiration_or_renewal_date"].isoformat(),
                "notice_period_days": c["notice_period_days"],
                "calculated_cancellation_deadline": c["calculated_cancellation_deadline"].isoformat(),
                "auto_renewal_term_months": c["auto_renewal_term_months"],
                "annual_spend_estimate": c["annual_spend_estimate"],
                "currency": c["currency"],
                "price_escalation_summary": c["price_escalation_summary"],
                "how_to_change_summary": c["how_to_change_summary"],
                "attachment_filename": c["attachment_filename"],
                "coi_or_compliance_expiry": c["coi_or_compliance_expiry"].isoformat(),
                "key_risk_flags": json.dumps(c["key_risk_flags"]),
                "source_evidence_quote": c["source_evidence_quote"],
                "confidence_score": c["confidence_score"],
                "sender_email": c["sender_email"],
                "email_subject": c["email_subject"],
                "raw_content": f"Dummy contract content for {c['vendor_name']} - {c['contract_title']}",
            })
            inserted_contracts.append(c["vendor_name"])

    return {
        "workspace_id": ws_id,
        "workspace_name": "Apex Property Management",
        "vertical_id": "property_mgmt",
        "associated_emails": list(emails_to_add),
        "contracts_seeded": inserted_contracts,
        "count": len(inserted_contracts),
    }
