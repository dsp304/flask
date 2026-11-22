-- =============================================================================
-- Contract Renewal Watchdog - MySQL Schema (utf8mb4)
-- Task 7: Multi-Email Workspace Members & Scoped Ownership
-- =============================================================================

CREATE TABLE IF NOT EXISTS workspaces (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL DEFAULT 'Default Workspace',
    vertical_id VARCHAR(64) NOT NULL DEFAULT 'general_b2b',
    default_notice_period_days INT NOT NULL DEFAULT 30,
    inbound_email_slug VARCHAR(64) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_workspaces_vertical (vertical_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS contracts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    workspace_id VARCHAR(64) NOT NULL,
    fingerprint_hash VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- 'active', 'needs_review', 'expired', 'cancelled', 'archived'
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
    how_to_change_summary TEXT NULL,
    attachment_filename VARCHAR(255) NULL,
    attachment_path VARCHAR(500) NULL,
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

CREATE TABLE IF NOT EXISTS oauth_connections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    workspace_id VARCHAR(64) NOT NULL,
    provider VARCHAR(64) NOT NULL, -- 'microsoft', 'google'
    email VARCHAR(255) NULL,
    encrypted_access_token TEXT NULL,
    encrypted_refresh_token TEXT NULL,
    token_expiry TIMESTAMP NULL,
    scopes TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_oauth_ws_provider (workspace_id, provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Alert Logs table to enforce notification idempotency and dispatch history
CREATE TABLE IF NOT EXISTS alert_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    contract_id INT NOT NULL,
    workspace_id VARCHAR(64) NOT NULL,
    alert_type VARCHAR(64) NOT NULL DEFAULT 'deadline_warning', -- 'deadline_warning', 'overdue_notice', 'coi_expiration'
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

-- Ingestion Jobs table for asynchronous mailbox backfill queue
CREATE TABLE IF NOT EXISTS ingestion_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    workspace_id VARCHAR(64) NOT NULL,
    job_type VARCHAR(64) NOT NULL, -- 'webhook', 'microsoft_graph', 'google_workspace'
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- 'pending', 'processing', 'completed', 'failed'
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

-- User Profiles table for initial sign-up information and user profile management
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

-- Workspace Members table for multi-email scoping & ownership enforcement (Task 7)
CREATE TABLE IF NOT EXISTS workspace_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    workspace_id VARCHAR(64) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'owner', -- 'owner', 'member', 'viewer'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_workspace_member_email UNIQUE (workspace_id, email),
    INDEX idx_wm_email (email),
    INDEX idx_wm_workspace (workspace_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Initial Seed Data
INSERT IGNORE INTO workspaces (id, name, vertical_id)
VALUES ('ws_default', 'Default Business Workspace', 'general_b2b');

-- Backfill initial demo/admin permissions for default workspace
INSERT IGNORE INTO workspace_members (workspace_id, email, role)
VALUES ('ws_default', 'demo@contractwatchdog.com', 'owner');

INSERT IGNORE INTO workspace_members (workspace_id, email, role)
VALUES ('ws_default', 'admin@contractwatchdog.com', 'owner');
