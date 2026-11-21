-- =============================================================================
-- Contract Renewal Watchdog - MySQL Schema (utf8mb4)
-- =============================================================================

CREATE TABLE IF NOT EXISTS workspaces (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL DEFAULT 'Default Workspace',
    vertical_id VARCHAR(64) NOT NULL DEFAULT 'general_b2b',
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

-- Initial Seed Data
INSERT IGNORE INTO workspaces (id, name, vertical_id)
VALUES ('ws_default', 'Default Business Workspace', 'general_b2b');
