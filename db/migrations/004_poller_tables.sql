-- 004_poller_tables.sql
-- Schema additions for the IMAP poller.
-- Run on Gandalf: mysql -u root -p dmarc < 004_poller_tables.sql

USE dmarc;

-- ---------------------------------------------------------------
-- imap_accounts: stores connection config for each DMARC inbox
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS imap_accounts (
    id                      INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    account_label           VARCHAR(100)    NOT NULL,
    host                    VARCHAR(253)    NOT NULL,
    port                    SMALLINT        NOT NULL DEFAULT 993,
    username                VARCHAR(255)    NOT NULL,
    password_enc            VARCHAR(512)    NOT NULL DEFAULT '',  -- AES-encrypted, empty for OAuth2
    auth_type               VARCHAR(20)     NOT NULL DEFAULT 'password', -- 'password' | 'oauth2'
    use_ssl                 TINYINT(1)      NOT NULL DEFAULT 1,
    mailbox                 VARCHAR(100)    NOT NULL DEFAULT 'INBOX',
    active                  TINYINT(1)      NOT NULL DEFAULT 1,
    last_polled             DATETIME            NULL,
    -- OAuth2 columns (populated by oauth_callback.cfm)
    oauth_access_token_enc  VARCHAR(1024)   NOT NULL DEFAULT '',
    oauth_refresh_token_enc VARCHAR(1024)   NOT NULL DEFAULT '',
    oauth_token_expiry      DATETIME            NULL,
    created_at              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE  KEY uq_imap_username (host, username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------
-- poller_runs: audit trail of each scheduled/manual poll run
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS poller_runs (
    id              INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    run_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    new_reports     INT             NOT NULL DEFAULT 0,
    skipped         INT             NOT NULL DEFAULT 0,
    errors          INT             NOT NULL DEFAULT 0,
    elapsed_sec     INT             NOT NULL DEFAULT 0,
    log_text        MEDIUMTEXT          NULL,
    PRIMARY KEY (id),
    KEY idx_run_at (run_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------
-- Ensure report table has message_id column for deduplication.
-- Safe to run even if the column already exists — will error if
-- so, which is fine; run in a script that ignores ALTER errors.
-- ---------------------------------------------------------------
ALTER TABLE report
    ADD COLUMN IF NOT EXISTS message_id  VARCHAR(255) NULL  AFTER reportid,
    ADD COLUMN IF NOT EXISTS raw_reports MEDIUMTEXT   NULL,
    ADD COLUMN IF NOT EXISTS received_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Index for fast deduplication lookup
CREATE INDEX IF NOT EXISTS idx_report_message_id ON report (message_id);

-- ---------------------------------------------------------------
-- failure: forensic/RUF reports
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS failure (
    id                  INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    message_id          VARCHAR(255)        NULL,
    failure_date        DATETIME            NULL,
    source_ip           VARCHAR(45)         NULL,   -- IPv4 or IPv6 text
    reported_domain     VARCHAR(253)        NULL,
    feedback_type       VARCHAR(50)     NOT NULL DEFAULT 'abuse',
    auth_failure        VARCHAR(50)         NULL,   -- e.g. 'dkim', 'spf', 'dmarc'
    dkim_domain         VARCHAR(253)        NULL,
    dkim_selector       VARCHAR(253)        NULL,
    spf_dns             VARCHAR(512)        NULL,
    original_mail_from  VARCHAR(255)        NULL,
    original_rcpt_to    VARCHAR(255)        NULL,
    reporting_mta       VARCHAR(255)        NULL,
    incidents           INT             NOT NULL DEFAULT 1,
    raw_message         MEDIUMTEXT          NULL,
    received_at         DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_failure_domain (reported_domain),
    KEY idx_failure_date   (failure_date),
    KEY idx_failure_msgid  (message_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
