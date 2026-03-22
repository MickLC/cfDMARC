-- 006_audit_log.sql
-- Creates the audit_log table referenced by includes/functions.cfm::auditLog().
-- Run on Gandalf: mysql -u root -p dmarc < 006_audit_log.sql

USE dmarc;

CREATE TABLE IF NOT EXISTS audit_log (
    id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED        NULL,               -- NULL for system/unauthenticated actions
    action      VARCHAR(100)    NOT NULL,               -- e.g. 'login', 'logout', 'create_account'
    detail      VARCHAR(512)    NOT NULL DEFAULT '',    -- human-readable context
    ip_address  VARCHAR(45)     NOT NULL DEFAULT '',    -- IPv4 or IPv6
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_user      (user_id),
    KEY idx_audit_action    (action),
    KEY idx_audit_created   (created_at),
    KEY idx_audit_ip        (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
