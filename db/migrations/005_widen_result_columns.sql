-- 005_widen_result_columns.sql
-- Widen dkimresult and spfresult columns in rptrecord from VARCHAR(20)
-- to VARCHAR(50). Some senders (notably docomo.ne.jp) emit non-standard
-- result values longer than 20 characters, causing strict-mode truncation
-- errors that aborted the entire report insert.
--
-- Run on Gandalf: mysql -u root -p dmarc < 005_widen_result_columns.sql

USE dmarc;

ALTER TABLE rptrecord
    MODIFY COLUMN dkimresult VARCHAR(50) NULL,
    MODIFY COLUMN spfresult  VARCHAR(50) NULL;
