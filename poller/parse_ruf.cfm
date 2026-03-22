<!--- poller/parse_ruf.cfm
      Parse one DMARC forensic/failure report (RUF).
      Included by poll.cfm inside the message-processing loop.

      Expects the following variables set by the caller (poll.cfm / fetch_gmail.cfm):
        msgBody      — raw MIME body text of the message:
                         Dovecot path : fetched.body (from fetchViaDoveadm)
                         Gmail path   : extracted by extractGmailRufBody()
                       parse_ruf.cfm searches this text for Content-Type:
                       message/feedback-report and message/rfc822 sections.
        msgSubject   — subject line
        cleanMsgId   — deduplicated Message-ID string
        acct         — current imap_accounts row

      Note: `attachments` is NOT used by this file. RUF reports have no
      ZIP/GZ attachment; all ARF content is in the message body.

      Inserts one row into the `failure` table.
      Returns early (no INSERT) if msgBody is empty.
--->
<cfscript>

    // Guard: if the caller has no body content there is nothing to parse.
    // This handles the subset of RUF messages that consist only of headers
    // (e.g. header-only forwards or malformed complaint messages).
    if (NOT len(trim(msgBody))) {
        logLine("  RUF: empty msgBody - nothing to parse, skipping", "WARN");
        return;
    }

    // Helper: extract a single header value from an RFC 2822 / ARF block
    function extractHeader(required string block, required string headerName, string defaultVal="") {
        pattern = "(?m)^" & reEscape(arguments.headerName) & ":\s*(.+?)$";
        m = reFind(pattern, arguments.block, 1, true, "ONE");
        if (m.len[1] GT 0 AND arrayLen(m.len) GT 1) {
            return trim(mid(arguments.block, m.pos[2], m.len[2]));
        }
        return arguments.defaultVal;
    }

    // reEscape helper since CFML doesn't have it built in
    function reEscape(required string s) {
        return reReplace(arguments.s, "([.\[\]\\^$|?*+(){}])", "\\\1", "ALL");
    }

    // -------------------------------------------------------------------
    // Split body into MIME parts; RUF messages are multipart/report
    // consisting of: human-readable text, feedback-report, [original msg]
    // -------------------------------------------------------------------
    arfBlock      = "";
    originalHdrs  = "";

    // Find the feedback-report section
    // Pattern: Content-Type: message/feedback-report  ...blank line... body
    fbReportStart = reFindNoCase("Content-Type:\s*message/feedback-report", msgBody);
    if (fbReportStart GT 0) {
        // Advance past the headers of this MIME part to the blank line
        bodyStart = find(chr(10) & chr(10), msgBody, fbReportStart);
        if (bodyStart EQ 0) bodyStart = find(chr(13) & chr(10) & chr(13) & chr(10), msgBody, fbReportStart);
        if (bodyStart GT 0) {
            arfBlock = mid(msgBody, bodyStart, len(msgBody) - bodyStart + 1);
            // Trim at next MIME boundary if present
            boundaryPos = reFindNoCase("^--", arfBlock, 1);
            if (boundaryPos GT 1) arfBlock = left(arfBlock, boundaryPos - 1);
        }
    }

    if (NOT len(trim(arfBlock))) {
        // Fallback: treat the whole body as the ARF block
        arfBlock = msgBody;
    }

    // Extract fields from the ARF feedback-report block
    reportType       = extractHeader(arfBlock, "Feedback-Type",          "abuse");
    arfVersion       = extractHeader(arfBlock, "Version",                "1");
    userAgent        = extractHeader(arfBlock, "User-Agent",              "");
    reportingMTA     = extractHeader(arfBlock, "Reporting-MTA",          "");
    arrivalDate      = extractHeader(arfBlock, "Arrival-Date",           "");
    sourceIP         = extractHeader(arfBlock, "Source-IP",              "");
    incidents        = val(extractHeader(arfBlock, "Incidents",          "1"));
    originalRcptTo   = extractHeader(arfBlock, "Original-Rcpt-To",       "");
    originalMailFrom = extractHeader(arfBlock, "Original-Mail-From",     "");
    reportedDomain   = extractHeader(arfBlock, "Reported-Domain",        "");
    authFailure      = extractHeader(arfBlock, "Auth-Failure",           "");
    dkimDomain       = extractHeader(arfBlock, "DKIM-Domain",            "");
    dkimSelector     = extractHeader(arfBlock, "DKIM-Selector",          "");
    dkimIdentity     = extractHeader(arfBlock, "DKIM-Identity",          "");
    dkimCanon        = extractHeader(arfBlock, "DKIM-Canonicalized-Body","");
    spfDNS           = extractHeader(arfBlock, "SPF-DNS",                "");

    // If we couldn't get domain from ARF, try from the subject
    if (NOT len(reportedDomain)) {
        // DMARC subjects often look like: Report Domain: example.com Submitter: ...
        dm = reFind("(?i)Report Domain:\s*([^\s,;]+)", msgSubject, 1, true, "ONE");
        if (dm.len[1] GT 0 AND arrayLen(dm.len) GT 1) {
            reportedDomain = trim(mid(msgSubject, dm.pos[2], dm.len[2]));
        }
    }

    // Parse arrival date; fall back to now()
    failureDate = now();
    if (len(trim(arrivalDate))) {
        try {
            // RFC 2822 dates can have timezone — strip to a parseable form
            cleanDate = reReplace(arrivalDate, "\s+[+-]\d{4}.*$", "");
            failureDate = parseDateTime(cleanDate);
        } catch(any e) {
            failureDate = now();
        }
    }

    // Original headers section (third MIME part in multipart/report)
    origHdrsStart = reFindNoCase("Content-Type:\s*message/rfc822", msgBody);
    if (origHdrsStart GT 0) {
        origBodyStart = find(chr(10) & chr(10), msgBody, origHdrsStart);
        if (origBodyStart EQ 0) origBodyStart = find(chr(13)&chr(10)&chr(13)&chr(10), msgBody, origHdrsStart);
        if (origBodyStart GT 0) {
            originalHdrs = left(mid(msgBody, origBodyStart, 4000), 4000);
        }
    }

    // -------------------------------------------------------------------
    // Insert into failure table
    // -------------------------------------------------------------------
    queryExecute(
        "INSERT INTO failure
             (message_id, failure_date, source_ip,
              reported_domain, feedback_type,
              auth_failure, dkim_domain, dkim_selector,
              spf_dns, original_mail_from, original_rcpt_to,
              reporting_mta, incidents, raw_message)
         VALUES
             (?, ?, ?,
              ?, ?,
              ?, ?, ?,
              ?, ?, ?,
              ?, ?, ?)",
        [
            { value: left(cleanMsgId, 255),     cfsqltype: "cf_sql_varchar" },
            { value: failureDate,               cfsqltype: "cf_sql_timestamp" },
            { value: left(sourceIP, 45),        cfsqltype: "cf_sql_varchar", null: NOT len(sourceIP) },
            { value: left(reportedDomain, 253), cfsqltype: "cf_sql_varchar", null: NOT len(reportedDomain) },
            { value: left(reportType, 50),      cfsqltype: "cf_sql_varchar" },
            { value: left(authFailure, 50),     cfsqltype: "cf_sql_varchar", null: NOT len(authFailure) },
            { value: left(dkimDomain, 253),     cfsqltype: "cf_sql_varchar", null: NOT len(dkimDomain) },
            { value: left(dkimSelector, 253),   cfsqltype: "cf_sql_varchar", null: NOT len(dkimSelector) },
            { value: left(spfDNS, 512),         cfsqltype: "cf_sql_varchar", null: NOT len(spfDNS) },
            { value: left(originalMailFrom,255),cfsqltype: "cf_sql_varchar", null: NOT len(originalMailFrom) },
            { value: left(originalRcptTo, 255), cfsqltype: "cf_sql_varchar", null: NOT len(originalRcptTo) },
            { value: left(reportingMTA, 255),   cfsqltype: "cf_sql_varchar", null: NOT len(reportingMTA) },
            { value: incidents,                 cfsqltype: "cf_sql_integer" },
            { value: left(msgBody, 8000),       cfsqltype: "cf_sql_clob" }
        ],
        { datasource: application.db.dsn }
    );

    logLine("  RUF: inserted failure record domain=#reportedDomain# type=#reportType#");

</cfscript>
