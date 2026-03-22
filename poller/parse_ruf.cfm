<!--- poller/parse_ruf.cfm
      Parse one DMARC forensic/failure report (RUF).
      Included by poll.cfm inside the message-processing loop.

      Expects the following variables set by the caller (poll.cfm / fetch_gmail.cfm):
        msgBody      - raw MIME body text of the message:
                         Dovecot path : fetched.body (from fetchViaDoveadm)
                         Gmail path   : extracted by extractGmailRufBody()
                       parse_ruf.cfm searches this text for Content-Type:
                       message/feedback-report and message/rfc822 sections.
        msgSubject   - subject line
        cleanMsgId   - deduplicated Message-ID string
        acct         - current imap_accounts row

      Note: `attachments` is NOT used by this file. RUF reports have no
      ZIP/GZ attachment; all content is in the message body.

      Handles two body formats:
        Format A - Standard ARF (RFC 5965): multipart/report with a
          message/feedback-report MIME part containing RFC 2822-style
          header fields (Source-IP:, Feedback-Type:, Reported-Domain:, etc.)

        Format B - Plain-text forensic notification: single-part text/plain
          body with key:value lines in the format used by antispamcloud,
          Validity/ReturnPath, and similar providers:
            Sender Domain: example.com
            Sender IP Address: 1.2.3.4
            Received Date: ...
            SPF Alignment: no
            DKIM Alignment: no
            DMARC Results: Reject
          Original message headers are appended after a separator line.

      Inserts one row into the `failure` table.
      Returns early (no INSERT) if msgBody is empty.

      Lucee backslash note: \\s in a CFML double-quoted string literal
      becomes \s in the string value (regex whitespace class). Single \s
      gets mangled to plain s by Lucee's string parser.
--->
<cfscript>

    if (NOT len(trim(msgBody))) {
        logLine("  RUF: empty msgBody - nothing to parse, skipping", "WARN");
        return;
    }

    // -----------------------------------------------------------------------
    // extractHeader(block, headerName, defaultVal)
    //
    // Extract a single header value from an RFC 2822 / ARF block.
    // Pattern uses (?m) multiline so ^ matches start of each line.
    // Note: \\s in the CFML string becomes \s for the regex engine.
    // -----------------------------------------------------------------------
    function extractHeader(required string block, required string headerName, string defaultVal="") {
        var pattern = "(?m)^" & reEscape(arguments.headerName) & ":\\s*(.+?)$";
        var m = reFind(pattern, arguments.block, 1, true, "ONE");
        if (m.len[1] GT 0 AND arrayLen(m.len) GT 1)
            return trim(mid(arguments.block, m.pos[2], m.len[2]));
        return arguments.defaultVal;
    }

    // reEscape: escape regex metacharacters in a literal string
    function reEscape(required string s) {
        return reReplace(arguments.s, "([.\[\]\\\\^$|?*+(){}])", "\\\\\1", "ALL");
    }

    // -----------------------------------------------------------------------
    // Determine body format and locate the ARF block
    // -----------------------------------------------------------------------
    arfBlock     = "";
    originalHdrs = "";
    isPlainText  = false;

    // Format A: standard ARF - look for message/feedback-report MIME part
    fbReportStart = reFindNoCase("Content-Type:[\t ]*message/feedback-report", msgBody);
    if (fbReportStart GT 0) {
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
        // Format B detection: plain-text body with "Sender Domain:" or
        // "Sender IP Address:" labels (antispamcloud / ReturnPath format)
        if (reFindNoCase("Sender (Domain|IP Address):", msgBody)
                OR reFindNoCase("(SPF|DKIM) Alignment:", msgBody)) {
            isPlainText = true;
            arfBlock    = msgBody;
        } else {
            // Final fallback: treat entire body as ARF
            arfBlock = msgBody;
        }
    }

    // -----------------------------------------------------------------------
    // Extract fields from the ARF block (Format A: standard header names)
    // -----------------------------------------------------------------------
    reportType       = extractHeader(arfBlock, "Feedback-Type",           "abuse");
    reportingMTA     = extractHeader(arfBlock, "Reporting-MTA",           "");
    arrivalDate      = extractHeader(arfBlock, "Arrival-Date",            "");
    sourceIP         = extractHeader(arfBlock, "Source-IP",               "");
    incidents        = val(extractHeader(arfBlock, "Incidents",           "1"));
    originalRcptTo   = extractHeader(arfBlock, "Original-Rcpt-To",        "");
    originalMailFrom = extractHeader(arfBlock, "Original-Mail-From",      "");
    reportedDomain   = extractHeader(arfBlock, "Reported-Domain",         "");
    authFailure      = extractHeader(arfBlock, "Auth-Failure",            "");
    dkimDomain       = extractHeader(arfBlock, "DKIM-Domain",             "");
    dkimSelector     = extractHeader(arfBlock, "DKIM-Selector",           "");
    spfDNS           = extractHeader(arfBlock, "SPF-DNS",                 "");

    // -----------------------------------------------------------------------
    // Format B overrides: plain-text label extraction
    //
    // Antispamcloud / ReturnPath / similar format uses human-readable labels
    // rather than ARF header names. Extract these only when Format A failed
    // to find values, or when isPlainText is true.
    // Labels observed in the wild:
    //   Sender Domain:        -> reportedDomain
    //   Sender IP Address:    -> sourceIP
    //   Received Date:        -> arrivalDate
    //   SPF Alignment:        -> used to set authFailure if not set
    //   DKIM Alignment:       -> used to set authFailure if not set
    //   DMARC Results:        -> used to set reportType
    // -----------------------------------------------------------------------
    if (isPlainText OR NOT len(reportedDomain)) {
        ptDomain = extractHeader(arfBlock, "Sender Domain", "");
        if (len(ptDomain)) reportedDomain = ptDomain;
    }

    if (isPlainText OR NOT len(sourceIP)) {
        ptIP = extractHeader(arfBlock, "Sender IP Address", "");
        if (len(ptIP)) sourceIP = ptIP;
    }

    if (isPlainText OR NOT len(arrivalDate)) {
        ptDate = extractHeader(arfBlock, "Received Date", "");
        if (len(ptDate)) arrivalDate = ptDate;
    }

    if (isPlainText AND NOT len(authFailure)) {
        // Synthesize authFailure from SPF/DKIM alignment results
        spfAlign  = lCase(trim(extractHeader(arfBlock, "SPF Alignment",  "")));
        dkimAlign = lCase(trim(extractHeader(arfBlock, "DKIM Alignment", "")));
        if (spfAlign EQ "no" AND dkimAlign EQ "no")
            authFailure = "dmarc";
        else if (spfAlign EQ "no")
            authFailure = "spf";
        else if (dkimAlign EQ "no")
            authFailure = "dkim";
    }

    if (isPlainText AND reportType EQ "abuse") {
        // Map DMARC Results value to a feedback-type
        dmarcResult = lCase(trim(extractHeader(arfBlock, "DMARC Results", "")));
        if (len(dmarcResult)) reportType = "dmarc-" & dmarcResult;  // e.g. "dmarc-reject"
    }

    // -----------------------------------------------------------------------
    // Subject-line domain fallback (for both formats)
    // Subjects: "DMARC Forensic Report for example.com from IP ..."
    // -----------------------------------------------------------------------
    if (NOT len(reportedDomain) AND len(msgSubject)) {
        dm = reFind("(?i)(Report|Forensic|Failure)[\t ]+[Ff]or[\t ]+([^\t ]+)", msgSubject, 1, true, "ONE");
        if (dm.len[1] GT 0 AND arrayLen(dm.len) GT 2)
            reportedDomain = trim(mid(msgSubject, dm.pos[3], dm.len[3]));
    }

    // Also try subject IP extraction if sourceIP still empty
    if (NOT len(sourceIP) AND len(msgSubject)) {
        ipMatch = reFind("(?i)from IP[\t ]+([^\t ]+)", msgSubject, 1, true, "ONE");
        if (ipMatch.len[1] GT 0 AND arrayLen(ipMatch.len) GT 1)
            sourceIP = trim(mid(msgSubject, ipMatch.pos[2], ipMatch.len[2]));
    }

    // -----------------------------------------------------------------------
    // Parse arrival date; fall back to now()
    // \\d in CFML string literal becomes \d for the regex engine.
    // -----------------------------------------------------------------------
    failureDate = now();
    if (len(trim(arrivalDate))) {
        try {
            cleanDate = reReplace(trim(arrivalDate), "\\s+[+-]\\d{4}.*$", "");
            failureDate = parseDateTime(cleanDate);
        } catch(any e) {
            failureDate = now();
        }
    }

    // -----------------------------------------------------------------------
    // Original headers from message/rfc822 MIME part (Format A only)
    // -----------------------------------------------------------------------
    origHdrsStart = reFindNoCase("Content-Type:[\t ]*message/rfc822", msgBody);
    if (origHdrsStart GT 0) {
        origBodyStart = find(chr(10) & chr(10), msgBody, origHdrsStart);
        if (origBodyStart EQ 0) origBodyStart = find(chr(13) & chr(10) & chr(13) & chr(10), msgBody, origHdrsStart);
        if (origBodyStart GT 0)
            originalHdrs = left(mid(msgBody, origBodyStart, 4000), 4000);
    }

    // -----------------------------------------------------------------------
    // Insert into failure table
    // -----------------------------------------------------------------------
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

    logLine("  RUF: inserted failure record domain=#reportedDomain# ip=#sourceIP# type=#reportType#");

</cfscript>
