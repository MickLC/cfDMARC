<!--- poller/parse_ruf.cfm
      Parse one DMARC forensic/failure report (RUF).
      Included by poll.cfm / fetch_gmail.cfm inside the message-processing loop.

      Expects:
        msgBody      - raw MIME body text of the message
        msgSubject   - subject line
        cleanMsgId   - deduplicated Message-ID string
        acct         - current imap_accounts row

      Handles three body formats:

        Format A - Standard ARF (RFC 5965):
          multipart/report with a message/feedback-report MIME part containing
          RFC 2822-style header fields (Source-IP:, Feedback-Type:, etc.)
          The feedback-report part body may be EMPTY (163.com / Coremail style)
          in which case we fall through to Format C prose extraction.

        Format B - Plain-text forensic notification:
          Single text/plain body with human-readable key:value lines:
            Sender Domain: example.com
            Sender IP Address: 1.2.3.4
            Received Date: ...
            SPF Alignment: no / DKIM Alignment: no / DMARC Results: Reject
          Used by antispamcloud, Validity/ReturnPath, and similar.

        Format C - Prose body fallback:
          Applies after Format A or B extraction leaves sourceIP empty.
          Scans for "from IP a.b.c.d" patterns in the text/plain part.
          Also reads the first external IP from a Received: header in the
          text/rfc822-headers or message/rfc822 MIME part.

      Lucee notes:
        - reEscape renamed to rufReEscape to avoid collision with Lucee built-in.
        - \\s in a CFML double-quoted string literal becomes \s in the string
          value, which the regex engine sees as the whitespace class.
          Single \s is consumed by Lucee's string parser and becomes plain s.
--->
<cfscript>

    if (NOT len(trim(msgBody))) {
        logLine("  RUF: empty msgBody - nothing to parse, skipping", "WARN");
        return;
    }

    // -----------------------------------------------------------------------
    // rufReEscape(s) - escape regex metacharacters in a literal string.
    // Named rufReEscape (not reEscape) to avoid collision with Lucee built-in.
    // -----------------------------------------------------------------------
    function rufReEscape(required string s) {
        return reReplace(arguments.s, "([.\[\]\\\\^$|?*+(){}])", "\\\\\1", "ALL");
    }

    // -----------------------------------------------------------------------
    // extractHeader(block, headerName, defaultVal)
    // Extract one RFC 2822-style header value from a text block.
    // \\s becomes \s for the regex engine (whitespace class).
    // -----------------------------------------------------------------------
    function extractHeader(required string block, required string headerName, string defaultVal="") {
        var pattern = "(?m)^" & rufReEscape(arguments.headerName) & ":\\s*(.+?)$";
        var m = reFind(pattern, arguments.block, 1, true, "ONE");
        if (m.len[1] GT 0 AND arrayLen(m.len) GT 1)
            return trim(mid(arguments.block, m.pos[2], m.len[2]));
        return arguments.defaultVal;
    }

    // -----------------------------------------------------------------------
    // Locate the ARF block (Format A: message/feedback-report MIME part)
    // -----------------------------------------------------------------------
    arfBlock     = "";
    originalHdrs = "";
    isPlainText  = false;

    fbReportStart = reFindNoCase("Content-Type:[\t ]*message/feedback-report", msgBody);
    if (fbReportStart GT 0) {
        bodyStart = find(chr(10) & chr(10), msgBody, fbReportStart);
        if (bodyStart EQ 0) bodyStart = find(chr(13) & chr(10) & chr(13) & chr(10), msgBody, fbReportStart);
        if (bodyStart GT 0) {
            arfBlock = mid(msgBody, bodyStart, len(msgBody) - bodyStart + 1);
            boundaryPos = reFindNoCase("^--", arfBlock, 1);
            if (boundaryPos GT 1) arfBlock = left(arfBlock, boundaryPos - 1);
        }
    }

    if (NOT len(trim(arfBlock))) {
        // Format B detection: plain-text key:value report body
        if (reFindNoCase("Sender (Domain|IP Address):", msgBody)
                OR reFindNoCase("(SPF|DKIM) Alignment:", msgBody)) {
            isPlainText = true;
            arfBlock    = msgBody;
        } else {
            arfBlock = msgBody;  // final fallback
        }
    }

    // -----------------------------------------------------------------------
    // Format A extraction: standard ARF header names
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
    // Format B extraction: plain-text label names
    // Fills in fields left empty by Format A extraction.
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
        spfAlign  = lCase(trim(extractHeader(arfBlock, "SPF Alignment",  "")));
        dkimAlign = lCase(trim(extractHeader(arfBlock, "DKIM Alignment", "")));
        if (spfAlign EQ "no" AND dkimAlign EQ "no")  authFailure = "dmarc";
        else if (spfAlign EQ "no")                   authFailure = "spf";
        else if (dkimAlign EQ "no")                  authFailure = "dkim";
    }
    if (isPlainText AND reportType EQ "abuse") {
        dmarcResult = lCase(trim(extractHeader(arfBlock, "DMARC Results", "")));
        if (len(dmarcResult)) reportType = "dmarc-" & dmarcResult;
    }

    // -----------------------------------------------------------------------
    // Format C: prose and header fallbacks when Format A/B left sourceIP empty
    //
    // C1: scan text/plain part for "from IP x.x.x.x" patterns
    //     (163.com Coremail: "received from IP 58.101.208.27")
    //
    // C2: scan original headers part for the first public Received: IP
    //     The third MIME part may be text/rfc822-headers (163.com) or
    //     message/rfc822 (standard ARF).
    // -----------------------------------------------------------------------
    if (NOT len(sourceIP)) {
        // C1: extract IP from prose in the text/plain section
        plainStart = reFindNoCase("Content-Type:[\t ]*text/plain", msgBody);
        if (plainStart GT 0) {
            plainBodyStart = find(chr(10) & chr(10), msgBody, plainStart);
            if (plainBodyStart EQ 0)
                plainBodyStart = find(chr(13) & chr(10) & chr(13) & chr(10), msgBody, plainStart);
            if (plainBodyStart GT 0) {
                plainBody  = mid(msgBody, plainBodyStart, len(msgBody) - plainBodyStart + 1);
                plainBound = reFindNoCase("^--", plainBody, 1);
                if (plainBound GT 1) plainBody = left(plainBody, plainBound - 1);

                ipPat   = "(?i)(?:from IP|received from IP|Source IP|IP:)[\t ]+([0-9a-fA-F:.]+)";
                ipMatch = reFind(ipPat, plainBody, 1, true, "ONE");
                if (ipMatch.len[1] GT 0 AND arrayLen(ipMatch.len) GT 1)
                    sourceIP = trim(mid(plainBody, ipMatch.pos[2], ipMatch.len[2]));
            }
        }
    }

    if (NOT len(sourceIP)) {
        // C2: parse Received: headers from the original message part
        origPartStart = reFindNoCase(
            "Content-Type:[\t ]*(text/rfc822-headers|message/rfc822)", msgBody);
        if (origPartStart GT 0) {
            origBodyStart = find(chr(10) & chr(10), msgBody, origPartStart);
            if (origBodyStart EQ 0)
                origBodyStart = find(chr(13) & chr(10) & chr(13) & chr(10), msgBody, origPartStart);
            if (origBodyStart GT 0) {
                origHdrs  = mid(msgBody, origBodyStart, len(msgBody) - origBodyStart + 1);
                origBound = reFindNoCase("^--", origHdrs, 1);
                if (origBound GT 1) origHdrs = left(origHdrs, origBound - 1);

                rcvdPat   = "(?i)Received:[\t ]+from[^\n]+\(([0-9a-fA-F:.]+)\)";
                rcvdMatch = reFind(rcvdPat, origHdrs, 1, true, "ONE");
                if (rcvdMatch.len[1] GT 0 AND arrayLen(rcvdMatch.len) GT 1) {
                    candidateIP = trim(mid(origHdrs, rcvdMatch.pos[2], rcvdMatch.len[2]));
                    if (NOT reFindNoCase("^(127\.|10\.|192\.168\.|::1$)", candidateIP))
                        sourceIP = candidateIP;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Subject-line fallbacks (both formats)
    // -----------------------------------------------------------------------
    if (NOT len(reportedDomain) AND len(msgSubject)) {
        dm = reFind("(?i)(Report|Forensic|Failure)[\t ]+[Ff]or[\t ]+([^\t ]+)",
                    msgSubject, 1, true, "ONE");
        if (dm.len[1] GT 0 AND arrayLen(dm.len) GT 2)
            reportedDomain = trim(mid(msgSubject, dm.pos[3], dm.len[3]));
    }

    if (NOT len(sourceIP) AND len(msgSubject)) {
        ipMatch2 = reFind("(?i)from IP[\t ]+([^\t ]+)", msgSubject, 1, true, "ONE");
        if (ipMatch2.len[1] GT 0 AND arrayLen(ipMatch2.len) GT 1)
            sourceIP = trim(mid(msgSubject, ipMatch2.pos[2], ipMatch2.len[2]));
    }

    // -----------------------------------------------------------------------
    // Parse arrival date
    // \\s and \\d become \s and \d for the regex engine.
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
    // Original headers for raw_message context
    // -----------------------------------------------------------------------
    if (NOT len(originalHdrs)) {
        origPartStart2 = reFindNoCase(
            "Content-Type:[\t ]*(text/rfc822-headers|message/rfc822)", msgBody);
        if (origPartStart2 GT 0) {
            origBodyStart2 = find(chr(10) & chr(10), msgBody, origPartStart2);
            if (origBodyStart2 EQ 0)
                origBodyStart2 = find(chr(13) & chr(10) & chr(13) & chr(10), msgBody, origPartStart2);
            if (origBodyStart2 GT 0)
                originalHdrs = left(mid(msgBody, origBodyStart2, 4000), 4000);
        }
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
