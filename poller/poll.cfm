<!--- poller/poll.cfm
      DMARC report poller entry point for cfschedule.

      Access control: caller must supply ?token= matching application.poller.token.

      Architecture:
        - cfimap getHeaderOnly  : list messages, get UIDs and Message-IDs for dedup
        - doveadm fetch         : retrieve hdr + body per UID (fields: "hdr body")
        - extractDmarcAttachment: parse raw MIME body, locate ZIP/GZ/XML part,
                                  base64-decode only the attachment payload
        - extractXmlFromBytes   : decompress ZIP/GZ in parse_rua.cfm

      Why doveadm instead of Jakarta Mail:
        Jakarta Mail StreamProvider SPI cannot be bootstrapped in Lucee's OSGi
        classloader context. doveadm is a local process with no such constraints.

      Note: doveadm path only works for local Dovecot accounts on this server.
      OAuth2/Gmail accounts need a different fetch mechanism (future work).
--->
<cfinclude template="/includes/functions.cfm">

<cfscript>
    param name="url.token" default="";
    if (NOT structKeyExists(application, "poller")
        OR NOT structKeyExists(application.poller, "token")
        OR url.token NEQ application.poller.token
        OR NOT len(url.token)) {
        cfheader(statusCode=403, statusText="Forbidden");
        cfabort();
    }

    pollStart  = now();
    pollLog    = [];
    totalNew   = 0;
    totalSkip  = 0;
    totalError = 0;

    function logLine(required string msg, string level="INFO") {
        var ts = dateTimeFormat(now(), "yyyy-mm-dd HH:nn:ss");
        arrayAppend(pollLog, "[#ts#] [#arguments.level#] #arguments.msg#");
        cflog(file="dmarc_poller", text="[#arguments.level#] #arguments.msg#",
              type=(arguments.level EQ "ERROR" ? "error" : "information"));
    }

    // -----------------------------------------------------------------------
    // extractDmarcAttachment(mimeBody, topHeaders)
    //
    // Given the raw MIME body string returned by doveadm fetch "body" and the
    // top-level headers string returned by doveadm fetch "hdr", locate the
    // DMARC report attachment part, strip MIME part headers, base64-decode
    // the payload, and return a byte array ready for extractXmlFromBytes().
    //
    // Returns: byte array, or javaCast("null","") if nothing usable found.
    //
    // Strategy:
    //   1. Check top-level Content-Type: if it IS application/zip|gzip|octet-stream,
    //      the entire body is the base64 payload (Google-style single-part message).
    //      Decode directly.
    //   2. If top-level Content-Type is multipart/*, extract boundary and split.
    //   3. For each part: parse part headers, look for attachment-like
    //      Content-Type or filename (*.zip/*.gz/*.xml).
    //   4. If part is itself multipart, recurse one level.
    //   5. Fallback: try decoding the whole body as flat base64.
    // -----------------------------------------------------------------------
    function extractDmarcAttachment(required string mimeBody, required string topHeaders) {

        // ---- helper: parse header block into a struct (lowercased names) ----
        // Handles RFC 2822 folded headers (continuation lines starting with whitespace)
        function parseHeaders(required string hdrs) {
            var result = {};
            var unfolded = reReplace(arguments.hdrs, "(#chr(13)##chr(10)#|#chr(10)#)[ #chr(9)#]+", " ", "ALL");
            for (var line in listToArray(unfolded, chr(10))) {
                line = reReplace(line, chr(13), "", "ALL");
                var colon = find(":", line);
                if (colon GT 1) {
                    var hname = lCase(trim(left(line, colon-1)));
                    var hval  = trim(mid(line, colon+1, len(line)));
                    result[hname] = hval;
                }
            }
            return result;
        }

        // ---- helper: extract boundary from Content-Type value ----
        function getBoundary(required string ctValue) {
            var m = reFind("(?i)boundary=[""']?([^""';\s,]+)[""']?", arguments.ctValue, 1, true);
            if (m.len[1] GT 0 AND arrayLen(m.len) GT 1)
                return mid(arguments.ctValue, m.pos[2], m.len[2]);
            return "";
        }

        // ---- helper: is this Content-Type or filename a DMARC attachment? ----
        function isDmarcPart(required string ct, required string filename) {
            if (reFindNoCase("application/(zip|gzip|x-zip|x-zip-compressed|x-gzip|octet-stream)", arguments.ct)) return true;
            if (reFindNoCase("\.xml(\.gz|\.zip)?$", arguments.filename)) return true;
            if (reFindNoCase("\.(gz|zip)$", arguments.filename)) return true;
            return false;
        }

        // ---- helper: extract filename from Content-Disposition or Content-Type ----
        function getFilename(required string cdValue, required string ctValue) {
            var combined = arguments.cdValue & " " & arguments.ctValue;
            var m = reFind("(?i)filename=[""']?([^""';\r\n]+)[""']?", combined, 1, true);
            if (m.len[1] GT 0 AND arrayLen(m.len) GT 1)
                return trim(reReplace(mid(combined, m.pos[2], m.len[2]), "[""']", "", "ALL"));
            return "";
        }

        // ---- helper: base64-decode a MIME part payload to byte array ----
        function decodeBase64Payload(required string payload) {
            var clean = reReplace(arguments.payload, "\s+", "", "ALL");
            if (NOT len(clean)) return javaCast("null","");
            return createObject("java","java.util.Base64").getDecoder().decode(clean);
        }

        // ---- helper: process an array of MIME parts, return first DMARC attachment bytes ----
        function processParts(required array parts) {
            for (var rawPart in arguments.parts) {
                rawPart = trim(rawPart);
                if (NOT len(rawPart)) continue;

                // Split part headers from part body on first blank line
                var splitPos  = 0;
                var crlfBlank = find(chr(13) & chr(10) & chr(13) & chr(10), rawPart);
                var lfBlank   = find(chr(10) & chr(10), rawPart);
                if (crlfBlank GT 0)
                    splitPos = crlfBlank + 4;   // position of first char after CRLFCRLF
                else if (lfBlank GT 0)
                    splitPos = lfBlank + 2;     // position of first char after LFLF

                if (splitPos EQ 0) continue;

                var partHdrBlock = left(rawPart, splitPos - 1);
                var partBody     = mid(rawPart, splitPos, len(rawPart));

                var ph  = parseHeaders(partHdrBlock);
                var pct = structKeyExists(ph, "content-type")              ? ph["content-type"]              : "";
                var pcd = structKeyExists(ph, "content-disposition")       ? ph["content-disposition"]       : "";
                var pte = structKeyExists(ph, "content-transfer-encoding") ? ph["content-transfer-encoding"] : "7bit";
                var pfn = getFilename(pcd, pct);

                // Nested multipart — recurse one level
                if (reFindNoCase("^multipart/", pct)) {
                    var innerBoundary = getBoundary(pct);
                    if (len(innerBoundary)) {
                        var innerParts  = listToArray(partBody, "--" & innerBoundary);
                        var innerResult = processParts(innerParts);
                        if (NOT isNull(innerResult)) return innerResult;
                    }
                    continue;
                }

                if (isDmarcPart(pct, pfn)) {
                    if (lCase(trim(pte)) EQ "base64") {
                        try {
                            var decoded = decodeBase64Payload(partBody);
                            if (NOT isNull(decoded) AND arrayLen(decoded) GT 4) return decoded;
                        } catch(any e) { /* try next part */ }
                    } else {
                        // 7bit/8bit/binary — return raw bytes via ISO-8859-1 lossless mapping
                        try {
                            var rawB = partBody.getBytes("ISO-8859-1");
                            if (arrayLen(rawB) GT 4) return rawB;
                        } catch(any e) {}
                    }
                }
            }
            return javaCast("null","");
        }

        // ================================================================
        // Main logic
        // ================================================================
        var topHdrs = parseHeaders(arguments.topHeaders);
        var topCT   = structKeyExists(topHdrs, "content-type")              ? topHdrs["content-type"]              : "";
        var topCTE  = structKeyExists(topHdrs, "content-transfer-encoding") ? topHdrs["content-transfer-encoding"] : "7bit";
        var topCD   = structKeyExists(topHdrs, "content-disposition")       ? topHdrs["content-disposition"]       : "";
        var topFN   = getFilename(topCD, topCT);
        var boundary = getBoundary(topCT);

        logLine("  MIME debug: topCT=[#left(topCT,80)#] boundary=[#boundary#] bodyLen=#len(arguments.mimeBody)#", "INFO");

        // Path 1: Top-level Content-Type IS the attachment (Google single-part style)
        // e.g. Content-Type: application/zip  with Content-Transfer-Encoding: base64
        if (isDmarcPart(topCT, topFN) AND NOT len(boundary)) {
            logLine("  MIME path: single-part attachment, CTE=#topCTE#", "INFO");
            if (lCase(trim(topCTE)) EQ "base64") {
                try {
                    var decoded = decodeBase64Payload(arguments.mimeBody);
                    if (NOT isNull(decoded) AND arrayLen(decoded) GT 4) return decoded;
                } catch(any e) {
                    logLine("  MIME path 1 decode error: #e.message#", "WARN");
                }
            } else {
                try {
                    var rawB = arguments.mimeBody.getBytes("ISO-8859-1");
                    if (arrayLen(rawB) GT 4) return rawB;
                } catch(any e) {}
            }
        }

        // Path 2: Multipart — find the attachment part
        if (len(boundary)) {
            logLine("  MIME path: multipart, boundary=#boundary#", "INFO");
            var parts  = listToArray(arguments.mimeBody, "--" & boundary);
            var result = processParts(parts);
            if (NOT isNull(result)) return result;
        }

        // Path 3: Fallback — try treating entire body as flat base64
        logLine("  MIME path: fallback flat-base64 (bodyLen=#len(arguments.mimeBody)#)", "WARN");
        try {
            var decoded = decodeBase64Payload(arguments.mimeBody);
            if (NOT isNull(decoded) AND arrayLen(decoded) GT 4) return decoded;
        } catch(any e) { /* not decodable */ }

        return javaCast("null","");
    }

    // -----------------------------------------------------------------------
    // fetchViaDoveadm  — retrieve raw hdr + body for one message UID
    // -----------------------------------------------------------------------
    function fetchViaDoveadm(required string username, required string mailbox, required string uid) {
        var result    = { body:"", headers:"", contentType:"", messageId:"" };
        var fetchOut  = "";
        var fetchErr  = "";   // var-scoped so it exists even when doveadm writes nothing to stderr

        cfexecute(
            name          = "/usr/bin/doveadm",
            arguments     = 'fetch -u #arguments.username# "hdr body" mailbox #arguments.mailbox# uid #arguments.uid#',
            variable      = "fetchOut",
            errorvariable = "fetchErr",
            timeout       = 30
        );

        if (len(trim(fetchErr))) {
            logLine("  doveadm stderr uid=#arguments.uid#: #left(fetchErr,300)#", "WARN");
        }
        if (NOT len(trim(fetchOut))) {
            // doveadm returned nothing — UID likely deleted between cfimap listing and now
            logLine("  doveadm returned empty output uid=#arguments.uid# (message gone?)", "WARN");
            return result;
        }

        // doveadm "hdr body" output format:
        //   hdr:\n<headers>\nbody:\n<raw MIME body>
        //
        // For a single-part message (e.g. Google DMARC reports), the body section
        // is the base64-encoded attachment directly.
        // For multipart messages, the body section is the full MIME body with
        // boundary markers and per-part headers embedded.
        var hdrStart  = reFindNoCase("(?m)^hdr:\s*$",  fetchOut);
        var bodyStart = reFindNoCase("(?m)^body:\s*$", fetchOut);

        if (hdrStart GT 0) {
            var afterHdrLabel = hdrStart + len(reMatch("(?m)^hdr:\s*$\n?", fetchOut)[1]);
            if (bodyStart GT 0 AND bodyStart GT afterHdrLabel) {
                result.headers = trim(mid(fetchOut, afterHdrLabel, bodyStart - afterHdrLabel));
            } else {
                result.headers = trim(mid(fetchOut, afterHdrLabel, len(fetchOut) - afterHdrLabel + 1));
            }
        }

        if (bodyStart GT 0) {
            var afterBodyLabel = bodyStart + len(reMatch("(?m)^body:\s*$\n?", fetchOut)[1]);
            // Do NOT trim() the body — extractDmarcAttachment handles whitespace internally
            result.body = mid(fetchOut, afterBodyLabel, len(fetchOut) - afterBodyLabel + 1);
        }

        // Extract Content-Type from headers (may be folded — unfold first)
        var unfolded = reReplace(result.headers, "(#chr(13)##chr(10)#|#chr(10)#)[ #chr(9)#]+", " ", "ALL");
        var ctMatch = reFind("(?i)Content-Type:\s*([^\r\n]+)", unfolded, 1, true);
        if (ctMatch.len[1] GT 0 AND arrayLen(ctMatch.len) GT 1)
            result.contentType = trim(mid(unfolded, ctMatch.pos[2], ctMatch.len[2]));

        // Extract Message-ID from headers
        var midMatch = reFind("(?i)Message-ID:\s*([^\r\n]+)", unfolded, 1, true);
        if (midMatch.len[1] GT 0 AND arrayLen(midMatch.len) GT 1)
            result.messageId = trim(mid(unfolded, midMatch.pos[2], midMatch.len[2]));

        return result;
    }

    // -----------------------------------------------------------------------
    // Main poll loop
    // -----------------------------------------------------------------------
    logLine("=== Poll run started (v2) ===");

    qAccounts = queryExecute(
        "SELECT id, label, host, port, username,
                password, auth_type, use_ssl, mailbox
         FROM   imap_accounts
         WHERE  active = 1
         ORDER  BY id",
        {}, {datasource:application.db.dsn}
    );

    logLine("Found #qAccounts.recordCount# active account(s)");

    for (acct in qAccounts) {

        logLine("--- Account: #acct.label# (#acct.username#) ---");

        try {

            if (acct.auth_type EQ "oauth2") {
                logLine("  OAuth2 accounts not yet supported via doveadm — skipping", "WARN");
                continue;
            }

            mailbox      = len(trim(acct.mailbox)) ? trim(acct.mailbox) : "INBOX";
            imapPassword = decryptValue(acct.password);

            cfimap(
                action     = "open",
                connection = "poll_#acct.id#",
                server     = acct.host,
                port       = acct.port,
                username   = acct.username,
                password   = imapPassword,
                secure     = (acct.use_ssl ? true : false),
                timeout    = 60
            );

            cfimap(
                action     = "getHeaderOnly",
                connection = "poll_#acct.id#",
                folder     = mailbox,
                name       = "qHeaders",
                maxRows    = application.poller.batchSize
            );

            msgCount = qHeaders.recordCount;
            logLine("#msgCount# message(s) in mailbox");

            for (msgIdx = 1; msgIdx LTE msgCount; msgIdx++) {

                try {
                    msgUID     = qHeaders.uid[msgIdx];
                    msgSubject = qHeaders.subject[msgIdx];

                    // Quick dedup from header column (avoids doveadm call for already-seen messages)
                    rawHdr     = qHeaders.header[msgIdx];
                    midMatch   = reFind("(?i)Message-ID:\s*([^\r\n]+)", rawHdr, 1, true);
                    quickMsgId = "";
                    if (midMatch.len[1] GT 0 AND arrayLen(midMatch.len) GT 1)
                        quickMsgId = reReplace(trim(mid(rawHdr, midMatch.pos[2], midMatch.len[2])), "[<>\s]", "", "ALL");

                    if (len(quickMsgId)) {
                        qDupe = queryExecute("SELECT id FROM report WHERE message_id=? LIMIT 1",
                            [{value:quickMsgId, cfsqltype:"cf_sql_varchar"}],
                            {datasource:application.db.dsn});
                        if (qDupe.recordCount) {
                            logLine("  uid=#msgUID# already in DB — skipping");
                            totalSkip++;
                            if (application.poller.markAsRead)
                                try { cfimap(action="markRead", connection="poll_#acct.id#", folder=mailbox, uid=msgUID); } catch(any e) {}
                            continue;
                        }
                    }

                    logLine("  uid=#msgUID# fetching via doveadm...");

                    fetched      = fetchViaDoveadm(acct.username, mailbox, msgUID);
                    contentType  = fetched.contentType;
                    msgBody      = "";
                    attachments  = [];
                    msgMessageId = len(fetched.messageId) ? fetched.messageId : (len(quickMsgId) ? quickMsgId : createUUID());

                    // Extract the DMARC attachment from the raw MIME body.
                    // extractDmarcAttachment() handles both single-part (Google-style)
                    // and multipart messages, and base64-decodes the attachment payload.
                    if (len(trim(fetched.body))) {
                        try {
                            rawBytes = extractDmarcAttachment(fetched.body, fetched.headers);
                            if (NOT isNull(rawBytes) AND arrayLen(rawBytes) GT 4) {
                                attachments = [{ name: "report", bytes: rawBytes }];
                                logLine("  uid=#msgUID# decoded #arrayLen(rawBytes)# bytes from body");
                            } else {
                                logLine("  uid=#msgUID# extractDmarcAttachment returned null/empty", "WARN");
                            }
                        } catch(any decErr) {
                            logLine("  uid=#msgUID# attachment extract error: #decErr.message# | #decErr.detail#", "WARN");
                        }
                    } else {
                        logLine("  uid=#msgUID# fetched.body is empty", "WARN");
                    }

                    cleanMsgId = reReplace(trim(msgMessageId), "[<>\s]", "", "ALL");
                    if (NOT len(cleanMsgId)) cleanMsgId = createUUID();

                    // Final dedup (in case quickMsgId was empty)
                    qDupe = queryExecute("SELECT id FROM report WHERE message_id=? LIMIT 1",
                        [{value:cleanMsgId, cfsqltype:"cf_sql_varchar"}],
                        {datasource:application.db.dsn});
                    if (qDupe.recordCount) {
                        logLine("  uid=#msgUID# duplicate — skipping");
                        totalSkip++;
                        if (application.poller.markAsRead)
                            try { cfimap(action="markRead", connection="poll_#acct.id#", folder=mailbox, uid=msgUID); } catch(any e) {}
                        continue;
                    }

                    isRUF = reFindNoCase("multipart/report", contentType)
                            AND reFindNoCase("report-type=feedback-report", contentType);
                    if (NOT isRUF AND len(fetched.headers)) isRUF = reFindNoCase("feedback-report", fetched.headers);

                    if (isRUF) {
                        logLine("  -> RUF");
                        include "/poller/parse_ruf.cfm";
                    } else {
                        logLine("  -> RUA (subject: #left(msgSubject,80)#)");
                        include "/poller/parse_rua.cfm";
                    }

                    if (application.poller.markAsRead)
                        try { cfimap(action="markRead", connection="poll_#acct.id#", folder=mailbox, uid=msgUID); } catch(any e) {}

                    totalNew++;

                } catch(any msgErr) {
                    logLine("  ERROR uid=#msgUID#: #msgErr.message# | #msgErr.detail#", "ERROR");
                    totalError++;
                }
            }

            try { cfimap(action="close", connection="poll_#acct.id#"); } catch(any e) {}

            queryExecute(
                "UPDATE imap_accounts SET last_polled=NOW(), last_status=? WHERE id=?",
                [
                    {value:"OK: #msgCount# checked, #totalNew# new", cfsqltype:"cf_sql_varchar"},
                    {value:acct.id, cfsqltype:"cf_sql_integer"}
                ],
                {datasource:application.db.dsn}
            );

        } catch(any acctErr) {
            logLine("ACCOUNT ERROR (#acct.label#): #acctErr.message# | #acctErr.detail#", "ERROR");
            totalError++;
            try { cfimap(action="close", connection="poll_#acct.id#"); } catch(any e) {}
            queryExecute("UPDATE imap_accounts SET last_status=? WHERE id=?",
                [{value:"Error: " & left(acctErr.message,200), cfsqltype:"cf_sql_varchar"},{value:acct.id,cfsqltype:"cf_sql_integer"}],
                {datasource:application.db.dsn});
        }
    }

    elapsed = dateDiff("s", pollStart, now());
    logLine("=== Done: #totalNew# new, #totalSkip# skipped, #totalError# errors, #elapsed#s ===");

    try {
        queryExecute(
            "INSERT INTO poller_runs (run_at,new_reports,skipped,errors,elapsed_sec,log_text)
             VALUES (NOW(),?,?,?,?,?)",
            [
                {value:totalNew,   cfsqltype:"cf_sql_integer"},
                {value:totalSkip,  cfsqltype:"cf_sql_integer"},
                {value:totalError, cfsqltype:"cf_sql_integer"},
                {value:elapsed,    cfsqltype:"cf_sql_integer"},
                {value:left(arrayToList(pollLog,chr(10)),8000), cfsqltype:"cf_sql_clob"}
            ],
            {datasource:application.db.dsn}
        );
    } catch(any logErr) {
        cflog(file="dmarc_poller", text="Failed to insert poller_run: #logErr.message#", type="error");
    }

    writeOutput("OK: " & totalNew & " new / " & totalSkip & " skipped / " & totalError & " errors");
</cfscript>
