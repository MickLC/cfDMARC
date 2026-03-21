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
    // splitOnLiteral(str, delimiter)
    //
    // CFML's listToArray treats each CHARACTER of the delimiter as a separate
    // split token. For multi-character delimiters like MIME boundaries we must
    // use Java's String.split() with a regex-escaped delimiter instead.
    // Returns a CFML array of substrings (empty segments are preserved).
    // -----------------------------------------------------------------------
    function splitOnLiteral(required string str, required string delim) {
        // Pattern.quote() escapes all regex special chars in the delimiter
        var pattern = createObject("java","java.util.regex.Pattern").quote(arguments.delim);
        var parts   = createObject("java","java.lang.String").init(arguments.str).split(pattern, -1);
        var result  = [];
        for (var p in parts) arrayAppend(result, javaCast("string", p));
        return result;
    }

    // -----------------------------------------------------------------------
    // extractDmarcAttachment(mimeBody, topHeaders)
    //
    // Given the raw MIME body string from doveadm fetch "body" and the
    // top-level headers string from doveadm fetch "hdr", find the DMARC
    // attachment, base64-decode it, and return the raw bytes.
    //
    // Handles:
    //   - Single-part messages where the body IS the base64 attachment
    //     (Google DMARC reports: Content-Type: application/zip at top level)
    //   - Multipart messages where the attachment is a named MIME part
    //   - One level of nested multipart
    //
    // Returns: byte array, or javaCast("null","") if nothing usable found.
    // -----------------------------------------------------------------------
    function extractDmarcAttachment(required string mimeBody, required string topHeaders) {

        // ---- helper: parse header block into a struct (lowercased names) ----
        function parseHeaders(required string hdrs) {
            var result   = {};
            var unfolded = reReplace(arguments.hdrs, "(#chr(13)##chr(10)#|#chr(10)#)[ #chr(9)#]+", " ", "ALL");
            for (var line in listToArray(unfolded, chr(10))) {
                line = reReplace(line, chr(13), "", "ALL");
                var colon = find(":", line);
                if (colon GT 1) {
                    result[lCase(trim(left(line, colon-1)))] = trim(mid(line, colon+1, len(line)));
                }
            }
            return result;
        }

        // ---- helper: extract boundary value from Content-Type header ----
        function getBoundary(required string ctValue) {
            var m = reFind("(?i)boundary=[""']?([^""';\s,]+)[""']?", arguments.ctValue, 1, true);
            if (m.len[1] GT 0 AND arrayLen(m.len) GT 1)
                return mid(arguments.ctValue, m.pos[2], m.len[2]);
            return "";
        }

        // ---- helper: is this Content-Type / filename a DMARC attachment? ----
        function isDmarcPart(required string ct, required string fn) {
            if (reFindNoCase("application/(zip|gzip|x-zip|x-zip-compressed|x-gzip|octet-stream)", arguments.ct)) return true;
            if (reFindNoCase("\.xml(\.gz|\.zip)?$", arguments.fn)) return true;
            if (reFindNoCase("\.(gz|zip)$", arguments.fn)) return true;
            return false;
        }

        // ---- helper: extract filename from Content-Disposition / Content-Type ----
        function getFilename(required string cd, required string ct) {
            var combined = arguments.cd & " " & arguments.ct;
            var m = reFind("(?i)filename=[""']?([^""';\r\n]+)[""']?", combined, 1, true);
            if (m.len[1] GT 0 AND arrayLen(m.len) GT 1)
                return trim(reReplace(mid(combined, m.pos[2], m.len[2]), "[""']", "", "ALL"));
            return "";
        }

        // ---- helper: base64-decode payload string to byte array ----
        function b64decode(required string payload) {
            var clean = reReplace(arguments.payload, "\s+", "", "ALL");
            if (NOT len(clean)) return javaCast("null","");
            return createObject("java","java.util.Base64").getDecoder().decode(clean);
        }

        // ---- helper: find first blank-line split in a MIME part ----
        function findBodyStart(required string part) {
            var crlfPos = find(chr(13) & chr(10) & chr(13) & chr(10), arguments.part);
            if (crlfPos GT 0) return crlfPos + 4;
            var lfPos = find(chr(10) & chr(10), arguments.part);
            if (lfPos GT 0) return lfPos + 2;
            return 0;
        }

        // ---- helper: process array of MIME parts; return first DMARC attachment bytes ----
        // Uses splitOnLiteral() to split on the boundary string — NOT listToArray,
        // which mishandles multi-character delimiters in CFML.
        function processParts(required array parts) {
            for (var rawPart in arguments.parts) {
                rawPart = trim(rawPart);
                if (NOT len(rawPart)) continue;
                // Skip the MIME epilogue marker "--"
                if (rawPart EQ "--") continue;

                var bStart = findBodyStart(rawPart);
                if (bStart EQ 0) continue;

                var partHdr  = left(rawPart, bStart - 1);
                var partBody = mid(rawPart, bStart, len(rawPart));
                var ph       = parseHeaders(partHdr);
                var pct      = structKeyExists(ph, "content-type")              ? ph["content-type"]              : "";
                var pcd      = structKeyExists(ph, "content-disposition")       ? ph["content-disposition"]       : "";
                var pte      = structKeyExists(ph, "content-transfer-encoding") ? ph["content-transfer-encoding"] : "7bit";
                var pfn      = getFilename(pcd, pct);

                if (reFindNoCase("^multipart/", pct)) {
                    var ib = getBoundary(pct);
                    if (len(ib)) {
                        var ir = processParts(splitOnLiteral(partBody, "--" & ib));
                        if (NOT isNull(ir)) return ir;
                    }
                    continue;
                }

                if (isDmarcPart(pct, pfn) AND lCase(trim(pte)) EQ "base64") {
                    try {
                        var dec = b64decode(partBody);
                        if (NOT isNull(dec) AND arrayLen(dec) GT 4) return dec;
                    } catch(any e) {}
                }
            }
            return javaCast("null","");
        }

        // ================================================================
        // Main logic
        // ================================================================
        var topHdrs  = parseHeaders(arguments.topHeaders);
        var topCT    = structKeyExists(topHdrs, "content-type")              ? topHdrs["content-type"]              : "";
        var topCTE   = structKeyExists(topHdrs, "content-transfer-encoding") ? topHdrs["content-transfer-encoding"] : "7bit";
        var topCD    = structKeyExists(topHdrs, "content-disposition")       ? topHdrs["content-disposition"]       : "";
        var topFN    = getFilename(topCD, topCT);
        var boundary = getBoundary(topCT);

        logLine("  MIME: topCT=[#left(topCT,80)#] CTE=[#topCTE#] boundary=[#boundary#] bodyLen=#len(arguments.mimeBody)#");

        // Path 1: entire body is the attachment (Google single-part, no boundary)
        if (isDmarcPart(topCT, topFN) AND NOT len(boundary)) {
            logLine("  MIME path 1: single-part, CTE=#topCTE#");
            if (lCase(trim(topCTE)) EQ "base64") {
                try {
                    var dec = b64decode(arguments.mimeBody);
                    if (NOT isNull(dec) AND arrayLen(dec) GT 4) return dec;
                } catch(any e) { logLine("  MIME path 1 error: #e.message#", "WARN"); }
            } else {
                try {
                    var rawB = arguments.mimeBody.getBytes("ISO-8859-1");
                    if (arrayLen(rawB) GT 4) return rawB;
                } catch(any e) {}
            }
        }

        // Path 2: multipart — split on literal boundary string, find attachment part
        if (len(boundary)) {
            logLine("  MIME path 2: multipart, boundary=#left(boundary,40)#");
            var result = processParts(splitOnLiteral(arguments.mimeBody, "--" & boundary));
            if (NOT isNull(result)) return result;
        }

        // Path 3: fallback — try whole body as flat base64
        logLine("  MIME path 3: flat-base64 fallback, bodyLen=#len(arguments.mimeBody)#", "WARN");
        try {
            var dec = b64decode(arguments.mimeBody);
            if (NOT isNull(dec) AND arrayLen(dec) GT 4) return dec;
        } catch(any e) {}

        return javaCast("null","");
    }

    // -----------------------------------------------------------------------
    // fetchViaDoveadm — retrieve raw hdr + body for one UID via doveadm.
    //
    // doveadm "hdr body" output uses either LF or CRLF line endings depending
    // on the message. The section labels are literal lines:
    //   "hdr:" followed by a newline
    //   "body:" followed by a newline
    //
    // We find these with a simple string search rather than a regex, which
    // is unreliable with mixed line endings in Lucee's POSIX regex engine.
    //
    // cfexecute throws (rather than populating errorvariable) when doveadm
    // exits non-zero — e.g. when a UID was deleted between cfimap listing
    // and the doveadm call. We catch that and return an empty result so the
    // caller can skip the message cleanly without a hard error.
    // -----------------------------------------------------------------------
    function fetchViaDoveadm(required string username, required string mailbox, required string uid) {
        var result   = { body:"", headers:"", contentType:"", messageId:"" };
        var fetchOut = "";
        var fetchErr = "";

        try {
            cfexecute(
                name          = "/usr/bin/doveadm",
                arguments     = 'fetch -u #arguments.username# "hdr body" mailbox #arguments.mailbox# uid #arguments.uid#',
                variable      = "fetchOut",
                errorvariable = "fetchErr",
                timeout       = 30
            );
        } catch(any execErr) {
            // doveadm exited non-zero (message deleted, permission error, etc.)
            logLine("  doveadm failed uid=#arguments.uid#: #execErr.message#", "WARN");
            return result;
        }

        if (len(trim(fetchErr))) {
            logLine("  doveadm stderr uid=#arguments.uid#: #left(fetchErr,300)#", "WARN");
        }
        if (NOT len(trim(fetchOut))) {
            logLine("  doveadm empty output uid=#arguments.uid# (message deleted?)", "WARN");
            return result;
        }

        // Locate section labels using literal string search.
        // Try CRLF first, then LF.
        var hdrLabel  = "";
        var bodyLabel = "";
        var hdrPos    = 0;
        var bodyPos   = 0;

        if (find("hdr:" & chr(13) & chr(10), fetchOut) GT 0) {
            hdrLabel  = "hdr:"  & chr(13) & chr(10);
            bodyLabel = "body:" & chr(13) & chr(10);
        } else {
            hdrLabel  = "hdr:"  & chr(10);
            bodyLabel = "body:" & chr(10);
        }

        hdrPos  = find(hdrLabel,  fetchOut);
        bodyPos = find(bodyLabel, fetchOut, hdrPos + len(hdrLabel));

        if (hdrPos GT 0) {
            var hdrContentStart = hdrPos + len(hdrLabel);
            if (bodyPos GT 0) {
                result.headers = trim(mid(fetchOut, hdrContentStart, bodyPos - hdrContentStart));
            } else {
                result.headers = trim(mid(fetchOut, hdrContentStart, len(fetchOut)));
            }
        }

        if (bodyPos GT 0) {
            var bodyContentStart = bodyPos + len(bodyLabel);
            result.body = mid(fetchOut, bodyContentStart, len(fetchOut));
            // Not trim()-ing body: extractDmarcAttachment handles internal whitespace
        }

        logLine("  fetch: hdrLen=#len(result.headers)# bodyLen=#len(result.body)#");

        // Unfold RFC 2822 headers before extracting Content-Type / Message-ID
        var unfolded = reReplace(result.headers, "(#chr(13)##chr(10)#|#chr(10)#)[ #chr(9)#]+", " ", "ALL");

        var ctMatch = reFind("(?i)Content-Type:\s*([^\r\n]+)", unfolded, 1, true);
        if (ctMatch.len[1] GT 0 AND arrayLen(ctMatch.len) GT 1)
            result.contentType = trim(mid(unfolded, ctMatch.pos[2], ctMatch.len[2]));

        var midMatch = reFind("(?i)Message-ID:\s*([^\r\n]+)", unfolded, 1, true);
        if (midMatch.len[1] GT 0 AND arrayLen(midMatch.len) GT 1)
            result.messageId = trim(mid(unfolded, midMatch.pos[2], midMatch.len[2]));

        return result;
    }

    // -----------------------------------------------------------------------
    // Main poll loop
    // -----------------------------------------------------------------------
    logLine("=== Poll run started (v5) ===");

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

                    // Initialize rawBytes each iteration — no "var" at page scope
                    rawBytes = javaCast("null","");

                    if (len(trim(fetched.body))) {
                        try {
                            rawBytes = extractDmarcAttachment(fetched.body, fetched.headers);
                            if (NOT isNull(rawBytes) AND arrayLen(rawBytes) GT 4) {
                                attachments = [{ name: "report", bytes: rawBytes }];
                                logLine("  uid=#msgUID# decoded #arrayLen(rawBytes)# bytes");
                            } else {
                                logLine("  uid=#msgUID# no attachment bytes extracted", "WARN");
                            }
                        } catch(any decErr) {
                            logLine("  uid=#msgUID# extract error: #decErr.message# | #decErr.detail#", "WARN");
                        }
                    } else {
                        logLine("  uid=#msgUID# body empty after fetch", "WARN");
                    }

                    cleanMsgId = reReplace(trim(msgMessageId), "[<>\s]", "", "ALL");
                    if (NOT len(cleanMsgId)) cleanMsgId = createUUID();

                    // Final dedup (in case quickMsgId was empty above)
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
