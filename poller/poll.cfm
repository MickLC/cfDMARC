<!--- poller/poll.cfm
      DMARC report poller entry point for cfschedule.

      Access control: caller must supply ?token= matching application.poller.token.

      Mailbox disposition after processing is controlled by two settings:
        application.poller.markAsRead  (boolean) - set \Seen flag via doveadm
        application.poller.deleteAfter (boolean) - expunge after processing
      deleteAfter only fires after a confirmed DB write (new) or confirmed
      duplicate skip; it never fires on error.

      Architecture:
        Password accounts (local Dovecot):
          - doveadm search UNSEEN : get UIDs of unseen messages (avoids cfimap
                                    maxRows pagination problem - cfimap always
                                    returns the first N messages, not the first N
                                    unseen ones)
          - cfimap getHeaderOnly  : fetch headers for specific unseen UIDs only
          - doveadm fetch         : retrieve hdr + body per UID
          - doveadm flags add     : mark \Seen after processing
          - extractDmarcAttachment: parse raw MIME body, locate ZIP/GZ/XML part,
                                    base64-decode only the attachment payload
                                    (RUA only; RUF messages use msgBody directly)
          - extractXmlFromBytes   : decompress ZIP/GZ in parse_rua.cfm

        OAuth2 accounts (Gmail):
          - fetch_gmail.cfm       : token refresh, Gmail REST API list/fetch,
                                    base64url-decode attachments from payload tree

      Why doveadm instead of Jakarta Mail:
        Jakarta Mail StreamProvider SPI cannot be bootstrapped in Lucee's OSGi
        classloader context. doveadm is a local process with no such constraints.

      Note: doveadm path only works for local Dovecot accounts on this server.
      Gmail accounts use fetch_gmail.cfm via the Gmail REST API.

      Variables consumed by parse_ruf.cfm / parse_rua.cfm (set below):
        msgBody      - raw MIME body text (RUF); not used by parse_rua.cfm
        msgSubject   - subject line
        cleanMsgId   - deduplicated Message-ID string
        attachments  - array of { name, bytes } structs (RUA); may be empty for RUF
        acct         - current imap_accounts row

      Lucee string-literal gotchas in this file:
        - Do NOT put a literal " (double-quote) inside a double-quoted CFML
          string that is passed to a regex function. Lucee's lexer treats the
          second " as the closing delimiter even inside a character class [...].
          Use chr(34) to embed a literal double-quote in regex patterns.
        - Do NOT use \s, \r, \n, \t inside double-quoted CFML string literals.
          Lucee's string parser consumes the backslash, so the regex engine
          never sees the escape sequence. Use [ \t] or chr() alternatives.
        - \\s (double-backslash) in a CFML string literal becomes \s in the
          string value, which the regex engine sees correctly as whitespace.
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

    // IMAP \Seen flag as a literal string for doveadm - chr(92) is backslash.
    // Do NOT write "\Seen" in a CFML string literal: Lucee treats \S as an
    // escape sequence and the backslash is dropped.
    SEEN_FLAG = chr(92) & "Seen";

    function logLine(required string msg, string level="INFO") {
        var ts = dateTimeFormat(now(), "yyyy-mm-dd HH:nn:ss");
        arrayAppend(pollLog, "[#ts#] [#arguments.level#] #arguments.msg#");
        cflog(file="dmarc_poller", text="[#arguments.level#] #arguments.msg#",
              type=(arguments.level EQ "ERROR" ? "error" : "information"));
    }

    // -----------------------------------------------------------------------
    // disposeMessage(username, mailbox, uid)
    // -----------------------------------------------------------------------
    function disposeMessage(required string username, required string mailbox, required string uid) {
        if (application.poller.markAsRead) {
            try {
                var flagOut = "";
                cfexecute(
                    name               = "/usr/bin/doveadm",
                    arguments          = "flags add -u #arguments.username# #SEEN_FLAG# mailbox #arguments.mailbox# uid #arguments.uid#",
                    variable           = "flagOut",
                    timeout            = 15,
                    terminateOnTimeout = false
                );
            } catch(any e) {
                logLine("  disposeMessage: doveadm flags add error uid=#arguments.uid#: #e.message#", "WARN");
            }
        }
        if (structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter) {
            try {
                cfimap(action="delete", connection=arguments.connection,
                       folder=arguments.mailbox, uid=arguments.uid);
            } catch(any e) {}
        }
    }

    // -----------------------------------------------------------------------
    // getUnseenUids(username, mailbox, maxCount)
    // -----------------------------------------------------------------------
    function getUnseenUids(required string username, required string mailbox, required numeric maxCount) {
        var searchOut = "";
        var uids      = [];
        try {
            cfexecute(
                name               = "/usr/bin/doveadm",
                arguments          = "search -u #arguments.username# mailbox #arguments.mailbox# UNSEEN",
                variable           = "searchOut",
                timeout            = 30,
                terminateOnTimeout = false
            );
        } catch(any e) {
            logLine("  getUnseenUids: doveadm search error: #e.message#", "WARN");
            return uids;
        }
        for (var line in listToArray(trim(searchOut), chr(10))) {
            line = trim(reReplace(line, chr(13), "", "ALL"));
            if (NOT len(line)) continue;
            var tokens = listToArray(line, " ");
            if (arrayLen(tokens) GTE 2) arrayAppend(uids, tokens[2]);
            if (arrayLen(uids) GTE arguments.maxCount) break;
        }
        return uids;
    }

    // -----------------------------------------------------------------------
    // splitOnLiteral(str, delimiter)
    // -----------------------------------------------------------------------
    function splitOnLiteral(required string str, required string delim) {
        var pattern = createObject("java","java.util.regex.Pattern").quote(arguments.delim);
        var parts   = createObject("java","java.lang.String").init(arguments.str).split(pattern, -1);
        var result  = [];
        for (var p in parts) arrayAppend(result, javaCast("string", p));
        return result;
    }

    // -----------------------------------------------------------------------
    // extractDmarcAttachment(mimeBody, topHeaders)
    // NOT called for RUF messages.
    // -----------------------------------------------------------------------
    function extractDmarcAttachment(required string mimeBody, required string topHeaders) {

        function parseHeaders(required string hdrs) {
            var result   = {};
            var unfolded = reReplace(arguments.hdrs, "(" & chr(13) & chr(10) & "|" & chr(10) & ")[ " & chr(9) & "]+", " ", "ALL");
            for (var line in listToArray(unfolded, chr(10))) {
                line = reReplace(line, chr(13), "", "ALL");
                var colon = find(":", line);
                if (colon GT 1) {
                    result[lCase(trim(left(line, colon-1)))] = trim(mid(line, colon+1, len(line)));
                }
            }
            return result;
        }

        function getBoundary(required string ctValue) {
            var pat = "(?i)boundary=([^'" & chr(34) & "; " & chr(9) & ",]+)";
            var m   = reFind(pat, arguments.ctValue, 1, true);
            if (m.len[1] GT 0 AND arrayLen(m.len) GT 1) {
                var val = mid(arguments.ctValue, m.pos[2], m.len[2]);
                return reReplace(val, "^'|'$", "", "ALL");
            }
            return "";
        }

        function isDmarcPart(required string ct, required string fn) {
            if (reFindNoCase("application/(zip|gzip|x-zip|x-zip-compressed|x-gzip|octet-stream)", arguments.ct)) return true;
            if (reFindNoCase("\.xml(\.gz|\.zip)?$", arguments.fn)) return true;
            if (reFindNoCase("\.(gz|zip)$", arguments.fn)) return true;
            return false;
        }

        function getFilename(required string cd, required string ct) {
            var combined = arguments.cd & " " & arguments.ct;
            var pat = "(?i)filename=([^" & chr(34) & "'; " & chr(9) & chr(13) & chr(10) & "]+)";
            var m   = reFind(pat, combined, 1, true);
            if (m.len[1] GT 0 AND arrayLen(m.len) GT 1) {
                var val = mid(combined, m.pos[2], m.len[2]);
                return trim(reReplace(val, "^[" & chr(34) & "']|[" & chr(34) & "']$", "", "ALL"));
            }
            return "";
        }

        function b64decode(required string payload) {
            var clean = reReplace(arguments.payload, "[ " & chr(9) & chr(13) & chr(10) & "]+", "", "ALL");
            if (NOT len(clean)) return javaCast("null","");
            return createObject("java","java.util.Base64").getDecoder().decode(clean);
        }

        function findBodyStart(required string part) {
            var crlfPos = find(chr(13) & chr(10) & chr(13) & chr(10), arguments.part);
            if (crlfPos GT 0) return crlfPos + 4;
            var lfPos = find(chr(10) & chr(10), arguments.part);
            if (lfPos GT 0) return lfPos + 2;
            return 0;
        }

        function processParts(required array parts) {
            for (var rawPart in arguments.parts) {
                rawPart = trim(rawPart);
                if (NOT len(rawPart) OR rawPart EQ "--") continue;

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

        var topHdrs  = parseHeaders(arguments.topHeaders);
        var topCT    = structKeyExists(topHdrs, "content-type")              ? topHdrs["content-type"]              : "";
        var topCTE   = structKeyExists(topHdrs, "content-transfer-encoding") ? topHdrs["content-transfer-encoding"] : "7bit";
        var topCD    = structKeyExists(topHdrs, "content-disposition")       ? topHdrs["content-disposition"]       : "";
        var topFN    = getFilename(topCD, topCT);
        var boundary = getBoundary(topCT);

        if (isDmarcPart(topCT, topFN) AND NOT len(boundary)) {
            if (lCase(trim(topCTE)) EQ "base64") {
                try {
                    var dec = b64decode(arguments.mimeBody);
                    if (NOT isNull(dec) AND arrayLen(dec) GT 4) return dec;
                } catch(any e) { logLine("  MIME path 1 decode error: #e.message#", "WARN"); }
            } else {
                try {
                    var rawB = arguments.mimeBody.getBytes("ISO-8859-1");
                    if (arrayLen(rawB) GT 4) return rawB;
                } catch(any e) {}
            }
        }

        if (len(boundary)) {
            var result = processParts(splitOnLiteral(arguments.mimeBody, "--" & boundary));
            if (NOT isNull(result)) return result;
        }

        logLine("  MIME: unexpected structure CT=[#left(topCT,60)#] boundary=[#boundary#] bodyLen=#len(arguments.mimeBody)#", "WARN");
        try {
            var dec = b64decode(arguments.mimeBody);
            if (NOT isNull(dec) AND arrayLen(dec) GT 4) return dec;
        } catch(any e) {}

        return javaCast("null","");
    }

    // -----------------------------------------------------------------------
    // fetchViaDoveadm - retrieve raw hdr + body for one UID via doveadm.
    // -----------------------------------------------------------------------
    function fetchViaDoveadm(required string username, required string mailbox, required string uid) {
        var result   = { body:"", headers:"", contentType:"", messageId:"" };
        var fetchOut = "";

        try {
            cfexecute(
                name               = "/usr/bin/doveadm",
                arguments          = 'fetch -u #arguments.username# "hdr body" mailbox #arguments.mailbox# uid #arguments.uid#',
                variable           = "fetchOut",
                timeout            = 30,
                terminateOnTimeout = false
            );
        } catch(any execErr) {
            logLine("  doveadm exec error uid=#arguments.uid#: #execErr.message#", "WARN");
            return result;
        }

        if (NOT len(trim(fetchOut))) {
            logLine("  doveadm empty output uid=#arguments.uid# (deleted or inaccessible)", "WARN");
            return result;
        }

        var hdrLabel  = (find("hdr:" & chr(13) & chr(10), fetchOut) GT 0)
                        ? "hdr:"  & chr(13) & chr(10)
                        : "hdr:"  & chr(10);
        var bodyLabel = (find("body:" & chr(13) & chr(10), fetchOut) GT 0)
                        ? "body:" & chr(13) & chr(10)
                        : "body:" & chr(10);

        var hdrPos  = find(hdrLabel,  fetchOut);
        var bodyPos = find(bodyLabel, fetchOut, hdrPos + len(hdrLabel));

        if (hdrPos GT 0) {
            var hdrContentStart = hdrPos + len(hdrLabel);
            result.headers = (bodyPos GT 0)
                ? trim(mid(fetchOut, hdrContentStart, bodyPos - hdrContentStart))
                : trim(mid(fetchOut, hdrContentStart, len(fetchOut)));
        }

        if (bodyPos GT 0) {
            result.body = mid(fetchOut, bodyPos + len(bodyLabel), len(fetchOut));
        }

        var unfolded = reReplace(result.headers,
            "(" & chr(13) & chr(10) & "|" & chr(10) & ")[ " & chr(9) & "]+", " ", "ALL");

        var ctPat = "(?i)Content-Type:[ " & chr(9) & "]*([^" & chr(13) & chr(10) & "]+)";
        var ctMatch = reFind(ctPat, unfolded, 1, true);
        if (ctMatch.len[1] GT 0 AND arrayLen(ctMatch.len) GT 1)
            result.contentType = trim(mid(unfolded, ctMatch.pos[2], ctMatch.len[2]));

        var midPat = "(?i)Message-ID:[ " & chr(9) & "]*([^" & chr(13) & chr(10) & "]+)";
        var midMatch = reFind(midPat, unfolded, 1, true);
        if (midMatch.len[1] GT 0 AND arrayLen(midMatch.len) GT 1)
            result.messageId = trim(mid(unfolded, midMatch.pos[2], midMatch.len[2]));

        return result;
    }

    // -----------------------------------------------------------------------
    // isRufContentType(ct)
    //
    // Returns true if the Content-Type value indicates a RUF message.
    // Matches both quoted and unquoted report-type parameter values:
    //   multipart/report; report-type=feedback-report
    //   multipart/report; report-type="feedback-report"
    // -----------------------------------------------------------------------
    function isRufContentType(required string ct) {
        if (NOT reFindNoCase("multipart/report", arguments.ct)) return false;
        // report-type= followed by optional quote, then feedback-report
        return reFindNoCase("report-type=[" & chr(34) & "']?feedback-report", arguments.ct) GT 0;
    }

    // -----------------------------------------------------------------------
    // Main poll loop
    // -----------------------------------------------------------------------
    logLine("=== Poll run started ===");

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
                include "/poller/fetch_gmail.cfm";
                continue;
            }

            mailbox = len(trim(acct.mailbox)) ? trim(acct.mailbox) : "INBOX";

            unseenUids = getUnseenUids(acct.username, mailbox, application.poller.batchSize);
            msgCount   = arrayLen(unseenUids);
            logLine("#msgCount# unseen message(s) in mailbox");

            if (msgCount EQ 0) {
                queryExecute(
                    "UPDATE imap_accounts SET last_polled=NOW(), last_status=? WHERE id=?",
                    [
                        {value:"OK: 0 unseen", cfsqltype:"cf_sql_varchar"},
                        {value:acct.id,        cfsqltype:"cf_sql_integer"}
                    ],
                    {datasource:application.db.dsn}
                );
                continue;
            }

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

            for (msgUID in unseenUids) {

                try {
                    cfimap(
                        action     = "getHeaderOnly",
                        connection = "poll_#acct.id#",
                        folder     = mailbox,
                        name       = "qOneHeader",
                        uid        = msgUID
                    );

                    msgSubject = qOneHeader.recordCount ? qOneHeader.subject[1] : "";

                    rawHdr     = qOneHeader.recordCount ? qOneHeader.header[1] : "";
                    var midPat2  = "(?i)Message-ID:[ " & chr(9) & "]*([^" & chr(13) & chr(10) & "]+)";
                    midMatch     = reFind(midPat2, rawHdr, 1, true);
                    quickMsgId   = "";
                    if (midMatch.len[1] GT 0 AND arrayLen(midMatch.len) GT 1)
                        quickMsgId = reReplace(trim(mid(rawHdr, midMatch.pos[2], midMatch.len[2])),
                                               "[<> " & chr(9) & chr(13) & chr(10) & "]+", "", "ALL");

                    if (len(quickMsgId)) {
                        qDupe = queryExecute("SELECT id FROM report WHERE message_id=? LIMIT 1",
                            [{value:quickMsgId, cfsqltype:"cf_sql_varchar"}],
                            {datasource:application.db.dsn});
                        if (qDupe.recordCount) {
                            logLine("  uid=#msgUID# already in DB - skipping");
                            totalSkip++;
                            disposeMessage(acct.username, mailbox, msgUID);
                            continue;
                        }
                    }

                    fetched      = fetchViaDoveadm(acct.username, mailbox, msgUID);
                    contentType  = fetched.contentType;
                    attachments  = [];
                    msgBody      = fetched.body;
                    msgMessageId = len(fetched.messageId) ? fetched.messageId : (len(quickMsgId) ? quickMsgId : createUUID());

                    if (NOT len(trim(fetched.body))) {
                        totalSkip++;
                        continue;
                    }

                    cleanMsgId = reReplace(trim(msgMessageId),
                                           "[<> " & chr(9) & chr(13) & chr(10) & "]+", "", "ALL");
                    if (NOT len(cleanMsgId)) cleanMsgId = createUUID();

                    qDupe = queryExecute("SELECT id FROM report WHERE message_id=? LIMIT 1",
                        [{value:cleanMsgId, cfsqltype:"cf_sql_varchar"}],
                        {datasource:application.db.dsn});
                    if (qDupe.recordCount) {
                        logLine("  uid=#msgUID# duplicate - skipping");
                        totalSkip++;
                        disposeMessage(acct.username, mailbox, msgUID);
                        continue;
                    }

                    // RUF detection:
                    //   Signal 1: Content-Type multipart/report; report-type=["']?feedback-report
                    //             (handles both quoted and unquoted parameter values)
                    //   Signal 2: feedback-report appears anywhere in the raw headers
                    //             (catches malformed or plain-text RUF variants)
                    isRUF = isRufContentType(contentType);
                    if (NOT isRUF AND len(fetched.headers))
                        isRUF = reFindNoCase("feedback-report", fetched.headers) GT 0;

                    if (isRUF) {
                        logLine("  uid=#msgUID# -> RUF");
                        include "/poller/parse_ruf.cfm";
                    } else {
                        try {
                            rawBytes = extractDmarcAttachment(fetched.body, fetched.headers);
                            if (NOT isNull(rawBytes) AND arrayLen(rawBytes) GT 4) {
                                attachments = [{ name: "report", bytes: rawBytes }];
                            } else {
                                logLine("  uid=#msgUID# RUA: no attachment bytes extracted - skipping", "WARN");
                                totalSkip++;
                                continue;
                            }
                        } catch(any decErr) {
                            logLine("  uid=#msgUID# RUA extract error: #decErr.message# - skipping", "WARN");
                            totalSkip++;
                            continue;
                        }
                        logLine("  uid=#msgUID# -> RUA");
                        include "/poller/parse_rua.cfm";
                    }

                    disposeMessage(acct.username, mailbox, msgUID);
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
                    {value:"OK: #msgCount# unseen checked, #totalNew# new", cfsqltype:"cf_sql_varchar"},
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
