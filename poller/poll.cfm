<!--- poller/poll.cfm
      DMARC report poller entry point for cfschedule.

      Access control: caller must supply ?token= matching application.poller.token.

      Architecture:
        - cfimap getHeaderOnly  : list messages, get UIDs and Message-IDs for dedup
        - doveadm fetch         : retrieve hdr + body per UID (fields: "hdr body")
        - java.util.Base64      : decode base64 body
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

    // Fetch message headers and body via doveadm.
    // Valid doveadm fetch fields include: uid hdr body (NOT "header")
    // Returns struct { body: "", headers: "", contentType: "", messageId: "" }
    function fetchViaDoveadm(required string username, required string mailbox, required string uid) {
        var result = { body:"", headers:"", contentType:"", messageId:"" };

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

        // doveadm output format for multiple fields:
        // hdr:\n<header text>\nbody:\n<base64 body>\n
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
            result.body = trim(mid(fetchOut, afterBodyLabel, len(fetchOut) - afterBodyLabel + 1));
        }

        // Extract Content-Type from headers
        var ctMatch = reFind("(?i)Content-Type:\s*([^\r\n]+)", result.headers, 1, true);
        if (ctMatch.len[1] GT 0 AND arrayLen(ctMatch.len) GT 1)
            result.contentType = trim(mid(result.headers, ctMatch.pos[2], ctMatch.len[2]));

        // Extract Message-ID from headers
        var midMatch = reFind("(?i)Message-ID:\s*([^\r\n]+)", result.headers, 1, true);
        if (midMatch.len[1] GT 0 AND arrayLen(midMatch.len) GT 1)
            result.messageId = trim(mid(result.headers, midMatch.pos[2], midMatch.len[2]));

        return result;
    }

    // Decode base64 string to byte array (strips whitespace first)
    function base64ToBytes(required string b64) {
        var clean = reReplace(arguments.b64, "\s+", "", "ALL");
        if (NOT len(clean)) return javaCast("null","");
        return createObject("java","java.util.Base64").getDecoder().decode(clean);
    }

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

                    if (len(trim(fetched.body))) {
                        try {
                            rawBytes = base64ToBytes(fetched.body);
                            if (NOT isNull(rawBytes) AND arrayLen(rawBytes) GT 1) {
                                attachments = [{ name: "report", bytes: rawBytes }];
                                logLine("  uid=#msgUID# decoded #arrayLen(rawBytes)# bytes from body");
                            }
                        } catch(any decErr) {
                            logLine("  uid=#msgUID# base64 decode error: #decErr.message#", "WARN");
                        }
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
