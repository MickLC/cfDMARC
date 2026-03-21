<!--- poller/poll.cfm
      DMARC report poller entry point for cfschedule.

      Access control: caller must supply ?token= matching application.poller.token.

      Uses Jakarta Mail (jakarta.mail) loaded explicitly from Lucee's own JAR,
      preventing the javax.mail/jakarta.mail classloader conflict.
      cfimap getAll silently discards inline MIME parts (no Content-Disposition:attachment)
      which is how Google sends DMARC reports. Jakarta Mail gives us every part reliably.
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

    // Jakarta Mail JAR — load explicitly so Lucee's classloader is used,
    // preventing the javax.mail vs jakarta.mail classloader conflict.
    MAIL_JAR = "/opt/lucee/tomcat/lucee-server/mvn/com/sun/mail/jakarta.mail/2.0.2/jakarta.mail-2.0.2.jar";

    function logLine(required string msg, string level="INFO") {
        var ts = dateTimeFormat(now(), "yyyy-mm-dd HH:nn:ss");
        arrayAppend(pollLog, "[#ts#] [#arguments.level#] #arguments.msg#");
        cflog(file="dmarc_poller", text="[#arguments.level#] #arguments.msg#",
              type=(arguments.level EQ "ERROR" ? "error" : "information"));
    }

    function streamToBytes(required any inputStream) {
        var baos = createObject("java","java.io.ByteArrayOutputStream").init();
        var buf  = createObject("java","java.lang.reflect.Array").newInstance(
                       createObject("java","java.lang.Byte").TYPE, javaCast("int",8192));
        var n = arguments.inputStream.read(buf);
        while (n GT 0) {
            baos.write(buf, javaCast("int",0), javaCast("int",n));
            n = arguments.inputStream.read(buf);
        }
        arguments.inputStream.close();
        return baos.toByteArray();
    }

    // Walk a MIME Part recursively via Jakarta Mail.
    // Collects every binary part regardless of Content-Disposition.
    // Returns struct { attachments: [], body: "" }
    function walkPart(required any part) {
        var result = { attachments: [], body: "" };
        var ct   = "";
        var disp = "";
        try { ct   = javaCast("string", arguments.part.getContentType() ?: ""); } catch(any e) {}
        try { disp = uCase(javaCast("string", arguments.part.getDisposition() ?: "")); } catch(any e) {}

        var isBinary = reFindNoCase(
            "(application/zip|application/gzip|application/x-gzip|application/octet-stream|text/xml|application/xml)", ct);

        // Collect as attachment if: marked ATTACHMENT, or binary content type
        if (disp EQ "ATTACHMENT" OR isBinary) {
            var fname = "";
            try { fname = javaCast("string", arguments.part.getFileName() ?: ""); } catch(any e) {}
            if (NOT len(trim(fname))) fname = "attachment";
            try {
                arrayAppend(result.attachments,
                    { name: fname, bytes: streamToBytes(arguments.part.getInputStream()) });
            } catch(any e) {}
            return result;
        }

        // Recurse into any Multipart content
        try {
            var content = arguments.part.getContent();
            // Check class name rather than instanceof to avoid classloader issues
            var className = content.getClass().getName();
            if (findNoCase("Multipart", className)) {
                for (var i = 0; i LT content.getCount(); i++) {
                    var sub = walkPart(content.getBodyPart(i));
                    for (var a in sub.attachments) arrayAppend(result.attachments, a);
                    if (NOT len(result.body) AND len(sub.body)) result.body = sub.body;
                }
                return result;
            }
            // Leaf text content
            if (reFindNoCase("text/(plain|html)", ct)) {
                result.body = javaCast("string", content ?: "");
            }
        } catch(any e) {}

        return result;
    }

    logLine("=== Poll run started ===");

    qAccounts = queryExecute(
        "SELECT id, label, host, port, username,
                password, auth_type,
                oauth_access_token, oauth_refresh_token,
                oauth_client_id, oauth_client_secret,
                oauth_token_expiry, use_ssl, mailbox
         FROM   imap_accounts
         WHERE  active = 1
         ORDER  BY id",
        {}, {datasource:application.db.dsn}
    );

    logLine("Found #qAccounts.recordCount# active account(s)");

    for (acct in qAccounts) {

        logLine("--- Account: #acct.label# (#acct.username#) ---");

        try {

            imapPassword = "";

            if (acct.auth_type EQ "oauth2") {
                needRefresh = NOT isDate(acct.oauth_token_expiry)
                              OR dateDiff("n", now(), acct.oauth_token_expiry) LT 5;
                if (needRefresh) {
                    logLine("Refreshing OAuth2 access token");
                    refreshToken = decryptValue(acct.oauth_refresh_token);
                    clientId     = acct.oauth_client_id;
                    clientSecret = decryptValue(acct.oauth_client_secret);
                    if (NOT len(refreshToken) OR NOT len(clientId) OR NOT len(clientSecret)) {
                        logLine("Missing OAuth2 credentials — skipping", "ERROR");
                        totalError++;
                        queryExecute("UPDATE imap_accounts SET last_status=? WHERE id=?",
                            [{value:"Error: missing OAuth2 credentials",cfsqltype:"cf_sql_varchar"},{value:acct.id,cfsqltype:"cf_sql_integer"}],
                            {datasource:application.db.dsn});
                        continue;
                    }
                    cfhttp(url="https://oauth2.googleapis.com/token", method="POST", result="tokenResp") {
                        cfhttpparam(type="formfield", name="client_id",     value=clientId);
                        cfhttpparam(type="formfield", name="client_secret", value=clientSecret);
                        cfhttpparam(type="formfield", name="refresh_token", value=refreshToken);
                        cfhttpparam(type="formfield", name="grant_type",    value="refresh_token");
                    }
                    tokenData = deserializeJSON(tokenResp.fileContent);
                    if (NOT structKeyExists(tokenData, "access_token")) {
                        logLine("Token refresh failed: #tokenResp.fileContent#", "ERROR");
                        totalError++;
                        queryExecute("UPDATE imap_accounts SET last_status=? WHERE id=?",
                            [{value:"Error: token refresh failed",cfsqltype:"cf_sql_varchar"},{value:acct.id,cfsqltype:"cf_sql_integer"}],
                            {datasource:application.db.dsn});
                        continue;
                    }
                    newExpiry = dateAdd("s", val(tokenData.expires_in ?: 3599), now());
                    queryExecute(
                        "UPDATE imap_accounts SET oauth_access_token=?, oauth_token_expiry=? WHERE id=?",
                        [
                            {value:encryptValue(tokenData.access_token), cfsqltype:"cf_sql_varchar"},
                            {value:newExpiry,                            cfsqltype:"cf_sql_timestamp"},
                            {value:acct.id,                              cfsqltype:"cf_sql_integer"}
                        ],
                        {datasource:application.db.dsn}
                    );
                    imapPassword = tokenData.access_token;
                } else {
                    imapPassword = decryptValue(acct.oauth_access_token);
                }
            } else {
                imapPassword = decryptValue(acct.password);
            }

            if (NOT len(imapPassword)) {
                logLine("Empty credential — skipping", "ERROR");
                totalError++;
                continue;
            }

            mailbox  = len(trim(acct.mailbox)) ? trim(acct.mailbox) : "INBOX";
            protocol = acct.use_ssl ? "imaps" : "imap";

            // Load Session from the explicit JAR to use Lucee's classloader
            props = createObject("java","java.util.Properties").init();
            props.setProperty("mail.store.protocol", protocol);
            props.setProperty("mail.#protocol#.host", acct.host);
            props.setProperty("mail.#protocol#.port", javaCast("string", acct.port));
            props.setProperty("mail.#protocol#.ssl.enable", acct.use_ssl ? "true" : "false");

            if (acct.auth_type EQ "oauth2") {
                props.setProperty("mail.#protocol#.auth.mechanisms", "XOAUTH2");
                props.setProperty("mail.#protocol#.sasl.enable",     "true");
                props.setProperty("mail.#protocol#.sasl.mechanisms", "XOAUTH2");
                connectPassword = toBase64(
                    "user=#acct.username#" & chr(1) & "auth=Bearer #imapPassword#" & chr(1) & chr(1)
                );
            } else {
                connectPassword = imapPassword;
            }

            jSession   = createObject("java", "jakarta.mail.Session", MAIL_JAR).getInstance(props);
            imapStore  = jSession.getStore(protocol);
            imapStore.connect(acct.host, acct.username, connectPassword);
            imapFolder = imapStore.getFolder(mailbox);
            imapFolder.open(javaCast("int", 2)); // Folder.READ_WRITE = 2

            jMessages = imapFolder.getMessages();
            msgCount  = arrayLen(jMessages);
            startIdx  = max(1, msgCount - application.poller.batchSize + 1);
            logLine("#msgCount# message(s); processing #(msgCount - startIdx + 1)#");

            for (msgIdx = startIdx; msgIdx LTE msgCount; msgIdx++) {

                try {
                    jMsg        = jMessages[msgIdx - 1];
                    msgSubject  = javaCast("string", jMsg.getSubject() ?: "");
                    contentType = javaCast("string", jMsg.getContentType() ?: "");

                    msgMessageId = "";
                    try {
                        hdrs = jMsg.getHeader("Message-ID");
                        if (NOT isNull(hdrs) AND arrayLen(hdrs) GT 0)
                            msgMessageId = javaCast("string", hdrs[1]);
                    } catch(any e) {}
                    if (NOT len(msgMessageId)) msgMessageId = createUUID();

                    parsed      = walkPart(jMsg);
                    attachments = parsed.attachments;
                    msgBody     = parsed.body;

                    logLine("  msg##msgIdx attachments=#arrayLen(attachments)# subject=#left(msgSubject,60)#");

                    cleanMsgId = reReplace(trim(msgMessageId), "[<>\s]", "", "ALL");
                    if (NOT len(cleanMsgId)) cleanMsgId = createUUID();

                    qDupe = queryExecute("SELECT id FROM report WHERE message_id=? LIMIT 1",
                        [{value:cleanMsgId, cfsqltype:"cf_sql_varchar"}],
                        {datasource:application.db.dsn});

                    if (qDupe.recordCount) {
                        logLine("  Duplicate — skipping");
                        totalSkip++;
                        if (application.poller.markAsRead)
                            jMsg.setFlag(
                                createObject("java","jakarta.mail.Flags$Flag", MAIL_JAR).SEEN,
                                javaCast("boolean", true));
                        continue;
                    }

                    isRUF = reFindNoCase("multipart/report", contentType)
                            AND reFindNoCase("report-type=feedback-report", contentType);
                    if (NOT isRUF) isRUF = reFindNoCase("feedback-report", msgBody);

                    if (isRUF) {
                        logLine("  -> RUF");
                        include "/poller/parse_ruf.cfm";
                    } else {
                        logLine("  -> RUA");
                        include "/poller/parse_rua.cfm";
                    }

                    if (application.poller.markAsRead)
                        jMsg.setFlag(
                            createObject("java","jakarta.mail.Flags$Flag", MAIL_JAR).SEEN,
                            javaCast("boolean", true));

                    totalNew++;

                } catch(any msgErr) {
                    logLine("  ERROR msg##msgIdx: #msgErr.message# | #msgErr.detail#", "ERROR");
                    totalError++;
                }
            }

            try { imapFolder.close(false); } catch(any e) {}
            try { imapStore.close();        } catch(any e) {}

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
            try { imapFolder.close(false); } catch(any e) {}
            try { imapStore.close();        } catch(any e) {}
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
