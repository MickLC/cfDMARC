<!--- poller/poll.cfm
      DMARC report poller entry point for cfschedule.

      Access control: caller must supply ?token= matching application.poller.token.

      Uses JavaMail directly for ALL accounts (password and OAuth2).
      cfimap getAll silently discards MIME parts that lack Content-Disposition:attachment,
      which is how Google sends DMARC reports. JavaMail gives us every part reliably.
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

    // Read a JavaMail InputStream into a Java byte array
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

    // Walk a MIME Part recursively; collect binary attachments and text body
    // Returns struct { attachments: [], body: "" }
    function walkPart(required any part) {
        var result = { attachments: [], body: "" };
        var ct = javaCast("string", arguments.part.getContentType() ?: "");
        var disp = "";
        try { disp = javaCast("string", arguments.part.getDisposition() ?: ""); } catch(any e) {}

        // Binary attachment types we care about
        var isBinary = reFindNoCase("(application/zip|application/gzip|application/x-gzip|application/octet-stream|text/xml|application/xml)", ct);
        var isAttachment = (disp EQ "ATTACHMENT") OR isBinary;

        if (isAttachment OR (disp EQ "" AND isBinary)) {
            var fname = "";
            try { fname = javaCast("string", arguments.part.getFileName() ?: ""); } catch(any e) {}
            if (NOT len(fname)) fname = "attachment";
            arrayAppend(result.attachments, { name: fname, bytes: streamToBytes(arguments.part.getInputStream()) });
            return result;
        }

        // Recurse into multipart
        try {
            var content = arguments.part.getContent();
            if (isInstanceOf(content, "javax.mail.Multipart")) {
                for (var i = 0; i LT content.getCount(); i++) {
                    var sub = walkPart(content.getBodyPart(i));
                    result.attachments.addAll(sub.attachments);
                    if (NOT len(result.body) AND len(sub.body)) result.body = sub.body;
                }
                return result;
            }
        } catch(any e) {}

        // Leaf text/plain or text/html
        if (reFindNoCase("text/(plain|html)", ct)) {
            try { result.body = javaCast("string", arguments.part.getContent() ?: ""); } catch(any e) {}
        }
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

            // ----------------------------------------------------------
            // Resolve credential
            // ----------------------------------------------------------
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

            // ----------------------------------------------------------
            // Open JavaMail store
            // ----------------------------------------------------------
            mailbox  = len(trim(acct.mailbox)) ? trim(acct.mailbox) : "INBOX";
            protocol = acct.use_ssl ? "imaps" : "imap";

            props = createObject("java","java.util.Properties").init();
            props.setProperty("mail.store.protocol", protocol);
            props.setProperty("mail.#protocol#.host", acct.host);
            props.setProperty("mail.#protocol#.port", javaCast("string", acct.port));
            props.setProperty("mail.#protocol#.ssl.enable", acct.use_ssl ? "true" : "false");

            if (acct.auth_type EQ "oauth2") {
                props.setProperty("mail.#protocol#.auth.mechanisms",  "XOAUTH2");
                props.setProperty("mail.#protocol#.sasl.enable",      "true");
                props.setProperty("mail.#protocol#.sasl.mechanisms",  "XOAUTH2");
                connectPassword = toBase64(
                    "user=#acct.username#" & chr(1) & "auth=Bearer #imapPassword#" & chr(1) & chr(1)
                );
            } else {
                connectPassword = imapPassword;
            }

            jSession   = createObject("java","javax.mail.Session").getInstance(props);
            imapStore  = jSession.getStore(protocol);
            imapStore.connect(acct.host, acct.username, connectPassword);
            imapFolder = imapStore.getFolder(mailbox);
            imapFolder.open(createObject("java","javax.mail.Folder").READ_WRITE);

            // Fetch all messages (we deduplicate by message_id, so seeing read messages is fine)
            jMessages = imapFolder.getMessages();
            msgCount  = arrayLen(jMessages);

            // Limit to batchSize, taking the most recent
            startIdx = max(1, msgCount - application.poller.batchSize + 1);
            logLine("#msgCount# message(s) in mailbox; processing #(msgCount - startIdx + 1)#");

            // ----------------------------------------------------------
            // Process messages
            // ----------------------------------------------------------
            for (msgIdx = startIdx; msgIdx LTE msgCount; msgIdx++) {

                try {
                    jMsg         = jMessages[msgIdx - 1];
                    msgSubject   = javaCast("string", jMsg.getSubject() ?: "");
                    contentType  = javaCast("string", jMsg.getContentType() ?: "");

                    // Get Message-ID header
                    msgMessageId = "";
                    try {
                        hdrs = jMsg.getHeader("Message-ID");
                        if (NOT isNull(hdrs) AND arrayLen(hdrs) GT 0)
                            msgMessageId = javaCast("string", hdrs[1]);
                    } catch(any e) {}
                    if (NOT len(msgMessageId)) msgMessageId = createUUID();

                    // Walk MIME structure to collect attachments and body
                    parsed      = walkPart(jMsg);
                    attachments = parsed.attachments;
                    msgBody     = parsed.body;

                    logLine("  uid=#jMsg.getMessageNumber()# attachments=#arrayLen(attachments)# subject=#msgSubject#");

                    // Deduplicate
                    cleanMsgId = reReplace(trim(msgMessageId), "[<>\s]", "", "ALL");
                    if (NOT len(cleanMsgId)) cleanMsgId = createUUID();

                    qDupe = queryExecute("SELECT id FROM report WHERE message_id=? LIMIT 1",
                        [{value:cleanMsgId, cfsqltype:"cf_sql_varchar"}],
                        {datasource:application.db.dsn});

                    if (qDupe.recordCount) {
                        logLine("  Duplicate — skipping");
                        totalSkip++;
                        if (application.poller.markAsRead)
                            jMsg.setFlag(createObject("java","javax.mail.Flags$Flag").SEEN, true);
                        continue;
                    }

                    // Route RUF vs RUA
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
                        jMsg.setFlag(createObject("java","javax.mail.Flags$Flag").SEEN, true);

                    totalNew++;

                } catch(any msgErr) {
                    logLine("  ERROR msg ##msgIdx: #msgErr.message# | #msgErr.detail#", "ERROR");
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
