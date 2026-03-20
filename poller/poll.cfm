<!--- poller/poll.cfm
      DMARC report poller — entry point for cfschedule.
      Loops every active imap_accounts row, connects via IMAP,
      fetches unread messages and delegates to parse_rua.cfm or
      parse_ruf.cfm.  Designed to be called 4x daily by cfschedule.

      ACCESS: localhost only — protected by Application.cfc onRequestStart.
--->
<cfinclude template="/includes/functions.cfm">

<cfscript>
    // Only allow localhost or scheduled task invocation
    if (cgi.remote_addr NEQ "127.0.0.1" AND cgi.remote_addr NEQ "::1") {
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
        cflog(file="dmarc_poller", text="[#arguments.level#] #arguments.msg#", type=(arguments.level EQ "ERROR" ? "error" : "information"));
    }

    logLine("=== Poll run started ===");

    // Fetch all active accounts
    qAccounts = queryExecute(
        "SELECT id, account_label, host, port, username,
                password_enc, auth_type,
                oauth_access_token_enc, oauth_refresh_token_enc,
                oauth_token_expiry, use_ssl, mailbox,
                last_polled
         FROM   imap_accounts
         WHERE  active = 1
         ORDER  BY id",
        {},
        { datasource: application.db.dsn }
    );

    logLine("Found #qAccounts.recordCount# active account(s)");

    for (acct in qAccounts) {

        logLine("--- Account: #acct.account_label# (#acct.username#) ---");

        try {

            // --------------------------------------------------------
            // Resolve credentials
            // --------------------------------------------------------
            imapPassword = "";

            if (acct.auth_type EQ "oauth2") {
                // Check token expiry; refresh if within 5 minutes of expiring
                needRefresh = false;
                if (NOT isDate(acct.oauth_token_expiry)
                    OR dateDiff("n", now(), acct.oauth_token_expiry) LT 5) {
                    needRefresh = true;
                }

                if (needRefresh) {
                    logLine("Access token expired or expiring soon — refreshing");
                    refreshToken = decryptValue(acct.oauth_refresh_token_enc);
                    if (NOT len(refreshToken)) {
                        logLine("No refresh token stored for #acct.account_label# — skipping", "ERROR");
                        totalError++;
                        continue;
                    }

                    // Exchange refresh token for new access token
                    cfhttp(
                        url    = "https://oauth2.googleapis.com/token",
                        method = "POST",
                        result = "tokenResp"
                    ) {
                        cfhttpparam(type="formfield", name="client_id",     value=application.googleOAuth.clientId);
                        cfhttpparam(type="formfield", name="client_secret", value=application.googleOAuth.clientSecret);
                        cfhttpparam(type="formfield", name="refresh_token", value=refreshToken);
                        cfhttpparam(type="formfield", name="grant_type",    value="refresh_token");
                    }

                    tokenData = deserializeJSON(tokenResp.fileContent);
                    if (NOT structKeyExists(tokenData, "access_token")) {
                        logLine("Token refresh failed: #tokenResp.fileContent#", "ERROR");
                        totalError++;
                        continue;
                    }

                    newExpiry = dateAdd("s", val(tokenData.expires_in ?: 3599), now());
                    queryExecute(
                        "UPDATE imap_accounts
                         SET    oauth_access_token_enc = ?,
                                oauth_token_expiry     = ?
                         WHERE  id = ?",
                        [
                            { value: encryptValue(tokenData.access_token), cfsqltype: "cf_sql_varchar" },
                            { value: newExpiry,                            cfsqltype: "cf_sql_timestamp" },
                            { value: acct.id,                              cfsqltype: "cf_sql_integer" }
                        ],
                        { datasource: application.db.dsn }
                    );
                    imapPassword = tokenData.access_token;
                    logLine("Access token refreshed; expires #dateTimeFormat(newExpiry,'yyyy-mm-dd HH:nn')#");
                } else {
                    imapPassword = decryptValue(acct.oauth_access_token_enc);
                }

            } else {
                // Standard password auth
                imapPassword = decryptValue(acct.password_enc);
            }

            if (NOT len(imapPassword)) {
                logLine("Empty password/token for #acct.account_label# — skipping", "ERROR");
                totalError++;
                continue;
            }

            // --------------------------------------------------------
            // Open IMAP connection
            // --------------------------------------------------------
            mailbox = len(trim(acct.mailbox)) ? trim(acct.mailbox) : "INBOX";

            if (acct.auth_type EQ "oauth2") {
                // Lucee IMAP tag does not natively support XOAUTH2.
                // We use the JavaMail API directly via cfobject.
                // Build SASL XOAUTH2 token:
                // base64("user=" + email + chr(1) + "auth=Bearer " + token + chr(1) + chr(1))
                xoauth2Raw = "user=#acct.username#" & chr(1) & "auth=Bearer #imapPassword#" & chr(1) & chr(1);
                xoauth2Token = toBase64(xoauth2Raw);

                props = createObject("java", "java.util.Properties").init();
                props.setProperty("mail.store.protocol", "imaps");
                props.setProperty("mail.imaps.host", acct.host);
                props.setProperty("mail.imaps.port", javaCast("string", acct.port));
                props.setProperty("mail.imaps.ssl.enable", "true");
                props.setProperty("mail.imaps.auth.mechanisms", "XOAUTH2");
                props.setProperty("mail.imaps.sasl.enable", "true");
                props.setProperty("mail.imaps.sasl.mechanisms", "XOAUTH2");
                props.setProperty("mail.imaps.auth.login.disable", "true");
                props.setProperty("mail.imaps.auth.plain.disable", "true");

                session   = createObject("java", "javax.mail.Session").getInstance(props);
                imapStore = session.getStore("imaps");
                imapStore.connect(acct.host, acct.username, xoauth2Token);

                imapFolder = imapStore.getFolder(mailbox);
                imapFolder.open(createObject("java", "javax.mail.Folder").READ_WRITE);

                // Fetch UNSEEN messages
                flagSeen    = createObject("java", "javax.mail.Flags$Flag");
                searchTerm  = createObject("java", "javax.mail.search.FlagTerm").init(
                    createObject("java", "javax.mail.Flags").init(flagSeen.SEEN),
                    javaCast("boolean", false)
                );
                jMessages   = imapFolder.search(searchTerm);
                useJavaMail = true;

            } else {
                // Standard cfImap tag — simpler path
                cfimap(
                    action     = "getHeaderList",
                    server     = acct.host,
                    port       = acct.port,
                    username   = acct.username,
                    password   = imapPassword,
                    secure     = (acct.use_ssl ? true : false),
                    folder     = mailbox,
                    messageType = "UNSEEN",
                    name       = "qMessages",
                    maxRows    = application.poller.batchSize
                );
                useJavaMail = false;
            }

            // Normalise to an array of message UIDs/objects for uniform processing
            if (useJavaMail) {
                msgCount = arrayLen(jMessages);
            } else {
                msgCount = qMessages.recordCount;
            }

            logLine("#msgCount# unread message(s) in #mailbox#");

            // --------------------------------------------------------
            // Process each message
            // --------------------------------------------------------
            for (msgIdx = 1; msgIdx LTE msgCount; msgIdx++) {

                try {
                    if (useJavaMail) {
                        jMsg       = jMessages[msgIdx - 1]; // Java arrays are 0-based
                        msgUID     = javaCast("string", jMsg.getMessageNumber());
                        msgSubject = javaCast("string", jMsg.getSubject() ?: "");
                        msgDate    = jMsg.getSentDate();
                        msgFrom    = javaCast("string", jMsg.getFrom()[1].toString() ?: "");
                    } else {
                        msgUID     = qMessages.uid[msgIdx];
                        msgSubject = qMessages.subject[msgIdx];
                        msgDate    = qMessages.date[msgIdx];
                        msgFrom    = qMessages.from[msgIdx];
                    }

                    logLine("Processing msg ##msgIdx: subject=#msgSubject#");

                    // Retrieve full message for parsing
                    if (useJavaMail) {
                        // Pass the JavaMail Message object; parsers will handle it
                        msgBody       = "";
                        attachments   = [];
                        contentType   = javaCast("string", jMsg.getContentType() ?: "");
                        msgMessageId  = javaCast("string", jMsg.getHeader("Message-ID")[1] ?: createUUID());

                        // Walk MIME parts to collect attachments
                        content = jMsg.getContent();
                        if (isInstanceOf(content, "javax.mail.internet.MimeMultipart") OR isInstanceOf(content, "javax.mail.Multipart")) {
                            for (partIdx = 0; partIdx LT content.getCount(); partIdx++) {
                                part = content.getBodyPart(partIdx);
                                partDisp = javaCast("string", part.getDisposition() ?: "");
                                partCT   = javaCast("string", part.getContentType() ?: "");
                                if (partDisp EQ "ATTACHMENT" OR reFindNoCase("(application/zip|application/gzip|application/x-gzip|application/octet-stream|text/xml|application/xml)", partCT)) {
                                    partName = javaCast("string", part.getFileName() ?: "attachment_#partIdx#");
                                    partIS   = part.getInputStream();
                                    // Read stream to byte array
                                    baos = createObject("java", "java.io.ByteArrayOutputStream").init();
                                    buf  = createObject("java", "java.lang.reflect.Array").newInstance(
                                        createObject("java", "java.lang.Byte").TYPE, javaCast("int", 8192)
                                    );
                                    bytesRead = partIS.read(buf);
                                    while (bytesRead GT 0) {
                                        baos.write(buf, javaCast("int", 0), javaCast("int", bytesRead));
                                        bytesRead = partIS.read(buf);
                                    }
                                    partIS.close();
                                    arrayAppend(attachments, { name: partName, bytes: baos.toByteArray() });
                                } else if (partCT CONTAINS "text/plain" OR partCT CONTAINS "multipart/report") {
                                    try { msgBody &= part.getContent(); } catch(any ignored) {}
                                }
                            }
                        } else if (isSimpleValue(content)) {
                            msgBody = javaCast("string", content);
                        }

                    } else {
                        // cfImap getMessageBody
                        cfimap(
                            action     = "getMessageBody",
                            server     = acct.host,
                            port       = acct.port,
                            username   = acct.username,
                            password   = imapPassword,
                            secure     = (acct.use_ssl ? true : false),
                            folder     = mailbox,
                            uid        = msgUID,
                            name       = "qMsgBody"
                        );
                        msgBody      = qMsgBody.body;
                        contentType  = qMsgBody.contentType;
                        msgMessageId = qMsgBody.messageId ?: createUUID();
                        // cfImap saves attachments to a temp path automatically via getAttachments
                        attachments = [];
                        cfimap(
                            action          = "getAttachments",
                            server          = acct.host,
                            port            = acct.port,
                            username        = acct.username,
                            password        = imapPassword,
                            secure          = (acct.use_ssl ? true : false),
                            folder          = mailbox,
                            uid             = msgUID,
                            attachmentPath  = getTempDirectory(),
                            name            = "qAttach"
                        );
                        if (qAttach.recordCount) {
                            for (attRow in qAttach) {
                                if (fileExists(attRow.file)) {
                                    attachments.append({ name: attRow.fileName, file: attRow.file });
                                }
                            }
                        }
                    }

                    // ------------------------------------------------
                    // Deduplicate by Message-ID
                    // ------------------------------------------------
                    cleanMsgId = reReplace(msgMessageId, "[<>\s]", "", "ALL");
                    qDupe = queryExecute(
                        "SELECT id FROM report WHERE message_id = ? LIMIT 1",
                        [{ value: cleanMsgId, cfsqltype: "cf_sql_varchar" }],
                        { datasource: application.db.dsn }
                    );
                    if (qDupe.recordCount) {
                        logLine("  Skipping duplicate message_id=#cleanMsgId#");
                        totalSkip++;
                        // Still mark as read so we don't keep seeing it
                        if (application.poller.markAsRead) {
                            if (useJavaMail) {
                                jMsg.setFlag(createObject("java","javax.mail.Flags$Flag").SEEN, true);
                            } else {
                                try { cfimap(action="markRead", server=acct.host, port=acct.port, username=acct.username, password=imapPassword, secure=(acct.use_ssl?true:false), folder=mailbox, uid=msgUID); } catch(any e2) {}
                            }
                        }
                        continue;
                    }

                    // ------------------------------------------------
                    // Route: RUF forensic vs RUA aggregate
                    // ------------------------------------------------
                    isRUF = false;
                    if (reFindNoCase("multipart/report", contentType) AND reFindNoCase("report-type=feedback-report", contentType)) {
                        isRUF = true;
                    } else if (reFindNoCase("feedback-report", msgBody)) {
                        isRUF = true;
                    }

                    if (isRUF) {
                        logLine("  -> RUF (forensic) message");
                        include "/poller/parse_ruf.cfm";
                    } else {
                        logLine("  -> RUA (aggregate) message");
                        include "/poller/parse_rua.cfm";
                    }

                    // ------------------------------------------------
                    // Mark as read
                    // ------------------------------------------------
                    if (application.poller.markAsRead) {
                        if (useJavaMail) {
                            jMsg.setFlag(createObject("java","javax.mail.Flags$Flag").SEEN, true);
                        } else {
                            try { cfimap(action="markRead", server=acct.host, port=acct.port, username=acct.username, password=imapPassword, secure=(acct.use_ssl?true:false), folder=mailbox, uid=msgUID); } catch(any ignored) {}
                        }
                    }

                    totalNew++;

                } catch(any msgErr) {
                    logLine("  ERROR on msg ##msgIdx: #msgErr.message# | #msgErr.detail#", "ERROR");
                    totalError++;
                }

            } // end message loop

            // Close JavaMail resources
            if (useJavaMail) {
                try { imapFolder.close(false); } catch(any e) {}
                try { imapStore.close();        } catch(any e) {}
            }

            // Update last_polled
            queryExecute(
                "UPDATE imap_accounts SET last_polled = NOW() WHERE id = ?",
                [{ value: acct.id, cfsqltype: "cf_sql_integer" }],
                { datasource: application.db.dsn }
            );

        } catch(any acctErr) {
            logLine("ACCOUNT ERROR (#acct.account_label#): #acctErr.message# | #acctErr.detail#", "ERROR");
            totalError++;
        }

    } // end account loop

    elapsed = dateDiff("s", pollStart, now());
    logLine("=== Poll complete: #totalNew# new, #totalSkip# skipped, #totalError# errors — #elapsed#s ===");

    // Write a brief summary to the poller_runs table for the status page
    queryExecute(
        "INSERT INTO poller_runs (run_at, new_reports, skipped, errors, elapsed_sec, log_text)
         VALUES (NOW(), ?, ?, ?, ?, ?)",
        [
            { value: totalNew,                                cfsqltype: "cf_sql_integer" },
            { value: totalSkip,                               cfsqltype: "cf_sql_integer" },
            { value: totalError,                              cfsqltype: "cf_sql_integer" },
            { value: elapsed,                                 cfsqltype: "cf_sql_integer" },
            { value: left(arrayToList(pollLog, chr(10)), 8000), cfsqltype: "cf_sql_clob" }
        ],
        { datasource: application.db.dsn }
    );
</cfscript>
<cfoutput>OK: #totalNew# new / #totalSkip# skipped / #totalError# errors</cfoutput>
