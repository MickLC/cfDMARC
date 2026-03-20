<!--- poller/poll.cfm
      DMARC report poller entry point for cfschedule.
      Localhost access only.
--->
<cfinclude template="/includes/functions.cfm">

<cfscript>
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
        cflog(file="dmarc_poller", text="[#arguments.level#] #arguments.msg#",
              type=(arguments.level EQ "ERROR" ? "error" : "information"));
    }

    logLine("=== Poll run started ===");

    qAccounts = queryExecute(
        "SELECT id, label, host, port, username,
                password, auth_type,
                oauth_access_token, oauth_refresh_token,
                oauth_client_id, oauth_client_secret,
                oauth_token_expiry, use_ssl, mailbox, last_polled
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
                    logLine("Refreshing access token");
                    refreshToken = decryptValue(acct.oauth_refresh_token);
                    clientId     = acct.oauth_client_id;
                    clientSecret = decryptValue(acct.oauth_client_secret);

                    if (NOT len(refreshToken) OR NOT len(clientId) OR NOT len(clientSecret)) {
                        logLine("Missing OAuth2 credentials for #acct.label# — skipping", "ERROR");
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
                logLine("Empty credential for #acct.label# — skipping", "ERROR");
                totalError++;
                continue;
            }

            mailbox = len(trim(acct.mailbox)) ? trim(acct.mailbox) : "INBOX";

            if (acct.auth_type EQ "oauth2") {

                xoauth2Raw   = "user=#acct.username#" & chr(1) & "auth=Bearer #imapPassword#" & chr(1) & chr(1);
                xoauth2Token = toBase64(xoauth2Raw);

                props = createObject("java","java.util.Properties").init();
                props.setProperty("mail.store.protocol",         "imaps");
                props.setProperty("mail.imaps.host",             acct.host);
                props.setProperty("mail.imaps.port",             javaCast("string",acct.port));
                props.setProperty("mail.imaps.ssl.enable",       "true");
                props.setProperty("mail.imaps.auth.mechanisms",  "XOAUTH2");
                props.setProperty("mail.imaps.sasl.enable",      "true");
                props.setProperty("mail.imaps.sasl.mechanisms",  "XOAUTH2");

                jSession    = createObject("java","javax.mail.Session").getInstance(props);
                imapStore   = jSession.getStore("imaps");
                imapStore.connect(acct.host, acct.username, xoauth2Token);
                imapFolder  = imapStore.getFolder(mailbox);
                imapFolder.open(createObject("java","javax.mail.Folder").READ_WRITE);
                flagSeen    = createObject("java","javax.mail.Flags$Flag");
                searchTerm  = createObject("java","javax.mail.search.FlagTerm").init(
                    createObject("java","javax.mail.Flags").init(flagSeen.SEEN),
                    javaCast("boolean",false)
                );
                jMessages   = imapFolder.search(searchTerm);
                useJavaMail = true;
                msgCount    = arrayLen(jMessages);

            } else {

                cfimap(
                    action      = "getHeaderList",
                    server      = acct.host,
                    port        = acct.port,
                    username    = acct.username,
                    password    = imapPassword,
                    secure      = (acct.use_ssl ? true : false),
                    folder      = mailbox,
                    messageType = "UNSEEN",
                    name        = "qMessages",
                    maxRows     = application.poller.batchSize
                );
                useJavaMail = false;
                msgCount    = qMessages.recordCount;
            }

            logLine("#msgCount# unread message(s)");

            for (msgIdx = 1; msgIdx LTE msgCount; msgIdx++) {

                try {
                    if (useJavaMail) {
                        jMsg       = jMessages[msgIdx - 1];
                        msgUID     = javaCast("string", jMsg.getMessageNumber());
                        msgSubject = javaCast("string", jMsg.getSubject() ?: "");
                        msgFrom    = javaCast("string", jMsg.getFrom()[1].toString() ?: "");
                        contentType  = javaCast("string", jMsg.getContentType() ?: "");
                        msgMessageId = javaCast("string", jMsg.getHeader("Message-ID")[1] ?: createUUID());
                        msgBody      = "";
                        attachments  = [];
                        content = jMsg.getContent();
                        if (isInstanceOf(content,"javax.mail.Multipart")) {
                            for (pIdx = 0; pIdx LT content.getCount(); pIdx++) {
                                part     = content.getBodyPart(pIdx);
                                partDisp = javaCast("string", part.getDisposition() ?: "");
                                partCT   = javaCast("string", part.getContentType() ?: "");
                                if (partDisp EQ "ATTACHMENT"
                                    OR reFindNoCase("(application/zip|application/gzip|application/x-gzip|application/octet-stream|text/xml|application/xml)",partCT)) {
                                    partName = javaCast("string", part.getFileName() ?: "att_#pIdx#");
                                    partIS   = part.getInputStream();
                                    baos = createObject("java","java.io.ByteArrayOutputStream").init();
                                    buf  = createObject("java","java.lang.reflect.Array").newInstance(
                                        createObject("java","java.lang.Byte").TYPE, javaCast("int",8192));
                                    bytesRead = partIS.read(buf);
                                    while (bytesRead GT 0) {
                                        baos.write(buf, javaCast("int",0), javaCast("int",bytesRead));
                                        bytesRead = partIS.read(buf);
                                    }
                                    partIS.close();
                                    arrayAppend(attachments, {name:partName, bytes:baos.toByteArray()});
                                } else {
                                    try { msgBody &= part.getContent(); } catch(any ignored) {}
                                }
                            }
                        } else if (isSimpleValue(content)) {
                            msgBody = javaCast("string", content);
                        }

                    } else {
                        cfimap(action="getMessageBody", server=acct.host, port=acct.port,
                               username=acct.username, password=imapPassword,
                               secure=(acct.use_ssl?true:false), folder=mailbox,
                               uid=msgUID, name="qMsgBody");
                        msgSubject   = qMessages.subject[msgIdx];
                        msgFrom      = qMessages.from[msgIdx];
                        msgUID       = qMessages.uid[msgIdx];
                        msgBody      = qMsgBody.body;
                        contentType  = qMsgBody.contentType;
                        msgMessageId = qMsgBody.messageId ?: createUUID();
                        attachments  = [];
                        cfimap(action="getAttachments", server=acct.host, port=acct.port,
                               username=acct.username, password=imapPassword,
                               secure=(acct.use_ssl?true:false), folder=mailbox,
                               uid=msgUID, attachmentPath=getTempDirectory(), name="qAttach");
                        if (qAttach.recordCount) {
                            for (attRow in qAttach) {
                                if (fileExists(attRow.file))
                                    attachments.append({name:attRow.fileName, file:attRow.file});
                            }
                        }
                    }

                    cleanMsgId = reReplace(msgMessageId, "[<>\s]", "", "ALL");
                    qDupe = queryExecute("SELECT id FROM report WHERE message_id=? LIMIT 1",
                        [{value:cleanMsgId, cfsqltype:"cf_sql_varchar"}],
                        {datasource:application.db.dsn});

                    if (qDupe.recordCount) {
                        logLine("  Duplicate message_id=#cleanMsgId# — skipping");
                        totalSkip++;
                        if (application.poller.markAsRead) {
                            if (useJavaMail)
                                jMsg.setFlag(createObject("java","javax.mail.Flags$Flag").SEEN, true);
                            else
                                try { cfimap(action="markRead",server=acct.host,port=acct.port,username=acct.username,password=imapPassword,secure=(acct.use_ssl?true:false),folder=mailbox,uid=msgUID); } catch(any e2) {}
                        }
                        continue;
                    }

                    isRUF = reFindNoCase("multipart/report",contentType)
                            AND reFindNoCase("report-type=feedback-report",contentType);
                    if (NOT isRUF) isRUF = reFindNoCase("feedback-report", msgBody);

                    if (isRUF) {
                        logLine("  -> RUF"); include "/poller/parse_ruf.cfm";
                    } else {
                        logLine("  -> RUA"); include "/poller/parse_rua.cfm";
                    }

                    if (application.poller.markAsRead) {
                        if (useJavaMail)
                            jMsg.setFlag(createObject("java","javax.mail.Flags$Flag").SEEN, true);
                        else
                            try { cfimap(action="markRead",server=acct.host,port=acct.port,username=acct.username,password=imapPassword,secure=(acct.use_ssl?true:false),folder=mailbox,uid=msgUID); } catch(any ignored) {}
                    }

                    totalNew++;

                } catch(any msgErr) {
                    logLine("  ERROR msg ##msgIdx: #msgErr.message#", "ERROR");
                    totalError++;
                }
            }

            if (useJavaMail) {
                try { imapFolder.close(false); } catch(any e) {}
                try { imapStore.close();        } catch(any e) {}
            }

            queryExecute(
                "UPDATE imap_accounts SET last_polled=NOW(), last_status=? WHERE id=?",
                [
                    {value:"OK: #msgCount# checked, #totalNew# new", cfsqltype:"cf_sql_varchar"},
                    {value:acct.id, cfsqltype:"cf_sql_integer"}
                ],
                {datasource:application.db.dsn}
            );

        } catch(any acctErr) {
            logLine("ACCOUNT ERROR (#acct.label#): #acctErr.message#", "ERROR");
            totalError++;
            queryExecute("UPDATE imap_accounts SET last_status=? WHERE id=?",
                [{value:"Error: " & left(acctErr.message,200), cfsqltype:"cf_sql_varchar"},{value:acct.id,cfsqltype:"cf_sql_integer"}],
                {datasource:application.db.dsn});
        }
    }

    elapsed = dateDiff("s", pollStart, now());
    logLine("=== Done: #totalNew# new, #totalSkip# skipped, #totalError# errors, #elapsed#s ===");

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
</cfscript>
<cfoutput>OK: #totalNew# new / #totalSkip# skipped / #totalError# errors</cfoutput>
