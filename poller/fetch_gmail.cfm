<!--- poller/fetch_gmail.cfm
      Gmail OAuth2 fetch path for poll.cfm.
      Included by poll.cfm when acct.auth_type EQ "oauth2".

      Expects (from poll.cfm scope):
        acct        - current imap_accounts query row
        logLine()   - logging function
        totalNew    - running counter (mutated)
        totalSkip   - running counter (mutated)
        totalError  - running counter (mutated)

      RUF vs RUA handling:
        RUA: ZIP/GZ/XML attachment bytes extracted into `attachments` array.
        RUF: No attachment. Report is the message body (multipart/report or
             plain-text forensic notification). msgBody assembled from payload
             parts via extractGmailRufBody().

      RUF detection (isRUF) covers three formats observed in the wild:
        1. Standard ARF: Content-Type multipart/report; report-type=feedback-report
        2. Plain-text forensic notification: subject matches
           "DMARC Forensic Report" or "DMARC Failure Report" (antispamcloud,
           Validity/ReturnPath, etc.)
        3. Auto-submitted with forensic-report-like subject

      Lucee string-literal gotchas:
        - Do NOT embed literal " inside double-quoted CFML strings passed to
          regex functions. Lucee's lexer treats it as the string terminator
          even inside a character class [...]. Use chr(34) instead.
        - Do NOT use \s, \r, \n, \t in double-quoted CFML string literals.
          Lucee's string parser consumes the backslash. Use chr() or explicit
          character classes like [ \t] instead.
        - \\s (double-backslash) in a CFML string literal becomes \s in the
          string value, which the regex engine sees correctly as whitespace.
--->
<cfscript>

    // -----------------------------------------------------------------------
    // gmailApiGet(accessToken, apiPath, params)
    // -----------------------------------------------------------------------
    function gmailApiGet(
        required string accessToken,
        required string apiPath,
        struct  params = {}
    ) {
        var apiEndpoint = "https://gmail.googleapis.com/gmail/v1/users/me/" & arguments.apiPath;
        cfhttp(
            url     = apiEndpoint,
            method  = "GET",
            result  = "gmailGetResp",
            timeout = 30
        ) {
            cfhttpparam(type="header", name="Authorization", value="Bearer #arguments.accessToken#");
            for (var k in arguments.params) {
                cfhttpparam(type="url", name=k, value=arguments.params[k]);
            }
        }
        if (NOT isJSON(gmailGetResp.fileContent)) {
            throw(type="GmailAPI",
                  message="Non-JSON response from Gmail API",
                  detail="HTTP #gmailGetResp.responseHeader.Status_Code ?: '?'# path=#arguments.apiPath# body=#left(gmailGetResp.fileContent,200)#");
        }
        var data = deserializeJSON(gmailGetResp.fileContent);
        if (structKeyExists(data, "error")) {
            throw(type="GmailAPI",
                  message="Gmail API error: #data.error.message ?: 'unknown'#",
                  detail="code=#data.error.code ?: ''# path=#arguments.apiPath#");
        }
        return data;
    }

    // -----------------------------------------------------------------------
    // refreshGmailToken(acctId, refreshToken, clientId, clientSecret)
    // -----------------------------------------------------------------------
    function refreshGmailToken(
        required numeric acctId,
        required string  refreshToken,
        required string  clientId,
        required string  clientSecret
    ) {
        cfhttp(
            url     = "https://oauth2.googleapis.com/token",
            method  = "POST",
            result  = "refreshResp",
            timeout = 30
        ) {
            cfhttpparam(type="formfield", name="grant_type",    value="refresh_token");
            cfhttpparam(type="formfield", name="refresh_token", value=arguments.refreshToken);
            cfhttpparam(type="formfield", name="client_id",     value=arguments.clientId);
            cfhttpparam(type="formfield", name="client_secret", value=arguments.clientSecret);
        }

        if (NOT isJSON(refreshResp.fileContent)) {
            throw(type="GmailAPI",
                  message="Non-JSON response from token endpoint",
                  detail=left(refreshResp.fileContent, 200));
        }

        var resp = deserializeJSON(refreshResp.fileContent);

        if (NOT structKeyExists(resp, "access_token")) {
            var errMsg = structKeyExists(resp, "error_description") ? resp.error_description : serializeJSON(resp);
            throw(type="GmailAPI", message="Token refresh failed: #errMsg#");
        }

        var newToken  = resp.access_token;
        var expiresIn = val(resp.expires_in ?: 3599);
        var newExpiry = dateAdd("s", expiresIn, now());

        queryExecute(
            "UPDATE imap_accounts
             SET    oauth_access_token = ?,
                    oauth_token_expiry = ?
             WHERE  id = ?",
            [
                { value: encryptValue(newToken), cfsqltype: "cf_sql_varchar" },
                { value: newExpiry,              cfsqltype: "cf_sql_timestamp" },
                { value: arguments.acctId,       cfsqltype: "cf_sql_integer" }
            ],
            { datasource: application.db.dsn }
        );

        return newToken;
    }

    // -----------------------------------------------------------------------
    // getValidAccessToken(acctRow)
    // -----------------------------------------------------------------------
    function getValidAccessToken(required struct acctRow) {
        var needRefresh = false;

        if (NOT len(trim(acctRow.oauth_access_token))) {
            needRefresh = true;
        } else if (NOT isDate(acctRow.oauth_token_expiry)) {
            needRefresh = true;
        } else {
            var secsRemaining = dateDiff("s", now(), acctRow.oauth_token_expiry);
            if (secsRemaining LT 300) needRefresh = true;
        }

        if (needRefresh) {
            if (NOT len(trim(acctRow.oauth_refresh_token)))
                throw(type="GmailAPI", message="No refresh token stored - re-authorize the account via Admin > Accounts");

            logLine("  Gmail: access token expired/missing - refreshing");
            var rt = decryptValue(acctRow.oauth_refresh_token);
            var cs = decryptValue(acctRow.oauth_client_secret);
            var ci = acctRow.oauth_client_id;
            return refreshGmailToken(acctRow.id, rt, ci, cs);
        }

        return decryptValue(acctRow.oauth_access_token);
    }

    // -----------------------------------------------------------------------
    // b64urlDecode(encoded)
    //
    // Whitespace stripping uses chr() to avoid \s mangling in Lucee.
    // -----------------------------------------------------------------------
    function b64urlDecode(required string encoded) {
        var std = arguments.encoded
            .replace("-", "+", "all")
            .replace("_", "/", "all");
        var pad = len(std) mod 4;
        if (pad EQ 2) std &= "==";
        else if (pad EQ 3) std &= "=";
        // Strip whitespace using chr() - do NOT use \s in a string literal
        var clean = reReplace(std, "[ " & chr(9) & chr(13) & chr(10) & "]+", "", "ALL");
        return createObject("java", "java.util.Base64").getDecoder().decode(clean);
    }

    // -----------------------------------------------------------------------
    // b64urlDecodeToString(encoded)
    // -----------------------------------------------------------------------
    function b64urlDecodeToString(required string encoded) {
        var bytes = b64urlDecode(arguments.encoded);
        return createObject("java", "java.lang.String").init(bytes, "UTF-8");
    }

    // -----------------------------------------------------------------------
    // extractHeaderValue(headers, name)
    // -----------------------------------------------------------------------
    function extractHeaderValue(required array headers, required string name) {
        for (var h in arguments.headers) {
            if (lCase(h.name) EQ lCase(arguments.name))
                return trim(h.value);
        }
        return "";
    }

    // -----------------------------------------------------------------------
    // fetchAttachmentBytes(body, gmailMsgId, accessToken)
    // -----------------------------------------------------------------------
    function fetchAttachmentBytes(
        required struct body,
        required string gmailMsgId,
        required string accessToken
    ) {
        if (structKeyExists(arguments.body, "data") AND len(arguments.body.data)) {
            return b64urlDecode(arguments.body.data);
        }

        if (structKeyExists(arguments.body, "attachmentId") AND len(arguments.body.attachmentId)) {
            var attData = gmailApiGet(
                arguments.accessToken,
                "messages/#arguments.gmailMsgId#/attachments/#arguments.body.attachmentId#"
            );
            if (structKeyExists(attData, "data") AND len(attData.data))
                return b64urlDecode(attData.data);
            logLine("  Gmail: attachment fetch returned no data id=#arguments.body.attachmentId# msg=#arguments.gmailMsgId#", "WARN");
            return javaCast("null", "");
        }

        return javaCast("null", "");
    }

    // -----------------------------------------------------------------------
    // findAttachmentParts(parts, gmailMsgId, accessToken)
    // -----------------------------------------------------------------------
    function findAttachmentParts(
        required array  parts,
        required string gmailMsgId,
        required string accessToken
    ) {
        var found = [];

        for (var part in arguments.parts) {
            var mimeType = lCase(trim(part.mimeType ?: ""));
            var filename = lCase(trim(part.filename ?: ""));

            if (left(mimeType, 10) EQ "multipart/") {
                if (structKeyExists(part, "parts") AND isArray(part.parts) AND arrayLen(part.parts)) {
                    var nested = findAttachmentParts(part.parts, arguments.gmailMsgId, arguments.accessToken);
                    for (var nb in nested) arrayAppend(found, nb);
                }
                continue;
            }

            var isDmarc = false;
            if (reFindNoCase("application/(zip|gzip|x-zip|x-zip-compressed|x-gzip|octet-stream|xml)", mimeType)) isDmarc = true;
            if (reFindNoCase("\.(zip|gz|xml)$", filename)) isDmarc = true;

            if (NOT isDmarc) continue;

            var bodyBytes = javaCast("null", "");
            try {
                if (structKeyExists(part, "body"))
                    bodyBytes = fetchAttachmentBytes(part.body, arguments.gmailMsgId, arguments.accessToken);
                else
                    logLine("  Gmail: DMARC part has no body struct mime=#mimeType# file=#filename# msg=#arguments.gmailMsgId#", "WARN");
            } catch(any partErr) {
                logLine("  Gmail: attachment decode error msg=#arguments.gmailMsgId# mime=#mimeType#: #partErr.message#", "WARN");
            }

            if (NOT isNull(bodyBytes) AND arrayLen(bodyBytes) GT 4)
                arrayAppend(found, bodyBytes);
        }

        return found;
    }

    // -----------------------------------------------------------------------
    // extractGmailRufBody(payload)
    //
    // Reassembles MIME body text from a Gmail format=full payload for
    // parse_ruf.cfm. Handles three structures:
    //   1. multipart - walks parts[] tree, decoding each part
    //   2. single-part with body.data inline (e.g. text/plain forensic notify)
    //   3. single-part with body.attachmentId (rare but possible)
    // Each part is prefixed with its Content-Type line so parse_ruf.cfm's
    // regex searches for "Content-Type: message/feedback-report" still work.
    // -----------------------------------------------------------------------
    function extractGmailRufBody(required struct payload) {
        var sb = createObject("java", "java.lang.StringBuilder").init();

        function walkParts(required array parts) {
            for (var part in arguments.parts) {
                var mimeType = trim(part.mimeType ?: "");

                if (reFindNoCase("^multipart/", mimeType)) {
                    if (structKeyExists(part, "parts") AND isArray(part.parts) AND arrayLen(part.parts))
                        walkParts(part.parts);
                    continue;
                }

                // Emit Content-Type header so parse_ruf.cfm can locate parts
                sb.append("Content-Type: " & mimeType & chr(10));
                sb.append(chr(10));

                var partData = "";
                if (structKeyExists(part, "body") AND isStruct(part.body)) {
                    if (structKeyExists(part.body, "data") AND len(part.body.data)) {
                        try { partData = b64urlDecodeToString(part.body.data); } catch(any e) { partData = ""; }
                    } else if (structKeyExists(part.body, "attachmentId") AND len(part.body.attachmentId)) {
                        // Rare: body text stored as attachment - fetch it
                        try {
                            var attResp = gmailApiGet(gmailToken,
                                "messages/" & gmailMsgId & "/attachments/" & part.body.attachmentId);
                            if (structKeyExists(attResp, "data") AND len(attResp.data))
                                partData = b64urlDecodeToString(attResp.data);
                        } catch(any e) { partData = ""; }
                    }
                }
                sb.append(partData);
                sb.append(chr(10) & chr(10));
            }
        }

        if (structKeyExists(arguments.payload, "parts") AND isArray(arguments.payload.parts) AND arrayLen(arguments.payload.parts)) {
            // Multipart message: emit top-level Content-Type then walk parts
            var topMimeType = trim(arguments.payload.mimeType ?: "");
            if (len(topMimeType)) {
                sb.append("Content-Type: " & topMimeType & chr(10));
                sb.append(chr(10));
            }
            walkParts(arguments.payload.parts);
        } else if (structKeyExists(arguments.payload, "body") AND isStruct(arguments.payload.body)) {
            // Single-part message (e.g. plain-text forensic notification)
            var topMimeType = trim(arguments.payload.mimeType ?: "");
            if (len(topMimeType)) {
                sb.append("Content-Type: " & topMimeType & chr(10));
                sb.append(chr(10));
            }
            if (structKeyExists(arguments.payload.body, "data") AND len(arguments.payload.body.data)) {
                try { sb.append(b64urlDecodeToString(arguments.payload.body.data)); } catch(any e) {}
            }
        }

        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // markGmailMessage(accessToken, gmailMsgId, markRead, deleteMsg)
    // -----------------------------------------------------------------------
    function markGmailMessage(
        required string  accessToken,
        required string  gmailMsgId,
        required boolean markRead,
        required boolean deleteMsg
    ) {
        if (NOT arguments.markRead AND NOT arguments.deleteMsg) return;

        try {
            if (arguments.deleteMsg) {
                var trashEndpoint = "https://gmail.googleapis.com/gmail/v1/users/me/messages/#arguments.gmailMsgId#/trash";
                cfhttp(url=trashEndpoint, method="POST", result="trashResp", timeout=15) {
                    cfhttpparam(type="header", name="Authorization",  value="Bearer #arguments.accessToken#");
                    cfhttpparam(type="header", name="Content-Length", value="0");
                }
            } else if (arguments.markRead) {
                var modEndpoint = "https://gmail.googleapis.com/gmail/v1/users/me/messages/#arguments.gmailMsgId#/modify";
                // Hardcoded JSON - do NOT use serializeJSON(), Lucee uppercases keys.
                var modBody = '{"removeLabelIds":["UNREAD"]}';
                cfhttp(url=modEndpoint, method="POST", result="modResp", timeout=15) {
                    cfhttpparam(type="header", name="Authorization",  value="Bearer #arguments.accessToken#");
                    cfhttpparam(type="header", name="Content-Type",   value="application/json");
                    cfhttpparam(type="body",   value=modBody);
                }
            }
        } catch(any e) {
            logLine("  Gmail: dispose error msg=#arguments.gmailMsgId#: #e.message#", "WARN");
        }
    }

    // =======================================================================
    // Main Gmail fetch loop
    // =======================================================================

    qGmailAcct = queryExecute(
        "SELECT id, label, username, mailbox, active,
                auth_type, oauth_client_id, oauth_client_secret,
                oauth_access_token, oauth_refresh_token, oauth_token_expiry
         FROM   imap_accounts
         WHERE  id = ?",
        [{ value: acct.id, cfsqltype: "cf_sql_integer" }],
        { datasource: application.db.dsn }
    );

    if (NOT qGmailAcct.recordCount) {
        logLine("  Gmail: account id=#acct.id# not found - skipping", "WARN");
    } else {

        gmailAcct = {
            "id"                  : qGmailAcct.id,
            "label"               : qGmailAcct.label,
            "username"            : qGmailAcct.username,
            "oauth_client_id"     : qGmailAcct.oauth_client_id,
            "oauth_client_secret" : qGmailAcct.oauth_client_secret,
            "oauth_access_token"  : qGmailAcct.oauth_access_token,
            "oauth_refresh_token" : qGmailAcct.oauth_refresh_token,
            "oauth_token_expiry"  : qGmailAcct.oauth_token_expiry
        };

        try {

            gmailToken = getValidAccessToken(gmailAcct);

            gmailListParams = {
                "q"          : "is:unread -in:trash -in:spam",
                "maxResults" : application.poller.batchSize
            };

            gmailList = gmailApiGet(gmailToken, "messages", gmailListParams);

            if (NOT structKeyExists(gmailList, "messages") OR NOT arrayLen(gmailList.messages)) {
                logLine("  Gmail: no unread messages");
                queryExecute(
                    "UPDATE imap_accounts SET last_polled=NOW(), last_status=? WHERE id=?",
                    [
                        { value: "OK: 0 messages", cfsqltype: "cf_sql_varchar" },
                        { value: acct.id,          cfsqltype: "cf_sql_integer" }
                    ],
                    { datasource: application.db.dsn }
                );
            } else {

                gmailMessages = gmailList.messages;
                logLine("  Gmail: #arrayLen(gmailMessages)# unread message(s)");

                gmailNew   = 0;
                gmailSkip  = 0;
                gmailError = 0;

                for (gmailMsgRef in gmailMessages) {

                    gmailMsgId = gmailMsgRef.id;

                    try {

                        gmailMeta    = gmailApiGet(gmailToken, "messages/#gmailMsgId#", { "format": "metadata" });
                        metaHeaders  = structKeyExists(gmailMeta, "payload") AND structKeyExists(gmailMeta.payload, "headers")
                                       ? gmailMeta.payload.headers : [];

                        rawMsgId   = extractHeaderValue(metaHeaders, "message-id");
                        cleanMsgId = reReplace(trim(rawMsgId),
                                               "[<> " & chr(9) & chr(13) & chr(10) & "]+", "", "ALL");
                        if (NOT len(cleanMsgId)) cleanMsgId = "gmail-" & gmailMsgId;

                        qDupe = queryExecute(
                            "SELECT id FROM report WHERE message_id=? LIMIT 1",
                            [{ value: cleanMsgId, cfsqltype: "cf_sql_varchar" }],
                            { datasource: application.db.dsn }
                        );

                        if (qDupe.recordCount) {
                            logLine("  Gmail: #cleanMsgId# already in DB - skipping");
                            gmailSkip++;
                            totalSkip++;
                            markGmailMessage(gmailToken, gmailMsgId,
                                application.poller.markAsRead,
                                structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);
                            continue;
                        }

                        gmailMsg     = gmailApiGet(gmailToken, "messages/#gmailMsgId#", { "format": "full" });
                        gmailPayload = gmailMsg.payload ?: {};
                        gmailHeaders = structKeyExists(gmailPayload, "headers") ? gmailPayload.headers : [];

                        rawMsgId2  = extractHeaderValue(gmailHeaders, "message-id");
                        cleanMsgId = len(trim(rawMsgId2))
                                     ? reReplace(trim(rawMsgId2),
                                                 "[<> " & chr(9) & chr(13) & chr(10) & "]+", "", "ALL")
                                     : cleanMsgId;

                        msgSubject     = extractHeaderValue(gmailHeaders, "subject");
                        contentType    = extractHeaderValue(gmailHeaders, "content-type");
                        autoSubmitted  = extractHeaderValue(gmailHeaders, "auto-submitted");

                        qDupe = queryExecute(
                            "SELECT id FROM report WHERE message_id=? LIMIT 1",
                            [{ value: cleanMsgId, cfsqltype: "cf_sql_varchar" }],
                            { datasource: application.db.dsn }
                        );

                        if (qDupe.recordCount) {
                            logLine("  Gmail: #cleanMsgId# already in DB - skipping (full dedup)");
                            gmailSkip++;
                            totalSkip++;
                            markGmailMessage(gmailToken, gmailMsgId,
                                application.poller.markAsRead,
                                structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);
                            continue;
                        }

                        // -------------------------------------------------------
                        // RUF detection - three signals, any one is sufficient:
                        //
                        // 1. Standard ARF Content-Type:
                        //    multipart/report; report-type=feedback-report
                        //
                        // 2. Plain-text forensic notification subject
                        //    (antispamcloud, Validity/ReturnPath, and others):
                        //    Subject: DMARC Forensic Report for ...
                        //    Subject: DMARC Failure Report for ...
                        //    Subject: Re: DMARC Forensic/Failure Report ...
                        //
                        // 3. Auto-submitted header present AND subject contains
                        //    "DMARC" (catches edge cases from less common senders)
                        // -------------------------------------------------------
                        isRUF = false;

                        // Signal 1: standard ARF Content-Type
                        if (reFindNoCase("multipart/report", contentType)
                                AND reFindNoCase("report-type=feedback-report", contentType))
                            isRUF = true;

                        // Signal 2: forensic/failure report subject line
                        if (NOT isRUF AND reFindNoCase("DMARC (Forensic|Failure) Report", msgSubject))
                            isRUF = true;

                        // Signal 3: auto-submitted + DMARC in subject
                        if (NOT isRUF AND len(autoSubmitted) AND reFindNoCase("DMARC", msgSubject)
                                AND reFindNoCase("Report", msgSubject))
                            isRUF = true;

                        if (isRUF) {

                            msgBody = extractGmailRufBody(gmailPayload);

                            if (NOT len(trim(msgBody))) {
                                logLine("  Gmail: RUF msg=#gmailMsgId# has no decodable body - skipping", "WARN");
                                gmailSkip++;
                                totalSkip++;
                                markGmailMessage(gmailToken, gmailMsgId,
                                    application.poller.markAsRead,
                                    structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);
                                continue;
                            }

                            logLine("  Gmail: msg=#gmailMsgId# -> RUF (sub=#left(msgSubject,60)#)");
                            include "/poller/parse_ruf.cfm";

                        } else {

                            attachments  = [];
                            rawBytesList = [];
                            topMime      = lCase(gmailPayload.mimeType ?: "");
                            topFile      = lCase(gmailPayload.filename ?: "");

                            if (structKeyExists(gmailPayload, "parts") AND isArray(gmailPayload.parts) AND arrayLen(gmailPayload.parts)) {
                                rawBytesList = findAttachmentParts(gmailPayload.parts, gmailMsgId, gmailToken);
                                for (rb in rawBytesList) {
                                    arrayAppend(attachments, { name: "report", bytes: rb });
                                }

                            } else if (structKeyExists(gmailPayload, "body") AND isStruct(gmailPayload.body)) {
                                isDmarcTopLevel = false;
                                if (reFindNoCase("application/(zip|gzip|x-zip|x-gzip|octet-stream|xml)", topMime)) isDmarcTopLevel = true;
                                if (reFindNoCase("\.(zip|gz|xml)$", topFile)) isDmarcTopLevel = true;

                                if (isDmarcTopLevel) {
                                    topBytes = javaCast("null", "");
                                    try {
                                        topBytes = fetchAttachmentBytes(gmailPayload.body, gmailMsgId, gmailToken);
                                    } catch(any topErr) {
                                        logLine("  Gmail: top-level attachment fetch error msg=#gmailMsgId#: #topErr.message#", "WARN");
                                    }
                                    if (NOT isNull(topBytes) AND arrayLen(topBytes) GT 4)
                                        arrayAppend(attachments, { name: "report", bytes: topBytes });
                                } else {
                                    logLine("  Gmail: msg=#gmailMsgId# single-part non-DMARC mime type: #topMime#", "WARN");
                                }

                            } else {
                                logLine("  Gmail: msg=#gmailMsgId# unrecognised payload shape - mimeType=#topMime#", "WARN");
                            }

                            if (NOT arrayLen(attachments)) {
                                logLine("  Gmail: RUA msg=#gmailMsgId# no attachment bytes found sub=#left(msgSubject,60)# - skipping", "WARN");
                                gmailSkip++;
                                totalSkip++;
                                markGmailMessage(gmailToken, gmailMsgId,
                                    application.poller.markAsRead,
                                    structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);
                                continue;
                            }

                            logLine("  Gmail: msg=#gmailMsgId# -> RUA");
                            include "/poller/parse_rua.cfm";

                        }

                        markGmailMessage(gmailToken, gmailMsgId,
                            application.poller.markAsRead,
                            structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);

                        gmailNew++;
                        totalNew++;

                    } catch(any msgErr) {
                        logLine("  Gmail ERROR msg=#gmailMsgId#: #msgErr.message# | #msgErr.detail#", "ERROR");
                        gmailError++;
                        totalError++;
                    }

                } // end for gmailMessages

                queryExecute(
                    "UPDATE imap_accounts SET last_polled=NOW(), last_status=? WHERE id=?",
                    [
                        { value: "OK: #arrayLen(gmailMessages)# checked, #gmailNew# new", cfsqltype: "cf_sql_varchar" },
                        { value: acct.id, cfsqltype: "cf_sql_integer" }
                    ],
                    { datasource: application.db.dsn }
                );

            } // end if gmailList.messages

        } catch(any acctErr) {
            logLine("  Gmail ACCOUNT ERROR (#acct.label#): #acctErr.message# | #acctErr.detail#", "ERROR");
            totalError++;
            queryExecute(
                "UPDATE imap_accounts SET last_status=? WHERE id=?",
                [
                    { value: "Error: " & left(acctErr.message, 200), cfsqltype: "cf_sql_varchar" },
                    { value: acct.id, cfsqltype: "cf_sql_integer" }
                ],
                { datasource: application.db.dsn }
            );
        }

    } // end if qGmailAcct.recordCount

</cfscript>
