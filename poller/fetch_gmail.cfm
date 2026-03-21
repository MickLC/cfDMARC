<!--- poller/fetch_gmail.cfm
      Gmail OAuth2 fetch path for poll.cfm.
      Included by poll.cfm when acct.auth_type EQ "oauth2".

      Expects (from poll.cfm scope):
        acct        — current imap_accounts query row
        logLine()   — logging function
        totalNew    — running counter (mutated)
        totalSkip   — running counter (mutated)
        totalError  — running counter (mutated)

      For each unprocessed message this file:
        1. Ensures a valid access token (refreshes if needed)
        2. Lists message IDs via Gmail API
        3. Deduplicates via Message-ID header before fetching bodies
        4. Populates attachments[], cleanMsgId, msgSubject, contentType
        5. Includes parse_rua.cfm or parse_ruf.cfm exactly as the doveadm path does
        6. Marks messages read and/or deletes them per poller settings

      Gmail API base: https://gmail.googleapis.com/gmail/v1/users/me

      Token storage columns (imap_accounts):
        oauth_access_token   — AES-encrypted via encryptValue()
        oauth_refresh_token  — AES-encrypted via encryptValue()
        oauth_token_expiry   — TIMESTAMP (local server time)
        oauth_client_id      — plaintext Google client ID
        oauth_client_secret  — AES-encrypted Google client secret
--->
<cfscript>

    // -----------------------------------------------------------------------
    // gmailApiGet(accessToken, path, params)
    //
    // GET https://gmail.googleapis.com/gmail/v1/users/me/{path}
    // Returns deserialized JSON struct, or throws on HTTP error.
    // -----------------------------------------------------------------------
    function gmailApiGet(
        required string accessToken,
        required string apiPath,
        struct  params = {}
    ) {
        var url = "https://gmail.googleapis.com/gmail/v1/users/me/" & arguments.apiPath;
        cfhttp(
            url     = url,
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
    // gmailApiPost(url, formFields)
    //
    // POST to an arbitrary URL (used for token refresh only).
    // Returns deserialized JSON struct.
    // -----------------------------------------------------------------------
    function gmailApiPost(required string postUrl, required struct fields) {
        cfhttp(url=arguments.postUrl, method="POST", result="gmailPostResp", timeout=30) {
            for (var k in arguments.fields) {
                cfhttpparam(type="formfield", name=k, value=arguments.fields[k]);
            }
        }
        if (NOT isJSON(gmailPostResp.fileContent)) {
            throw(type="GmailAPI",
                  message="Non-JSON response from token endpoint",
                  detail=left(gmailPostResp.fileContent, 200));
        }
        return deserializeJSON(gmailPostResp.fileContent);
    }

    // -----------------------------------------------------------------------
    // refreshGmailToken(acctId, refreshToken, clientId, clientSecret)
    //
    // Exchanges a refresh token for a new access token and writes it back
    // to imap_accounts.  Returns the new plaintext access token.
    // -----------------------------------------------------------------------
    function refreshGmailToken(
        required numeric acctId,
        required string  refreshToken,
        required string  clientId,
        required string  clientSecret
    ) {
        var resp = gmailApiPost(
            "https://oauth2.googleapis.com/token",
            {
                grant_type    : "refresh_token",
                refresh_token : arguments.refreshToken,
                client_id     : arguments.clientId,
                client_secret : arguments.clientSecret
            }
        );

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
    // getValidAccessToken(acct)
    //
    // Returns a live access token for the account, refreshing if the stored
    // token is absent, expired, or within 5 minutes of expiry.
    // -----------------------------------------------------------------------
    function getValidAccessToken(required struct acctRow) {
        var needRefresh = false;

        if (NOT len(trim(acctRow.oauth_access_token))) {
            needRefresh = true;
        } else if (NOT isDate(acctRow.oauth_token_expiry)) {
            needRefresh = true;
        } else {
            // Refresh if expiry is within 5 minutes
            var secsRemaining = dateDiff("s", now(), acctRow.oauth_token_expiry);
            if (secsRemaining LT 300) needRefresh = true;
        }

        if (needRefresh) {
            if (NOT len(trim(acctRow.oauth_refresh_token)))
                throw(type="GmailAPI", message="No refresh token stored — re-authorize the account via Admin > Accounts");

            logLine("  Gmail: access token expired/missing — refreshing");
            var rt       = decryptValue(acctRow.oauth_refresh_token);
            var cs       = decryptValue(acctRow.oauth_client_secret);
            var ci       = acctRow.oauth_client_id;
            return refreshGmailToken(acctRow.id, rt, ci, cs);
        }

        return decryptValue(acctRow.oauth_access_token);
    }

    // -----------------------------------------------------------------------
    // b64urlDecode(str)
    //
    // Gmail API returns attachment data as base64url (uses - and _ instead
    // of + and /).  Java's Base64.getDecoder() handles standard base64 only;
    // use getMimeDecoder() which also handles URL-safe alphabet.
    // -----------------------------------------------------------------------
    function b64urlDecode(required string encoded) {
        // Translate URL-safe alphabet to standard base64
        var std = arguments.encoded
            .replace("-", "+", "all")
            .replace("_", "/", "all");
        // Re-pad if necessary
        var pad = len(std) mod 4;
        if (pad EQ 2) std &= "==";
        else if (pad EQ 3) std &= "=";
        var clean = reReplace(std, "\s+", "", "ALL");
        return createObject("java", "java.util.Base64").getDecoder().decode(clean);
    }

    // -----------------------------------------------------------------------
    // extractHeaderValue(headers, name)
    //
    // Gmail API returns headers as array of {name, value} structs.
    // Returns first matching value (case-insensitive), or empty string.
    // -----------------------------------------------------------------------
    function extractHeaderValue(required array headers, required string name) {
        for (var h in arguments.headers) {
            if (lCase(h.name) EQ lCase(arguments.name))
                return trim(h.value);
        }
        return "";
    }

    // -----------------------------------------------------------------------
    // findAttachmentParts(parts, msgId, accessToken)
    //
    // Recursively walks a Gmail message payload parts[] tree.
    // Returns array of byte arrays for any ZIP/GZ/XML/octet-stream parts.
    // Fetches large attachments by attachmentId if body.data is absent.
    // -----------------------------------------------------------------------
    function findAttachmentParts(
        required array  parts,
        required string gmailMsgId,
        required string accessToken
    ) {
        var found = [];

        for (var part in arguments.parts) {
            var mimeType = lCase(part.mimeType ?: "");
            var filename = "";
            if (structKeyExists(part, "filename")) filename = lCase(trim(part.filename));

            // Recurse into multipart containers
            if (left(mimeType, 10) EQ "multipart/") {
                if (structKeyExists(part, "parts") AND isArray(part.parts) AND arrayLen(part.parts)) {
                    var nested = findAttachmentParts(part.parts, arguments.gmailMsgId, arguments.accessToken);
                    for (var nb in nested) arrayAppend(found, nb);
                }
                continue;
            }

            // Is this a DMARC attachment?
            var isDmarc = false;
            if (reFindNoCase("application/(zip|gzip|x-zip|x-zip-compressed|x-gzip|octet-stream|xml)", mimeType)) isDmarc = true;
            if (reFindNoCase("\.xml(\.gz|\.zip)?$", filename)) isDmarc = true;
            if (reFindNoCase("\.(gz|zip|xml)$", filename)) isDmarc = true;

            if (NOT isDmarc) continue;

            var bodyBytes = javaCast("null", "");

            try {
                if (structKeyExists(part, "body")) {
                    var body = part.body;

                    // Inline data
                    if (structKeyExists(body, "data") AND len(body.data)) {
                        bodyBytes = b64urlDecode(body.data);

                    // Large attachment — fetch by attachmentId
                    } else if (structKeyExists(body, "attachmentId") AND len(body.attachmentId)) {
                        var attData = gmailApiGet(
                            arguments.accessToken,
                            "messages/#arguments.gmailMsgId#/attachments/#body.attachmentId#"
                        );
                        if (structKeyExists(attData, "data") AND len(attData.data))
                            bodyBytes = b64urlDecode(attData.data);
                    }
                }
            } catch(any partErr) {
                logLine("  Gmail: attachment decode error msg=#arguments.gmailMsgId#: #partErr.message#", "WARN");
            }

            if (NOT isNull(bodyBytes) AND arrayLen(bodyBytes) GT 4)
                arrayAppend(found, bodyBytes);
        }

        return found;
    }

    // -----------------------------------------------------------------------
    // markGmailMessage(accessToken, gmailMsgId, markRead, deleteMsg)
    //
    // Applies disposition to a Gmail message after successful processing.
    // markRead  — removes UNREAD label
    // deleteMsg — moves to TRASH (Gmail doesn't hard-delete via API)
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
                // TRASH is the API equivalent of delete for Gmail
                cfhttp(
                    url     = "https://gmail.googleapis.com/gmail/v1/users/me/messages/#arguments.gmailMsgId#/trash",
                    method  = "POST",
                    result  = "trashResp",
                    timeout = 15
                ) {
                    cfhttpparam(type="header", name="Authorization",  value="Bearer #arguments.accessToken#");
                    cfhttpparam(type="header", name="Content-Length", value="0");
                }
            } else if (arguments.markRead) {
                // Remove UNREAD label
                var modBody = serializeJSON({ removeLabelIds: ["UNREAD"] });
                cfhttp(
                    url     = "https://gmail.googleapis.com/gmail/v1/users/me/messages/#arguments.gmailMsgId#/modify",
                    method  = "POST",
                    result  = "modResp",
                    timeout = 15
                ) {
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
    // Replaces the doveadm path for this account.
    // =======================================================================

    // Load full OAuth2 token columns (poll.cfm's main query omits them for brevity)
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
        logLine("  Gmail: account id=#acct.id# not found — skipping", "WARN");
    } else {

        gmailAcct = {
            id                  : qGmailAcct.id,
            label               : qGmailAcct.label,
            username            : qGmailAcct.username,
            oauth_client_id     : qGmailAcct.oauth_client_id,
            oauth_client_secret : qGmailAcct.oauth_client_secret,
            oauth_access_token  : qGmailAcct.oauth_access_token,
            oauth_refresh_token : qGmailAcct.oauth_refresh_token,
            oauth_token_expiry  : qGmailAcct.oauth_token_expiry
        };

        try {

            // Step 1: get a live access token
            gmailToken = getValidAccessToken(gmailAcct);

            // Step 2: list unread messages in INBOX (batch-limited)
            // q=in:inbox is:unread scopes to what we care about.
            // If markAsRead=false we'll see the same messages repeatedly —
            // deduplication via Message-ID in the DB handles that safely.
            gmailListParams = {
                q          : "in:inbox is:unread",
                maxResults : application.poller.batchSize
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

                        // Step 3: fetch full message (headers + payload)
                        gmailMsg = gmailApiGet(
                            gmailToken,
                            "messages/#gmailMsgId#",
                            { format: "full" }
                        );

                        gmailPayload = gmailMsg.payload ?: {};
                        gmailHeaders = structKeyExists(gmailPayload, "headers") ? gmailPayload.headers : [];

                        // Extract Message-ID for deduplication
                        rawMsgId    = extractHeaderValue(gmailHeaders, "message-id");
                        cleanMsgId  = reReplace(trim(rawMsgId), "[<>\s]", "", "ALL");
                        if (NOT len(cleanMsgId)) cleanMsgId = "gmail-" & gmailMsgId;

                        msgSubject  = extractHeaderValue(gmailHeaders, "subject");
                        contentType = extractHeaderValue(gmailHeaders, "content-type");

                        // Step 4: deduplicate
                        qDupe = queryExecute(
                            "SELECT id FROM report WHERE message_id=? LIMIT 1",
                            [{ value: cleanMsgId, cfsqltype: "cf_sql_varchar" }],
                            { datasource: application.db.dsn }
                        );

                        if (qDupe.recordCount) {
                            logLine("  Gmail: #cleanMsgId# already in DB — skipping");
                            gmailSkip++;
                            totalSkip++;
                            markGmailMessage(gmailToken, gmailMsgId,
                                application.poller.markAsRead,
                                structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);
                            continue;
                        }

                        // Step 5: collect attachment bytes from payload tree
                        attachments = [];

                        // Top-level payload may itself be an attachment (unlikely for email
                        // but handle for completeness) — or the parts array has what we need.
                        if (structKeyExists(gmailPayload, "parts") AND isArray(gmailPayload.parts) AND arrayLen(gmailPayload.parts)) {
                            var rawBytesList = findAttachmentParts(gmailPayload.parts, gmailMsgId, gmailToken);
                            for (var rb in rawBytesList) {
                                arrayAppend(attachments, { name: "report", bytes: rb });
                            }
                        } else if (structKeyExists(gmailPayload, "body") AND structKeyExists(gmailPayload.body, "data") AND len(gmailPayload.body.data)) {
                            // Single-part message
                            var topMime = lCase(gmailPayload.mimeType ?: "");
                            if (reFindNoCase("application/(zip|gzip|x-zip|x-gzip|octet-stream|xml)", topMime)
                                OR reFindNoCase("\.xml|\.gz|\.zip", lCase(gmailPayload.filename ?: ""))) {
                                var topBytes = b64urlDecode(gmailPayload.body.data);
                                if (NOT isNull(topBytes) AND arrayLen(topBytes) GT 4)
                                    arrayAppend(attachments, { name: "report", bytes: topBytes });
                            }
                        }

                        if (NOT arrayLen(attachments)) {
                            logLine("  Gmail: no attachment bytes for msg=#gmailMsgId# sub=#left(msgSubject,60)#", "WARN");
                            gmailSkip++;
                            totalSkip++;
                            // Still dispose — it's not a DMARC message
                            markGmailMessage(gmailToken, gmailMsgId,
                                application.poller.markAsRead,
                                structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);
                            continue;
                        }

                        // Step 6: detect RUF vs RUA and parse
                        // Gmail strips raw MIME so we use the content-type header.
                        isRUF = reFindNoCase("multipart/report", contentType)
                                AND reFindNoCase("report-type=feedback-report", contentType);

                        if (isRUF) {
                            logLine("  Gmail: msg=#gmailMsgId# -> RUF");
                            include "/poller/parse_ruf.cfm";
                        } else {
                            logLine("  Gmail: msg=#gmailMsgId# -> RUA");
                            include "/poller/parse_rua.cfm";
                        }

                        // Step 7: dispose only after confirmed parse
                        markGmailMessage(gmailToken, gmailMsgId,
                            application.poller.markAsRead,
                            structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);

                        gmailNew++;
                        totalNew++;

                    } catch(any msgErr) {
                        logLine("  Gmail ERROR msg=#gmailMsgId#: #msgErr.message# | #msgErr.detail#", "ERROR");
                        gmailError++;
                        totalError++;
                        // No dispose on error — leave message intact
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
