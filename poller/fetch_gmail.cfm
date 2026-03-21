<!--- poller/fetch_gmail.cfm
      Gmail OAuth2 fetch path for poll.cfm.
      Included by poll.cfm when acct.auth_type EQ "oauth2".

      Expects (from poll.cfm scope):
        acct        - current imap_accounts query row
        logLine()   - logging function
        totalNew    - running counter (mutated)
        totalSkip   - running counter (mutated)
        totalError  - running counter (mutated)

      For each unprocessed message this file:
        1. Ensures a valid access token (refreshes if needed)
        2. Lists message IDs via Gmail API
        3. Fetches metadata only (headers, no payload) for deduplication
        4. Skips already-seen messages cheaply - no full payload download
        5. Fetches full payload only for genuinely new messages
        6. Includes parse_rua.cfm or parse_ruf.cfm exactly as the doveadm path does
        7. Marks messages read and/or deletes them per poller settings

      Gmail API base: https://gmail.googleapis.com/gmail/v1/users/me

      Token storage columns (imap_accounts):
        oauth_access_token   - AES-encrypted via encryptValue()
        oauth_refresh_token  - AES-encrypted via encryptValue()
        oauth_token_expiry   - TIMESTAMP (local server time)
        oauth_client_id      - plaintext Google client ID
        oauth_client_secret  - AES-encrypted Google client secret

      Lucee gotchas observed in this file:
        - No var declarations at page scope (only inside functions)
        - Local variable named apiEndpoint (not url) to avoid URL scope collision
          inside cfhttp tag attributes
        - Unquoted struct keys with underscores get uppercased/mangled by Lucee;
          token refresh POST uses explicit cfhttpparam calls instead of a struct
        - Struct keys used as cfhttpparam names are quoted strings to be safe
        - serializeJSON() uppercases all struct keys, breaking camelCase JSON keys
          required by external APIs; use string literals for those payloads

      Gmail payload shapes observed in the wild:
        A) multipart/* - payload.parts[] array, attachments inside parts
        B) single-part with inline data - payload.body.data (base64url)
        C) single-part with large attachment - payload.body.attachmentId,
           payload.body.data is absent or empty (Google DMARC reports use this)
      All three shapes are handled in the full-fetch branch.
--->
<cfscript>

    // -----------------------------------------------------------------------
    // gmailApiGet(accessToken, apiPath, params)
    //
    // GET https://gmail.googleapis.com/gmail/v1/users/me/{apiPath}
    // Returns deserialized JSON struct, or throws on HTTP error.
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
    //
    // Exchanges a refresh token for a new access token and writes it back
    // to imap_accounts.  Returns the new plaintext access token.
    //
    // Uses explicit cfhttpparam calls rather than a struct to avoid Lucee
    // mangling underscore-containing keys (grant_type, refresh_token, etc.).
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
    // Gmail API returns attachment data as base64url (uses - and _ instead
    // of + and /).  Translate to standard base64 before decoding.
    // -----------------------------------------------------------------------
    function b64urlDecode(required string encoded) {
        var std = arguments.encoded
            .replace("-", "+", "all")
            .replace("_", "/", "all");
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
    // fetchAttachmentBytes(body, gmailMsgId, accessToken)
    //
    // Given a Gmail message body struct, returns the raw attachment bytes.
    // Handles both inline data (body.data) and large attachments
    // (body.attachmentId where body.data is absent).
    // Returns null if no bytes can be obtained.
    // -----------------------------------------------------------------------
    function fetchAttachmentBytes(
        required struct body,
        required string gmailMsgId,
        required string accessToken
    ) {
        // Inline base64url data
        if (structKeyExists(arguments.body, "data") AND len(arguments.body.data)) {
            return b64urlDecode(arguments.body.data);
        }

        // Large attachment - no inline data, must fetch by attachmentId
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
    //
    // Recursively walks a Gmail message payload parts[] tree.
    // Returns array of byte arrays for any ZIP/GZ/XML/octet-stream parts.
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
    // markGmailMessage(accessToken, gmailMsgId, markRead, deleteMsg)
    //
    // Applies disposition to a Gmail message after successful processing.
    // markRead  - removes UNREAD label via the Gmail modify endpoint
    // deleteMsg - moves to TRASH (Gmail doesn't hard-delete via API)
    //
    // Bug fix: do NOT use serializeJSON() to build the modify request body.
    // Lucee's serializeJSON() uppercases all struct keys, so
    // {removeLabelIds:["UNREAD"]} becomes {"REMOVELABELIDS":["UNREAD"]},
    // which the Gmail API ignores silently.  Use a hardcoded JSON string
    // literal instead to guarantee the correct camelCase key.
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
                // Hardcoded JSON string - do NOT replace with serializeJSON().
                // Lucee uppercases struct keys, producing {"REMOVELABELIDS":["UNREAD"]}
                // which the Gmail API ignores.  The literal string below is correct.
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
    // Replaces the doveadm path for this account.
    //
    // Two-pass strategy per message:
    //   Pass 1 (metadata): fetch headers only - cheap, used for dedup check.
    //   Pass 2 (full):     fetch complete payload - only for new messages.
    // This means already-processed messages cost one lightweight API call
    // instead of a full payload download, which matters during backlog drain.
    //
    // IMPORTANT: No var declarations at page scope - Lucee only allows var
    // inside functions. All loop variables are plain assignments.
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

            // Step 1: get a live access token
            gmailToken = getValidAccessToken(gmailAcct);

            // Step 2: list unread messages in INBOX (batch-limited)
            gmailListParams = {
                "q"          : "in:inbox is:unread",
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

                        // Pass 1: metadata fetch - headers only, no payload.
                        // Much faster than format=full; used for dedup check only.
                        gmailMeta    = gmailApiGet(gmailToken, "messages/#gmailMsgId#", { "format": "metadata" });
                        metaHeaders  = structKeyExists(gmailMeta, "payload") AND structKeyExists(gmailMeta.payload, "headers")
                                       ? gmailMeta.payload.headers : [];

                        rawMsgId   = extractHeaderValue(metaHeaders, "message-id");
                        cleanMsgId = reReplace(trim(rawMsgId), "[<>\s]", "", "ALL");
                        if (NOT len(cleanMsgId)) cleanMsgId = "gmail-" & gmailMsgId;

                        // Dedup check - if already in DB, dispose and move on.
                        // No full payload download needed.
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

                        // Pass 2: full fetch - only reached for new messages.
                        gmailMsg     = gmailApiGet(gmailToken, "messages/#gmailMsgId#", { "format": "full" });
                        gmailPayload = gmailMsg.payload ?: {};
                        gmailHeaders = structKeyExists(gmailPayload, "headers") ? gmailPayload.headers : [];

                        // Re-extract headers from full fetch (more complete than metadata)
                        rawMsgId2  = extractHeaderValue(gmailHeaders, "message-id");
                        cleanMsgId = len(trim(rawMsgId2))
                                     ? reReplace(trim(rawMsgId2), "[<>\s]", "", "ALL")
                                     : cleanMsgId;

                        msgSubject  = extractHeaderValue(gmailHeaders, "subject");
                        contentType = extractHeaderValue(gmailHeaders, "content-type");

                        // Final dedup on full Message-ID (catches any metadata vs full discrepancy)
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

                        // Collect attachment bytes.
                        // No var declarations - page scope, not function scope.
                        //
                        // Shape A: multipart - walk parts[] tree
                        // Shape B: single-part with inline body.data
                        // Shape C: single-part with body.attachmentId (no body.data)
                        //          This is what Google DMARC reports use.
                        attachments  = [];
                        rawBytesList = [];
                        topMime      = lCase(gmailPayload.mimeType ?: "");
                        topFile      = lCase(gmailPayload.filename ?: "");

                        if (structKeyExists(gmailPayload, "parts") AND isArray(gmailPayload.parts) AND arrayLen(gmailPayload.parts)) {
                            // Shape A: multipart
                            rawBytesList = findAttachmentParts(gmailPayload.parts, gmailMsgId, gmailToken);
                            for (rb in rawBytesList) {
                                arrayAppend(attachments, { name: "report", bytes: rb });
                            }

                        } else if (structKeyExists(gmailPayload, "body") AND isStruct(gmailPayload.body)) {
                            // Shape B or C: single-part
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
                            logLine("  Gmail: no attachment bytes for msg=#gmailMsgId# sub=#left(msgSubject,60)#", "WARN");
                            gmailSkip++;
                            totalSkip++;
                            markGmailMessage(gmailToken, gmailMsgId,
                                application.poller.markAsRead,
                                structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);
                            continue;
                        }

                        // Detect RUF vs RUA and parse
                        isRUF = reFindNoCase("multipart/report", contentType)
                                AND reFindNoCase("report-type=feedback-report", contentType);

                        if (isRUF) {
                            logLine("  Gmail: msg=#gmailMsgId# -> RUF");
                            include "/poller/parse_ruf.cfm";
                        } else {
                            logLine("  Gmail: msg=#gmailMsgId# -> RUA");
                            include "/poller/parse_rua.cfm";
                        }

                        // Dispose only after confirmed parse
                        markGmailMessage(gmailToken, gmailMsgId,
                            application.poller.markAsRead,
                            structKeyExists(application.poller, "deleteAfter") AND application.poller.deleteAfter);

                        gmailNew++;
                        totalNew++;

                    } catch(any msgErr) {
                        logLine("  Gmail ERROR msg=#gmailMsgId#: #msgErr.message# | #msgErr.detail#", "ERROR");
                        gmailError++;
                        totalError++;
                        // No dispose on error - leave message intact
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
