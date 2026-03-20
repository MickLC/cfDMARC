<!--- admin/oauth_callback.cfm
      Google OAuth2 callback.
      Google redirects here with ?code=...&state=<imap_account_id>
      after the user grants consent.

      Exchanges the authorization code for access + refresh tokens,
      encrypts and stores them, then redirects to accounts.cfm.
--->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    param name="url.code"  default="";
    param name="url.state" default="";
    param name="url.error" default="";

    acctId = val(url.state);

    if (len(url.error)) {
        cflocation(url="/admin/accounts.cfm?msg=" & urlEncodedFormat("Google OAuth2 error: #url.error#"), addToken=false);
    }

    if (NOT len(url.code) OR acctId LTE 0) {
        cflocation(url="/admin/accounts.cfm?msg=Invalid+OAuth2+callback", addToken=false);
    }

    // Exchange code for tokens
    cfhttp(
        url    = "https://oauth2.googleapis.com/token",
        method = "POST",
        result = "tokenResp"
    ) {
        cfhttpparam(type="formfield", name="code",          value=url.code);
        cfhttpparam(type="formfield", name="client_id",     value=application.googleOAuth.clientId);
        cfhttpparam(type="formfield", name="client_secret", value=application.googleOAuth.clientSecret);
        cfhttpparam(type="formfield", name="redirect_uri",  value=application.googleOAuth.redirectURI);
        cfhttpparam(type="formfield", name="grant_type",    value="authorization_code");
    }

    tokenData = deserializeJSON(tokenResp.fileContent);

    if (NOT structKeyExists(tokenData, "access_token")) {
        errMsg = structKeyExists(tokenData, "error_description") ? tokenData.error_description : "Unknown error";
        cflog(file="dmarc_errors", text="OAuth2 token exchange failed for acct #acctId#: #tokenResp.fileContent#", type="error");
        cflocation(url="/admin/accounts.cfm?msg=" & urlEncodedFormat("Token exchange failed: #errMsg#"), addToken=false);
    }

    accessToken  = tokenData.access_token;
    refreshToken = structKeyExists(tokenData, "refresh_token") ? tokenData.refresh_token : "";
    expiresIn    = val(tokenData.expires_in ?: 3599);
    tokenExpiry  = dateAdd("s", expiresIn, now());

    // Store encrypted tokens
    queryExecute(
        "UPDATE imap_accounts
         SET    oauth_access_token_enc  = ?,
                oauth_refresh_token_enc = ?,
                oauth_token_expiry      = ?,
                auth_type               = 'oauth2'
         WHERE  id = ?",
        [
            { value: encryptValue(accessToken),                                 cfsqltype: "cf_sql_varchar" },
            { value: (len(refreshToken) ? encryptValue(refreshToken) : ""),     cfsqltype: "cf_sql_varchar" },
            { value: tokenExpiry,                                               cfsqltype: "cf_sql_timestamp" },
            { value: acctId,                                                    cfsqltype: "cf_sql_integer" }
        ],
        { datasource: application.db.dsn }
    );

    auditLog("oauth2.authorized", "imap_account_id=#acctId#");
    cflog(file="dmarc_poller", text="[INFO] OAuth2 tokens stored for account id=#acctId#; expires #dateTimeFormat(tokenExpiry,'yyyy-mm-dd HH:nn')#");

    cflocation(url="/admin/accounts.cfm?msg=" & urlEncodedFormat("Gmail OAuth2 authorization complete for account ##acctId#"), addToken=false);
</cfscript>
