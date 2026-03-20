<!--- admin/oauth_callback.cfm
      Google OAuth2 callback — exchanges auth code for tokens
      and stores them encrypted in imap_accounts.
--->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    param name="url.code"  default="";
    param name="url.state" default="";
    param name="url.error" default="";

    acctId = val(url.state);

    if (len(url.error))
        cflocation(url="/admin/accounts.cfm?msg=" & urlEncodedFormat("OAuth2 error: #url.error#"), addToken=false);

    if (NOT len(url.code) OR acctId LTE 0)
        cflocation(url="/admin/accounts.cfm?msg=Invalid+OAuth2+callback", addToken=false);

    // Load client credentials for this account
    qAcct = queryExecute(
        "SELECT oauth_client_id, oauth_client_secret FROM imap_accounts WHERE id=?",
        [{value:acctId, cfsqltype:"cf_sql_integer"}],
        {datasource:application.db.dsn}
    );
    if (NOT qAcct.recordCount)
        cflocation(url="/admin/accounts.cfm?msg=Account+not+found", addToken=false);

    clientId     = qAcct.oauth_client_id;
    clientSecret = decryptValue(qAcct.oauth_client_secret);
    redirectURI  = application.baseURL & "/admin/oauth_callback.cfm";

    cfhttp(url="https://oauth2.googleapis.com/token", method="POST", result="tokenResp") {
        cfhttpparam(type="formfield", name="code",          value=url.code);
        cfhttpparam(type="formfield", name="client_id",     value=clientId);
        cfhttpparam(type="formfield", name="client_secret", value=clientSecret);
        cfhttpparam(type="formfield", name="redirect_uri",  value=redirectURI);
        cfhttpparam(type="formfield", name="grant_type",    value="authorization_code");
    }

    tokenData = deserializeJSON(tokenResp.fileContent);
    if (NOT structKeyExists(tokenData, "access_token")) {
        errMsg = structKeyExists(tokenData,"error_description") ? tokenData.error_description : "Unknown error";
        cflog(file="dmarc_errors", text="OAuth2 token exchange failed acct #acctId#: #tokenResp.fileContent#", type="error");
        cflocation(url="/admin/accounts.cfm?msg=" & urlEncodedFormat("Token exchange failed: #errMsg#"), addToken=false);
    }

    accessToken  = tokenData.access_token;
    refreshToken = structKeyExists(tokenData,"refresh_token") ? tokenData.refresh_token : "";
    tokenExpiry  = dateAdd("s", val(tokenData.expires_in ?: 3599), now());

    queryExecute(
        "UPDATE imap_accounts
         SET    oauth_access_token  = ?,
                oauth_refresh_token = ?,
                oauth_token_expiry  = ?,
                auth_type           = 'oauth2'
         WHERE  id = ?",
        [
            {value:encryptValue(accessToken),                              cfsqltype:"cf_sql_varchar"},
            {value:(len(refreshToken) ? encryptValue(refreshToken) : ""),  cfsqltype:"cf_sql_varchar"},
            {value:tokenExpiry,                                            cfsqltype:"cf_sql_timestamp"},
            {value:acctId,                                                 cfsqltype:"cf_sql_integer"}
        ],
        {datasource:application.db.dsn}
    );

    auditLog("oauth2.authorized", "imap_account_id=#acctId#");
    cflocation(url="/admin/accounts.cfm?msg=Gmail+OAuth2+authorised+for+account+#acctId#", addToken=false);
</cfscript>
