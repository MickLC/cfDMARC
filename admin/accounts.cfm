<!--- admin/accounts.cfm
      IMAP accounts management UI.
      Supports both password-auth and OAuth2 (Gmail) accounts.
      CRUD: list, add, edit, delete, test-connection.
--->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    param name="url.action"    default="list";
    param name="url.id"        default="0";
    param name="form.action"   default="";

    pageMessage = "";
    pageError   = "";

    // ----------------------------------------------------------------
    // POST handlers
    // ----------------------------------------------------------------
    if (cgi.request_method EQ "POST") {

        param name="form.account_label"   default="";
        param name="form.host"            default="";
        param name="form.port"            default="993";
        param name="form.username"        default="";
        param name="form.password"        default="";
        param name="form.auth_type"       default="password";
        param name="form.use_ssl"         default="1";
        param name="form.mailbox"         default="INBOX";
        param name="form.active"          default="1";
        param name="form.acct_id"         default="0";

        acctId = val(form.acct_id);

        if (form.action EQ "save") {

            // Validate required fields
            if (NOT len(trim(form.account_label)) OR NOT len(trim(form.host)) OR NOT len(trim(form.username))) {
                pageError = "Account label, host, and username are required.";
            } else {

                if (acctId GT 0) {
                    // UPDATE
                    // Only re-encrypt password if a new one was supplied
                    if (len(trim(form.password))) {
                        newPwdEnc = encryptValue(trim(form.password));
                        queryExecute(
                            "UPDATE imap_accounts SET
                                account_label = ?, host = ?, port = ?,
                                username = ?, password_enc = ?,
                                auth_type = ?, use_ssl = ?,
                                mailbox = ?, active = ?
                             WHERE id = ?",
                            [
                                { value: left(trim(form.account_label),100), cfsqltype:"cf_sql_varchar" },
                                { value: left(trim(form.host),253),          cfsqltype:"cf_sql_varchar" },
                                { value: val(form.port),                     cfsqltype:"cf_sql_integer" },
                                { value: left(trim(form.username),255),      cfsqltype:"cf_sql_varchar" },
                                { value: newPwdEnc,                          cfsqltype:"cf_sql_varchar" },
                                { value: form.auth_type,                     cfsqltype:"cf_sql_varchar" },
                                { value: val(form.use_ssl),                  cfsqltype:"cf_sql_tinyint" },
                                { value: left(trim(form.mailbox),100),       cfsqltype:"cf_sql_varchar" },
                                { value: val(form.active),                   cfsqltype:"cf_sql_tinyint" },
                                { value: acctId,                             cfsqltype:"cf_sql_integer" }
                            ],
                            { datasource: application.db.dsn }
                        );
                    } else {
                        queryExecute(
                            "UPDATE imap_accounts SET
                                account_label = ?, host = ?, port = ?,
                                username = ?, auth_type = ?,
                                use_ssl = ?, mailbox = ?, active = ?
                             WHERE id = ?",
                            [
                                { value: left(trim(form.account_label),100), cfsqltype:"cf_sql_varchar" },
                                { value: left(trim(form.host),253),          cfsqltype:"cf_sql_varchar" },
                                { value: val(form.port),                     cfsqltype:"cf_sql_integer" },
                                { value: left(trim(form.username),255),      cfsqltype:"cf_sql_varchar" },
                                { value: form.auth_type,                     cfsqltype:"cf_sql_varchar" },
                                { value: val(form.use_ssl),                  cfsqltype:"cf_sql_tinyint" },
                                { value: left(trim(form.mailbox),100),       cfsqltype:"cf_sql_varchar" },
                                { value: val(form.active),                   cfsqltype:"cf_sql_tinyint" },
                                { value: acctId,                             cfsqltype:"cf_sql_integer" }
                            ],
                            { datasource: application.db.dsn }
                        );
                    }
                    pageMessage = "Account updated.";
                    auditLog("accounts.update", "id=#acctId# label=#form.account_label#");

                } else {
                    // INSERT
                    pwdEnc = len(trim(form.password)) ? encryptValue(trim(form.password)) : "";
                    queryExecute(
                        "INSERT INTO imap_accounts
                             (account_label, host, port, username, password_enc,
                              auth_type, use_ssl, mailbox, active)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [
                            { value: left(trim(form.account_label),100), cfsqltype:"cf_sql_varchar" },
                            { value: left(trim(form.host),253),          cfsqltype:"cf_sql_varchar" },
                            { value: val(form.port),                     cfsqltype:"cf_sql_integer" },
                            { value: left(trim(form.username),255),      cfsqltype:"cf_sql_varchar" },
                            { value: pwdEnc,                             cfsqltype:"cf_sql_varchar" },
                            { value: form.auth_type,                     cfsqltype:"cf_sql_varchar" },
                            { value: val(form.use_ssl),                  cfsqltype:"cf_sql_tinyint" },
                            { value: left(trim(form.mailbox),100),       cfsqltype:"cf_sql_varchar" },
                            { value: val(form.active),                   cfsqltype:"cf_sql_tinyint" }
                        ],
                        { datasource: application.db.dsn }
                    );
                    pageMessage = "Account added.";
                    auditLog("accounts.add", "label=#form.account_label# type=#form.auth_type#");
                }

                // Redirect to list after save
                cflocation(url="/admin/accounts.cfm?msg=" & urlEncodedFormat(pageMessage), addToken=false);
            }

        } else if (form.action EQ "delete" AND acctId GT 0) {
            queryExecute(
                "DELETE FROM imap_accounts WHERE id = ?",
                [{ value: acctId, cfsqltype: "cf_sql_integer" }],
                { datasource: application.db.dsn }
            );
            auditLog("accounts.delete", "id=#acctId#");
            cflocation(url="/admin/accounts.cfm?msg=Account+deleted", addToken=false);

        } else if (form.action EQ "toggle" AND acctId GT 0) {
            queryExecute(
                "UPDATE imap_accounts SET active = NOT active WHERE id = ?",
                [{ value: acctId, cfsqltype: "cf_sql_integer" }],
                { datasource: application.db.dsn }
            );
            cflocation(url="/admin/accounts.cfm", addToken=false);
        }
    }

    // ----------------------------------------------------------------
    // GET — pick up redirect message
    // ----------------------------------------------------------------
    param name="url.msg" default="";
    if (len(url.msg)) pageMessage = htmlEditFormat(url.msg);

    // ----------------------------------------------------------------
    // Load account list
    // ----------------------------------------------------------------
    qAccounts = queryExecute(
        "SELECT id, account_label, host, port, username, auth_type,
                use_ssl, mailbox, active, last_polled,
                oauth_access_token_enc
         FROM   imap_accounts
         ORDER  BY account_label",
        {},
        { datasource: application.db.dsn }
    );

    // ----------------------------------------------------------------
    // Load one account for edit form
    // ----------------------------------------------------------------
    editAcct = {};
    if (url.action EQ "edit" AND val(url.id) GT 0) {
        qEdit = queryExecute(
            "SELECT * FROM imap_accounts WHERE id = ?",
            [{ value: val(url.id), cfsqltype: "cf_sql_integer" }],
            { datasource: application.db.dsn }
        );
        if (qEdit.recordCount) {
            editAcct = {
                id            : qEdit.id,
                account_label : qEdit.account_label,
                host          : qEdit.host,
                port          : qEdit.port,
                username      : qEdit.username,
                auth_type     : qEdit.auth_type,
                use_ssl       : qEdit.use_ssl,
                mailbox       : qEdit.mailbox,
                active        : qEdit.active
            };
        }
    }

    showForm = (url.action EQ "add" OR url.action EQ "edit");

    // OAuth2 authorization URL for Gmail
    oauthURL = "https://accounts.google.com/o/oauth2/v2/auth"
             & "?client_id="    & urlEncodedFormat(application.googleOAuth.clientId)
             & "&redirect_uri=" & urlEncodedFormat(application.googleOAuth.redirectURI)
             & "&response_type=code"
             & "&scope="        & urlEncodedFormat(application.googleOAuth.scopes)
             & "&access_type=offline"
             & "&prompt=consent";
</cfscript>

<cfset variables.pageTitle = "IMAP Accounts">
<cfset variables.activeNav = "accounts">
<cfinclude template="/includes/header.cfm">

<cfoutput>

<!--- Messages --->
<cfif len(pageMessage)>
<div class="alert alert-success mb-3"><i class="bi bi-check-circle"></i> #pageMessage#</div>
</cfif>
<cfif len(pageError)>
<div class="alert alert-danger mb-3"><i class="bi bi-exclamation-triangle"></i> #pageError#</div>
</cfif>

<!--- Account list --->
<div class="card mb-4">
    <div class="card-header d-flex justify-content-between align-items-center">
        <span>IMAP Accounts</span>
        <a href="?action=add" class="btn btn-sm btn-primary"><i class="bi bi-plus-lg"></i> Add Account</a>
    </div>
    <div class="card-body p-0">
    <cfif qAccounts.recordCount EQ 0>
        <p class="text-muted p-3 mb-0">No accounts configured. Add one to start polling for DMARC reports.</p>
    <cfelse>
        <table class="table mb-0">
        <thead><tr>
            <th>Label</th><th>Host</th><th>User</th><th>Auth</th>
            <th>SSL</th><th>Mailbox</th><th>Last Polled</th><th>Status</th><th></th>
        </tr></thead>
        <tbody>
        <cfloop query="qAccounts">
            <tr>
                <td class="mono" style="font-size:0.82rem;">#htmlEditFormat(qAccounts.account_label)#</td>
                <td style="font-size:0.8rem;color:var(--text-secondary)">#htmlEditFormat(qAccounts.host)#:#qAccounts.port#</td>
                <td style="font-size:0.8rem;">#htmlEditFormat(qAccounts.username)#</td>
                <td>
                    <cfif qAccounts.auth_type EQ "oauth2">
                        <span class="badge badge-pass">OAuth2</span>
                        <cfif NOT len(qAccounts.oauth_access_token_enc)>
                            <span class="badge badge-fail ms-1" title="No token — click Authorize">No token</span>
                        </cfif>
                    <cfelse>
                        <span class="badge badge-neutral">Password</span>
                    </cfif>
                </td>
                <td><cfif qAccounts.use_ssl><i class="bi bi-lock-fill" style="color:var(--accent-green)" title="SSL"></i><cfelse><i class="bi bi-unlock" style="color:var(--text-muted)"></i></cfif></td>
                <td style="font-size:0.8rem;">#htmlEditFormat(qAccounts.mailbox)#</td>
                <td style="font-size:0.78rem;color:var(--text-muted);" class="mono">
                    <cfif isDate(qAccounts.last_polled)>#timeAgo(qAccounts.last_polled)#<cfelse>&mdash;</cfif>
                </td>
                <td>
                    <form method="post" action="/admin/accounts.cfm" style="display:inline">
                    <input type="hidden" name="acct_id" value="#qAccounts.id#">
                    <input type="hidden" name="action" value="toggle">
                    <button type="submit" class="btn btn-sm #(qAccounts.active ? 'btn-success' : 'btn-outline-secondary')#" title="#(qAccounts.active ? 'Active — click to disable' : 'Inactive — click to enable')#">
                        <i class="bi bi-#(qAccounts.active ? 'toggle-on' : 'toggle-off')#"></i>
                        #(qAccounts.active ? 'Active' : 'Inactive')#
                    </button>
                    </form>
                </td>
                <td style="white-space:nowrap;">
                    <a href="?action=edit&id=#qAccounts.id#" class="btn btn-sm btn-outline-secondary me-1"
                       title="Edit"><i class="bi bi-pencil"></i></a>
                    <cfif qAccounts.auth_type EQ "oauth2">
                    <a href="#oauthURL#&state=#qAccounts.id#" class="btn btn-sm btn-outline-secondary me-1"
                       title="Authorize with Google"><i class="bi bi-google"></i> Authorize</a>
                    </cfif>
                    <form method="post" action="/admin/accounts.cfm" style="display:inline"
                          onsubmit="return confirm('Delete this account?')">
                    <input type="hidden" name="acct_id"  value="#qAccounts.id#">
                    <input type="hidden" name="action"   value="delete">
                    <button type="submit" class="btn btn-sm btn-danger" title="Delete">
                        <i class="bi bi-trash"></i>
                    </button>
                    </form>
                </td>
            </tr>
        </cfloop>
        </tbody>
        </table>
    </cfif>
    </div>
</div>

<!--- Add / Edit form --->
<cfif showForm>
<div class="card">
    <div class="card-header">
        <cfif url.action EQ "edit">Edit Account<cfelse>Add Account</cfif>
    </div>
    <div class="card-body">

    <cfif NOT structIsEmpty(editAcct) OR url.action EQ "add">
    <form method="post" action="/admin/accounts.cfm">
    <input type="hidden" name="action"  value="save">
    <input type="hidden" name="acct_id" value="#(structKeyExists(editAcct,'id') ? editAcct.id : 0)#">

    <div class="row g-3">
        <div class="col-md-6">
            <label class="form-label">Account Label *</label>
            <input type="text" name="account_label" class="form-control"
                   value="#htmlEditFormat(structKeyExists(editAcct,'account_label') ? editAcct.account_label : '')#"
                   placeholder="e.g. Whizardries DMARC" required>
        </div>
        <div class="col-md-4">
            <label class="form-label">Auth Type *</label>
            <select name="auth_type" class="form-select" id="authTypeSelect">
                <option value="password" #(structKeyExists(editAcct,'auth_type') AND editAcct.auth_type EQ 'oauth2' ? '' : 'selected')#>Password</option>
                <option value="oauth2"   #(structKeyExists(editAcct,'auth_type') AND editAcct.auth_type EQ 'oauth2' ? 'selected' : '')#>OAuth2 (Gmail)</option>
            </select>
        </div>
        <div class="col-md-2">
            <label class="form-label">Active</label>
            <select name="active" class="form-select">
                <option value="1" #(structKeyExists(editAcct,'active') AND NOT editAcct.active ? '' : 'selected')#>Yes</option>
                <option value="0" #(structKeyExists(editAcct,'active') AND NOT editAcct.active ? 'selected' : '')#>No</option>
            </select>
        </div>
    </div>

    <div class="row g-3 mt-0" id="passwordFields">
        <div class="col-md-6">
            <label class="form-label">IMAP Host *</label>
            <input type="text" name="host" class="form-control"
                   value="#htmlEditFormat(structKeyExists(editAcct,'host') ? editAcct.host : '')#"
                   placeholder="mail.example.com">
        </div>
        <div class="col-md-2">
            <label class="form-label">Port</label>
            <input type="number" name="port" class="form-control"
                   value="#(structKeyExists(editAcct,'port') ? editAcct.port : 993)#">
        </div>
        <div class="col-md-2">
            <label class="form-label">SSL</label>
            <select name="use_ssl" class="form-select">
                <option value="1" #(structKeyExists(editAcct,'use_ssl') AND NOT editAcct.use_ssl ? '' : 'selected')#>Yes</option>
                <option value="0" #(structKeyExists(editAcct,'use_ssl') AND NOT editAcct.use_ssl ? 'selected' : '')#>No</option>
            </select>
        </div>
        <div class="col-md-2">
            <label class="form-label">Mailbox</label>
            <input type="text" name="mailbox" class="form-control"
                   value="#htmlEditFormat(structKeyExists(editAcct,'mailbox') ? editAcct.mailbox : 'INBOX')#">
        </div>
    </div>

    <div class="row g-3 mt-0">
        <div class="col-md-6">
            <label class="form-label">Username (email) *</label>
            <input type="email" name="username" class="form-control"
                   value="#htmlEditFormat(structKeyExists(editAcct,'username') ? editAcct.username : '')#"
                   placeholder="dmarc_report@example.com">
        </div>
        <div class="col-md-6" id="passwordField">
            <label class="form-label" id="pwdLabel">Password
                <cfif url.action EQ "edit"><span style="font-size:0.72rem;color:var(--text-muted)">(leave blank to keep existing)</span></cfif>
            </label>
            <input type="password" name="password" class="form-control" autocomplete="new-password">
        </div>
    </div>

    <div id="oauthNote" class="alert alert-info mt-3" style="display:none;">
        <i class="bi bi-info-circle"></i>
        For <strong>OAuth2 (Gmail)</strong> accounts: fill in the host (<code>imap.gmail.com</code>),
        port (<code>993</code>), and username (Gmail address), then save.
        After saving, click the <strong>Authorize</strong> button on the account list to
        complete the Google OAuth2 consent flow.
        The password field is not used for OAuth2 accounts.
    </div>

    <div class="mt-3">
        <button type="submit" class="btn btn-primary"><i class="bi bi-save"></i> Save Account</button>
        <a href="/admin/accounts.cfm" class="btn btn-outline-secondary ms-2">Cancel</a>
    </div>
    </form>
    </cfif>

    </div>
</div>
</cfif>

<script>
(function(){
    function toggleAuthFields() {
        var isOAuth = document.getElementById('authTypeSelect').value === 'oauth2';
        document.getElementById('passwordField').style.display = isOAuth ? 'none' : '';
        document.getElementById('oauthNote').style.display     = isOAuth ? '' : 'none';
        document.querySelector('label[id="pwdLabel"]');
    }
    var sel = document.getElementById('authTypeSelect');
    if (sel) {
        sel.addEventListener('change', toggleAuthFields);
        toggleAuthFields();
    }
})();
</script>

</cfoutput>
<cfinclude template="/includes/footer.cfm">
