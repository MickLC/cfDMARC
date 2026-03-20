<!--- admin/poller.cfm
      Poller status page: shows recent run history and lets an admin
      trigger a manual poll run via a button.
--->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    param name="url.action" default="";

    pageMessage = "";

    // Manual poll trigger
    if (url.action EQ "run") {
        // Fire a synchronous HTTP request to the poller
        try {
            cfhttp(
                url     = application.baseURL & "/poller/poll.cfm",
                method  = "GET",
                timeout = 300,
                result  = "pollResult"
            );
            if (find("OK:", pollResult.fileContent)) {
                pageMessage = "Poll run complete: #htmlEditFormat(trim(pollResult.fileContent))#";
            } else {
                pageMessage = "Poll returned unexpected response. Check dmarc_poller log.";
            }
        } catch(any e) {
            pageMessage = "Poll request error: #e.message#";
        }
    }

    // Recent poll runs
    qRuns = queryExecute(
        "SELECT id, run_at, new_reports, skipped, errors, elapsed_sec, log_text
         FROM   poller_runs
         ORDER  BY run_at DESC
         LIMIT  20",
        {},
        { datasource: application.db.dsn }
    );

    // Account status
    qAccts = queryExecute(
        "SELECT id, account_label, username, auth_type, active,
                last_polled, oauth_token_expiry, oauth_access_token_enc
         FROM   imap_accounts
         ORDER  BY account_label",
        {},
        { datasource: application.db.dsn }
    );
</cfscript>

<cfset variables.pageTitle = "Poller">
<cfset variables.activeNav = "poller">
<cfinclude template="/includes/header.cfm">

<cfoutput>

<cfif len(pageMessage)>
<div class="alert alert-info mb-3"><i class="bi bi-info-circle"></i> #pageMessage#</div>
</cfif>

<div class="row g-3 mb-4">
    <!--- Run now button --->
    <div class="col-auto">
        <a href="?action=run"
           class="btn btn-primary"
           onclick="return confirm('Run the poller now? This may take a minute.')"
        ><i class="bi bi-arrow-repeat"></i> Run Now</a>
    </div>
    <div class="col-auto">
        <a href="/admin/accounts.cfm" class="btn btn-outline-secondary">
            <i class="bi bi-envelope-at"></i> Manage Accounts
        </a>
    </div>
</div>

<!--- Account status table --->
<div class="card mb-4">
    <div class="card-header">Account Status</div>
    <div class="card-body p-0">
    <table class="table mb-0">
    <thead><tr>
        <th>Label</th><th>User</th><th>Auth</th>
        <th>Token Status</th><th>Last Polled</th><th>Active</th>
    </tr></thead>
    <tbody>
    <cfloop query="qAccts">
        <cfscript>
            tokenStatus = "";
            tokenClass  = "neutral";
            if (qAccts.auth_type EQ "oauth2") {
                if (NOT len(qAccts.oauth_access_token_enc)) {
                    tokenStatus = "No token";
                    tokenClass  = "fail";
                } else if (isDate(qAccts.oauth_token_expiry)
                           AND dateDiff("n", now(), qAccts.oauth_token_expiry) LT 5) {
                    tokenStatus = "Expired / refreshing";
                    tokenClass  = "warn";
                } else {
                    tokenStatus = "Valid";
                    tokenClass  = "pass";
                }
            } else {
                tokenStatus = "N/A";
            }
        </cfscript>
        <tr>
            <td class="mono" style="font-size:0.82rem;">#htmlEditFormat(qAccts.account_label)#</td>
            <td style="font-size:0.8rem;">#htmlEditFormat(qAccts.username)#</td>
            <td><span class="badge badge-#(qAccts.auth_type EQ 'oauth2' ? 'pass' : 'neutral')#">#qAccts.auth_type#</span></td>
            <td><span class="badge badge-#tokenClass#">#tokenStatus#</span></td>
            <td class="mono" style="font-size:0.78rem;color:var(--text-muted);">
                <cfif isDate(qAccts.last_polled)>#timeAgo(qAccts.last_polled)#<cfelse>&mdash;</cfif>
            </td>
            <td>
                <span class="badge badge-#(qAccts.active ? 'pass' : 'fail')#">
                    #(qAccts.active ? 'Active' : 'Inactive')#
                </span>
            </td>
        </tr>
    </cfloop>
    </tbody>
    </table>
    </div>
</div>

<!--- Recent run history --->
<div class="card">
    <div class="card-header">Recent Poll Runs</div>
    <div class="card-body p-0">
    <cfif qRuns.recordCount EQ 0>
        <p class="text-muted p-3 mb-0">No poll runs recorded yet.</p>
    <cfelse>
    <table class="table mb-0">
    <thead><tr>
        <th>Run At</th><th>New</th><th>Skipped</th><th>Errors</th><th>Time</th><th>Log</th>
    </tr></thead>
    <tbody>
    <cfloop query="qRuns">
        <tr>
            <td class="mono" style="font-size:0.78rem;">#dateTimeFormat(qRuns.run_at, "yyyy-mm-dd HH:nn:ss")#</td>
            <td><span class="badge badge-#(qRuns.new_reports GT 0 ? 'pass' : 'neutral')#">#qRuns.new_reports#</span></td>
            <td><span class="badge badge-neutral">#qRuns.skipped#</span></td>
            <td><span class="badge badge-#(qRuns.errors GT 0 ? 'fail' : 'neutral')#">#qRuns.errors#</span></td>
            <td class="mono" style="font-size:0.78rem;">#qRuns.elapsed_sec#s</td>
            <td>
                <a href="##" class="btn btn-sm btn-outline-secondary py-0"
                   style="font-size:0.7rem;"
                   onclick="document.getElementById('log-#qRuns.id#').classList.toggle('d-none'); return false;">
                    View log
                </a>
                <pre id="log-#qRuns.id#"
                     class="d-none mt-2 p-2"
                     style="font-size:0.72rem;background:var(--bg-primary);border:1px solid var(--border-color);border-radius:4px;max-height:300px;overflow-y:auto;white-space:pre-wrap;">#htmlEditFormat(qRuns.log_text)#</pre>
            </td>
        </tr>
    </cfloop>
    </tbody>
    </table>
    </cfif>
    </div>
</div>

</cfoutput>
<cfinclude template="/includes/footer.cfm">
