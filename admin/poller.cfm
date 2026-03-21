<!--- admin/poller.cfm
      Poller status page.
--->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    param name="url.action" default="";
    pageMessage      = "";
    pageMessageClass = "alert-info";
    pollErrorBody    = "";

    if (url.action EQ "run") {
        try {
            pollURL = application.baseURL & "/poller/poll.cfm?token=" & urlEncodedFormat(application.poller.token);
            cfhttp(url=pollURL, method="GET", timeout=300, result="pollResult");
            httpStatus = pollResult.responseHeader["Status_Code"] ?: "?";
            if (find("OK:", pollResult.fileContent)) {
                pageMessage      = "Poll complete: #htmlEditFormat(trim(pollResult.fileContent))#";
                pageMessageClass = "alert-success";
            } else {
                pageMessage      = "Unexpected response (HTTP #htmlEditFormat(httpStatus)#). Check dmarc_poller log.";
                pageMessageClass = "alert-danger";
                pollErrorBody    = pollResult.fileContent;
            }
        } catch(any e) {
            pageMessage      = "Poll error: #htmlEditFormat(e.message)#";
            pageMessageClass = "alert-danger";
        }
    }

    qRuns = queryExecute(
        "SELECT id, run_at, new_reports, skipped, errors, elapsed_sec, log_text
         FROM   poller_runs
         ORDER  BY run_at DESC LIMIT 20",
        {}, {datasource:application.db.dsn}
    );

    qAccts = queryExecute(
        "SELECT id, label, username, auth_type, active,
                last_polled, last_status, oauth_token_expiry, oauth_access_token
         FROM   imap_accounts
         ORDER  BY label",
        {}, {datasource:application.db.dsn}
    );
</cfscript>

<cfset variables.pageTitle = "Poller">
<cfset variables.activeNav = "poller">
<cfinclude template="/includes/header.cfm">

<cfoutput>

<cfif len(pageMessage)>
<div class="alert #pageMessageClass# mb-3">
    <i class="bi bi-#(pageMessageClass EQ 'alert-success' ? 'check-circle' : 'exclamation-triangle')#"></i>
    #pageMessage#
    <cfif len(pollErrorBody)>
        <div class="mt-2">
            <a href="##" class="alert-link" style="font-size:0.85rem;"
               onclick="document.getElementById('poll-error-body').classList.toggle('d-none');return false;">
                Show / hide full response
            </a>
        </div>
        <pre id="poll-error-body" class="d-none mt-2 p-2"
             style="font-size:0.72rem;background:var(--bg-primary);border:1px solid var(--border-color);border-radius:4px;max-height:400px;overflow:auto;white-space:pre-wrap;word-break:break-all;">#htmlEditFormat(pollErrorBody)#</pre>
    </cfif>
</div>
</cfif>

<div class="d-flex gap-2 mb-4">
    <a href="?action=run" class="btn btn-primary"
       onclick="return confirm('Run the poller now?')"
    ><i class="bi bi-arrow-repeat"></i> Run Now</a>
    <a href="/admin/accounts.cfm" class="btn btn-outline-secondary"><i class="bi bi-envelope-at"></i> Manage Accounts</a>
</div>

<div class="card mb-4">
    <div class="card-header">Account Status</div>
    <div class="card-body p-0">
    <table class="table mb-0">
    <thead><tr>
        <th>Label</th><th>User</th><th>Auth</th><th>Token</th><th>Last Polled</th><th>Last Status</th><th>Active</th>
    </tr></thead>
    <tbody>
    <cfloop query="qAccts">
        <cfscript>
            tokenStatus = "N/A";
            tokenClass  = "neutral";
            if (qAccts.auth_type EQ "oauth2") {
                if (NOT len(qAccts.oauth_access_token)) {
                    tokenStatus = "No token"; tokenClass = "fail";
                } else if (isDate(qAccts.oauth_token_expiry) AND dateDiff("n",now(),qAccts.oauth_token_expiry) LT 5) {
                    tokenStatus = "Expiring"; tokenClass = "warn";
                } else {
                    tokenStatus = "Valid"; tokenClass = "pass";
                }
            }
        </cfscript>
        <tr>
            <td class="mono" style="font-size:0.82rem;">#htmlEditFormat(qAccts.label)#</td>
            <td style="font-size:0.8rem;">#htmlEditFormat(qAccts.username)#</td>
            <td><span class="badge badge-#(qAccts.auth_type EQ 'oauth2' ? 'pass' : 'neutral')#">#qAccts.auth_type#</span></td>
            <td><span class="badge badge-#tokenClass#">#tokenStatus#</span></td>
            <td class="mono" style="font-size:0.78rem;color:var(--text-muted);">
                <cfif isDate(qAccts.last_polled)>#timeAgo(qAccts.last_polled)#<cfelse>&mdash;</cfif>
            </td>
            <td style="font-size:0.75rem;color:var(--text-muted);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                #len(qAccts.last_status) ? htmlEditFormat(qAccts.last_status) : '&mdash;'#
            </td>
            <td><span class="badge badge-#(qAccts.active ? 'pass' : 'fail')#">#(qAccts.active ? 'Active' : 'Inactive')#</span></td>
        </tr>
    </cfloop>
    </tbody>
    </table>
    </div>
</div>

<div class="card">
    <div class="card-header">Recent Poll Runs</div>
    <div class="card-body p-0">
    <cfif qRuns.recordCount EQ 0>
        <p class="text-muted p-3 mb-0">No poll runs yet.</p>
    <cfelse>
    <table class="table mb-0">
    <thead><tr><th>Run At</th><th>New</th><th>Skipped</th><th>Errors</th><th>Time</th><th>Log</th></tr></thead>
    <tbody>
    <cfloop query="qRuns">
        <tr>
            <td class="mono" style="font-size:0.78rem;">#dateTimeFormat(qRuns.run_at,"yyyy-mm-dd HH:nn:ss")#</td>
            <td><span class="badge badge-#(qRuns.new_reports GT 0 ? 'pass':'neutral')#">#qRuns.new_reports#</span></td>
            <td><span class="badge badge-neutral">#qRuns.skipped#</span></td>
            <td><span class="badge badge-#(qRuns.errors GT 0 ? 'fail':'neutral')#">#qRuns.errors#</span></td>
            <td class="mono" style="font-size:0.78rem;">#qRuns.elapsed_sec#s</td>
            <td>
                <a href="##" class="btn btn-sm btn-outline-secondary py-0" style="font-size:0.7rem;"
                   onclick="document.getElementById('log-#qRuns.id#').classList.toggle('d-none');return false;">Log</a>
                <pre id="log-#qRuns.id#" class="d-none mt-2 p-2"
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
