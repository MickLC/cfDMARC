<!--- Application.cfc --->
<cfcomponent output="false">

    <cfset this.name              = "DMARCDashboard">
    <cfset this.sessionManagement = true>
    <cfset this.sessionTimeout    = createTimeSpan(0, 8, 0, 0)>
    <cfset this.scriptProtect     = "all">
    <cfset this.datasource        = "dmarc">

    <cffunction name="onApplicationStart" returntype="boolean" output="false">
        <cfinclude template="/config/settings.cfm">
        <cfreturn true>
    </cffunction>

    <cffunction name="onSessionStart" returntype="void" output="false">
        <cfset session.loggedIn     = false>
        <cfset session.userId       = "">
        <cfset session.username     = "">
        <cfset session.sessionToken = "">
    </cffunction>

    <cffunction name="onRequestStart" returntype="boolean" output="false">
        <cfargument name="targetPage" type="string" required="true">
        <cfif structKeyExists(url, "reload") AND url.reload EQ "true"
              AND structKeyExists(session, "loggedIn") AND session.loggedIn>
            <cfset onApplicationStart()>
        </cfif>
        <cfif NOT structKeyExists(application, "db")>
            <cfset onApplicationStart()>
        </cfif>
        <cfreturn true>
    </cffunction>

    <!---
        onError is written entirely in cfscript.
        In cfscript, single-quoted strings are NOT scanned for # expressions,
        so CSS hex colors can be written literally without any escaping.
    --->
    <cffunction name="onError" returntype="void" output="false">
        <cfargument name="exception" required="true">
        <cfargument name="eventName" type="string" required="true">
        <cfscript>
            cflog(
                file = 'dmarc_errors',
                text = 'Error in ' & arguments.eventName & ': '
                     & arguments.exception.message & ' | '
                     & arguments.exception.detail  & ' | '
                     & (structKeyExists(arguments.exception, 'stackTrace') ? arguments.exception.stackTrace : ''),
                type = 'error'
            );

            local.isAdmin = structKeyExists(session, 'loggedIn') AND session.loggedIn;

            // Classify error for a useful hint
            local.hint = '';
            if (findNoCase('Unknown column', arguments.exception.message)
                OR findNoCase("doesn't exist", arguments.exception.message)
                OR (findNoCase('Table', arguments.exception.message) AND findNoCase('exist', arguments.exception.message))) {
                local.hint = 'This looks like a missing database table or column &mdash; have you run all migrations? (<code>db/migrations/004_poller_tables.sql</code>)';
            } else if (findNoCase('Access denied', arguments.exception.message)) {
                local.hint = 'Database access denied. Check credentials in <code>config/settings.cfm</code> and the MariaDB grant.';
            } else if (findNoCase('datasource', arguments.exception.message) OR findNoCase('No datasource', arguments.exception.message)) {
                local.hint = 'Lucee datasource not found. Verify the <code>dmarc</code> datasource in the Lucee Web Admin.';
            } else if (findNoCase('decrypt', arguments.exception.message) OR findNoCase('encryptionKey', arguments.exception.message)) {
                local.hint = 'Encryption error. Check <code>application.encryptionKey</code> in <code>config/settings.cfm</code>.';
            }

            // In cfscript, single-quoted strings are never scanned for # —
            // hex colors are completely safe here.
            local.css = '
body      { background:#0d1117; color:#e6edf3; font-family:sans-serif; padding:2rem; }
.err-card { background:#1c2128; border:1px solid #30363d; border-radius:6px; padding:1.5rem; max-width:900px; margin:2rem auto; }
h2        { color:#f85149; font-size:1.1rem; margin-bottom:1rem; }
.lbl      { font-size:.7rem; text-transform:uppercase; letter-spacing:.08em; color:#6e7681; font-family:monospace; margin-bottom:.2rem; }
.val      { background:#0d1117; border:1px solid #30363d; border-radius:4px; padding:.5rem .8rem; font-family:monospace; font-size:.82rem; white-space:pre-wrap; word-break:break-all; color:#e6edf3; max-height:280px; overflow-y:auto; margin-bottom:1rem; }
.hint     { background:rgba(56,139,253,.1); border:1px solid rgba(56,139,253,.3); border-radius:4px; padding:.7rem 1rem; font-size:.85rem; color:#79c0ff; margin-bottom:1rem; }
.btn      { border:1px solid #30363d; color:#8b949e; background:transparent; border-radius:4px; padding:.3rem .75rem; font-size:.85rem; text-decoration:none; display:inline-block; margin-right:.4rem; }
a         { color:#388bfd; }
';

            local.html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
                & '<title>Error &mdash; DMARC Dashboard</title>'
                & '<link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">'
                & '<style>' & local.css & '</style>'
                & '</head><body><div class="err-card">'
                & '<h2>&#9888; An error occurred</h2>';

            if (len(local.hint)) {
                local.html &= '<div class="hint">' & local.hint & '</div>';
            }

            if (local.isAdmin) {
                local.html &= '<div class="lbl">Event</div><div class="val">'    & htmlEditFormat(arguments.eventName)          & '</div>';
                local.html &= '<div class="lbl">Message</div><div class="val">'  & htmlEditFormat(arguments.exception.message)  & '</div>';

                if (len(trim(arguments.exception.detail))) {
                    local.html &= '<div class="lbl">Detail</div><div class="val">' & htmlEditFormat(arguments.exception.detail) & '</div>';
                }
                if (structKeyExists(arguments.exception, 'queryError') AND len(trim(arguments.exception.queryError))) {
                    local.html &= '<div class="lbl">Query Error</div><div class="val">' & htmlEditFormat(arguments.exception.queryError) & '</div>';
                }
                if (structKeyExists(arguments.exception, 'sql') AND len(trim(arguments.exception.sql))) {
                    local.html &= '<div class="lbl">SQL</div><div class="val">' & htmlEditFormat(arguments.exception.sql) & '</div>';
                }
                if (structKeyExists(arguments.exception, 'stackTrace') AND len(trim(arguments.exception.stackTrace))) {
                    local.html &= '<div class="lbl">Stack Trace</div><div class="val">' & htmlEditFormat(arguments.exception.stackTrace) & '</div>';
                }
            } else {
                local.html &= '<p style="color:#8b949e;">The error has been logged. '
                           &  '<a href="/admin/login.cfm">Sign in</a> to see full details.</p>';
            }

            local.html &= '<div class="mt-3">'
                & '<a href="javascript:history.back()" class="btn">&#8592; Back</a>'
                & '<a href="/admin/dashboard.cfm" class="btn">Dashboard</a>'
                & '</div></div></body></html>';

            writeOutput(local.html);
        </cfscript>
    </cffunction>

</cfcomponent>
