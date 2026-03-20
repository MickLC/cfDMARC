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
        onError contains zero # characters — Lucee treats # as an expression
        delimiter in every string literal in every context (tag attrs, cfscript
        double/single-quoted strings, HTML entity refs, CSS hex colors, all of it).
        Solutions used here:
          - CSS colors  -> rgb() / rgba()
          - HTML entities -> chr()  e.g. chr(9888) warning, chr(8592) left arrow
          - Quoted HTML attrs -> chr(34) for double-quote inside cfscript strings
    --->
    <cffunction name="onError" returntype="void" output="false">
        <cfargument name="exception" required="true">
        <cfargument name="eventName" type="string" required="true">
        <cfscript>
            cflog(
                file = "dmarc_errors",
                text = "Error in " & arguments.eventName & ": "
                     & arguments.exception.message & " | "
                     & arguments.exception.detail  & " | "
                     & (structKeyExists(arguments.exception, "stackTrace") ? arguments.exception.stackTrace : ""),
                type = "error"
            );

            local.isAdmin = structKeyExists(session, "loggedIn") AND session.loggedIn;

            local.hint = "";
            if (findNoCase("Unknown column", arguments.exception.message)
                OR findNoCase("doesnt exist", arguments.exception.message)
                OR (findNoCase("Table", arguments.exception.message) AND findNoCase("exist", arguments.exception.message))) {
                local.hint = "Missing database table or column. Have you run all migrations? (db/migrations/004_poller_tables.sql)";
            } else if (findNoCase("Access denied", arguments.exception.message)) {
                local.hint = "Database access denied. Check credentials in config/settings.cfm and the MariaDB grant.";
            } else if (findNoCase("datasource", arguments.exception.message) OR findNoCase("No datasource", arguments.exception.message)) {
                local.hint = "Lucee datasource not found. Verify the dmarc datasource in the Lucee Web Admin.";
            } else if (findNoCase("decrypt", arguments.exception.message) OR findNoCase("encryptionKey", arguments.exception.message)) {
                local.hint = "Encryption error. Check application.encryptionKey in config/settings.cfm.";
            }

            local.css = "body{margin:0;background:rgb(13,17,23);color:rgb(230,237,243);font-family:sans-serif;padding:2rem;}"
                & ".ec{background:rgb(28,33,40);border:1px solid rgb(48,54,61);border-radius:6px;padding:1.5rem;max-width:900px;margin:2rem auto;}"
                & "h2{color:rgb(248,81,73);font-size:1.1rem;margin-bottom:1rem;}"
                & ".lb{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:rgb(110,118,129);font-family:monospace;margin-bottom:.2rem;margin-top:.8rem;}"
                & ".vl{background:rgb(13,17,23);border:1px solid rgb(48,54,61);border-radius:4px;padding:.5rem .8rem;font-family:monospace;font-size:.82rem;white-space:pre-wrap;word-break:break-all;color:rgb(230,237,243);max-height:280px;overflow-y:auto;margin-bottom:.25rem;}"
                & ".ht{background:rgba(56,139,253,.1);border:1px solid rgba(56,139,253,.3);border-radius:4px;padding:.7rem 1rem;font-size:.85rem;color:rgb(121,192,255);margin-bottom:1rem;}"
                & ".bt{border:1px solid rgb(48,54,61);color:rgb(139,148,158);background:transparent;border-radius:4px;padding:.3rem .75rem;font-size:.85rem;text-decoration:none;display:inline-block;margin-right:.4rem;}"
                & "a{color:rgb(56,139,253);}";

            local.q    = chr(34);
            local.warn = chr(9888);
            local.larr = chr(8592);

            local.html = "<!DOCTYPE html><html lang=" & local.q & "en" & local.q & "><head><meta charset=" & local.q & "UTF-8" & local.q & ">"
                & "<title>Error - DMARC Dashboard</title>"
                & "<style>" & local.css & "</style>"
                & "</head><body><div class=" & local.q & "ec" & local.q & ">"
                & "<h2>" & local.warn & " An error occurred</h2>";

            if (len(local.hint)) {
                local.html &= "<div class=" & local.q & "ht" & local.q & ">" & htmlEditFormat(local.hint) & "</div>";
            }

            if (local.isAdmin) {
                local.html &= "<div class=" & local.q & "lb" & local.q & ">Event</div>"
                           &  "<div class=" & local.q & "vl" & local.q & ">" & htmlEditFormat(arguments.eventName) & "</div>";
                local.html &= "<div class=" & local.q & "lb" & local.q & ">Message</div>"
                           &  "<div class=" & local.q & "vl" & local.q & ">" & htmlEditFormat(arguments.exception.message) & "</div>";
                if (len(trim(arguments.exception.detail))) {
                    local.html &= "<div class=" & local.q & "lb" & local.q & ">Detail</div>"
                               &  "<div class=" & local.q & "vl" & local.q & ">" & htmlEditFormat(arguments.exception.detail) & "</div>";
                }
                if (structKeyExists(arguments.exception, "queryError") AND len(trim(arguments.exception.queryError))) {
                    local.html &= "<div class=" & local.q & "lb" & local.q & ">Query Error</div>"
                               &  "<div class=" & local.q & "vl" & local.q & ">" & htmlEditFormat(arguments.exception.queryError) & "</div>";
                }
                if (structKeyExists(arguments.exception, "sql") AND len(trim(arguments.exception.sql))) {
                    local.html &= "<div class=" & local.q & "lb" & local.q & ">SQL</div>"
                               &  "<div class=" & local.q & "vl" & local.q & ">" & htmlEditFormat(arguments.exception.sql) & "</div>";
                }
                if (structKeyExists(arguments.exception, "stackTrace") AND len(trim(arguments.exception.stackTrace))) {
                    local.html &= "<div class=" & local.q & "lb" & local.q & ">Stack Trace</div>"
                               &  "<div class=" & local.q & "vl" & local.q & ">" & htmlEditFormat(arguments.exception.stackTrace) & "</div>";
                }
            } else {
                local.html &= "<p>The error has been logged. "
                           &  "<a href=" & local.q & "/admin/login.cfm" & local.q & ">Sign in</a> to see full details.</p>";
            }

            local.html &= "<div style=" & local.q & "margin-top:1rem;" & local.q & ">"
                & "<a href=" & local.q & "javascript:history.back()" & local.q & " class=" & local.q & "bt" & local.q & ">" & local.larr & " Back</a> "
                & "<a href=" & local.q & "/admin/dashboard.cfm" & local.q & " class=" & local.q & "bt" & local.q & ">Dashboard</a>"
                & "</div></div></body></html>";

            writeOutput(local.html);
        </cfscript>
    </cffunction>

</cfcomponent>
