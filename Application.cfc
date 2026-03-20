<!--- Application.cfc --->
<cfcomponent output="false">

    <cfset this.name               = "DMARCDashboard">
    <cfset this.sessionManagement  = true>
    <cfset this.sessionTimeout     = createTimeSpan(0, 8, 0, 0)>
    <cfset this.scriptProtect      = "all">

    <!--- Datasource — must match Lucee admin config --->
    <cfset this.datasource = "dmarc">

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

        <!--- Reload application if ?reload=true and logged in as admin --->
        <cfif structKeyExists(url, "reload") AND url.reload EQ "true"
              AND structKeyExists(session, "loggedIn") AND session.loggedIn>
            <cfset onApplicationStart()>
        </cfif>

        <!--- Ensure settings are always available --->
        <cfif NOT structKeyExists(application, "db")>
            <cfset onApplicationStart()>
        </cfif>

        <cfreturn true>
    </cffunction>

    <cffunction name="onError" returntype="void" output="true">
        <cfargument name="exception" required="true">
        <cfargument name="eventName" type="string" required="true">

        <!--- Always log the full detail server-side --->
        <cflog file="dmarc_errors"
               text="Error in #arguments.eventName#: #arguments.exception.message# | #arguments.exception.detail# | #arguments.exception.stackTrace#"
               type="error">

        <cfset isAdmin = structKeyExists(session, "loggedIn") AND session.loggedIn>

        <!--- Classify the error to give a useful hint --->
        <cfset hint = "">
        <cfif findNoCase("Unknown column", arguments.exception.message)
           OR findNoCase("doesn't exist", arguments.exception.message)
           OR (findNoCase("Table", arguments.exception.message) AND findNoCase("exist", arguments.exception.message))>
            <cfset hint = "This looks like a missing database table or column. Have you run all migrations? (<code>db/migrations/004_poller_tables.sql</code>)">
        <cfelseif findNoCase("Access denied", arguments.exception.message)>
            <cfset hint = "Database access denied. Check the credentials in <code>config/settings.cfm</code> and the MariaDB grant.">
        <cfelseif findNoCase("datasource", arguments.exception.message)
               OR findNoCase("No datasource", arguments.exception.message)>
            <cfset hint = "Lucee datasource not found. Verify the <code>dmarc</code> datasource is configured in the Lucee Web Admin.">
        <cfelseif findNoCase("decrypt", arguments.exception.message)
               OR findNoCase("encryptionKey", arguments.exception.message)>
            <cfset hint = "Encryption/decryption error. Check that <code>application.encryptionKey</code> is set correctly in <code>config/settings.cfm</code>.">
        </cfif>

        <!--- Style block is intentionally OUTSIDE cfoutput to avoid # in hex colors
              being parsed as CFML expression delimiters --->
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Error &mdash; DMARC Dashboard</title>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body      { background: #0d1117; color: #e6edf3; font-family: 'IBM Plex Sans', sans-serif; padding: 2rem; }
                .err-card { background: #1c2128; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; max-width: 900px; margin: 2rem auto; }
                .err-card h2  { color: #f85149; font-size: 1.1rem; margin-bottom: 1rem; }
                .err-label    { font-size: 0.7rem; text-transform: uppercase; letter-spacing: .08em; color: #6e7681; font-family: 'IBM Plex Mono', monospace; margin-bottom: .25rem; }
                .err-value    { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: .6rem .9rem; font-family: 'IBM Plex Mono', monospace; font-size: .82rem; white-space: pre-wrap; word-break: break-all; color: #e6edf3; }
                .err-hint     { background: rgba(56,139,253,.1); border: 1px solid rgba(56,139,253,.3); border-radius: 4px; padding: .75rem 1rem; font-size: .85rem; color: #79c0ff; margin-bottom: 1rem; }
                .btn-back     { border: 1px solid #30363d; color: #8b949e; background: transparent; border-radius: 4px; padding: .3rem .75rem; font-size: .85rem; text-decoration: none; }
                .btn-back:hover { background: #1c2128; color: #e6edf3; }
                a             { color: #388bfd; }
            </style>
        </head>
        <body>
        <div class="err-card">

        <cfoutput>
            <h2>&#9888; An error occurred</h2>

            <cfif len(hint)>
            <div class="err-hint">#hint#</div>
            </cfif>

            <cfif isAdmin>

            <div class="mb-3">
                <div class="err-label">Event</div>
                <div class="err-value">#htmlEditFormat(arguments.eventName)#</div>
            </div>

            <div class="mb-3">
                <div class="err-label">Message</div>
                <div class="err-value">#htmlEditFormat(arguments.exception.message)#</div>
            </div>

            <cfif len(trim(arguments.exception.detail))>
            <div class="mb-3">
                <div class="err-label">Detail</div>
                <div class="err-value">#htmlEditFormat(arguments.exception.detail)#</div>
            </div>
            </cfif>

            <cfif structKeyExists(arguments.exception, "queryError") AND len(trim(arguments.exception.queryError))>
            <div class="mb-3">
                <div class="err-label">Query Error</div>
                <div class="err-value">#htmlEditFormat(arguments.exception.queryError)#</div>
            </div>
            </cfif>

            <cfif structKeyExists(arguments.exception, "sql") AND len(trim(arguments.exception.sql))>
            <div class="mb-3">
                <div class="err-label">SQL</div>
                <div class="err-value">#htmlEditFormat(arguments.exception.sql)#</div>
            </div>
            </cfif>

            <cfif structKeyExists(arguments.exception, "stackTrace") AND len(trim(arguments.exception.stackTrace))>
            <div class="mb-3">
                <div class="err-label">Stack Trace</div>
                <div class="err-value" style="max-height:300px;overflow-y:auto;font-size:.75rem;">#htmlEditFormat(arguments.exception.stackTrace)#</div>
            </div>
            </cfif>

            <cfelse>
                <p style="color:#8b949e;">The error has been logged.
                   <a href="/admin/login.cfm">Sign in</a>
                   to see the full error details.</p>
            </cfif>

            <div class="mt-3">
                <a href="javascript:history.back()" class="btn-back">&#8592; Back</a>
                &nbsp;
                <a href="/admin/dashboard.cfm" class="btn-back">Dashboard</a>
            </div>
        </cfoutput>

        </div>
        </body>
        </html>

    </cffunction>

</cfcomponent>
