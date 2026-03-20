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

    <!---
        output="false" is REQUIRED here.
        With output="true" Lucee parses # everywhere in the function body —
        including inside <style> blocks — whether or not they are inside
        <cfoutput> tags.  Using output="false" + writeOutput() lets us
        write literal CSS hex colors without escaping them as ##.
    --->
    <cffunction name="onError" returntype="void" output="false">
        <cfargument name="exception" required="true">
        <cfargument name="eventName" type="string" required="true">

        <!--- Always log full detail server-side --->
        <cflog file="dmarc_errors"
               text="Error in #arguments.eventName#: #arguments.exception.message# | #arguments.exception.detail# | #arguments.exception.stackTrace#"
               type="error">

        <cfset local.isAdmin = structKeyExists(session, "loggedIn") AND session.loggedIn>

        <!--- Classify the error to give a useful hint --->
        <cfset local.hint = "">
        <cfif findNoCase("Unknown column", arguments.exception.message)
           OR findNoCase("doesn't exist", arguments.exception.message)
           OR (findNoCase("Table", arguments.exception.message) AND findNoCase("exist", arguments.exception.message))>
            <cfset local.hint = "This looks like a missing database table or column. Have you run all migrations? (<code>db/migrations/004_poller_tables.sql</code>)">
        <cfelseif findNoCase("Access denied", arguments.exception.message)>
            <cfset local.hint = "Database access denied. Check the credentials in <code>config/settings.cfm</code> and the MariaDB grant.">
        <cfelseif findNoCase("datasource", arguments.exception.message)
               OR findNoCase("No datasource", arguments.exception.message)>
            <cfset local.hint = "Lucee datasource not found. Verify the <code>dmarc</code> datasource is configured in the Lucee Web Admin.">
        <cfelseif findNoCase("decrypt", arguments.exception.message)
               OR findNoCase("encryptionKey", arguments.exception.message)>
            <cfset local.hint = "Encryption/decryption error. Check that <code>application.encryptionKey</code> is set correctly in <code>config/settings.cfm</code>.">
        </cfif>

        <!--- Static shell — no CFML expressions, so hex colors are safe --->
        <cfset writeOutput('<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Error &mdash; DMARC Dashboard</title>
<link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">
<style>
body      { background: #0d1117; color: #e6edf3; font-family: sans-serif; padding: 2rem; }
.err-card { background: #1c2128; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; max-width: 900px; margin: 2rem auto; }
.err-card h2 { color: #f85149; font-size: 1.1rem; margin-bottom: 1rem; }
.err-label   { font-size: 0.7rem; text-transform: uppercase; letter-spacing: .08em; color: #6e7681; font-family: monospace; margin-bottom: .25rem; }
.err-value   { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: .6rem .9rem; font-family: monospace; font-size: .82rem; white-space: pre-wrap; word-break: break-all; color: #e6edf3; max-height: 300px; overflow-y: auto; }
.err-hint    { background: rgba(56,139,253,.1); border: 1px solid rgba(56,139,253,.3); border-radius: 4px; padding: .75rem 1rem; font-size: .85rem; color: #79c0ff; margin-bottom: 1rem; }
.btn-back    { border: 1px solid #30363d; color: #8b949e; background: transparent; border-radius: 4px; padding: .3rem .75rem; font-size: .85rem; text-decoration: none; display: inline-block; margin-right: .5rem; }
a { color: #388bfd; }
</style>
</head>
<body>
<div class="err-card">
<h2>&#9888; An error occurred</h2>')>

        <!--- Hint --->
        <cfif len(local.hint)>
            <cfset writeOutput('<div class="err-hint">' & local.hint & '</div>')>
        </cfif>

        <cfif local.isAdmin>

            <!--- Event --->
            <cfset writeOutput('<div class="mb-3"><div class="err-label">Event</div><div class="err-value">'
                & htmlEditFormat(arguments.eventName)
                & '</div></div>')>

            <!--- Message --->
            <cfset writeOutput('<div class="mb-3"><div class="err-label">Message</div><div class="err-value">'
                & htmlEditFormat(arguments.exception.message)
                & '</div></div>')>

            <!--- Detail --->
            <cfif len(trim(arguments.exception.detail))>
                <cfset writeOutput('<div class="mb-3"><div class="err-label">Detail</div><div class="err-value">'
                    & htmlEditFormat(arguments.exception.detail)
                    & '</div></div>')>
            </cfif>

            <!--- QueryError --->
            <cfif structKeyExists(arguments.exception, "queryError") AND len(trim(arguments.exception.queryError))>
                <cfset writeOutput('<div class="mb-3"><div class="err-label">Query Error</div><div class="err-value">'
                    & htmlEditFormat(arguments.exception.queryError)
                    & '</div></div>')>
            </cfif>

            <!--- SQL --->
            <cfif structKeyExists(arguments.exception, "sql") AND len(trim(arguments.exception.sql))>
                <cfset writeOutput('<div class="mb-3"><div class="err-label">SQL</div><div class="err-value">'
                    & htmlEditFormat(arguments.exception.sql)
                    & '</div></div>')>
            </cfif>

            <!--- Stack trace --->
            <cfif structKeyExists(arguments.exception, "stackTrace") AND len(trim(arguments.exception.stackTrace))>
                <cfset writeOutput('<div class="mb-3"><div class="err-label">Stack Trace</div><div class="err-value">'
                    & htmlEditFormat(arguments.exception.stackTrace)
                    & '</div></div>')>
            </cfif>

        <cfelse>
            <cfset writeOutput('<p style="color:#8b949e;">The error has been logged.
                <a href="/admin/login.cfm">Sign in</a> to see full details.</p>')>
        </cfif>

        <!--- Nav buttons --->
        <cfset writeOutput('<div class="mt-3">
            <a href="javascript:history.back()" class="btn-back">&#8592; Back</a>
            <a href="/admin/dashboard.cfm" class="btn-back">Dashboard</a>
            </div></div></body></html>')>

    </cffunction>

</cfcomponent>
