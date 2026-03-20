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

        <cflog file="dmarc_errors"
               text="Error in #arguments.eventName#: #arguments.exception.message# | #arguments.exception.detail#"
               type="error">

        <!--- Don't expose internals --->
        <cfoutput>
        <!DOCTYPE html>
        <html lang="en">
        <head><title>Error — DMARC Dashboard</title></head>
        <body style="font-family:monospace;padding:2rem;">
            <h2>An error occurred.</h2>
            <p>The error has been logged. Please try again or contact the administrator.</p>
            <cfif structKeyExists(session, "loggedIn") AND session.loggedIn>
                <pre>#htmlEditFormat(arguments.exception.message)#
#htmlEditFormat(arguments.exception.detail)#</pre>
            </cfif>
        </body>
        </html>
        </cfoutput>
    </cffunction>

</cfcomponent>
