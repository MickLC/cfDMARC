<!--- admin/logout.cfm --->
<cfinclude template="/includes/functions.cfm">
<cfscript>
    if (structKeyExists(session, "sessionToken") AND len(session.sessionToken)) {
        queryExecute(
            "DELETE FROM sessions WHERE id = ?",
            [ session.sessionToken ],
            { datasource: application.db.dsn }
        );
        auditLog(action="logout", detail="Session ended");
    }
    session.loggedIn     = false;
    session.userId       = "";
    session.username     = "";
    session.sessionToken = "";
    location(url="/admin/login.cfm", addtoken=false);
    abort;
</cfscript>
