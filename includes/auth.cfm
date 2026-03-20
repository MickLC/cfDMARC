<!--- includes/auth.cfm
      Include at the top of every protected page.
      Validates the session token against the database.
      Redirects to login if not authenticated.
--->
<cfscript>
    if (NOT structKeyExists(application, "db")) {
        include "/config/settings.cfm";
    }
    include "/includes/functions.cfm";

    var _authenticated = false;
    var _redirectTo    = CGI.SCRIPT_NAME;
    if (len(CGI.QUERY_STRING)) _redirectTo &= "?" & CGI.QUERY_STRING;

    if (structKeyExists(session, "loggedIn")
        AND session.loggedIn EQ true
        AND structKeyExists(session, "sessionToken")
        AND len(session.sessionToken)) {

        var _tokenCheck = queryExecute(
            "SELECT s.id, s.user_id, u.username
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.id = ?
               AND s.expires_at > NOW()
               AND u.active = 1",
            [ session.sessionToken ],
            { datasource: application.db.dsn }
        );

        if (_tokenCheck.recordCount EQ 1) {
            _authenticated = true;
            queryExecute(
                "UPDATE sessions SET last_active = NOW() WHERE id = ?",
                [ session.sessionToken ],
                { datasource: application.db.dsn }
            );
        } else {
            session.loggedIn     = false;
            session.userId       = "";
            session.username     = "";
            session.sessionToken = "";
        }
    }

    if (NOT _authenticated) {
        location(
            url  = "/admin/login.cfm?redir=" & urlEncodedFormat(_redirectTo),
            addToken = false
        );
        abort;
    }
</cfscript>
