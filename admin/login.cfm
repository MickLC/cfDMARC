<!--- admin/login.cfm --->
<cfinclude template="/includes/functions.cfm">
<cfparam name="url.redir"     default="/admin/dashboard.cfm">
<cfparam name="form.username" default="">
<cfparam name="form.password" default="">

<cfset variables.error = "">
<cfset variables.redir = url.redir>

<cfif structKeyExists(session, "loggedIn") AND session.loggedIn>
    <cflocation url="#variables.redir#" addtoken="false">
    <cfabort>
</cfif>

<cfif CGI.REQUEST_METHOD EQ "POST" AND len(trim(form.username)) AND len(trim(form.password))>
    <cfscript>
        var _user = queryExecute(
            "SELECT id, username, password_hash, active FROM users WHERE username = ? LIMIT 1",
            [ trim(form.username) ],
            { datasource: application.db.dsn }
        );

        if (_user.recordCount EQ 1 AND _user.active EQ 1
            AND verifyPassword(trim(form.password), _user.password_hash)) {

            var _token = generateToken(64);
            queryExecute(
                "INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at)
                 VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 8 HOUR))",
                [ _token, _user.id, left(CGI.REMOTE_ADDR,45), left(CGI.HTTP_USER_AGENT,512) ],
                { datasource: application.db.dsn }
            );
            queryExecute(
                "UPDATE users SET last_login = NOW() WHERE id = ?",
                [ _user.id ], { datasource: application.db.dsn }
            );
            session.loggedIn     = true;
            session.userId       = _user.id;
            session.username     = _user.username;
            session.sessionToken = _token;
            auditLog(action="login", detail="Successful login", userId=_user.id);
            location(url=variables.redir, addtoken=false);
            abort;
        } else {
            sleep(1200);
            variables.error = "Invalid username or password.";
            auditLog(action="login_failed", detail="Failed login for: #htmlEditFormat(form.username)#", userId=0);
        }
    </cfscript>
</cfif>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In — DMARC Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-primary:#0d1117; --bg-card:#1c2128; --border-color:#30363d;
            --text-primary:#e6edf3; --text-muted:#6e7681;
            --accent-blue:#388bfd; --accent-red:#f85149;
        }
        body { background:var(--bg-primary); color:var(--text-primary);
               font-family:'IBM Plex Sans',sans-serif; min-height:100vh;
               display:flex; align-items:center; justify-content:center; }
        .login-wrap { width:100%; max-width:360px; padding:1rem; }
        .login-brand { text-align:center; margin-bottom:2rem; }
        .login-brand .mono { font-family:'IBM Plex Mono',monospace; font-size:0.7rem;
                             text-transform:uppercase; letter-spacing:0.15em; color:var(--accent-blue); }
        .login-brand h1 { font-size:1.4rem; font-weight:300; color:var(--text-primary); margin:0.25rem 0 0; }
        .login-card { background:var(--bg-card); border:1px solid var(--border-color); border-radius:8px; padding:1.75rem; }
        .form-control { background:var(--bg-primary); border:1px solid var(--border-color); color:var(--text-primary); font-size:0.875rem; }
        .form-control:focus { background:var(--bg-primary); border-color:var(--accent-blue);
                              color:var(--text-primary); box-shadow:0 0 0 2px rgba(56,139,253,.2); }
        .form-label { font-size:0.8rem; color:#8b949e; margin-bottom:0.3rem; }
        .btn-signin { background:var(--accent-blue); border:none; color:#fff; width:100%;
                      padding:0.6rem; font-size:0.9rem; border-radius:4px; margin-top:0.5rem; }
        .btn-signin:hover { background:#58a6ff; }
        .error-msg { background:rgba(248,81,73,.1); border:1px solid rgba(248,81,73,.3);
                     color:#ffa198; border-radius:4px; padding:0.6rem 0.75rem; font-size:0.82rem; margin-bottom:1rem; }
        .login-footer { text-align:center; margin-top:1.5rem; font-size:0.72rem;
                        color:var(--text-muted); font-family:'IBM Plex Mono',monospace; }
    </style>
</head>
<body>
<div class="login-wrap">
    <div class="login-brand">
        <div class="mono">whizardries.com</div>
        <h1>DMARC Dashboard</h1>
    </div>
    <div class="login-card">
        <cfif len(variables.error)>
            <div class="error-msg"><cfoutput>#variables.error#</cfoutput></div>
        </cfif>
        <cfoutput>
        <form method="post" action="/admin/login.cfm?redir=#urlEncodedFormat(variables.redir)#" autocomplete="off">
            <div class="mb-3">
                <label class="form-label" for="username">Username</label>
                <input type="text" class="form-control" id="username" name="username"
                       value="#htmlEditFormat(form.username)#" autocomplete="username" required autofocus>
            </div>
            <div class="mb-3">
                <label class="form-label" for="password">Password</label>
                <input type="password" class="form-control" id="password" name="password"
                       autocomplete="current-password" required>
            </div>
            <button type="submit" class="btn btn-signin">Sign in</button>
        </form>
        </cfoutput>
    </div>
    <div class="login-footer">DMARC Dashboard &mdash; Administrative Access</div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/js/bootstrap.bundle.min.js"></script>
</body>
</html>
