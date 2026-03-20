<!--- admin/setup.cfm
      First-run setup: creates the initial admin user.
      DELETE THIS FILE after running it once.
--->
<cfinclude template="/includes/functions.cfm">
<cfparam name="form.username" default="">
<cfparam name="form.email"    default="">
<cfparam name="form.password" default="">
<cfparam name="form.confirm"  default="">
<cfset variables.error   = "">
<cfset variables.success = "">
<cfset variables.done    = false>
<cfscript>
    _userCount = queryExecute("SELECT COUNT(*) AS cnt FROM users", {}, { datasource: application.db.dsn });
    if (_userCount.cnt GT 0) {
        variables.error = "Setup has already been completed. Delete this file from the server.";
        variables.done  = true;
    }
</cfscript>
<cfif CGI.REQUEST_METHOD EQ "POST" AND NOT variables.done>
    <cfscript>
        errs = [];
        if (NOT len(trim(form.username)))           arrayAppend(errs, "Username is required.");
        if (NOT len(trim(form.email)))              arrayAppend(errs, "Email is required.");
        if (len(trim(form.password)) LT 12)         arrayAppend(errs, "Password must be at least 12 characters.");
        if (form.password NEQ form.confirm)         arrayAppend(errs, "Passwords do not match.");
        if (NOT isValid("email", trim(form.email))) arrayAppend(errs, "Invalid email address.");
        if (arrayLen(errs) EQ 0) {
            _hash = hashPassword(trim(form.password));
            queryExecute(
                "INSERT INTO users (username, email, password_hash, active) VALUES (?, ?, ?, 1)",
                [ trim(form.username), trim(form.email), _hash ],
                { datasource: application.db.dsn }
            );
            auditLog(action="setup", detail="Initial admin user created: #trim(form.username)#", userId=0);
            variables.success = "Admin user '#htmlEditFormat(trim(form.username))#' created. Delete this file now.";
            variables.done    = true;
        } else {
            variables.error = arrayToList(errs, "<br>");
        }
    </cfscript>
</cfif>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup — DMARC Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root{--bg-primary:#0d1117;--bg-card:#1c2128;--border-color:#30363d;--text-primary:#e6edf3;--text-muted:#6e7681;--accent-blue:#388bfd;}
        body{background:var(--bg-primary);color:var(--text-primary);font-family:'IBM Plex Sans',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;}
        .setup-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:2rem;width:100%;max-width:400px;}
        .form-control{background:var(--bg-primary);border:1px solid var(--border-color);color:var(--text-primary);}
        .form-control:focus{background:var(--bg-primary);border-color:var(--accent-blue);color:var(--text-primary);box-shadow:0 0 0 2px rgba(56,139,253,.2);}
        .form-label{font-size:0.8rem;color:#8b949e;}
        .btn-primary{background:var(--accent-blue);border:none;width:100%;padding:.6rem;}
        .error-msg{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);color:#ffa198;border-radius:4px;padding:.6rem .75rem;font-size:.82rem;margin-bottom:1rem;}
        .success-msg{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.3);color:#7ee787;border-radius:4px;padding:.6rem .75rem;font-size:.82rem;}
        h2{font-size:1.1rem;font-weight:500;margin-bottom:1.5rem;}
        .warn-box{background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.3);color:#e3b341;border-radius:4px;padding:.6rem .75rem;font-size:.78rem;margin-bottom:1rem;}
    </style>
</head>
<body>
<div class="setup-card">
    <div style="font-family:'IBM Plex Mono',monospace;font-size:.65rem;text-transform:uppercase;letter-spacing:.15em;color:var(--accent-blue);margin-bottom:.5rem;">DMARC Dashboard</div>
    <h2>Initial Setup</h2>
    <cfif len(variables.error)><div class="error-msg"><cfoutput>#variables.error#</cfoutput></div></cfif>
    <cfif len(variables.success)>
        <div class="success-msg"><cfoutput>#variables.success#</cfoutput></div>
        <a href="/admin/login.cfm" class="btn btn-primary mt-3">Go to Login</a>
    <cfelseif NOT variables.done>
        <div class="warn-box"><strong>⚠ Delete this file</strong> from the server after creating your admin account.</div>
        <form method="post">
            <div class="mb-3"><label class="form-label">Username</label>
                <input type="text" class="form-control" name="username" value="<cfoutput>#htmlEditFormat(form.username)#</cfoutput>" required></div>
            <div class="mb-3"><label class="form-label">Email</label>
                <input type="email" class="form-control" name="email" value="<cfoutput>#htmlEditFormat(form.email)#</cfoutput>" required></div>
            <div class="mb-3"><label class="form-label">Password (min 12 chars)</label>
                <input type="password" class="form-control" name="password" required></div>
            <div class="mb-3"><label class="form-label">Confirm Password</label>
                <input type="password" class="form-control" name="confirm" required></div>
            <button type="submit" class="btn btn-primary">Create Admin Account</button>
        </form>
    </cfif>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/js/bootstrap.bundle.min.js"></script>
</body></html>
