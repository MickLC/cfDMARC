<!--- config/settings.example.cfm
      Copy to settings.cfm and fill in values.
      settings.cfm is gitignored and must never be committed.
--->
<cfscript>
    // ----------------------------------------------------------------
    // Database
    // ----------------------------------------------------------------
    application.db = {
        host     : "db.example.com",
        port     : 3306,
        name     : "dmarc",
        username : "dmarc_app",
        password : "CHANGE_ME",
        dsn      : "dmarc"          // Lucee datasource name — configure in Lucee admin
    };

    // ----------------------------------------------------------------
    // Security
    // ----------------------------------------------------------------
    // Pepper for password hashing.
    // Generate with: openssl rand -base64 32
    application.pepper = "CHANGE_ME_USE_ENV_VAR_DMARC_PEPPER";

    // AES key for encrypting IMAP passwords and OAuth tokens in DB.
    // Generate with: openssl rand -base64 32
    application.encryptionKey = "CHANGE_ME_USE_STRONG_RANDOM_KEY";

    application.sessionTimeout = createTimeSpan(0, 8, 0, 0);
    application.cookieName     = "DMARC_SESSION";

    // ----------------------------------------------------------------
    // Application
    // ----------------------------------------------------------------
    application.appName    = "DMARC Dashboard";
    application.appVersion = "1.0.0";
    application.baseURL    = "https://dmarc.example.com";  // no trailing slash
    application.adminEmail = "admin@example.com";

    // ----------------------------------------------------------------
    // Google OAuth2 (for Gmail IMAP accounts)
    // ----------------------------------------------------------------
    application.googleOAuth = {
        clientId     : "CHANGE_ME.apps.googleusercontent.com",
        clientSecret : "CHANGE_ME",
        redirectURI  : application.baseURL & "/admin/oauth_callback.cfm",
        scopes       : "https://mail.google.com/"
    };

    // ----------------------------------------------------------------
    // Poller
    // ----------------------------------------------------------------
    // token: shared secret passed as ?token= when calling poll.cfm.
    // Replaces IP-based access control (which breaks behind AJP/reverse-proxy).
    // Generate with: openssl rand -hex 32
    application.poller = {
        token        : "CHANGE_ME_RANDOM_HEX_TOKEN",
        markAsRead   : true,
        deleteAfter  : false,
        batchSize    : 50
    };
</cfscript>
