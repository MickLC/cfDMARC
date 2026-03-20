<!--- config/settings.example.cfm
      Copy to settings.cfm and fill in values.
      settings.cfm is gitignored and must never be committed.
--->
<cfscript>
    // ----------------------------------------------------------------
    // Database
    // ----------------------------------------------------------------
    application.db = {
        host     : "gandalf.whizardries.com",
        port     : 3306,
        name     : "dmarc",
        username : "dmarc_app",
        password : "CHANGE_ME",
        dsn      : "dmarc"        // Lucee datasource name — configure in Lucee admin
    };

    // ----------------------------------------------------------------
    // Security
    // ----------------------------------------------------------------
    // Pepper for password hashing.
    // Reads from environment variable DMARC_PEPPER first,
    // falls back to the value below.
    // Generate with: openssl rand -base64 32
    application.pepper = "CHANGE_ME_USE_ENV_VAR_DMARC_PEPPER";

    // AES key for encrypting IMAP passwords and OAuth tokens in DB.
    // Generate with: openssl rand -base64 32
    application.encryptionKey = "CHANGE_ME_USE_STRONG_RANDOM_KEY";

    // Session settings
    application.sessionTimeout  = createTimeSpan(0, 8, 0, 0); // 8 hours
    application.cookieName      = "DMARC_SESSION";

    // ----------------------------------------------------------------
    // Application
    // ----------------------------------------------------------------
    application.appName    = "DMARC Dashboard";
    application.appVersion = "1.0.0";
    application.baseURL    = "https://dmarc.whizardries.com";
    application.adminEmail = "admin@whizardries.com";

    // ----------------------------------------------------------------
    // Google OAuth2 (for Gmail IMAP accounts)
    // ----------------------------------------------------------------
    // Create at https://console.cloud.google.com
    // These are defaults — can be overridden per imap_account row.
    application.googleOAuth = {
        clientId     : "CHANGE_ME.apps.googleusercontent.com",
        clientSecret : "CHANGE_ME",
        redirectURI  : application.baseURL & "/admin/oauth_callback.cfm",
        scopes       : "https://mail.google.com/"
    };

    // ----------------------------------------------------------------
    // Poller
    // ----------------------------------------------------------------
    application.poller = {
        markAsRead   : true,    // mark processed messages read in IMAP
        deleteAfter  : false,   // never delete — leave mail management to you
        batchSize    : 50       // max messages to process per poll run
    };
</cfscript>
