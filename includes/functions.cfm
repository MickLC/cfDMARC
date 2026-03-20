<!--- includes/functions.cfm
      Shared utility functions.
--->
<cfscript>

// ----------------------------------------------------------------
// Password hashing via GeneratePBKDFKey (PBKDF2WithHmacSHA256)
// Matches the approach used in cfblocklist which is proven to work.
// Hash format: iterations:salt:derived
// ----------------------------------------------------------------

function hashPassword(required string plaintext) {
    var pepper = structKeyExists(application, "pepper")
                 ? application.pepper
                 : environmentGet("DMARC_PEPPER", "");
    var salt       = generateSecretKey("AES", "256");
    var iterations = randRange(50000, 100000, "SHA1PRNG");
    var derived    = generatePBKDFKey(
        "PBKDF2WithHmacSHA256",
        arguments.plaintext,
        salt & pepper,
        iterations,
        256
    );
    return iterations & ":" & salt & ":" & derived;
}

function verifyPassword(required string plaintext, required string storedHash) {
    var pepper = structKeyExists(application, "pepper")
                 ? application.pepper
                 : environmentGet("DMARC_PEPPER", "");
    var parts      = listToArray(arguments.storedHash, ":");
    var iterations = val(parts[1]);
    var salt       = parts[2];
    var expected   = parts[3];
    var derived    = generatePBKDFKey(
        "PBKDF2WithHmacSHA256",
        arguments.plaintext,
        salt & pepper,
        iterations,
        256
    );
    // Constant-time comparison to prevent timing attacks
    var jMD = createObject("java", "java.security.MessageDigest");
    return jMD.isEqual(
        derived.getBytes("UTF-8"),
        expected.getBytes("UTF-8")
    );
}

// ----------------------------------------------------------------
// Encryption for stored credentials (IMAP passwords, OAuth tokens)
// ----------------------------------------------------------------

function encryptValue(required string plaintext) {
    if (NOT len(trim(arguments.plaintext))) return "";
    return encrypt(arguments.plaintext, application.encryptionKey, "AES/CBC/PKCS5Padding", "BASE64");
}

function decryptValue(required string ciphertext) {
    if (NOT len(trim(arguments.ciphertext))) return "";
    try {
        return decrypt(arguments.ciphertext, application.encryptionKey, "AES/CBC/PKCS5Padding", "BASE64");
    } catch(any e) {
        cflog(file="dmarc_errors", text="decryptValue failed: #e.message#", type="error");
        return "";
    }
}

// ----------------------------------------------------------------
// Session token generation
// ----------------------------------------------------------------

function generateToken(numeric length=64) {
    return lCase(toBase64(generateSecretKey("AES", arguments.length * 4)))
           .replaceAll("[^a-z0-9]", "")
           .left(arguments.length);
}

function hashToken(required string token) {
    return lCase(hash(arguments.token, "SHA-256"));
}

// ----------------------------------------------------------------
// Audit logging
// ----------------------------------------------------------------

function auditLog(
    required string action,
    string  detail  = "",
    numeric userId  = 0
) {
    // Resolve user ID — prefer explicit argument, then session, then NULL
    var hasUid = false;
    var uid    = 0;

    if (arguments.userId GT 0) {
        hasUid = true;
        uid    = arguments.userId;
    } else if (structKeyExists(session, "userId") AND isNumeric(session.userId) AND session.userId GT 0) {
        hasUid = true;
        uid    = session.userId;
    }

    var ip = len(CGI.REMOTE_ADDR) ? CGI.REMOTE_ADDR : "unknown";

    queryExecute(
        "INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?, ?, ?, ?)",
        [
            { value: uid,                         cfsqltype: "cf_sql_integer", null: NOT hasUid },
            { value: arguments.action,            cfsqltype: "cf_sql_varchar" },
            { value: left(arguments.detail, 512), cfsqltype: "cf_sql_varchar" },
            { value: left(ip, 45),                cfsqltype: "cf_sql_varchar" }
        ]
    );
}

// ----------------------------------------------------------------
// IP address helpers
// ----------------------------------------------------------------

function intToIPv4(required numeric ipInt) {
    var n = arguments.ipInt;
    return (bitAnd(bitSHRN(n,24), 255)) & "." &
           (bitAnd(bitSHRN(n,16), 255)) & "." &
           (bitAnd(bitSHRN(n,8),  255)) & "." &
           (bitAnd(n, 255));
}

function hexToIPv6(required string hexStr) {
    var h = uCase(arguments.hexStr);
    if (len(h) NEQ 32) return arguments.hexStr;
    var parts = [];
    for (var i = 1; i LTE 32; i += 4) {
        arrayAppend(parts, mid(h, i, 4));
    }
    return arrayToList(parts, ":");
}

function formatSourceIP(numeric ip=0, string ip6="") {
    if (len(trim(arguments.ip6))) return hexToIPv6(arguments.ip6);
    if (arguments.ip GT 0) return intToIPv4(arguments.ip);
    return "unknown";
}

// ----------------------------------------------------------------
// Formatting helpers
// ----------------------------------------------------------------

function formatNumber(required numeric n) {
    return numberFormat(arguments.n, "_,___");
}

function passRateBadgeClass(required numeric pct) {
    if (arguments.pct GTE 95) return "success";
    if (arguments.pct GTE 75) return "warning";
    return "danger";
}

function dispositionLabel(required string disposition) {
    switch(lCase(arguments.disposition)) {
        case "none":        return "Delivered";
        case "quarantine":  return "Quarantine";
        case "reject":      return "Reject";
        default:            return arguments.disposition;
    }
}

function truncate(required string str, numeric maxLen=50) {
    if (len(arguments.str) LTE arguments.maxLen) return arguments.str;
    return left(arguments.str, arguments.maxLen - 3) & "...";
}

function timeAgo(required date dt) {
    var diffSeconds = dateDiff("s", arguments.dt, now());
    if (diffSeconds LT 60)    return diffSeconds & "s ago";
    if (diffSeconds LT 3600)  return int(diffSeconds/60) & "m ago";
    if (diffSeconds LT 86400) return int(diffSeconds/3600) & "h ago";
    return int(diffSeconds/86400) & "d ago";
}

</cfscript>
