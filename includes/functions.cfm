<!--- includes/functions.cfm
      Shared utility functions.
--->
<cfscript>

// ----------------------------------------------------------------
// Password hashing via BCrypt (work factor 12)
// BCrypt is available in Lucee via the bundled Spring Security crypto jar.
// The pepper is prepended before hashing for defence in depth.
// ----------------------------------------------------------------

function hashPassword(required string plaintext) {
    var pepper = structKeyExists(application, "pepper")
                 ? application.pepper
                 : environmentGet("DMARC_PEPPER", "");
    var salted = pepper & arguments.plaintext;
    var encoder = createObject("java", "org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder")
                    .init(javaCast("int", 12));
    return encoder.encode(javaCast("string", salted));
}

function verifyPassword(required string plaintext, required string storedHash) {
    var pepper = structKeyExists(application, "pepper")
                 ? application.pepper
                 : environmentGet("DMARC_PEPPER", "");
    var salted = pepper & arguments.plaintext;
    var encoder = createObject("java", "org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder")
                    .init(javaCast("int", 12));
    return encoder.matches(javaCast("string", salted), javaCast("string", arguments.storedHash));
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
    string detail   = "",
    numeric userId  = 0
) {
    var uid = arguments.userId GT 0
              ? arguments.userId
              : (structKeyExists(session, "userId") ? session.userId : javaCast("null", ""));
    var ip = CGI.REMOTE_ADDR ?: "unknown";
    queryExecute(
        "INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?, ?, ?, ?)",
        [
            { value: isNull(uid) ? javaCast("null","") : uid, null: isNull(uid) },
            arguments.action,
            left(arguments.detail, 512),
            left(ip, 45)
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
