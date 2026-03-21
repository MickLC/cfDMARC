<!--- poller/msgdump.cfm
      Diagnostic: dump what cfimap getAll returns for a given message UID.
      Usage: /poller/msgdump.cfm?token=TOKEN&uid=1
      DELETE THIS FILE after debugging.
--->
<cfinclude template="/includes/functions.cfm">
<cfscript>
param name="url.token" default="";
param name="url.uid"   default="1";

if (NOT structKeyExists(application,"poller")
    OR url.token NEQ application.poller.token) {
    cfheader(statusCode=403, statusText="Forbidden");
    cfabort();
}

q = queryExecute("SELECT * FROM imap_accounts WHERE active=1 LIMIT 1",
    {}, {datasource:application.db.dsn});
if (NOT q.recordCount) { writeOutput("no account"); cfabort(); }

pwd = decryptValue(q.password);
attachDir = getTempDirectory() & "msgdump/";
if (NOT directoryExists(attachDir)) directoryCreate(attachDir);

cfimap(action="open", connection="dump_conn", server=q.host, port=q.port,
       username=q.username, password=pwd,
       secure=(q.use_ssl?true:false), timeout=60);

cfimap(action="getAll", connection="dump_conn", folder=q.mailbox,
       uid=url.uid, attachmentPath=attachDir,
       generateUniqueFilenames=true, name="qMsg");

cfimap(action="close", connection="dump_conn");

writeOutput("<h3>getAll result columns:</h3><pre>");
writeOutput(htmlEditFormat(structKeyList(qMsg.getMetadata())));
writeOutput("</pre>");

writeOutput("<b>subject:</b> " & htmlEditFormat(qMsg.subject) & "<br>");
writeOutput("<b>messageId:</b> " & htmlEditFormat(qMsg.messageId) & "<br>");
writeOutput("<b>body length:</b> " & len(qMsg.body) & "<br>");
writeOutput("<b>body (first 200 bytes as hex):</b><br>");
if (len(qMsg.body)) {
    bodyBytes = qMsg.body.getBytes("ISO-8859-1");
    hexStr = "";
    for (i=1; i LTE min(arrayLen(bodyBytes),200); i++) {
        b = bodyBytes[i];
        if (b LT 0) b = b + 256;
        hexStr &= right("0" & formatBaseN(b,16), 2) & " ";
    }
    writeOutput("<pre>" & hexStr & "</pre>");
}

writeOutput("<b>attachments column:</b> [" & htmlEditFormat(qMsg.attachments) & "]<br>");

qFiles = directoryList(attachDir, false, "query");
writeOutput("<b>files saved to attachDir (" & attachDir & "):</b> " & qFiles.recordCount & "<br>");
for (f in qFiles) {
    writeOutput("  " & f.name & " (" & f.size & " bytes)<br>");
}

writeOutput("<hr><b>header (first 800 chars):</b><pre>");
writeOutput(htmlEditFormat(left(qMsg.header, 800)));
writeOutput("</pre>");
</cfscript>
