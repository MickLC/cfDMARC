<!--- poller/msgdump.cfm
      Diagnostic: dump what cfimap getAll returns for a given UID.
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

writeOutput("columns: " & queryColumnList(qMsg) & "<br><br>");
writeOutput("subject: "   & htmlEditFormat(qMsg.subject)   & "<br>");
writeOutput("messageId: " & htmlEditFormat(qMsg.messageId) & "<br>");
writeOutput("body len: "  & len(qMsg.body)                & "<br>");

if (len(qMsg.body)) {
    bodyBytes = qMsg.body.getBytes("ISO-8859-1");
    hexStr = "";
    top = min(arrayLen(bodyBytes), 32);
    for (i = 1; i LTE top; i++) {
        b = bodyBytes[i];
        if (b LT 0) b = b + 256;
        hexStr &= right("0" & formatBaseN(b, 16), 2) & " ";
    }
    writeOutput("body first #top# bytes (hex): " & hexStr & "<br>");
}

writeOutput("attachments col: [" & htmlEditFormat(qMsg.attachments) & "]<br><br>");

qFiles = directoryList(attachDir, false, "query");
writeOutput("files in attachDir: " & qFiles.recordCount & "<br>");
for (f in qFiles) {
    writeOutput("  " & f.name & " (" & f.size & " bytes)<br>");
}

writeOutput("<br><b>header (first 1000 chars):</b><br><pre>");
writeOutput(htmlEditFormat(left(qMsg.header, 1000)));
writeOutput("</pre>");
</cfscript>
