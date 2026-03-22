<!--- admin/backfill_records.cfm
      One-time tool to backfill rptrecord rows for all report rows that
      have raw_reports XML but 0 associated rptrecord rows.

      This repairs the historical dataset affected by the XmlName case bug:
      Lucee returns XmlName in uppercase, so "child.XmlName NEQ 'record'"
      never matched, silently skipping every record element and writing
      "inserted 0 record row(s)" for every report since the poller launched.

      Safe to re-run: skips any report that already has rptrecord rows.
      Processes in batches to avoid request timeouts on large backlogs.
      Keep clicking "Continue" until it reports nothing left to process.

      Access: admin session required (same as all other admin pages).
--->
<cfinclude template="/includes/auth_check.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    param name="url.offset"    default="0"  type="numeric";
    param name="url.batchSize" default="50" type="numeric";

    // Clamp batch size: min 1, max 200
    batchSize = max(1, min(200, url.batchSize));
    offset    = max(0, url.offset);

    // -----------------------------------------------------------------------
    // getNodeText - identical to parse_rua.cfm; inline here so this page
    // is self-contained and won't be affected by future changes to the poller.
    // -----------------------------------------------------------------------
    function getNodeText(required any xmlNode, required string path, string defaultVal="") {
        try {
            var parts   = listToArray(arguments.path, ".");
            var current = arguments.xmlNode;
            for (var part in parts) {
                if (NOT structKeyExists(current, part)) return arguments.defaultVal;
                current = current[part];
            }
            if (isStruct(current) AND structKeyExists(current, "XmlText")) return trim(current.XmlText);
            return arguments.defaultVal;
        } catch(any e) { return arguments.defaultVal; }
    }

    // -----------------------------------------------------------------------
    // Count total reports that still need backfilling.
    // A report "needs backfilling" if it has raw_reports content but has
    // no rows in rptrecord.  We re-count on every batch so the display
    // accurately reflects what was already completed in prior batches.
    // -----------------------------------------------------------------------
    qTotalNeeded = queryExecute(
        "SELECT COUNT(*) AS cnt
         FROM   report r
         WHERE  r.raw_reports IS NOT NULL
           AND  r.raw_reports <> ''
           AND  NOT EXISTS (
                    SELECT 1 FROM rptrecord rr WHERE rr.report_id = r.serial
                )",
        {},
        { datasource: application.db.dsn }
    );
    totalNeeded = qTotalNeeded.cnt;

    // -----------------------------------------------------------------------
    // Fetch this batch of reports to process.
    // -----------------------------------------------------------------------
    qBatch = queryExecute(
        "SELECT r.serial, r.domain, r.org, r.raw_reports
         FROM   report r
         WHERE  r.raw_reports IS NOT NULL
           AND  r.raw_reports <> ''
           AND  NOT EXISTS (
                    SELECT 1 FROM rptrecord rr WHERE rr.report_id = r.serial
                )
         ORDER  BY r.serial ASC
         LIMIT  ? OFFSET ?",
        [
            { value: batchSize, cfsqltype: "cf_sql_integer" },
            { value: offset,    cfsqltype: "cf_sql_integer" }
        ],
        { datasource: application.db.dsn }
    );

    batchCount  = qBatch.recordCount;
    cntOk       = 0;
    cntFail     = 0;
    failDetails = [];

    // -----------------------------------------------------------------------
    // Process each report in the batch.
    // -----------------------------------------------------------------------
    for (row in qBatch) {

        try {
            // Strip UTF-8 BOM if present (same fix as parse_rua.cfm)
            xmlStr = row.raw_reports;
            if (len(xmlStr) AND asc(left(xmlStr, 1)) EQ 65279) {
                xmlStr = mid(xmlStr, 2, len(xmlStr) - 1);
            }

            rpt = xmlParse(xmlStr);
            fb  = rpt.feedback;

            records     = fb.xmlChildren;
            recInserted = 0;

            for (child in records) {
                // lCase() required: Lucee returns XmlName in uppercase
                if (lCase(child.XmlName) NEQ "record") continue;

                rec = child;

                sourceIP      = getNodeText(rec, "row.source_ip");
                rcount        = val(getNodeText(rec, "row.count", "0"));
                disposition   = getNodeText(rec, "row.policy_evaluated.disposition", "none");
                dkimAlign     = getNodeText(rec, "row.policy_evaluated.dkim",        "fail");
                spfAlign      = getNodeText(rec, "row.policy_evaluated.spf",         "fail");
                reasonType    = getNodeText(rec, "row.policy_evaluated.reason.type");
                reasonComment = getNodeText(rec, "row.policy_evaluated.reason.comment");
                hFrom         = getNodeText(rec, "identifiers.header_from");
                dkimDomain    = getNodeText(rec, "auth_results.dkim.domain");
                dkimResult    = getNodeText(rec, "auth_results.dkim.result");
                spfDomain     = getNodeText(rec, "auth_results.spf.domain");
                spfResult     = getNodeText(rec, "auth_results.spf.result");

                isIPv6addr = find(":", sourceIP) GT 0;
                ipColSQL   = isIPv6addr ? "ip6"           : "ip";
                ipValSQL   = isIPv6addr ? "INET6_ATON(?)" : "INET_ATON(?)";

                optCols   = "";
                optVals   = "";
                optParams = [];

                if (len(reasonType))    { optCols &= ", reason";     optVals &= ", ?"; arrayAppend(optParams, { value: left(reasonType,100),    cfsqltype: "cf_sql_varchar" }); }
                if (len(reasonComment)) { optCols &= ", comment";    optVals &= ", ?"; arrayAppend(optParams, { value: left(reasonComment,255), cfsqltype: "cf_sql_varchar" }); }
                if (len(dkimDomain))    { optCols &= ", dkimdomain"; optVals &= ", ?"; arrayAppend(optParams, { value: left(dkimDomain,253),    cfsqltype: "cf_sql_varchar" }); }
                if (len(dkimResult))    { optCols &= ", dkimresult"; optVals &= ", ?"; arrayAppend(optParams, { value: left(dkimResult,20),     cfsqltype: "cf_sql_varchar" }); }
                if (len(spfDomain))     { optCols &= ", spfdomain";  optVals &= ", ?"; arrayAppend(optParams, { value: left(spfDomain,253),     cfsqltype: "cf_sql_varchar" }); }
                if (len(spfResult))     { optCols &= ", spfresult";  optVals &= ", ?"; arrayAppend(optParams, { value: left(spfResult,20),      cfsqltype: "cf_sql_varchar" }); }

                baseParams = [
                    { value: row.serial,               cfsqltype: "cf_sql_integer" },
                    { value: sourceIP,                 cfsqltype: "cf_sql_varchar" },
                    { value: rcount,                   cfsqltype: "cf_sql_integer" },
                    { value: left(disposition,20),     cfsqltype: "cf_sql_varchar" },
                    { value: left(spfAlign,10),        cfsqltype: "cf_sql_varchar" },
                    { value: left(dkimAlign,10),       cfsqltype: "cf_sql_varchar" },
                    { value: left(hFrom,253),          cfsqltype: "cf_sql_varchar" }
                ];

                queryExecute(
                    "INSERT INTO rptrecord
                         (report_id, #ipColSQL#, rcount, disposition,
                          spf_align, dkim_align, identifier_hfrom
                          #optCols#)
                     VALUES
                         (?, #ipValSQL#, ?, ?,
                          ?, ?, ?
                          #optVals#)",
                    arrayMerge(baseParams, optParams),
                    { datasource: application.db.dsn }
                );

                recInserted++;
            }

            cntOk++;

        } catch(any e) {
            cntFail++;
            arrayAppend(failDetails, {
                serial : row.serial,
                org    : row.org,
                domain : row.domain,
                error  : left(e.message, 200)
            });
        }
    }

    remaining   = totalNeeded - batchCount; // what's still left after this batch
    nextOffset  = offset + batchSize;
    isDone      = (batchCount EQ 0);
</cfscript>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Backfill rptrecord — DMARC Admin</title>
    <cfinclude template="/includes/head_css.cfm">
    <style>
        .bf-card   { background: rgb(22,27,34); border: 1px solid rgb(48,54,61); border-radius: 8px; padding: 1.5rem; max-width: 860px; margin: 1.5rem auto; }
        .bf-title  { font-size: 1.1rem; font-weight: 600; margin-bottom: .25rem; }
        .bf-sub    { font-size: .82rem; color: rgb(110,118,129); margin-bottom: 1.2rem; }
        .stat-row  { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.2rem; }
        .stat      { flex: 1; min-width: 120px; background: rgb(13,17,23); border: 1px solid rgb(48,54,61); border-radius: 6px; padding: .75rem 1rem; text-align: center; }
        .stat-n    { font-size: 1.6rem; font-weight: 700; line-height: 1.1; }
        .stat-l    { font-size: .72rem; color: rgb(110,118,129); text-transform: uppercase; letter-spacing: .06em; margin-top: .2rem; }
        .ok        { color: rgb(63,185,80); }
        .warn      { color: rgb(210,153,34); }
        .err       { color: rgb(248,81,73); }
        .neu       { color: rgb(139,148,158); }
        .btn       { display: inline-block; padding: .5rem 1.2rem; border-radius: 6px; font-size: .9rem; font-weight: 600; text-decoration: none; cursor: pointer; border: none; }
        .btn-go    { background: rgb(35,134,54); color: #fff; margin-right: .5rem; }
        .btn-go:hover { background: rgb(46,160,67); }
        .btn-dash  { background: transparent; border: 1px solid rgb(48,54,61); color: rgb(139,148,158); }
        .btn-dash:hover { border-color: rgb(110,118,129); color: rgb(230,237,243); }
        .done-msg  { color: rgb(63,185,80); font-size: 1rem; font-weight: 600; padding: .75rem 0; }
        .fail-tbl  { width: 100%; border-collapse: collapse; font-size: .8rem; margin-top: .75rem; }
        .fail-tbl th { text-align: left; color: rgb(110,118,129); padding: .3rem .5rem; border-bottom: 1px solid rgb(48,54,61); font-weight: 500; }
        .fail-tbl td { padding: .3rem .5rem; border-bottom: 1px solid rgb(33,38,45); color: rgb(230,237,243); font-family: monospace; vertical-align: top; }
        .fail-tbl td:last-child { color: rgb(248,81,73); word-break: break-word; }
        .section-hd { font-size: .72rem; text-transform: uppercase; letter-spacing: .08em; color: rgb(110,118,129); margin: 1rem 0 .4rem; }
        .bs-form   { display: inline-flex; align-items: center; gap: .5rem; margin-left: 1rem; font-size: .82rem; color: rgb(110,118,129); }
        .bs-form input { width: 60px; background: rgb(13,17,23); border: 1px solid rgb(48,54,61); color: rgb(230,237,243); border-radius: 4px; padding: .25rem .5rem; font-size: .82rem; }
    </style>
</head>
<body>
<cfinclude template="/includes/nav.cfm">

<div class="bf-card">
    <div class="bf-title">Backfill rptrecord rows</div>
    <div class="bf-sub">
        Repairs reports affected by the XmlName case bug — every report inserted before the fix
        has a header row but 0 record rows. This tool re-parses <code>raw_reports</code> and
        inserts the missing <code>rptrecord</code> rows. Safe to re-run; already-complete reports
        are skipped automatically.
    </div>

    <cfif isDone>

        <div class="done-msg">&#10003; Nothing left to backfill — all reports with raw XML have record rows.</div>
        <div style="margin-top:1rem;">
            <a href="/admin/dashboard.cfm" class="btn btn-dash">&#8592; Dashboard</a>
        </div>

    <cfelse>

        <!--- Stats for this batch --->
        <div class="stat-row">
            <div class="stat">
                <div class="stat-n neu"><cfoutput>#numberFormat(totalNeeded)#</cfoutput></div>
                <div class="stat-l">Needed (start of batch)</div>
            </div>
            <div class="stat">
                <div class="stat-n neu"><cfoutput>#batchCount#</cfoutput></div>
                <div class="stat-l">Processed this batch</div>
            </div>
            <div class="stat">
                <div class="stat-n ok"><cfoutput>#cntOk#</cfoutput></div>
                <div class="stat-l">Backfilled OK</div>
            </div>
            <div class="stat">
                <div class="stat-n err"><cfoutput>#cntFail#</cfoutput></div>
                <div class="stat-l">Parse errors</div>
            </div>
            <div class="stat">
                <div class="stat-n <cfoutput>#remaining GT 0 ? 'warn' : 'ok'#</cfoutput>"><cfoutput>#numberFormat(remaining)#</cfoutput></div>
                <div class="stat-l">Still remaining</div>
            </div>
        </div>

        <!--- Failures --->
        <cfif arrayLen(failDetails)>
            <div class="section-hd">Parse failures this batch (raw_reports XML was unparseable — these rows will be skipped on future runs)</div>
            <table class="fail-tbl">
                <thead><tr><th>ID</th><th>Org</th><th>Domain</th><th>Error</th></tr></thead>
                <tbody>
                <cfloop array="#failDetails#" item="f">
                    <tr>
                        <td><cfoutput>#f.serial#</cfoutput></td>
                        <td><cfoutput>#htmlEditFormat(f.org)#</cfoutput></td>
                        <td><cfoutput>#htmlEditFormat(f.domain)#</cfoutput></td>
                        <td><cfoutput>#htmlEditFormat(f.error)#</cfoutput></td>
                    </tr>
                </cfloop>
                </tbody>
            </table>
            <p style="font-size:.78rem;color:rgb(110,118,129);margin-top:.5rem;">
                Parse failures are not retried automatically. If you need those reports you will
                need to re-ingest from the original email attachments.
            </p>
        </cfif>

        <!--- Continue / done --->
        <div style="margin-top:1.2rem;display:flex;align-items:center;flex-wrap:wrap;gap:.5rem;">
            <cfif remaining GT 0>
                <a href="/admin/backfill_records.cfm?offset=<cfoutput>#nextOffset#</cfoutput>&batchSize=<cfoutput>#batchSize#</cfoutput>"
                   class="btn btn-go">Continue &#8594; (<cfoutput>#numberFormat(remaining)#</cfoutput> remaining)</a>
            <cfelse>
                <div class="done-msg">&#10003; Backfill complete — no more reports to process.</div>
            </cfif>
            <a href="/admin/dashboard.cfm" class="btn btn-dash">&#8592; Dashboard</a>
            <form method="get" action="/admin/backfill_records.cfm" style="display:inline;">
                <input type="hidden" name="offset" value="0">
                <span class="bs-form">
                    Batch size: <input type="number" name="batchSize" value="<cfoutput>#batchSize#</cfoutput>" min="1" max="200">
                    <button type="submit" class="btn btn-dash" style="padding:.25rem .7rem;font-size:.8rem;">Restart</button>
                </span>
            </form>
        </div>

    </cfif>
</div>

</body>
</html>
