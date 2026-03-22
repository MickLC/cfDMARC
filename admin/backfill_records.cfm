<!--- admin/backfill_records.cfm
      One-time tool to backfill rptrecord rows for all report rows that
      have raw_reports XML but 0 associated rptrecord rows.

      This repairs the historical dataset affected by the XmlName case bug:
      Lucee returns XmlName in uppercase, so "child.XmlName NEQ 'record'"
      never matched, silently skipping every record element and writing
      "inserted 0 record row(s)" for every report since the poller launched.

      Safe to re-run: skips any report that already has rptrecord rows.
      Reports with no <record> elements (e.g. Microsoft metadata-only
      reports) will count as processed but insert 0 rows — this is correct.
      Keep clicking "Continue" until it reports nothing left to process.

      Access: admin session required (same as all other admin pages).
--->
<cfinclude template="/includes/auth.cfm">

<cfscript>
    param name="url.offset"    default="0"  type="numeric";
    param name="url.batchSize" default="50" type="numeric";

    // Clamp batch size: min 1, max 200
    batchSize = max(1, min(200, url.batchSize));
    offset    = max(0, url.offset);

    // -----------------------------------------------------------------------
    // getNodeText — identical to parse_rua.cfm; inline here so this page
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
    // -----------------------------------------------------------------------
    qTotalNeeded = queryExecute(
        "SELECT COUNT(*) AS cnt
         FROM   report r
         WHERE  r.raw_reports IS NOT NULL
           AND  r.raw_reports <> ''
           AND  NOT EXISTS (
                    SELECT 1 FROM rptrecord rr WHERE rr.report_id = r.id
                )",
        {},
        { datasource: application.db.dsn }
    );
    totalNeeded = qTotalNeeded.cnt;

    // -----------------------------------------------------------------------
    // Fetch this batch.
    // -----------------------------------------------------------------------
    qBatch = queryExecute(
        "SELECT r.id, r.domain, r.org, r.raw_reports
         FROM   report r
         WHERE  r.raw_reports IS NOT NULL
           AND  r.raw_reports <> ''
           AND  NOT EXISTS (
                    SELECT 1 FROM rptrecord rr WHERE rr.report_id = r.id
                )
         ORDER  BY r.id ASC
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
    // The outer try/catch catches true failures: XML that cannot be parsed
    // at all. A DB error on one record (bad sender data) is caught by an
    // inner try/catch and skips only that record, not the whole report.
    // -----------------------------------------------------------------------
    for (row in qBatch) {

        try {
            // Strip UTF-8 BOM if present
            xmlStr = row.raw_reports;
            if (len(xmlStr) AND asc(left(xmlStr, 1)) EQ 65279) {
                xmlStr = mid(xmlStr, 2, len(xmlStr) - 1);
            }

            rpt = xmlParse(xmlStr);
            fb  = rpt.feedback;

            recInserted = 0;
            recSkipped  = 0;

            for (child in fb.xmlChildren) {
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
                if (len(dkimResult))    { optCols &= ", dkimresult"; optVals &= ", ?"; arrayAppend(optParams, { value: left(dkimResult,50),     cfsqltype: "cf_sql_varchar" }); }
                if (len(spfDomain))     { optCols &= ", spfdomain";  optVals &= ", ?"; arrayAppend(optParams, { value: left(spfDomain,253),     cfsqltype: "cf_sql_varchar" }); }
                if (len(spfResult))     { optCols &= ", spfresult";  optVals &= ", ?"; arrayAppend(optParams, { value: left(spfResult,50),      cfsqltype: "cf_sql_varchar" }); }

                baseParams = [
                    { value: row.id,               cfsqltype: "cf_sql_integer" },
                    { value: sourceIP,             cfsqltype: "cf_sql_varchar" },
                    { value: rcount,               cfsqltype: "cf_sql_integer" },
                    { value: left(disposition,20), cfsqltype: "cf_sql_varchar" },
                    { value: left(spfAlign,10),    cfsqltype: "cf_sql_varchar" },
                    { value: left(dkimAlign,10),   cfsqltype: "cf_sql_varchar" },
                    { value: left(hFrom,253),      cfsqltype: "cf_sql_varchar" }
                ];

                try {
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
                } catch(any recErr) {
                    recSkipped++;
                }
            }

            cntOk++;

        } catch(any e) {
            cntFail++;
            arrayAppend(failDetails, {
                id     : row.id,
                org    : row.org,
                domain : row.domain,
                error  : left(e.message, 200)
            });
        }
    }

    remaining  = totalNeeded - batchCount;
    nextOffset = offset + batchSize;
    isDone     = (batchCount EQ 0);

    variables.pageTitle = "Backfill rptrecord";
    variables.activeNav = "";
</cfscript>

<cfinclude template="/includes/header.cfm">

<style>
    .bf-intro  { font-size: .85rem; color: var(--text-secondary); margin-bottom: 1.25rem; max-width: 720px; }
    .stat-row  { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.25rem; }
    .stat-tile { flex: 1; min-width: 120px; }
    .done-msg  { color: var(--accent-green); font-size: 1rem; font-weight: 600; padding: .5rem 0 1rem; }
    .fail-tbl  { width: 100%; border-collapse: collapse; font-size: .8rem; margin-top: .5rem; }
    .fail-tbl th { text-align: left; color: var(--text-muted); padding: .35rem .5rem; border-bottom: 1px solid var(--border-color); font-weight: 500; font-family: var(--font-mono); font-size: .7rem; text-transform: uppercase; letter-spacing: .06em; }
    .fail-tbl td { padding: .35rem .5rem; border-bottom: 1px solid var(--border-color); color: var(--text-primary); font-family: var(--font-mono); font-size: .78rem; vertical-align: top; word-break: break-word; }
    .fail-tbl td.err-msg { color: var(--accent-red); }
    .section-hd { font-size: .7rem; text-transform: uppercase; letter-spacing: .08em; color: var(--text-muted); margin: 1rem 0 .4rem; font-family: var(--font-mono); }
    .color-ok   { color: var(--accent-green) !important; }
    .color-err  { color: var(--accent-red) !important; }
    .color-warn { color: var(--accent-yellow) !important; }
</style>

<div class="card">
    <div class="card-header"><i class="bi bi-database-fill-gear me-2"></i>Backfill rptrecord rows</div>
    <div class="card-body">

        <p class="bf-intro">
            Repairs reports affected by the <code>XmlName</code> case bug &mdash; every report
            inserted before the fix has a header row but 0 record rows.
            Reads <code>raw_reports</code> XML from each affected row and inserts the missing
            <code>rptrecord</code> entries. Safe to re-run; reports that already have records
            are skipped automatically. Reports with no <code>&lt;record&gt;</code> elements
            (e.g. Microsoft metadata-only reports) count as processed with 0 rows inserted
            &mdash; this is correct behaviour.
        </p>

        <cfif isDone>

            <div class="done-msg"><i class="bi bi-check-circle-fill me-2"></i>Nothing left to backfill &mdash; all reports with raw XML have been processed.</div>
            <a href="/admin/dashboard.cfm" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-left me-1"></i>Dashboard</a>

        <cfelse>

            <div class="stat-row">
                <div class="stat-tile">
                    <div class="stat-label">Needed at start</div>
                    <div class="stat-value mono"><cfoutput>#numberFormat(totalNeeded)#</cfoutput></div>
                </div>
                <div class="stat-tile">
                    <div class="stat-label">This batch</div>
                    <div class="stat-value mono"><cfoutput>#batchCount#</cfoutput></div>
                </div>
                <div class="stat-tile">
                    <div class="stat-label">Processed OK</div>
                    <div class="stat-value mono color-ok"><cfoutput>#cntOk#</cfoutput></div>
                </div>
                <div class="stat-tile">
                    <div class="stat-label">Report failures</div>
                    <div class="stat-value mono <cfoutput>#cntFail GT 0 ? 'color-err' : ''#</cfoutput>"><cfoutput>#cntFail#</cfoutput></div>
                </div>
                <div class="stat-tile">
                    <div class="stat-label">Still remaining</div>
                    <div class="stat-value mono <cfoutput>#remaining GT 0 ? 'color-warn' : 'color-ok'#</cfoutput>"><cfoutput>#numberFormat(remaining)#</cfoutput></div>
                </div>
            </div>

            <cfif arrayLen(failDetails)>
                <div class="section-hd">Report failures this batch (XML could not be parsed at all)</div>
                <p style="font-size:.8rem;color:var(--text-muted);margin-bottom:.5rem;">
                    These reports had XML that could not be parsed. Individual record-level DB
                    errors (e.g. oversized fields from non-compliant senders) are silently skipped
                    per record and do not appear here. True parse failures will keep reappearing
                    until re-ingested from the original email attachments.
                </p>
                <table class="fail-tbl">
                    <thead><tr><th>ID</th><th>Org</th><th>Domain</th><th>Error</th></tr></thead>
                    <tbody>
                    <cfloop array="#failDetails#" item="f">
                        <cfoutput>
                        <tr>
                            <td>#f.id#</td>
                            <td>#htmlEditFormat(f.org)#</td>
                            <td>#htmlEditFormat(f.domain)#</td>
                            <td class="err-msg">#htmlEditFormat(f.error)#</td>
                        </tr>
                        </cfoutput>
                    </cfloop>
                    </tbody>
                </table>
            </cfif>

            <div style="margin-top:1.25rem;display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;">
                <cfif remaining GT 0>
                    <cfoutput>
                    <a href="/admin/backfill_records.cfm?offset=#nextOffset#&batchSize=#batchSize#"
                       class="btn btn-success btn-sm">
                        Continue <i class="bi bi-arrow-right ms-1"></i>
                        (#numberFormat(remaining)# remaining)
                    </a>
                    </cfoutput>
                <cfelse>
                    <div class="done-msg"><i class="bi bi-check-circle-fill me-2"></i>Backfill complete.</div>
                </cfif>

                <a href="/admin/dashboard.cfm" class="btn btn-outline-secondary btn-sm">
                    <i class="bi bi-arrow-left me-1"></i>Dashboard
                </a>

                <form method="get" action="/admin/backfill_records.cfm"
                      style="display:inline-flex;align-items:center;gap:.4rem;margin-left:.5rem;">
                    <input type="hidden" name="offset" value="0">
                    <label style="font-size:.8rem;color:var(--text-muted);margin:0;">Batch:</label>
                    <input type="number" name="batchSize"
                           value="<cfoutput>#batchSize#</cfoutput>"
                           min="1" max="200"
                           class="form-control form-control-sm"
                           style="width:70px;">
                    <button type="submit" class="btn btn-outline-secondary btn-sm">Restart</button>
                </form>
            </div>

        </cfif>

    </div>
</div>

<cfinclude template="/includes/footer.cfm">
