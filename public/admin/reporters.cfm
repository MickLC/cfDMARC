<!--- admin/reporters.cfm --->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    // ── Filters ───────────────────────────────────────────────────────────────
    param name="url.days"   default="90";
    param name="url.domain" default="";
    param name="url.sort"   default="reports";
    param name="url.dir"    default="desc";

    filterDays = isNumeric(url.days) ? int(url.days) : 90;
    if (NOT listFind("7,30,90,365,0", filterDays)) filterDays = 90;
    dateLabel  = filterDays EQ 0 ? "All time" : "Last #filterDays# days";
    dateClause = filterDays GT 0
        ? "AND rpt.mindate >= DATE_SUB(NOW(), INTERVAL #filterDays# DAY)"
        : "";

    validSorts = "reports,messages,domains,last_report";
    sortCol    = listFind(validSorts, url.sort) ? url.sort : "reports";
    sortDir    = (url.dir EQ "asc") ? "ASC" : "DESC";
    flipDir    = (sortDir EQ "DESC") ? "asc" : "desc";

    filterDomain = len(trim(url.domain)) ? trim(url.domain) : "";
    domainClause = len(filterDomain) ? "AND rpt.domain = ?" : "";
    domainParam  = len(filterDomain)
        ? [{ value: filterDomain, cfsqltype: "cf_sql_varchar" }]
        : [];

    // ── Domain list for dropdown ──────────────────────────────────────────────
    qDomainList = queryExecute("
        SELECT DISTINCT domain FROM report ORDER BY domain ASC
    ", {}, { datasource: application.db.dsn });

    // ── Reporter summary — one row per org ────────────────────────────────────
    qReporters = queryExecute("
        SELECT
            rpt.org,
            rpt.email,
            COUNT(DISTINCT rpt.id)                                                       AS reports,
            COUNT(DISTINCT rpt.domain)                                                   AS domains,
            SUM(rec.rcount)                                                              AS messages,
            SUM(CASE WHEN rec.dkim_align = 'pass' OR  rec.spf_align = 'pass'
                     THEN rec.rcount ELSE 0 END)                                         AS passes,
            SUM(CASE WHEN rec.dkim_align != 'pass' AND rec.spf_align != 'pass'
                     THEN rec.rcount ELSE 0 END)                                         AS failures,
            ROUND(100.0 * SUM(CASE WHEN rec.dkim_align = 'pass' OR rec.spf_align = 'pass'
                                   THEN rec.rcount ELSE 0 END)
                  / NULLIF(SUM(rec.rcount), 0), 1)                                       AS pass_rate,
            GROUP_CONCAT(DISTINCT rpt.domain ORDER BY rpt.domain SEPARATOR ', ')        AS domain_list,
            MAX(rpt.received_at)                                                         AS last_report,
            MIN(rpt.mindate)                                                             AS first_report
        FROM report rpt
        LEFT JOIN rptrecord rec ON rec.report_id = rpt.id
        WHERE 1=1
            #dateClause#
            #domainClause#
        GROUP BY rpt.org, rpt.email
        ORDER BY #sortCol# #sortDir#
    ", domainParam, { datasource: application.db.dsn });

    // ── Individual reports per org (for expanded rows) ────────────────────────
    // Fetch all at once and bucket by org in CF — avoids N+1 queries
    qAllReports = queryExecute("
        SELECT
            rpt.id,
            rpt.org,
            rpt.domain,
            rpt.reportid,
            rpt.mindate,
            rpt.maxdate,
            rpt.received_at,
            SUM(rec.rcount)                                                              AS message_count,
            SUM(CASE WHEN rec.dkim_align = 'pass' OR  rec.spf_align = 'pass'
                     THEN rec.rcount ELSE 0 END)                                         AS pass_count,
            SUM(CASE WHEN rec.dkim_align != 'pass' AND rec.spf_align != 'pass'
                     THEN rec.rcount ELSE 0 END)                                         AS fail_count,
            COUNT(DISTINCT CASE WHEN rec.ip  > 0   THEN rec.ip
                                WHEN rec.ip6 <> '' THEN rec.ip6 END)                    AS source_count
        FROM report rpt
        LEFT JOIN rptrecord rec ON rec.report_id = rpt.id
        WHERE 1=1
            #dateClause#
            #domainClause#
        GROUP BY rpt.id
        ORDER BY rpt.org, rpt.received_at DESC
    ", domainParam, { datasource: application.db.dsn });

    // Bucket individual reports by org name
    reportsByOrg = {};
    for (r in qAllReports) {
        if (NOT structKeyExists(reportsByOrg, r.org)) {
            reportsByOrg[r.org] = [];
        }
        arrayAppend(reportsByOrg[r.org], {
            id:           r.id,
            domain:       r.domain,
            reportid:     r.reportid,
            mindate:      r.mindate,
            maxdate:      r.maxdate,
            received_at:  r.received_at,
            message_count: r.message_count,
            pass_count:   r.pass_count,
            fail_count:   r.fail_count,
            source_count: r.source_count
        });
    }

    // Totals for header bar
    totalReporters = qReporters.recordCount;
    totalReports   = 0;
    totalMessages  = 0;
    for (row in qReporters) {
        totalReports   += row.reports;
        totalMessages  += row.messages;
    }

    // Sort link helper
    function sortLink(string col) {
        var d = (col EQ sortCol) ? flipDir : "desc";
        var base = "?days=#filterDays#&sort=#col#&dir=#d#";
        if (len(filterDomain)) base &= "&domain=#urlEncodedFormat(filterDomain)#";
        return base;
    }
    function sortIcon(string col) {
        if (col NEQ sortCol)
            return "<i class='bi bi-arrow-down-up text-muted' style='opacity:0.3'></i>";
        return sortDir EQ "DESC"
            ? "<i class='bi bi-arrow-down' style='color:var(--accent-blue)'></i>"
            : "<i class='bi bi-arrow-up'   style='color:var(--accent-blue)'></i>";
    }
</cfscript>

<cfset variables.pageTitle = "Reporters">
<cfset variables.activeNav = "reporters">
<cfinclude template="/includes/header.cfm">

<cfoutput>

<!--- ── Filter bar ──────────────────────────────────────────────────────── --->
<div class="d-flex flex-wrap gap-2 align-items-center justify-content-between mb-3">

    <div class="d-flex gap-2 align-items-center flex-wrap">
        <!--- Domain filter --->
        <form method="get" class="d-flex gap-2 align-items-center m-0">
            <input type="hidden" name="days" value="#filterDays#">
            <input type="hidden" name="sort" value="#sortCol#">
            <input type="hidden" name="dir"  value="#lCase(sortDir)#">
            <select name="domain" class="form-select form-select-sm" style="width:auto;min-width:160px;"
                    onchange="this.form.submit()">
                <option value="">All domains</option>
                <cfloop query="qDomainList">
                    <option value="#htmlEditFormat(qDomainList.domain)#"
                        #(qDomainList.domain EQ filterDomain ? 'selected' : '')#>
                        #htmlEditFormat(qDomainList.domain)#
                    </option>
                </cfloop>
            </select>
        </form>

        <!--- Summary counts --->
        <span class="mono" style="font-size:0.75rem;color:var(--text-muted);">
            #totalReporters# reporter#(totalReporters NEQ 1 ? 's' : '')#
            &middot; #formatNumber(totalReports)# report#(totalReports NEQ 1 ? 's' : '')#
            &middot; #formatNumber(totalMessages)# messages
        </span>
    </div>

    <!--- Days filter --->
    <div class="btn-group btn-group-sm">
        <cfset dSuffix = len(filterDomain) ? "&domain=" & urlEncodedFormat(filterDomain) : "">
        <a href="?days=7&sort=#sortCol#&dir=#lCase(sortDir)##dSuffix#"
           class="btn btn-outline-secondary #(filterDays EQ 7   ? 'active' : '')#">7d</a>
        <a href="?days=30&sort=#sortCol#&dir=#lCase(sortDir)##dSuffix#"
           class="btn btn-outline-secondary #(filterDays EQ 30  ? 'active' : '')#">30d</a>
        <a href="?days=90&sort=#sortCol#&dir=#lCase(sortDir)##dSuffix#"
           class="btn btn-outline-secondary #(filterDays EQ 90  ? 'active' : '')#">90d</a>
        <a href="?days=365&sort=#sortCol#&dir=#lCase(sortDir)##dSuffix#"
           class="btn btn-outline-secondary #(filterDays EQ 365 ? 'active' : '')#">1y</a>
        <a href="?days=0&sort=#sortCol#&dir=#lCase(sortDir)##dSuffix#"
           class="btn btn-outline-secondary #(filterDays EQ 0   ? 'active' : '')#">All</a>
    </div>
</div>

<!--- ── Reporters table ─────────────────────────────────────────────────── --->
<cfif totalReporters EQ 0>
    <div class="alert alert-info">No reporters found for the selected filters.</div>
<cfelse>
    <div class="card">
        <div class="card-body p-0">
            <table class="table mb-0">
                <thead>
                    <tr>
                        <th>
                            <a href="#sortLink('reports')#" class="sort-link">
                                Reporter #sortIcon('reports')#
                            </a>
                        </th>
                        <th style="text-align:right">
                            <a href="#sortLink('reports')#" class="sort-link">
                                Reports #sortIcon('reports')#
                            </a>
                        </th>
                        <th style="text-align:right">
                            <a href="#sortLink('messages')#" class="sort-link">
                                Messages #sortIcon('messages')#
                            </a>
                        </th>
                        <th style="text-align:right">Pass Rate</th>
                        <th>
                            <a href="#sortLink('domains')#" class="sort-link">
                                Domains #sortIcon('domains')#
                            </a>
                        </th>
                        <th style="text-align:right">
                            <a href="#sortLink('last_report')#" class="sort-link">
                                Last Report #sortIcon('last_report')#
                            </a>
                        </th>
                        <th style="width:1.5rem"></th>
                    </tr>
                </thead>
                <tbody>
                <cfloop query="qReporters">
                    <cfset rowPassRate = qReporters.pass_rate NEQ "" ? qReporters.pass_rate : 0>
                    <cfset badgeCls   = rowPassRate GTE 95 ? "pass" : (rowPassRate GTE 75 ? "warn" : "fail")>
                    <cfset detailId   = "reporter-detail-#qReporters.currentRow#">
                    <cfset orgReports = structKeyExists(reportsByOrg, qReporters.org)
                                        ? reportsByOrg[qReporters.org] : []>

                    <!--- Summary row --->
                    <tr class="reporter-row" data-target="#detailId#" style="cursor:pointer;">
                        <td>
                            <div style="font-weight:500;font-size:0.85rem;">
                                #htmlEditFormat(qReporters.org)#
                            </div>
                            <div style="font-size:0.72rem;color:var(--text-muted);font-family:var(--font-mono);">
                                #htmlEditFormat(qReporters.email)#
                            </div>
                        </td>
                        <td class="mono" style="text-align:right;">#formatNumber(qReporters.reports)#</td>
                        <td class="mono" style="text-align:right;">#formatNumber(qReporters.messages)#</td>
                        <td style="text-align:right;">
                            <span class="badge badge-#badgeCls#">#rowPassRate#%</span>
                        </td>
                        <td style="font-size:0.78rem;color:var(--text-secondary);">
                            <cfif qReporters.domains EQ 1>
                                #htmlEditFormat(qReporters.domain_list)#
                            <cfelse>
                                <span title="#htmlEditFormat(qReporters.domain_list)#">
                                    #qReporters.domains# domains
                                </span>
                            </cfif>
                        </td>
                        <td class="mono" style="text-align:right;font-size:0.78rem;color:var(--text-muted);">
                            #timeAgo(qReporters.last_report)#
                        </td>
                        <td style="color:var(--text-muted);font-size:0.75rem;">
                            <i class="bi bi-chevron-down toggle-icon"></i>
                        </td>
                    </tr>

                    <!--- Expanded detail: org stats + individual report list --->
                    <tr id="#detailId#" class="detail-row" style="display:none;">
                        <td colspan="7" style="background:var(--bg-secondary);padding:0;border-bottom:1px solid var(--border-color);">

                            <!--- Org-level stats strip --->
                            <div class="d-flex flex-wrap gap-4 px-3 py-2"
                                 style="border-bottom:1px solid var(--border-color);">
                                <div>
                                    <div class="detail-section-label">Pass / Fail</div>
                                    <span style="font-family:var(--font-mono);font-size:0.82rem;color:var(--accent-green);">
                                        #formatNumber(qReporters.passes)# pass
                                    </span>
                                    &nbsp;/&nbsp;
                                    <span style="font-family:var(--font-mono);font-size:0.82rem;
                                        color:#(qReporters.failures GT 0 ? 'var(--accent-red)' : 'var(--text-muted)')#">
                                        #formatNumber(qReporters.failures)# fail
                                    </span>
                                </div>
                                <div>
                                    <div class="detail-section-label">First Seen</div>
                                    <span class="mono" style="font-size:0.78rem;color:var(--text-secondary);">
                                        #dateFormat(qReporters.first_report, "yyyy-mm-dd")#
                                    </span>
                                </div>
                                <div>
                                    <div class="detail-section-label">Domains Covered</div>
                                    <span style="font-size:0.78rem;color:var(--text-secondary);">
                                        #htmlEditFormat(qReporters.domain_list)#
                                    </span>
                                </div>
                                <div class="ms-auto">
                                    <div class="pass-bar" style="width:160px;height:5px;margin-top:1.2rem;">
                                        <div class="pass-bar-fill #(rowPassRate GTE 95 ? 'high' : (rowPassRate GTE 75 ? 'medium' : 'low'))#"
                                             style="width:#rowPassRate#%"></div>
                                    </div>
                                </div>
                            </div>

                            <!--- Individual reports sub-table --->
                            <cfif arrayLen(orgReports) GT 0>
                                <table class="table table-sm mb-0 sub-report-table">
                                    <thead>
                                        <tr>
                                            <th>Report ID</th>
                                            <th>Domain</th>
                                            <th>Period</th>
                                            <th style="text-align:right">Messages</th>
                                            <th style="text-align:right">Pass</th>
                                            <th style="text-align:right">Fail</th>
                                            <th style="text-align:right">Sources</th>
                                            <th style="text-align:right">Received</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                    <cfloop array="#orgReports#" item="rr">
                                        <cfset rrRate = rr.message_count GT 0
                                            ? int(100 * rr.pass_count / rr.message_count) : 0>
                                        <tr>
                                            <td class="mono" style="font-size:0.72rem;color:var(--text-muted);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
                                                title="#htmlEditFormat(rr.reportid)#">
                                                #htmlEditFormat(left(rr.reportid, 24))##(len(rr.reportid) GT 24 ? '…' : '')#
                                            </td>
                                            <td style="font-size:0.78rem;">#htmlEditFormat(rr.domain)#</td>
                                            <td class="mono" style="font-size:0.72rem;color:var(--text-muted);white-space:nowrap;">
                                                #dateFormat(rr.mindate, "mmm d")# – #dateFormat(rr.maxdate, "mmm d")#
                                            </td>
                                            <td class="mono" style="text-align:right;">#formatNumber(rr.message_count)#</td>
                                            <td class="mono" style="text-align:right;color:var(--accent-green);">
                                                #formatNumber(rr.pass_count)#
                                            </td>
                                            <td class="mono" style="text-align:right;
                                                color:#(rr.fail_count GT 0 ? 'var(--accent-red)' : 'var(--text-muted)')#">
                                                #formatNumber(rr.fail_count)#
                                            </td>
                                            <td class="mono" style="text-align:right;color:var(--text-muted);">
                                                #rr.source_count#
                                            </td>
                                            <td class="mono" style="text-align:right;font-size:0.72rem;color:var(--text-muted);">
                                                #timeAgo(rr.received_at)#
                                            </td>
                                        </tr>
                                    </cfloop>
                                    </tbody>
                                </table>
                            </cfif>

                        </td>
                    </tr>

                </cfloop>
                </tbody>
            </table>
        </div>
    </div>
</cfif>

<style>
    .sort-link {
        color: var(--text-secondary);
        text-decoration: none;
        white-space: nowrap;
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
    }
    .sort-link:hover { color: var(--text-primary); }

    .reporter-row:hover td { background: var(--bg-card-hover) !important; }

    .sub-report-table { background: transparent; }
    .sub-report-table > :not(caption) > * > * {
        background: transparent;
        border-bottom-color: rgba(48,54,61,0.6);
        padding: 0.35rem 0.75rem;
    }
    .sub-report-table thead th {
        font-family: var(--font-mono);
        font-size: 0.62rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--text-muted);
        border-bottom: 1px solid var(--border-color);
        font-weight: 500;
        background: transparent;
        padding-left: 0.75rem;
    }
    .sub-report-table tbody tr:hover td {
        background: rgba(255,255,255,0.02) !important;
    }

    .detail-section-label {
        font-family: var(--font-mono);
        font-size: 0.62rem;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: var(--text-muted);
        margin-bottom: 0.2rem;
    }
</style>

<script>
document.querySelectorAll('.reporter-row').forEach(function(row) {
    row.addEventListener('click', function() {
        var targetId = this.getAttribute('data-target');
        var detail   = document.getElementById(targetId);
        var icon     = this.querySelector('.toggle-icon');
        var isOpen   = detail.style.display !== 'none';

        detail.style.display = isOpen ? 'none' : 'table-row';
        icon.className = isOpen
            ? 'bi bi-chevron-down toggle-icon'
            : 'bi bi-chevron-up toggle-icon';
    });
});
</script>

</cfoutput>

<cfinclude template="/includes/footer.cfm">
