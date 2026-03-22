<!--- admin/sources.cfm --->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    // ── Date filter (shared with dashboard) ──────────────────────────────────
    param name="url.days"   default="30";
    param name="url.sort"   default="failures";
    param name="url.dir"    default="desc";
    param name="url.domain" default="";

    filterDays = isNumeric(url.days) ? int(url.days) : 30;
    if (NOT listFind("7,30,90,365,0", filterDays)) filterDays = 30;
    dateLabel  = filterDays EQ 0 ? "All time" : "Last #filterDays# days";
    dateClause = filterDays GT 0
        ? "AND rpt.mindate >= DATE_SUB(NOW(), INTERVAL #filterDays# DAY)"
        : "";

    // ── Sort ─────────────────────────────────────────────────────────────────
    validSorts = "messages,failures,fail_rate,domains,last_seen";
    sortCol    = listFind(validSorts, url.sort) ? url.sort : "failures";
    sortDir    = (url.dir EQ "asc") ? "ASC" : "DESC";
    // flip direction for the toggle links
    flipDir    = (sortDir EQ "DESC") ? "asc" : "desc";

    // ── Domain filter ─────────────────────────────────────────────────────────
    filterDomain  = len(trim(url.domain)) ? trim(url.domain) : "";
    domainClause  = len(filterDomain) ? "AND rpt.domain = ?" : "";
    domainParam   = len(filterDomain) ? [{ value: filterDomain, cfsqltype: "cf_sql_varchar" }] : [];

    // ── Domain list for dropdown ──────────────────────────────────────────────
    qDomainList = queryExecute("
        SELECT DISTINCT domain FROM report ORDER BY domain ASC
    ", {}, { datasource: application.db.dsn });

    // ── Main sources query ───────────────────────────────────────────────────
    // One row per unique source IP, aggregated across all matching reports.
    qSources = queryExecute("
        SELECT
            CASE
                WHEN rec.ip  IS NOT NULL AND rec.ip  > 0 THEN INET_NTOA(rec.ip)
                WHEN rec.ip6 IS NOT NULL AND rec.ip6 <> '' THEN HEX(rec.ip6)
                ELSE 'unknown'
            END AS source_ip,
            rec.ip  AS ip_int,
            rec.ip6 AS ip6_hex,
            COUNT(DISTINCT rpt.id)                                                       AS report_count,
            COUNT(DISTINCT rpt.domain)                                                   AS domains,
            SUM(rec.rcount)                                                              AS messages,
            SUM(CASE WHEN rec.dkim_align != 'pass' AND rec.spf_align != 'pass'
                     THEN rec.rcount ELSE 0 END)                                         AS failures,
            ROUND(100.0 * SUM(CASE WHEN rec.dkim_align != 'pass' AND rec.spf_align != 'pass'
                                   THEN rec.rcount ELSE 0 END)
                  / NULLIF(SUM(rec.rcount), 0), 1)                                       AS fail_rate,
            ROUND(100.0 * SUM(CASE WHEN rec.dkim_align = 'pass' OR rec.spf_align = 'pass'
                                   THEN rec.rcount ELSE 0 END)
                  / NULLIF(SUM(rec.rcount), 0), 1)                                       AS pass_rate,
            GROUP_CONCAT(DISTINCT rpt.domain ORDER BY rpt.domain SEPARATOR ', ')        AS domain_list,
            MAX(rpt.received_at)                                                         AS last_seen,
            -- disposition breakdown
            SUM(CASE WHEN rec.disposition = 'none'       THEN rec.rcount ELSE 0 END)    AS disp_none,
            SUM(CASE WHEN rec.disposition = 'quarantine' THEN rec.rcount ELSE 0 END)    AS disp_quarantine,
            SUM(CASE WHEN rec.disposition = 'reject'     THEN rec.rcount ELSE 0 END)    AS disp_reject,
            -- auth method breakdown (pass counts)
            SUM(CASE WHEN rec.dkim_align = 'pass' THEN rec.rcount ELSE 0 END)           AS dkim_pass,
            SUM(CASE WHEN rec.spf_align  = 'pass' THEN rec.rcount ELSE 0 END)           AS spf_pass,
            SUM(CASE WHEN rec.dkim_align = 'pass' AND rec.spf_align = 'pass'
                     THEN rec.rcount ELSE 0 END)                                         AS both_pass
        FROM rptrecord rec
        JOIN report rpt ON rpt.id = rec.report_id
        WHERE 1=1
            #dateClause#
            #domainClause#
        GROUP BY rec.ip, rec.ip6
        ORDER BY #sortCol# #sortDir#
    ", domainParam, { datasource: application.db.dsn });

    totalSources   = qSources.recordCount;
    totalMessages  = 0;
    totalFailures  = 0;
    for (row in qSources) {
        totalMessages += row.messages;
        totalFailures += row.failures;
    }
    overallFailRate = totalMessages GT 0
        ? numberFormat(100 * totalFailures / totalMessages, "99.9")
        : 0;

    // Helper: build a sort link preserving current filter/days params
    function sortLink(string col) {
        var d = (col EQ sortCol) ? flipDir : "desc";
        return "?days=#filterDays#&sort=#col#&dir=#d##len(filterDomain) ? '&domain=' & urlEncodedFormat(filterDomain) : ''#";
    }

    function sortIcon(string col) {
        if (col NEQ sortCol) return "<i class='bi bi-arrow-down-up text-muted' style='opacity:0.3'></i>";
        return sortDir EQ "DESC"
            ? "<i class='bi bi-arrow-down' style='color:var(--accent-blue)'></i>"
            : "<i class='bi bi-arrow-up'   style='color:var(--accent-blue)'></i>";
    }
</cfscript>

<cfset variables.pageTitle = "Sending Sources">
<cfset variables.activeNav = "sources">
<cfinclude template="/includes/header.cfm">

<cfoutput>

<!--- ── Filter bar ──────────────────────────────────────────────────────── --->
<div class="d-flex flex-wrap gap-2 align-items-center justify-content-between mb-3">

    <div class="d-flex gap-2 align-items-center flex-wrap">
        <!--- Domain filter --->
        <form method="get" class="d-flex gap-2 align-items-center m-0">
            <input type="hidden" name="days"  value="#filterDays#">
            <input type="hidden" name="sort"  value="#sortCol#">
            <input type="hidden" name="dir"   value="#lCase(sortDir)#">
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
            #totalSources# source#(totalSources NEQ 1 ? 's' : '')# &middot;
            #formatNumber(totalMessages)# messages &middot;
            <span style="color:#(totalFailures GT 0 ? 'var(--accent-red)' : 'var(--accent-green)')#">
                #formatNumber(totalFailures)# failures (#overallFailRate#%)
            </span>
        </span>
    </div>

    <!--- Days filter --->
    <div class="btn-group btn-group-sm">
        <a href="?days=7&sort=#sortCol#&dir=#lCase(sortDir)##len(filterDomain) ? '&domain=' & urlEncodedFormat(filterDomain) : ''#"
           class="btn btn-outline-secondary #(filterDays EQ 7   ? 'active' : '')#">7d</a>
        <a href="?days=30&sort=#sortCol#&dir=#lCase(sortDir)##len(filterDomain) ? '&domain=' & urlEncodedFormat(filterDomain) : ''#"
           class="btn btn-outline-secondary #(filterDays EQ 30  ? 'active' : '')#">30d</a>
        <a href="?days=90&sort=#sortCol#&dir=#lCase(sortDir)##len(filterDomain) ? '&domain=' & urlEncodedFormat(filterDomain) : ''#"
           class="btn btn-outline-secondary #(filterDays EQ 90  ? 'active' : '')#">90d</a>
        <a href="?days=365&sort=#sortCol#&dir=#lCase(sortDir)##len(filterDomain) ? '&domain=' & urlEncodedFormat(filterDomain) : ''#"
           class="btn btn-outline-secondary #(filterDays EQ 365 ? 'active' : '')#">1y</a>
        <a href="?days=0&sort=#sortCol#&dir=#lCase(sortDir)##len(filterDomain) ? '&domain=' & urlEncodedFormat(filterDomain) : ''#"
           class="btn btn-outline-secondary #(filterDays EQ 0   ? 'active' : '')#">All</a>
    </div>
</div>

<!--- ── Sources table ───────────────────────────────────────────────────── --->
<cfif totalSources EQ 0>
    <div class="alert alert-info">No sending sources found for the selected filters.</div>
<cfelse>
    <div class="card">
        <div class="card-body p-0">
            <table class="table mb-0" id="sources-table">
                <thead>
                    <tr>
                        <th><a href="#sortLink('messages')#" class="sort-link">
                            Source IP #sortIcon('messages')#</a></th>
                        <th style="text-align:right">
                            <a href="#sortLink('messages')#" class="sort-link">
                            Messages #sortIcon('messages')#</a></th>
                        <th style="text-align:right">
                            <a href="#sortLink('failures')#" class="sort-link">
                            Failures #sortIcon('failures')#</a></th>
                        <th style="text-align:right">
                            <a href="#sortLink('fail_rate')#" class="sort-link">
                            Fail Rate #sortIcon('fail_rate')#</a></th>
                        <th>Auth</th>
                        <th>
                            <a href="#sortLink('domains')#" class="sort-link">
                            Domains #sortIcon('domains')#</a></th>
                        <th style="text-align:right">
                            <a href="#sortLink('last_seen')#" class="sort-link">
                            Last Seen #sortIcon('last_seen')#</a></th>
                        <th style="width:1.5rem"></th>
                    </tr>
                </thead>
                <tbody>
                <cfloop query="qSources">
                    <cfset rowFailRate = qSources.fail_rate NEQ "" ? qSources.fail_rate : 0>
                    <cfset rowPassRate = qSources.pass_rate NEQ "" ? qSources.pass_rate : 0>
                    <cfset badgeClass  = rowFailRate EQ 0
                        ? "pass"
                        : (rowFailRate LT 25 ? "warn" : "fail")>
                    <cfset rowId = "row-#qSources.currentRow#">
                    <cfset detailId = "detail-#qSources.currentRow#">

                    <!--- Main row --->
                    <tr class="source-row" data-target="#detailId#" style="cursor:pointer;">
                        <td class="mono" style="font-size:0.82rem;">
                            #htmlEditFormat(qSources.source_ip)#
                        </td>
                        <td class="mono" style="text-align:right;">#formatNumber(qSources.messages)#</td>
                        <td class="mono" style="text-align:right;
                            color:#(qSources.failures GT 0 ? 'var(--accent-red)' : 'var(--text-muted)')#">
                            #formatNumber(qSources.failures)#
                        </td>
                        <td style="text-align:right;">
                            <span class="badge badge-#badgeClass#">#rowFailRate#%</span>
                        </td>
                        <td>
                            <!--- Compact DKIM/SPF pass indicators --->
                            <span class="auth-pill #(qSources.dkim_pass GT 0 ? 'auth-pass' : 'auth-fail')#">DKIM</span>
                            <span class="auth-pill #(qSources.spf_pass  GT 0 ? 'auth-pass' : 'auth-fail')#">SPF</span>
                        </td>
                        <td style="font-size:0.78rem;color:var(--text-secondary);">
                            <cfif qSources.domains EQ 1>
                                #htmlEditFormat(qSources.domain_list)#
                            <cfelse>
                                <span title="#htmlEditFormat(qSources.domain_list)#">
                                    #qSources.domains# domains
                                </span>
                            </cfif>
                        </td>
                        <td class="mono" style="text-align:right;font-size:0.78rem;color:var(--text-muted);">
                            #timeAgo(qSources.last_seen)#
                        </td>
                        <td style="color:var(--text-muted);font-size:0.75rem;">
                            <i class="bi bi-chevron-down toggle-icon"></i>
                        </td>
                    </tr>

                    <!--- Expandable detail row --->
                    <tr id="#detailId#" class="detail-row" style="display:none;">
                        <td colspan="8" style="background:var(--bg-secondary);padding:0.75rem 1.25rem;">
                            <div class="row g-3">

                                <!--- Pass rate bar --->
                                <div class="col-12">
                                    <div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:0.3rem;">
                                        Pass rate: #rowPassRate#% &nbsp;&middot;&nbsp;
                                        #formatNumber(qSources.report_count)# report#(qSources.report_count NEQ 1 ? 's' : '')#
                                    </div>
                                    <div class="pass-bar" style="height:6px;">
                                        <div class="pass-bar-fill #(rowPassRate GTE 95 ? 'high' : (rowPassRate GTE 75 ? 'medium' : 'low'))#"
                                             style="width:#rowPassRate#%"></div>
                                    </div>
                                </div>

                                <!--- Auth breakdown --->
                                <div class="col-sm-4">
                                    <div class="detail-section-label">Authentication</div>
                                    <table class="detail-mini-table">
                                        <tr><td>DKIM pass</td>
                                            <td class="mono">#formatNumber(qSources.dkim_pass)#</td></tr>
                                        <tr><td>SPF pass</td>
                                            <td class="mono">#formatNumber(qSources.spf_pass)#</td></tr>
                                        <tr><td>Both pass</td>
                                            <td class="mono">#formatNumber(qSources.both_pass)#</td></tr>
                                        <tr><td>Neither</td>
                                            <td class="mono"
                                                style="color:#(qSources.failures GT 0 ? 'var(--accent-red)' : 'inherit')#">
                                                #formatNumber(qSources.failures)#</td></tr>
                                    </table>
                                </div>

                                <!--- Disposition breakdown --->
                                <div class="col-sm-4">
                                    <div class="detail-section-label">Disposition</div>
                                    <table class="detail-mini-table">
                                        <tr><td>Delivered (none)</td>
                                            <td class="mono">#formatNumber(qSources.disp_none)#</td></tr>
                                        <tr><td>Quarantined</td>
                                            <td class="mono"
                                                style="color:#(qSources.disp_quarantine GT 0 ? 'var(--accent-yellow)' : 'inherit')#">
                                                #formatNumber(qSources.disp_quarantine)#</td></tr>
                                        <tr><td>Rejected</td>
                                            <td class="mono"
                                                style="color:#(qSources.disp_reject GT 0 ? 'var(--accent-red)' : 'inherit')#">
                                                #formatNumber(qSources.disp_reject)#</td></tr>
                                    </table>
                                </div>

                                <!--- Domains seen sending from this IP --->
                                <div class="col-sm-4">
                                    <div class="detail-section-label">Domains</div>
                                    <cfset domArr = listToArray(qSources.domain_list, ", ")>
                                    <cfloop array="#domArr#" item="dom">
                                        <div style="font-size:0.78rem;font-family:var(--font-mono);
                                                    color:var(--text-secondary);line-height:1.8;">
                                            <a href="?days=#filterDays#&domain=#urlEncodedFormat(trim(dom))#"
                                               style="color:var(--accent-blue);text-decoration:none;">
                                                #htmlEditFormat(trim(dom))#
                                            </a>
                                        </div>
                                    </cfloop>
                                </div>

                            </div>
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

    .auth-pill {
        display: inline-block;
        font-family: var(--font-mono);
        font-size: 0.62rem;
        font-weight: 600;
        padding: 0.15em 0.45em;
        border-radius: 3px;
        letter-spacing: 0.04em;
        margin-right: 2px;
    }
    .auth-pass { background: rgba(63,185,80,.15);  color: var(--accent-green); border: 1px solid rgba(63,185,80,.3); }
    .auth-fail { background: rgba(248,81,73,.12);  color: var(--accent-red);   border: 1px solid rgba(248,81,73,.25); }

    .source-row:hover td { background: var(--bg-card-hover) !important; }

    .detail-row td { border-bottom: 1px solid var(--border-color); }

    .detail-section-label {
        font-family: var(--font-mono);
        font-size: 0.65rem;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: var(--text-muted);
        margin-bottom: 0.4rem;
    }

    .detail-mini-table { width: 100%; border-collapse: collapse; }
    .detail-mini-table td {
        font-size: 0.78rem;
        padding: 0.15rem 0.5rem 0.15rem 0;
        color: var(--text-secondary);
        vertical-align: middle;
    }
    .detail-mini-table td.mono { text-align: right; color: var(--text-primary); }
</style>

<script>
document.querySelectorAll('.source-row').forEach(function(row) {
    row.addEventListener('click', function() {
        var targetId = this.getAttribute('data-target');
        var detail   = document.getElementById(targetId);
        var icon     = this.querySelector('.toggle-icon');
        var isOpen   = detail.style.display !== 'none';

        detail.style.display = isOpen ? 'none' : 'table-row';
        icon.className = isOpen ? 'bi bi-chevron-down toggle-icon' : 'bi bi-chevron-up toggle-icon';
    });
});
</script>

</cfoutput>

<cfinclude template="/includes/footer.cfm">
