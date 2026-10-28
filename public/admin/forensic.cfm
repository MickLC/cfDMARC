<!--- admin/forensic.cfm --->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<style>
    .ruf-row:hover td { background: var(--bg-card-hover) !important; }

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
    .auth-pass    { background: rgba(63,185,80,.15);  color: var(--accent-green); border: 1px solid rgba(63,185,80,.3); }
    .auth-fail    { background: rgba(248,81,73,.12);  color: var(--accent-red);   border: 1px solid rgba(248,81,73,.25); }
    .auth-unknown { background: rgba(139,148,158,.1); color: var(--text-muted);   border: 1px solid var(--border-color); }

    .detail-section-label {
        font-family: var(--font-mono);
        font-size: 0.62rem;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: var(--text-muted);
        margin-bottom: 0.3rem;
    }
    .detail-mini-table { width: 100%; border-collapse: collapse; }
    .detail-mini-table td {
        font-size: 0.78rem;
        padding: 0.15rem 0.4rem 0.15rem 0;
        color: var(--text-secondary);
        vertical-align: top;
    }
    .detail-mini-table td.mono {
        text-align: right;
        color: var(--text-primary);
        font-family: var(--font-mono);
        word-break: break-all;
    }
</style>

<cfscript>
    // ── Filters ───────────────────────────────────────────────────────────────
    param name="url.days"   default="30";
    param name="url.domain" default="";
    param name="url.type"   default="";
    param name="url.page"   default="1";

    filterDays = isNumeric(url.days) ? int(url.days) : 30;
    if (NOT listFind("7,30,90,365,0", filterDays)) filterDays = 30;
    dateLabel  = filterDays EQ 0 ? "All time" : "Last #filterDays# days";
    dateClause = filterDays GT 0
        ? "AND f.received_at >= DATE_SUB(NOW(), INTERVAL #filterDays# DAY)"
        : "";

    filterDomain = len(trim(url.domain)) ? trim(url.domain) : "";
    filterType   = len(trim(url.type))   ? trim(url.type)   : "";

    domainClause = len(filterDomain) ? "AND f.reported_domain = ?" : "";
    typeClause   = len(filterType)   ? "AND f.auth_failure = ?"    : "";

    // When type=unknown we need to match NULL or empty string
    typeClause = len(filterType) ? (
        filterType EQ "unknown"
            ? "AND (f.auth_failure IS NULL OR f.auth_failure = '')"
            : "AND f.auth_failure = ?"
    ) : "";

    baseParams = [];
    if (len(filterDomain)) arrayAppend(baseParams, { value: filterDomain, cfsqltype: "cf_sql_varchar" });
    // Only add type param when it's a real value (not "unknown" which uses IS NULL clause)
    if (len(filterType) AND filterType NEQ "unknown")
        arrayAppend(baseParams, { value: filterType, cfsqltype: "cf_sql_varchar" });

    pageSize    = 50;
    currentPage = isNumeric(url.page) AND url.page GTE 1 ? int(url.page) : 1;
    pageOffset  = (currentPage - 1) * pageSize;

    // ── Summary stats — COALESCE all SUM() to guard against NULL result sets ──
    qStats = queryExecute("
        SELECT
            COUNT(*)                                                           AS total_reports,
            COUNT(DISTINCT f.reported_domain)                                  AS domains,
            COUNT(DISTINCT f.source_ip)                                        AS sources,
            COALESCE(SUM(f.incidents), 0)                                      AS total_incidents,
            COALESCE(SUM(CASE WHEN f.auth_failure = 'dkim'  THEN 1 ELSE 0 END), 0) AS dkim_failures,
            COALESCE(SUM(CASE WHEN f.auth_failure = 'spf'   THEN 1 ELSE 0 END), 0) AS spf_failures,
            COALESCE(SUM(CASE WHEN f.auth_failure = 'dmarc' THEN 1 ELSE 0 END), 0) AS dmarc_failures
        FROM failure f
        WHERE 1=1
            #dateClause#
            #domainClause#
            #typeClause#
    ", baseParams, { datasource: application.db.dsn });

    // ── Domain list for dropdown ──────────────────────────────────────────────
    qDomainList = queryExecute("
        SELECT DISTINCT reported_domain AS domain
        FROM failure
        WHERE reported_domain IS NOT NULL AND reported_domain <> ''
        ORDER BY reported_domain ASC
    ", {}, { datasource: application.db.dsn });

    // ── Auth failure type breakdown ───────────────────────────────────────────
    // Always unfiltered by type so all pills show regardless of current type filter.
    // COALESCE incidents in case any row somehow has NULLs.
    qTypes = queryExecute("
        SELECT
            COALESCE(NULLIF(f.auth_failure, ''), 'unknown') AS failure_type,
            COUNT(*)                                         AS report_count,
            COALESCE(SUM(f.incidents), 0)                    AS incidents
        FROM failure f
        WHERE 1=1
            #dateClause#
            #domainClause#
        GROUP BY failure_type
        ORDER BY incidents DESC
    ", len(filterDomain) ? [{ value: filterDomain, cfsqltype: "cf_sql_varchar" }] : [],
    { datasource: application.db.dsn });

    // ── Paginated record list ─────────────────────────────────────────────────
    qCount = queryExecute("
        SELECT COUNT(*) AS total_rows FROM failure f
        WHERE 1=1
            #dateClause#
            #domainClause#
            #typeClause#
    ", baseParams, { datasource: application.db.dsn });

    totalRows  = qCount.total_rows;
    totalPages = ceiling(totalRows / pageSize);
    if (currentPage GT totalPages AND totalPages GT 0) currentPage = totalPages;

    qRecords = queryExecute("
        SELECT
            f.id,
            f.message_id,
            f.failure_date,
            f.source_ip,
            f.reported_domain,
            f.feedback_type,
            f.auth_failure,
            f.dkim_domain,
            f.dkim_selector,
            f.spf_dns,
            f.original_mail_from,
            f.original_rcpt_to,
            f.reporting_mta,
            COALESCE(f.incidents, 0) AS incidents,
            f.received_at
        FROM failure f
        WHERE 1=1
            #dateClause#
            #domainClause#
            #typeClause#
        ORDER BY f.received_at DESC
        LIMIT #pageSize# OFFSET #pageOffset#
    ", baseParams, { datasource: application.db.dsn });

    function pageUrl(numeric p, string domain="", string type="") {
        var q  = "?days=#filterDays#&page=#p#";
        var dm = len(arguments.domain) ? arguments.domain : filterDomain;
        var tp = len(arguments.type)   ? arguments.type   : filterType;
        if (len(dm)) q &= "&domain=#urlEncodedFormat(dm)#";
        if (len(tp)) q &= "&type=#urlEncodedFormat(tp)#";
        return q;
    }
</cfscript>

<cfset variables.pageTitle = "Forensic (RUF)">
<cfset variables.activeNav = "forensic">
<cfinclude template="/includes/header.cfm">

<cfoutput>

<!--- ── What is RUF? notice ─────────────────────────────────────────────── --->
<div class="alert alert-info mb-3" style="font-size:0.82rem;">
    <strong>RUF reports</strong> are forensic failure reports sent by receivers for individual
    messages that failed DMARC. They contain more detail than aggregate RUA reports but are
    not universally supported — many large providers (Google, Microsoft) no longer send them.
</div>

<!--- ── Filter bar ──────────────────────────────────────────────────────── --->
<div class="d-flex flex-wrap gap-2 align-items-center justify-content-between mb-3">

    <div class="d-flex gap-2 align-items-center flex-wrap">
        <form method="get" class="d-flex gap-2 align-items-center m-0">
            <input type="hidden" name="days" value="#filterDays#">
            <input type="hidden" name="type" value="#htmlEditFormat(filterType)#">
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

        <!--- Auth failure type filter pills --->
        <div class="d-flex gap-1 flex-wrap">
            <a href="#pageUrl(1, filterDomain, '')#"
               class="btn btn-sm #(NOT len(filterType) ? 'btn-secondary' : 'btn-outline-secondary')#"
               style="font-size:0.72rem;">All</a>
            <cfloop query="qTypes">
                <a href="#pageUrl(1, filterDomain, qTypes.failure_type)#"
                   class="btn btn-sm #(filterType EQ qTypes.failure_type ? 'btn-secondary' : 'btn-outline-secondary')#"
                   style="font-size:0.72rem;">
                    #uCase(htmlEditFormat(qTypes.failure_type))#
                    <span class="mono" style="font-size:0.65rem;opacity:0.7;">(#formatNumber(qTypes.incidents)#)</span>
                </a>
            </cfloop>
        </div>

        <span class="mono" style="font-size:0.75rem;color:var(--text-muted);">
            #formatNumber(qStats.total_reports)# report#(qStats.total_reports NEQ 1 ? 's' : '')#
            &middot; #formatNumber(qStats.total_incidents)# incidents
            &middot; #dateLabel#
        </span>
    </div>

    <div class="btn-group btn-group-sm">
        <cfset dSuffix = len(filterDomain) ? "&domain=" & urlEncodedFormat(filterDomain) : "">
        <cfset tSuffix = len(filterType)   ? "&type="   & urlEncodedFormat(filterType)   : "">
        <a href="?days=7#dSuffix##tSuffix#"   class="btn btn-outline-secondary #(filterDays EQ 7   ? 'active':'')#">7d</a>
        <a href="?days=30#dSuffix##tSuffix#"  class="btn btn-outline-secondary #(filterDays EQ 30  ? 'active':'')#">30d</a>
        <a href="?days=90#dSuffix##tSuffix#"  class="btn btn-outline-secondary #(filterDays EQ 90  ? 'active':'')#">90d</a>
        <a href="?days=365#dSuffix##tSuffix#" class="btn btn-outline-secondary #(filterDays EQ 365 ? 'active':'')#">1y</a>
        <a href="?days=0#dSuffix##tSuffix#"   class="btn btn-outline-secondary #(filterDays EQ 0   ? 'active':'')#">All</a>
    </div>
</div>

<!--- ── Summary stat tiles ──────────────────────────────────────────────── --->
<div class="row g-3 mb-3">
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">RUF Reports</div>
        <div class="stat-value">#formatNumber(qStats.total_reports)#</div>
        <div class="stat-sub">#qStats.domains# domain#(qStats.domains NEQ 1 ? 's' : '')#</div>
    </div></div>
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">Total Incidents</div>
        <div class="stat-value">#formatNumber(qStats.total_incidents)#</div>
        <div class="stat-sub">#qStats.sources# unique source#(qStats.sources NEQ 1 ? 's' : '')#</div>
    </div></div>
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">DKIM Failures</div>
        <div class="stat-value" style="color:#(qStats.dkim_failures GT 0 ? 'var(--accent-red)' : 'var(--accent-green)')#">
            #formatNumber(qStats.dkim_failures)#
        </div>
        <div class="stat-sub">auth_failure = dkim</div>
    </div></div>
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">SPF Failures</div>
        <div class="stat-value" style="color:#(qStats.spf_failures GT 0 ? 'var(--accent-red)' : 'var(--accent-green)')#">
            #formatNumber(qStats.spf_failures)#
        </div>
        <div class="stat-sub">auth_failure = spf</div>
    </div></div>
</div>

<!--- ── Record table ────────────────────────────────────────────────────── --->
<cfif totalRows EQ 0>
    <div class="alert alert-info">
        <cfif qStats.total_reports EQ 0 AND NOT len(filterDomain) AND NOT len(filterType)>
            No RUF forensic reports have been received yet. RUF reporting must be enabled in
            your DMARC DNS record (<code>ruf=mailto:...</code>) and supported by the reporter.
        <cfelse>
            No records match the selected filters.
        </cfif>
    </div>
<cfelse>
    <div class="card">
        <div class="card-header d-flex align-items-center justify-content-between">
            <span>Forensic Reports</span>
            <span class="mono" style="font-size:0.72rem;color:var(--text-muted);">
                #formatNumber(totalRows)# record#(totalRows NEQ 1 ? 's' : '')#
                <cfif totalPages GT 1>&middot; page #currentPage# of #totalPages#</cfif>
            </span>
        </div>
        <div class="card-body p-0">
            <table class="table mb-0">
                <thead>
                    <tr>
                        <th>Received</th>
                        <th>Domain</th>
                        <th>Source IP</th>
                        <th style="text-align:center">Auth Failure</th>
                        <th>Mail From</th>
                        <th style="text-align:right">Incidents</th>
                        <th style="width:1.5rem"></th>
                    </tr>
                </thead>
                <tbody>
                <cfloop query="qRecords">
                    <cfset detailId = "ruf-detail-#qRecords.currentRow#">
                    <cfset authType = len(trim(qRecords.auth_failure)) ? lCase(qRecords.auth_failure) : "unknown">

                    <tr class="ruf-row" data-target="#detailId#" style="cursor:pointer;">
                        <td class="mono" style="font-size:0.75rem;white-space:nowrap;color:var(--text-muted);">
                            #timeAgo(qRecords.received_at)#
                        </td>
                        <td style="font-size:0.82rem;">#htmlEditFormat(qRecords.reported_domain)#</td>
                        <td class="mono" style="font-size:0.75rem;">#htmlEditFormat(qRecords.source_ip)#</td>
                        <td style="text-align:center;">
                            <span class="auth-pill auth-fail">#uCase(htmlEditFormat(authType))#</span>
                        </td>
                        <td class="mono" style="font-size:0.75rem;color:var(--text-secondary);
                                               overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px;"
                              title="#htmlEditFormat(qRecords.original_mail_from)#">
                            #htmlEditFormat(qRecords.original_mail_from)#
                        </td>
                        <td class="mono" style="text-align:right;">#formatNumber(qRecords.incidents)#</td>
                        <td style="color:var(--text-muted);font-size:0.75rem;">
                            <i class="bi bi-chevron-down toggle-icon"></i>
                        </td>
                    </tr>

                    <tr id="#detailId#" class="detail-row" style="display:none;">
                        <td colspan="7" style="background:var(--bg-secondary);padding:0.75rem 1.25rem;
                                              border-bottom:1px solid var(--border-color);">
                            <div class="row g-3">

                                <div class="col-sm-6 col-lg-3">
                                    <div class="detail-section-label">Report Metadata</div>
                                    <table class="detail-mini-table">
                                        <tr><td>Feedback type</td>
                                            <td class="mono">#htmlEditFormat(qRecords.feedback_type)#</td></tr>
                                        <tr><td>Auth failure</td>
                                            <td class="mono">#htmlEditFormat(qRecords.auth_failure)#</td></tr>
                                        <tr><td>Reporting MTA</td>
                                            <td class="mono">#htmlEditFormat(qRecords.reporting_mta)#</td></tr>
                                        <tr><td>Failure date</td>
                                            <td class="mono" style="font-size:0.72rem;">
                                                <cfif isDate(qRecords.failure_date)>
                                                    #dateTimeFormat(qRecords.failure_date, "yyyy-mm-dd HH:nn")#
                                                <cfelse>
                                                    —
                                                </cfif>
                                            </td></tr>
                                    </table>
                                </div>

                                <div class="col-sm-6 col-lg-3">
                                    <div class="detail-section-label">DKIM</div>
                                    <table class="detail-mini-table">
                                        <tr><td>Signing domain</td>
                                            <td class="mono">#len(trim(qRecords.dkim_domain)) ? htmlEditFormat(qRecords.dkim_domain) : '—'#</td></tr>
                                        <tr><td>Selector</td>
                                            <td class="mono">#len(trim(qRecords.dkim_selector)) ? htmlEditFormat(qRecords.dkim_selector) : '—'#</td></tr>
                                    </table>

                                    <div class="detail-section-label mt-3">SPF</div>
                                    <table class="detail-mini-table">
                                        <tr><td>SPF DNS</td>
                                            <td class="mono" style="font-size:0.68rem;word-break:break-all;">
                                                #len(trim(qRecords.spf_dns)) ? htmlEditFormat(qRecords.spf_dns) : '—'#
                                            </td></tr>
                                    </table>
                                </div>

                                <div class="col-sm-6 col-lg-3">
                                    <div class="detail-section-label">Envelope</div>
                                    <table class="detail-mini-table">
                                        <tr><td>Mail From</td>
                                            <td class="mono" style="word-break:break-all;">
                                                #len(trim(qRecords.original_mail_from)) ? htmlEditFormat(qRecords.original_mail_from) : '—'#
                                            </td></tr>
                                        <tr><td>Rcpt To</td>
                                            <td class="mono" style="word-break:break-all;">
                                                #len(trim(qRecords.original_rcpt_to)) ? htmlEditFormat(qRecords.original_rcpt_to) : '—'#
                                            </td></tr>
                                    </table>
                                </div>

                                <div class="col-sm-6 col-lg-3">
                                    <div class="detail-section-label">Message ID</div>
                                    <div class="mono" style="font-size:0.68rem;color:var(--text-secondary);
                                                            word-break:break-all;line-height:1.5;">
                                        #len(trim(qRecords.message_id)) ? htmlEditFormat(qRecords.message_id) : '—'#
                                    </div>
                                </div>

                            </div>
                        </td>
                    </tr>
                </cfloop>
                </tbody>
            </table>

            <!--- Pagination --->
            <cfif totalPages GT 1>
                <div class="d-flex justify-content-between align-items-center px-3 py-2"
                     style="border-top:1px solid var(--border-color);">
                    <div>
                        <cfif currentPage GT 1>
                            <a href="#pageUrl(currentPage - 1)#" class="btn btn-sm btn-outline-secondary">
                                <i class="bi bi-chevron-left"></i> Prev
                            </a>
                        </cfif>
                    </div>
                    <span class="mono" style="font-size:0.72rem;color:var(--text-muted);">
                        #((currentPage-1)*pageSize)+1# – #min(currentPage*pageSize, totalRows)#
                        of #formatNumber(totalRows)#
                    </span>
                    <div>
                        <cfif currentPage LT totalPages>
                            <a href="#pageUrl(currentPage + 1)#" class="btn btn-sm btn-outline-secondary">
                                Next <i class="bi bi-chevron-right"></i>
                            </a>
                        </cfif>
                    </div>
                </div>
            </cfif>

        </div>
    </div>
</cfif>

<script>
document.querySelectorAll('.ruf-row').forEach(function(row) {
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
