<!--- admin/alignment.cfm --->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    // ── Filters ───────────────────────────────────────────────────────────────
    param name="url.days"    default="30";
    param name="url.domain"  default="";
    param name="url.outcome" default="";   // all | both | dkim | spf | neither
    param name="url.page"    default="1";

    filterDays = isNumeric(url.days) ? int(url.days) : 30;
    if (NOT listFind("7,30,90,365,0", filterDays)) filterDays = 30;
    dateLabel  = filterDays EQ 0 ? "All time" : "Last #filterDays# days";
    dateClause = filterDays GT 0
        ? "AND rpt.mindate >= DATE_SUB(NOW(), INTERVAL #filterDays# DAY)"
        : "";

    filterDomain  = len(trim(url.domain))  ? trim(url.domain)  : "";
    filterOutcome = listFind("both,dkim,spf,neither", lCase(url.outcome))
        ? lCase(url.outcome) : "";

    domainClause = len(filterDomain) ? "AND rpt.domain = ?" : "";

    outcomeClause = "";
    switch (filterOutcome) {
        case "both":    outcomeClause = "AND rec.dkim_align = 'pass' AND rec.spf_align = 'pass'";    break;
        case "dkim":    outcomeClause = "AND rec.dkim_align = 'pass' AND rec.spf_align != 'pass'";   break;
        case "spf":     outcomeClause = "AND rec.dkim_align != 'pass' AND rec.spf_align = 'pass'";   break;
        case "neither": outcomeClause = "AND rec.dkim_align != 'pass' AND rec.spf_align != 'pass'";  break;
    }

    pageSize    = 50;
    currentPage = isNumeric(url.page) AND url.page GTE 1 ? int(url.page) : 1;
    pageOffset  = (currentPage - 1) * pageSize;

    baseParams = len(filterDomain)
        ? [{ value: filterDomain, cfsqltype: "cf_sql_varchar" }]
        : [];

    // ── Domain list for dropdown ──────────────────────────────────────────────
    qDomainList = queryExecute("
        SELECT DISTINCT domain FROM report ORDER BY domain ASC
    ", {}, { datasource: application.db.dsn });

    // ── Outcome summary — the alignment matrix ────────────────────────────────
    qSummary = queryExecute("
        SELECT
            SUM(rec.rcount)                                                                AS total,
            SUM(CASE WHEN rec.dkim_align = 'pass' AND rec.spf_align = 'pass'
                     THEN rec.rcount ELSE 0 END)                                           AS both_pass,
            SUM(CASE WHEN rec.dkim_align = 'pass' AND rec.spf_align != 'pass'
                     THEN rec.rcount ELSE 0 END)                                           AS dkim_only,
            SUM(CASE WHEN rec.dkim_align != 'pass' AND rec.spf_align = 'pass'
                     THEN rec.rcount ELSE 0 END)                                           AS spf_only,
            SUM(CASE WHEN rec.dkim_align != 'pass' AND rec.spf_align != 'pass'
                     THEN rec.rcount ELSE 0 END)                                           AS neither,
            -- DKIM standalone stats
            SUM(CASE WHEN rec.dkim_align = 'pass' THEN rec.rcount ELSE 0 END)             AS dkim_pass_total,
            SUM(CASE WHEN rec.dkim_align != 'pass' THEN rec.rcount ELSE 0 END)            AS dkim_fail_total,
            -- SPF standalone stats
            SUM(CASE WHEN rec.spf_align = 'pass' THEN rec.rcount ELSE 0 END)              AS spf_pass_total,
            SUM(CASE WHEN rec.spf_align != 'pass' THEN rec.rcount ELSE 0 END)             AS spf_fail_total,
            -- Disposition breakdown
            SUM(CASE WHEN rec.disposition = 'none'       THEN rec.rcount ELSE 0 END)      AS disp_none,
            SUM(CASE WHEN rec.disposition = 'quarantine' THEN rec.rcount ELSE 0 END)      AS disp_quarantine,
            SUM(CASE WHEN rec.disposition = 'reject'     THEN rec.rcount ELSE 0 END)      AS disp_reject
        FROM rptrecord rec
        JOIN report rpt ON rpt.id = rec.report_id
        WHERE 1=1
            #dateClause#
            #domainClause#
    ", baseParams, { datasource: application.db.dsn });

    total        = qSummary.total GT 0 ? qSummary.total : 0;
    bothPass     = qSummary.both_pass;
    dkimOnly     = qSummary.dkim_only;
    spfOnly      = qSummary.spf_only;
    neitherPass  = qSummary.neither;
    dmarcPass    = bothPass + dkimOnly + spfOnly;  // DMARC passes on either auth method

    pctOf = function(n) {
        return total GT 0 ? numberFormat(100 * n / total, "99.9") : 0;
    };

    // ── Top DKIM selectors (for failing messages) ─────────────────────────────
    qSelectors = queryExecute("
        SELECT
            rec.dkimdomain,
            rec.dkimresult,
            COUNT(DISTINCT rpt.id)                                                         AS report_count,
            SUM(rec.rcount)                                                                AS messages
        FROM rptrecord rec
        JOIN report rpt ON rpt.id = rec.report_id
        WHERE rec.dkimdomain IS NOT NULL AND rec.dkimdomain <> ''
            #dateClause#
            #domainClause#
        GROUP BY rec.dkimdomain, rec.dkimresult
        ORDER BY messages DESC
        LIMIT 10
    ", baseParams, { datasource: application.db.dsn });

    // ── Top SPF domains ───────────────────────────────────────────────────────
    qSPFDomains = queryExecute("
        SELECT
            rec.spfdomain,
            rec.spfresult,
            SUM(rec.rcount)                                                                AS messages
        FROM rptrecord rec
        JOIN report rpt ON rpt.id = rec.report_id
        WHERE rec.spfdomain IS NOT NULL AND rec.spfdomain <> ''
            #dateClause#
            #domainClause#
        GROUP BY rec.spfdomain, rec.spfresult
        ORDER BY messages DESC
        LIMIT 10
    ", baseParams, { datasource: application.db.dsn });

    // ── Record count for pagination ───────────────────────────────────────────
    qCount = queryExecute("
        SELECT COUNT(*) AS total_rows
        FROM rptrecord rec
        JOIN report rpt ON rpt.id = rec.report_id
        WHERE 1=1
            #dateClause#
            #domainClause#
            #outcomeClause#
    ", baseParams, { datasource: application.db.dsn });

    totalRows  = qCount.total_rows;
    totalPages = ceiling(totalRows / pageSize);
    if (currentPage GT totalPages AND totalPages GT 0) currentPage = totalPages;

    // ── Record detail table ───────────────────────────────────────────────────
    qRecords = queryExecute("
        SELECT
            rpt.domain,
            rpt.org,
            rpt.mindate,
            CASE
                WHEN rec.ip  IS NOT NULL AND rec.ip  > 0 THEN INET_NTOA(rec.ip)
                WHEN rec.ip6 IS NOT NULL AND rec.ip6 <> '' THEN HEX(rec.ip6)
                ELSE 'unknown'
            END                                                                            AS source_ip,
            rec.rcount,
            rec.dkim_align,
            rec.spf_align,
            rec.dkimdomain,
            rec.dkimresult,
            rec.spfdomain,
            rec.spfresult,
            rec.disposition,
            rec.identifier_hfrom
        FROM rptrecord rec
        JOIN report rpt ON rpt.id = rec.report_id
        WHERE 1=1
            #dateClause#
            #domainClause#
            #outcomeClause#
        ORDER BY rec.rcount DESC, rpt.mindate DESC
        LIMIT #pageSize# OFFSET #pageOffset#
    ", baseParams, { datasource: application.db.dsn });

    // ── URL builder helper (preserves all filters) ────────────────────────────
    function pageUrl(numeric p, string outcome="", string domain="") {
        var q = "?days=#filterDays#&page=#p#";
        var o = len(arguments.outcome) ? arguments.outcome : filterOutcome;
        var dm = len(arguments.domain) ? arguments.domain : filterDomain;
        if (len(o))  q &= "&outcome=#o#";
        if (len(dm)) q &= "&domain=#urlEncodedFormat(dm)#";
        return q;
    }
</cfscript>

<cfset variables.pageTitle = "Alignment">
<cfset variables.activeNav = "alignment">
<cfinclude template="/includes/header.cfm">

<cfoutput>

<!--- ── Filter bar ──────────────────────────────────────────────────────── --->
<div class="d-flex flex-wrap gap-2 align-items-center justify-content-between mb-3">

    <div class="d-flex gap-2 align-items-center flex-wrap">
        <!--- Domain filter --->
        <form method="get" class="d-flex gap-2 align-items-center m-0">
            <input type="hidden" name="days"    value="#filterDays#">
            <input type="hidden" name="outcome" value="#filterOutcome#">
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

        <span class="mono" style="font-size:0.75rem;color:var(--text-muted);">
            #formatNumber(total)# messages &middot; #dateLabel#
        </span>
    </div>

    <div class="btn-group btn-group-sm">
        <cfset dSuffix = len(filterDomain) ? "&domain=" & urlEncodedFormat(filterDomain) : "">
        <cfset oSuffix = len(filterOutcome) ? "&outcome=" & filterOutcome : "">
        <a href="?days=7#oSuffix##dSuffix#"   class="btn btn-outline-secondary #(filterDays EQ 7   ? 'active':'')#">7d</a>
        <a href="?days=30#oSuffix##dSuffix#"  class="btn btn-outline-secondary #(filterDays EQ 30  ? 'active':'')#">30d</a>
        <a href="?days=90#oSuffix##dSuffix#"  class="btn btn-outline-secondary #(filterDays EQ 90  ? 'active':'')#">90d</a>
        <a href="?days=365#oSuffix##dSuffix#" class="btn btn-outline-secondary #(filterDays EQ 365 ? 'active':'')#">1y</a>
        <a href="?days=0#oSuffix##dSuffix#"   class="btn btn-outline-secondary #(filterDays EQ 0   ? 'active':'')#">All</a>
    </div>
</div>

<!--- ── Outcome matrix ──────────────────────────────────────────────────── --->
<div class="row g-3 mb-3">

    <!--- DMARC pass (both + either) --->
    <div class="col-6 col-lg-3">
        <a href="#pageUrl(1, 'both')#" class="outcome-tile outcome-both #(filterOutcome EQ 'both' ? 'active' : '')#">
            <div class="outcome-icons">
                <span class="auth-pill auth-pass">DKIM</span>
                <span class="auth-pill auth-pass">SPF</span>
            </div>
            <div class="outcome-value">#formatNumber(bothPass)#</div>
            <div class="outcome-pct">#pctOf(bothPass)#%</div>
            <div class="outcome-label">Both pass</div>
        </a>
    </div>

    <div class="col-6 col-lg-3">
        <a href="#pageUrl(1, 'dkim')#" class="outcome-tile outcome-dkim #(filterOutcome EQ 'dkim' ? 'active' : '')#">
            <div class="outcome-icons">
                <span class="auth-pill auth-pass">DKIM</span>
                <span class="auth-pill auth-fail">SPF</span>
            </div>
            <div class="outcome-value">#formatNumber(dkimOnly)#</div>
            <div class="outcome-pct">#pctOf(dkimOnly)#%</div>
            <div class="outcome-label">DKIM only</div>
        </a>
    </div>

    <div class="col-6 col-lg-3">
        <a href="#pageUrl(1, 'spf')#" class="outcome-tile outcome-spf #(filterOutcome EQ 'spf' ? 'active' : '')#">
            <div class="outcome-icons">
                <span class="auth-pill auth-fail">DKIM</span>
                <span class="auth-pill auth-pass">SPF</span>
            </div>
            <div class="outcome-value">#formatNumber(spfOnly)#</div>
            <div class="outcome-pct">#pctOf(spfOnly)#%</div>
            <div class="outcome-label">SPF only</div>
        </a>
    </div>

    <div class="col-6 col-lg-3">
        <a href="#pageUrl(1, 'neither')#" class="outcome-tile outcome-neither #(filterOutcome EQ 'neither' ? 'active' : '')#">
            <div class="outcome-icons">
                <span class="auth-pill auth-fail">DKIM</span>
                <span class="auth-pill auth-fail">SPF</span>
            </div>
            <div class="outcome-value" style="color:var(--accent-red)">#formatNumber(neitherPass)#</div>
            <div class="outcome-pct">#pctOf(neitherPass)#%</div>
            <div class="outcome-label">Neither — DMARC fail</div>
        </a>
    </div>

</div>

<!--- ── Auth method stats + disposition ─────────────────────────────────── --->
<div class="row g-3 mb-3">

    <div class="col-md-4"><div class="card h-100">
        <div class="card-header">DKIM Alignment</div>
        <div class="card-body">
            <div class="d-flex justify-content-between mb-1" style="font-size:0.78rem;">
                <span style="color:var(--text-muted)">Pass</span>
                <span class="mono" style="color:var(--accent-green)">
                    #formatNumber(qSummary.dkim_pass_total)#
                    (#pctOf(qSummary.dkim_pass_total)#%)
                </span>
            </div>
            <div class="pass-bar mb-2" style="height:6px;">
                <div class="pass-bar-fill #(pctOf(qSummary.dkim_pass_total) GTE 95 ? 'high' : (pctOf(qSummary.dkim_pass_total) GTE 75 ? 'medium' : 'low'))#"
                     style="width:#pctOf(qSummary.dkim_pass_total)#%"></div>
            </div>
            <div class="d-flex justify-content-between" style="font-size:0.78rem;">
                <span style="color:var(--text-muted)">Fail</span>
                <span class="mono" style="color:#(qSummary.dkim_fail_total GT 0 ? 'var(--accent-red)' : 'var(--text-muted)')#">
                    #formatNumber(qSummary.dkim_fail_total)#
                    (#pctOf(qSummary.dkim_fail_total)#%)
                </span>
            </div>

            <cfif qSelectors.recordCount GT 0>
                <hr style="border-color:var(--border-color);margin:0.75rem 0 0.5rem;">
                <div style="font-family:var(--font-mono);font-size:0.62rem;text-transform:uppercase;
                            letter-spacing:0.1em;color:var(--text-muted);margin-bottom:0.4rem;">
                    Top signing domains
                </div>
                <cfloop query="qSelectors">
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <span class="mono" style="font-size:0.72rem;color:var(--text-secondary);
                                                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%;"
                              title="#htmlEditFormat(qSelectors.dkimdomain)#">
                            #htmlEditFormat(qSelectors.dkimdomain)#
                        </span>
                        <div class="d-flex align-items-center gap-1">
                            <span class="badge badge-#(lCase(qSelectors.dkimresult) EQ 'pass' ? 'pass' : 'fail')#"
                                  style="font-size:0.6rem;">
                                #lCase(htmlEditFormat(qSelectors.dkimresult))#
                            </span>
                            <span class="mono" style="font-size:0.7rem;color:var(--text-muted);">
                                #formatNumber(qSelectors.messages)#
                            </span>
                        </div>
                    </div>
                </cfloop>
            </cfif>
        </div>
    </div></div>

    <div class="col-md-4"><div class="card h-100">
        <div class="card-header">SPF Alignment</div>
        <div class="card-body">
            <div class="d-flex justify-content-between mb-1" style="font-size:0.78rem;">
                <span style="color:var(--text-muted)">Pass</span>
                <span class="mono" style="color:var(--accent-green)">
                    #formatNumber(qSummary.spf_pass_total)#
                    (#pctOf(qSummary.spf_pass_total)#%)
                </span>
            </div>
            <div class="pass-bar mb-2" style="height:6px;">
                <div class="pass-bar-fill #(pctOf(qSummary.spf_pass_total) GTE 95 ? 'high' : (pctOf(qSummary.spf_pass_total) GTE 75 ? 'medium' : 'low'))#"
                     style="width:#pctOf(qSummary.spf_pass_total)#%"></div>
            </div>
            <div class="d-flex justify-content-between" style="font-size:0.78rem;">
                <span style="color:var(--text-muted)">Fail</span>
                <span class="mono" style="color:#(qSummary.spf_fail_total GT 0 ? 'var(--accent-red)' : 'var(--text-muted)')#">
                    #formatNumber(qSummary.spf_fail_total)#
                    (#pctOf(qSummary.spf_fail_total)#%)
                </span>
            </div>

            <cfif qSPFDomains.recordCount GT 0>
                <hr style="border-color:var(--border-color);margin:0.75rem 0 0.5rem;">
                <div style="font-family:var(--font-mono);font-size:0.62rem;text-transform:uppercase;
                            letter-spacing:0.1em;color:var(--text-muted);margin-bottom:0.4rem;">
                    Top envelope-from domains
                </div>
                <cfloop query="qSPFDomains">
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <span class="mono" style="font-size:0.72rem;color:var(--text-secondary);
                                                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%;"
                              title="#htmlEditFormat(qSPFDomains.spfdomain)#">
                            #htmlEditFormat(qSPFDomains.spfdomain)#
                        </span>
                        <div class="d-flex align-items-center gap-1">
                            <span class="badge badge-#(lCase(qSPFDomains.spfresult) EQ 'pass' ? 'pass' : 'fail')#"
                                  style="font-size:0.6rem;">
                                #lCase(htmlEditFormat(qSPFDomains.spfresult))#
                            </span>
                            <span class="mono" style="font-size:0.7rem;color:var(--text-muted);">
                                #formatNumber(qSPFDomains.messages)#
                            </span>
                        </div>
                    </div>
                </cfloop>
            </cfif>
        </div>
    </div></div>

    <div class="col-md-4"><div class="card h-100">
        <div class="card-header">Disposition</div>
        <div class="card-body">
            <div class="disp-row">
                <span>Delivered <span style="font-size:0.65rem;color:var(--text-muted)">(none)</span></span>
                <span class="mono">#formatNumber(qSummary.disp_none)#</span>
            </div>
            <div class="pass-bar mb-2" style="height:4px;">
                <div class="pass-bar-fill high" style="width:#pctOf(qSummary.disp_none)#%"></div>
            </div>

            <div class="disp-row">
                <span style="color:#(qSummary.disp_quarantine GT 0 ? 'var(--accent-yellow)' : 'var(--text-secondary)')#">
                    Quarantined
                </span>
                <span class="mono" style="color:#(qSummary.disp_quarantine GT 0 ? 'var(--accent-yellow)' : 'inherit')#">
                    #formatNumber(qSummary.disp_quarantine)#
                </span>
            </div>
            <div class="pass-bar mb-2" style="height:4px;">
                <div class="pass-bar-fill medium" style="width:#pctOf(qSummary.disp_quarantine)#%"></div>
            </div>

            <div class="disp-row">
                <span style="color:#(qSummary.disp_reject GT 0 ? 'var(--accent-red)' : 'var(--text-secondary)')#">
                    Rejected
                </span>
                <span class="mono" style="color:#(qSummary.disp_reject GT 0 ? 'var(--accent-red)' : 'inherit')#">
                    #formatNumber(qSummary.disp_reject)#
                </span>
            </div>
            <div class="pass-bar" style="height:4px;">
                <div class="pass-bar-fill low" style="width:#pctOf(qSummary.disp_reject)#%"></div>
            </div>

            <hr style="border-color:var(--border-color);margin:0.9rem 0 0.6rem;">
            <div style="font-size:0.72rem;color:var(--text-muted);">
                DMARC pass rate:
                <span class="mono" style="color:#(pctOf(dmarcPass) GTE 95 ? 'var(--accent-green)' : (pctOf(dmarcPass) GTE 75 ? 'var(--accent-yellow)' : 'var(--accent-red)'))#">
                    #pctOf(dmarcPass)#%
                </span>
                <span style="font-size:0.68rem;">(#formatNumber(dmarcPass)# of #formatNumber(total)#)</span>
            </div>
        </div>
    </div></div>

</div>

<!--- ── Record table ────────────────────────────────────────────────────── --->
<div class="card">
    <div class="card-header d-flex align-items-center justify-content-between">
        <span>
            Record Detail
            <cfif len(filterOutcome)>
                &nbsp;<span class="badge badge-neutral" style="font-size:0.65rem;text-transform:none;letter-spacing:0;">
                    filtered: #filterOutcome#
                    &nbsp;<a href="#pageUrl(1, '', filterDomain)#"
                             style="color:var(--text-muted);text-decoration:none;"
                             title="Clear outcome filter">&times;</a>
                </span>
            </cfif>
        </span>
        <span class="mono" style="font-size:0.72rem;color:var(--text-muted);">
            #formatNumber(totalRows)# record#(totalRows NEQ 1 ? 's' : '')#
            <cfif totalPages GT 1>
                &middot; page #currentPage# of #totalPages#
            </cfif>
        </span>
    </div>
    <div class="card-body p-0">
        <cfif totalRows EQ 0>
            <div class="p-3" style="color:var(--text-muted);font-size:0.85rem;">
                No records match the selected filters.
            </div>
        <cfelse>
            <div style="overflow-x:auto;">
            <table class="table mb-0 align-table">
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Domain</th>
                        <th>Header From</th>
                        <th style="text-align:center">DKIM</th>
                        <th>DKIM domain</th>
                        <th style="text-align:center">SPF</th>
                        <th>SPF domain</th>
                        <th style="text-align:center">Disposition</th>
                        <th style="text-align:right">Count</th>
                        <th>Period</th>
                        <th>Reporter</th>
                    </tr>
                </thead>
                <tbody>
                <cfloop query="qRecords">
                    <cfset dkimPass = (lCase(qRecords.dkim_align) EQ "pass")>
                    <cfset spfPass  = (lCase(qRecords.spf_align)  EQ "pass")>
                    <cfset dmarcOk  = dkimPass OR spfPass>
                    <tr>
                        <td class="mono" style="font-size:0.75rem;white-space:nowrap;">
                            #htmlEditFormat(qRecords.source_ip)#
                        </td>
                        <td style="font-size:0.78rem;">#htmlEditFormat(qRecords.domain)#</td>
                        <td class="mono" style="font-size:0.75rem;color:var(--text-secondary);">
                            #htmlEditFormat(qRecords.identifier_hfrom)#
                        </td>
                        <td style="text-align:center;">
                            <span class="auth-pill #(dkimPass ? 'auth-pass' : 'auth-fail')#">
                                #(dkimPass ? 'pass' : 'fail')#
                            </span>
                        </td>
                        <td class="mono" style="font-size:0.72rem;color:var(--text-secondary);">
                            <cfif len(trim(qRecords.dkimdomain))>
                                #htmlEditFormat(qRecords.dkimdomain)#
                                <cfif len(trim(qRecords.dkimresult)) AND lCase(qRecords.dkimresult) NEQ lCase(qRecords.dkim_align)>
                                    <span style="color:var(--text-muted);font-size:0.68rem;">
                                        (#lCase(htmlEditFormat(qRecords.dkimresult))#)
                                    </span>
                                </cfif>
                            <cfelse>
                                <span style="color:var(--text-muted);">—</span>
                            </cfif>
                        </td>
                        <td style="text-align:center;">
                            <span class="auth-pill #(spfPass ? 'auth-pass' : 'auth-fail')#">
                                #(spfPass ? 'pass' : 'fail')#
                            </span>
                        </td>
                        <td class="mono" style="font-size:0.72rem;color:var(--text-secondary);">
                            <cfif len(trim(qRecords.spfdomain))>
                                #htmlEditFormat(qRecords.spfdomain)#
                                <cfif len(trim(qRecords.spfresult)) AND lCase(qRecords.spfresult) NEQ lCase(qRecords.spf_align)>
                                    <span style="color:var(--text-muted);font-size:0.68rem;">
                                        (#lCase(htmlEditFormat(qRecords.spfresult))#)
                                    </span>
                                </cfif>
                            <cfelse>
                                <span style="color:var(--text-muted);">—</span>
                            </cfif>
                        </td>
                        <td style="text-align:center;">
                            <cfset disp = lCase(qRecords.disposition)>
                            <span class="badge badge-#(disp EQ 'none' ? 'neutral' : (disp EQ 'quarantine' ? 'warn' : 'fail'))#"
                                  style="font-size:0.62rem;">
                                #(disp EQ 'none' ? 'delivered' : disp)#
                            </span>
                        </td>
                        <td class="mono" style="text-align:right;">#formatNumber(qRecords.rcount)#</td>
                        <td class="mono" style="font-size:0.72rem;color:var(--text-muted);white-space:nowrap;">
                            #dateFormat(qRecords.mindate, "mmm d")#
                        </td>
                        <td style="font-size:0.72rem;color:var(--text-secondary);">
                            #htmlEditFormat(qRecords.org)#
                        </td>
                    </tr>
                </cfloop>
                </tbody>
            </table>
            </div>

            <!--- Pagination --->
            <cfif totalPages GT 1>
                <div class="d-flex justify-content-between align-items-center px-3 py-2"
                     style="border-top:1px solid var(--border-color);">
                    <div>
                        <cfif currentPage GT 1>
                            <a href="#pageUrl(currentPage - 1)#"
                               class="btn btn-sm btn-outline-secondary">
                                <i class="bi bi-chevron-left"></i> Prev
                            </a>
                        </cfif>
                    </div>
                    <span class="mono" style="font-size:0.72rem;color:var(--text-muted);">
                        #((currentPage-1)*pageSize)+1# –
                        #min(currentPage*pageSize, totalRows)#
                        of #formatNumber(totalRows)#
                    </span>
                    <div>
                        <cfif currentPage LT totalPages>
                            <a href="#pageUrl(currentPage + 1)#"
                               class="btn btn-sm btn-outline-secondary">
                                Next <i class="bi bi-chevron-right"></i>
                            </a>
                        </cfif>
                    </div>
                </div>
            </cfif>

        </cfif>
    </div>
</div>

<style>
    .outcome-tile {
        display: block;
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 0.85rem 1rem;
        text-decoration: none;
        transition: border-color 0.15s, background 0.15s;
        cursor: pointer;
    }
    .outcome-tile:hover { background: var(--bg-card-hover); border-color: #444c56; }
    .outcome-tile.active { border-color: var(--accent-blue); background: rgba(56,139,253,0.06); }

    .outcome-icons  { margin-bottom: 0.5rem; }
    .outcome-value  {
        font-family: var(--font-mono);
        font-size: 1.5rem;
        font-weight: 600;
        color: var(--text-primary);
        line-height: 1;
    }
    .outcome-pct   { font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); margin-top: 0.15rem; }
    .outcome-label { font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.3rem; }

    .outcome-neither .outcome-value { color: var(--accent-red); }

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

    .disp-row {
        display: flex;
        justify-content: space-between;
        font-size: 0.78rem;
        color: var(--text-secondary);
        margin-bottom: 0.25rem;
    }

    .align-table tbody tr:hover td { background: var(--bg-card-hover) !important; }
</style>

</cfoutput>

<cfinclude template="/includes/footer.cfm">
