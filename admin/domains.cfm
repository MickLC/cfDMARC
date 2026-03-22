<!--- admin/domains.cfm --->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    // ── Date filter ───────────────────────────────────────────────────────────
    param name="url.days" default="90";
    filterDays = isNumeric(url.days) ? int(url.days) : 90;
    if (NOT listFind("7,30,90,365,0", filterDays)) filterDays = 90;
    dateLabel  = filterDays EQ 0 ? "All time" : "Last #filterDays# days";
    dateClause = filterDays GT 0
        ? "AND rpt.mindate >= DATE_SUB(NOW(), INTERVAL #filterDays# DAY)"
        : "";

    // ── Per-domain summary ────────────────────────────────────────────────────
    qDomains = queryExecute("
        SELECT
            rpt.domain,
            COUNT(DISTINCT rpt.id)                                                       AS report_count,
            COUNT(DISTINCT rpt.org)                                                      AS reporter_count,
            COUNT(DISTINCT CASE WHEN rec.ip  > 0  THEN rec.ip
                                WHEN rec.ip6 <> '' THEN rec.ip6 END)                    AS source_count,
            SUM(rec.rcount)                                                              AS messages,
            SUM(CASE WHEN rec.dkim_align = 'pass' OR  rec.spf_align = 'pass'
                     THEN rec.rcount ELSE 0 END)                                         AS passes,
            SUM(CASE WHEN rec.dkim_align != 'pass' AND rec.spf_align != 'pass'
                     THEN rec.rcount ELSE 0 END)                                         AS failures,
            ROUND(100.0 * SUM(CASE WHEN rec.dkim_align = 'pass' OR rec.spf_align = 'pass'
                                   THEN rec.rcount ELSE 0 END)
                  / NULLIF(SUM(rec.rcount), 0), 1)                                       AS pass_rate,
            SUM(CASE WHEN rec.disposition = 'quarantine' THEN rec.rcount ELSE 0 END)    AS disp_quarantine,
            SUM(CASE WHEN rec.disposition = 'reject'     THEN rec.rcount ELSE 0 END)    AS disp_reject,
            -- Most-recently-reported policy values for this domain
            SUBSTRING_INDEX(GROUP_CONCAT(rpt.policy_p    ORDER BY rpt.received_at DESC), ',', 1) AS policy_p,
            SUBSTRING_INDEX(GROUP_CONCAT(rpt.policy_sp   ORDER BY rpt.received_at DESC), ',', 1) AS policy_sp,
            SUBSTRING_INDEX(GROUP_CONCAT(rpt.policy_adkim ORDER BY rpt.received_at DESC), ',', 1) AS policy_adkim,
            SUBSTRING_INDEX(GROUP_CONCAT(rpt.policy_aspf  ORDER BY rpt.received_at DESC), ',', 1) AS policy_aspf,
            SUBSTRING_INDEX(GROUP_CONCAT(rpt.policy_pct   ORDER BY rpt.received_at DESC), ',', 1) AS policy_pct,
            MAX(rpt.received_at)                                                         AS last_report,
            MIN(rpt.mindate)                                                             AS first_seen
        FROM report rpt
        LEFT JOIN rptrecord rec ON rec.report_id = rpt.id
        WHERE 1=1 #dateClause#
        GROUP BY rpt.domain
        ORDER BY messages DESC
    ", {}, { datasource: application.db.dsn });

    // ── 30-day daily trend per domain (for sparklines) ────────────────────────
    // Fetch all at once, keyed by domain in CF after query
    qTrends = queryExecute("
        SELECT
            rpt.domain,
            DATE(rpt.mindate)                                                            AS report_date,
            SUM(rec.rcount)                                                              AS messages,
            SUM(CASE WHEN rec.dkim_align = 'pass' OR rec.spf_align = 'pass'
                     THEN rec.rcount ELSE 0 END)                                         AS pass_count
        FROM report rpt
        LEFT JOIN rptrecord rec ON rec.report_id = rpt.id
        WHERE rpt.mindate >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY rpt.domain, DATE(rpt.mindate)
        ORDER BY rpt.domain, report_date ASC
    ", {}, { datasource: application.db.dsn });

    // Build sparkline data structures: { domain: { msgs:[], rates:[] } }
    // Note: no var keyword here — var is only valid inside functions in Lucee.
    sparkData = {};
    for (trow in qTrends) {
        trendDomain = trow.domain;
        if (NOT structKeyExists(sparkData, trendDomain)) {
            sparkData[trendDomain] = { msgs: [], rates: [] };
        }
        arrayAppend(sparkData[trendDomain].msgs, trow.messages);
        trendRate = trow.messages GT 0
            ? numberFormat(100 * trow.pass_count / trow.messages, "99.9")
            : 0;
        arrayAppend(sparkData[trendDomain].rates, trendRate);
    }

    // ── Policy helpers ────────────────────────────────────────────────────────
    function policyBadgeClass(required string p) {
        switch (lCase(arguments.p)) {
            case "reject":      return "fail";
            case "quarantine":  return "warn";
            case "none":        return "neutral";
            default:            return "neutral";
        }
    }

    function alignLabel(required string a) {
        return lCase(arguments.a) EQ "s" ? "strict" : "relaxed";
    }
</cfscript>

<cfset variables.pageTitle = "Domains">
<cfset variables.activeNav = "domains">
<cfinclude template="/includes/header.cfm">

<cfoutput>

<!--- ── Filter bar ──────────────────────────────────────────────────────── --->
<div class="d-flex align-items-center justify-content-between mb-3">
    <span class="mono" style="font-size:0.75rem;color:var(--text-muted);">
        #qDomains.recordCount# domain#(qDomains.recordCount NEQ 1 ? 's' : '')# &middot; #dateLabel#
    </span>
    <div class="btn-group btn-group-sm">
        <a href="?days=7"   class="btn btn-outline-secondary #(filterDays EQ 7   ? 'active' : '')#">7d</a>
        <a href="?days=30"  class="btn btn-outline-secondary #(filterDays EQ 30  ? 'active' : '')#">30d</a>
        <a href="?days=90"  class="btn btn-outline-secondary #(filterDays EQ 90  ? 'active' : '')#">90d</a>
        <a href="?days=365" class="btn btn-outline-secondary #(filterDays EQ 365 ? 'active' : '')#">1y</a>
        <a href="?days=0"   class="btn btn-outline-secondary #(filterDays EQ 0   ? 'active' : '')#">All</a>
    </div>
</div>

<cfif qDomains.recordCount EQ 0>
    <div class="alert alert-info">No domain data found for the selected time range.</div>
<cfelse>

    <cfloop query="qDomains">
        <cfset dom       = qDomains.domain>
        <cfset passRate  = qDomains.pass_rate NEQ "" ? qDomains.pass_rate : 0>
        <cfset barClass  = passRate GTE 95 ? "high" : (passRate GTE 75 ? "medium" : "low")>
        <cfset badgeCls  = passRate GTE 95 ? "pass" : (passRate GTE 75 ? "warn" : "fail")>
        <cfset cardId    = "domain-detail-#qDomains.currentRow#">

        <!--- ── Domain card ──────────────────────────────────────────────── --->
        <div class="domain-card mb-3">

            <!--- Card header: click to expand --->
            <div class="domain-card-header" data-target="#cardId#">
                <div class="row align-items-center g-0">

                    <!--- Domain name + policy pill --->
                    <div class="col-12 col-md-3 mb-2 mb-md-0">
                        <div class="domain-name">#htmlEditFormat(dom)#</div>
                        <div class="mt-1">
                            <span class="badge badge-#policyBadgeClass(qDomains.policy_p)# policy-badge">
                                p=#lCase(htmlEditFormat(qDomains.policy_p))#
                            </span>
                            <cfif len(trim(qDomains.policy_sp)) AND qDomains.policy_sp NEQ qDomains.policy_p>
                                <span class="badge badge-neutral policy-badge">
                                    sp=#lCase(htmlEditFormat(qDomains.policy_sp))#
                                </span>
                            </cfif>
                            <cfif len(trim(qDomains.policy_pct)) AND qDomains.policy_pct NEQ "100">
                                <span class="badge badge-warn policy-badge">
                                    pct=#htmlEditFormat(qDomains.policy_pct)#%
                                </span>
                            </cfif>
                        </div>
                    </div>

                    <!--- Pass rate bar --->
                    <div class="col-12 col-md-3 mb-2 mb-md-0 px-md-3">
                        <div class="d-flex justify-content-between" style="font-size:0.72rem;color:var(--text-muted);margin-bottom:0.3rem;">
                            <span>Pass rate</span>
                            <span style="font-family:var(--font-mono);
                                color:#(passRate GTE 95 ? 'var(--accent-green)' : (passRate GTE 75 ? 'var(--accent-yellow)' : 'var(--accent-red)'))#">
                                #passRate#%
                            </span>
                        </div>
                        <div class="pass-bar" style="height:6px;">
                            <div class="pass-bar-fill #barClass#" style="width:#passRate#%"></div>
                        </div>
                        <div style="font-size:0.68rem;color:var(--text-muted);margin-top:0.25rem;">
                            #formatNumber(qDomains.messages)# messages &middot;
                            <span style="color:var(--accent-red)">#formatNumber(qDomains.failures)# failed</span>
                        </div>
                    </div>

                    <!--- Sparkline (30-day pass rate trend) --->
                    <div class="col-12 col-md-3 mb-2 mb-md-0 px-md-2">
                        <div style="font-size:0.65rem;color:var(--text-muted);margin-bottom:0.2rem;">
                            30d trend
                        </div>
                        <div id="spark-#qDomains.currentRow#" style="min-height:40px;"></div>
                    </div>

                    <!--- Stats summary --->
                    <div class="col-12 col-md-2 px-md-2">
                        <div class="stat-mini-row">
                            <span class="stat-mini-label">Reports</span>
                            <span class="stat-mini-val mono">#formatNumber(qDomains.report_count)#</span>
                        </div>
                        <div class="stat-mini-row">
                            <span class="stat-mini-label">Sources</span>
                            <span class="stat-mini-val mono">#qDomains.source_count#</span>
                        </div>
                        <div class="stat-mini-row">
                            <span class="stat-mini-label">Reporters</span>
                            <span class="stat-mini-val mono">#qDomains.reporter_count#</span>
                        </div>
                    </div>

                    <!--- Chevron --->
                    <div class="col-auto ms-auto d-flex align-items-center">
                        <i class="bi bi-chevron-down toggle-icon" style="color:var(--text-muted);font-size:0.85rem;"></i>
                    </div>

                </div>
            </div>

            <!--- ── Expanded detail panel ─────────────────────────────────── --->
            <div id="#cardId#" class="domain-card-detail" style="display:none;">
                <div class="row g-3 p-3">

                    <!--- Policy details --->
                    <div class="col-sm-6 col-lg-3">
                        <div class="detail-section-label">Published Policy</div>
                        <table class="detail-mini-table">
                            <tr><td>Policy (p=)</td>
                                <td><span class="badge badge-#policyBadgeClass(qDomains.policy_p)# policy-badge">
                                    #lCase(htmlEditFormat(qDomains.policy_p))#</span></td></tr>
                            <tr><td>Subdomain (sp=)</td>
                                <td><span class="badge badge-#policyBadgeClass(qDomains.policy_sp)# policy-badge">
                                    #lCase(htmlEditFormat(qDomains.policy_sp))#</span></td></tr>
                            <tr><td>DKIM alignment</td>
                                <td class="mono">#alignLabel(qDomains.policy_adkim)#</td></tr>
                            <tr><td>SPF alignment</td>
                                <td class="mono">#alignLabel(qDomains.policy_aspf)#</td></tr>
                            <tr><td>Percentage</td>
                                <td class="mono">#htmlEditFormat(qDomains.policy_pct)#%</td></tr>
                        </table>
                    </div>

                    <!--- Volume breakdown --->
                    <div class="col-sm-6 col-lg-3">
                        <div class="detail-section-label">Message Breakdown</div>
                        <table class="detail-mini-table">
                            <tr><td>Total</td>
                                <td class="mono">#formatNumber(qDomains.messages)#</td></tr>
                            <tr><td>Passed</td>
                                <td class="mono" style="color:var(--accent-green)">
                                    #formatNumber(qDomains.passes)#</td></tr>
                            <tr><td>Failed</td>
                                <td class="mono" style="color:#(qDomains.failures GT 0 ? 'var(--accent-red)' : 'inherit')#">
                                    #formatNumber(qDomains.failures)#</td></tr>
                            <tr><td>Quarantined</td>
                                <td class="mono" style="color:#(qDomains.disp_quarantine GT 0 ? 'var(--accent-yellow)' : 'inherit')#">
                                    #formatNumber(qDomains.disp_quarantine)#</td></tr>
                            <tr><td>Rejected</td>
                                <td class="mono" style="color:#(qDomains.disp_reject GT 0 ? 'var(--accent-red)' : 'inherit')#">
                                    #formatNumber(qDomains.disp_reject)#</td></tr>
                        </table>
                    </div>

                    <!--- Coverage --->
                    <div class="col-sm-6 col-lg-3">
                        <div class="detail-section-label">Coverage</div>
                        <table class="detail-mini-table">
                            <tr><td>Reports received</td>
                                <td class="mono">#formatNumber(qDomains.report_count)#</td></tr>
                            <tr><td>Reporting orgs</td>
                                <td class="mono">#qDomains.reporter_count#</td></tr>
                            <tr><td>Sending sources</td>
                                <td class="mono">#qDomains.source_count#</td></tr>
                            <tr><td>First seen</td>
                                <td class="mono" style="font-size:0.75rem;">
                                    #dateFormat(qDomains.first_seen, "yyyy-mm-dd")#</td></tr>
                            <tr><td>Last report</td>
                                <td class="mono" style="font-size:0.75rem;">
                                    #timeAgo(qDomains.last_report)#</td></tr>
                        </table>
                    </div>

                    <!--- Quick links --->
                    <div class="col-sm-6 col-lg-3">
                        <div class="detail-section-label">Drill Down</div>
                        <div class="d-flex flex-column gap-2">
                            <a href="/admin/sources.cfm?days=#filterDays#&domain=#urlEncodedFormat(dom)#"
                               class="btn btn-sm btn-outline-secondary">
                                <i class="bi bi-diagram-3"></i> Sources for #htmlEditFormat(dom)#
                            </a>
                            <a href="/admin/reporters.cfm?days=#filterDays#&domain=#urlEncodedFormat(dom)#"
                               class="btn btn-sm btn-outline-secondary">
                                <i class="bi bi-building"></i> Reporters for #htmlEditFormat(dom)#
                            </a>
                            <a href="/admin/alignment.cfm?days=#filterDays#&domain=#urlEncodedFormat(dom)#"
                               class="btn btn-sm btn-outline-secondary">
                                <i class="bi bi-shield-check"></i> Alignment detail
                            </a>
                        </div>
                    </div>

                </div>
            </div>
        </div>

        <!--- Sparkline script for this domain --->
        <cfset sparkRates = structKeyExists(sparkData, dom) ? sparkData[dom].rates : []>
        <script>
        (function(){
            var el = document.getElementById('spark-#qDomains.currentRow#');
            if (!el) return;
            <cfif arrayLen(sparkRates) GT 0>
            new ApexCharts(el, {
                chart: { type: 'line', height: 40, sparkline: { enabled: true },
                         animations: { enabled: false } },
                series: [{ name: 'Pass Rate %', data: [#arrayToList(sparkRates)#] }],
                stroke: { width: 1.5, curve: 'smooth' },
                colors: ['#(passRate GTE 95 ? '##3fb950' : (passRate GTE 75 ? '##d29922' : '##f85149'))#'],
                tooltip: {
                    theme: 'dark',
                    y: { formatter: function(v){ return v + '%'; } }
                },
                yaxis: { min: 0, max: 100 }
            }).render();
            <cfelse>
            el.innerHTML = '<span style="font-size:0.68rem;color:var(--text-muted);">no data</span>';
            </cfif>
        })();
        </script>

    </cfloop>

</cfif>

<style>
    .domain-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        overflow: hidden;
    }

    .domain-card-header {
        padding: 0.9rem 1.1rem;
        cursor: pointer;
        transition: background 0.15s;
    }
    .domain-card-header:hover { background: var(--bg-card-hover); }

    .domain-name {
        font-family: var(--font-mono);
        font-size: 0.9rem;
        font-weight: 500;
        color: var(--text-primary);
    }

    .policy-badge {
        font-size: 0.62rem;
        padding: 0.18em 0.5em;
        letter-spacing: 0.02em;
    }

    .domain-card-detail {
        border-top: 1px solid var(--border-color);
        background: var(--bg-secondary);
    }

    .stat-mini-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.75rem;
        padding: 0.1rem 0;
    }
    .stat-mini-label { color: var(--text-muted); }
    .stat-mini-val   { color: var(--text-primary); }

    .detail-section-label {
        font-family: var(--font-mono);
        font-size: 0.65rem;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: var(--text-muted);
        margin-bottom: 0.5rem;
    }

    .detail-mini-table { width: 100%; border-collapse: collapse; }
    .detail-mini-table td {
        font-size: 0.78rem;
        padding: 0.18rem 0.4rem 0.18rem 0;
        color: var(--text-secondary);
        vertical-align: middle;
    }
    .detail-mini-table td.mono {
        text-align: right;
        color: var(--text-primary);
        font-family: var(--font-mono);
    }
</style>

<script>
document.querySelectorAll('.domain-card-header').forEach(function(hdr) {
    hdr.addEventListener('click', function() {
        var targetId = this.getAttribute('data-target');
        var detail   = document.getElementById(targetId);
        var icon     = this.querySelector('.toggle-icon');
        var isOpen   = detail.style.display !== 'none';

        detail.style.display = isOpen ? 'none' : 'block';
        icon.className = isOpen
            ? 'bi bi-chevron-down toggle-icon'
            : 'bi bi-chevron-up toggle-icon';
    });
});
</script>

</cfoutput>

<cfinclude template="/includes/footer.cfm">
