<!--- admin/dashboard.cfm --->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<cfscript>
    param name="url.days" default="90";
    filterDays = isNumeric(url.days) ? int(url.days) : 90;
    if (NOT listFind("7,30,90,365,0", filterDays)) filterDays = 90;
    dateLabel  = filterDays EQ 0 ? "All time" : "Last #filterDays# days";
    dateClause = filterDays GT 0 ? "AND rpt.mindate >= DATE_SUB(NOW(), INTERVAL #filterDays# DAY)" : "";

    qStats = queryExecute("
        SELECT
            COUNT(DISTINCT rpt.id)                                               AS report_count,
            COUNT(DISTINCT rpt.domain)                                           AS domain_count,
            COUNT(DISTINCT rpt.org)                                              AS reporter_count,
            COALESCE(SUM(rec.rcount), 0)                                         AS total_messages,
            COALESCE(SUM(CASE WHEN rec.dkim_align='pass' OR rec.spf_align='pass' THEN rec.rcount ELSE 0 END),0) AS total_pass,
            COALESCE(SUM(CASE WHEN rec.dkim_align!='pass' AND rec.spf_align!='pass' THEN rec.rcount ELSE 0 END),0) AS total_fail
        FROM report rpt
        LEFT JOIN rptrecord rec ON rec.report_id = rpt.id
        WHERE 1=1 #dateClause#
    ", {}, { datasource: application.db.dsn });

    totalMessages = qStats.total_messages;
    totalPass     = qStats.total_pass;
    totalFail     = qStats.total_fail;
    passRate      = totalMessages GT 0 ? numberFormat(100 * totalPass / totalMessages, "99.9") : 0;

    qDomains = queryExecute("
        SELECT rpt.domain,
            SUM(rec.rcount) AS messages,
            ROUND(100.0 * SUM(CASE WHEN rec.dkim_align='pass' OR rec.spf_align='pass' THEN rec.rcount ELSE 0 END)
                  / NULLIF(SUM(rec.rcount),0), 1) AS pass_rate,
            MAX(rpt.received_at) AS last_report
        FROM report rpt
        LEFT JOIN rptrecord rec ON rec.report_id = rpt.id
        WHERE 1=1 #dateClause#
        GROUP BY rpt.domain ORDER BY messages DESC
    ", {}, { datasource: application.db.dsn });

    // Trend chart: daily for <=90 days, weekly for 365/all-time.
    useWeeklyTrend  = (filterDays EQ 0 OR filterDays EQ 365);
    trendDateClause = filterDays GT 0 ? "WHERE rpt.mindate >= DATE_SUB(NOW(), INTERVAL #filterDays# DAY)" : "";

    if (useWeeklyTrend) {
        trendGroupExpr = "DATE(DATE_SUB(rpt.mindate, INTERVAL WEEKDAY(rpt.mindate) DAY))";
        trendLabelExpr = "DATE_FORMAT(DATE_SUB(rpt.mindate, INTERVAL WEEKDAY(rpt.mindate) DAY), '%b %d')";
    } else {
        trendGroupExpr = "DATE(rpt.mindate)";
        trendLabelExpr = "DATE_FORMAT(rpt.mindate, '%b %d')";
    }

    qTrend = queryExecute("
        SELECT #trendLabelExpr# AS period_label,
            SUM(rec.rcount) AS messages,
            SUM(CASE WHEN rec.dkim_align='pass' OR rec.spf_align='pass' THEN rec.rcount ELSE 0 END) AS pass_count
        FROM report rpt
        LEFT JOIN rptrecord rec ON rec.report_id = rpt.id
        #trendDateClause#
        GROUP BY #trendGroupExpr#
        ORDER BY #trendGroupExpr# ASC
    ", {}, { datasource: application.db.dsn });

    chartDates    = [];
    chartMessages = [];
    chartPassRate = [];
    for (row in qTrend) {
        arrayAppend(chartDates,    '"#row.period_label#"');
        arrayAppend(chartMessages, row.messages);
        arrayAppend(chartPassRate, row.messages GT 0 ? numberFormat(100*row.pass_count/row.messages, "99.9") : 0);
    }

    chartTitle = useWeeklyTrend
        ? "Message Volume & Pass Rate — #dateLabel# (weekly)"
        : "Message Volume & Pass Rate — #dateLabel#";

    // Recent reports ordered by report date (mindate), not ingestion time
    qRecent = queryExecute("
        SELECT rpt.id, rpt.domain, rpt.org, rpt.mindate, rpt.maxdate,
            SUM(rec.rcount) AS message_count,
            SUM(CASE WHEN rec.dkim_align='pass' OR rec.spf_align='pass' THEN rec.rcount ELSE 0 END) AS pass_count
        FROM report rpt
        LEFT JOIN rptrecord rec ON rec.report_id = rpt.id
        GROUP BY rpt.id ORDER BY rpt.mindate DESC LIMIT 10
    ", {}, { datasource: application.db.dsn });

    qFailSources = queryExecute("
        SELECT CASE WHEN rec.ip IS NOT NULL THEN INET_NTOA(rec.ip)
                    WHEN rec.ip6 IS NOT NULL THEN HEX(rec.ip6) ELSE 'unknown' END AS source_ip,
            rpt.domain,
            SUM(CASE WHEN rec.dkim_align!='pass' AND rec.spf_align!='pass' THEN rec.rcount ELSE 0 END) AS fail_count
        FROM rptrecord rec
        JOIN report rpt ON rpt.id = rec.report_id
        WHERE rec.dkim_align!='pass' AND rec.spf_align!='pass' #dateClause#
        GROUP BY source_ip, rpt.domain ORDER BY fail_count DESC LIMIT 8
    ", {}, { datasource: application.db.dsn });
</cfscript>

<cfset variables.pageTitle = "Overview">
<cfset variables.activeNav = "dashboard">
<cfinclude template="/includes/header.cfm">

<cfoutput>
<div class="d-flex justify-content-between align-items-center mb-3">
    <div class="text-muted mono" style="font-size:0.75rem;">#dateLabel#</div>
    <div class="btn-group btn-group-sm">
        <a href="?days=7"   class="btn btn-outline-secondary #(filterDays EQ 7   ? 'active':'')#">7d</a>
        <a href="?days=30"  class="btn btn-outline-secondary #(filterDays EQ 30  ? 'active':'')#">30d</a>
        <a href="?days=90"  class="btn btn-outline-secondary #(filterDays EQ 90  ? 'active':'')#">90d</a>
        <a href="?days=365" class="btn btn-outline-secondary #(filterDays EQ 365 ? 'active':'')#">1y</a>
        <a href="?days=0"   class="btn btn-outline-secondary #(filterDays EQ 0   ? 'active':'')#">All</a>
    </div>
</div>

<div class="row g-3 mb-3">
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">Total Messages</div>
        <div class="stat-value">#formatNumber(totalMessages)#</div>
        <div class="stat-sub">#formatNumber(qStats.report_count)# reports</div>
    </div></div>
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">DMARC Pass Rate</div>
        <div class="stat-value" style="color:var(--accent-#(passRate GTE 95 ? 'green':(passRate GTE 75 ? 'yellow':'red'))#)">
            #passRate#<span style="font-size:1rem">%</span></div>
        <div class="stat-sub">#formatNumber(totalPass)# passed</div>
    </div></div>
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">Domains Monitored</div>
        <div class="stat-value">#qStats.domain_count#</div>
        <div class="stat-sub">#qStats.reporter_count# reporters</div>
    </div></div>
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">DMARC Failures</div>
        <div class="stat-value" style="color:#(totalFail GT 0 ? 'var(--accent-red)':'var(--accent-green)')#">#formatNumber(totalFail)#</div>
        <div class="stat-sub">#(totalMessages GT 0 ? numberFormat(100*totalFail/totalMessages,"99.9"):0)#% fail rate</div>
    </div></div>
</div>

<div class="row g-3 mb-3">
    <div class="col-lg-8"><div class="card h-100">
        <div class="card-header">#htmlEditFormat(chartTitle)#</div>
        <div class="card-body"><div id="chart-trend" style="min-height:240px;"></div></div>
    </div></div>
    <div class="col-lg-4"><div class="card h-100">
        <div class="card-header">Domain Health</div>
        <div class="card-body p-0">
            <table class="table table-borderless mb-0"><tbody>
            <cfloop query="qDomains">
                <cfset domRate = qDomains.pass_rate NEQ "" ? qDomains.pass_rate : 0>
                <cfset barClass = domRate GTE 95 ? "high" : (domRate GTE 75 ? "medium" : "low")>
                <tr><td style="width:100%">
                    <div style="font-size:0.8rem;font-weight:500;">#qDomains.domain#</div>
                    <div class="pass-bar"><div class="pass-bar-fill #barClass#" style="width:#domRate#%"></div></div>
                    <div style="font-size:0.7rem;color:var(--text-muted);margin-top:2px;">
                        #formatNumber(qDomains.messages)# msgs &middot; #domRate#% pass</div>
                </td><td style="white-space:nowrap;vertical-align:middle;padding-left:0;">
                    <span class="badge badge-#(domRate GTE 95 ? 'pass':(domRate GTE 75 ? 'warn':'fail'))#">#domRate#%</span>
                </td></tr>
            </cfloop>
            </tbody></table>
        </div>
    </div></div>
</div>

<div class="row g-3">
    <div class="col-lg-7"><div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
            <span>Recent Reports</span>
            <a href="/admin/reporters.cfm" style="font-size:0.72rem;color:var(--accent-blue);text-decoration:none;">View all</a>
        </div>
        <div class="card-body p-0"><table class="table mb-0">
            <thead><tr><th>Domain</th><th>Reporter</th><th>Messages</th><th>Pass</th><th>Report Date</th></tr></thead>
            <tbody>
            <cfloop query="qRecent">
                <cfset recRate = qRecent.message_count GT 0 ? int(100*qRecent.pass_count/qRecent.message_count) : 0>
                <tr>
                    <td class="mono" style="font-size:0.8rem;">#qRecent.domain#</td>
                    <td style="color:var(--text-secondary)">#qRecent.org#</td>
                    <td class="mono">#formatNumber(qRecent.message_count)#</td>
                    <td><span class="badge badge-#(recRate GTE 95 ? 'pass':(recRate GTE 75 ? 'warn':'fail'))#">#recRate#%</span></td>
                    <td style="color:var(--text-muted);font-size:0.78rem;" class="mono">
                        #dateFormat(qRecent.mindate, "mmm d")#<cfif dateFormat(qRecent.mindate, "mmm d") NEQ dateFormat(qRecent.maxdate, "mmm d")>–#dateFormat(qRecent.maxdate, "mmm d")#</cfif>
                    </td>
                </tr>
            </cfloop>
            </tbody>
        </table></div>
    </div></div>
    <div class="col-lg-5"><div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
            <span>Top Failing Sources</span>
            <a href="/admin/sources.cfm" style="font-size:0.72rem;color:var(--accent-blue);text-decoration:none;">View all</a>
        </div>
        <div class="card-body p-0"><table class="table mb-0">
            <thead><tr><th>Source IP</th><th>Domain</th><th>Failures</th></tr></thead>
            <tbody>
            <cfloop query="qFailSources">
                <tr>
                    <td class="mono" style="font-size:0.78rem;">#qFailSources.source_ip#</td>
                    <td style="font-size:0.78rem;color:var(--text-secondary)">#qFailSources.domain#</td>
                    <td><span class="badge badge-fail">#formatNumber(qFailSources.fail_count)#</span></td>
                </tr>
            </cfloop>
            </tbody>
        </table></div>
    </div></div>
</div>

<script>
(function(){
    var options={
        chart:{type:'line',height:240,background:'transparent',toolbar:{show:false},animations:{enabled:true,easing:'easeinout',speed:600}},
        theme:{mode:'dark'},
        colors:['##388bfd','##3fb950'],
        series:[
            {name:'Messages',type:'bar',data:[#arrayToList(chartMessages)#]},
            {name:'Pass Rate %',type:'line',data:[#arrayToList(chartPassRate)#]}
        ],
        xaxis:{categories:[#arrayToList(chartDates)#],labels:{style:{colors:'##6e7681',fontSize:'11px',fontFamily:'IBM Plex Mono'}},axisBorder:{color:'##30363d'},axisTicks:{color:'##30363d'}},
        yaxis:[
            {title:{text:'Messages',style:{color:'##6e7681',fontSize:'11px'}},labels:{style:{colors:'##6e7681',fontSize:'11px'}}},
            {opposite:true,min:0,max:100,title:{text:'Pass Rate %',style:{color:'##6e7681',fontSize:'11px'}},labels:{style:{colors:'##6e7681',fontSize:'11px'},formatter:function(v){return v+'%';}}}
        ],
        grid:{borderColor:'##21262d',strokeDashArray:3},
        stroke:{width:[0,2],curve:'smooth'},
        dataLabels:{enabled:false},
        legend:{labels:{colors:'##8b949e'},fontSize:'12px',fontFamily:'IBM Plex Mono'},
        tooltip:{theme:'dark',y:[{formatter:function(v){return v.toLocaleString()+' msgs';}},{formatter:function(v){return v+'%';}}]},
        plotOptions:{bar:{borderRadius:2,columnWidth:'60%'}}
    };
    new ApexCharts(document.querySelector('##chart-trend'),options).render();
})();
</script>
</cfoutput>

<cfinclude template="/includes/footer.cfm">
