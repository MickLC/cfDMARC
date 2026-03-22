<!--- admin/audit.cfm --->
<cfinclude template="/includes/auth.cfm">
<cfinclude template="/includes/functions.cfm">

<style>
    .audit-row:hover td { background: var(--bg-card-hover) !important; }

    .action-badge {
        display: inline-block;
        font-family: var(--font-mono);
        font-size: 0.62rem;
        font-weight: 600;
        padding: 0.18em 0.5em;
        border-radius: 3px;
        letter-spacing: 0.03em;
        white-space: nowrap;
    }
    /* Colour by action category */
    .action-login    { background: rgba(56,139,253,.15);  color: var(--accent-blue);   border: 1px solid rgba(56,139,253,.3); }
    .action-logout   { background: rgba(139,148,158,.1);  color: var(--text-secondary); border: 1px solid var(--border-color); }
    .action-create   { background: rgba(63,185,80,.15);   color: var(--accent-green);  border: 1px solid rgba(63,185,80,.3); }
    .action-update   { background: rgba(210,153,34,.15);  color: var(--accent-yellow); border: 1px solid rgba(210,153,34,.3); }
    .action-delete   { background: rgba(248,81,73,.15);   color: var(--accent-red);    border: 1px solid rgba(248,81,73,.3); }
    .action-default  { background: rgba(139,148,158,.1);  color: var(--text-secondary); border: 1px solid var(--border-color); }
</style>

<cfscript>
    // ── Filters ───────────────────────────────────────────────────────────────
    param name="url.days"   default="7";
    param name="url.user"   default="";
    param name="url.action" default="";
    param name="url.page"   default="1";

    filterDays = isNumeric(url.days) ? int(url.days) : 7;
    if (NOT listFind("1,7,30,90,0", filterDays)) filterDays = 7;
    dateLabel  = filterDays EQ 0 ? "All time" : "Last #filterDays# day#(filterDays NEQ 1 ? 's' : '')#";
    dateClause = filterDays GT 0
        ? "AND al.created_at >= DATE_SUB(NOW(), INTERVAL #filterDays# DAY)"
        : "";

    filterUser   = len(trim(url.user))   ? trim(url.user)   : "";
    filterAction = len(trim(url.action)) ? trim(url.action) : "";

    userClause   = len(filterUser)   ? "AND u.username = ?"    : "";
    actionClause = len(filterAction) ? "AND al.action LIKE ?"  : "";

    baseParams = [];
    if (len(filterUser))   arrayAppend(baseParams, { value: filterUser,          cfsqltype: "cf_sql_varchar" });
    if (len(filterAction)) arrayAppend(baseParams, { value: filterAction & "%",  cfsqltype: "cf_sql_varchar" });

    pageSize    = 100;
    currentPage = isNumeric(url.page) AND url.page GTE 1 ? int(url.page) : 1;
    pageOffset  = (currentPage - 1) * pageSize;

    // ── User list for dropdown ────────────────────────────────────────────────
    qUserList = queryExecute("
        SELECT DISTINCT u.username
        FROM audit_log al
        LEFT JOIN users u ON u.id = al.user_id
        WHERE u.username IS NOT NULL
        ORDER BY u.username ASC
    ", {}, { datasource: application.db.dsn });

    // ── Action category list for dropdown ─────────────────────────────────────
    qActionList = queryExecute("
        SELECT DISTINCT
            CASE
                WHEN al.action LIKE 'login%'   THEN 'login'
                WHEN al.action LIKE 'logout%'  THEN 'logout'
                WHEN al.action LIKE 'create%'  THEN 'create'
                WHEN al.action LIKE 'update%'  THEN 'update'
                WHEN al.action LIKE 'delete%'  THEN 'delete'
                ELSE al.action
            END AS action_category,
            COUNT(*) AS cnt
        FROM audit_log al
        WHERE 1=1 #dateClause#
        GROUP BY action_category
        ORDER BY cnt DESC
    ", {}, { datasource: application.db.dsn });

    // ── Summary stats ─────────────────────────────────────────────────────────
    qStats = queryExecute("
        SELECT
            COUNT(*)                                                             AS total_events,
            COUNT(DISTINCT al.user_id)                                           AS unique_users,
            COUNT(DISTINCT al.ip_address)                                        AS unique_ips,
            SUM(CASE WHEN al.action LIKE 'login%'  THEN 1 ELSE 0 END)           AS logins,
            SUM(CASE WHEN al.action LIKE 'delete%' THEN 1 ELSE 0 END)           AS deletes
        FROM audit_log al
        LEFT JOIN users u ON u.id = al.user_id
        WHERE 1=1
            #dateClause#
            #userClause#
            #actionClause#
    ", baseParams, { datasource: application.db.dsn });

    // ── Count for pagination ──────────────────────────────────────────────────
    qCount = queryExecute("
        SELECT COUNT(*) AS total_rows
        FROM audit_log al
        LEFT JOIN users u ON u.id = al.user_id
        WHERE 1=1
            #dateClause#
            #userClause#
            #actionClause#
    ", baseParams, { datasource: application.db.dsn });

    totalRows  = qCount.total_rows;
    totalPages = ceiling(totalRows / pageSize);
    if (currentPage GT totalPages AND totalPages GT 0) currentPage = totalPages;

    // ── Audit log records ─────────────────────────────────────────────────────
    qLog = queryExecute("
        SELECT
            al.id,
            al.action,
            al.detail,
            al.ip_address,
            al.created_at,
            COALESCE(u.username, 'system') AS username
        FROM audit_log al
        LEFT JOIN users u ON u.id = al.user_id
        WHERE 1=1
            #dateClause#
            #userClause#
            #actionClause#
        ORDER BY al.created_at DESC
        LIMIT #pageSize# OFFSET #pageOffset#
    ", baseParams, { datasource: application.db.dsn });

    // ── Helper: action badge CSS class ────────────────────────────────────────
    function actionBadgeClass(required string action) {
        var a = lCase(arguments.action);
        if (a CONTAINS "login")  return "action-login";
        if (a CONTAINS "logout") return "action-logout";
        if (a CONTAINS "create" OR a CONTAINS "add" OR a CONTAINS "insert") return "action-create";
        if (a CONTAINS "update" OR a CONTAINS "edit" OR a CONTAINS "change") return "action-update";
        if (a CONTAINS "delete" OR a CONTAINS "remove") return "action-delete";
        return "action-default";
    }

    function pageUrl(numeric p, string user="", string action="") {
        var q  = "?days=#filterDays#&page=#p#";
        var u  = len(arguments.user)   ? arguments.user   : filterUser;
        var ac = len(arguments.action) ? arguments.action : filterAction;
        if (len(u))  q &= "&user=#urlEncodedFormat(u)#";
        if (len(ac)) q &= "&action=#urlEncodedFormat(ac)#";
        return q;
    }
</cfscript>

<cfset variables.pageTitle = "Audit Log">
<cfset variables.activeNav = "audit">
<cfinclude template="/includes/header.cfm">

<cfoutput>

<!--- ── Filter bar ──────────────────────────────────────────────────────── --->
<div class="d-flex flex-wrap gap-2 align-items-center justify-content-between mb-3">

    <div class="d-flex gap-2 align-items-center flex-wrap">
        <!--- User filter --->
        <form method="get" class="d-flex gap-2 align-items-center m-0">
            <input type="hidden" name="days"   value="#filterDays#">
            <input type="hidden" name="action" value="#htmlEditFormat(filterAction)#">
            <select name="user" class="form-select form-select-sm" style="width:auto;min-width:140px;"
                    onchange="this.form.submit()">
                <option value="">All users</option>
                <cfloop query="qUserList">
                    <option value="#htmlEditFormat(qUserList.username)#"
                        #(qUserList.username EQ filterUser ? 'selected' : '')#>
                        #htmlEditFormat(qUserList.username)#
                    </option>
                </cfloop>
            </select>
        </form>

        <!--- Action category filter --->
        <form method="get" class="d-flex gap-2 align-items-center m-0">
            <input type="hidden" name="days" value="#filterDays#">
            <input type="hidden" name="user" value="#htmlEditFormat(filterUser)#">
            <select name="action" class="form-select form-select-sm" style="width:auto;min-width:130px;"
                    onchange="this.form.submit()">
                <option value="">All actions</option>
                <cfloop query="qActionList">
                    <option value="#htmlEditFormat(qActionList.action_category)#"
                        #(qActionList.action_category EQ filterAction ? 'selected' : '')#>
                        #htmlEditFormat(qActionList.action_category)#
                        (#formatNumber(qActionList.cnt)#)
                    </option>
                </cfloop>
            </select>
        </form>

        <span class="mono" style="font-size:0.75rem;color:var(--text-muted);">
            #formatNumber(qStats.total_events)# event#(qStats.total_events NEQ 1 ? 's' : '')#
            &middot; #dateLabel#
        </span>
    </div>

    <!--- Days filter — shorter range defaults since audit is high-volume --->
    <div class="btn-group btn-group-sm">
        <cfset uSuffix = len(filterUser)   ? "&user="   & urlEncodedFormat(filterUser)   : "">
        <cfset aSuffix = len(filterAction) ? "&action=" & urlEncodedFormat(filterAction) : "">
        <a href="?days=1#uSuffix##aSuffix#"  class="btn btn-outline-secondary #(filterDays EQ 1  ? 'active':'')#">24h</a>
        <a href="?days=7#uSuffix##aSuffix#"  class="btn btn-outline-secondary #(filterDays EQ 7  ? 'active':'')#">7d</a>
        <a href="?days=30#uSuffix##aSuffix#" class="btn btn-outline-secondary #(filterDays EQ 30 ? 'active':'')#">30d</a>
        <a href="?days=90#uSuffix##aSuffix#" class="btn btn-outline-secondary #(filterDays EQ 90 ? 'active':'')#">90d</a>
        <a href="?days=0#uSuffix##aSuffix#"  class="btn btn-outline-secondary #(filterDays EQ 0  ? 'active':'')#">All</a>
    </div>
</div>

<!--- ── Summary tiles ───────────────────────────────────────────────────── --->
<div class="row g-3 mb-3">
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">Total Events</div>
        <div class="stat-value">#formatNumber(qStats.total_events)#</div>
        <div class="stat-sub">#qStats.unique_users# user#(qStats.unique_users NEQ 1 ? 's' : '')#</div>
    </div></div>
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">Logins</div>
        <div class="stat-value">#formatNumber(qStats.logins)#</div>
        <div class="stat-sub">#qStats.unique_ips# unique IP#(qStats.unique_ips NEQ 1 ? 's' : '')#</div>
    </div></div>
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">Delete Actions</div>
        <div class="stat-value" style="color:#(qStats.deletes GT 0 ? 'var(--accent-red)' : 'var(--text-primary)')#">
            #formatNumber(qStats.deletes)#
        </div>
        <div class="stat-sub">destructive operations</div>
    </div></div>
    <div class="col-6 col-lg-3"><div class="stat-tile">
        <div class="stat-label">Showing</div>
        <div class="stat-value" style="font-size:1.2rem;">#formatNumber(totalRows)#</div>
        <div class="stat-sub">matching records</div>
    </div></div>
</div>

<!--- ── Audit log table ─────────────────────────────────────────────────── --->
<div class="card">
    <div class="card-header d-flex align-items-center justify-content-between">
        <span>Audit Log
            <cfif len(filterUser) OR len(filterAction)>
                &nbsp;<a href="?days=#filterDays#"
                         style="font-size:0.7rem;color:var(--text-muted);text-decoration:none;"
                         title="Clear filters">clear filters &times;</a>
            </cfif>
        </span>
        <span class="mono" style="font-size:0.72rem;color:var(--text-muted);">
            <cfif totalPages GT 1>page #currentPage# of #totalPages#</cfif>
        </span>
    </div>
    <div class="card-body p-0">
        <cfif totalRows EQ 0>
            <div class="p-3" style="color:var(--text-muted);font-size:0.85rem;">
                No audit events found for the selected filters.
            </div>
        <cfelse>
            <table class="table mb-0">
                <thead>
                    <tr>
                        <th style="white-space:nowrap;">Timestamp</th>
                        <th>User</th>
                        <th>Action</th>
                        <th>Detail</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
                <cfloop query="qLog">
                    <tr class="audit-row">
                        <td class="mono" style="font-size:0.72rem;color:var(--text-muted);white-space:nowrap;">
                            #dateTimeFormat(qLog.created_at, "yyyy-mm-dd HH:nn:ss")#
                        </td>
                        <td style="font-size:0.82rem;">
                            <cfif qLog.username NEQ "system">
                                <a href="?days=#filterDays#&user=#urlEncodedFormat(qLog.username)##(len(filterAction) ? '&action=' & urlEncodedFormat(filterAction) : '')#"
                                   style="color:var(--accent-blue);text-decoration:none;">
                                    #htmlEditFormat(qLog.username)#
                                </a>
                            <cfelse>
                                <span style="color:var(--text-muted);">system</span>
                            </cfif>
                        </td>
                        <td>
                            <span class="action-badge #actionBadgeClass(qLog.action)#">
                                #htmlEditFormat(qLog.action)#
                            </span>
                        </td>
                        <td style="font-size:0.78rem;color:var(--text-secondary);max-width:320px;
                                   overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
                            title="#htmlEditFormat(qLog.detail)#">
                            #htmlEditFormat(qLog.detail)#
                        </td>
                        <td class="mono" style="font-size:0.75rem;color:var(--text-muted);white-space:nowrap;">
                            #htmlEditFormat(qLog.ip_address)#
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

        </cfif>
    </div>
</div>

</cfoutput>

<cfinclude template="/includes/footer.cfm">
