<!--- includes/header.cfm
      Shared header and sidebar. Included by all protected admin pages.

      Expects these variables to be set by the calling page:
        variables.pageTitle  (string)  — shown in <title> and topbar
        variables.activeNav  (string)  — nav item key to highlight
--->
<cfparam name="variables.pageTitle" default="DMARC Dashboard">
<cfparam name="variables.activeNav" default="">
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><cfoutput>#htmlEditFormat(variables.pageTitle)# — #htmlEditFormat(application.appName)#</cfoutput></title>

    <!--- Fonts --->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">

    <!--- Bootstrap 5 --->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">

    <!--- Bootstrap Icons --->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

    <!--- ApexCharts --->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/apexcharts/3.45.2/apexcharts.min.js"></script>

    <style>
        :root {
            --bg-primary:     #0d1117;
            --bg-secondary:   #161b22;
            --bg-card:        #1c2128;
            --bg-card-hover:  #222830;
            --border-color:   #30363d;
            --text-primary:   #e6edf3;
            --text-secondary: #8b949e;
            --text-muted:     #6e7681;
            --accent-blue:    #388bfd;
            --accent-green:   #3fb950;
            --accent-yellow:  #d29922;
            --accent-red:     #f85149;
            --accent-purple:  #a371f7;
            --font-sans:      'IBM Plex Sans', sans-serif;
            --font-mono:      'IBM Plex Mono', monospace;
        }

        * { box-sizing: border-box; }

        body {
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-sans);
            font-size: 0.9rem;
            min-height: 100vh;
        }

        /* ---- Sidebar ---- */
        #sidebar {
            width: 220px;
            min-height: 100vh;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            position: fixed;
            top: 0;
            left: 0;
            display: flex;
            flex-direction: column;
            z-index: 100;
        }

        #sidebar .brand {
            padding: 1.25rem 1.25rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        #sidebar .brand-title {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--accent-blue);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            display: block;
        }

        #sidebar .brand-sub {
            font-size: 0.7rem;
            color: var(--text-muted);
            font-family: var(--font-mono);
        }

        #sidebar nav {
            flex: 1;
            padding: 0.75rem 0;
        }

        #sidebar .nav-section {
            font-family: var(--font-mono);
            font-size: 0.65rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            color: var(--text-muted);
            padding: 0.75rem 1.25rem 0.25rem;
        }

        #sidebar .nav-link {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            padding: 0.45rem 1.25rem;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.85rem;
            border-left: 2px solid transparent;
            transition: all 0.15s ease;
        }

        #sidebar .nav-link:hover {
            color: var(--text-primary);
            background: var(--bg-card);
        }

        #sidebar .nav-link.active {
            color: var(--accent-blue);
            border-left-color: var(--accent-blue);
            background: rgba(56, 139, 253, 0.08);
        }

        #sidebar .nav-link i {
            font-size: 0.9rem;
            width: 1rem;
            text-align: center;
        }

        #sidebar .sidebar-footer {
            padding: 1rem 1.25rem;
            border-top: 1px solid var(--border-color);
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        #sidebar .sidebar-footer a {
            color: var(--text-muted);
            text-decoration: none;
        }

        #sidebar .sidebar-footer a:hover { color: var(--accent-red); }

        /* ---- Main content ---- */
        #main {
            margin-left: 220px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        #topbar {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 0.75rem 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 50;
        }

        #topbar .page-title {
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text-primary);
            margin: 0;
        }

        #topbar .topbar-meta {
            font-family: var(--font-mono);
            font-size: 0.72rem;
            color: var(--text-muted);
        }

        #content { padding: 1.5rem; flex: 1; }

        /* ---- Cards ---- */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
        }

        .card-header {
            background: transparent;
            border-bottom: 1px solid var(--border-color);
            padding: 0.75rem 1rem;
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            font-family: var(--font-mono);
        }

        .card-body { padding: 1rem; }

        /* ---- Stat tiles ---- */
        .stat-tile {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem 1.25rem;
            transition: border-color 0.15s;
        }

        .stat-tile:hover { border-color: #444c56; }

        .stat-tile .stat-label {
            font-family: var(--font-mono);
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-muted);
            margin-bottom: 0.4rem;
        }

        .stat-tile .stat-value {
            font-size: 1.75rem;
            font-weight: 600;
            line-height: 1;
            color: var(--text-primary);
            font-family: var(--font-mono);
        }

        .stat-tile .stat-sub {
            font-size: 0.72rem;
            color: var(--text-muted);
            margin-top: 0.3rem;
        }

        /* ---- Tables ---- */
        .table { color: var(--text-primary); font-size: 0.85rem; }

        .table > :not(caption) > * > * {
            background: transparent;
            border-bottom-color: var(--border-color);
            padding: 0.5rem 0.75rem;
        }

        .table thead th {
            font-family: var(--font-mono);
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
            font-weight: 500;
        }

        .table tbody tr:hover td { background: var(--bg-card-hover) !important; }

        /* ---- Badges ---- */
        .badge-pass    { background: rgba(63,185,80,.15);  color: var(--accent-green);  border: 1px solid rgba(63,185,80,.3); }
        .badge-fail    { background: rgba(248,81,73,.15);  color: var(--accent-red);    border: 1px solid rgba(248,81,73,.3); }
        .badge-warn    { background: rgba(210,153,34,.15); color: var(--accent-yellow); border: 1px solid rgba(210,153,34,.3); }
        .badge-neutral { background: rgba(139,148,158,.1); color: var(--text-secondary);border: 1px solid var(--border-color); }

        .badge {
            font-family: var(--font-mono);
            font-size: 0.68rem;
            font-weight: 500;
            padding: 0.2em 0.55em;
            border-radius: 3px;
        }

        /* ---- Pass rate bar ---- */
        .pass-bar {
            height: 4px;
            background: var(--border-color);
            border-radius: 2px;
            overflow: hidden;
            margin-top: 0.3rem;
        }

        .pass-bar-fill { height: 100%; border-radius: 2px; transition: width 0.6s ease; }
        .pass-bar-fill.high   { background: var(--accent-green); }
        .pass-bar-fill.medium { background: var(--accent-yellow); }
        .pass-bar-fill.low    { background: var(--accent-red); }

        /* ---- Alerts ---- */
        .alert { border-radius: 6px; font-size: 0.85rem; border: 1px solid; }
        .alert-danger  { background: rgba(248,81,73,.1);  border-color: rgba(248,81,73,.3);  color: #ffa198; }
        .alert-success { background: rgba(63,185,80,.1);  border-color: rgba(63,185,80,.3);  color: #7ee787; }
        .alert-warning { background: rgba(210,153,34,.1); border-color: rgba(210,153,34,.3); color: #e3b341; }
        .alert-info    { background: rgba(56,139,253,.1); border-color: rgba(56,139,253,.3); color: #79c0ff; }

        /* ---- Forms ---- */
        .form-control, .form-select {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            font-size: 0.875rem;
            border-radius: 4px;
        }

        .form-control:focus, .form-select:focus {
            background: var(--bg-primary);
            border-color: var(--accent-blue);
            color: var(--text-primary);
            box-shadow: 0 0 0 2px rgba(56,139,253,.2);
        }

        .form-label { font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.3rem; }

        /* ---- Buttons ---- */
        .btn { font-size: 0.85rem; border-radius: 4px; }
        .btn-primary { background: var(--accent-blue); border-color: var(--accent-blue); color: #fff; }
        .btn-primary:hover { background: #58a6ff; border-color: #58a6ff; }
        .btn-outline-secondary { border-color: var(--border-color); color: var(--text-secondary); }
        .btn-outline-secondary:hover { background: var(--bg-card); border-color: #444c56; color: var(--text-primary); }
        .btn-danger  { background: var(--accent-red);   border-color: var(--accent-red); }
        .btn-success { background: var(--accent-green); border-color: var(--accent-green); color: #000; }

        /* ---- Utilities ---- */
        .mono { font-family: var(--font-mono); }

        /* ---- ApexCharts dark overrides ---- */
        .apexcharts-tooltip {
            background: var(--bg-card) !important;
            border: 1px solid var(--border-color) !important;
            color: var(--text-primary) !important;
        }
        .apexcharts-tooltip-title {
            background: var(--bg-secondary) !important;
            border-bottom: 1px solid var(--border-color) !important;
        }

        /* ---- Responsive ---- */
        @media (max-width: 768px) {
            #sidebar { transform: translateX(-100%); }
            #main { margin-left: 0; }
        }
    </style>
</head>
<body>

<cfoutput>
<!--- Sidebar --->
<div id="sidebar">
    <div class="brand">
        <!--- Brand reads from application.appName set in config/settings.cfm --->
        <span class="brand-title">#htmlEditFormat(application.appName)#</span>
        <span class="brand-sub">v#application.appVersion#</span>
    </div>
    <nav>
        <div class="nav-section">Reports</div>
        <a href="/admin/dashboard.cfm"  class="nav-link #(variables.activeNav EQ 'dashboard'  ? 'active' : '')#"><i class="bi bi-speedometer2"></i> Overview</a>
        <a href="/admin/sources.cfm"    class="nav-link #(variables.activeNav EQ 'sources'    ? 'active' : '')#"><i class="bi bi-diagram-3"></i> Sending Sources</a>
        <a href="/admin/domains.cfm"    class="nav-link #(variables.activeNav EQ 'domains'    ? 'active' : '')#"><i class="bi bi-globe2"></i> Domains</a>
        <a href="/admin/reporters.cfm"  class="nav-link #(variables.activeNav EQ 'reporters'  ? 'active' : '')#"><i class="bi bi-building"></i> Reporters</a>
        <a href="/admin/alignment.cfm"  class="nav-link #(variables.activeNav EQ 'alignment'  ? 'active' : '')#"><i class="bi bi-shield-check"></i> Alignment</a>
        <a href="/admin/forensic.cfm"   class="nav-link #(variables.activeNav EQ 'forensic'   ? 'active' : '')#"><i class="bi bi-bug"></i> Forensic (RUF)</a>

        <div class="nav-section">System</div>
        <a href="/admin/accounts.cfm"   class="nav-link #(variables.activeNav EQ 'accounts'   ? 'active' : '')#"><i class="bi bi-envelope-at"></i> IMAP Accounts</a>
        <a href="/admin/tokens.cfm"     class="nav-link #(variables.activeNav EQ 'tokens'     ? 'active' : '')#"><i class="bi bi-share"></i> Share Links</a>
        <a href="/admin/users.cfm"      class="nav-link #(variables.activeNav EQ 'users'      ? 'active' : '')#"><i class="bi bi-person"></i> Users</a>
        <a href="/admin/poller.cfm"     class="nav-link #(variables.activeNav EQ 'poller'     ? 'active' : '')#"><i class="bi bi-arrow-repeat"></i> Poller</a>
    </nav>
    <div class="sidebar-footer">
        <div>#htmlEditFormat(session.username)#</div>
        <a href="/admin/logout.cfm"><i class="bi bi-box-arrow-left"></i> Sign out</a>
    </div>
</div>

<!--- Main wrapper --->
<div id="main">
    <div id="topbar">
        <h1 class="page-title">#htmlEditFormat(variables.pageTitle)#</h1>
        <span class="topbar-meta">#dateTimeFormat(now(), "yyyy-mm-dd HH:nn")#</span>
    </div>
    <div id="content">
</cfoutput>
