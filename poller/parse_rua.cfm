<!--- poller/parse_rua.cfm
      Parse one DMARC aggregate report (RUA).
      Included by poll.cfm inside the message-processing loop.

      Expects the following variables set by poll.cfm:
        attachments   — array of structs { name, bytes }
        cleanMsgId    — deduplicated Message-ID string
        msgSubject    — message subject for logging
        acct          — current imap_accounts row

      Sets: (nothing — writes directly to DB)
--->
<cfscript>

    function extractXmlFromBytes(required any rawBytes) {
        // Sniff magic bytes (Java bytes are signed; cast to int to get 0-255 range)
        // GZip: 0x1F 0x8B   ZIP: 0x50 0x4B
        var b0 = rawBytes[1];
        var b1 = rawBytes[2];
        // Convert signed byte to unsigned int for reliable comparison
        if (b0 LT 0) b0 = b0 + 256;
        if (b1 LT 0) b1 = b1 + 256;

        if (b0 EQ 31 AND b1 EQ 139) {
            // GZIP
            var bis = createObject("java","java.io.ByteArrayInputStream").init(rawBytes);
            var gis = createObject("java","java.util.zip.GZIPInputStream").init(bis);
            var sr  = createObject("java","java.io.InputStreamReader").init(gis, "UTF-8");
            var br  = createObject("java","java.io.BufferedReader").init(sr);
            var sb  = createObject("java","java.lang.StringBuilder").init();
            var line = br.readLine();
            while (NOT isNull(line)) {
                sb.append(line);
                sb.append(chr(10));
                line = br.readLine();
            }
            br.close();
            return sb.toString();

        } else if (b0 EQ 80 AND b1 EQ 75) {
            // ZIP — first XML entry wins
            var bis   = createObject("java","java.io.ByteArrayInputStream").init(rawBytes);
            var zis   = createObject("java","java.util.zip.ZipInputStream").init(bis);
            var entry = zis.getNextEntry();
            while (NOT isNull(entry)) {
                var eName = javaCast("string", entry.getName());
                if (reFindNoCase("\.xml$", eName)) {
                    var sr   = createObject("java","java.io.InputStreamReader").init(zis, "UTF-8");
                    var br   = createObject("java","java.io.BufferedReader").init(sr);
                    var sb   = createObject("java","java.lang.StringBuilder").init();
                    var line = br.readLine();
                    while (NOT isNull(line)) {
                        sb.append(line);
                        sb.append(chr(10));
                        line = br.readLine();
                    }
                    zis.close();
                    return sb.toString();
                }
                entry = zis.getNextEntry();
            }
            zis.close();
            throw(type="DMARCPoller", message="No XML entry found in ZIP attachment");

        } else {
            // Assume raw UTF-8 XML
            return createObject("java","java.lang.String").init(rawBytes, "UTF-8");
        }
    }

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
        } catch(any e) {
            return arguments.defaultVal;
        }
    }

    // -------------------------------------------------------------------
    // Find and decompress the XML attachment
    // attachments is set by poll.cfm as [{ name: "report", bytes: rawBytes }]
    // Process any attachment that has a bytes key — the MIME filtering was
    // already done upstream in extractDmarcAttachment().
    // -------------------------------------------------------------------
    xmlContent = "";

    for (att in attachments) {
        if (structKeyExists(att, "bytes") AND NOT isNull(att.bytes) AND arrayLen(att.bytes) GT 4) {
            try {
                xmlContent = extractXmlFromBytes(att.bytes);
                // Sanity check: must look like XML
                if (NOT reFindNoCase("^\s*<\?xml|^\s*<feedback", xmlContent)) {
                    logLine("  RUA: attachment #att.name# decoded but doesn't look like XML (first 100: #left(xmlContent,100)#)", "WARN");
                    xmlContent = "";
                }
            } catch(any attErr) {
                logLine("  RUA: error extracting attachment #att.name#: #attErr.message#", "WARN");
                xmlContent = "";
            }
            if (len(trim(xmlContent))) break;
        } else if (structKeyExists(att, "file") AND fileExists(att.file)) {
            try {
                var rawFileBytes = fileReadBinary(att.file);
                xmlContent = extractXmlFromBytes(rawFileBytes);
                if (NOT reFindNoCase("^\s*<\?xml|^\s*<feedback", xmlContent)) xmlContent = "";
            } catch(any attErr) {
                logLine("  RUA: error reading attachment file #att.name#: #attErr.message#", "WARN");
            }
            try { fileDelete(att.file); } catch(any e) {}
            if (len(trim(xmlContent))) break;
        }
    }

    if (NOT len(trim(xmlContent))) {
        logLine("  RUA: no usable XML attachment found in message", "WARN");
        return;
    }

    // -------------------------------------------------------------------
    // Parse XML
    // -------------------------------------------------------------------
    try {
        rpt = xmlParse(xmlContent);
    } catch(any parseErr) {
        logLine("  RUA: XML parse error: #parseErr.message#", "ERROR");
        return;
    }

    fb = rpt.feedback;

    // Header metadata
    orgName    = getNodeText(fb, "report_metadata.org_name");
    reportId   = getNodeText(fb, "report_metadata.report_id");
    email      = getNodeText(fb, "report_metadata.email");
    extraInfo  = getNodeText(fb, "report_metadata.extra_contact_info");
    beginUnix  = val(getNodeText(fb, "report_metadata.date_range.begin", "0"));
    endUnix    = val(getNodeText(fb, "report_metadata.date_range.end",   "0"));
    pDomain    = getNodeText(fb, "policy_published.domain");
    pAdkim     = getNodeText(fb, "policy_published.adkim", "r");
    pAspf      = getNodeText(fb, "policy_published.aspf",  "r");
    pP         = getNodeText(fb, "policy_published.p",     "none");
    pSp        = getNodeText(fb, "policy_published.sp",    "none");
    pPct       = val(getNodeText(fb, "policy_published.pct", "100"));

    if (NOT len(pDomain)) pDomain = "unknown";

    minDate = (beginUnix GT 0) ? dateAdd("s", beginUnix, createDateTime(1970,1,1,0,0,0)) : now();
    maxDate = (endUnix   GT 0) ? dateAdd("s", endUnix,   createDateTime(1970,1,1,0,0,0)) : now();

    // -------------------------------------------------------------------
    // Insert report header
    // -------------------------------------------------------------------
    queryExecute(
        "INSERT INTO report
             (mindate, maxdate, domain, org, reportid, email,
              extra_contact_info, policy_adkim, policy_aspf,
              policy_p, policy_sp, policy_pct,
              message_id, raw_reports, received_at)
         VALUES
             (?, ?, ?, ?, ?, ?,
              ?, ?, ?,
              ?, ?, ?,
              ?, ?, NOW())",
        [
            { value: minDate,             cfsqltype: "cf_sql_timestamp" },
            { value: maxDate,             cfsqltype: "cf_sql_timestamp" },
            { value: left(pDomain,  253), cfsqltype: "cf_sql_varchar" },
            { value: left(orgName,  100), cfsqltype: "cf_sql_varchar" },
            { value: left(reportId, 200), cfsqltype: "cf_sql_varchar" },
            { value: left(email,    200), cfsqltype: "cf_sql_varchar" },
            { value: left(extraInfo,255), cfsqltype: "cf_sql_varchar", null: NOT len(extraInfo) },
            { value: left(pAdkim,   1),   cfsqltype: "cf_sql_char" },
            { value: left(pAspf,    1),   cfsqltype: "cf_sql_char" },
            { value: left(pP,       20),  cfsqltype: "cf_sql_varchar" },
            { value: left(pSp,      20),  cfsqltype: "cf_sql_varchar" },
            { value: pPct,               cfsqltype: "cf_sql_smallint" },
            { value: left(cleanMsgId,255),cfsqltype: "cf_sql_varchar" },
            { value: xmlContent,         cfsqltype: "cf_sql_clob" }
        ],
        { datasource: application.db.dsn, result: "insertResult" }
    );

    newReportId = insertResult.generatedKey;
    logLine("  RUA: inserted report id=#newReportId# org=#orgName# domain=#pDomain#");

    // -------------------------------------------------------------------
    // Insert rptrecord rows
    // -------------------------------------------------------------------
    records     = fb.xmlChildren;
    recInserted = 0;

    for (child in records) {
        if (child.XmlName NEQ "record") continue;

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
        ipColSQL   = isIPv6addr ? "ip6"          : "ip";
        ipValSQL   = isIPv6addr ? "INET6_ATON(?)" : "INET_ATON(?)";

        optCols   = "";
        optVals   = "";
        optParams = [];

        if (len(reasonType)) {
            optCols &= ", reason"; optVals &= ", ?";
            arrayAppend(optParams, { value: left(reasonType,100),    cfsqltype: "cf_sql_varchar" });
        }
        if (len(reasonComment)) {
            optCols &= ", comment"; optVals &= ", ?";
            arrayAppend(optParams, { value: left(reasonComment,255), cfsqltype: "cf_sql_varchar" });
        }
        if (len(dkimDomain)) {
            optCols &= ", dkimdomain"; optVals &= ", ?";
            arrayAppend(optParams, { value: left(dkimDomain,253),    cfsqltype: "cf_sql_varchar" });
        }
        if (len(dkimResult)) {
            optCols &= ", dkimresult"; optVals &= ", ?";
            arrayAppend(optParams, { value: left(dkimResult,20),     cfsqltype: "cf_sql_varchar" });
        }
        if (len(spfDomain)) {
            optCols &= ", spfdomain"; optVals &= ", ?";
            arrayAppend(optParams, { value: left(spfDomain,253),     cfsqltype: "cf_sql_varchar" });
        }
        if (len(spfResult)) {
            optCols &= ", spfresult"; optVals &= ", ?";
            arrayAppend(optParams, { value: left(spfResult,20),      cfsqltype: "cf_sql_varchar" });
        }

        baseParams = [
            { value: newReportId,          cfsqltype: "cf_sql_integer" },
            { value: sourceIP,             cfsqltype: "cf_sql_varchar" },
            { value: rcount,               cfsqltype: "cf_sql_integer" },
            { value: left(disposition,20), cfsqltype: "cf_sql_varchar" },
            { value: left(spfAlign,10),    cfsqltype: "cf_sql_varchar" },
            { value: left(dkimAlign,10),   cfsqltype: "cf_sql_varchar" },
            { value: left(hFrom,253),      cfsqltype: "cf_sql_varchar" }
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

    logLine("  RUA: inserted #recInserted# record row(s) for report id=#newReportId#");

</cfscript>
