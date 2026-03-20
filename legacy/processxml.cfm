<!---
  LEGACY FILE — preserved for historical reference only.
  This was the original XML processor from 2016/2017.
  It read XML files from /tmp and generated SQL output to screen.
  Superseded by the poller/parse_rua.cfm in the current application.
--->

<!---<cfset report=xmlParse('/tmp/google.com!chandler-clan.com!1500163200!1500249599.xml') />--->

<cfdirectory action="list" directory="/tmp" name="getFiles" filter="*.xml" sort="dateLastModified"/>

<cfoutput> 

<cfdump var="#getFiles#" />
<cfloop query="#getFiles#">
<cfset report=xmlParse('/tmp/#getFiles.name#')>
insert into report (mindate,maxdate,domain,org,reportid,email,
<cfif isDefined("report.feedback.report_metadata.extra_contact_info.XmlText")>
	extra_contact_info,
</cfif>
policy_adkim,policy_aspf,policy_p,policy_sp,policy_pct)
values 
(from_unixtime(#report.feedback.report_metadata.date_range.begin.XmlText#),from_unixtime(#report.feedback.report_metadata.date_range.end.XmlText#),'#report.feedback.policy_published.domain.XmlText#','#report.feedback.report_metadata.org_name.XmlText#','#report.feedback.report_metadata.report_id.XmlText#','#report.feedback.report_metadata.email.xmltext#',
<cfif isDefined('report.feedback.report_metadata.extra_contact_info.XmlText')>
	'#report.feedback.report_metadata.extra_contact_info.xmltext#',
</cfif>
'#report.feedback.policy_published.adkim.xmltext#','#report.feedback.policy_published.aspf.xmltext#','#report.feedback.policy_published.p.xmltext#','#report.feedback.policy_published.sp.xmltext#','#report.feedback.policy_published.pct.xmltext#')
<br><br>
select last_insert_id() from report
<br><br>
<cfloop index="i" from="1" to="#arraylen(report.feedback.record)#">
insert into rptrecord (serial,
<cfif isIPv6(#report.feedback.record[i].row.source_ip.xmltext#)>
	ip6,
<cfelse>
	ip,
</cfif>
rcount,disposition,
<cfif isDefined('report.feedback.record[i].row.policy_evaluated.reason.type.xmltext')>
	reason,
</cfif>
<cfif isDefined('report.feedback.record[i].row.policy_evaluated.reason.comment.xmltext')>
	comment,
</cfif>
<cfif isDefined('report.feedback.record[i].auth_results.dkim.domain.xmltext')>
        dkimdomain, 
</cfif> 
<cfif isDefined('report.feedback.record[i].auth_results.dkim.result.xmltext')>
        dkimresult,
</cfif>
<cfif isDefined('report.feedback.record[i].auth_results.spf.domain.xmltext')>
        spfdomain, 
</cfif> 
<cfif isDefined('report.feedback.record[i].auth_results.spf.result.xmltext')>
        spfresult,
</cfif>
spf_align,dkim_align,identifier_hfrom)
values
(serial,
<cfif isIPv6(#report.feedback.record[i].row.source_ip.xmltext#)>
	inet6_aton(#report.feedback.record[i].row.source_ip.xmltext#),
<cfelse>
	inet_aton(#report.feedback.record[i].row.source_ip.xmltext#),
</cfif>
#report.feedback.record[i].row.count.xmltext#,'#report.feedback.record[i].row.policy_evaluated.disposition.xmltext#',
<cfif isDefined('report.feedback.record[i].row.policy_evaluated.reason.type.xmltext')>
         '#report.feedback.record[i].row.policy_evaluated.reason.type.xmltext#', 
</cfif> 
<cfif isDefined('report.feedback.record[i].row.policy_evaluated.reason.comment.xmltext')>
         '#report.feedback.record[i].row.policy_evaluated.reason.comment.xmltext#',
</cfif>
<cfif isDefined('report.feedback.record[i].auth_results.dkim.domain.xmltext')>
        '#report.feedback.record[i].auth_results.dkim.domain.xmltext#', 
</cfif> 
<cfif isDefined('report.feedback.record[i].auth_results.dkim.result.xmltext')>
        '#report.feedback.record[i].auth_results.dkim.result.xmltext#',
</cfif>
<cfif isDefined('report.feedback.record[i].auth_results.spf.domain.xmltext')>
        '#report.feedback.record[i].auth_results.spf.domain.xmltext#', 
</cfif> 
<cfif isDefined('report.feedback.record[i].auth_results.spf.result.xmltext')>
        '#report.feedback.record[i].auth_results.spf.result.xmltext#',
</cfif>
'#report.feedback.record[i].row.policy_evaluated.spf.xmltext#','#report.feedback.record[i].row.policy_evaluated.dkim.xmltext#','#report.feedback.record[i].identifiers.header_from.xmltext#'
)<br />
</cfloop>
</cfloop>
</cfoutput>
