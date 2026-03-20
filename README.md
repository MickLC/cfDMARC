# cfDMARC — Legacy Branch

This branch is a reference marker. It was created from `master` at the point
the current application skeleton was first committed (March 2026).

## Original 2016 Pipeline Files

The original shell-script-based pipeline files are preserved in git history
on the `master` branch at commit `cc6eeb8`:

- `legacy/processxml.cfm` — ColdFusion XML processor (read XML from `/tmp`,
  output raw SQL to screen)
- `legacy/getxml.sh` — Bash script using `munpack` to extract attachments
  from a Maildir
- `legacy/procmailrc` — Procmail rule routing DMARC report emails to the
  Maildir

To view them:
```bash
git show cc6eeb8:legacy/processxml.cfm
git show cc6eeb8:legacy/getxml.sh
git show cc6eeb8:legacy/procmailrc
```

## Architecture Then vs Now

```
[2016]
Email → procmail → Maildir → getxml.sh → /tmp/*.xml → processxml.cfm → SQL output (manual)

[Current]
Email → IMAP → poll.cfm → parse_rua.cfm → MariaDB → Dashboard
```

## Active Development

See the `develop` branch for current work.
See `master` for stable releases.
