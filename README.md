# cfDMARC

A ColdFusion/Lucee DMARC reporting dashboard for self-hosted infrastructure.

## Features

- IMAP polling (password auth + Google OAuth2) for automated report ingestion
- Parses RUA (aggregate) and RUF (forensic) DMARC reports
- MariaDB backend — schema supports multiple domains automatically
- Dark dashboard UI with ApexCharts visualizations
- Time-limited share tokens for read-only public views
- Full audit logging

## Requirements

- Lucee 5.x or Adobe ColdFusion 2018+
- MariaDB 10.5+ (tested on 11.4)
- Apache/Nginx vhost

## Setup

1. Clone repo to web root: `git clone https://github.com/MickLC/cfDMARC /var/www/dmarc`
2. Copy config: `cp config/settings.example.cfm config/settings.cfm`
3. Edit `config/settings.cfm` with your DB credentials and keys
4. Configure a Lucee datasource named `dmarc` pointing at your MariaDB instance
5. Run `db/001_migrate_schema.sql` against your database
6. Browse to `/admin/setup.cfm` to create the first admin user
7. **Delete `admin/setup.cfm`** after setup
8. Configure a `cfschedule` task pointing at `/poller/poll.cfm`

## Security Notes

- `config/settings.cfm` is gitignored — never commit it
- Generate pepper and encryption key with `openssl rand -base64 32`
- Set `DMARC_PEPPER` as an environment variable rather than in settings.cfm
- Delete `admin/setup.cfm` immediately after creating your admin account
