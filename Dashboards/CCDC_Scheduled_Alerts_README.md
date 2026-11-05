# CCDC Defense Monitor — scheduled alert add-on

The app retains **12 dashboards** and **71 original on-demand saved searches**. It now also contains **five enabled scheduled alerts** (`CCDC ALERT | ...`).

## What they do

1. **Privileged accounts and group additions:** Event 4720 or privileged-group membership additions (4728, 4732, 4756). Every new account triggers investigation, even if not privileged.
2. **Windows security log cleared:** Event 1102, or System 104 when the text mentions the Security log.
3. **Service installed:** Event 7045 or 4697. All new services are flagged for review; this cannot automatically decide that the service is malicious.
4. **Repeated login failures:** >=8 Windows 4625 / SSH failures in 10 minutes, grouped per source/host. The field normalization is best-effort and must be validated against actual events.
5. **Critical log silence:** Host list below, after enabling, reports never-seen or >15 minute ingest silence. It uses `metadata` recentTime (index time). Splunk itself cannot alert when the search head or scheduler is down.

These alerts run on **5-minute staggered schedules** with 15- to 30-minute notification suppression. They are visible under **Activity > Triggered Alerts** in Splunk Web when they produce results. They do NOT send email, SMS or webhooks or take network action. They require data feeds and Splunk alert tracking to work. No Sysmon/Palo Alto/Windows forwarding is configured by this installer.

## Critical server host list — CONFIGURE BEFORE DEPENDING ON ALERT 5

1. In Splunk Search, run `index=* | stats count by host | sort host` to get EXACT values of the `host` field for your five servers. Do not assume the `host` field equals the VM IP address.
2. Edit `$SPLUNK_HOME/etc/apps/ccdc_defense/lookups/ccdc_critical_hosts.csv` and replace each `CHANGE_ME_*` value with the corresponding exact `host` field string. Set `enabled` from `0` to `1` for each VERIFIED host.
3. A host must normally send logs regularly (at least once per 15 minutes) for the alert to be meaningful. Hosts with sparse normal logs need an input producing regular heartbeat events, or a longer threshold.
4. Permissions: ensure the Splunk daemon user can read the CSV.
5. In Splunk, manually run **CCDC ALERT | Critical server log silence**. Confirm all expected hosts appear when data is absent, and no healthy host appears. A never-observed host is reported separately as `NEVER_OBSERVED`.

The lookup CSV is **preserved** by this installer when updating an already-installed app.

## Verify and tune

- Use `sudo bash <installer>.sh --verify` to check packaged counts (12 dashboards, 76 saved searches, 5 enabled alerts). The check is static, not a test that live data works.
- In Splunk Web, go to **Settings > Searches, reports, and alerts**, find the five `CCDC ALERT | ...` entries, and manually run/test each search with known data. Some field names differ by sourcetype.
- To change thresholds, lookback, suppression or temporarily disable a noisy alert, edit the relevant saved-search settings using Splunk Web or create overrides in the app's `local/savedsearches.conf`. Avoid editing `default/savedsearches.conf` directly for permanent tuning.
- Install or enable Windows Security and System channel forwarding on Windows, and SSH auth logs on Linux. A dashboard or saved search cannot detect missing telemetry.
- Expect new-account and new-service alerts during legitimate CCDC hardening; coordinate with the team's change log before investigating.
- For update, use `sudo bash <installer>.sh --update`; the original app is backed up in `$SPLUNK_HOME/var/ccdc_defense_backups`. Choose a safe time for Splunk restart, and avoid a restart during scoring.

## Limitations

- The queries have **not** been run against your real CCDC Splunk indexes. Their searches use `index=*`, which should be narrowed once you know the right indexes.
- Search timing depends on correct event timestamps and ingestion delays; the 5-to-10-minute search windows may need widening.
- Triggered alert tracking is **not** a remote notification channel and is not a substitute for observing dashboards.
- Alert 5 only detects missing **indexed events** for listed hosts. A service can fail while the host remains sending logs; use service scoring separately.
- A sustained attacker could suppress/erase host-side logs. Correlate with Palo Alto logs and scored service status.
