# CCDC Defense Monitor — Command Center, Dashboards & Scheduled Alerts

Self-contained Splunk Enterprise dashboard and detection package for the CCDC practice/competition environment. **Run the installer on the Debian 12 Splunk Enterprise server**, not on endpoints.

## What's included

| Component | Count | Description |
|---|---:|---|
| Security Command Center | 1 dashboard / 20 panels | Consolidated, auto-refreshing security triage view |
| Original dashboards | 12 | Overall Monitoring, Log Coverage, Detection Triage, AD, MSSQL, Windows workstation, Rocky E-commerce, Ubuntu Email, Debian Splunk, Ubuntu workstation, Palo Alto, VyOS |
| Original on-demand reports | 71 | Existing investigation searches (not scheduled) |
| Additional Command Center hunts | 13 | New on-demand investigation searches (not scheduled) |
| Scheduled alerts | 5 | Enabled detection searches, with in-Splunk alert tracking |
| **Total** | **13 dashboards, 89 saved searches** | 84 on-demand reports and 5 scheduled alerts |

The original 12 dashboards and all 76 original saved searches (71 reports + 5 alerts) are packaged unchanged. The Command Center **does not copy every panel** from the 12 existing dashboards; it surfaces high-priority events and offers the older dashboards for detailed analysis.

### Command Center coverage

Host log freshness and event volume; Windows/Defender malware events; AD accounts and privileged-group changes; Splunk user, role, and management API changes; Windows remote logins and failed logins; new services and scheduled tasks; process executions; file create/delete activity; Sysmon network connections; RDP events; Linux SSH and sudo activity; Palo Alto and VyOS logs; MSSQL audit events; Splunk internal errors.

Default window: **last 30 minutes**. The 20 Command Center panels refresh every **2 minutes**. On a resource-constrained Splunk VM, monitor search concurrency and CPU; reduce search frequency/panel count if necessary.

> Empty panels **do not** prove there is no threat activity. Sources must exist, audit policies and log forwarding must be enabled, and field names must match the searches. The installer does not deploy Sysmon, Windows auditing, SQL Audit, firewalls, forwarders, or syslog senders.

## Installation / update

The new GitHub script should be saved as:

`Dashboards/setup-dashboards-main.sh`

The script contains an embedded, checksum-verified app archive and **works offline** after it is copied to the Splunk server. No additional XML or ZIP file is needed.

1. Transfer `setup-dashboards-main.sh` to the Debian Splunk server using an approved method; inspect its contents before executing.
2. Install or update an existing CCDC Defense Monitor app:

   ```bash
   sudo bash setup-dashboards-main.sh
   ```

   Running without arguments automatically chooses a fresh installation or a backed-up update. For an explicit update, use `sudo bash setup-dashboards-main.sh --update`.

3. Verify packaged components:

   ```bash
   sudo bash setup-dashboards-main.sh --verify
   ```

   Expected:

   ```text
   Dashboards: 13 (expected 13); searches: 89 (expected 89); scheduled alerts: 5 (expected 5)
   Static package check passed. Not a live Splunk validation.
   ```

4. Restart Splunk **only when service interruption is acceptable** using the VM's existing service manager. Avoid restarting while scored services are being checked.
5. Open **Splunk Web → Apps → CCDC Defense Monitor → CCDC | Security Command Center**. A direct relative URL is `/en-US/app/ccdc_defense/ccdc_command_center`. If the navigation is stale, refresh Splunk Web or load `/en-US/debug/refresh`.

The installer **does not** change Splunk listening/receiving ports, users, roles, firewall rules, forwarders, input definitions, or indexes. On update it backs up the previous app under `$SPLUNK_HOME/var/ccdc_defense_backups/`, preserves existing `local/` overrides and the `lookups/ccdc_critical_hosts.csv` file, and does not restart Splunk automatically.

## Five scheduled alerts

All five alerts use staggered **5-minute schedules** and write to **Activity → Triggered Alerts** in Splunk Web when triggered. These are **not** external notifications: no email, SMS, or webhook action is configured.

| Alert name (prefix: `CCDC ALERT |`) | When it triggers | Suppression |
|---|---|---|
| Privileged accounts and group additions | Windows Event 4720 (new account) or selected additions to privileged groups (4728/4732/4756) | 15 min |
| Windows security logs cleared | Windows 1102 or System 104 referencing the Security log | 15 min |
| Windows services installed | Windows 7045 or 4697 | 15 min |
| Repeated Windows or SSH failures | At least 8 Windows 4625/SSH authentication failures per normalized source/host over 10 minutes | 30 min |
| Critical server log silence | An **enabled** server in the CSV has no indexed events for more than 15 minutes, or has never been observed | 30 min |

The searches use best-effort fields and signatures; verify them against real WinEventLog, Linux, and Sysmon source formats before treating a non-trigger as a clean bill of health. Legitimate account creation and new services can trigger alerts during team hardening.

### Required configuration: critical-host log silence

This alert is **not operational by default**: the included CSV has placeholder hostnames and `enabled=0` for each entry.

1. In Splunk Search & Reporting, run:

   ```spl
   index=* earliest=-30m
   | stats count by host
   | sort host
   ```

2. Edit `$SPLUNK_HOME/etc/apps/ccdc_defense/lookups/ccdc_critical_hosts.csv`, replacing each `CHANGE_ME_*` with the **exact indexed `host` value** of your critical servers. Set `enabled` to `1` **only** for verified hosts. Do not rename machines or change their addresses to match the CSV.
3. Ensure the Splunk daemon account can read the CSV and the selected hosts normally generate at least one event every 15 minutes. A sparse-logging host may need a permitted heartbeat event or a longer threshold.
4. Run the saved search **`CCDC ALERT | Critical server log silence`** manually to validate the results.

Note: This alert measures indexed log intake, **not service availability**. A host can still send logs while HTTP, SMTP, MSSQL, or another scored service is down. It also cannot fire if Splunk or its scheduler is down.

## Data sources required for full monitoring

| Source | Enables |
|---|---|
| Windows Security + System event forwarding | Logons, account changes, services, audit-log clearing, privilege changes |
| Windows Defender Operational | Malware detections and Defender configuration changes |
| Sysmon with suitable configuration | Process creation, file activity, network connections |
| PowerShell/TerminalServices Operational (when configured) | Additional scripting and RDP events |
| Linux auth/sudo/audit logs | SSH and privileged changes |
| Splunk `_audit` and `_internal` permissions | Splunk account/role activity, API traces, scheduler/errors |
| Palo Alto and VyOS syslog | Network traffic, denies, firewall threats, router configuration |
| MSSQL Audit or Extended Events | SQL account and privileged database activity |

**Quick validation search:**

```spl
index=* earliest=-15m
| stats count latest(_time) as last_seen by host source sourcetype
| eval minutes_ago=round((now()-last_seen)/60,1)
| sort host
```

For Splunk's own changes, also test `index=_audit earliest=-30m | head 20`. Check whether your logged-in role has permission to search `_audit` and `_internal`.

## Splunk port protection (not installed by this script)

Use **Palo Alto rules for routed traffic** and **Debian's host firewall** for local access controls. Confirm sources for scoring, authorized administration, SSH, and forwarders **before** restricting anything.

| TCP port | Default purpose | Protect by allowing only required sources |
|---|---|---|
| `8000` | Splunk Web | Admin workstations and CCDC scoring/query sources |
| `8089` | Splunk management API | Authorized management and scoring sources |
| `9997` | Forwarder ingestion | Expected forwarder endpoints |
| `22` | SSH (if enabled) | Authorized management sources |

Inspect the existing firewall with `sudo ufw status verbose` and listeners with `sudo ss -lntp`. **Do not blindly block 8000 or 8089**: CCDC Splunk query/management checks may rely on them. Traffic between machines on the same subnet may bypass Palo Alto entirely. Prefer an allowlist validated from actual source addresses, confirm scored services and forwarded logs, and use the NETLAB console as a recovery path.

## Troubleshooting

| Symptom | First check |
|---|---|
| Script reports `expected 12` or only 76 searches | You still have the old GitHub installer; replace it with the updated 13-dashboard script |
| `Already installed` | Use the updated installer or `--update`; it backs up the existing app |
| Command Center does not appear | Run `--verify`, restart using existing service manager when safe, then refresh Web navigation |
| Dashboard opens but panels are empty | Time range, indexes, event channel forwarding, field extraction, and role permissions |
| Some high-detail panels stay empty | Defender Operational, Sysmon, MSSQL audit, Palo Alto/VyOS ingestion must be configured separately |
| Critical log silence never triggers | Replace `CHANGE_ME_*` hostnames and enable the correct CSV entries |
| Alerts never trigger | Confirm the scheduler, saved-search permissions, inputs, and known test events; inspect `index=_internal` for errors |
| Dashboard slows Splunk down | The main screen runs 20 searches; reduce refresh rate, time range, or panel count |

## Maintenance and rollback

- Tune alerts under **Settings → Searches, reports, and alerts** or `local/savedsearches.conf`. Avoid modifying the packaged `default/` configuration directly.
- Backup directory: `$SPLUNK_HOME/var/ccdc_defense_backups/` (outside `etc/apps`). On a failed validation, restore an appropriate previous app backup during a safe maintenance window, then restart through the existing Splunk service method.
- This package was checked for embedded archive integrity, XML structure, file counts, and simulated installation/update behavior. **It has not been validated on your live Splunk Enterprise 10.0.2 VM or actual CCDC logs.**
