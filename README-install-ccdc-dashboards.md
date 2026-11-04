# CCDC Splunk Dashboards Installer

Installs the **CCDC Defense Monitor** app on the Midwest Invitational CCDC **Debian 12 / Splunk Enterprise 10.0.2** server (`172.20.240.20`). The goal is to deploy dashboards and detection searches quickly without building each one manually in Splunk Web.

This README accompanies **`install-ccdc-dashboards.sh`**. Run it on the **Splunk Enterprise server**, not on the Windows/Linux endpoints.

## What it installs

- **12 Splunk dashboards:** Overview, Log Coverage, Detection Triage, Active Directory, MSSQL, Windows 11, Rocky Ecom, Ubuntu Email, Debian Splunk, Ubuntu Workstation, Palo Alto, and VyOS.
- **71 saved search reports:** 54 CCDC-oriented searches based on the CyberHawks detection catalog, plus 17 additional CCDC searches.
- Hostname selectors and time-range inputs on applicable dashboards.
- The Splunk app at `/opt/splunk/etc/apps/ccdc_defense/`.

**All automatic detection scheduling is disabled.** The saved searches are reports, not active alerts. The searches and dashboards have not been verified against this competition's live logs; a dashboard can be installed correctly and still show no data.

## Requirements

- Debian Splunk VM (`172.20.240.20`) with Splunk Enterprise installed at `/opt/splunk`.
- Root/sudo access for installing or updating the app.
- The complete `install-ccdc-dashboards.sh` script. **Do not remove the encoded payload at the end of the file**: the dashboards are packaged inside it.
- Splunk Web access, typically `http://172.20.240.20:8000` (or `https://` if configured).

The installer itself works **offline** after the complete script is copied to the VM. It does not download its app from GitHub.

## Install

1. Copy `install-ccdc-dashboards.sh` to the Debian Splunk VM using a competition-approved method. If downloading from a public GitHub repository is permitted, you can use your repository's **Raw** file URL. Alternatively, paste the full script into a file using `nano`.
2. Open a terminal on the Debian Splunk VM, navigate to the script, and run:

   ```bash
   sudo bash install-ccdc-dashboards.sh
   ```

3. Verify the installed files:

   ```bash
   bash install-ccdc-dashboards.sh --verify
   ```

   Expected file counts:

   ```text
   Dashboard XML files: 12 (expected 12)
   Saved reports: 71 (expected 71)
   Scheduled searches enabled by this app: 0
   ```

   **These counts verify the installed files, not that detections are receiving events.**

4. When it is safe to interrupt Splunk briefly, restart Splunk using its **existing** service manager and OS account. To check for a systemd unit:

   ```bash
   systemctl list-unit-files | grep -i splunk
   ```

   If Splunk is managed by `Splunkd.service`, for example:

   ```bash
   sudo systemctl restart Splunkd.service
   ```

   Use the actual unit and start method on your VM. The installer **does not restart Splunk automatically**.

5. Open Splunk Web and select **Apps → CCDC Defense Monitor**. Start with **Log Coverage** to see which hosts and sourcetypes are actually arriving. If the app menu does not refresh, reload Splunk Web or use its `/en-US/debug/refresh` page.

## Verify logs before using detections

In **Search & Reporting**, run:

```spl
index=* earliest=-15m
| stats count by host, source, sourcetype
| sort -count
```

Use the **actual indexed `host` field**, especially for DHCP workstations. A working receiver or forwarder service alone does not prove events are being indexed.

The central server needs TCP `9997` receiving configured separately, and endpoint forwarders need to send it logs. Windows Security/System/Application events, Linux authentication logs, SQL auditing, Palo Alto syslog, and VyOS syslog require their own source-specific configuration. Many advanced searches also require additional auditing, Sysmon, or Zeek; **Zeek is not included or assumed for this topology**.

## Update an existing installation

Running the normal install command again will stop if the app already exists. To update:

```bash
sudo bash install-ccdc-dashboards.sh --update
```

This backs up the previous app under:

```text
/opt/splunk/var/ccdc_defense_backups/
```

The update replaces packaged app files but is intended to preserve `local/` customizations. Verify and restart using the existing Splunk service method when appropriate.

## Useful commands

```bash
# Show available script options
bash install-ccdc-dashboards.sh --help

# Check installed dashboard/report counts
bash install-ccdc-dashboards.sh --verify

# Check Splunk status
sudo /opt/splunk/bin/splunk status
```

## Troubleshooting

| Problem | What to check |
|---|---|
| `Splunk Enterprise not found` | Verify `/opt/splunk/bin/splunk` exists; the script supports a different path through `SPLUNK_HOME`. |
| `Built-in app payload missing` or checksum failure | The script was truncated or edited; recopy the **complete** file, including the encoded payload. |
| App doesn't appear in Splunk Web | Check app directory ownership, restart through the proper service, then refresh Splunk Web. |
| Dashboard opens but has no data | Use **Log Coverage** and the SPL query above; check forwarders, receiving port `9997`, and relevant sourcetypes. |
| Some detection searches return nothing | The required event might not have occurred, or additional auditing/log sources may be missing. |
| `Already installed` | Use `--update`, not the default install mode. |

## Competition notes

- **No changes** are made by this installer to admin passwords, firewall rules, indexes, receiving ports, forwarders, or network addressing.
- Do not restart Splunk unnecessarily during scoring; the competition checks Splunk Query and Splunk Management functionality.
- Do not change hostnames, IPs, VLANs, or scored services to fit dashboard filters.
- Only enable automatic alerts after checking real incoming data and tuning false positives.

## Source acknowledgment

This project adapts **detection topics** from [CyberHawks-IIT/splunk-detections](https://github.com/CyberHawks-IIT/splunk-detections) into original CCDC-oriented searches and dashboards. It is not a verbatim copy of their detection implementations and has not been validated on the CyberHawks lab or this CCDC environment.
