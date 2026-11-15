# CCDC Splunk Server Setup

`setup-splunk.sh` is the main setup and hardening script for the **Debian 12 / Splunk Enterprise** server used in UW–Whitewater's Collegiate Cyber Defense Competition (CCDC) environment. Its goal is to improve server security and centralize useful security logs **without unnecessarily disrupting scored services**.

The script combines core configuration with optional security features. Some steps use supporting scripts from this repository and may require confirmation or a Splunk restart.

## Main features

| Area | What the script does |
| --- | --- |
| **Splunk configuration** | Enables the Splunk receiving port (**TCP 9997**), configures login lockout protection, and restarts Splunk to apply changes. |
| **Dashboards and accounts** | Installs CCDC monitoring dashboards and runs the helper to create a lower-privilege Splunk Analyst account. |
| **Account and SSH security** | Restricts root/sysadmin SSH access, adds controls for administrative elevation over SSH, supports interactive Linux root password changes, and audits privileged accounts. |
| **Host firewall** | Offers a UFW default-deny configuration while retaining required TCP ports **22, 8000, 8089, and 9997**, plus **UDP 514** for Palo Alto syslog. Includes an optional IPv6 restriction. |
| **Palo Alto syslog** | Configures rsyslog to listen on **UDP 514**, save events in `/var/log/paloalto/pan.log`, and configure a Splunk file monitor (`index=main`, `sourcetype=pan:log`). |
| **Security monitoring** | Adds local Splunk inputs for **Suricata**, **ClamAV**, **auditd**, and Palo Alto logs. Offers passive Suricata IDS, notify-only ClamAV on-access scanning, and auditd installation. |
| **Updates and vulnerability mitigation** | Offers Debian package updates, an optional Splunk maintenance upgrade, and selected security/CVE mitigation helpers, including Splunk component and configuration hardening. |
| **Verification** | Checks selected service states, ports, configuration, and security settings, then prints PASS/FAIL/SKIP/REVIEW results. |

## Usage

Run the main setup **from the NETLAB VM console**, not over SSH:

```bash
sudo bash setup-splunk.sh
```

Additional modes:

```bash
sudo bash setup-splunk.sh --verify                # Read-only local verification
sudo bash setup-splunk.sh --audit-admins          # Review privileged Linux accounts
sudo bash setup-splunk.sh --paloalto-syslog-only  # Configure/test UDP 514 collector and Splunk input
sudo bash setup-splunk.sh --help                  # Show available modes
```

**Prerequisites:** Debian 12 with Splunk Enterprise installed (normally at `/opt/splunk`), administrative console access, and network access to required repository helpers/downloads. Verify the VM's actual IP and CCDC scoring requirements before applying firewall or service changes.

## Important notes and current limitations

- **Not every feature is automatic.** Upgrades, optional monitoring tools, account actions, and some mitigations require operator approval. A script feature being present does not prove it is enabled on a particular VM.
- **Palo Alto syslog delivery still needs end-to-end testing.** A local UDP 514 listener and successful test message do not prove the Palo Alto firewall is sending events or that Splunk is indexing real firewall traffic.
- **Analyst account creation needs better retry/recovery behavior.** A partially created role or user can prevent a clean rerun.
- **Endpoint log coverage is incomplete.** Windows Sysmon, forwarders, other Linux hosts, and log-source health checks must be deployed and verified separately.
- **CVE coverage is not complete.** The script includes selected upgrades and mitigations, but installed Splunk versions, applications, advisories, and effective settings still require review.
- **Firewall changes can affect CCDC scoring.** The UFW reset is optional; UDP 514 may be allowed broadly by default unless the Palo Alto source IPs are restricted. Use the console, preserve a recovery path, and verify scored services after changes.

For the broader project status, unresolved issues, and future implementation plan, see the [repository README](../README.md).
