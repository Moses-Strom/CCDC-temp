# CCDC Splunk Defense Toolkit

**Status and implementation roadmap — reviewed November 15, 2026**  
**Repository:** https://github.com/Moses-Strom/CCDC-temp  
**Purpose:** Prepare and defend the CCDC Debian/Splunk server, centralize logs from the competition network, detect suspicious activity, and preserve scored services.

> **Project status: functional foundation, not yet deployment-ready.** The server hardening script and several collectors/dashboards exist, and local UDP 514 reception has been tested. End-to-end Palo Alto delivery, analyst-role recovery, full endpoint log coverage, remaining CVE remediation, and reliable recovery have **not** been established. An installed configuration is not the same as an operationally verified security control.
>
> This status review uses the repository's public `main` branch, especially `Setup/setup-splunk.sh` and `Dashboards/create-splunk-analyst.py`, plus results reported from the practice/CCDC testing. Not every downloaded helper or target VM was independently tested. Verify against the actual checkout and live VM before relying on a status below.

## 1. Goals and environment

The Debian 12 Splunk Enterprise VM is the central security-monitoring node for an authorized Collegiate Cyber Defense Competition environment. The competition topology includes a Palo Alto firewall, VyOS router, Windows Active Directory and SQL servers, Linux application/email servers, and Windows/Linux workstations. The intended competition Splunk address is `172.20.240.20` **only when confirmed in the active pod**.

The solution is intended to:

1. **Maintain scoring:** Keep Splunk Web, management/query, forwarder receipt, SSH and required network connectivity operational.
2. **Reduce attack surface:** Harden the Debian host and Splunk, while preventing unauthorized account changes and persistence.
3. **Collect useful evidence:** Receive Windows, Linux, firewall, IDS and AV logs with known sources and reliable timestamps.
4. **Detect and investigate:** Provide meaningful dashboards and alerts for account activity, authentication, persistence, suspicious execution, tampering and logging outages.
5. **Recover quickly:** Preserve working configurations and test a restoration path when a service is damaged.
6. **Be repeatable:** Make setup predictable, safe to rerun and easy to execute during a time-constrained competition.

### Expected data paths

```text
Windows AD / SQL / workstation  ── Splunk Universal Forwarder ── TCP 9997 ──┐
Linux servers / workstations    ── Splunk Universal Forwarder ── TCP 9997 ──┤
Palo Alto firewall              ── syslog UDP 514 ── rsyslog ── pan.log ──┤
Debian local logs               ── Splunk monitor inputs ─────────────────┤
                                                                          ▼
                                                             Splunk Enterprise
                                                            searches / alerts
```

The local UDP 514 smoke test establishes only the **Debian-local** path. Real Palo Alto transmission and end-to-end Splunk ingestion are still unresolved.

## 2. What's currently implemented

**Status definitions**

- **Implemented in code:** The relevant configuration or automation appears in the repository. It may be optional and may not have run on the current VM.
- **Locally tested:** A limited local test has succeeded; it does not prove network-wide operation.
- **Incomplete / needs verification:** Additional integration, proof or remediation is needed.

| Component | Status | Current coverage and important limitation |
| --- | --- | --- |
| Central Splunk Enterprise setup | Implemented in code | `Setup/setup-splunk.sh` configures the server and performs read-only verification; deployed version and every scored service need confirmation. |
| TCP 9997 Splunk receiving | Implemented in code | Configures the Splunk receiving stanza; **not proof** that every Universal Forwarder connects or delivers data. |
| Splunk Web and API | Implemented in code | Preserves ports **8000/TCP** and **8089/TCP**; verify effective access restrictions and CCDC scoring. |
| Debian UFW | Implemented in code; local rules previously observed | Default-deny inbound with TCP **22, 8000, 8089, 9997** and UDP **514**. The full reset is optional. UDP 514 may be allowed from any source unless `CCDC_PA_SYSLOG_ALLOWED_IPS` is set. |
| Palo Alto syslog collector | Locally tested; integration unresolved | rsyslog UDP **514** writes to `/var/log/paloalto/pan.log`; Splunk monitor uses `index=main`, `sourcetype=pan:log`. Actual Palo Alto messages did **not** reliably appear during testing. |
| Old UDP 9997 syslog | Removal logic implemented | Managed UDP 9997 rsyslog receiver is retired; **TCP 9997 must remain** for forwarders. |
| Dashboards / saved alerts | Installer implemented; content advertised | Root README previously described **12 dashboards, 71 saved searches and five scheduled alerts**. Actual search usefulness depends on logs, permissions, event fields and active alert schedules; audit these counts rather than assuming success. |
| Analyst account / role | Implemented, **known retry bug** | `create-splunk-analyst.py` creates a restricted role and user, but refuses to continue if the role already exists—even if an earlier run created the role and failed before creating the user. |
| Splunk authentication protection | Implemented in code | Configures login lockout (five failures in five minutes; 30-minute lockout). Protect the existing Splunk administrator account and avoid repeated invalid-credential tests. |
| Debian root / privileged account review | Optional | Interactive root password change, sudo/account audit and optional account expiry; preserve a verified recovery administrator. |
| SSH / privilege elevation hardening | Implemented in code | Root/sysadmin SSH restrictions and PAM-based SSH-session elevation controls; test from NETLAB console for unintended lockout or scoring impact. |
| Splunk maintenance upgrade | Optional | Script calls an upgrade helper targeting the 10.0.x maintenance branch (currently **10.0.12** in the reviewed workflow), with an optional late retry. **Do not assume** the VM is actually upgraded. |
| Targeted CVE mitigations | Optional / incomplete | Helpers cover PostgreSQL sidecar, scripted-lookup enforcement and Secure Gateway decisions, but effective configuration, app versions, restarts and outstanding advisories still require review. |
| ClamAV | Optional | On-access **notify-only** monitoring; detection is not assured for custom threats and it is not a replacement for stronger endpoint controls. |
| Suricata | Optional | Passive IDS with rule verification and selected interface; validate traffic visibility, updated signatures and useful alerts. It does not block traffic. |
| auditd / local security logs | Optional | Helper-based file-change monitoring and Linux log coverage diagnostics; not proof that audit rules or remote Linux coverage are complete. |
| Splunk local file inputs | Implemented in code | Monitors Suricata `eve.json`, ClamAV `clamonacc.log`, auditd `audit.log`, and Palo Alto `pan.log`, with permissions setup. No guarantee that files exist, are readable or contain events. |
| Full backup/restore | **Not established** | Config backups exist in parts of setup, but a tested whole-service recovery workflow and clean-baseline process are outstanding. |

### Important repository files

- [`Setup/setup-splunk.sh`](Setup/setup-splunk.sh) — primary Debian/Splunk orchestration, firewall, rsyslog, monitoring and verification.
- [`Dashboards/create-splunk-analyst.py`](Dashboards/create-splunk-analyst.py) — analyst role and user creation; **needs idempotent recovery**.
- [`Dashboards/setup-dashboards-main.sh`](Dashboards/setup-dashboards-main.sh) — dashboard and search installation; verify runtime functionality and visibility.
- `Setup/ccdc-upgrade-splunk.sh`, `Setup/ccdc-post-upgrade-cve-hardening.sh`, `Setup/ccdc-mitigate-postgres.sh` — referenced security/upgrade helpers; review the exact current versions before treating mitigations as complete.
- `Setup/ccdc-readonly-security-audit.sh`, `Setup/ccdc-install-auditd.sh`, `Setup/check-linux-log-coverage.sh` — referenced audit and telemetry helpers.
- [`Universal Forwarder/`](Universal%20Forwarder/) — Windows/Linux forwarding resources. Confirm actual script filenames and version compatibility before deployment.
- [`Dashboards/`](Dashboards/) — monitoring dashboards and supporting resources.

**Version note:** The older README described Splunk Enterprise and Universal Forwarder **10.0.2** (starting environment). That is *not* proof of the currently installed version. Use `sudo /opt/splunk/bin/splunk version` and `dpkg-query -W splunk` on the actual VM.

## 3. Known problems and immediate investigation

### P0 — Palo Alto syslog does not reach Splunk consistently

**Observed:** UDP 514/UFW and the Debian-local `logger` → `pan.log` test have previously passed, but actual Palo Alto firewall messages were not observed as expected. Cause unknown: Palo Alto setup, network path, Debian collector, file access, or Splunk indexing remain possible. **Do not attribute fault to either operator without evidence.**

Work through the pipeline one hop at a time:

1. **Palo Alto owner:** Verify syslog server profile destination is the correct Debian VM IP, protocol **UDP**, port **514**, the service route / source interface and source IP, and that log-forwarding profiles/rules are actually attached to the relevant traffic/system/threat log types. Commit changes and generate a permitted test event.
2. **Network path:** Check Palo Alto/VyOS routing and upstream filtering. On Debian, inspect `sudo tcpdump -ni any 'udp dst port 514'` while the firewall emits a test log. If packets are absent, investigate the sender/path first.
3. **Debian receiver:** Check `sudo ss -lunp | grep ':514'`, `sudo ufw status numbered`, rsyslog config and `/var/log/paloalto/pan.log`. A listening socket and open UFW rule are **not** proof that remote packets arrive.
4. **Splunk indexing:** Verify the `monitor:///var/log/paloalto/pan.log` input using `btool`, the Splunk daemon's read permission, timestamps/index/sourcetype and search `index=main sourcetype=pan:log earliest=-30m`.
5. Record the **first failed hop** and keep a screenshot/log from both teams. Do not keep changing unrelated setup functions until the failure is isolated.

**Acceptance:** A new, identifiable event generated on Palo Alto is visible in the Debian packet capture, the rsyslog file, and Splunk within an agreed delay; repeat for system, traffic and threat logs that CCDC needs. Restrict UDP 514 to confirmed sending source IPs after diagnosis.

### P0 — Analyst role cannot be retried after partial failure

**Root cause in current helper:** It exits when `ccdc_analyst` already exists, rather than verifying whether that role has the intended capabilities and finishing creation of a missing user. The prior `401` authentication failure is a separate condition; it must not trigger blind retries or account lockouts.

**Required redesign:** Make role and user creation **idempotent** with safe reconciliation. Use a read-only precheck of admin authentication, roles and users. If the role exists and matches policy, reuse it; if an existing role differs, show an exact diff and require confirmation before changing it. If user creation partially succeeded, verify assigned roles and report a recoverable state. Never silently change the Splunk `admin` password or overwrite unrelated accounts/roles. Do not print passwords in logs. Require an actual analyst Web login and access test.

**Acceptance:** The helper can run twice successfully; it can recover when the role exists but user does not; bad credentials produce a clear error without destructive changes; the analyst sees only permitted indexes and shared dashboards, cannot administer Splunk, and can use saved searches as intended.

### P0 — Incomplete endpoint and log-source coverage

Dashboards only help when **every required system is actually producing logs**. Build a per-host inventory and validate at least one newly generated event from each enabled source:

| Source / host | Required collection plan | Proof of delivery |
| --- | --- | --- |
| Windows AD server | Security/System/Application, relevant PowerShell and **Sysmon** Operational events; account/group changes, logon failures, service creation, execution and log-clearing activity | Windows UF connected; test events searchable in Splunk with correct host/source/sourcetype |
| Windows SQL server | Same Windows baseline + SQL/service/error events and database audit events appropriate to scoring | Recent SQL and Windows events searchable |
| Windows workstation | Security/System/Application, PowerShell and Sysmon; useful process/file/network telemetry without excessive volume | New workstation events searchable |
| Debian Splunk VM | Splunk `_internal`/`_audit`, Linux authentication, system logs, auditd, UFW (if enabled), Suricata and ClamAV | Every configured local file/input produces fresh events |
| Rocky Linux e-commerce server | System/authentication, web server/access/error and application/service logs; auditd where justified | Fresh web and auth events from that exact host |
| Ubuntu email server | SSH/auth/system logs plus SMTP/IMAP/POP/webmail service logs | Test mail-service and auth events visible |
| Ubuntu workstation | System/SSH/auth and selected process/audit telemetry | Fresh workstation events visible |
| Palo Alto firewall | Traffic, threat, system/config and authentication logs via **UDP 514** | Firewall-generated event visible end-to-end |
| VyOS router (if available/authorized) | Syslog for routing, interfaces, firewall and administrative events | New router event visible or documented as unavailable |

**Implementation requirements:** Standardize host naming; assign source and sourcetype deliberately; deploy appropriate Universal Forwarder inputs to each Windows/Linux machine; create a single documented configuration source; install/configure Sysmon and verify its event channel; monitor permissions; watch ingestion latency; and control log volume against Splunk license/storage limits. Build a **log-source health dashboard** showing last-seen time, stale sources and gaps, plus an alert when a previously active source stops reporting.

## 4. CVE and vulnerability-remediation backlog

**No claim of “all CVEs fixed” is justified yet.** An upgrade helper and a mitigation script are useful only if the correct package is installed, the related app exists or is absent, the effective setting is checked, any required restart happened, and the affected service remains healthy.

| Advisory / concern | What to verify or remediate | Status |
| --- | --- | --- |
| **November 2026 advance notice** | Splunk's [SVD-2026-1101](https://advisory.splunk.com/) announced advisories for **November 18, 2026** and identifies **10.0.12** among the fixed Splunk Enterprise/UF releases. As of this README date, individual November disclosures are **not yet published**. Confirm installed versions and review details on release. | **Open — verify installed version and upcoming disclosures** |
| **Sept/Oct Enterprise CVEs** | Review [SVD-2026-1001](https://advisory.splunk.com/advisories/SVD-2026-1001) and [SVD-2026-1002](https://advisory.splunk.com/advisories/SVD-2026-1002); October 10.0 fixes require at least 10.0.10 for those advisories, with additional measures for specified CVEs. | **Partial — verify upgrade + per-CVE actions** |
| **October Enterprise CVEs** | Review [SVD-2026-1007](https://advisory.splunk.com/advisories/SVD-2026-1007) and [SVD-2026-1008](https://advisory.splunk.com/advisories/SVD-2026-1008); fixes on 10.0 branch begin at 10.0.11 for these advisories, with extra Secure Gateway measures. | **Partial — verify release and app-specific requirements** |
| **Scripted lookup raw writes** | For **CVE-2026-76264**, after a fixed-version upgrade confirm `[lookup] scripted_lookup_raw_write_enforcement = block` is **effective**, not merely written, and Splunk restarted as required. | **Conditional helper; effective state unknown** |
| **Splunk Secure Gateway** | For **CVE-2026-76292/76295** and related advisories, inventory app version and dependencies; upgrade or disable unused Secure Gateway, then verify the effective state. Do not break a service that CCDC requires without approval. | **Conditional helper; verify** |
| **PostgreSQL sidecar** | Review **CVE-2026-20253** and other sidecar issues; confirm applicable version, whether the service is needed, and whether the actual fixed release or a compatible mitigation is in effect. | **Conditional helper; verify** |
| **Node.js / Splunk Visual Exporter** | [SVD-2026-1015](https://advisory.splunk.com/advisories/SVD-2026-1015) says to consider **Splunk Enterprise 10.2+** for vulnerable Node.js components on the 10.0 branch and separately review disabling/removing unused Visual Exporter. **10.0.12 alone is not proof this advisory is resolved.** Check CCDC compatibility and dashboard-export requirements first. | **Open** |
| **Debian packages / dependencies** | Record Debian package updates, security advisories, bundled Splunk runtimes, installed Splunk apps/add-ons and third-party helpers. Prioritize confirmed exposure without breaking scoring. | **Not exhaustively assessed** |

**Do next:** Obtain a read-only inventory of installed Splunk version, enabled apps, affected configuration settings, Debian security status and exposed ports. Build a CVE register with: CVE/advisory, affected versions, applicability, mitigation, restart requirement, test result, owner and date. A **PASS** requires evidence. Run upgrades first in the disposable VM and verify scoring afterward.

## 5. Further hardening and reliability work

### High priority

- **Management-plane exposure:** Review who can access Splunk Web **8000/TCP** and management API **8089/TCP**. Narrow source access where CCDC permits, use valid TLS, audit administrator sessions, and avoid exposing privileged interfaces unnecessarily. Preserve scored checks.
- **Account/persistence baselines:** Before making changes, inventory users, group membership, sudo policy, SSH authorized keys, cron jobs, systemd services/timers, startup hooks, recent executable changes, package integrity and Splunk apps/authentication state. Distinguish pre-existing suspicious state from known-good baseline; record before-and-after evidence.
- **Security monitoring content:** Test alerts for privileged-account changes, new services/timers, remote access, repeated logon failures, Windows log clearing, suspicious process execution, unauthorized Splunk changes and stopped log sources. Test both actual detection and alert delivery.
- **Reliable recovery:** Create a limited but useful VM-accessible backup plan for Splunk configuration, apps, input definitions, system configuration and relevant audit evidence. Verify restore steps and permissions **without relying on Proxmox/snapshot access**, which the team may not have during competition. Establish console recovery for lockouts.
- **CVE and app inventory:** Keep an actionable list of affected components rather than claiming universal protection from a small set of patches.

### Refactor the patchwork setup workflow

The current `setup-splunk.sh` works as a prototype, but a single interactive script managing upgrades, users, PAM, UFW, AV/IDS, dashboards and Splunk restarts is difficult to diagnose and safe-retry.

**Desired next design:**

1. Replace scattered long typed confirmations such as `APPLY-UFW` with **clear `y/N` questions** and an explicit summary of consequences. Continue to refuse disruptive firewall/PAM operations from SSH, and require confirmation from the VM console. Do not silently reset rules.
2. Split operations into **preflight → choose features → apply → verify → report**. Use short prompts, sensible defaults, and one final summary of what will change.
3. Separate modular tasks: `preflight`, `splunk-core`, `network/ufw`, `rsyslog`, `analyst`, `forwarders/inputs`, `ids-av`, `cve`, `dashboards`, `backup`, `verify`.
4. Make every task **idempotent**: rerunning should check and reconcile known state, not leave partial roles/configuration or duplicate inputs. Back up the exact file being changed; validate before activating it; provide rollback instructions.
5. Use one shared configuration for expected host IPs, allowed syslog senders, port requirements, Splunk indexes, forwarder hosts and approved features. Do not hard-code example PA source IPs as verified facts.
6. Keep `--verify` truly read-only and support narrowly scoped setup commands (such as `--paloalto-syslog-only`) without rerunning unrelated protections.
7. Report **PASS / FAIL / SKIP / REVIEW** per component, with a concise failure reason and next diagnostic command. Avoid false failures for optional features and false successes for mere file presence.
8. Centralize log input definitions, normalize sourcetypes/host metadata and avoid duplicate monitors. Ensure permissions and restart needs are checked as part of each source setup.
9. Minimize unreviewed script downloads from a mutable branch: pin/test approved helper versions, verify downloaded artifacts, and prefer the checked-out repo for offline competition use.
10. Add automated checks (Bash syntax, shellcheck where available, smoke tests, repeat-run tests, mocked UFW/rsyslog cases, analyst role partial-failure tests) and an end-to-end VM regression checklist.
11. Reduce redundant terminal output. Keep detailed logs on disk while displaying a concise result summary, plus a command to retrieve diagnostics.

## 6. Recommended implementation order

| Priority | Task | Definition of done |
| --- | --- | --- |
| **P0** | Resolve Palo Alto delivery | Firewall-generated traffic, system and threat test logs appear in packet capture, `pan.log` and Splunk; sending IP is documented. |
| **P0** | Repair analyst setup | Fresh and repeat runs succeed; partial role creation is recoverable; least privilege verified; no admin password change. |
| **P0** | End-to-end endpoint source coverage | Every expected VM has a tested input; Windows Sysmon/PowerShell and Linux service/auth telemetry reach Splunk; source inventory is current. |
| **P0** | Verify current CVEs | Installed versions and apps inventoried; applicable advisories have evidence of patch/mitigation or explicit accepted risk. |
| **P1** | Refactor setup UX and modularity | Short `y/N` prompts, safe console-only destructive changes, idempotent reruns, smaller modules and actionable failure output. |
| **P1** | Test alerts and dashboard permissions | Detection test events are visible; alerts fire correctly; analyst role can read shared dashboards and saved searches. |
| **P1** | Persistence and compromise assessment | Baseline audit covers accounts, scheduled tasks/services, startup hooks, files and configuration changes; findings documented. |
| **P1** | Narrow management and syslog access | Only approved sources reach privileged interfaces and UDP 514, while all scored services still work. |
| **P2** | Backup and recovery drills | Config/data backup, integrity checks and a VM-console restore procedure tested. |
| **P2** | Repeatability/maintenance | Fresh-VM install and second-run tests pass; dependency versions, assumptions and a troubleshooting guide are documented. |

## 7. Quick operational checks (read-only unless noted)

Run on the **Debian Splunk VM** from the NETLAB console:

```bash
# Read-only script verification and installed Splunk version
sudo bash setup-splunk.sh --verify
sudo /opt/splunk/bin/splunk version

# Core network listeners and firewall allowances
sudo ss -lntup | grep -E ':(22|8000|8089|9997|514)\b'
sudo ufw status numbered

# rsyslog active configuration and recent service errors
sudo rsyslogd -N1 -f /etc/rsyslog.conf
sudo systemctl is-active rsyslog
sudo journalctl -u rsyslog -n 30 --no-pager
sudo tail -n 20 /var/log/paloalto/pan.log

# Effective Splunk inputs, not just a config file on disk
sudo /opt/splunk/bin/splunk btool inputs list --debug
```

**Local syslog test — creates a benign event, does not test the real Palo Alto path:**

```bash
logger --udp --server 127.0.0.1 --port 514 --tag CCDC_TEST 'CCDC_UDP514_LOCAL_SMOKE'
sudo grep -F 'CCDC_UDP514_LOCAL_SMOKE' /var/log/paloalto/pan.log
```

**Splunk searches:**

```spl
index=main sourcetype=pan:log earliest=-30m
| table _time host source _raw
```

```spl
| tstats latest(_time) AS last_seen WHERE index=main BY host sourcetype
| eval minutes_since=round((now()-last_seen)/60,1)
| sort - minutes_since
```

The source-health search is an investigation starting point, **not** a complete alert until expected hosts/sourcetypes and thresholds are defined. `_internal`/`_audit` may need separate index access.

## 8. CCDC operating constraints

- Work only inside the authorized CCDC environment and competition rules. The actual topology, permitted source addresses and scored services take precedence over examples in this repository.
- Do not break the scoring-critical TCP services or required ping. Validate from another VM after any firewall, PAM, package or Splunk change.
- Don't automatically rotate or overwrite the existing **Splunk `admin`** password; any recovery must preserve an available verified administrator. Debian `root` password rotation remains interactive.
- ClamAV and Suricata are supplemental detection; they do not establish a clean host or guarantee prevention of custom malware and persistence.
- Don't assume Proxmox access is available. Prefer NETLAB console checks, configuration backups and tested service-level recovery.
- Do not commit passwords, private keys, real user data or sensitive competition artifacts to this repository.

## 9. Tracking and evidence

For each remediation, record: **task, owner, target VM, source version/commit, configuration changed, preflight, result, rollback, proof, and scoring regression result**. Keep temporary screenshots or diagnostic logs out of the public repo if they reveal sensitive information.

Suggested milestone sequence: **restore trustworthy ingestion → fix analyst access → confirm endpoint coverage → close applicable CVEs → simplify setup → test persistence detection and recovery → final full-pod simulation**.

### References

- [Splunk security advisories](https://advisory.splunk.com/)
- [SVD-2026-1001: September/October Enterprise vulnerabilities](https://advisory.splunk.com/advisories/SVD-2026-1001)
- [SVD-2026-1007: October Enterprise vulnerabilities](https://advisory.splunk.com/advisories/SVD-2026-1007)
- [SVD-2026-1015: Node.js and Splunk Visual Exporter](https://advisory.splunk.com/advisories/SVD-2026-1015)
- [Splunk installation and administration documentation](https://help.splunk.com/)
- [rsyslog remote server documentation](https://docs.rsyslog.com/doc/getting_started/beginner_tutorials/06-remote-server.html)

*This README is a status assessment and action plan, not a certification that every control is deployed or every vulnerability remediated.*
