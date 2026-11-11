# CCDC Splunk Enterprise Server Setup

Configures the Midwest Invitational CCDC **Debian 12 / Splunk Enterprise 10.0.2** VM, expected at **`172.20.240.20`**, to receive Universal Forwarder logs and optionally run host-based malware and network detection without deliberately interfering with scored Splunk ports.

This README accompanies **`setup-splunk.sh`**. Run it on the **Debian Splunk server** from the **NETLAB+ VM console**, not from an SSH session. Do not run it on endpoints.

## What the combined script does

1. Verifies prerequisites and refuses to make setup changes from an SSH session. Run from a verified **NETLAB+ VM console**.
2. Displays listening ports and offers optional Debian package updates (full upgrades require separate approval).
3. **Optionally changes the Debian Linux `root` password** using the system `passwd root` command. The password is entered interactively, is not displayed, and is not stored in a script or passed on the command line. **This no longer changes the separate Splunk Web `admin` password.**
4. **Optionally audits Linux administrator/sudo access**, including direct sudoers rules, groups, and UID 0. Lists candidates for review and permits *individual* account expiry only after confirmed root console recovery and a second typed confirmation. Never automatically expires every sudo user.
5. Backs up `inputs.conf` and enables Splunk Universal Forwarder receiving on TCP `9997`.
6. Backs up `authentication.conf` and configures Splunk account lockout: **5 failed attempts in 5 minutes → 30-minute lockout**.
7. Denies **new SSH logins for `root` and `sysadmin`**, and adds PAM-based restrictions against `sudo`, `su`, and other monitored privilege-elevation commands in SSH sessions. Authorized local NETLAB console administration remains available; this does not prove denial of every possible elevation path.
8. Optionally **resets and enables UFW** after two explicit confirmations. The applied policy is default **deny incoming**, **allow outgoing**, with inbound TCP allowances on `22`, `8000`, `8089`, and `9997`. Existing UFW user rules are replaced; review CCDC scoring requirements before approving this step.
9. Optionally installs/enables **ClamAV on-access monitoring in notify-only mode**. No automatic quarantine, deletion, or file blocking; avoids scanning large Splunk index directories.
10. Optionally installs/enables **Suricata in passive AF_PACKET IDS mode**, attempting to download an ET Open ruleset. Suricata itself does not block packets.
11. Adds Splunk file-monitor inputs for Suricata EVE JSON and ClamAV on-access logs, with best-effort least-privilege ACLs.
12. **Optionally** restarts Splunk at the end; a skipped restart may leave new input configuration inactive.
13. Prints **`CCDC Splunk Server Setup Complete`** followed immediately by per-check **`PASS` / `FAIL` / `SKIP`** verification, an overall `RESULT`, and a disk-space summary.

**Account audit/expiry is optional:** The script does not automatically disable accounts. For an independent, *read-only* account review, run `sudo bash setup-splunk.sh --audit-admins`. The privilege report uses the actual output from `sudo -l -U`, not that command's exit status alone. Some non-sudo privilege mechanisms, external identities, or directory-managed accounts may require separate review.

**Important:** ClamAV/Suricata package installation and signature downloads may use considerable CPU, RAM, disk, and network resources. Even though detection-only modes do not intentionally block traffic, their performance overhead can affect services. Test on a practice VM before competition scoring.

## Required network ports and firewall

| Port | Protocol | Purpose | Current script behavior |
|---|---|---|---|
| `22` | TCP | SSH | UFW allows inbound TCP 22 if approved; sshd denies `root`/`sysadmin` logins, and PAM restricts standard SSH-initiated elevation paths |
| `8000` | TCP | Splunk Web | UFW allows inbound 8000 if approved; service must already be configured to listen |
| `8089` | TCP | Splunk management / scoring | UFW allows inbound 8089 if approved; no localhost-only or IP allowlist restriction is applied |
| `9997` | TCP | Splunk Universal Forwarder ingestion | Configures Splunk receiver; UFW allows inbound 9997 if approved; usually requires Splunk restart |

The UFW step is **optional** and asks for approval and the literal `APPLY-UFW` confirmation. When approved it backs up previous `/etc/ufw` settings under `/root`, resets UFW user rules, sets **default deny incoming / allow outgoing**, explicitly allows those four TCP ports, and enables UFW. It preserves standard UFW ICMP behavior, but scored connectivity still requires external checks. It does **not** reconfigure Palo Alto, switches, or VyOS.

Because `ufw reset` discards existing user rules, do not apply it before checking for any additional required CCDC services or management pathways. The final verification checks policy and those four UFW rules, but it cannot verify access from the scoring network.

Suricata passively observes traffic visible on the Debian VM's selected interface. It cannot see all traffic between other CCDC VMs without mirroring or forwarding.

## Requirements

- NETLAB+ console access to the Debian Splunk VM, with `sudo`/root privileges. **The script refuses an SSH-originated setup session.**
- Existing Splunk Enterprise in `/opt/splunk` (or set `SPLUNK_HOME` to the actual location).
- Debian 12, Python 3, `ss`, `systemctl`, and `ps`. Optional IDS configuration also needs `iproute2` (`ip`).
- Debian APT repositories reachable if installing ClamAV/Suricata; signatures/rules downloads may need outbound internet access.
- Adequate available RAM and disk for ClamAV signatures, Suricata rules, IDS logs, and Splunk data.
- To rotate the Linux root password, you must be able to run `passwd` as root; the command asks for the new password directly. If you intend to expire any admin account, you must **first test a separate root login using NETLAB console**. Setting a password does not prove that console login works.
- ClamAV on-access monitoring needs kernel fanotify support. The setup reports a service error if it cannot start.
- Actual capture interface can be specified with `CCDC_SURICATA_IFACE` if the automatic selection is wrong.

Never commit competition passwords or secrets to the GitHub repository.

4. Answer the prompts. For **root password rotation**, the standard `passwd` utility prompts twice without printing the password. For **administrator account review**, optionally list privileged users; expiration requires a verified *new* root console login, an explicit username, and a typed `EXPIRE USERNAME` confirmation. ClamAV and Suricata remain optional.
5. Choose whether to restart Splunk **after** installing the monitoring inputs. A restart is usually required to activate changes but can briefly affect scoring.
6. Read the `PASS`, `FAIL`, `SKIP`, and `RESULT` lines **below `CCDC Splunk Server Setup Complete`**. The script checks local status/configuration but does not prove scoring reachability or real detection events.

The server setup writes backups of modified Splunk configuration files. It also backs up OpenSSH and PAM files and the prior UFW configuration when those changes are made, and backs up ClamAV daemon configuration.

## What the final verification looks like

After interactive setup, the script displays the following **heading** and a detailed line-by-line report. These lines are illustrative; **the actual statuses depend on your VM**:

```text
===========================================================
 CCDC Splunk Server Setup Complete
===========================================================
 PASS / FAIL / SKIP verification of each setup area
-----------------------------------------------------------
PASS | Linux root account exists and is not expired
PASS | Splunk reports running
PASS | Splunk receiving enabled on TCP 9997 in effective configuration
PASS | TCP 8000 service listening
PASS | UFW active with default deny incoming / allow outgoing
PASS | UFW inbound TCP 22 allowed
PASS | sshd config denies new root/sysadmin SSH logins
PASS | PAM sudo configured to deny SSH-ancestry privilege elevation
PASS | clamav-daemon.service active
PASS | suricata.service active
RESULT | PASS: All applicable static/local checks succeeded (live remote behavior unproven).
```

The real report also checks these items where applicable:

- Whether Debian root password rotation succeeded **during the current run**, and whether root is still enabled and not expired; checks any accounts expired during the run.
- Whether the Splunk credential-store file remained unchanged **during the current run**, when a baseline is available. This is **not** a remote Splunk login test.
- Whether Splunk's restart command succeeded if you opted to restart; whether its 9997 receiver, authentication lockout settings, and TCP listeners are in place.
- The `root`/`sysadmin` OpenSSH deny rules, PAM elevation guard files, PAM configuration for available services, and UID-0 SSH login protection. **Actual remote denial still needs an SSH test.**
- UFW default policy, permitted TCP 22/8000/8089/9997 rules, and unexpected extra user `ALLOW IN` rules.
- ClamAV service status, notify-only configuration and log-file presence; Suricata service status, rule-file presence and YAML test, passive capture configuration, configured interface existence, and EVE JSON file presence.
- Splunk inputs for Suricata/ClamAV, an operation-error count, and a disk-space summary.

`PASS` means **that specific local check passed**, not that CCDC scoring or live detection was proved. `FAIL` means review the printed problem. `SKIP` means a step was not requested or could not be checked in read-only mode. The final result is `FAIL` when the verification detects failures; services not yet listening (including port 9997 before restart) can fail verification.

Run the report again later without making configuration changes:

```bash
sudo bash setup-splunk.sh --verify
```

This mode prints `CCDC Splunk Server Read-Only Verification` instead of the setup-complete heading.

## Audit administrators without changing anything

```bash
sudo bash setup-splunk.sh --audit-admins
```

Inspect the actual sudo privileges for a particular account:

```bash
sudo -l -U sysadmin
sudo passwd -S root
sudo chage -l sysadmin
```

**To expire an account deliberately:** Run the main script from NETLAB console and opt into the administrator audit/expiry prompt. The script refuses to expire `root`, the current `sudo`/console user, active terminal users, common service accounts, the running Splunk service account, or non-local users. It also skips the expiry step if the root account has no usable password or you cannot affirm that root console login was actually tested.

A manually expired account can be restored through an authorized root console session with `sudo usermod --expiredate "" USERNAME`. Account expiry prevents normal *new* logins; it does not terminate an existing session or remove already-running processes. Avoid expiring any account required by CCDC scoring or your team's recovery plan.

## Verify without making any changes

```bash
sudo bash setup-splunk.sh --verify
```

Useful manual commands:

```bash
sudo /opt/splunk/bin/splunk status
sudo bash setup-splunk.sh --audit-admins
sudo passwd -S root
sudo /opt/splunk/bin/splunk cmd btool inputs list | grep -A 3 'splunktcp://9997'
sudo /opt/splunk/bin/splunk cmd btool authentication list splunk_auth
sudo ufw status verbose
sudo ss -lntp | grep -E ':(22|8000|8089|9997)\b'
sudo sshd -T -C user=sysadmin,host=localhost,addr=127.0.0.1 | grep -Ei 'denyusers|permitrootlogin'
sudo systemctl is-active clamav-daemon clamav-clamonacc clamav-freshclam suricata
sudo systemctl cat suricata | grep -E 'ExecStart|af-packet'
sudo tail -n 10 /var/log/clamav/clamonacc.log
sudo tail -n 10 /var/log/suricata/eve.json
df -h /opt/splunk
```

If you elected not to restart Splunk, the newly written `inputs.conf` and log-monitor settings may not be active yet. `btool` shows effective **on-disk** settings, not whether a forwarder has actually delivered data.

## Verify event collection in Splunk

General host coverage:

```spl
index=* earliest=-15m
| stats count by host, source, sourcetype
| sort -count
```

Suricata JSON coverage:

```spl
index=* sourcetype="suricata:eve" earliest=-30m
| spath
| stats count by event_type
| sort -count
```

Suricata detections:

```spl
index=* sourcetype="suricata:eve" earliest=-30m
| spath
| search event_type=alert
| table _time host src_ip dest_ip dest_port alert.signature alert.severity
| sort -_time
```

ClamAV on-access results:

```spl
index=* sourcetype="clamav:clamonacc" earliest=-30m
| table _time host _raw
| sort -_time
```

An empty search does **not** prove there are no threats. Check whether a log file exists, whether the correct service is running, whether Splunk can read the file, whether the index is enabled, and whether the relevant activity occurred.

## Troubleshooting

| Problem | What to check |
|---|---|
| `STOP: ... SSH session` | Use the actual NETLAB VM console. Running under `sudo` from SSH is still considered SSH. |
| Root password rotation fails | Run from a terminal with a working TTY and root privileges; verify with `passwd -S root`. No password is stored by the script. |
| Account cannot be expired | The script intentionally protects current, system, service and remote accounts, and requires a usable, **tested** root console recovery path. |
| Privileged account unexpectedly missing | Review exact `sudo -l -U USERNAME`, `/etc/sudoers`, `/etc/sudoers.d`, UID 0, directory-backed identities, and polkit. A group name alone does not prove effective sudo permission. |
| Splunk missing | Check `/opt/splunk/bin/splunk` and `SPLUNK_HOME`. |
| `sshd` restriction validation fails | Review `/etc/ssh/sshd_config` include lines and `sshd -t`. Script restores the prior drop-in if validation fails. |
| SSH sudo/PAM verification fails | Check `/etc/pam.d/sudo`, `/etc/pam.d/su`, and `/usr/local/sbin/ccdc-deny-ssh-elevation`. Review PAM backups under `/root/ccdc-ssh-pam-backup-*`; test local console recovery before making repairs. |
| UFW verification fails | Check `sudo ufw status verbose`. UFW is optional, but its final verification expects the intended policy and rules; declining UFW may produce `FAIL` if it is absent or different. |
| ClamAV daemon fails to start | Ensure the signature database is downloaded, check `journalctl -u clamav-daemon`, and inspect `clamd.conf` and backups. |
| ClamAV on-access watcher inactive | Check `journalctl -u clamav-clamonacc` and kernel fanotify support; examine `/var/log/clamav/clamonacc.log`. |
| Suricata fails configuration test | Check `/var/log/suricata/ccdc-config-test.log`, installed rules, and the selected interface. |
| Suricata alerts absent | Ensure an ET Open or other appropriate ruleset is present; check passive traffic visibility and `eve.json`. |
| Suricata/ClamAV Splunk input empty | Verify the `ccdc_endpoint_ids_inputs` app, the Splunk OS user's ACL/read permissions, and a safe Splunk restart. Existing older `ccdc_suricata_inputs` definitions should be checked for duplication. |
| TCP 9997 not listening | Check effective receiver settings and restart Splunk when safe. |
| TCP 8089 unavailable | Check Splunk and network access; management checks may require this port. |
| Slow Splunk server | Monitor RAM/CPU/disk and tune or disable optional ClamAV/Suricata services rather than risking scored services. |
| No Windows/AD logs | This script does not install Universal Forwarders or enable Windows audit policies. Verify those separately. |

## Competition cautions

- **Splunk Web/query and Splunk management connectivity are scored.** Do not block required access. This script **can reset and enable UFW** if explicitly authorized; test from another VM/scoring source afterward.
- Changing **Linux root** credentials does not rotate **Splunk Web admin** credentials. Review those accounts separately after an incident.
- Expiring administrator accounts may prevent console recovery, despite SSH still being denied; never expire all administrators or an account required by scoring or team operations.
- Keep ICMP connectivity and required scored services intact. UFW defaults ordinarily allow standard ICMP, but verify from the scoring system when possible.
- `DenyUsers root sysadmin` prevents new SSH authentication for those names. The additional PAM guard restricts common privilege-elevation operations from SSH sessions but does not guarantee that every non-PAM path is blocked. SSH remains available for other user identities; established sessions and Splunk Web accounts are separate.
- ClamAV is **notify-only**: it will detect and log but **will not automatically stop malware**. It is not a substitute for endpoint hardening.
- Suricata is **IDS**, not IPS. It doesn't drop packets, and it sees only traffic visible to the Splunk VM.
- Avoid automatic Debian upgrades and disruptive restarts during active scoring. Package installation and signatures still use resources and can fail when repositories are unreachable.
- Do not modify names, IPs, routing, or VLANs unless the competition rules/injects direct you to.
- The script has passed **Bash syntax checks** and static inspection, but **has not been tested end-to-end on the actual Debian 12 / Splunk 10.0.2 VM**. Verify services and score availability on a practice VM first.

## Next step: dashboards

After Splunk receiver and logging are verified, install the separate CCDC Defense Monitor dashboard app using your current `Dashboards/setup-dashboards-main.sh`. This server script **does not install dashboard XML files**. It creates only an invisible Splunk input app for Suricata/ClamAV log ingestion.
