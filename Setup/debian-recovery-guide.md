# CCDC Debian 12 / Splunk — guest-only backup and startup audit

This is for a competition VM where you can access **Debian via NETLAB console but cannot access Proxmox**. It does **not** interact with the hypervisor and does **not** restart any service.

## What is possible

- **`scan`**: read-only report of systemd services/timers, Splunk startup service, cron, Splunk scripted inputs, users, ports and patterns that deserve investigation.
- **`baseline`**: file hashes and metadata for likely startup/persistence paths. Capture it *before* red-team activity, store a copy off the VM.
- **`audit`**: compare these locations to the trusted baseline. Unexpected changes require investigation; matching hashes are not a clean bill of health.
- **`backup`**: compress the **root filesystem** into a GNU tar archive with ownership, permissions, ACLs, xattrs and a checksum.
- **`verify`**: check that the archive checksum matches and that its directory listing can be read.

**Not a VM snapshot:** the archive is not an automatically bootable disk image and cannot capture a consistent snapshot of a running Splunk index. The script deliberately excludes `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/mnt`, `/media`, and the archive's destination. It also uses `--one-file-system`, so separately mounted persistent `/boot`, `/var`, `/opt`, `/home`, etc. must be backed up separately. Examine `findmnt` output. A full OS recovery may require rescue access or help from the competition administrator.

**Not a malware guarantee:** a root-level attacker can modify services, manipulate the in-guest inspection tools, or hide files. A trusted off-machine baseline and clean restoration are substantially safer than relying on a scan of the compromised guest.

## Start of competition, BEFORE red-team activity

Run as root on Debian (using a copy of `ccdc-debian-backup-audit.sh` you inspected first):

```bash
# 1. Save a trusted inventory of startup-related files and configs
sudo bash ccdc-debian-backup-audit.sh baseline /var/backups/ccdc-guest/baseline

# 2. Run a read-only startup inspection
sudo bash ccdc-debian-backup-audit.sh scan /var/backups/ccdc-guest/initial-scan
```

Review the initial report. Do not assume the VM is clean just because you have a baseline; ideally review it against a trusted competition image/configuration before using it.

For a **fuller root-filesystem copy**, prefer a mounted, authorized storage destination that is *not on the same VM filesystem*:

```bash
sudo bash ccdc-debian-backup-audit.sh backup /mnt/approved-team-backup
```

`/mnt/approved-team-backup` is an **example**. It must be a real, already-mounted, writable storage destination. The script will refuse to make a whole-root backup on the same filesystem by default, because filling the Splunk disk could break scoring. If the only destination is local and your team accepts the risk *before scoring*, the explicit override is:

```bash
sudo CCDC_ALLOW_LOCAL_BACKUP=1 bash ccdc-debian-backup-audit.sh backup /var/backups/ccdc-guest
```

Immediately transfer the archive, matching `.sha256`, `.system-info.txt`, and baseline to a trusted off-VM location **using a competition-approved method**. These files contain sensitive configuration, credentials/password hashes, private keys, and audit information—store and transfer them securely. Confirm storage space first.

The backup may report failure because Splunk/log files changed while tar was reading them, or because the disk filled. A `.partial` file is **not a verified backup**. Avoid attempting a large backup during active scoring.

## Before restarting Splunk after suspicious activity

Run:

```bash
sudo bash ccdc-debian-backup-audit.sh audit \
  /var/backups/ccdc-guest/baseline \
  /var/backups/ccdc-guest/after-incident
```

Prioritize reviewing these files in the output directory:

- `changed-startup-services.txt.diff` — new or modified Splunk/systemd units and their launch commands
- `changed-file-hashes.diff` — modified files in `/etc`, systemd directories, Splunk app configs and script paths
- `splunk-scripted-inputs.txt` — configured Splunk scripted inputs and installed app scripts
- `review-possible-destructive-commands.txt` — dangerous command patterns that deserve manual review (many false positives possible)
- `cron-summary.txt` — scheduled tasks

For a manual **read-only** check of service execution settings:

```bash
systemctl list-unit-files | grep -i splunk
# Substitute the actual service name from the output:
sudo systemctl cat Splunkd.service
sudo systemctl show Splunkd.service -p ExecStart -p ExecStartPre -p ExecStartPost -p ExecStop
```

A malicious scripted input could also execute when Splunk starts, even if the systemd unit is unchanged. Splunk documents `[script://...]` inputs in `inputs.conf` that execute commands on a schedule. Review any unexpected scripts before restarting. No scan can conclusively prove the absence of a hidden script.

## If the server is already compromised

1. **Do not blindly restart Splunk.** First preserve logs/evidence and inspect the current startup definitions from NETLAB console if accessible.
2. Compare to the trusted baseline held **outside** the VM; an attacker could alter an on-VM baseline.
3. If the root filesystem is still accessible, prefer **targeted recovery** of known-good configurations in coordination with the team, and verify scored services.
4. If the VM won't boot, an in-guest restore script cannot run. Use whatever VM reset/scrub option the rules permit, or ask your NETLAB administrator about a rescue/restore procedure. A local tar archive **does not** by itself restore the dead VM.
5. A full filesystem extraction should be performed only in an offline/rescue environment by someone with the necessary access. Do **not** extract this archive over `/` on a running, potentially compromised VM.

### A useful decision rule

- **Suspect only Splunk accounts or dashboards changed:** restore verified Splunk settings/account records, then validate access and audit for other persistence.
- **Unknown new startup services/scripts, root compromise, or OS damage:** prefer a known-clean system state over trying to declare the compromised VM safe.
- **No trustworthy external restore or rescue access:** keep a baseline and independent copies of essential configuration so you can at least rebuild after an allowed VM scrub/reset.

## Sources

- [GNU tar options for ACLs/xattrs and filesystem selection](https://man7.org/linux/man-pages/man1/tar.1.html)
- [Splunk `inputs.conf` scripted-input specification](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/inputs.conf)
- [systemd `ExecStartPre`/`ExecStartPost` service configuration](https://www.freedesktop.org/software/systemd/man/devel/systemd.service.html)
