# CCDC Splunk Universal Forwarder Installation Guide

This guide explains how to install and configure the Splunk Universal Forwarder on Windows and Linux machines during CCDC.

The installation scripts configure each machine to forward logs to the central Splunk Enterprise server.

**Supported operating systems:**
- Windows Server 2019 / 2022
- Windows 11
- Debian / Ubuntu
- Rocky Linux / RHEL

**Splunk Universal Forwarder version:** `10.0.2`

> **Important:** These scripts are intended for fresh installations. They have not yet been fully verified on every competition VM. Test them in NETLAB+ before relying on them during a scored competition.

---

## 1. Before You Start

### Requirements

- Access to the machine you are configuring.
- Administrator privileges (Windows) or root/sudo privileges (Linux).
- The correct installation script.
- Network connectivity to the central Splunk server.
- The appropriate Linux installer package (`.deb` or `.rpm`) if installing on Linux.

### Central Splunk Server

| Setting | Value |
|---|---|
| Server | Debian Splunk Enterprise |
| IP address | `172.20.240.20` |
| Receiving port | `9997` |
| Splunk version | `10.0.2` |
| Forwarding protocol | TCP |

**Important:** The central Splunk server must have receiving enabled on TCP port `9997` before machines can forward logs to it.

On the central Splunk server, check the configured receiving ports:

```bash
sudo /opt/splunk/bin/splunk list listen
```

If receiving is not enabled, an authorized Splunk administrator can enable it:

```bash
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin
```

Enter the central Splunk administrator password if prompted.

This command is for the **central Splunk server**, not the Universal Forwarder machines.

Make sure host firewalls and network rules permit the required TCP traffic.

---

## 2. Download the Installers

The Linux and Windows installation scripts handle installers differently.

| Operating system | Installer | Download required beforehand? |
|---|---|---|
| Debian / Ubuntu | `.deb` | Yes |
| Rocky Linux / RHEL | `.rpm` | Yes |
| Windows Server / Windows 11 | `.msi` | No, script downloads automatically |

### Installer download links

**Windows 64-bit:**

https://download.splunk.com/products/universalforwarder/releases/10.0.2/windows/splunkforwarder-10.0.2-e2d18b4767e9-windows-x64.msi

**Debian / Ubuntu 64-bit:**

https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb

**Rocky Linux / RHEL 64-bit:**

https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm

If a direct link fails, find the appropriate installer on the [official Splunk Universal Forwarder download page](https://www.splunk.com/en_us/download/universal-forwarder.html).

Do not rename a downloaded HTML page or error response to `.deb`, `.rpm`, or `.msi`. Make sure the file is an actual installer.

### Recommended folder structure

```text
CCDC-Splunk/
│
├── Installers/
│   ├── splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb
│   └── splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm
│
└── Scripts/
    ├── install-splunk-uf.sh
    └── install-splunk-uf.ps1
```

The Windows installer does not need to be included because the PowerShell script downloads it automatically.

**Note:** You only need the Linux installer that matches the machine's operating system.

---

## 3. Linux Installation (`*nix`)

Use these instructions for Debian, Ubuntu, Rocky Linux, and RHEL.

### Step 1: Get the files onto the machine

Copy the `CCDC-Splunk` folder, or the required files from it, onto the Linux machine.

You need:

- `install-splunk-uf.sh`
- The appropriate `.deb` or `.rpm` installer package.

You can transfer the files using a supported shared folder, removable storage, or another method available in your competition environment.

### Step 2: Open a terminal

Open a terminal on the Linux machine.

Navigate to your `CCDC-Splunk` folder:

```bash
cd ~/CCDC-Splunk
```

This example assumes the folder is inside your home directory. Use the actual location if it differs.

Check that the files exist:

```bash
ls Scripts/
ls Installers/
```

You should see the installation script and the appropriate package.

### Step 3: Run the installation script

Choose the command for your operating system.

**Debian / Ubuntu:**

```bash
sudo bash Scripts/install-splunk-uf.sh Installers/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb
```

**Rocky Linux / RHEL:**

```bash
sudo bash Scripts/install-splunk-uf.sh Installers/splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm
```

Replace the installer filename if yours differs.

The script must run with root privileges because it installs software, creates a service account, and configures the Universal Forwarder.

You do not need to run `chmod +x` when executing the script with `bash`.

### Step 4: What the script does

The script automatically attempts to:

1. Check for root privileges.
2. Verify that the installer package exists.
3. Detect Debian/Ubuntu or Rocky/RHEL.
4. Check whether a Universal Forwarder installation already exists.
5. Create the `splunkfwd` Linux user and group.
6. Install the Universal Forwarder.
7. Assign ownership of the forwarder directory to `splunkfwd`.
8. Configure forwarding to `172.20.240.20:9997`.
9. Configure collection of supported Linux log files.
10. Start the Universal Forwarder.
11. Configure it to start automatically when the machine boots.
12. Check the forwarder and connection.

The script does not ask you to create a local Splunk admin password.

**Note:** First-time initialization and service startup must be tested on the actual competition Linux images. If the script fails, record the error instead of assuming installation completed.

### Step 5: Verify the service

Check whether the forwarder is running:

```bash
sudo systemctl status SplunkForwarder
```

The expected status is:

```text
Active: active (running)
```

If the service is not running, investigate the error.

View recent forwarder logs:

```bash
sudo tail -n 50 /opt/splunkforwarder/var/log/splunk/splunkd.log
```

### Step 6: Verify the forwarding configuration

Run:

```bash
sudo cat /opt/splunkforwarder/etc/system/local/outputs.conf
```

You should see:

```ini
[tcpout]
defaultGroup = ccdc_indexer

[tcpout:ccdc_indexer]
server = 172.20.240.20:9997
```

This confirms that the destination is configured correctly.

It does not guarantee that logs have been delivered successfully.

### Step 7: Verify log collection

Check the configured inputs:

```bash
sudo cat /opt/splunkforwarder/etc/system/local/inputs.conf
```

Depending on the operating system and installed services, the script may configure:

- `/var/log/syslog`
- `/var/log/messages`
- `/var/log/auth.log`
- `/var/log/secure`
- `/var/log/audit/audit.log`
- `/var/log/audit.log`
- `/var/log/cron`
- `/var/log/maillog`
- `/var/log/mail.log`
- Apache access and error logs.

Only log files present when the script runs are added.

**Important:** The `splunkfwd` user might not have permission to read protected logs, particularly authentication and audit logs.

If the forwarder is running but certain logs are missing in Splunk, check log file permissions and the forwarder's internal logs. Avoid making sensitive logs publicly readable.

---

## 4. Windows Installation

Use these instructions for:

- Windows Server 2019
- Windows Server 2022
- Windows 11

### Step 1: Get the script onto the Windows machine

Copy `install-splunk-uf.ps1` onto the Windows machine.

For example:

```text
C:\CCDC-Splunk\Scripts\install-splunk-uf.ps1
```

You do not need to download the Windows MSI beforehand.

The script automatically downloads Splunk Universal Forwarder 10.0.2 from the configured Splunk download URL.

**Important:** The machine must have network access to the download server.

### Step 2: Open PowerShell as Administrator

1. Open the Start menu.
2. Search for `PowerShell`.
3. Right-click **Windows PowerShell**.
4. Select **Run as administrator**.
5. Approve the administrator prompt.

Administrator privileges are required to install the forwarder and configure its service.

### Step 3: Navigate to the script folder

Run:

```powershell
cd C:\CCDC-Splunk
```

If the folder is stored somewhere else, navigate to its actual location.

### Step 4: Allow the script to run

If PowerShell prevents the script from running because of its execution policy, enter:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

Confirm if prompted.

This sets the execution policy for the current PowerShell session only.

Only use this for scripts your team has reviewed and trusts.

### Step 5: Run the installation script

```powershell
.\Scripts\install-splunk-uf.ps1
```

The script does not require command-line arguments or a separate local Splunk admin password.

### Step 6: What the script does

The script automatically attempts to:

1. Check for Windows administrator privileges.
2. Check whether the Universal Forwarder is already installed.
3. Download the Windows Universal Forwarder MSI.
4. Install Splunk Universal Forwarder 10.0.2.
5. Configure forwarding to `172.20.240.20:9997`.
6. Enable Security, System, and Application event log collection.
7. Configure the Windows service to start automatically.
8. Start the service if necessary.
9. Test TCP connectivity to the central Splunk server.
10. Display the service status.

The script configures the forwarder to run using the Windows Local System account.

It does not prompt for separate Splunk administrator credentials.

### Step 7: Verify the service

In PowerShell, run:

```powershell
Get-Service SplunkForwarder
```

Look for:

```text
Status   Name
------   ----
Running  SplunkForwarder
```

If the service is not running, check the installation output and Windows event logs.

### Step 8: Test connectivity

Run:

```powershell
Test-NetConnection 172.20.240.20 -Port 9997
```

Look for:

```text
TcpTestSucceeded : True
```

This confirms the Windows machine can establish a TCP connection to the central Splunk server.

It does not guarantee that events are being indexed.

If the test fails, check the network connection, firewall rules, and receiving port on the central server.

---

## 5. Verify Data in Splunk

This step is required for both Linux and Windows.

A successful installation does not necessarily mean logs are being collected or received.

### Step 1: Open Splunk

Open a browser and navigate to the central Splunk Enterprise web interface:

```text
http://172.20.240.20:8000
```

This assumes Splunk Web is enabled and using its default HTTP port. Use the configured URL or HTTPS address if your server differs.

Log in with the central Splunk server credentials.

### Step 2: Open Search & Reporting

Navigate to the Search & Reporting app.

### Step 3: Search for incoming logs

Run:

```spl
index=* earliest=-15m | stats count by host, sourcetype
```

This displays machines and log types that have sent events during the last 15 minutes.

### Step 4: Find your specific machine

Run:

```spl
index=* earliest=-15m host="MACHINE-NAME"
```

Replace `MACHINE-NAME` with the hostname of the machine you configured.

To find the hostname:

**Windows:**

```powershell
hostname
```

**Linux:**

```bash
hostname
```

If the hostname appears with recent events, the forwarder is successfully sending at least some data.

### Step 5: Check the log types

For Windows, look for event logs such as:

- Security
- System
- Application

For Linux, look for the available log files configured by the installation script.

If you only see some sources, investigate the missing inputs and their permissions.

---

## 6. Troubleshooting

| Problem | Possible cause / solution |
|---|---|
| Linux says the package cannot be found | Check the filename and path in `Installers/`. |
| Linux reports an unsupported operating system | The distribution is not handled by the current script. |
| Linux package installation fails | Check the error message and package dependencies. |
| Linux service fails to start | Check `systemctl status` and `splunkd.log`. |
| Linux logs are missing | Check file permissions for the `splunkfwd` user. |
| Windows PowerShell blocks the script | Check execution policy and whether you trust the script. |
| Windows download fails | Check internet access and the MSI download URL. |
| Windows installation fails | Check administrator privileges and the MSI exit code. |
| Forwarder already installed | The script intentionally stops to avoid overwriting an installation. |
| TCP port 9997 is unreachable | Check receiving settings, network connectivity, and firewall rules. |
| Service running but no logs in Splunk | Check forwarding, log inputs, permissions, and the central server. |

### Useful Linux commands

Check service:

```bash
sudo systemctl status SplunkForwarder
```

Restart service:

```bash
sudo systemctl restart SplunkForwarder
```

View recent forwarder logs:

```bash
sudo tail -n 50 /opt/splunkforwarder/var/log/splunk/splunkd.log
```

Check forwarding destination:

```bash
sudo cat /opt/splunkforwarder/etc/system/local/outputs.conf
```

Check configured log inputs:

```bash
sudo cat /opt/splunkforwarder/etc/system/local/inputs.conf
```

### Useful Windows commands

Check service:

```powershell
Get-Service SplunkForwarder
```

Restart service:

```powershell
Restart-Service SplunkForwarder
```

Test connectivity:

```powershell
Test-NetConnection 172.20.240.20 -Port 9997
```

View recent forwarder logs:

```powershell
Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" -Tail 50
```

---

## 7. Important Competition Notes

### Existing installations

These scripts are designed for fresh installations.

If a Universal Forwarder installation already exists, the scripts are configured to stop rather than overwrite it.

If an installation fails partway through, investigate the failure before rerunning the script.

### Do not install on the central Splunk server

The Debian Splunk Enterprise machine at `172.20.240.20` is the central receiver.

You generally do not need to install a separate Universal Forwarder on that machine.

Splunk Enterprise can collect its own local logs when configured to do so.

### Internet access

The Windows script downloads its installer automatically.

If internet access is unavailable in the competition environment, the Windows script must be modified to use a locally stored MSI.

The Linux script already uses a local `.deb` or `.rpm` package.

### Account permissions

The Linux forwarder runs as `splunkfwd`.

The Windows forwarder is configured to run as Local System.

These identities must have access to the logs they are configured to collect.

For competition testing, verify collection before making additional permission changes.

### Network configuration

All forwarders are configured to send logs to:

```text
172.20.240.20:9997
```

Do not change competition network addressing, firewall configuration, or required services without understanding the competition rules and dependencies.

---

## 8. Installation Checklist

Complete this checklist for each machine.

- [ ] Correct installation script selected.
- [ ] Linux installer downloaded and copied to the machine, if applicable.
- [ ] Script executed with administrator/root privileges.
- [ ] Installation completed without errors.
- [ ] Splunk Universal Forwarder service is running.
- [ ] Service is configured to start automatically.
- [ ] Forwarding destination is `172.20.240.20:9997`.
- [ ] TCP connectivity to the central server works.
- [ ] Machine appears in Splunk Search & Reporting.
- [ ] Expected log sources are being collected.
- [ ] Forwarder continues running after a reboot.

**Installation is only considered verified when the machine successfully sends the expected logs to the central Splunk server.**

---

## 9. Quick Command Reference

### Linux

**Debian / Ubuntu:**

```bash
sudo bash Scripts/install-splunk-uf.sh Installers/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb
```

**Rocky Linux / RHEL:**

```bash
sudo bash Scripts/install-splunk-uf.sh Installers/splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm
```

**Check service:**

```bash
sudo systemctl status SplunkForwarder
```

### Windows

**Run PowerShell as Administrator:**

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Scripts\install-splunk-uf.ps1
```

**Check service:**

```powershell
Get-Service SplunkForwarder
```

**Test connection:**

```powershell
Test-NetConnection 172.20.240.20 -Port 9997
```

### Central Splunk server

**Verify incoming data:**

```spl
index=* earliest=-15m | stats count by host, sourcetype
```

