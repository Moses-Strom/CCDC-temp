# Splunk Universal Forwarder Installation Guide

This guide explains how to install and configure the Splunk Universal Forwarder on Linux (`*nix`) and Windows machines.

The scripts automatically configure the Universal Forwarder to send logs to the central Splunk server.

## 1. Before You Start

### What you need

- Access to the machine you want to install the forwarder on.
- Administrator/root privileges.
- The appropriate Universal Forwarder installer.
- The installation script for your operating system.
- Network connectivity to the central Splunk server.

### Central Splunk server information

| Setting | Value |
|---|---|
| Splunk server IP | `172.20.240.20` |
| Receiving port | `9997` |
| Universal Forwarder version | `10.0.2` |

**Important:** The Splunk server must have receiving enabled on TCP port `9997` before forwarders can send it data.

---

## 2. Download the Installers

Download the installer that matches the operating system of the machine you are configuring.

| Operating system | Installer |
|---|---|
| Debian / Ubuntu | `.deb` |
| Rocky Linux / RHEL | `.rpm` |
| Windows 64-bit | `.msi` |

Use the official Splunk download page:

[Windows](https://download.splunk.com/products/universalforwarder/releases/10.0.2/windows/splunkforwarder-10.0.2-e2d18b4767e9-windows-x64.msi)

[Debian / Ubuntu](https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb)

[Rocky Linux](https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9.x86_64.rpm?utm_source=chatgpt.com)

Select version **10.0.2** and the correct operating system.

### Recommended folder structure

Keep the installers and scripts organized in one folder:

```text
CCDC-Splunk/
│
├── Installers/
│   ├── splunkforwarder-linux-amd64.deb
│   ├── splunkforwarder-linux-x64.rpm
│   └── splunkforwarder-windows-x64.msi
│
└── Scripts/
    ├── install-splunk-uf.sh
    └── install-splunk-uf.ps1
```

The filenames above are examples. If your downloaded files have different names, use their actual filenames when following the instructions.

**You do not need all three installers on every machine.** Only use the installer that matches the operating system.

---

# 3. Linux Installation (`*nix`)

Use these instructions for Debian, Ubuntu, Rocky Linux, and other supported Linux distributions.

### Step 1: Get the files onto the Linux machine

Copy the following files onto the Linux machine:

- `install-splunk-uf.sh`
- The appropriate Linux installer (`.deb` or `.rpm`)

For example, place them in a folder called `CCDC-Splunk`.

You can use a USB drive, shared folder, or another method available in the competition environment.

### Step 2: Open a terminal

Open a terminal on the Linux machine.

Navigate to the folder containing the files.

For example:

```bash
cd ~/CCDC-Splunk
```

If you placed the files somewhere else, navigate to that location instead.

### Step 3: Make the script executable

Run:

```bash
chmod +x install-splunk-uf.sh
```

This gives the script permission to run.

### Step 4: Run the script

**For Debian / Ubuntu:**

```bash
sudo ./install-splunk-uf.sh ./splunkforwarder-linux-amd64.deb
```

**For Rocky Linux / RHEL:**

```bash
sudo ./install-splunk-uf.sh ./splunkforwarder-linux-x64.rpm
```

Replace the installer filename with the actual name of your downloaded package if it differs.

### Step 5: Follow the prompts

The script will handle the installation and configuration.

Depending on the script version, it will:

1. Check for the required privileges.
2. Create the `splunkfwd` user and group.
3. Install the Universal Forwarder.
4. Set the appropriate file ownership.
5. Configure the forwarding destination.
6. Configure selected log files for collection.
7. Start the Universal Forwarder.
8. Configure it to start automatically when the machine boots.

If the script asks for credentials, enter the credentials requested by the script.

### Step 6: Verify the installation

Check whether the Universal Forwarder service is running:

```bash
sudo systemctl status SplunkForwarder
```

You can also check the forwarding configuration:

```bash
sudo cat /opt/splunkforwarder/etc/system/local/outputs.conf
```

You should see the central Splunk server configured as the forwarding destination:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 172.20.240.20:9997
```

**If the service is running and the destination is correct, the Linux installation is configured.**

---

# 4. Windows Installation

Use these instructions for Windows Server and Windows workstation machines.

### Step 1: Get the files onto the Windows machine

Copy the following files onto the Windows machine:

- `install-splunk-uf.ps1`
- The Windows Universal Forwarder installer (`.msi`), if your script is configured to use a local installer.

Place them in a folder such as:

```text
C:\CCDC-Splunk\
```

**Note:** The previously provided PowerShell script downloads the Windows MSI automatically. If you are using that version, you do not need to manually place the MSI in the folder. The machine will need access to the download site. If internet access is unavailable, the script must be adjusted to use the locally downloaded MSI instead.

### Step 2: Open PowerShell as Administrator

1. Open the Windows Start menu.
2. Search for `PowerShell`.
3. Right-click Windows PowerShell.
4. Select **Run as administrator**.
5. Approve the User Account Control prompt.

Administrator privileges are required to install and configure the service.

### Step 3: Navigate to the script folder

Run:

```powershell
cd C:\CCDC-Splunk
```

If you saved the script somewhere else, navigate to that folder instead.

### Step 4: Allow the script to run

If PowerShell prevents the script from running, enter:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

If prompted, confirm the change.

This only changes the execution policy for the current PowerShell session.

### Step 5: Run the installation script

Run:

```powershell
.\install-splunk-uf.ps1
```

### Step 6: Follow the prompts

The script will:

1. Check that PowerShell is running as Administrator.
2. Download the Universal Forwarder installer if using the download-based version.
3. Prompt you for the Splunk administrator password.
4. Install the Universal Forwarder.
5. Configure it to forward data to `172.20.240.20:9997`.
6. Enable Windows Security, System, and Application event log collection.
7. Start the Universal Forwarder service.
8. Configure the service to start automatically.

Enter the password requested by the script when prompted.

**Important:** Use the Splunk credentials requested by the script, not the Windows administrator password.

### Step 7: Verify the installation

Check whether the Universal Forwarder service is running:

```powershell
Get-Service SplunkForwarder
```

You should see the service with a status of `Running`.

Next, test connectivity to the central Splunk server:

```powershell
Test-NetConnection 172.20.240.20 -Port 9997
```

Look for:

```text
TcpTestSucceeded : True
```

This confirms that the machine can establish a TCP connection to the Splunk receiving port.

---

# 5. Verify Data in Splunk

After installing the forwarder, log in to the central Splunk Enterprise web interface.

1. Open a browser.
2. Navigate to the Splunk web interface.
3. Log in.
4. Open **Search & Reporting**.
5. Run the following search:

```spl
index=* | stats count by host, source, sourcetype
```

This displays the hosts and log sources that have sent data to Splunk.

You can also search for a specific machine:

```spl
