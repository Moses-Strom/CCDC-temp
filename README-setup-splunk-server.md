# CCDC Splunk Enterprise Server Setup

Configures the Midwest Invitational CCDC **Debian 12 / Splunk Enterprise 10.0.2** server at **`172.20.240.20`**. The script is intended to prepare Splunk to receive Universal Forwarder logs while preserving the scored Splunk services.

This README accompanies **`setup-splunk-server.sh`**. Run it on the **Debian Splunk server**, not on the Windows/Linux endpoints.

## What the script does

1. Checks for root privileges, Splunk Enterprise, Python 3, and the `ss` utility.
2. Shows currently listening ports.
3. **Optionally** checks for Debian updates and installs available package upgrades.
4. **Optionally** changes the Splunk `admin` password, using a hidden-password prompt and Splunk's local management API (`127.0.0.1:8089`).
5. Backs up the existing `inputs.conf` and enables the Universal Forwarder receiver on **TCP `9997`**.
6. **Optionally** resets and configures UFW, allowing required incoming ports and denying other inbound traffic.
7. **Optionally** restarts Splunk if an expected systemd unit exists.
8. Checks Splunk status, receiver configuration, listening ports, and disk space.

**Important:** The receiver configuration is applied whenever you run the script. System upgrades, password change, UFW reset, and restart are separately prompted. The script does **not** install Splunk, deploy Universal Forwarders, or install dashboards.

## Required ports

| Port | Protocol | Purpose |
|---|---|---|
| `22` | TCP | SSH administration (only necessary if SSH is provided/required) |
| `8000` | TCP | Splunk Web |
| `8089` | TCP | Splunk management API; competition management checks |
| `9997` | TCP | Splunk-to-Splunk receiving from Universal Forwarders |

If you confirm the optional **UFW reset**, the script allows those incoming TCP ports, sets **deny incoming / allow outgoing**, and enables low-level firewall logging. **UFW saves its enabled rules across reboots; no separate `save` command is needed.**

Before resetting, check for any additional scored services or existing required rules. The script skips UFW reset when it detects an SSH session, so perform firewall work from the **NETLAB+ console**. Do not assume UFW manages any separate nftables or other firewall configuration.

## Requirements

- Access to the **Debian Splunk VM** (`172.20.240.20`) through NETLAB+.
- `sudo`/root privileges.
- Existing Splunk Enterprise installation at `/opt/splunk`.
- Python 3 and `ss` available.
- UFW installed **only if you want the firewall-reset feature**. If it is missing, the script skips that section; investigate before adding packages during scoring.
- The current Splunk `admin` password **if you choose to change it**.

The script does not store or print your passwords. **Never commit passwords or competition credentials to GitHub.**

## Run the script

1. Copy `setup-splunk-server.sh` onto the **Debian Splunk VM** using a competition-approved method.
2. From a terminal in the folder containing the script, run:

   ```bash
   sudo bash setup-splunk-server.sh
   ```

3. Follow the prompts in order:

   - **Check for Debian package updates?** Choose `y` only when you want to refresh the package list. If updates are available, a second prompt asks whether to install them. Full upgrades can disrupt scored services; check what's broken before upgrading.
   - **Change Splunk admin password?** Choose `y` to enter the current password, a new password, and confirmation. The username stays `admin`.
   - **Type RESET to replace UFW rules:** Only type `RESET` after reviewing the current listening services and confirming no additional inbound ports are required. Press Enter to keep the existing UFW rules.
   - **Restart Splunk now?** Choose `y` only when a brief interruption is acceptable. The script attempts a restart through a known `Splunkd.service` or `splunkd.service` unit; otherwise follow the VM's existing Splunk service procedure.

## Verify the receiver and scored services

Run these commands on the Debian Splunk server:

```bash
# Show Splunk process status
sudo /opt/splunk/bin/splunk status

# Show effective receiving configuration
sudo /opt/splunk/bin/splunk cmd btool inputs list | grep -A 3 'splunktcp://9997'

# Check listening ports
sudo ss -lntp | grep -E ':(22|8000|8089|9997)[[:space:]]'

# Check UFW state, if installed
sudo ufw status verbose

# Check disk space
df -h /opt/splunk
```

You should verify that TCP `9997` is actually listening **after Splunk restarts**. The script writes its configuration to:

```text
/opt/splunk/etc/system/local/inputs.conf
```

It creates a timestamped backup of that file before editing it. If the stanza already exists in that file, it enables it rather than blindly appending another one.

Next, open Splunk Web, typically at `http://172.20.240.20:8000` (or HTTPS if your server is configured for it), and test real log receipt:

```spl
index=* earliest=-15m
| stats count by host, sourcetype
```

**An open TCP port is not proof that forwarder logs are being indexed.**

## Troubleshooting

| Problem | What to check |
|---|---|
| `Splunk not found` | Check whether Splunk Enterprise is installed at `/opt/splunk`. |
| Password change fails | Confirm `admin` credentials and local Splunk Management availability on `127.0.0.1:8089`. The script stops on failure. |
| UFW not installed | The script skips firewall setup; don't install it automatically without checking the existing firewall setup. |
| Port `9997` not listening | Restart Splunk safely, then check the effective receiver config and Splunk logs. |
| Port `8089` unreachable | Check Splunk status and host/network firewall settings; this port is needed for management checks. |
| No events in Splunk | Check the forwarder installation, network connectivity to `172.20.240.20:9997`, log inputs, permissions, and index access. |
| Restart wasn't performed | Changes requiring a restart might not be active; use the installed service's existing management method when safe. |

## Competition cautions

- The competition scores Splunk Query and Splunk Management connectivity. **Keep required services available and working.**
- The competition requires maintaining ICMP connectivity. Verify it after any firewall changes; don't assume opening the TCP ports covers all scoring checks.
- Do not change system names, network interfaces, public/private IP addresses, or VLANs without an inject directing it.
- **Avoid automatic package upgrades and firewall resets during active scoring.** The script prompts for both, but you are responsible for deciding when changes are appropriate.
- The script has been reviewed for Bash syntax, **not tested end-to-end on your NETLAB+ VM**. Test it on a practice VM before relying on it during competition.

## Next step: install dashboards

After configuring Splunk and verifying incoming logs, run **`install-ccdc-dashboards.sh`** using its separate README. The dashboard installer does not change the server setup or forwarding configuration.
