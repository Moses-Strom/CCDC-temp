# CCDC Defense Monitor: readable GitHub package

An original CCDC-oriented Splunk Enterprise app containing **12 Simple XML dashboards** and **71 saved searches** (unscheduled reports). Adapted to the NETLAB+ competition topology. This is **not** the original CyberHawks YAML detection suite, and the searches have **not** been validated against live CCDC logs.

## Repo layout

- `install.sh` — copies the visible source app to an existing Splunk Enterprise installation; backs up the previous app on `--update`.
- `ccdc_defense/default/data/ui/views/` — **12 editable XML dashboards**, one per view.
- `ccdc_defense/default/data/ui/nav/default.xml` — dashboard menu.
- `ccdc_defense/default/savedsearches.conf` — **71 searches**, all with scheduling off.
- `ccdc_defense/default/app.conf` — app display name.

## Install on Debian Splunk VM (172.20.240.20)

Transfer the **whole folder** to the Debian VM by an approved means (public GitHub clone, an approved file transfer, etc.). From inside the folder:

```bash
sudo bash install.sh
```

To check files after installing:

```bash
bash install.sh --verify
```

To back up the installed copy and replace it with your current source files:

```bash
sudo bash install.sh --update
```

Restart Splunk **only when it's acceptable to interrupt scoring**, using the service manager already configured on that VM. Then open Splunk Web → **Apps → CCDC Defense Monitor**. Begin with **Log Coverage** to see which sources actually report data.

## Before relying on the dashboards

1. Configure Splunk Enterprise to receive forwarders on TCP 9997.
2. Confirm Windows Event Logs and Linux system/authentication logs reach the indexer.
3. Configure Palo Alto / VyOS syslog separately if those dashboards are required.
4. Add Sysmon and Windows audit policies, or SQL Server logging, only as necessary for the detections you intend to use.
5. Check the field names and indexes in the actual events; many searches currently use broad `index=*` and should be narrowed once the environment is known.
6. Do not enable scheduled searches in bulk; test them first and watch Splunk performance.

**The app installation is not proof of detection.** Empty panels can mean no matching events, missing inputs, field-name differences, permissions, or failed data ingestion.

## Limitations

- This installer doesn't configure system packages, Splunk admin, firewalls, 9997, log forwarding or audit policies.
- Some searches require data sources not present in the competition topology (such as Zeek or ADCS).
- `--verify` checks file counts, not Splunk Web rendering or SPL search correctness.
- Do not replace competition services or scoring configurations without verifying their requirements.

## Research / inspiration

- CyberHawks-IIT `splunk-detections` detection taxonomy
- BYU-CCDC `public-ccdc-resources/splunk` deployment ideas
- SpecterOps, *Spelunking through Splunk* (search optimization)
- Red Siege, *Threat Detection Made Simple: Splunk Attack Range Basics* (learning/testing approach)
