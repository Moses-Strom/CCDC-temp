# CCDC Splunk Resources

Scripts and monitoring dashboards designed for the Collegiate Cyber Defense Competition (CCDC).

## Splunk Version
- **Splunk Enterprise:** 10.0.2
- **Splunk Universal Forwarder:** 10.0.2
- **Splunk Server OS:** Debian 12

## Repository Contents

### 1. Splunk Server Setup
- `setup-splunk-server.sh` — Configures Splunk Enterprise and enables log receiving.

### 2. Universal Forwarders
- `install-splunk-uf.sh` — Linux forwarder installation.
- `install-splunk-uf.ps1` — Windows forwarder installation.

### 3. Security Dashboards
- `setup-dashboards-main.sh` — Main monitoring package with 12 dashboards, 71 saved searches, and 5 scheduled security alerts.
- `setup-dashboards-backup.sh` — Lightweight backup with 4 dashboards and 33 monitoring panels.

## Purpose
Centralize security logs, monitor authentication attempts, detect suspicious activity, track system changes, and assist with incident response during CCDC.

## Notes
- Scripts are intended for authorized CCDC environments.
- Review configurations before execution.
- Dashboard functionality depends on available log sources.
- Verify network connectivity and Splunk log ingestion after installation.

**Repository:** https://github.com/Moses-Strom/CCDC-temp
