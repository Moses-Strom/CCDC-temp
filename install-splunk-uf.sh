
#!/bin/bash

# CCDC Splunk Universal Forwarder Installer
# Debian / Ubuntu / Rocky Linux
# Runs Splunk as splunkfwd

set -e

SPLUNK_HOME="/opt/splunkforwarder"
SPLUNK_SERVER="172.20.240.20"
SPLUNK_PORT="9997"
PACKAGE="$1"

echo "=========================================="
echo " CCDC Splunk Universal Forwarder Installer"
echo "=========================================="

# Require root
if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash install-splunk-uf.sh package"
    exit 1
fi

# Require installer package
if [[ -z "$PACKAGE" || ! -f "$PACKAGE" ]]; then
    echo "Usage: sudo bash install-splunk-uf.sh package.deb"
    echo "Or: sudo bash install-splunk-uf.sh package.rpm"
    exit 1
fi

# Prevent accidental reinstall
if [[ -d "$SPLUNK_HOME" ]]; then
    echo "A Splunk Forwarder installation already exists."
    echo "Stopping to avoid overwriting its configuration."
    exit 1
fi

# Detect package manager and validate package
if command -v apt-get >/dev/null 2>&1; then
    echo "[+] Debian/Ubuntu detected"

    if [[ "$PACKAGE" != *.deb ]]; then
        echo "Expected a .deb package"
        exit 1
    fi

    PACKAGE_TYPE="deb"

elif command -v dnf >/dev/null 2>&1; then
    echo "[+] Rocky/RHEL detected"

    if [[ "$PACKAGE" != *.rpm ]]; then
        echo "Expected an .rpm package"
        exit 1
    fi

    PACKAGE_TYPE="rpm"

else
    echo "Unsupported operating system"
    exit 1
fi

# Create service account
echo "[+] Creating Splunk service account..."

groupadd -f splunkfwd

id splunkfwd >/dev/null 2>&1 || \
    useradd -m -g splunkfwd splunkfwd

# Install Splunk
echo "[+] Installing Universal Forwarder..."

if [[ "$PACKAGE_TYPE" == "deb" ]]; then
    apt-get install -y "./$PACKAGE"
else
    dnf install -y "./$PACKAGE"
fi

# Set ownership
echo "[+] Setting directory ownership..."

chown -R splunkfwd:splunkfwd "$SPLUNK_HOME"

# Configure forwarding
echo "[+] Configuring forwarding destination..."

mkdir -p "$SPLUNK_HOME/etc/system/local"

cat > "$SPLUNK_HOME/etc/system/local/outputs.conf" <<EOF
[tcpout]
defaultGroup = ccdc_indexer

[tcpout:ccdc_indexer]
server = ${SPLUNK_SERVER}:${SPLUNK_PORT}
EOF

# Configure log collection
echo "[+] Configuring Linux logs..."

INPUTS="$SPLUNK_HOME/etc/system/local/inputs.conf"

touch "$INPUTS"

for LOG in \
    /var/log/syslog \
    /var/log/messages \
    /var/log/auth.log \
    /var/log/secure \
    /var/log/audit/audit.log \
    /var/log/audit.log \
    /var/log/cron \
    /var/log/maillog \
    /var/log/mail.log \
    /var/log/apache2/access.log \
    /var/log/apache2/error.log \
    /var/log/httpd/access_log \
    /var/log/httpd/error_log
do
    if [[ -f "$LOG" ]]; then
        echo "[+] Monitoring $LOG"

        cat >> "$INPUTS" <<EOF

[monitor://${LOG}]
disabled = 0
index = main
EOF
    fi
done

# Set ownership after configuration
chown -R splunkfwd:splunkfwd "$SPLUNK_HOME"

# Start Splunk as dedicated user
echo "[+] Starting Splunk..."

runuser -u splunkfwd -- \
    "$SPLUNK_HOME/bin/splunk" start \
    --accept-license \
    --answer-yes \
    --no-prompt

# Enable boot startup
echo "[+] Enabling boot startup..."

"$SPLUNK_HOME/bin/splunk" enable boot-start \
    -user splunkfwd \
    -group splunkfwd \
    -systemd-managed 1

# Restart service
echo "[+] Restarting Splunk..."

systemctl restart SplunkForwarder

# Check service
echo "[+] Checking service status..."

systemctl status SplunkForwarder --no-pager

# Check forwarding configuration
echo "[+] Checking forwarding configuration..."

runuser -u splunkfwd -- \
    "$SPLUNK_HOME/bin/splunk" list forward-server

# Test network connectivity
echo "[+] Testing connection to central Splunk server..."

if command -v nc >/dev/null 2>&1; then
    nc -zvw5 "$SPLUNK_SERVER" "$SPLUNK_PORT"
else
    echo "Netcat not installed. Skipping connectivity test."
fi

echo ""
echo "=========================================="
echo " Installation completed!"
echo " Forwarding to: ${SPLUNK_SERVER}:${SPLUNK_PORT}"
echo "=========================================="
