
#!/bin/sh
#
# Alpine Linux 3.22.7
# Furniture Store Server Firewall
#
# Services:
# SSH       TCP 22       Public IPv4/IPv6
# Apache    TCP 80,443   Public IPv4/IPv6
# Samba     TCP 139,445  Internal IPv4 only
# Samba     UDP 137,138  Internal IPv4 only
# MariaDB   TCP 3306     No remote access
#
# Does not flush unrelated nftables tables.

set -eu

CONFIG="/etc/nftables.nft"
BACKUP="/root/firewall-backups"
TEMP="/root/nftables-new.nft"
TABLE="store_fw"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root."
    exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
    echo "ERROR: Install nftables first."
    exit 1
fi

if [ ! -x /etc/init.d/nftables ]; then
    echo "ERROR: Install nftables-openrc first."
    exit 1
fi

mkdir -p "$BACKUP"

# Back up existing configuration
if [ -f "$CONFIG" ]; then
    cp -a "$CONFIG" "$BACKUP/nftables.previous"
fi

# Back up the complete active ruleset for recovery
nft list ruleset > "$BACKUP/ruleset.previous"

# Preserve our previous table separately
HAD_OLD_TABLE=0

if nft list table inet "$TABLE" \
    > "$BACKUP/old-table.nft" 2>/dev/null; then
    HAD_OLD_TABLE=1
fi

# Generate the new rules
cat > "$TEMP" <<'NFT'
#!/usr/sbin/nft -f

table inet store_fw {

    chain input {
        type filter hook input priority 0;
        policy drop;

        # Loopback
        iifname "lo" accept

        # Existing and related connections
        ct state established,related accept

        # Invalid connections
        ct state invalid drop

        # IPv4 ICMP diagnostics
        ip protocol icmp icmp type {
            destination-unreachable,
            time-exceeded,
            parameter-problem,
            echo-request
        } accept

        # IPv6 ICMP and essential neighbor discovery
        icmpv6 type {
            destination-unreachable,
            packet-too-big,
            time-exceeded,
            parameter-problem,
            echo-request,
            nd-router-solicit,
            nd-router-advert,
            nd-neighbor-solicit,
            nd-neighbor-advert
        } accept

        # DHCPv4 client replies
        udp sport 67 udp dport 68 accept

        # DHCPv6 client replies
        ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept

        # SSH - required service, IPv4 and IPv6
        tcp dport 22 accept

        # Public Apache website
        tcp dport { 80, 443 } accept

        # Samba - internal IPv4 subnet only
        ip saddr 192.168.220.0/24 tcp dport { 139, 445 } accept
        ip saddr 192.168.220.0/24 udp dport { 137, 138 } accept

        # MariaDB intentionally not exposed remotely

        # Rate-limited firewall logging
        limit rate 5/second burst 10 packets \
            log prefix "NFT-DROP: " counter drop
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;
    }

    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}
NFT

echo "Validating new firewall configuration..."

# Remove only our own previous table.
# All unrelated nftables tables remain untouched.
if [ "$HAD_OLD_TABLE" -eq 1 ]; then
    nft delete table inet "$TABLE"
fi

# Validate the new rules
if ! nft -c -f "$TEMP"; then
    echo "ERROR: Validation failed."

    # Restore our previous table if one existed
    if [ "$HAD_OLD_TABLE" -eq 1 ]; then
        nft -f "$BACKUP/old-table.nft"
    fi

    exit 1
fi

# Apply new rules
if ! nft -f "$TEMP"; then
    echo "ERROR: Applying firewall failed."

    if [ "$HAD_OLD_TABLE" -eq 1 ]; then
        nft -f "$BACKUP/old-table.nft"
    fi

    exit 1
fi

# Install persistent configuration
cp "$TEMP" "$CONFIG"
chmod 600 "$CONFIG"

# Enable firewall at boot
rc-update add nftables default

echo ""
echo "======================================"
echo " FIREWALL CONFIGURATION APPLIED"
echo "======================================"
echo "SSH:       TCP 22 - IPv4 and IPv6"
echo "Apache:    TCP 80,443 - IPv4 and IPv6"
echo "Samba:     LAN IPv4 only"
echo "MariaDB:   Remote access blocked"
echo "IPv6:      Essential ICMPv6 enabled"
echo "Logging:   Rate-limited blocked traffic"
echo "Startup:   OpenRC enabled"
echo "======================================"

echo ""
echo "Active firewall rules:"
nft list table inet "$TABLE"

echo ""
echo "Backup location: $BACKUP"
