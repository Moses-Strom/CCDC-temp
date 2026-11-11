
#!/usr/bin/env bash
# CCDC Sudo/Admin Audit Testing
# Debian 12 - LAB USE ONLY

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo or as root."
    exit 1
fi

# Check dependencies
for cmd in useradd usermod visudo; do
    command -v "$cmd" >/dev/null || {
        echo "Missing required command: $cmd"
        exit 1
    }
done

getent group sudo >/dev/null || {
    echo "Missing sudo group."
    exit 1
}

USERS=(
    ccdc_admin_1
    ccdc_admin_2
    ccdc_limited_1
    ccdc_limited_2
    ccdc_normal_1
    ccdc_normal_2
)

# Do not modify existing accounts
for user in "${USERS[@]}"; do
    if id "$user" &>/dev/null; then
        echo "Account already exists: $user"
        echo "Aborting to avoid changing existing users."
        exit 1
    fi
done

# Create all six users
for user in "${USERS[@]}"; do
    useradd -m -s /bin/bash "$user"
    echo "Created: $user"
done

# Full sudo administrators
usermod -aG sudo ccdc_admin_1
usermod -aG sudo ccdc_admin_2

# Limited sudo users
# Only allowed to run id and whoami as root
SUDOERS_FILE="/etc/sudoers.d/ccdc-limited-test"

cat > "$SUDOERS_FILE" <<'EOF'
ccdc_limited_1 ALL=(root) NOPASSWD: /usr/bin/id, /usr/bin/whoami
ccdc_limited_2 ALL=(root) NOPASSWD: /usr/bin/id, /usr/bin/whoami
EOF

chmod 0440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE"

# Ordinary users receive no sudo permissions

echo
echo "=== Accounts Created ==="
for user in "${USERS[@]}"; do
    id "$user"
done

echo
echo "Test accounts created successfully."
echo "Passwords are locked by default."
echo "Use sudo passwd <username> if login is needed."
