#!/bin/bash
# install.sh — build and install security_guard for PHP 8.3

set -euo pipefail

PHP_BIN="${PHP_BIN:-php}"
PHPIZE="${PHPIZE:-phpize}"
PHPCONFIG="${PHPCONFIG:-php-config}"
INI_DIR="${INI_DIR:-/etc/php.d}"
CONF_DIR="${CONF_DIR:-/etc/security_guard}"
LOG_DIR="${LOG_DIR:-/var/log/security_guard}"

echo "==> Building security_guard..."
$PHPIZE
./configure --enable-security-guard --with-php-config="$PHPCONFIG"
make -j"$(nproc)"
make install

echo "==> Creating config directories..."
install -d -m 750 -o root -g root "$CONF_DIR"
install -d -m 750 -o root -g root "$LOG_DIR"
install -d -m 750 -o root -g root "$LOG_DIR/users"

echo "==> Installing sample config files..."
for f in allowed_commands.conf allowed_files.conf allowed_network.conf; do
    dest="$CONF_DIR/$f"
    if [ ! -f "$dest" ]; then
        install -m 640 -o root -g root "etc/$f" "$dest"
    else
        echo "    $dest already exists, skipping"
    fi
done

echo "==> Installing php.ini snippet..."
install -m 640 -o root -g root php_security_guard.ini "$INI_DIR/security_guard.ini"

echo ""
echo "Done. Restart PHP-FPM to activate:"
echo "  systemctl restart php-fpm83"
echo ""
echo "Edit $INI_DIR/security_guard.ini to change enforcement_mode from 'monitor' to 'block'."
