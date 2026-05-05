# Installation Guide

This page describes how to compile and install PHP Security Guard on a Linux server.

### Prerequisites

*   **PHP Development Headers**: `php-devel` (on RHEL/CentOS) or `php-dev` (on Debian/Ubuntu).
*   **Compilation Tools**: `gcc`, `make`, `autoconf`.
*   **Git**: To clone the repository.

### Compilation from Source

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/melkih/php-security-guard.git
    cd php-security-guard
    ```

2.  **Prepare the build environment**:
    Identify the `phpize` binary for your target PHP version.
    ```bash
    /usr/local/bin/phpize
    ```

3.  **Configure**:
    Point to the correct `php-config` path.
    ```bash
    ./configure --with-php-config=/usr/local/bin/php-config
    ```

4.  **Build and Install**:
    ```bash
    make
    make install
    ```

### Post-Installation

After running `make install`, the `security_guard.so` file will be moved to your PHP extensions directory.

1.  **Create configuration directories**:
    ```bash
    mkdir -p /etc/security_guard
    mkdir -p /var/log/security_guard
    chown -R root:root /etc/security_guard
    chmod 755 /etc/security_guard
    ```

2.  **Enable the extension**:
    Add the configuration to your `php.ini` or create a new `.ini` file in the scan directory (e.g., `/usr/local/php/php.d/security_guard.ini`).

    ```ini
    extension=security_guard.so
    security_guard.enabled=1
    security_guard.enforcement_mode=monitor
    ```

3.  **Restart PHP-FPM**:
    ```bash
    systemctl restart php-fpm
    ```

4.  **Verify**:
    ```bash
    php -m | grep security_guard
    ```
