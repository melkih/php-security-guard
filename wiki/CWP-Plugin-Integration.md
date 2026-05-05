# CWP Plugin Integration

The **PHP Security Guard** includes a management plugin specifically designed for **CentOS Web Panel (CWP)** administrators.

### Overview

The plugin provides a graphical user interface (GUI) inside the CWP administration panel, allowing you to manage whitelists without editing text files manually via SSH.

### Features

*   **Whitelist Management**: Add, remove, and list entries for Commands, Files, and Networks.
*   **Version Detection**: Automatically detects installed PHP versions and allows testing policies against them.
*   **Security Status**: Overview of current enforcement modes and logging status.

### Installation

The plugin is automatically installed if you use the `install.sh` script with CWP detected. To install manually:

1.  Copy the plugin files to the CWP 3rd party modules directory:
    ```bash
    cp cwp-plugin/module_security_guard.php /usr/local/cwpsrv/htdocs/resources/admin/modules/
    ```

2.  Register the module in the CWP 3rd party menu:
    Edit `/usr/local/cwpsrv/htdocs/resources/admin/include/3rdparty.php` and add:
    ```php
    <li><a href="index.php?module=module_security_guard"><span class="icon16 icomoon-icon-shield"></span>Security Guard</a></li>
    ```

### Usage

1.  Log in to your **CWP Admin Panel**.
2.  Navigate to **3rd Party Software** -> **Security Guard**.
3.  Use the tabs to navigate between **Commands**, **Files**, and **Network**.
4.  Adding a rule through the UI immediately updates the corresponding `.conf` file in `/etc/security_guard/`.

### Configuration Sync

The extension reloads the configuration from disk based on the `security_guard.config_reload_interval` INI setting (default is 60 seconds). Any changes made in the CWP UI will be active across the server within this timeframe.
