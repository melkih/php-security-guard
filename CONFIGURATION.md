# PHP Security Guard Configuration

This document lists all the INI directives available for PHP Security Guard. These directives should be added to your `php.ini` file or a file inside your `php.d` or `conf.d` directory.

### Core Settings

* **`security_guard.enabled`** (boolean, default: `0`)
  Master switch to enable or disable the extension globally. If set to `0`, the extension loads but does nothing.

* **`security_guard.enforcement_mode`** (string, default: `monitor`)
  Defines the primary behavior of the security engine.
  * **Options:**
    * `off`: The extension will not intercept, log, or block any calls.
    * `monitor`: (Recommended for initial setup) Intercepts calls, evaluates them against whitelists, and writes logs, but **never** blocks the execution.
    * `block`: Intercepts calls and immediately halts execution if a violation occurs (returning `false` or throwing a PHP warning depending on settings).

### Whitelist Configuration Files

* **`security_guard.allowed_commands_file`** (string)
  Absolute path to the configuration file containing allowed OS command binaries.
  * *Example:* `/etc/security_guard/allowed_commands.conf`

* **`security_guard.allowed_files_file`** (string)
  Absolute path to the configuration file containing allowed absolute file and directory paths.
  * *Example:* `/etc/security_guard/allowed_files.conf`

* **`security_guard.allowed_network_file`** (string)
  Absolute path to the configuration file containing allowed network destinations (domains, URLs, IPs, CIDRs).
  * *Example:* `/etc/security_guard/allowed_network.conf`

### Logging

* **`security_guard.log_allowed`** (boolean, default: `0`)
  If enabled (`1`), operations that are authorized by the whitelists will also be logged. Warning: This can generate massive log files on busy servers.

* **`security_guard.log_denied`** (boolean, default: `1`)
  If enabled (`1`), operations that violate the whitelists will be logged.

* **`security_guard.log_format`** (string, default: `jsonl`)
  The format used for writing audit logs.
  * **Options:** `jsonl` (JSON Lines - recommended), `text` (human-readable plain text).

* **`security_guard.log_path`** (string, default: `/var/log/security_guard/audit.log`)
  Absolute path to the directory or file where logs will be written.

* **`security_guard.log_scope`** (string, default: `global`)
  Determines how log files are split.
  * **Options:**
    * `global`: All logs are written to a single file.
    * `per_user`: Logs are split into files named by the executing Linux/PHP user (e.g., `user1_audit.log`).

### Network & Wildcard Rules

* **`security_guard.allow_wildcard_domains`** (boolean, default: `1`)
  Enables the use of `*.domain.com` in the network whitelist to allow all subdomains.

* **`security_guard.require_base_domain_for_wildcard`** (boolean, default: `1`)
  If enabled (`1`), a wildcard rule (`*.example.com`) will only be considered valid if the base domain (`example.com`) is also explicitly present in the whitelist.

* **`security_guard.block_private_networks`** (boolean, default: `1`)
  If enabled (`1`), automatically blocks all outgoing requests to private internal IP spaces (like `10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.0/8`) to prevent SSRF attacks.

* **`security_guard.explicit_allow_overrides_private_block`** (boolean, default: `1`)
  If enabled (`1`), an explicit whitelist entry for a local IP (e.g., `ip|127.0.0.1`) will override the `block_private_networks` protection for that specific target.

* **`security_guard.block_metadata_endpoints`** (boolean, default: `1`)
  If enabled (`1`), automatically blocks requests to known cloud metadata IP addresses (e.g., AWS/GCP `169.254.169.254`) preventing SSRF cloud credential theft.

### System & Performance

* **`security_guard.emit_php_warning`** (boolean, default: `1`)
  If enabled (`1`) and `enforcement_mode` is set to `block`, the extension will throw a standard PHP `E_WARNING` when a call is blocked, which will appear in the application's native PHP error logs.

* **`security_guard.config_reload_interval`** (integer, default: `60`)
  The time in seconds that the extension caches the whitelist files in persistent memory before checking the disk for modifications. Lower values mean faster updates but slightly more disk I/O. Set to `0` to reload on every request (not recommended for production).
