# Core Configuration

The behavior of PHP Security Guard is controlled via standard PHP INI directives.

### Enforcement Settings

| Directive | Default | Description |
|-----------|---------|-------------|
| `security_guard.enabled` | `1` | Globally enables or disables the extension logic. |
| `security_guard.enforcement_mode` | `off` | **off**: No checks performed.<br>**monitor**: Violations are logged but allowed.<br>**block**: Violations are logged and blocked. |

### Path Settings

| Directive | Default Value | Description |
|-----------|---------------|-------------|
| `security_guard.allowed_commands_file` | `/etc/security_guard/allowed_commands.conf` | Path to the command whitelist. |
| `security_guard.allowed_files_file` | `/etc/security_guard/allowed_files.conf` | Path to the file access whitelist. |
| `security_guard.allowed_network_file` | `/etc/security_guard/allowed_network.conf` | Path to the network whitelist. |

### Logging Settings

| Directive | Default | Description |
|-----------|---------|-------------|
| `security_guard.log_path` | `/var/log/security_guard` | Directory where JSONL logs will be written. |
| `security_guard.log_scope` | `per_user` | **global**: One log file for all.<br>**per_user**: Logs separated by UID (e.g. `audit_1005.log`). |
| `security_guard.log_allowed` | `0` | Log successfully whitelisted operations (high volume). |
| `security_guard.log_denied` | `1` | Log all policy violations and blocks. |

### Network Hardening

| Directive | Default | Description |
|-----------|---------|-------------|
| `security_guard.block_private_networks` | `1` | Blocks access to RFC1918 IPs (10.x, 192.168.x, 172.16.x) and 127.0.0.1. |
| `security_guard.block_metadata_endpoints` | `1` | Blocks access to Cloud Metadata (169.254.169.254). |
| `security_guard.allow_wildcard_domains` | `1` | Support for `*.example.com` in whitelist. |

### Feedback

| Directive | Default | Description |
|-----------|---------|-------------|
| `security_guard.emit_php_warning` | `1` | Emits a PHP Warning when a function is blocked. |
| `security_guard.block_message` | "Security policy blocked this operation" | Custom message shown in PHP warnings. |
