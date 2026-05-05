# Policy Syntax

The whitelist files (`.conf`) use a pipe-delimited format for easy parsing and management.

### Commands Whitelist
**File**: `allowed_commands.conf`

**Format**: `command|BINARY_PATH|TIMESTAMP|AUTHOR|COMMENT`

**Example**:
```text
command|/usr/bin/optipng|2026-05-04T14:30:00-03:00|admin|PNG optimization
command|/usr/bin/jpegtran|2026-05-04T14:31:00-03:00|admin|JPEG optimization
```
*Note: Only absolute paths are supported. Chained commands (e.g. using `;` or `|`) are natively blocked even if the primary binary is allowed.*

---

### Files Whitelist
**File**: `allowed_files.conf`

**Format**: `file|ABSOLUTE_PATH|TIMESTAMP|AUTHOR|COMMENT`

**Example**:
```text
file|/etc/ssl/certs/ca-bundle.crt|2026-05-04T14:42:00-03:00|admin|CA bundle
file|/home/user/public_html/uploads|2026-05-04T14:40:00-03:00|admin|WordPress uploads
```

---

### Network Whitelist
**File**: `allowed_network.conf`

**Formats**:
*   **Domain**: `domain|HOST|TIMESTAMP|AUTHOR|COMMENT`
*   **URL**: `url|FULL_URL|TIMESTAMP|AUTHOR|COMMENT`
*   **IP**: `ip|IP_ADDRESS|TIMESTAMP|AUTHOR|COMMENT`
*   **CIDR**: `cidr|NETWORK/MASK|TIMESTAMP|AUTHOR|COMMENT`

**Example**:
```text
domain|api.mercadopago.com|2026-05-04T15:00:00-03:00|admin|Payment gateway
domain|*.stripe.com|2026-05-04T15:02:00-03:00|admin|Stripe subdomains
ip|1.1.1.1|2026-05-04T15:04:00-03:00|admin|Cloudflare DNS
cidr|192.168.1.0/24|2026-05-04T15:05:00-03:00|admin|Internal range
```

### Validation Rules
1.  **Wildcards**: `*.example.com` is valid.
2.  **IP vs Host**: If a user calls `file_get_contents('http://1.1.1.1/')`, the extension checks the **IP** whitelist. If they call `http://google.com`, it checks the **Domain** whitelist.
3.  **SSRF Protection**: Explicit blocks on private networks take priority unless `explicit_allow_overrides_private_block` is enabled.
