# Welcome to PHP Security Guard Wiki

**PHP Security Guard** is a native PHP extension designed to provide granular security controls in shared hosting environments (like CWP, cPanel, or DirectAdmin).

Unlike standard "disable_functions" which is all-or-nothing, this extension allows administrators to define **whitelists** for sensitive operations.

### Key Capabilities

*   **Command Interception**: Blocks unauthorized system binaries and prevents shell injection (nesting) natively.
*   **File Access Control**: Restricts sensitive file reading to explicit authorized paths.
*   **Network Guard**: Filters outbound connections by Domain, URL, IP, or CIDR.
*   **SSRF Protection**: Natively blocks access to private networks (127.0.0.1, 10.x, etc.) and Cloud Metadata endpoints (169.254.169.254).
*   **Dual-Layer Hooking**: Hooks into both `zend_execute_ex` (userland PHP) and `zend_execute_internal` (internal C functions) to ensure no function escapes the policy engine.

### Security Philosophy

1.  **Deny by Default**: If it's not in the whitelist, it's not allowed.
2.  **Granular Control**: Manage permissions per Linux user/PHP-FPM pool.
3.  **Low Overhead**: Written in highly optimized C to ensure minimal impact on page load times.
4.  **Auditability**: Every block or violation is logged in structured JSONL format for easy ingestion by SIEMs or log analyzers.

---

### Navigation

*   [[Installation Guide]]
*   [[Core Configuration]]
*   [[Policy Syntax]]
*   [[CWP Plugin Integration]]
*   [[Audit Logs and Monitoring]]
