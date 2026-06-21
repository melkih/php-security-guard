# Forum Post Suggestion: CWP Community

**Title: [Security] Granular Control for PHP Functions - Protection against RCE and SPAM Botnets**

Hi everyone,

As many of you know, CWP (Control Web Panel) has been a target for automated botnets exploiting RCE (Remote Code Execution) vulnerabilities (such as CVE-2022-44877 and more recent variants like CVE-2025-48703). 

We've seen massive infections involving files like `defauit.php` and `nbpafebaef.jpg` which lead to mass-corruption of PHP files and server-wide SPAM issues.

### The Dilemma
Standard security advice is to add functions like `exec`, `shell_exec`, `system`, and `curl_exec` to the `disable_functions` list in `php.ini`. However, we all know that **disabling these functions globally often breaks legitimate plugins**, WordPress themes, and administrative scripts.

### The Solution: PHP Security Guard
I've been working on a native PHP extension called **PHP Security Guard** that offers a "middle ground". 

Instead of disabling these functions completely, this extension allows you to:
1.  **Whitelist specific binaries**: Allow `/usr/bin/optipng` but block everything else in `exec()`.
2.  **Filter Network Access**: Allow `curl_exec` only for specific domains (like payment gateways) while blocking unauthorized outbound connections.
3.  **Prevent Shell Injections**: Natively blocks shell operators like `;`, `&&`, `|`, and backticks inside command strings.
4.  **SSRF Protection**: Automatically blocks access to internal IPs (127.0.0.1) and Cloud Metadata endpoints from within PHP scripts.

### Monitored Functions
The extension currently intercepts:
`exec, passthru, shell_exec, system, proc_open, popen, curl_exec, curl_multi_exec, parse_ini_file, show_source`

### How to Help?
The project is in its **Alpha Version** and is open source. It includes a native C extension and a management module specifically for the CWP Admin Panel.

I’m looking for:
*   **Testers**: Run it on your staging servers and give feedback.
*   **Contributors**: Help refine the C engine or the CWP UI.
*   **Security Enthusiasts**: Help us identify more bypasses to keep the engine robust.

**Repository**: [https://github.com/melkih/php-security-guard](https://github.com/melkih/php-security-guard)

Let's work together to make CWP environments more resilient against automated attacks without breaking the web applications we host!

Best regards,
[Your Name]
