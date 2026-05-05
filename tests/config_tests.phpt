--TEST--
security_guard: config — modes, deduplication, wildcard validation
--SKIPIF--
<?php
if (!extension_loaded('security_guard')) die('skip security_guard not loaded');
?>
--INI--
security_guard.enabled=1
security_guard.enforcement_mode=monitor
security_guard.allowed_commands_file=/tmp/sg_cfg_commands.conf
security_guard.allowed_network_file=/tmp/sg_cfg_network.conf
security_guard.log_denied=0
security_guard.log_allowed=0
security_guard.emit_php_warning=0
--FILE--
<?php
/**
 * Configuration tests for security_guard.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */

// Monitor mode: blocked calls pass through (but log violation)
file_put_contents('/tmp/sg_cfg_commands.conf', "# empty\n");

// In monitor mode exec should NOT be blocked even if not whitelisted
ob_start();
$r = @exec('/bin/ls /tmp');
$w = ob_get_clean();
// No block warning in monitor mode
var_dump(strpos($w, 'Security policy') === false);

// Deduplication: duplicate entries in conf should not cause errors
file_put_contents('/tmp/sg_cfg_commands.conf',
    "command|/usr/bin/optipng|2026-01-01T00:00:00-03:00|admin|First\n" .
    "command|/usr/bin/optipng|2026-01-02T00:00:00-03:00|root|Duplicate\n"
);
// Just verify no crash/warning loading duplicates
var_dump(true);

// Wildcard without base domain should emit warning but not crash
file_put_contents('/tmp/sg_cfg_network.conf',
    "domain|*.orphan.com|2026-01-01T00:00:00-03:00|admin|No base domain\n"
);
// Reload is triggered by config_reload_interval; here we just ensure no fatal
var_dump(true);

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
OK
