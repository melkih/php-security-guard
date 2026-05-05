--TEST--
security_guard: file group — allow and deny
--SKIPIF--
<?php
if (!extension_loaded('security_guard')) die('skip security_guard not loaded');
?>
--INI--
security_guard.enabled=1
security_guard.enforcement_mode=block
security_guard.allowed_files_file=/tmp/sg_test_files.conf
security_guard.log_denied=0
security_guard.log_allowed=0
security_guard.emit_php_warning=0
--FILE--
<?php
/**
 * File tests for security_guard.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */

// Setup allowed directory
@mkdir('/tmp/sg_uploads', 0755, true);
file_put_contents('/tmp/sg_uploads/test.txt', 'hello');

file_put_contents('/tmp/sg_test_files.conf',
    "file|/tmp/sg_uploads|2026-01-01T00:00:00-03:00|test|Uploads dir\n"
);

// Allow: path inside whitelisted directory
$r = @file_get_contents('/tmp/sg_uploads/test.txt');
var_dump($r === 'hello');

// Deny: /etc/passwd
$r2 = @file_get_contents('/etc/passwd');
var_dump($r2 === false);

// Deny: path traversal via relative path
$r3 = @file_get_contents('../../etc/passwd');
var_dump($r3 === false);

// Deny: path outside whitelisted dir
$r4 = @file_get_contents('/tmp/other.txt');
var_dump($r4 === false);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
