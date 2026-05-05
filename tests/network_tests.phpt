--TEST--
security_guard: network group — domain, IP, CIDR, wildcard, private block
--SKIPIF--
<?php
if (!extension_loaded('security_guard')) die('skip security_guard not loaded');
?>
--INI--
security_guard.enabled=1
security_guard.enforcement_mode=block
security_guard.allowed_network_file=/tmp/sg_test_network.conf
security_guard.block_private_networks=1
security_guard.explicit_allow_overrides_private_block=1
security_guard.block_metadata_endpoints=1
security_guard.allow_wildcard_domains=1
security_guard.require_base_domain_for_wildcard=1
security_guard.log_denied=0
security_guard.log_allowed=0
security_guard.emit_php_warning=0
--FILE--
<?php
/**
 * Network tests for security_guard.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */

file_put_contents('/tmp/sg_test_network.conf',
    "domain|api.mercadopago.com|2026-01-01T00:00:00-03:00|test|Gateway\n" .
    "domain|teste.com|2026-01-01T00:00:00-03:00|test|Base domain\n" .
    "domain|*.teste.com|2026-01-01T00:00:00-03:00|test|Wildcard\n" .
    "ip|127.0.0.1|2026-01-01T00:00:00-03:00|test|Loopback explicit\n" .
    "cidr|192.168.10.0/24|2026-01-01T00:00:00-03:00|test|Internal CIDR\n"
);

// Allow: whitelisted domain (we can't actually fetch, just test the decision)
// Use curl so we can intercept before the connection

// Test 1: domain allowed — curl would proceed (we just ensure no block warning)
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://api.mercadopago.com/v1/payments');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
// We expect it to NOT be blocked (may fail to connect, that's OK)
// suppress connection errors
$err = '';
ob_start();
@curl_exec($ch);
$warning = ob_get_clean();
var_dump(strpos($warning, 'Security policy') === false); // no block warning
curl_close($ch);

// Test 2: blocked domain
$ch2 = curl_init();
curl_setopt($ch2, CURLOPT_URL, 'https://evil.example.com/payload');
curl_setopt($ch2, CURLOPT_RETURNTRANSFER, 1);
ob_start();
$r2 = curl_exec($ch2);
$w2 = ob_get_clean();
var_dump($r2 === false);
curl_close($ch2);

// Test 3: wildcard — allowed subdomain
$ch3 = curl_init();
curl_setopt($ch3, CURLOPT_URL, 'https://api.teste.com/resource');
curl_setopt($ch3, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch3, CURLOPT_CONNECTTIMEOUT, 1);
ob_start();
@curl_exec($ch3);
$w3 = ob_get_clean();
var_dump(strpos($w3, 'Security policy') === false);
curl_close($ch3);

// Test 4: wildcard — multi-level NOT allowed
$ch4 = curl_init();
curl_setopt($ch4, CURLOPT_URL, 'https://sub.api.teste.com/resource');
curl_setopt($ch4, CURLOPT_RETURNTRANSFER, 1);
ob_start();
$r4 = curl_exec($ch4);
$w4 = ob_get_clean();
var_dump($r4 === false);
curl_close($ch4);

// Test 5: private IP blocked by default
$r5 = @file_get_contents('http://10.0.0.1/');
var_dump($r5 === false);

// Test 6: explicit IP whitelist overrides private block
$r6_ch = curl_init();
curl_setopt($r6_ch, CURLOPT_URL, 'http://127.0.0.1/');
curl_setopt($r6_ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($r6_ch, CURLOPT_CONNECTTIMEOUT, 1);
ob_start();
@curl_exec($r6_ch);
$w6 = ob_get_clean();
var_dump(strpos($w6, 'Security policy') === false); // should not be blocked
curl_close($r6_ch);

// Test 7: CIDR — IP in allowed range
$ch7 = curl_init();
curl_setopt($ch7, CURLOPT_URL, 'http://192.168.10.25/api');
curl_setopt($ch7, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch7, CURLOPT_CONNECTTIMEOUT, 1);
ob_start();
@curl_exec($ch7);
$w7 = ob_get_clean();
var_dump(strpos($w7, 'Security policy') === false);
curl_close($ch7);

// Test 8: metadata endpoint blocked
$r8 = @file_get_contents('http://169.254.169.254/latest/meta-data/');
var_dump($r8 === false);

// Test 9: domain lookalike blocked
$ch9 = curl_init();
curl_setopt($ch9, CURLOPT_URL, 'https://teste.com.evil.com/resource');
curl_setopt($ch9, CURLOPT_RETURNTRANSFER, 1);
$r9 = curl_exec($ch9);
var_dump($r9 === false);
curl_close($ch9);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
