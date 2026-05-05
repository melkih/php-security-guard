<?php
/**
 * PHP Security Guard - Test Script
 * 
 * Este script tenta executar todas as funções monitoradas pela extensão
 * para validar o funcionamento do bloqueio/monitoramento.
 */

// Define o alvo de comandos e arquivos (php.ini) e de rede (google.com)
$cmd_target = "cat /usr/local/php/php.ini";
$file_target = "/usr/local/php/php.ini";
$network_target_url = "https://google.com";
$network_target_domain = "google.com";

echo "========================================\n";
echo "PHP SECURITY GUARD - TESTE DE VIOLAÇÕES\n";
echo "========================================\n\n";

function run_test($name, $callback) {
    echo str_pad("Testando $name ", 40, ".");
    ob_start();
    try {
        $result = $callback();
        $output = ob_get_clean();
        
        // Se retornou falso, ou vazio e sem erros lançados, 
        // a extensão pode ter bloqueado e retornado false em modo 'block'
        if ($result === false) {
            echo " BLOQUEADO (retornou false)\n";
        } else {
            echo " PERMITIDO / EXECUTADO\n";
        }
    } catch (Throwable $e) {
        ob_get_clean();
        echo " ERRO/BLOQUEADO: " . $e->getMessage() . "\n";
    }
}

// ---------------------------------------------------------
// 1. EXECUÇÃO DE COMANDOS (OS COMMANDS)
// ---------------------------------------------------------
echo "\n--- 1. TESTES DE COMANDOS (Alvo: $cmd_target) ---\n";

run_test('exec()', function() use ($cmd_target) {
    return exec($cmd_target);
});

run_test('shell_exec()', function() use ($cmd_target) {
    return shell_exec($cmd_target);
});

run_test('system()', function() use ($cmd_target) {
    return system($cmd_target);
});

run_test('passthru()', function() use ($cmd_target) {
    passthru($cmd_target, $ret);
    return $ret === 0 ? true : false;
});

run_test('popen()', function() use ($cmd_target) {
    $fp = popen($cmd_target, "r");
    if ($fp) { pclose($fp); return true; }
    return false;
});

run_test('proc_open()', function() use ($cmd_target) {
    $desc = [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"],
        2 => ["pipe", "w"]
    ];
    $proc = proc_open($cmd_target, $desc, $pipes);
    if (is_resource($proc)) { proc_close($proc); return true; }
    return false;
});


// ---------------------------------------------------------
// 2. LEITURA DE ARQUIVOS (FILESYSTEM)
// ---------------------------------------------------------
echo "\n--- 2. TESTES DE ARQUIVOS (Alvo: $file_target) ---\n";

run_test('file_get_contents() (Arquivo)', function() use ($file_target) {
    return @file_get_contents($file_target);
});

run_test('fopen() (Arquivo)', function() use ($file_target) {
    $fp = @fopen($file_target, "r");
    if ($fp) { fclose($fp); return true; }
    return false;
});

run_test('readfile()', function() use ($file_target) {
    return @readfile($file_target);
});

run_test('show_source()', function() use ($file_target) {
    return @show_source($file_target, true);
});

run_test('highlight_file()', function() use ($file_target) {
    return @highlight_file($file_target, true);
});

run_test('parse_ini_file()', function() use ($file_target) {
    return @parse_ini_file($file_target);
});


// ---------------------------------------------------------
// 3. REQUISIÇÕES DE REDE (NETWORK)
// ---------------------------------------------------------
echo "\n--- 3. TESTES DE REDE (Alvo: $network_target_url) ---\n";

run_test('file_get_contents() (URL)', function() use ($network_target_url) {
    return @file_get_contents($network_target_url);
});

run_test('fopen() (URL)', function() use ($network_target_url) {
    $fp = @fopen($network_target_url, "r");
    if ($fp) { fclose($fp); return true; }
    return false;
});

run_test('fsockopen()', function() use ($network_target_domain) {
    $fp = @fsockopen($network_target_domain, 443, $errno, $errstr, 2);
    if ($fp) { fclose($fp); return true; }
    return false;
});

run_test('pfsockopen()', function() use ($network_target_domain) {
    $fp = @pfsockopen($network_target_domain, 443, $errno, $errstr, 2);
    if ($fp) { fclose($fp); return true; }
    return false;
});

run_test('stream_socket_client()', function() use ($network_target_domain) {
    $fp = @stream_socket_client("tcp://$network_target_domain:443", $errno, $errstr, 2);
    if ($fp) { fclose($fp); return true; }
    return false;
});

// CURL TESTES
run_test('curl_exec()', function() use ($network_target_url) {
    if (!extension_loaded('curl')) return "CURL_NÃO_INSTALADO";
    $ch = curl_init($network_target_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 2);
    $res = curl_exec($ch);
    curl_close($ch);
    return $res !== false ? true : false;
});

run_test('curl_multi_exec()', function() use ($network_target_url) {
    if (!extension_loaded('curl')) return "CURL_NÃO_INSTALADO";
    $ch = curl_init($network_target_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 2);
    
    $mh = curl_multi_init();
    curl_multi_add_handle($mh, $ch);
    
    $active = null;
    $status = curl_multi_exec($mh, $active);
    
    curl_multi_remove_handle($mh, $ch);
    curl_multi_close($mh);
    
    // cURL retorna CURLM_OK (0) se exec func com sucesso
    return $status === 0 ? true : false;
});

echo "\n========================================\n";
echo "Fim do teste. Verifique os logs em /var/log/security_guard/\n";
echo "========================================\n";
