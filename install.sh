#!/bin/bash
# install.sh — build and install security_guard
#
# Suporta CWP (múltiplas versões PHP), cPanel, DirectAdmin e instalação manual.
# Uso: bash install.sh [--php-version 83] [--mode monitor|block] [--uninstall]

set -euo pipefail

# ── Constantes ──────────────────────────────────────────────────────────────

CONF_DIR="/etc/security_guard"
LOG_DIR="/var/log/security_guard"
EXT_NAME="security_guard"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Cores para output
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}==>${NC} $*"; }
warn()    { echo -e "${YELLOW}[aviso]${NC} $*"; }
error()   { echo -e "${RED}[erro]${NC} $*" >&2; }
heading() { echo -e "\n${BOLD}${CYAN}$*${NC}"; }

# ── Flags de linha de comando ─────────────────────────────────────────────

OPT_PHP_VERSION=""
OPT_MODE="monitor"
OPT_UNINSTALL=0
OPT_NONINTERACTIVE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --php-version) OPT_PHP_VERSION="$2"; shift 2 ;;
        --mode)        OPT_MODE="$2";        shift 2 ;;
        --uninstall)   OPT_UNINSTALL=1;      shift   ;;
        --yes|-y)      OPT_NONINTERACTIVE=1; shift   ;;
        --help|-h)
            echo "Uso: bash install.sh [opções]"
            echo "  --php-version VER   Versão PHP alvo (ex: 83, 82). Omitir para seleção interativa."
            echo "  --mode MODE         Modo inicial: monitor (padrão) ou block."
            echo "  --uninstall         Remove a extensão da versão PHP selecionada."
            echo "  --yes               Modo não-interativo (aceita padrões)."
            exit 0
            ;;
        *) error "Opção desconhecida: $1"; exit 1 ;;
    esac
done

# ── Detecção de ambientes e versões PHP ──────────────────────────────────

detect_panel() {
    if [[ -f /usr/local/cwpsrv/htdocs/resources/admin/index.php ]]; then
        echo "cwp"
    elif [[ -d /usr/local/cpanel ]]; then
        echo "cpanel"
    elif [[ -d /usr/local/directadmin ]]; then
        echo "directadmin"
    elif [[ -d /usr/local/hestia ]]; then
        echo "hestia"
    else
        echo "generic"
    fi
}

# Retorna lista de versões instaladas no formato "83:/usr/local/php83"
discover_cwp_versions() {
    local versions=()
    for dir in /usr/local/php*/; do
        [[ -d "$dir" ]] || continue
        local phpize="$dir/bin/phpize"
        local phpbin="$dir/bin/php"
        [[ -x "$phpize" && -x "$phpbin" ]] || continue
        local ver
        ver=$("$phpbin" -n -r 'echo PHP_MAJOR_VERSION . PHP_MINOR_VERSION;' 2>/dev/null) || continue
        versions+=("${ver}:${dir%/}")
    done
    printf '%s\n' "${versions[@]}"
}

discover_cpanel_versions() {
    local versions=()
    for dir in /opt/cpanel/ea-php*/; do
        [[ -d "$dir" ]] || continue
        local phpize="$dir/root/usr/bin/phpize"
        local phpbin="$dir/root/usr/bin/php"
        [[ -x "$phpize" && -x "$phpbin" ]] || continue
        local ver
        ver=$("$phpbin" -n -r 'echo PHP_MAJOR_VERSION . PHP_MINOR_VERSION;' 2>/dev/null) || continue
        versions+=("${ver}:${dir%/}")
    done
    printf '%s\n' "${versions[@]}"
}

discover_generic_versions() {
    local versions=()
    for phpbin in /usr/bin/php* /usr/local/bin/php*; do
        [[ -x "$phpbin" ]] || continue
        local bname="$(basename "$phpbin")"
        [[ "$bname" =~ ^php([0-9.]*|)$ ]] || continue
        local phpize="${phpbin/php/phpize}"
        [[ -x "$phpize" ]] || phpize="$(dirname "$phpbin")/phpize"
        [[ -x "$phpize" ]] || continue
        local ver
        ver=$("$phpbin" -n -r 'echo PHP_MAJOR_VERSION . PHP_MINOR_VERSION;' 2>/dev/null) || continue
        local phpconfig="${phpize/phpize/php-config}"
        [[ -x "$phpconfig" ]] || phpconfig="$(dirname "$phpbin")/php-config"
        versions+=("${ver}:${phpbin}|${phpize}|${phpconfig}")
    done
    printf '%s\n' "${versions[@]}"
}

# ── Resolução de paths por versão/painel ─────────────────────────────────

resolve_paths() {
    local panel="$1"
    local base_dir="$2"   # ex: /usr/local/php83 ou /opt/cpanel/ea-php83

    case "$panel" in
        cwp)
            PHPIZE_BIN="$base_dir/bin/phpize"
            PHP_CONFIG_BIN="$base_dir/bin/php-config"
            PHP_BIN="$base_dir/bin/php"
            EXT_DIR="$("$PHP_CONFIG_BIN" --extension-dir 2>/dev/null)"
            # CWP armazena INI extras em php.d dentro do diretório da versão
            INI_DIR="$base_dir/etc/php.d"
            [[ -d "$INI_DIR" ]] || INI_DIR="$base_dir/etc"
            # Nome do serviço FPM no CWP
            local short_ver="${base_dir##*/php}"   # ex: 83
            FPM_SERVICE="php-fpm${short_ver}"
            ;;
        cpanel)
            PHPIZE_BIN="$base_dir/root/usr/bin/phpize"
            PHP_CONFIG_BIN="$base_dir/root/usr/bin/php-config"
            PHP_BIN="$base_dir/root/usr/bin/php"
            EXT_DIR="$("$PHP_CONFIG_BIN" --extension-dir 2>/dev/null)"
            INI_DIR="$base_dir/root/etc/php.d"
            [[ -d "$INI_DIR" ]] || INI_DIR="/etc/php.d"
            FPM_SERVICE="ea-php${PHP_SHORT_VER}-php-fpm"
            ;;
        *)
            if [[ "$base_dir" == *"|"* ]]; then
                # Generic detection passing explicit binaries
                PHP_BIN="${base_dir%%|*}"
                local rest="${base_dir#*|}"
                PHPIZE_BIN="${rest%%|*}"
                PHP_CONFIG_BIN="${rest#*|}"
            else
                PHPIZE_BIN="${PHPIZE_BIN:-phpize}"
                PHP_CONFIG_BIN="${PHP_CONFIG_BIN:-php-config}"
                PHP_BIN="${PHP_BIN:-php}"
            fi
            EXT_DIR="$("$PHP_CONFIG_BIN" --extension-dir 2>/dev/null || echo /usr/lib/php)"
            local scan_dir
            scan_dir="$("$PHP_BIN" --ini 2>/dev/null | grep -i 'Scan for additional \.ini files in' | cut -d: -f2 | tr -d ' ')"
            if [[ -n "$scan_dir" && "$scan_dir" != "(none)" ]]; then
                INI_DIR="$scan_dir"
            else
                # Se não tem diretório de scan, caímos pro fallback
                INI_DIR="${INI_DIR:-/etc/php.d}"
            fi
            FPM_SERVICE="php-fpm"
            ;;
    esac
}

# ── Seleção interativa da versão ─────────────────────────────────────────

select_php_version() {
    local panel="$1"
    local -a versions=()
    local -a bases=()

    heading "Detectando versões PHP disponíveis..."

    local raw
    case "$panel" in
        cwp)     raw=$(discover_cwp_versions)     ;;
        cpanel)  raw=$(discover_cpanel_versions)  ;;
        *)       raw=$(discover_generic_versions) ;;
    esac

    while IFS=: read -r ver base; do
        [[ -n "$ver" ]] || continue
        versions+=("$ver")
        bases+=("$base")
        echo "  [$((${#versions[@]}))] PHP ${ver:0:1}.${ver:1:1}  →  $base"
    done <<< "$raw"

    if [[ ${#versions[@]} -eq 0 ]]; then
        error "Nenhuma versão PHP com phpize encontrada."
        error "Defina PHPIZE_BIN e PHP_CONFIG_BIN manualmente ou use --php-version."
        exit 1
    fi

    if [[ -n "$OPT_PHP_VERSION" ]]; then
        # Procura a versão solicitada
        for i in "${!versions[@]}"; do
            if [[ "${versions[$i]}" == "$OPT_PHP_VERSION" ]]; then
                PHP_SHORT_VER="${versions[$i]}"
                SELECTED_BASE="${bases[$i]}"
                return
            fi
        done
        error "Versão '${OPT_PHP_VERSION}' não encontrada nas versões disponíveis."
        exit 1
    fi

    if [[ ${#versions[@]} -eq 1 ]]; then
        PHP_SHORT_VER="${versions[0]}"
        SELECTED_BASE="${bases[0]}"
        info "Única versão detectada: PHP ${PHP_SHORT_VER:0:1}.${PHP_SHORT_VER:1:1} — selecionada automaticamente."
        return
    fi

    echo ""
    read -rp "Selecione a versão (1-${#versions[@]}): " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#versions[@]} )); then
        error "Opção inválida."
        exit 1
    fi
    PHP_SHORT_VER="${versions[$((choice-1))]}"
    SELECTED_BASE="${bases[$((choice-1))]}"
}

# ── Desinstalação ────────────────────────────────────────────────────────

do_uninstall() {
    local panel="$1"
    heading "Desinstalando ${EXT_NAME} (PHP ${PHP_SHORT_VER:0:1}.${PHP_SHORT_VER:1:1})"

    local ini_file="$INI_DIR/${EXT_NAME}.ini"
    local so_file="$EXT_DIR/${EXT_NAME}.so"

    [[ -f "$ini_file" ]] && { rm -f "$ini_file"; info "Removido: $ini_file"; }
    [[ -f "$so_file"  ]] && { rm -f "$so_file";  info "Removido: $so_file";  }

    warn "Os arquivos de configuração em ${CONF_DIR} e logs em ${LOG_DIR} NÃO foram removidos."
    warn "Para remover manualmente: rm -rf ${CONF_DIR} ${LOG_DIR}"
    echo ""
    info "Reinicie o PHP-FPM para aplicar: systemctl restart ${FPM_SERVICE}"
}

# ── Build ────────────────────────────────────────────────────────────────

do_build() {
    heading "Compilando ${EXT_NAME} para PHP ${PHP_SHORT_VER:0:1}.${PHP_SHORT_VER:1:1}..."

    cd "$SCRIPT_DIR"
    "$PHPIZE_BIN" --clean 2>/dev/null || true
    "$PHPIZE_BIN"
    ./configure --enable-security-guard --with-php-config="$PHP_CONFIG_BIN"
    make -j"$(nproc)"
    make install

    info "Extensão instalada em: $EXT_DIR/${EXT_NAME}.so"
}

# ── Configuração ─────────────────────────────────────────────────────────

do_configure() {
    heading "Configurando diretórios e arquivos..."

    # Diretórios de configuração (compartilhados entre versões PHP)
    install -d -m 750 -o root -g root "$CONF_DIR"
    install -d -m 750 -o root -g root "$LOG_DIR"
    install -d -m 750 -o root -g root "$LOG_DIR/users"
    info "Diretórios criados: $CONF_DIR  $LOG_DIR"

    # Arquivos .conf de exemplo (preserva existentes)
    for f in allowed_commands.conf allowed_files.conf allowed_network.conf; do
        local dest="$CONF_DIR/$f"
        if [[ ! -f "$dest" ]]; then
            install -m 640 -o root -g root "$SCRIPT_DIR/etc/$f" "$dest"
            info "Instalado: $dest"
        else
            warn "$dest já existe — preservado sem alteração."
        fi
    done

    # INI snippet
    [[ -d "$INI_DIR" ]] || { mkdir -p "$INI_DIR"; }
    local ini_dest="$INI_DIR/${EXT_NAME}.ini"

    # Gera INI com o modo escolhido
    sed "s|enforcement_mode=monitor|enforcement_mode=${OPT_MODE}|" \
        "$SCRIPT_DIR/php_security_guard.ini" > "$ini_dest"
    chmod 640 "$ini_dest"
    info "INI instalado: $ini_dest  (modo: ${OPT_MODE})"
}

# ── Verificação pós-instalação ───────────────────────────────────────────

do_verify() {
    heading "Verificando instalação..."

    if "$PHP_BIN" -m 2>/dev/null | grep -q "^${EXT_NAME}$"; then
        info "Extensão carregada com sucesso pelo PHP CLI."
    else
        warn "A extensão não aparece em 'php -m'. Verifique o INI e reinicie o FPM."
    fi

    "$PHP_BIN" -r "phpinfo();" 2>/dev/null | grep -i "security_guard" | head -5 || true
}

# ── Sumário final ────────────────────────────────────────────────────────

print_summary() {
    local php_ver="${PHP_SHORT_VER:0:1}.${PHP_SHORT_VER:1:1}"
    heading "Instalação concluída"
    echo ""
    echo -e "  ${BOLD}Extensão:${NC}        ${EXT_DIR}/${EXT_NAME}.so"
    echo -e "  ${BOLD}INI:${NC}             ${INI_DIR}/${EXT_NAME}.ini"
    echo -e "  ${BOLD}Configurações:${NC}   ${CONF_DIR}/"
    echo -e "  ${BOLD}Logs:${NC}            ${LOG_DIR}/"
    echo -e "  ${BOLD}Modo inicial:${NC}    ${OPT_MODE}"
    echo ""
    echo -e "  ${BOLD}Próximos passos:${NC}"
    echo "    1. Edite os arquivos em ${CONF_DIR}/ com suas whitelists."
    echo "    2. Reinicie o PHP-FPM:"
    echo "         systemctl restart ${FPM_SERVICE}"
    echo "    3. Verifique os logs em ${LOG_DIR}/"
    echo "    4. Quando pronto para produção, mude para modo block:"
    echo "         sed -i 's/enforcement_mode=monitor/enforcement_mode=block/' ${INI_DIR}/${EXT_NAME}.ini"
    echo "         systemctl restart ${FPM_SERVICE}"
    echo ""
    if [[ "$OPT_MODE" == "monitor" ]]; then
        echo -e "  ${YELLOW}Atenção:${NC} modo 'monitor' — chamadas NÃO serão bloqueadas ainda."
        echo "  Monitore ${LOG_DIR}/ por alguns dias antes de ativar o bloqueio."
    fi
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    error "Execute como root: sudo bash install.sh"
    exit 1
fi

PANEL=$(detect_panel)
info "Painel detectado: ${PANEL}"

select_php_version "$PANEL"
resolve_paths "$PANEL" "$SELECTED_BASE"

echo ""
echo -e "  PHP selecionado : ${BOLD}PHP ${PHP_SHORT_VER:0:1}.${PHP_SHORT_VER:1:1}${NC}"
echo -e "  phpize          : $PHPIZE_BIN"
echo -e "  php-config      : $PHP_CONFIG_BIN"
echo -e "  INI dir         : $INI_DIR"
echo -e "  Serviço FPM     : $FPM_SERVICE"
echo ""

if [[ "$OPT_NONINTERACTIVE" -eq 0 ]]; then
    read -rp "Confirmar instalação? [s/N] " confirm
    [[ "$confirm" =~ ^[sS]$ ]] || { echo "Cancelado."; exit 0; }
fi

if [[ "$OPT_UNINSTALL" -eq 1 ]]; then
    do_uninstall "$PANEL"
    exit 0
fi

do_build
do_configure
do_verify
print_summary
