#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Bot Mitigation Adaptive Layer 7 — https://github.com/iamsahildhamija/bot-mitigation
# One enclosing function allows an inspected curl | bash installation to copy itself.
bot_mitigation_main() {
set -Eeuo pipefail
umask 077
export LC_ALL=C
VERSION="1.0.0"
ROOT=""
if [[ ${BOT_MITIGATION_TESTING:-} == 1 ]]; then
    ROOT=${BOT_MITIGATION_ROOT:-}
    [[ $ROOT == /* && $ROOT != / && $ROOT != *'/../'* && -f $ROOT/.bot-mitigation-test-root ]] || { echo 'Invalid isolated test root.' >&2; return 2; }
    [[ $(cat "$ROOT/.bot-mitigation-test-root") == bot-mitigation-test ]] || return 2
else
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
fi
CONFIG_DIR=$ROOT/etc/bot-mitigation
CONFIG_FILE=$CONFIG_DIR/config.conf
STATE_DIR=$ROOT/var/lib/bot-mitigation
APP_LOG=$ROOT/var/log/bot-mitigation.log
RUNTIME_DIR=$ROOT/run/bot-mitigation
EXECUTABLE=$ROOT/usr/local/sbin/bot-mitigation
UNIT=$ROOT/etc/systemd/system/bot-mitigation.service
INIT_SCRIPT=$ROOT/etc/init.d/bot-mitigation
SELF_SOURCE=${BASH_SOURCE[0]:-}
FW_BACKEND=none
SERVICE_MANAGER=none
SERVICE_RUNNING=no

say() { printf '%s\n' "$*"; }
error() { printf 'ERROR: %s\n' "$*" >&2; }
require_root() { [[ -n $ROOT || $EUID == 0 ]] || { error 'Run this command with sudo/root privileges.'; return 1; }; }
require_linux() { [[ -n $ROOT || $(uname -s) == Linux ]] || { error 'Installation and service control require Linux; help, version, self-test and analyze are portable.'; return 1; }; }
secure_dirs() {
    local d
    local -a directories=("$STATE_DIR" "$RUNTIME_DIR")
    # systemd mounts /etc read-only for the daemon. Installation/CLI own config
    # permissions; runtime only reads configuration and writes state/logs.
    if [[ ${1:-} != runtime ]]; then directories+=("$CONFIG_DIR"); fi
    for d in "${directories[@]}"; do
        [[ ! -L $d ]] || { error "Refusing symlink directory: $d"; return 1; }
        mkdir -p "$d"; chmod 700 "$d"
    done
    mkdir -p "$(dirname "$APP_LOG")"
    for d in "$APP_LOG" "$CONFIG_FILE" "$STATE_DIR/firewall.lock" "$STATE_DIR/daemon.lock" "$STATE_DIR/emergency-disabled" "$CONFIG_DIR/whitelist"; do
        [[ ! -L $d ]] || { error "Refusing symlink: $d"; return 1; }
    done
    touch "$APP_LOG"; chmod 600 "$APP_LOG"
}
log_event() {
    local level=$1; shift
    [[ ${LOG_LEVEL:-INFO} != WARN || $level != INFO ]] || return 0
    local message=$* size i
    # Log messages are bounded and stripped of control characters, including terminal escapes.
    message=$(printf '%.3000s' "$message" | tr '\000-\010\013-\037\177' '?')
    [[ -d $STATE_DIR && -f $APP_LOG ]] || { printf '[%s] %s\n' "$level" "$message" >&2; return; }
    size=$(wc -c < "$APP_LOG")
    if (( size > LOG_MAX_BYTES )); then
        rm -f "$APP_LOG.$LOG_KEEP"
        for ((i=LOG_KEEP-1;i>=1;i--)); do [[ ! -f $APP_LOG.$i ]] || mv "$APP_LOG.$i" "$APP_LOG.$((i+1))"; done
        mv "$APP_LOG" "$APP_LOG.1"; : > "$APP_LOG"; chmod 600 "$APP_LOG"
    fi
    printf '%s [%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$level" "$message" >> "$APP_LOG"
}
defaults() {
    MODE=dry-run LOG_FILES='' WEB_SERVER=auto PROTECTED_PORTS='80 443' MANAGEMENT_PORTS=22
    LOG_IP_MODE=unknown FIREWALL_SCOPE=unconfirmed FIREWALL_BACKEND=auto
    WINDOW_SHORT=10 WINDOW_MEDIUM=30 WINDOW_LONG=60 WINDOW_HISTORY=300
    MIN_UNIQUE_IPS=20 BURST_MULTIPLIER=5 SCORE_THRESHOLD_OBSERVE=55 SCORE_THRESHOLD_BLOCK=80
    DEFAULT_BLOCK_TIME=300 MAX_BLOCK_TIME=3600 WARMUP_TIME=300
    ENABLE_GEOIP=no MAXMIND_LICENSE_KEY='' GEOIP_COUNTRY_DB='' GEOIP_ASN_DB=''
    TRUSTED_IPS='' TRUSTED_NETWORKS='' TRUSTED_PROXY_RANGES=''
    EXCLUDED_PATHS='/.well-known/acme-challenge/ /health /healthz /readyz'
    ENABLE_NETWORK_ESCALATION=no ENABLE_ASN_ESCALATION=no ENABLE_COUNTRY_ESCALATION=no ENABLE_CHALLENGE=no
    LOG_LEVEL=INFO STATE_RETENTION=86400 MAX_EVENTS=20000 MAX_SCOPES=256 MAX_TRACKED_IPS=50000
    LOG_MAX_BYTES=5242880 LOG_KEEP=3
}
config_template() {
cat <<'BOT_CONFIG'
# Linux Bot Mitigation. Data only: KEY=value or KEY="value".
# No shell expansion, commands, multiline values, or inline comments.
MODE=dry-run
# Space-separated absolute log paths; blank uses bounded discovery at startup.
LOG_FILES=""
WEB_SERVER=auto
PROTECTED_PORTS="80 443"
# Ports that must never be blocked. Include every custom SSH/management port.
MANAGEMENT_PORTS="22"
# To enforce: confirm the FIRST log IP is the direct socket peer (not a header).
# Rewritten real-IP/CDN logs are suitable for observation only.
LOG_IP_MODE=unknown
# Firewall blocks affect every website and path on protected ports for that IP.
# Explicitly acknowledge this host-wide effect by setting FIREWALL_SCOPE=host.
FIREWALL_SCOPE=unconfirmed
FIREWALL_BACKEND=auto
WINDOW_SHORT=10
WINDOW_MEDIUM=30
WINDOW_LONG=60
WINDOW_HISTORY=300
MIN_UNIQUE_IPS=20
BURST_MULTIPLIER=5
SCORE_THRESHOLD_OBSERVE=55
SCORE_THRESHOLD_BLOCK=80
DEFAULT_BLOCK_TIME=300
MAX_BLOCK_TIME=3600
# Seconds of clean observed traffic before automatic enforcement after restart.
WARMUP_TIME=300
ENABLE_GEOIP=no
# Reserved credential for administrator-managed geoipupdate; never used/logged.
MAXMIND_LICENSE_KEY=""
GEOIP_COUNTRY_DB=""
GEOIP_ASN_DB=""
TRUSTED_IPS=""
TRUSTED_NETWORKS=""
TRUSTED_PROXY_RANGES=""
# Prefix exclusions. Matching requests do not contribute to risk. Firewall
# bans cannot exempt a URL: allowlist service IPs for guaranteed reachability.
EXCLUDED_PATHS="/.well-known/acme-challenge/ /health /healthz /readyz"
# Broad automatic bans and web-server challenges are deliberately unsupported.
# yes is rejected, rather than silently pretending the feature is active.
ENABLE_NETWORK_ESCALATION=no
ENABLE_ASN_ESCALATION=no
ENABLE_COUNTRY_ESCALATION=no
ENABLE_CHALLENGE=no
LOG_LEVEL=INFO
# Repeat history/cache retention in seconds; bounded even during an attack.
STATE_RETENTION=86400
MAX_EVENTS=20000
MAX_SCOPES=256
MAX_TRACKED_IPS=50000
LOG_MAX_BYTES=5242880
LOG_KEEP=3
BOT_CONFIG
}
trim() { REPLY=$1; REPLY=${REPLY#"${REPLY%%[![:space:]]*}"}; REPLY=${REPLY%"${REPLY##*[![:space:]]}"}; }
load_config() {
    defaults
    [[ -f $CONFIG_FILE ]] || return 0
    local line key value number=0
    while IFS= read -r line || [[ -n $line ]]; do
        number=$((number+1)); trim "$line"; line=$REPLY
        [[ -n $line && $line != \#* ]] || continue
        [[ $line == *=* ]] || { error "Configuration line $number: expected KEY=value."; return 2; }
        key=${line%%=*}; value=${line#*=}; trim "$key"; key=$REPLY; trim "$value"; value=$REPLY
        case $key in
            MODE|LOG_FILES|WEB_SERVER|PROTECTED_PORTS|MANAGEMENT_PORTS|LOG_IP_MODE|FIREWALL_SCOPE|FIREWALL_BACKEND|WINDOW_SHORT|WINDOW_MEDIUM|WINDOW_LONG|WINDOW_HISTORY|MIN_UNIQUE_IPS|BURST_MULTIPLIER|SCORE_THRESHOLD_OBSERVE|SCORE_THRESHOLD_BLOCK|DEFAULT_BLOCK_TIME|MAX_BLOCK_TIME|WARMUP_TIME|ENABLE_GEOIP|MAXMIND_LICENSE_KEY|GEOIP_COUNTRY_DB|GEOIP_ASN_DB|TRUSTED_IPS|TRUSTED_NETWORKS|TRUSTED_PROXY_RANGES|EXCLUDED_PATHS|ENABLE_NETWORK_ESCALATION|ENABLE_ASN_ESCALATION|ENABLE_COUNTRY_ESCALATION|ENABLE_CHALLENGE|LOG_LEVEL|STATE_RETENTION|MAX_EVENTS|MAX_SCOPES|MAX_TRACKED_IPS|LOG_MAX_BYTES|LOG_KEEP) ;;
            *) error "Configuration line $number: unknown option (value redacted)."; return 2;;
        esac
        if [[ $value == \"*\" && ${#value} -ge 2 ]]; then value=${value:1:${#value}-2}
        elif [[ $value == \'*\' && ${#value} -ge 2 ]]; then value=${value:1:${#value}-2}; fi
        [[ $value != *$'\r'* && $value != *$'\t'* && $value != *$'\033'* ]] || { error "Configuration line $number: control character."; return 2; }
        printf -v "$key" '%s' "$value"
    done < "$CONFIG_FILE"
    validate_config
}
number_between() {
    local key=$1 lower=$2 upper=$3 value=${!1}
    [[ $value =~ ^(0|[1-9][0-9]{0,8})$ ]] && (( value >= lower && value <= upper )) || { error "Configuration: $key must be an integer from $lower to $upper."; return 2; }
}
validate_config() {
    local item port path
    case $MODE in dry-run|enforce) ;; *) error 'MODE must be dry-run or enforce.'; return 2;; esac
    case $WEB_SERVER in auto|nginx|apache|litespeed|openlitespeed) ;; *) error 'WEB_SERVER must be auto, nginx, apache, litespeed or openlitespeed.'; return 2;; esac
    case $LOG_IP_MODE in unknown|direct|proxy) ;; *) error 'LOG_IP_MODE must be unknown, direct or proxy.'; return 2;; esac
    case $FIREWALL_SCOPE in unconfirmed|host) ;; *) error 'FIREWALL_SCOPE must be unconfirmed or host.'; return 2;; esac
    case $FIREWALL_BACKEND in auto|none|nftables|iptables) ;; *) error 'Invalid FIREWALL_BACKEND.'; return 2;; esac
    case $ENABLE_GEOIP in yes|no) ;; *) error 'ENABLE_GEOIP must be yes or no.'; return 2;; esac
    case $LOG_LEVEL in INFO|WARN) ;; *) error 'LOG_LEVEL must be INFO or WARN.'; return 2;; esac
    for item in ENABLE_NETWORK_ESCALATION ENABLE_ASN_ESCALATION ENABLE_COUNTRY_ESCALATION ENABLE_CHALLENGE; do
        [[ ${!item} == no ]] || { error "$item is not implemented safely and must remain no."; return 2; }
    done
    for item in WINDOW_SHORT WINDOW_MEDIUM WINDOW_LONG WINDOW_HISTORY; do number_between "$item" 1 3600 || return; done
    (( WINDOW_SHORT <= WINDOW_MEDIUM && WINDOW_MEDIUM <= WINDOW_LONG && WINDOW_LONG <= WINDOW_HISTORY )) || { error 'Windows must be ordered SHORT <= MEDIUM <= LONG <= HISTORY.'; return 2; }
    number_between MIN_UNIQUE_IPS 5 10000 || return
    number_between BURST_MULTIPLIER 2 100 || return
    number_between SCORE_THRESHOLD_OBSERVE 1 99 || return
    number_between SCORE_THRESHOLD_BLOCK 2 100 || return
    (( SCORE_THRESHOLD_BLOCK > SCORE_THRESHOLD_OBSERVE )) || { error 'SCORE_THRESHOLD_BLOCK must be greater than SCORE_THRESHOLD_OBSERVE.'; return 2; }
    number_between DEFAULT_BLOCK_TIME 10 86400 || return; number_between MAX_BLOCK_TIME 10 86400 || return
    (( DEFAULT_BLOCK_TIME <= MAX_BLOCK_TIME )) || { error 'DEFAULT_BLOCK_TIME must not exceed MAX_BLOCK_TIME.'; return 2; }
    number_between WARMUP_TIME 0 86400 || return; number_between STATE_RETENTION 300 604800 || return
    (( STATE_RETENTION >= WINDOW_HISTORY )) || { error 'STATE_RETENTION must be at least WINDOW_HISTORY.'; return 2; }
    number_between MAX_EVENTS 100 100000 || return; number_between MAX_SCOPES 1 1024 || return
    number_between MAX_TRACKED_IPS 100 100000 || return; number_between LOG_MAX_BYTES 65536 104857600 || return
    number_between LOG_KEEP 1 10 || return
    [[ -n $PROTECTED_PORTS ]] || { error 'PROTECTED_PORTS is empty.'; return 2; }
    read -r -a PORT_ARRAY <<< "$PROTECTED_PORTS"
    ((${#PORT_ARRAY[@]} <= 15)) || { error 'At most 15 protected ports are supported.'; return 2; }
    for port in $PROTECTED_PORTS $MANAGEMENT_PORTS; do
        [[ $port =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= 65535 )) || { error 'Invalid TCP/UDP port.'; return 2; }
    done
    for port in $PROTECTED_PORTS; do
        for item in 22 $MANAGEMENT_PORTS; do [[ $port != "$item" ]] || { error 'PROTECTED_PORTS overlaps an SSH/management port.'; return 2; }; done
    done
    for item in $TRUSTED_IPS $TRUSTED_NETWORKS $TRUSTED_PROXY_RANGES; do valid_target "$item" || { error 'Invalid trusted IP/CIDR.'; return 2; }; done
    for path in $LOG_FILES; do
        [[ $path == /* && $path != *[\*\?\[\]\\]* && -f $path && -r $path ]] || { error "Unreadable/non-absolute access log: $path"; return 2; }
    done
    for path in "$GEOIP_COUNTRY_DB" "$GEOIP_ASN_DB"; do
        [[ -z $path || $path == /* ]] || { error 'GeoIP database paths must be absolute.'; return 2; }
    done
    for path in $EXCLUDED_PATHS; do [[ $path == /* && $path != *'|'* && $path != *'\\'* ]] || { error 'EXCLUDED_PATHS must contain literal URL prefixes.'; return 2; }; done
}
backup_file() {
    local file=$1 dest sum original_mtime
    [[ -f $file ]] || return 0
    mkdir -p "$STATE_DIR/backups"
    dest=$(mktemp "$STATE_DIR/backups/$(basename "$file").XXXXXX")
    cp -p "$file" "$dest"
    sum=$(cksum < "$file")
    original_mtime=$(stat -c '%Y' -- "$file" 2>/dev/null || stat -f '%m' "$file")
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$file" "$dest" "$sum" "$original_mtime" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" 'application-owned file replacement' >> "$STATE_DIR/backups/manifest.tsv"
    # Keep the most recent 20 files, not an unbounded history.
    local old count=0
    while IFS= read -r old; do
        count=$((count+1)); (( count <= 20 )) || rm -f "$STATE_DIR/backups/$old"
    done < <(ls -1t "$STATE_DIR/backups" | awk '$0 != "manifest.tsv"')
    tail -n 100 "$STATE_DIR/backups/manifest.tsv" > "$STATE_DIR/backups/manifest.new"
    mv "$STATE_DIR/backups/manifest.new" "$STATE_DIR/backups/manifest.tsv"
}
set_config() {
    local key=$1 value=$2 temp
    backup_file "$CONFIG_FILE"
    temp=$(mktemp "$CONFIG_DIR/.config.XXXXXX")
    awk -v key="$key" -v val="$value" 'BEGIN{done=0} $0 ~ "^[[:space:]]*"key"[[:space:]]*=" {if(!done)print key"="val;done=1;next} {print} END{if(!done)print key"="val}' "$CONFIG_FILE" > "$temp"
    chmod 600 "$temp"; mv "$temp" "$CONFIG_FILE"
}
platform_detect() {
    OS_ID=unknown PACKAGE_MANAGER=none
    if [[ -r $ROOT/etc/os-release ]]; then
        OS_ID=$(awk -F= '$1=="ID" {gsub(/["\047]/,"",$2);print $2;exit}' "$ROOT/etc/os-release")
    fi
    local cmd
    for cmd in apt-get dnf yum apk zypper pacman; do if command -v "$cmd" >/dev/null 2>&1; then PACKAGE_MANAGER=$cmd; break; fi; done
    SERVICE_MANAGER=none
    if [[ -d $ROOT/run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then SERVICE_MANAGER=systemd
    elif [[ -d $ROOT/run/openrc ]] && command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then SERVICE_MANAGER=openrc; fi
}
dependencies() {
    local cmd missing=''
    for cmd in bash awk tail flock date mktemp cksum tr wc chmod mkdir cp mv rm cat readlink od mkfifo sleep ls stat; do
        command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
    done
    if [[ -n $missing ]]; then
        error "Missing required tools:$missing"
        say "Detected package manager: $PACKAGE_MANAGER. Install bash, awk (gawk/mawk), coreutils and util-linux using your distribution packages, then retry. No packages were automatically installed."
        return 1
    fi
}
service_owned() {
    local file
    case $SERVICE_MANAGER in systemd) file=$UNIT;; openrc) file=$INIT_SCRIPT;; *) return 1;; esac
    [[ -f $file && ! -L $file ]] && awk '/^# Managed by Linux Bot Mitigation$/ {ok=1} END{exit !ok}' "$file"
}
service_action() {
    local action=$1
    case $action in
        start|restart|enable) service_owned || { error 'Refusing service changes without an owned service definition.'; return 1; };;
        stop|disable)
            if ! service_owned; then
                # No owned service is installed. Never stop a coincidentally named service.
                [[ ! -e $UNIT && ! -e $INIT_SCRIPT ]] && return 0
                error 'Refusing to stop/disable an unowned service definition.'; return 1
            fi;;
    esac
    case $SERVICE_MANAGER in
        systemd) systemctl "$action" bot-mitigation.service;;
        openrc)
            case $action in
                enable) rc-update add bot-mitigation default;;
                disable) rc-update del bot-mitigation default;;
                is-active) rc-service bot-mitigation status;;
                is-enabled) rc-update show default | awk '$1=="bot-mitigation" {yes=1} END{exit !yes}';;
                *) rc-service bot-mitigation "$action";;
            esac;;
        *) error 'No active supported service manager (systemd/OpenRC).'; return 1;;
    esac
}
emit_systemd() {
cat <<'BOT_UNIT'
# Managed by Linux Bot Mitigation
[Unit]
Description=Linux Bot Mitigation - adaptive HTTP burst observation and mitigation
After=network.target
StartLimitIntervalSec=300
StartLimitBurst=3
[Service]
Type=simple
ExecStart=/usr/local/sbin/bot-mitigation daemon
ExecStopPost=/usr/local/sbin/bot-mitigation cleanup
Restart=on-failure
RestartSec=10
TimeoutStopSec=15
KillMode=control-group
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=/var/lib/bot-mitigation /var/log /run/bot-mitigation
RuntimeDirectory=bot-mitigation
RuntimeDirectoryMode=0700
[Install]
WantedBy=multi-user.target
BOT_UNIT
}
emit_openrc() {
cat <<'BOT_INIT'
#!/sbin/openrc-run
# Managed by Linux Bot Mitigation
name="Linux Bot Mitigation"
description="Adaptive HTTP burst observation and mitigation"
command="/usr/local/sbin/bot-mitigation"
command_args="daemon"
supervisor="supervise-daemon"
respawn_delay=10
respawn_max=3
respawn_period=300
pidfile="/run/bot-mitigation/openrc.pid"
depend() { need net; }
start_pre() { checkpath --directory --mode 0700 /run/bot-mitigation; }
stop_post() { /usr/local/sbin/bot-mitigation cleanup; }
BOT_INIT
}
discover_logs() {
    LOG_ARRAY=()
    local file seen='' limit=0
    if [[ -n $LOG_FILES ]]; then read -r -a LOG_ARRAY <<< "$LOG_FILES"; return; fi
    # Bounded, shallow glob patterns only. Never walk the entire filesystem.
    for file in "$ROOT"/var/log/nginx/*access*.log "$ROOT"/var/log/nginx/access.log "$ROOT"/var/log/apache2/*access*.log "$ROOT"/var/log/httpd/*access*log "$ROOT"/usr/local/apache/domlogs/* "$ROOT"/usr/local/apache/logs/access_log "$ROOT"/var/www/vhosts/system/*/logs/access_log "$ROOT"/var/www/vhosts/system/*/logs/access_ssl_log "$ROOT"/usr/local/lsws/logs/access.log "$ROOT"/usr/local/lsws/*/logs/access.log "$ROOT"/home/*/logs/*access*.log; do
        [[ -f $file && -r $file && $file != *'.gz' && $file != *$'\n'* && $file != *' '* ]] || continue
        case " $seen " in *" $file "*) continue;; esac
        LOG_ARRAY+=("$file"); seen="$seen $file"; limit=$((limit+1))
        (( limit < 256 )) || break
    done
}
web_detect() {
    DETECTED_WEB_SERVER=$WEB_SERVER
    [[ $WEB_SERVER == auto ]] || return 0
    local cmd out=''
    for cmd in nginx apache2 httpd lshttpd openlitespeed; do command -v "$cmd" >/dev/null 2>&1 && out="$out $cmd"; done
    DETECTED_WEB_SERVER=${out:-unknown}
}
enforcement_ready() {
    [[ $LOG_IP_MODE == direct ]] || { error 'Enforcement requires LOG_IP_MODE=direct after verifying that log IPs are socket peers; CDN/header-rewritten logs are observation-only.'; return 1; }
    [[ $FIREWALL_SCOPE == host ]] || { error 'Enforcement requires FIREWALL_SCOPE=host, acknowledging blocks affect all hosted domains and URLs on protected ports.'; return 1; }
    firewall_detect || return
    [[ $FW_BACKEND != none ]] || { error 'No usable firewall backend; staying fail-open.'; return 1; }
}
lock_firewall() { exec 8>"$STATE_DIR/firewall.lock"; flock -x 8; }
unlock_firewall() { flock -u 8; exec 8>&-; }
cleanup_firewall() {
    require_root || return
    if [[ ! -d $STATE_DIR ]]; then
        if fw_orphans_present; then error 'Reserved firewall objects have no ownership state; manual review required.'; return 1; fi
        return 0
    fi
    lock_firewall
    local rc=0
    firewall_clear || rc=$?
    if (( rc == 0 )); then rm -f "$STATE_DIR/active.tsv"; fi
    unlock_firewall
    return "$rc"
}
installation_rollback() {
    local rc=$1 file base
    trap - EXIT INT TERM
    (( rc != 0 )) || return 0
    error 'Installation failed; rolling back application-owned changes.'
    service_action stop >/dev/null 2>&1 || true
    if ! cleanup_firewall; then
        : > "$STATE_DIR/emergency-disabled"
        service_action disable >/dev/null 2>&1 || true
        error 'Firewall cleanup needs attention. Recovery executable, config and ownership state retained; no new bans are possible.'
        return "$rc"
    fi
    if [[ $INSTALL_WAS_ENABLED != yes ]]; then service_action disable >/dev/null 2>&1 || true; fi
    for file in "$EXECUTABLE" "$UNIT" "$INIT_SCRIPT" "$CONFIG_FILE" "$STATE_DIR/installed"; do
        base=$(basename "$file")
        if [[ -f $INSTALL_TRANSACTION/$base ]]; then cp -p "$INSTALL_TRANSACTION/$base" "$file"
        elif [[ -f $INSTALL_TRANSACTION/new-$base ]]; then rm -f "$file"; fi
    done
    [[ $SERVICE_MANAGER != systemd ]] || systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ $INSTALL_WAS_RUNNING == yes ]]; then service_action start >/dev/null 2>&1 || true; fi
    rm -rf "$INSTALL_TRANSACTION"
    if [[ $INSTALL_FRESH == yes ]]; then
        # These directories were absent before this transaction and are private to us.
        rm -rf "$CONFIG_DIR" "$STATE_DIR" "$RUNTIME_DIR"
        [[ $INSTALL_HAD_LOG == yes ]] || rm -f "$APP_LOG"
    fi
    return "$rc"
}
install_app() {
    require_root; require_linux
    local enforce=no arg file base existing_install=no
    [[ ! -f $STATE_DIR/installed ]] || existing_install=yes
    for arg in "$@"; do case $arg in --enforce) enforce=yes;; *) error "Unknown install option: $arg"; return 2;; esac; done
    platform_detect
    case $OS_ID in ubuntu|debian|almalinux|rocky|rhel|fedora|centos|alpine|opensuse*|sles|arch|manjaro|ol|amzn) ;; *) error "Unsupported distribution ID: $OS_ID. No system changes made."; return 1;; esac
    dependencies
    [[ $SERVICE_MANAGER != none ]] || { error 'No running systemd/OpenRC detected. No startup configuration was installed.'; return 1; }
    load_config
    [[ $enforce != yes ]] || { MODE=enforce; enforcement_ready; }
    for file in "$UNIT" "$INIT_SCRIPT"; do
        if [[ -e $file ]] && ! awk '/^# Managed by Linux Bot Mitigation$/ {ok=1} END{exit !ok}' "$file"; then error "Refusing to replace an unowned service: $file"; return 1; fi
    done
    [[ ! -e $EXECUTABLE || -f $STATE_DIR/installed ]] || { error 'Executable path already exists without an installation marker; refusing to overwrite.'; return 1; }
    [[ ! -L $EXECUTABLE && ! -L $UNIT && ! -L $INIT_SCRIPT ]] || { error 'Refusing symlink installation target.'; return 1; }
    INSTALL_FRESH=no INSTALL_HAD_LOG=no INSTALL_HAD_SERVICE=no INSTALL_WAS_RUNNING=no INSTALL_WAS_ENABLED=no
    [[ -d $STATE_DIR || -d $CONFIG_DIR ]] || INSTALL_FRESH=yes
    [[ ! -f $APP_LOG ]] || INSTALL_HAD_LOG=yes
    [[ ! -f $UNIT && ! -f $INIT_SCRIPT ]] || INSTALL_HAD_SERVICE=yes
    service_action is-active >/dev/null 2>&1 && INSTALL_WAS_RUNNING=yes
    service_action is-enabled >/dev/null 2>&1 && INSTALL_WAS_ENABLED=yes
    if [[ $INSTALL_HAD_SERVICE == no && ( $INSTALL_WAS_RUNNING == yes || $INSTALL_WAS_ENABLED == yes ) ]]; then
        error 'An active/enabled service with this name exists outside the owned install paths.'; return 1
    fi
    secure_dirs
    exec 6>"$STATE_DIR/install.lock"; flock -x 6
    INSTALL_TRANSACTION=$(mktemp -d "$STATE_DIR/install.XXXXXX")
    mkdir -p "$(dirname "$EXECUTABLE")" "$(dirname "$UNIT")" "$(dirname "$INIT_SCRIPT")"
    for file in "$EXECUTABLE" "$UNIT" "$INIT_SCRIPT" "$CONFIG_FILE" "$STATE_DIR/installed"; do
        base=$(basename "$file")
        if [[ -f $file ]]; then cp -p "$file" "$INSTALL_TRANSACTION/$base"; backup_file "$file"
        else : > "$INSTALL_TRANSACTION/new-$base"; fi
    done
    trap 'installation_rollback "$?"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    service_action stop >/dev/null 2>&1 || [[ $INSTALL_WAS_RUNNING == no ]]
    cleanup_firewall
    [[ -f $CONFIG_FILE ]] || config_template > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    if [[ $enforce == yes ]]; then set_config MODE enforce
    elif [[ $existing_install == no ]]; then set_config MODE dry-run; fi
    # Capture the executing function if the script arrived through stdin.
    local candidate=$INSTALL_TRANSACTION/candidate.sh
    if [[ -n $SELF_SOURCE && -f $SELF_SOURCE && $SELF_SOURCE != /dev/* ]]; then cp "$SELF_SOURCE" "$candidate"
    else
        { printf '#!/usr/bin/env bash\n# SPDX-License-Identifier: MIT\n'; declare -f bot_mitigation_main; printf '\nbot_mitigation_main "$@"\n'; } > "$candidate"
    fi
    bash -n "$candidate"
    bash "$candidate" self-test > "$INSTALL_TRANSACTION/self-test.log"
    cp "$candidate" "$EXECUTABLE.new"; chmod 755 "$EXECUTABLE.new"; mv "$EXECUTABLE.new" "$EXECUTABLE"
    if [[ $SERVICE_MANAGER == systemd ]]; then emit_systemd > "$UNIT"; chmod 644 "$UNIT"; systemctl daemon-reload
    else emit_openrc > "$INIT_SCRIPT"; chmod 755 "$INIT_SCRIPT"; fi
    printf '%s\n' "$VERSION" > "$STATE_DIR/installed"
    [[ -f $CONFIG_DIR/whitelist ]] || : > "$CONFIG_DIR/whitelist"
    load_config
    discover_logs
    ((${#LOG_ARRAY[@]} > 0)) || { error 'No readable access logs discovered. Set LOG_FILES in config and reinstall; rolling back this installation.'; return 1; }
    service_action enable
    service_action start
    sleep 1
    service_action is-active >/dev/null 2>&1 || { error 'Service did not remain active after start.'; return 1; }
    trap - EXIT INT TERM
    rm -rf "$INSTALL_TRANSACTION"
    flock -u 6; exec 6>&-
    log_event INFO "Installed version=$VERSION mode=$MODE; no web-server configuration modified; no dependencies installed."
    say "Linux Bot Mitigation installed successfully.
Service: running
Startup: enabled
Mode: $MODE
Firewall enforcement: $([[ $MODE == enforce && ! -f $STATE_DIR/emergency-disabled ]] && printf enabled || printf disabled)
"
    [[ $MODE != dry-run ]] || say 'The service is monitoring traffic and WILL NOT block visitors.'
    say 'View status: sudo bot-mitigation status
View detections: sudo bot-mitigation logs
Diagnostics: sudo bot-mitigation doctor
Enable enforcement (after configuration): sudo bot-mitigation enforce on
Emergency fail-open: sudo bot-mitigation emergency-disable
Uninstall: sudo bot-mitigation uninstall'
}
set_mode() {
    local mode=$1
    require_root; require_linux; secure_dirs; platform_detect
    [[ -f $CONFIG_FILE ]] || { error 'Not installed.'; return 1; }
    if [[ $mode == enforce ]]; then
        load_config; enforcement_ready
        [[ ! -f $STATE_DIR/emergency-disabled ]] || { error 'Emergency lock is active; run emergency-enable to return to observation first.'; return 1; }
        MODE=enforce
        lock_firewall
        if ! firewall_setup; then
            firewall_clear || true
            unlock_firewall
            : > "$STATE_DIR/emergency-disabled"; service_action stop >/dev/null 2>&1 || true
            set_config MODE dry-run
            error 'Firewall validation/setup failed; enforcement stays disabled.'; return 1
        fi
        unlock_firewall
        set_config MODE enforce
        if ! service_action restart || ! service_action is-active >/dev/null 2>&1; then
            : > "$STATE_DIR/emergency-disabled"; service_action stop >/dev/null 2>&1 || true
            set_config MODE dry-run; cleanup_firewall || true
            error 'Restart failed. Enforcement disabled.'; return 1
        fi
        say 'Enforcement enabled. Automatic blocks remain subject to warmup, scoring and allowlists.'
    else
        : > "$STATE_DIR/emergency-disabled"
        service_action stop >/dev/null 2>&1 || true
        cleanup_firewall
        set_config MODE dry-run
        rm -f "$STATE_DIR/emergency-disabled"
        service_action start
        say 'DRY-RUN enabled. Application firewall blocks removed.'
    fi
}
emergency_disable() {
    require_root; require_linux; secure_dirs; platform_detect
    : > "$STATE_DIR/emergency-disabled"
    service_action stop >/dev/null 2>&1 || true
    cleanup_firewall || { error 'New bans are prevented; firewall cleanup failed. Keep the installation and use doctor/manual recovery.'; return 1; }
    [[ ! -f $CONFIG_FILE ]] || set_config MODE dry-run
    say 'Emergency fail-open: mitigation stopped, new bans disabled, all owned firewall objects removed. Configuration and logs retained.'
}
uninstall_app() {
    local purge=no arg
    for arg in "$@"; do case $arg in --purge) purge=yes;; *) error "Unknown uninstall option: $arg"; return 2;; esac; done
    require_root; require_linux; platform_detect
    [[ ! -L $STATE_DIR ]] || { error 'Refusing symlink state directory.'; return 1; }
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    if [[ -d $STATE_DIR ]]; then
        : > "$STATE_DIR/emergency-disabled"
        service_action stop >/dev/null 2>&1 || true
        cleanup_firewall || { error 'Uninstall halted because owned firewall objects could not be removed. Executable and recovery state retained.'; return 1; }
    fi
    if [[ -f $UNIT || -f $INIT_SCRIPT ]]; then service_action disable; fi
    local file
    for file in "$UNIT" "$INIT_SCRIPT"; do
        if [[ -f $file ]]; then
            awk '/^# Managed by Linux Bot Mitigation$/ {ok=1} END{exit !ok}' "$file" || { error "Unowned service left untouched: $file"; return 1; }
            rm -f "$file"
        fi
    done
    [[ $SERVICE_MANAGER != systemd ]] || systemctl daemon-reload
    if [[ -f $STATE_DIR/installed ]]; then rm -f "$EXECUTABLE"; fi
    rm -rf "$RUNTIME_DIR"
    if [[ -d $STATE_DIR ]]; then
        # Retain backups/manifest only when not purging. Explicit names, never a system-wide wildcard.
        for file in installed stats.json active.tsv history.tsv geo.tsv daemon-mode firewall.lock daemon.lock install.lock firewall.owner emergency-disabled; do rm -f "$STATE_DIR/$file"; done
    fi
    if [[ $purge == yes ]]; then
        rm -rf "$CONFIG_DIR" "$STATE_DIR"
        rm -f "$APP_LOG" "$APP_LOG".[0-9] "$APP_LOG.10"
    elif [[ -f $CONFIG_FILE ]]; then set_config MODE dry-run; fi
    say "Linux Bot Mitigation has been removed.
Service: removed
Firewall objects created by this application: removed
Web-server configurations: never modified
Executable: removed
Configuration/logs/backups: $([[ $purge == yes ]] && printf removed || printf retained)
Dependencies: retained (none installed automatically)"
    [[ $purge == yes ]] || say 'For later total removal, run: sudo bash script.sh uninstall --purge'
}
materialize_engine() { emit_detector > "$1"; }
run_engine() {
    local engine=$1 source=$2 geo=${3:-} warmup=${4:-$WARMUP_TIME} live=${5:-0} excluded
    excluded=${EXCLUDED_PATHS// /|}
    local -a engine_args=( -v log_source="$source" -v geo_file="$geo" -v enable_geoip="$([[ $ENABLE_GEOIP == yes ]] && printf 1 || printf 0)" \
        -v window_short="$WINDOW_SHORT" -v window_medium="$WINDOW_MEDIUM" -v window_long="$WINDOW_LONG" -v window_history="$WINDOW_HISTORY" \
        -v min_unique="$MIN_UNIQUE_IPS" -v burst_multiplier="$BURST_MULTIPLIER" -v score_observe="$SCORE_THRESHOLD_OBSERVE" -v score_block="$SCORE_THRESHOLD_BLOCK" \
        -v max_events="$MAX_EVENTS" -v max_scopes="$MAX_SCOPES" -v max_ips="$MAX_TRACKED_IPS" -v state_retention="$STATE_RETENTION" \
        -v warmup="$warmup" -v excluded_paths="$excluded" -v live="$live" -v start_epoch="$(date +%s)" -f "$engine" )
    if [[ ${ENGINE_EXEC:-0} == 1 ]]; then exec awk "${engine_args[@]}"; else awk "${engine_args[@]}"; fi
}
geo_lookup() {
    local ip=$1 now country='-' asn='-' value
    [[ $ENABLE_GEOIP == yes && $GEO_ACTIVE == yes ]] || return 0
    valid_target "$ip" || return 0
    now=$(date +%s)
    if (( now - GEO_PERIOD >= 60 )); then GEO_PERIOD=$now; GEO_COUNT=0; fi
    (( GEO_COUNT < 120 )) || return 0
    # Lookup once per cached address, with bounded on-disk and in-process state.
    if awk -v ip="$ip" '$1==ip {found=1;exit} END{exit !found}' "$STATE_DIR/geo.tsv" 2>/dev/null; then return 0; fi
    GEO_COUNT=$((GEO_COUNT+1))
    if [[ -n $GEOIP_COUNTRY_DB && -r $GEOIP_COUNTRY_DB ]]; then
        if value=$(timeout 1 mmdblookup --file "$GEOIP_COUNTRY_DB" --ip "$ip" country iso_code 2>/dev/null); then
            country=$(printf '%s\n' "$value" | awk -F'"' '/"[A-Z][A-Z]"/ {print $2;exit}')
        else log_event WARN 'Country GeoIP lookup failed; disabling optional GeoIP until restart.'; GEO_ACTIVE=no; return 0; fi
    fi
    if [[ -n $GEOIP_ASN_DB && -r $GEOIP_ASN_DB ]]; then
        if value=$(timeout 1 mmdblookup --file "$GEOIP_ASN_DB" --ip "$ip" autonomous_system_number 2>/dev/null); then
            asn=$(printf '%s\n' "$value" | awk '/uint32/ {print $1;exit}')
        else log_event WARN 'ASN GeoIP lookup failed; disabling optional GeoIP until restart.'; GEO_ACTIVE=no; return 0; fi
    fi
    [[ $country =~ ^[A-Z]{2}$ ]] || country=-
    [[ $asn =~ ^[0-9]{1,10}$ ]] || asn=-
    printf '%s\t%s\t%s\t%s\n' "$ip" "$country" "$asn" "$now" >> "$STATE_DIR/geo.tsv"
    tail -n 5000 "$STATE_DIR/geo.tsv" > "$STATE_DIR/geo.new"; mv "$STATE_DIR/geo.new" "$STATE_DIR/geo.tsv"
}
mitigate() {
    local ip=$1 score=$2 scope=$3 reasons=$4 manual=${5:-no} now duration count record expires
    valid_target "$ip" || return 0
    target_is_safe "$ip" || return 0
    ip=$(canonical_target "$ip")
    if [[ $MODE != enforce || -f $STATE_DIR/emergency-disabled ]]; then
        log_event DRY-RUN "Would temporarily block $ip; score=$score; scope=$scope; $reasons"
        return 0
    fi
    lock_firewall
    if [[ -f $STATE_DIR/emergency-disabled ]]; then unlock_firewall; return 0; fi
    now=$(date +%s)
    record=$(awk -v ip="$ip" -v now="$now" '$1==ip && $2>now {print $2;exit}' "$STATE_DIR/active.tsv" 2>/dev/null || true)
    if [[ -n $record ]]; then unlock_firewall; return 0; fi
    local active_count=0
    if [[ -f $STATE_DIR/active.tsv ]]; then active_count=$(awk -v now="$now" '$2>now{n++} END{print n+0}' "$STATE_DIR/active.tsv"); fi
    if (( active_count >= 5000 )); then unlock_firewall; log_event WARN 'Temporary penalty capacity reached; candidate skipped.'; return 0; fi
    count=$(awk -v ip="$ip" -v since="$((now-STATE_RETENTION))" '$1==ip && $3>=since && $2~/^[0-9]+$/ {print $2;exit}' "$STATE_DIR/history.tsv" 2>/dev/null || true)
    [[ $count =~ ^[0-9]{1,3}$ ]] || count=0
    (( count < 10 )) || count=10
    duration=$((DEFAULT_BLOCK_TIME * (1 << count)))
    (( duration <= MAX_BLOCK_TIME )) || duration=$MAX_BLOCK_TIME
    if firewall_add "$ip" "$duration"; then
        expires=$((now+duration))
        printf '%s\t%s\n' "$ip" "$expires" >> "$STATE_DIR/active.tsv"
        { if [[ -f $STATE_DIR/history.tsv ]]; then awk -v ip="$ip" -v since="$((now-STATE_RETENTION))" '$1!=ip && $3>=since' "$STATE_DIR/history.tsv" | tail -n 4999; fi; printf '%s\t%s\t%s\n' "$ip" "$((count+1))" "$now"; } > "$STATE_DIR/history.new"
        mv "$STATE_DIR/history.new" "$STATE_DIR/history.tsv"
        log_event MITIGATION "IP=$ip duration=${duration}s score=$score scope=$scope manual=$manual; $reasons"
    else
        log_event ERROR "Firewall rejected temporary block for $ip; failing open; $reasons"
        unlock_firewall
        return 1
    fi
    unlock_firewall
}
daemon_cleanup() {
    local rc=$?
    trap - EXIT TERM INT
    [[ -z ${TAIL_PID:-} ]] || kill "$TAIL_PID" 2>/dev/null || true
    [[ -z ${TICK_PID:-} ]] || kill "$TICK_PID" 2>/dev/null || true
    [[ -z ${ENGINE_PID:-} ]] || kill "$ENGINE_PID" 2>/dev/null || true
    [[ -z ${TAIL_PID:-} ]] || wait "$TAIL_PID" 2>/dev/null || true
    [[ -z ${TICK_PID:-} ]] || wait "$TICK_PID" 2>/dev/null || true
    [[ -z ${ENGINE_PID:-} ]] || wait "$ENGINE_PID" 2>/dev/null || true
    cleanup_firewall || true
    rm -f "$STATE_DIR/daemon-mode"
    [[ -z ${DAEMON_TEMP:-} ]] || rm -rf "$DAEMON_TEMP"
    log_event INFO "Daemon stopped; owned firewall cleanup attempted; exit=$rc."
}
daemon_run() {
    require_root; require_linux; secure_dirs runtime
    exec 9>"$STATE_DIR/daemon.lock"
    flock -n 9 || { error 'Another daemon already holds the lock.'; return 1; }
    if ! load_config; then
        : > "$STATE_DIR/emergency-disabled"; cleanup_firewall || true
        error 'Invalid configuration. Enforcement disabled; correct config then use emergency-enable.'; return 2
    fi
    [[ ! -f $STATE_DIR/emergency-disabled ]] || MODE=dry-run
    discover_logs; web_detect
    ((${#LOG_ARRAY[@]} > 0)) || { error 'No readable access logs. Configure LOG_FILES.'; cleanup_firewall || true; return 1; }
    trap daemon_cleanup EXIT
    trap 'exit 0' TERM INT
    if [[ $MODE == enforce ]]; then
        if enforcement_ready; then
            lock_firewall
            if ! firewall_setup; then MODE=dry-run; firewall_clear || true; log_event ERROR 'Firewall setup failed. Continuing in DRY-RUN.'; fi
            unlock_firewall
        else MODE=dry-run; cleanup_firewall || true; log_event WARN 'Enforcement prerequisites unmet. Continuing in DRY-RUN.'; fi
    else cleanup_firewall; fi
    printf '%s\n' "$MODE" > "$STATE_DIR/daemon-mode"
    DAEMON_TEMP=$(mktemp -d "$RUNTIME_DIR/session.XXXXXX")
    materialize_engine "$DAEMON_TEMP/detector.awk"
    mkfifo "$DAEMON_TEMP/input" "$DAEMON_TEMP/output"
    exec 7<>"$DAEMON_TEMP/output"
    GEO_ACTIVE=no GEO_COUNT=0 GEO_PERIOD=0
    if [[ $ENABLE_GEOIP == yes ]]; then
        if command -v mmdblookup >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then GEO_ACTIVE=yes
        else log_event WARN 'Optional mmdblookup/timeout unavailable; GeoIP scoring disabled.'; fi
    fi
    touch "$STATE_DIR/geo.tsv"
    awk -v since="$(($(date +%s)-STATE_RETENTION))" 'NF>=4 && $4>=since {print}' "$STATE_DIR/geo.tsv" | tail -n 5000 > "$STATE_DIR/geo.new"
    mv "$STATE_DIR/geo.new" "$STATE_DIR/geo.tsv"
    # Native tail -F follows names through rename/recreate and copytruncate.
    tail -n 0 -F -- "${LOG_ARRAY[@]}" > "$DAEMON_TEMP/input" 2>> "$APP_LOG" & TAIL_PID=$!
    ENGINE_EXEC=1 run_engine "$DAEMON_TEMP/detector.awk" "${LOG_ARRAY[0]}" "$STATE_DIR/geo.tsv" "$WARMUP_TIME" 1 < "$DAEMON_TEMP/input" > "$DAEMON_TEMP/output" & ENGINE_PID=$!
    (while sleep 1; do printf '@BM_TICK\t%s\n' "$(date +%s)"; done) > "$DAEMON_TEMP/input" & TICK_PID=$!
    log_event INFO "Daemon started; mode=$MODE web=$DETECTED_WEB_SERVER logs=${#LOG_ARRAY[@]} backend=$FW_BACKEND; headers never trusted."
    local kind a b c d last_sweep=0 now
    while :; do
        if IFS=$'\t' read -r -t 2 -u 7 kind a b c d; then
            case $kind in
                EVENT) log_event SECURITY "Score=$a scope=$b; $c";;
                CANDIDATE) mitigate "$a" "$b" "$c" "$d" || log_event ERROR 'Candidate could not be applied; fail-open.';;
                LOOKUP) geo_lookup "$a";;
                STATS) printf '%s\n' "$a" > "$STATE_DIR/stats.new"; mv "$STATE_DIR/stats.new" "$STATE_DIR/stats.json";;
            esac
        fi
        kill -0 "$TAIL_PID" 2>/dev/null && kill -0 "$ENGINE_PID" 2>/dev/null && kill -0 "$TICK_PID" 2>/dev/null || { error 'Log follower or detector exited unexpectedly.'; return 1; }
        now=$(date +%s)
        if (( now-last_sweep >= 30 )); then
            last_sweep=$now
            if [[ -f $STATE_DIR/active.tsv ]]; then
                lock_firewall
                awk -v since="$((now-3600))" '$2>=since' "$STATE_DIR/active.tsv" | tail -n 5000 > "$STATE_DIR/active.new"
                mv "$STATE_DIR/active.new" "$STATE_DIR/active.tsv"; unlock_firewall
            fi
        fi
    done
}
analyze_file() {
    [[ $# == 1 && -f $1 && -r $1 ]] || { error 'Usage: bot-mitigation analyze /absolute/path/to/access.log'; return 2; }
    load_config
    local temp rc=0 kind a b c d
    temp=$(mktemp -d "${TMPDIR:-/tmp}/bot-mitigation-analyze.XXXXXX")
    materialize_engine "$temp/detector.awk"
    run_engine "$temp/detector.awk" "$1" '' 0 0 < "$1" > "$temp/result" || rc=$?
    while IFS=$'\t' read -r kind a b c d; do
        case $kind in
            EVENT) printf 'Risk score: %s\nScope: %s\nReasons: %s\n' "$a" "$b" "$c";;
            CANDIDATE) printf '[DRY-RUN] Correlated candidate %s; score=%s; scope=%s; %s\n' "$a" "$b" "$c" "$d";;
            STATS) printf 'Stats: %s\n' "$a";;
        esac
    done < "$temp/result"
    rm -rf "$temp"
    return "$rc"
}
unblock_target() {
    local requested=$1 target expiry temp rc=0
    valid_target "$requested" || { error 'Invalid IP/CIDR.'; return 2; }
    requested=$(canonical_target "$requested")
    lock_firewall
    temp=$(mktemp "$STATE_DIR/.active.XXXXXX")
    if [[ -f $STATE_DIR/active.tsv ]]; then
        while read -r target expiry; do
            if network_tool overlap "$target" "$requested"; then
                if ! firewall_remove "$target"; then rc=1; printf '%s\t%s\n' "$target" "$expiry" >> "$temp"; fi
            else printf '%s\t%s\n' "$target" "$expiry" >> "$temp"; fi
        done < "$STATE_DIR/active.tsv"
    fi
    if ! firewall_remove "$requested"; then rc=1; fi
    if (( rc == 0 )); then mv "$temp" "$STATE_DIR/active.tsv"; else rm -f "$temp"; fi
    unlock_firewall
    (( rc == 0 )) || { error 'Some matching blocks could not be removed.'; return 1; }
    log_event INFO "Administrator override: unblocked $requested and overlapping tracked penalties."
    say "Unblocked: $requested"
}
whitelist_command() {
    local action=${1:-} target=${2:-} temp line
    case $action in
        list) [[ ! -f $CONFIG_DIR/whitelist ]] || cat "$CONFIG_DIR/whitelist"; return 0;;
        add|remove) [[ $# == 2 ]] || { error 'Usage: whitelist add|remove IP-or-CIDR'; return 2; };;
        *) error 'Usage: whitelist add|remove|list [IP-or-CIDR]'; return 2;;
    esac
    require_root; secure_dirs
    valid_target "$target" || { error 'Invalid whitelist IP/CIDR.'; return 2; }
    target=$(canonical_target "$target")
    lock_firewall
    temp=$(mktemp "$CONFIG_DIR/.whitelist.XXXXXX")
    if [[ -f $CONFIG_DIR/whitelist ]]; then
        while IFS= read -r line; do [[ $line == "$target" ]] || printf '%s\n' "$line" >> "$temp"; done < "$CONFIG_DIR/whitelist"
    fi
    [[ $action != add ]] || printf '%s\n' "$target" >> "$temp"
    chmod 600 "$temp"; mv "$temp" "$CONFIG_DIR/whitelist"
    # Clear all penalties so an older CIDR cannot continue covering a new allowlist.
    local rc=0
    if [[ $action == add ]]; then
        firewall_clear || rc=1
        if (( rc == 0 )); then
            rm -f "$STATE_DIR/active.tsv"
            if [[ $MODE == enforce && ! -f $STATE_DIR/emergency-disabled ]]; then firewall_setup || rc=1; fi
        fi
    fi
    unlock_firewall
    log_event INFO "Whitelist $action: $target; administrator override."
    (( rc == 0 )) || { error 'Allowlist saved, but firewall reconciliation needs attention. Run emergency-disable.'; return 1; }
    say "Whitelist $action: $target"
}
blacklist_command() {
    local action=${1:-} target=${2:-}
    case $action in
        list) firewall_list;;
        remove) [[ $# == 2 ]] || return 2; require_root; secure_dirs; unblock_target "$target";;
        add)
            [[ $# == 2 ]] || { error 'Usage: blacklist add IP-or-CIDR'; return 2; }
            require_root; secure_dirs
            target_is_safe "$target" || { error 'Target invalid, protected, nonpublic, allowlisted, or too broad (minimum /24 IPv4, /64 IPv6).'; return 2; }
            if [[ $MODE == enforce ]]; then
                enforcement_ready; lock_firewall
                if ! firewall_setup; then unlock_firewall; return 1; fi
                unlock_firewall
            fi
            mitigate "$target" 100 manual 'Administrator-requested temporary penalty' yes
            [[ $MODE != dry-run ]] || say 'DRY-RUN: no firewall changes made.';;
        *) error 'Usage: blacklist add|remove|list [IP-or-CIDR]'; return 2;;
    esac
}
status_command() {
    platform_detect; discover_logs; web_detect; firewall_detect
    local active=0 expired=0 now service=stopped startup=disabled actual_mode=$MODE
    service_action is-active >/dev/null 2>&1 && service=running
    service_action is-enabled >/dev/null 2>&1 && startup=enabled
    [[ ! -f $STATE_DIR/emergency-disabled ]] || actual_mode='EMERGENCY DISABLED'
    now=$(date +%s)
    if [[ -f $STATE_DIR/active.tsv ]]; then
        read -r active expired < <(awk -v now="$now" '$2>now {a++} $2<=now && $2>=now-3600 {e++} END {print a+0,e+0}' "$STATE_DIR/active.tsv")
    fi
    printf 'Linux Bot Mitigation\nVersion: %s\nService: %s\nStartup: %s\nConfigured mode: %s\nWeb server binaries/config: %s\nLogs selected: %s\nFirewall backend: %s\nGeoIP configured: %s\nTracked unexpired penalties: %s\nRecently expired penalties: %s\n' "$VERSION" "$service" "$startup" "$actual_mode" "$DETECTED_WEB_SERVER" "${#LOG_ARRAY[@]}" "$FW_BACKEND" "$ENABLE_GEOIP" "$active" "$expired"
    if [[ -f $STATE_DIR/daemon-mode ]]; then printf 'Daemon effective mode: %s\n' "$(cat "$STATE_DIR/daemon-mode")"; fi
    [[ ! -f $STATE_DIR/stats.json ]] || cat "$STATE_DIR/stats.json"
    [[ $actual_mode != enforce || -f $STATE_DIR/firewall.owner ]] || say 'Enforcement has no active owned firewall objects; consult logs/doctor.'
}
doctor_command() {
    local rc=0 file
    if load_config; then say 'Configuration: valid'; else rc=1; say 'Configuration: INVALID (read-only diagnosis; no settings changed)'; defaults; fi
    platform_detect; web_detect; discover_logs
    printf 'OS: %s\nPackage manager: %s\nInit: %s\nWeb-server binaries/config: %s\n' "$OS_ID" "$PACKAGE_MANAGER" "$SERVICE_MANAGER" "$DETECTED_WEB_SERVER"
    say 'IPv4/IPv6 parsing: supported (common/combined logs). Header fields: never trusted.'
    say "Client IP mode: $LOG_IP_MODE; server-wide firewall acknowledgment: $FIREWALL_SCOPE"
    [[ $LOG_IP_MODE == direct ]] || say 'WARNING: confirm socket-peer logging before enforcement; CDN/real-IP rewriting requires observation mode.'
    [[ -z $TRUSTED_PROXY_RANGES ]] || say 'Trusted proxy ranges are protected from bans; forwarded client IPs are not firewall targets.'
    if ((${#LOG_ARRAY[@]} == 0)); then say 'WARNING: no readable access logs discovered.'; rc=1; fi
    for file in "${LOG_ARRAY[@]}"; do
        printf 'Readable access log: %s\n' "$file"
        tail -n 5 -- "$file" | awk 'BEGIN{n=0;c=0} /\[[0-9][0-9]\/[A-Za-z]+\/[0-9]+:/ && /"[A-Z]+ / {n++; if(split($0,a,"\"")>=6)c++} END{printf "  Recognizable sampled requests: %d; combined referrer/UA samples: %d\n",n,c; if(!n) print "  WARNING: empty/unsupported sample; use analyze for validation."}'
    done
    say 'Scope: each log is isolated unless a valid virtual-host prefix is present. Shared common logs cannot attribute domains. Firewall penalties affect every hosted domain on protected ports.'
    if [[ $ENABLE_GEOIP == yes ]]; then
        command -v mmdblookup >/dev/null 2>&1 || say 'WARNING: mmdblookup absent; GeoIP disabled at runtime.'
        for file in "$GEOIP_COUNTRY_DB" "$GEOIP_ASN_DB"; do
            [[ -z $file ]] || { [[ -r $file ]] && say "GeoIP DB readable: $file" || say "WARNING: GeoIP DB unreadable: $file"; }
        done
    fi
    firewall_doctor || rc=1
    service_action is-active >/dev/null 2>&1 && say 'Service: running' || say 'Service: stopped'
    [[ ! -f $STATE_DIR/emergency-disabled ]] || say 'Emergency lock: ACTIVE; new bans disabled.'
    [[ ! -f $STATE_DIR/firewall.owner || -f $STATE_DIR/installed ]] || { say 'WARNING: ownership manifest exists without installation marker.'; rc=1; }
    return "$rc"
}
help_command() {
cat <<'BOT_HELP'
Linux Bot Mitigation — adaptive Layer 7 bot mitigation and HTTP burst protection.
Usage: bot-mitigation COMMAND [ARGUMENTS]
  install [--enforce]       Install/upgrade with rollback; dry-run on fresh install
  status | stats           Service/detection status and bounded statistics
  start | stop | restart   Manage systemd/OpenRC service (stop clears owned blocks)
  logs                     Follow security log (Ctrl-C exits)
  dry-run on|off           Enable observation, or explicitly enable enforcement
  enforce on|off           Enable enforcement, or clear blocks and observe
  whitelist add|remove IP-or-CIDR | whitelist list
  blacklist add|remove IP-or-CIDR | blacklist list
                           All blacklist additions are temporary and honor mode
  unblock IP-or-CIDR       Remove matching and overlapping tracked penalties
  emergency-disable       Stop mitigation, lock out new bans, remove owned rules
  emergency-enable        Clear emergency lock and start in DRY-RUN only
  config                   Show config path and redacted configuration
  doctor                   Read-only diagnostics
  self-test                Synthetic detector/safety tests; no firewall changes
  analyze FILE             Offline log simulation; no firewall changes
  update                   Explain verified manual upgrade (no remote execution)
  uninstall [--purge]      Remove application; --purge also removes config/logs
  version | help
Never treats country, missing referrer, or a crawler User-Agent alone as proof.
BOT_HELP
}
dispatch() {
    local command=${1:-help}; [[ $# == 0 ]] || shift
    defaults
    case $command in
        help|-h|--help) help_command; return;;
        version|--version) say "$VERSION"; return;;
        self-test) detector_self_test; safety_self_test; return;;
        install) install_app "$@"; return;;
        daemon) daemon_run; return;;
        cleanup) cleanup_firewall; return;;
        emergency-disable) emergency_disable; return;;
        uninstall) uninstall_app "$@"; return;;
        doctor) doctor_command; return;;
        analyze|simulate) analyze_file "$@"; return;;
        update) say 'Automatic remote updates are disabled. Download a pinned release over HTTPS, verify its published digest/signature through a trusted channel, inspect it, run bash -n script.sh and bash script.sh self-test, then sudo bash script.sh install. Installation preserves configuration/whitelists and backs up the executable with rollback on failure.'; return;;
    esac
    if ! load_config; then
        # Read-only commands never mutate state. Mutating commands refuse invalid config.
        case $command in enforce|dry-run|start|restart|blacklist)
            require_root || return
            if [[ -d $STATE_DIR ]]; then : > "$STATE_DIR/emergency-disabled"; cleanup_firewall || true; fi;;
        esac
        return 2
    fi
    case $command in
        status) status_command;;
        stats) [[ ! -f $STATE_DIR/stats.json ]] || cat "$STATE_DIR/stats.json"; status_command;;
        config) say "Configuration: $CONFIG_FILE"; if [[ -f $CONFIG_FILE ]]; then awk '/^[[:space:]]*MAXMIND_LICENSE_KEY[[:space:]]*=/ {$0="MAXMIND_LICENSE_KEY=\"[redacted]\""} {print}' "$CONFIG_FILE"; else config_template; fi;;
        logs) [[ -r $APP_LOG ]] || { error "Cannot read $APP_LOG; try sudo, or install first."; return 1; }; tail -n 100 -F -- "$APP_LOG";;
        enforce|dry-run)
            [[ $# == 1 ]] || { error 'Specify on or off.'; return 2; }
            case "$command:$1" in enforce:on|dry-run:off) set_mode enforce;; enforce:off|dry-run:on) set_mode dry-run;; *) error 'Specify on or off.'; return 2;; esac;;
        emergency-enable)
            require_root; require_linux; secure_dirs; platform_detect
            cleanup_firewall; set_config MODE dry-run
            rm -f "$STATE_DIR/emergency-disabled"
            service_action start
            say 'Emergency lock cleared; DRY-RUN active. Enforcement requires a separate enforce on.';;
        start|restart|stop)
            require_root; require_linux; platform_detect
            if [[ $command == stop ]]; then
                secure_dirs; : > "$STATE_DIR/emergency-disabled"
                service_action stop; cleanup_firewall
                say 'Stopped and fail-open. Run emergency-enable to resume observation.'
            else service_action "$command"; fi;;
        whitelist) whitelist_command "$@";;
        blacklist) blacklist_command "$@";;
        unblock) [[ $# == 1 ]] || return 2; require_root; secure_dirs; unblock_target "$1";;
        *) error "Unknown command: $command"; help_command; return 2;;
    esac
}


network_awk() {
cat <<'BOT_NETWORK_AWK'
# Strict address validation without floating-point 128-bit arithmetic.
# Every address is represented as 16-bit words; all arithmetic is exact.
function clear(a, k) { for (k in a) delete a[k] }
function v4(s, a,    n,i,p) {
    n=split(s,p,"."); if(n!=4) return 0
    for(i=1;i<=4;i++) {
        if(p[i]!~/^[0-9]+$/ || length(p[i])>3 || p[i]+0>255 || (length(p[i])>1 && substr(p[i],1,1)=="0")) return 0
    }
    a[1]=p[1]*256+p[2]; a[2]=p[3]*256+p[4]; return 1
}
function hex(s,    i,n,c) {
    n=0
    for(i=1;i<=length(s);i++) { c=index("0123456789abcdef",tolower(substr(s,i,1)))-1; if(c<0)return -1; n=n*16+c }
    return n
}
function parse(s,a,    part,n,ip,pfx,pos,left,right,nl,nr,i,w,l,r,v,tail,j,words) {
    clear(a)
    if(s=="" || s~/[^0-9a-fA-F:.\/]/) return 0
    n=split(s,part,"/"); if(n>2)return 0
    ip=part[1]; a["hadprefix"]=(n==2)
    if(n==2 && (part[2]!~/^[0-9]+$/ || length(part[2])>3 || (length(part[2])>1 && substr(part[2],1,1)=="0")))return 0
    if(index(ip,":")==0) {
        if(!v4(ip,a))return 0
        a["family"]=4; a["words"]=2; pfx=(n==2?part[2]+0:32); if(pfx>32)return 0
    } else {
        if(ip~/\./) {
            # IPv4 tails occupy exactly two IPv6 words.
            j=0; for(i=1;i<=length(ip);i++)if(substr(ip,i,1)==":")j=i
            tail=substr(ip,j+1); if(!v4(tail,v))return 0
            ip=substr(ip,1,j) sprintf("%x:%x",v[1],v[2])
        }
        pos=index(ip,"::")
        if(pos) {
            left=substr(ip,1,pos-1); right=substr(ip,pos+2)
            if(index(right,"::") || left~/:$/ || right~/^:/)return 0
            nl=(left==""?0:split(left,l,":")); nr=(right==""?0:split(right,r,":"))
            if(nl+nr>=8)return 0
            for(i=1;i<=nl;i++)a[i]=l[i]
            for(i=nl+1;i<=8-nr;i++)a[i]="0"
            for(i=1;i<=nr;i++)a[8-nr+i]=r[i]
        } else {
            if(split(ip,words,":")!=8)return 0
            for(i=1;i<=8;i++)a[i]=words[i]
        }
        for(i=1;i<=8;i++) {
            if(a[i]=="" || length(a[i])>4 || a[i]!~/^[0-9a-fA-F]+$/)return 0
            a[i]=hex(a[i]); if(a[i]<0)return 0
        }
        a["family"]=6; a["words"]=8; pfx=(n==2?part[2]+0:128); if(pfx>128)return 0
    }
    a["prefix"]=pfx
    # Normalize CIDR host bits instead of passing ambiguous ranges to firewalls.
    for(i=1;i<=a["words"];i++) {
        w=pfx-(i-1)*16
        if(w<=0)a[i]=0
        else if(w<16)a[i]=int(a[i]/(2^(16-w)))*(2^(16-w))
    }
    return 1
}
function overlap(a,b,    p,i,w,d) {
    if(a["family"]!=b["family"])return 0
    p=(a["prefix"]<b["prefix"]?a["prefix"]:b["prefix"])
    for(i=1;i<=a["words"];i++) {
        w=p-(i-1)*16; if(w<=0)break; d=(w>=16?1:2^(16-w))
        if(int(a[i]/d)!=int(b[i]/d))return 0
    }
    return 1
}
function canon(a,    s,i) {
    if(a["family"]==4)s=sprintf("%d.%d.%d.%d",int(a[1]/256),a[1]%256,int(a[2]/256),a[2]%256)
    else { s=""; for(i=1;i<=8;i++)s=s (i==1?"":":") sprintf("%04x",a[i]) }
    return s (a["hadprefix"]?"/" a["prefix"]:"")
}
function trusted_overlap(list,    n,t,i,b) {
    n=split(list,t,/[ \t\r\n]+/)
    for(i=1;i<=n;i++)if(t[i]!="") {
        # A malformed protection entry closes the mitigation path, never opens it.
        if(!parse(t[i],b) || overlap(address,b))return 1
    }
    return 0
}
BEGIN {
    if(!parse(target,address))exit 1
    if(action=="valid")exit 0
    if(action=="canonical") { print canon(address); exit 0 }
    if(action=="family") { print address["family"]; exit 0 }
    if(action=="overlap" || action=="contains") {
        if(!parse(other,second))exit 1
        if(action=="contains" && address["prefix"]>second["prefix"])exit 1
        exit !overlap(address,second)
    }
    if(action!="safe")exit 1
    if(address["family"]==4) {
        if(address["prefix"]<24)exit 1
        special="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4"
    } else {
        if(address["prefix"]<64)exit 1
        # Restrict to ordinary global unicast, excluding special-purpose space.
        parse("2000::/3",second); if(!overlap(address,second))exit 1
        special="2001::/23 2001:db8::/32 2002::/16 3fff::/20"
    }
    if(trusted_overlap(special) || trusted_overlap(trusted))exit 1
    if(allow_file!="") {
        while((read_status=(getline line < allow_file))>0) {
            sub(/#.*/,"",line)
            if(trusted_overlap(line)) { close(allow_file); exit 1 }
        }
        close(allow_file)
        if(read_status<0)exit 1
    }
    exit 0
}

BOT_NETWORK_AWK
}

# Firewall calls are serialized by the caller's firewall.lock. No firewall
# objects are touched by detection, simulation, or read-only commands.
network_tool() {
    local action=$1 target=${2-} other=${3-} allow_file=''
    case "$target" in ''|*[!0-9a-fA-F.:/]*) return 1;; esac
    case "$other" in *[!0-9a-fA-F.:/]*) return 1;; esac
    if [[ -e "${CONFIG_DIR}/whitelist" ]]; then
        [[ -f "${CONFIG_DIR}/whitelist" && -r "${CONFIG_DIR}/whitelist" ]] || return 1
        allow_file="${CONFIG_DIR}/whitelist"
    fi
    local -a args=(-v "action=$action" -v "target=$target" -v "other=$other"
        -v "trusted=${TRUSTED_IPS-} ${TRUSTED_NETWORKS-} ${TRUSTED_PROXY_RANGES-}" -v "allow_file=$allow_file")
    if [[ -n "${NETWORK_AWK_PATH-}" ]]; then
        awk "${args[@]}" -f "$NETWORK_AWK_PATH"
    else
        awk "${args[@]}" "$(network_awk)"
    fi
}
valid_target() { network_tool valid "${1-}"; }
canonical_target() { network_tool canonical "${1-}"; }
target_is_safe() { network_tool safe "${1-}"; }

fw_warn() { printf 'Firewall: %s\n' "$*" >&2; }
fw_ports() {
    local p result='' count=0
    local -a port_values=()
    read -r -a port_values <<< "${PROTECTED_PORTS-}"
    for p in "${port_values[@]}"; do
        case "$p" in ''|*[!0-9]*|0*) return 1;; esac
        [[ ${#p} -le 5 ]] && (( p >= 1 && p <= 65535 )) || return 1
        # SSH is deliberately unavailable through this HTTP mitigation tool.
        [[ "$p" != 22 ]] || return 1
        result="${result}${result:+,}$p"; count=$((count+1))
    done
    (( count > 0 && count <= 32 )) || return 1
    printf '%s\n' "$result"
}
fw_load_owner() {
    local extra=''
    [[ -f "$STATE_DIR/firewall.owner" && ! -L "$STATE_DIR/firewall.owner" ]] || return 1
    IFS=' ' read -r FW_OWN_BACKEND FW_TOKEN FW_PORTS FW_FAMILIES extra < "$STATE_DIR/firewall.owner" || return 1
    [[ -z "$extra" && ${#FW_TOKEN} == 8 ]] || return 1
    case "$FW_TOKEN" in *[!0-9a-f]*) return 1;; esac
    case "$FW_OWN_BACKEND" in nftables|iptables) ;; *) return 1;; esac
    case "$FW_PORTS" in ''|*[!0-9,]*|,*|*,|*,,*) return 1;; esac
    case "$FW_FAMILIES" in 4|4,6) ;; *) return 1;; esac
    FW_MARKER="bot-mitigation:$FW_TOKEN"
    FW_CHAIN="BOT_MITIGATION_$FW_TOKEN"
    FW_SET4="bot_mitigation4_$FW_TOKEN"
    FW_SET6="bot_mitigation6_$FW_TOKEN"
}
fw_save_owner() {
    local temp
    temp=$(mktemp "$STATE_DIR/.firewall.owner.XXXXXX") || return 1
    if ! printf '%s %s %s %s\n' "$FW_OWN_BACKEND" "$FW_TOKEN" "$FW_PORTS" "$FW_FAMILIES" > "$temp" ||
        ! chmod 600 "$temp" || ! mv -f -- "$temp" "$STATE_DIR/firewall.owner"; then
        rm -f -- "$temp"; return 1
    fi
    fw_load_owner
}
firewall_detect() {
    FW_BACKEND=none
    case "${FIREWALL_BACKEND:-auto}" in
        none) return 0;;
        auto)
            if command -v nft >/dev/null 2>&1; then FW_BACKEND=nftables
            elif command -v iptables >/dev/null 2>&1 && command -v ipset >/dev/null 2>&1; then FW_BACKEND=iptables
            fi;;
        nftables) command -v nft >/dev/null 2>&1 && FW_BACKEND=nftables;;
        iptables) if command -v iptables >/dev/null 2>&1 && command -v ipset >/dev/null 2>&1; then FW_BACKEND=iptables; fi;;
        *) return 1;;
    esac
    return 0
}
fw_nft_owned() {
    local listing
    listing=$(nft list table inet bot_mitigation 2>/dev/null) || return 1
    awk -v marker="\"$FW_MARKER\"" '$1=="comment" && $2==marker {found=1} END {exit !found}' <<< "$listing"
}
fw_nft_setup() {
    local listing rules
    # A successful global listing distinguishes absent objects from denied access.
    listing=$(nft list tables 2>/dev/null) || { fw_warn 'nftables unavailable or permission denied; remaining fail-open.'; return 1; }
    if [[ "$listing" == *'table inet bot_mitigation'* ]]; then
        fw_nft_owned || { fw_warn 'Reserved nftables table has no matching ownership marker; refusing changes.'; return 1; }
        nft list set inet bot_mitigation blocked4 >/dev/null 2>&1 &&
            nft list set inet bot_mitigation blocked6 >/dev/null 2>&1 || return 1
        return 0
    fi
    # nft submits the whole batch atomically. create (not add) rejects collisions.
    rules="create table inet bot_mitigation { comment \"$FW_MARKER\"; }
add set inet bot_mitigation blocked4 { type ipv4_addr; flags interval,timeout; timeout 5m; size 65536; }
add set inet bot_mitigation blocked6 { type ipv6_addr; flags interval,timeout; timeout 5m; size 65536; }
add chain inet bot_mitigation input { type filter hook input priority -10; policy accept; }
add rule inet bot_mitigation input ip saddr @blocked4 tcp dport { $FW_PORTS } counter drop comment \"$FW_MARKER\"
add rule inet bot_mitigation input ip saddr @blocked4 udp dport { $FW_PORTS } counter drop comment \"$FW_MARKER\"
add rule inet bot_mitigation input ip6 saddr @blocked6 tcp dport { $FW_PORTS } counter drop comment \"$FW_MARKER\"
add rule inet bot_mitigation input ip6 saddr @blocked6 udp dport { $FW_PORTS } counter drop comment \"$FW_MARKER\""
    nft -f - <<< "$rules" || { fw_warn 'Atomic nftables setup failed; no partial table was committed.'; return 1; }
}
fw_ipt_chain_owned() {
    local command=$1 listing line
    listing=$("$command" -w 5 -S "$FW_CHAIN" 2>/dev/null) || return 1
    # Empty, token-named chains may result from an interrupted creation. The
    # manifest predates creation; nonempty chains must have only marked rules.
    while IFS= read -r line; do
        case "$line" in
            "-N $FW_CHAIN") ;;
            "-A $FW_CHAIN "*) [[ "$line" == *"--comment $FW_MARKER "* || "$line" == *"--comment \"$FW_MARKER\" "* ]] || return 1;;
            '') ;;
            *) return 1;;
        esac
    done <<< "$listing"
}
fw_ipt_family_setup() {
    local command=$1 family=$2 setname=$3 port proto
    local -a ports=()
    "$command" -w 5 -S INPUT >/dev/null 2>&1 || return 1
    # Existing objects are never adopted. Existing complete setup is handled
    # before entering this function; token collisions therefore fail safely.
    if "$command" -w 5 -S "$FW_CHAIN" >/dev/null 2>&1 || ipset list "$setname" >/dev/null 2>&1; then
        fw_warn "Refusing existing firewall objects for $command; run emergency-disable to reconcile owned state."; return 1
    fi
    ipset create "$setname" hash:net family "$family" timeout 300 maxelem 65536 || return 1
    "$command" -w 5 -N "$FW_CHAIN" || return 1
    "$command" -w 5 -A "$FW_CHAIN" -m set --match-set "$setname" src -m comment --comment "$FW_MARKER" -j DROP || return 1
    "$command" -w 5 -A "$FW_CHAIN" -m comment --comment "$FW_MARKER" -j RETURN || return 1
    IFS=',' read -r -a ports <<< "$FW_PORTS"
    for port in "${ports[@]}"; do
        for proto in tcp udp; do
            "$command" -w 5 -I INPUT 1 -p "$proto" --dport "$port" -m comment --comment "$FW_MARKER" -j "$FW_CHAIN" || return 1
        done
    done
}
fw_ipt_family_ready() {
    local command=$1 setname=$2 port proto
    local -a ports=()
    fw_ipt_chain_owned "$command" && ipset list "$setname" >/dev/null 2>&1 || return 1
    "$command" -w 5 -C "$FW_CHAIN" -m set --match-set "$setname" src -m comment --comment "$FW_MARKER" -j DROP >/dev/null 2>&1 || return 1
    "$command" -w 5 -C "$FW_CHAIN" -m comment --comment "$FW_MARKER" -j RETURN >/dev/null 2>&1 || return 1
    IFS=',' read -r -a ports <<< "$FW_PORTS"
    for port in "${ports[@]}"; do
        for proto in tcp udp; do
            "$command" -w 5 -C INPUT -p "$proto" --dport "$port" -m comment --comment "$FW_MARKER" -j "$FW_CHAIN" >/dev/null 2>&1 || return 1
        done
    done
}
fw_ipt_family_clear() {
    local command=$1 setname=$2 port proto failed=0 listing
    local -a ports=()
    command -v "$command" >/dev/null 2>&1 || return 1
    "$command" -w 5 -S INPUT >/dev/null 2>&1 || return 1
    if "$command" -w 5 -S "$FW_CHAIN" >/dev/null 2>&1; then
        # Even if an administrator added unrelated rules, detach our exact
        # marked hooks immediately; those extra rules themselves remain intact.
        fw_ipt_chain_owned "$command" || fw_warn "Unrecognized rules in $FW_CHAIN; leaving those rules intact."
        IFS=',' read -r -a ports <<< "$FW_PORTS"
        for port in "${ports[@]}"; do
            for proto in tcp udp; do
                while "$command" -w 5 -C INPUT -p "$proto" --dport "$port" -m comment --comment "$FW_MARKER" -j "$FW_CHAIN" >/dev/null 2>&1; do
                    "$command" -w 5 -D INPUT -p "$proto" --dport "$port" -m comment --comment "$FW_MARKER" -j "$FW_CHAIN" || { failed=1; break; }
                done
            done
        done
        # Never flush. Delete only exact rules whose contents we created.
        while "$command" -w 5 -C "$FW_CHAIN" -m set --match-set "$setname" src -m comment --comment "$FW_MARKER" -j DROP >/dev/null 2>&1; do
            "$command" -w 5 -D "$FW_CHAIN" -m set --match-set "$setname" src -m comment --comment "$FW_MARKER" -j DROP || { failed=1; break; }
        done
        while "$command" -w 5 -C "$FW_CHAIN" -m comment --comment "$FW_MARKER" -j RETURN >/dev/null 2>&1; do
            "$command" -w 5 -D "$FW_CHAIN" -m comment --comment "$FW_MARKER" -j RETURN || { failed=1; break; }
        done
        "$command" -w 5 -X "$FW_CHAIN" || failed=1
    fi
    # A set whose token matches the root-only manifest is application-owned.
    # destroy refuses sets still referenced by any remaining rule.
    listing=$(ipset list -name 2>/dev/null) || return 1
    if [[ $'\n'"$listing"$'\n' == *$'\n'"$setname"$'\n'* ]]; then
        # Empty our set even if an external rule prevents its destruction.
        ipset flush "$setname" || failed=1
        ipset destroy "$setname" || failed=1
    fi
    return "$failed"
}
firewall_setup() {
    local ports old_backend='' new_owner=no failed=0
    [[ "${MODE-}" == enforce && ! -e "$STATE_DIR/emergency-disabled" ]] || { fw_warn 'Enforcement is disabled.'; return 1; }
    ports=$(fw_ports) || { fw_warn 'Invalid protected web ports (SSH port 22 is forbidden).'; return 1; }
    firewall_detect || return 1
    [[ "$FW_BACKEND" != none ]] || { fw_warn 'No usable firewall backend; remaining fail-open.'; return 1; }
    if [[ -e "$STATE_DIR/firewall.owner" ]]; then
        fw_load_owner || { fw_warn 'Invalid ownership manifest; refusing firewall changes.'; return 1; }
        [[ "$FW_OWN_BACKEND" == "$FW_BACKEND" && "$FW_PORTS" == "$ports" ]] || {
            fw_warn 'Backend or ports changed: disable enforcement before applying the new configuration.'; return 1;
        }
    else
        # Refuse the reserved static name before writing any ownership claim.
        if [[ "$FW_BACKEND" == nftables ]] && nft list table inet bot_mitigation >/dev/null 2>&1; then
            fw_warn 'Reserved nftables table already exists without an ownership manifest.'; return 1
        fi
        FW_OWN_BACKEND=$FW_BACKEND
        FW_TOKEN=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n') || return 1
        FW_PORTS=$ports; FW_FAMILIES=4,6
        if [[ "$FW_BACKEND" == iptables ]]; then
            if ! command -v ip6tables >/dev/null 2>&1 || ! ip6tables -w 5 -S INPUT >/dev/null 2>&1; then
                FW_FAMILIES=4; fw_warn 'IPv6 iptables is unavailable; IPv6 will remain fail-open.'
            fi
            # Dynamic names include a newly generated token, still checked before claiming them.
            if ipset list "bot_mitigation4_$FW_TOKEN" >/dev/null 2>&1 || ipset list "bot_mitigation6_$FW_TOKEN" >/dev/null 2>&1 ||
                iptables -w 5 -S "BOT_MITIGATION_$FW_TOKEN" >/dev/null 2>&1 ||
                { command -v ip6tables >/dev/null 2>&1 && ip6tables -w 5 -S "BOT_MITIGATION_$FW_TOKEN" >/dev/null 2>&1; }; then
                fw_warn 'Firewall name collision; refusing setup.'; return 1
            fi
        fi
        fw_save_owner || return 1; new_owner=yes
    fi
    if [[ "$FW_BACKEND" == nftables ]]; then
        if fw_nft_setup; then return 0; fi
        # Failed nft creation is atomic; retain existing ownership for diagnostics.
        [[ "$new_owner" == no ]] || rm -f -- "$STATE_DIR/firewall.owner"
        return 1
    fi
    if ! fw_ipt_family_ready iptables "$FW_SET4"; then
        fw_ipt_family_setup iptables inet "$FW_SET4" || failed=1
    fi
    if [[ "$FW_FAMILIES" == 4,6 && "$failed" == 0 ]] && ! fw_ipt_family_ready ip6tables "$FW_SET6"; then
        fw_ipt_family_setup ip6tables inet6 "$FW_SET6" || failed=1
    fi
    if [[ "$failed" != 0 ]]; then
        fw_warn 'iptables setup failed; rolling back application-owned objects.'
        firewall_clear || fw_warn 'Rollback requires attention; ownership manifest retained.'
        return 1
    fi
}
firewall_add() {
    local target=${1-} duration=${2-} family setname rules
    [[ "${MODE-}" == enforce && ! -e "$STATE_DIR/emergency-disabled" ]] || return 1
    case "$duration" in ''|*[!0-9]*|0*) return 1;; esac
    [[ ${#duration} -le 6 ]] && (( duration > 0 && duration <= 86400 )) || return 1
    target_is_safe "$target" || { fw_warn 'Target rejected by protected-network checks.'; return 1; }
    target=$(canonical_target "$target") || return 1
    family=$(network_tool family "$target") || return 1
    fw_load_owner || return 1
    case "$FW_OWN_BACKEND" in
        nftables)
            fw_nft_owned || return 1
            setname="blocked$family"; rules=''
            # Exact replacement is atomic. If the element expires between lookup
            # and deletion, the batch fails open and a later decision can retry.
            if nft get element inet bot_mitigation "$setname" "{ $target }" >/dev/null 2>&1; then
                rules="delete element inet bot_mitigation $setname { $target }"$'\n'
            fi
            rules="${rules}add element inet bot_mitigation $setname { $target timeout ${duration}s }"
            nft -f - <<< "$rules";;
        iptables)
            if [[ "$family" == 6 ]]; then
                [[ "$FW_FAMILIES" == 4,6 ]] || return 1
                setname=$FW_SET6; fw_ipt_chain_owned ip6tables || return 1
            else setname=$FW_SET4; fw_ipt_chain_owned iptables || return 1; fi
            ipset -exist add "$setname" "$target" timeout "$duration";;
        *) return 1;;
    esac
}
firewall_remove() {
    local target family setname
    target=$(canonical_target "${1-}") || return 1
    family=$(network_tool family "$target") || return 1
    [[ -e "$STATE_DIR/firewall.owner" ]] || return 0
    fw_load_owner || return 1
    if [[ "$FW_OWN_BACKEND" == nftables ]]; then
        fw_nft_owned || return 1
        setname="blocked$family"
        if nft get element inet bot_mitigation "$setname" "{ $target }" >/dev/null 2>&1; then
            nft delete element inet bot_mitigation "$setname" "{ $target }"
        fi
    else
        if [[ "$family" == 6 ]]; then
            [[ "$FW_FAMILIES" == 4,6 ]] || return 0
            setname=$FW_SET6; fw_ipt_chain_owned ip6tables || return 1
        else setname=$FW_SET4; fw_ipt_chain_owned iptables || return 1; fi
        ipset -exist del "$setname" "$target"
    fi
}
fw_orphans_present() {
    local listing=''
    if command -v nft >/dev/null 2>&1 && nft list table inet bot_mitigation >/dev/null 2>&1; then return 0; fi
    if command -v ipset >/dev/null 2>&1; then
        listing=$(ipset list -name 2>/dev/null) || listing=''
        if [[ "$listing" == *bot_mitigation4_* || "$listing" == *bot_mitigation6_* ]]; then return 0; fi
    fi
    if command -v iptables >/dev/null 2>&1; then
        listing=$(iptables -w 5 -S 2>/dev/null) || listing=''
        [[ "$listing" != *BOT_MITIGATION_* ]] || return 0
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        listing=$(ip6tables -w 5 -S 2>/dev/null) || listing=''
        [[ "$listing" != *BOT_MITIGATION_* ]] || return 0
    fi
    return 1
}
firewall_clear() {
    local failed=0 listing
    if [[ ! -e "$STATE_DIR/firewall.owner" ]]; then
        if fw_orphans_present; then
            fw_warn 'Reserved firewall objects exist without matching ownership; manual review required.'; return 1
        fi
        return 0
    fi
    fw_load_owner || { fw_warn 'Invalid ownership manifest; no objects removed.'; return 1; }
    if [[ "$FW_OWN_BACKEND" == nftables ]]; then
        listing=$(nft list tables 2>/dev/null) || return 1
        if [[ "$listing" == *'table inet bot_mitigation'* ]]; then
            fw_nft_owned || { fw_warn 'Ownership marker mismatch; no table removed.'; return 1; }
            nft delete table inet bot_mitigation || return 1
        fi
    else
        fw_ipt_family_clear iptables "$FW_SET4" || failed=1
        if [[ "$FW_FAMILIES" == 4,6 ]]; then fw_ipt_family_clear ip6tables "$FW_SET6" || failed=1; fi
        [[ "$failed" == 0 ]] || return 1
    fi
    rm -f -- "$STATE_DIR/firewall.owner"
}
firewall_list() {
    [[ -e "$STATE_DIR/firewall.owner" ]] || { printf 'No application-owned firewall objects.\n'; return 0; }
    fw_load_owner || { fw_warn 'Ownership manifest is invalid.'; return 1; }
    if [[ "$FW_OWN_BACKEND" == nftables ]]; then
        fw_nft_owned || return 1
        nft list table inet bot_mitigation
    else
        ipset list "$FW_SET4" || return 1
        if [[ "$FW_FAMILIES" == 4,6 ]]; then ipset list "$FW_SET6"; fi
    fi
}
firewall_doctor() {
    firewall_detect || return 1
    printf 'Firewall backend: %s\n' "$FW_BACKEND"
    case "$FW_BACKEND" in
        nftables)
            if nft list tables >/dev/null 2>&1; then printf 'nftables read access: available (inet IPv4/IPv6).\n'
            else printf 'nftables read access: unavailable; enforcement will fail open.\n'; fi;;
        iptables)
            if iptables -w 5 -S INPUT >/dev/null 2>&1; then printf 'IPv4 firewall read access: available.\n'; else printf 'IPv4 firewall read access: unavailable.\n'; fi
            if command -v ip6tables >/dev/null 2>&1 && ip6tables -w 5 -S INPUT >/dev/null 2>&1; then printf 'IPv6 firewall read access: available.\n'; else printf 'IPv6 firewall: unavailable; IPv6 remains fail-open.\n'; fi;;
        none) printf 'Enforcement unavailable; observation remains available.\n';;
    esac
    if [[ -e "$STATE_DIR/firewall.owner" ]]; then
        firewall_list || { printf 'WARNING: missing, inaccessible, or conflicting owned firewall objects.\n'; return 1; }
    elif fw_orphans_present; then
        printf 'WARNING: reserved firewall objects exist without an ownership manifest; they will not be modified.\n'
    fi
}


emit_detector() {
cat <<'BOT_DETECTOR_AWK'
# Linux Bot Mitigation: bounded, persistent POSIX AWK campaign detector.
# Input: common/combined access logs, with an optional leading virtual host.
# Output is a tab-delimited data protocol, never executable shell text.

BEGIN {
    OFS = "\t"
    if (!window_short) window_short = 10
    if (!window_medium) window_medium = 30
    if (!window_long) window_long = 60
    if (!window_history) window_history = 300
    if (!min_unique) min_unique = 20
    if (!burst_multiplier) burst_multiplier = 5
    if (!score_observe) score_observe = 55
    if (!score_block) score_block = 80
    if (!max_events) max_events = 20000
    if (!max_scopes) max_scopes = 256
    if (!max_ips) max_ips = 50000
    if (!state_retention) state_retention = 86400
    if (!stats_interval) stats_interval = 10
    if (warmup == "") warmup = 300
    windows[1] = window_short; windows[2] = window_medium; windows[3] = window_long
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", months, " ")
    for (i = 1; i <= 12; i++) monthnum[months[i]] = i
    split("31 28 31 30 31 30 31 31 30 31 30 31", monthdays, " ")
    exclusions = split(excluded_paths, excluded, "|")
    source = (log_source != "" ? clean(log_source) : "stdin")
    wall_clock = start_epoch + 0
    oldest = 1
    load_geo()
}

function clean(s) {
    gsub(/[[:cntrl:]]/, " ", s)
    return substr(s, 1, 2048)
}

function json(s,    i, c, out) {
    out = "\""
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "\\") out = out "\\\\"
        else if (c == "\"") out = out "\\\""
        else if (c ~ /[[:cntrl:]]/) out = out " "
        else out = out c
    }
    return out "\""
}

function clear(a,    k) { for (k in a) delete a[k] }
function maximum(a, b) { return a > b ? a : b }
function minimum(a, b) { return a < b ? a : b }
function leap(y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }

# Gregorian arithmetic avoids GNU-only mktime(), timezone state, and child processes.
function epoch(stamp,    d, a, n, day, mon, yr, hr, mn, sec, zone, zhr, zmn, days, j) {
    n = split(stamp, d, " ")
    if (n != 2 || d[2] !~ /^[+-][0-9][0-9][0-9][0-9]$/) return -1
    n = split(d[1], a, /[\/:]/)
    if (n != 6 || a[1] !~ /^[0-9][0-9]$/ || a[2] !~ /^[A-Za-z][A-Za-z][A-Za-z]$/ || a[3] !~ /^[0-9][0-9][0-9][0-9]$/) return -1
    if (a[4] !~ /^[0-9][0-9]$/ || a[5] !~ /^[0-9][0-9]$/ || a[6] !~ /^[0-9][0-9]$/) return -1
    day = a[1] + 0; mon = monthnum[a[2]] + 0; yr = a[3] + 0
    hr = a[4] + 0; mn = a[5] + 0; sec = a[6] + 0
    if (yr < 1970 || yr > 9999 || mon < 1 || day < 1 || day > monthdays[mon] + (mon == 2 && leap(yr)) || hr > 23 || mn > 59 || sec > 59) return -1
    zone = d[2]; zhr = substr(zone, 2, 2) + 0; zmn = substr(zone, 4, 2) + 0
    if (zhr > 14 || zmn > 59 || (zhr == 14 && zmn != 0)) return -1
    days = 365 * (yr - 1970) + int((yr - 1) / 4) - int(1969 / 4) - int((yr - 1) / 100) + int(1969 / 100) + int((yr - 1) / 400) - int(1969 / 400)
    for (j = 1; j < mon; j++) days += monthdays[j] + (j == 2 && leap(yr))
    return (days + day - 1) * 86400 + hr * 3600 + mn * 60 + sec - (substr(zone, 1, 1) == "+" ? 1 : -1) * (zhr * 3600 + zmn * 60)
}

# Consume a quoted log field, respecting escaped quotes. Unknown escapes retain
# their backslash so different source values cannot collapse into one cohort.
function quoted(text,    i, c, nextc, out) {
    sub(/^[ \t]+/, "", text)
    if (substr(text, 1, 1) != "\"") return 0
    out = ""
    for (i = 2; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (c == "\"") {
            qvalue = clean(out); qrest = substr(text, i + 1)
            return 1
        }
        if (c == "\\") {
            nextc = substr(text, ++i, 1)
            if (nextc != "\"" && nextc != "\\") out = out "\\"
            c = nextc
        }
        out = out c
    }
    return 0
}

function parse(line,    pos, stamp, pre, a, n, request, rest, statuspart, pathparts) {
    if (length(line) > 16384 || line ~ /\t/) return 0
    if (!match(line, /\[[0-9][0-9]\/[A-Za-z][A-Za-z][A-Za-z]\/[0-9][0-9][0-9][0-9]:/)) return 0
    pos = RSTART
    pre = substr(line, 1, pos - 1); sub(/^[ ]+/, "", pre); sub(/[ ]+$/, "", pre)
    n = split(pre, a, / +/)
    if (n != 3 && n != 4) return 0
    client = "" a[n - 2]
    if (client !~ /^[0-9A-Fa-f:.]+$/ || (index(client, ".") == 0 && index(client, ":") == 0) || length(client) > 45) return 0
    host = (n == 4 ? a[1] : "")
    if (host != "" && (host !~ /^[A-Za-z0-9_.:\[\]-]+$/ || length(host) > 255)) return 0
    rest = substr(line, pos + 1); pos = index(rest, "]")
    if (!pos) return 0
    stamp = substr(rest, 1, pos - 1); timestamp = epoch(stamp)
    if (timestamp < 0) return 0
    if (!quoted(substr(rest, pos + 1))) return 0
    request = qvalue; rest = qrest
    n = split(request, a, " ")
    if (n != 3 || a[1] !~ /^[A-Z]+$/ || a[3] !~ /^HTTP\/[0-9][0-9.]*$/ || length(a[2]) > 1024) return 0
    method = a[1]; path = a[2]
    if (substr(path, 1, 1) != "/" && path != "*") return 0
    sub(/[?#].*$/, "", path)
    sub(/^[ ]+/, "", rest)
    if (!match(rest, /^[0-9][0-9][0-9] +(-|[0-9]+)( |$)/)) return 0
    statuspart = substr(rest, RSTART, RLENGTH); split(statuspart, a, " ")
    statuscode = a[1] + 0
    if (statuscode < 100 || statuscode > 599) return 0
    rest = substr(rest, RLENGTH + 1)
    refknown = 0; uaknown = 0; emptyref = 0; ua = ""
    if (quoted(rest)) {
        refknown = 1; emptyref = (qvalue == "" || qvalue == "-"); rest = qrest
        if (quoted(rest) && qvalue != "" && qvalue != "-" && length(qvalue) <= 512) {
            uaknown = 1; ua = qvalue
        }
    }
    return 1
}

function is_excluded(p,    i) {
    for (i = 1; i <= exclusions; i++) if (excluded[i] != "" && index(p, excluded[i]) == 1) return 1
    return 0
}

function static_path(p) {
    p = tolower(p)
    return p ~ /\.(css|js|map|png|jpg|jpeg|gif|ico|svg|webp|woff|woff2|ttf|mp4|mp3|pdf|zip)$/
}

# Optional offline metadata: IP<TAB>country<TAB>ASN. Malformed records contribute
# no score. Data is bounded and periodically reloaded for a driver's local cache.
function load_geo(    line, f, n, ip, count) {
    if (geo_file == "") return
    clear(geo_country); clear(geo_asn)
    count = 0
    while ((getline line < geo_file) > 0 && count < max_ips) {
        n = split(line, f, "\t"); ip = "" f[1]
        if ((n != 3 && n != 4) || (n == 4 && f[4] !~ /^[0-9]+$/) || ip !~ /^[0-9A-Fa-f:.]+$/ || length(ip) > 45) continue
        if (f[2] !~ /^[A-Z][A-Z]$/ && f[2] != "-") continue
        if (f[3] !~ /^(AS)?[0-9]+$/ && f[3] != "-") continue
        if (f[2] != "-") geo_country[ip] = f[2]
        if (f[3] != "-") { sub(/^AS/, "", f[3]); geo_asn[ip] = "AS" f[3] }
        count++
    }
    close(geo_file)
}

function remove_event(id, pressure,    s, p, n) {
    if (!(id in e_time)) return
    s = e_scope[id]; p = e_previous[id]; n = e_next[id]
    if (p) e_next[p] = n; else head[s] = n
    if (n) e_previous[n] = p; else tail[s] = p
    if (pressure && e_time[id] > last_seen[s] - window_history) overflow_until[s] = last_seen[s] + window_history
    delete e_time[id]; delete e_scope[id]; delete e_ip[id]; delete e_ua[id]
    delete e_path[id]; delete e_refknown[id]; delete e_empty[id]; delete e_status[id]
    delete e_method[id]; delete e_previous[id]; delete e_next[id]; delete e_flagged[id]
    event_count--
    if (id == oldest) while (!(oldest in e_time) && oldest <= serial) oldest++
}

function prune(now,    k, a, s) {
    if (now - last_prune < 60) return
    last_prune = now
    for (k in ip_last) if (ip_last[k] < now - state_retention) {
        split(k, a, SUBSEP); s = a[1]
        delete ip_last[k]; delete ip_first[k]; delete candidate_at[k]
        tracked--; scope_tracked[s]--
    }
    for (k in lookup_at) if (lookup_at[k] < now - state_retention) { delete lookup_at[k]; lookup_count-- }
    # Scope identities are capped, with inactive scopes released after retention.
    for (s in scope_name) if (last_seen[s] < now - state_retention) {
        while (head[s]) remove_event(head[s], 0)
        delete scope_id[scope_name[s]]; delete scope_name[s]; delete first_seen[s]
        delete last_seen[s]; delete scope_total[s]; delete scope_tracked[s]
        delete last_evaluated[s]; delete last_alert[s]; delete last_burst[s]
        delete scope_bursts[s]; delete scope_suspicious[s]; delete last_score[s]
        delete top_ua_json[s]; delete top_url_json[s]; delete top_country_json[s]; delete top_asn_json[s]
        delete rate_short[s]; delete rate_medium[s]; delete rate_long[s]; delete rate_history[s]; delete overflow_until[s]
        delete unevaluated[s]
        delete repeated_ua[s]; delete repeated_path[s]; delete repeated_at[s]
        delete head[s]; delete tail[s]
        scopes--
    }
}

function add_event(s, t,    k, id) {
    while (head[s] && e_time[head[s]] <= t - window_history) remove_event(head[s], 0)
    while (event_count >= max_events) {
        while (!(oldest in e_time) && oldest <= serial) oldest++
        remove_event(oldest, 1); dropped++
    }
    id = ++serial; e_time[id] = t; e_scope[id] = s; e_ip[id] = client
    e_ua[id] = (uaknown ? ua : ""); e_path[id] = path
    e_refknown[id] = refknown; e_empty[id] = emptyref
    e_status[id] = statuscode; e_method[id] = method
    e_previous[id] = tail[s]
    if (tail[s]) e_next[tail[s]] = id; else head[s] = id
    tail[s] = id; event_count++
    k = s SUBSEP client
    if (!(k in ip_first) && tracked < max_ips) {
        ip_first[k] = t; tracked++; scope_tracked[s]++
        if (enable_geoip && !(client in lookup_at) && lookup_count < max_ips) {
            lookup_at[client] = t; lookup_count++
            print "LOOKUP", client
        }
    }
    if (k in ip_first) ip_last[k] = t
}

function reason_add(reason, message) { return reason (reason == "" ? "" : "; ") message }

# Build at most five compact statistics entries from bounded scratch counts.
function top_json(counts,    k, j, best, out, sep) {
    clear(top_selected); out = "["; sep = ""
    for (j = 1; j <= 5; j++) {
        best = ""
        for (k in counts) if (!(k in top_selected) && (best == "" || counts[k] > counts[best] || (counts[k] == counts[best] && k < best))) best = k
        if (best == "") break
        top_selected[best] = 1
        out = out sep "{\"value\":" json(best) ",\"requests\":" counts[best] "}"
        sep = ","
    }
    return out "]"
}

# Live evaluation runs on the driver's one-second heartbeat. Offline evaluation
# runs at timestamp boundaries and EOF. Scans are bounded to the current scope;
# a suspicious campaign never labels every visitor in the burst as malicious.
function evaluate(s, t,    id, w, q, ips, ip, k, v, key, win, fresh, sameua, samepath, coherent, empty, dominantua, dominantpath, mostua, mostpath, cc, asn, mostcountry, mostasn, ccknown, asnknown, score, reason, basecount, basespan, expected, ratio, synch, cohortips, novelty, ipratio, bestscore, bestreason, bestready, repeat, alert, unusual, errors, ua_known, ref_known, empties) {
    if (!head[s]) return
    if (t - geo_reload_at >= 10) { load_geo(); geo_reload_at = t }
    # History baseline excludes the entire longest detection window.
    basecount = 0; rate_history[s] = 0
    for (id = head[s]; id; id = e_next[id]) if (e_time[id] > t - window_history) {
        rate_history[s]++
        if (e_time[id] <= t - window_long) basecount++
    }
    rate_history[s] /= window_history
    basespan = minimum(window_history, t - first_seen[s]) - window_long
    expected = (basespan > 0 ? basecount / basespan : 0)
    bestscore = -1; bestw = 1; bestu = ""; bestp = ""; bestready = 0
    for (w = 1; w <= 3; w++) {
        win = windows[w]
        clear(ip_counts); clear(ua_counts); clear(path_counts)
        clear(country_counts); clear(asn_counts); clear(cohort_ip)
        q = ips = fresh = ua_known = ref_known = empties = errors = unusual = ccknown = asnknown = 0
        for (id = tail[s]; id && e_time[id] > t - win; id = e_previous[id]) {
            q++; ip = e_ip[id]; k = s SUBSEP ip
            if (++ip_counts[ip] == 1) {
                ips++
                if (k in ip_first && ip_first[k] > t - win) fresh++
            }
            v = e_ua[id]
            if (v != "") { ua_counts[v]++; ua_known++ }
            path_counts[e_path[id]]++
            if (e_refknown[id]) { ref_known++; empties += e_empty[id] }
            errors += (e_status[id] >= 400)
            unusual += (e_method[id] != "GET" && e_method[id] != "HEAD")
            if (ip in geo_country) { country_counts[geo_country[ip]]++; ccknown++ }
            if (ip in geo_asn) { asn_counts[geo_asn[ip]]++; asnknown++ }

        }
        if (w == 1) rate_short[s] = q / win
        if (w == 2) rate_medium[s] = q / win
        if (w == 3) rate_long[s] = q / win
        if (!q) continue
        dominantua = dominantpath = ""; mostua = mostpath = 0
        for (v in ua_counts) if (ua_counts[v] > mostua || (ua_counts[v] == mostua && v < dominantua)) { mostua = ua_counts[v]; dominantua = v }
        for (v in path_counts) if (path_counts[v] > mostpath || (path_counts[v] == mostpath && v < dominantpath)) { mostpath = path_counts[v]; dominantpath = v }
        sameua = mostua / q; samepath = mostpath / q
        cohortips = cohort_n = cohort_empty_n = 0
        cohort_first_time = t; cohort_last_time = 0
        # Most legitimate traffic fails concentration checks. Avoid constructing
        # per-request cohort identities unless a dominant signature exists.
        if (sameua >= 0.8 && samepath >= 0.75 && !static_path(dominantpath)) {
            for (id = tail[s]; id && e_time[id] > t - win; id = e_previous[id]) {
                if (e_ua[id] != dominantua || e_path[id] != dominantpath) continue
                cohort_n++; ip = e_ip[id]
                if (!(ip in cohort_ip)) { cohort_ip[ip] = 1; cohortips++ }
                if (e_time[id] < cohort_first_time) cohort_first_time = e_time[id]
                if (e_time[id] > cohort_last_time) cohort_last_time = e_time[id]
                if (e_refknown[id] && e_empty[id]) cohort_empty_n++
            }
        }
        coherent = cohort_n / q
        novelty = (ips ? fresh / ips : 0); ipratio = ips / q
        empty = (ref_known ? empties / ref_known : 0)
        ratio = q / maximum(2, expected * win)
        velocity = (ratio >= burst_multiplier)
        synch = (cohort_n && cohort_last_time - cohort_first_time <= maximum(2, win / 2))
        repeat = (repeated_ua[s] == dominantua && repeated_path[s] == dominantpath && repeated_at[s] && t - repeated_at[s] >= window_long && t - repeated_at[s] <= window_history)
        score = 0; reason = ""
        if (ips >= min_unique) { score += 25; reason = reason_add(reason, ips " unique IPs / " win "s") }
        if (velocity && ips >= min_unique) { score += 20; reason = reason_add(reason, sprintf("%.1fx preceding-history request baseline", ratio)) }
        if (novelty >= 0.8 && ips >= min_unique) { score += 10; reason = reason_add(reason, int(novelty * 100) "% fresh IPs") }
        if (sameua >= 0.8 && ua_known / q >= 0.9 && ips >= min_unique) { score += 15; reason = reason_add(reason, int(sameua * 100) "% identical UA") }
        if (samepath >= 0.75 && ips >= min_unique) { score += 10; reason = reason_add(reason, int(samepath * 100) "% same URL path") }
        if (empty >= 0.8 && ref_known / q >= 0.9 && ips >= min_unique) { score += 5; reason = reason_add(reason, int(empty * 100) "% empty referrer") }
        if (cohortips >= min_unique && coherent >= 0.75 && synch) { score += 10; reason = reason_add(reason, "synchronized exact UA/path cohort") }
        mostcountry = mostasn = 0; cc = asn = ""
        for (v in country_counts) if (country_counts[v] > mostcountry) { mostcountry = country_counts[v]; cc = v }
        for (v in asn_counts) if (asn_counts[v] > mostasn) { mostasn = asn_counts[v]; asn = v }
        # Supporting metadata is capped at six points, never a block gate.
        if (ips >= min_unique && ccknown / q >= 0.8 && mostcountry / q >= 0.8) { score += 2; reason = reason_add(reason, int(mostcountry / q * 100) "% country " cc) }
        if (ips >= min_unique && asnknown / q >= 0.8 && mostasn / q >= 0.8) { score += 4; reason = reason_add(reason, int(mostasn / q * 100) "% ASN " asn) }
        if (repeat && coherent >= 0.75 && cohortips >= min_unique) { score += 5; reason = reason_add(reason, "repeated correlated cohort") }
        if (errors / q >= 0.6 && ips >= min_unique) { score += 3; reason = reason_add(reason, int(errors / q * 100) "% HTTP errors") }
        if (unusual / q >= 0.8 && ips >= min_unique) { score += 2; reason = reason_add(reason, "unusual method concentration") }
        score = minimum(100, score)
        correlation = (ips >= min_unique && cohortips >= min_unique && velocity && novelty >= 0.85 && ipratio >= 0.8 && sameua >= 0.8 && samepath >= 0.75 && coherent >= 0.75 && cohort_n && cohort_empty_n / cohort_n >= 0.9 && (synch || repeat))
        ready = (correlation && t - first_seen[s] >= warmup && t >= overflow_until[s])
        if (score > bestscore || (score == bestscore && ready > bestready)) {
            bestscore = score; bestreason = reason; bestw = w; bestu = dominantua; bestp = dominantpath; bestready = ready
        }
    }
    last_evaluated[s] = t; last_score[s] = maximum(0, bestscore); unevaluated[s] = 0
    if (bestscore < score_observe) return
    if (t - first_seen[s] < warmup) bestreason = reason_add(bestreason, "baseline warmup: observe only")
    if (t < overflow_until[s]) bestreason = reason_add(bestreason, "event capacity exceeded: observe only")
    if (!bestready && t - first_seen[s] >= warmup && t >= overflow_until[s]) bestreason = reason_add(bestreason, "individual mitigation correlation not satisfied")
    alert = (!last_alert[s] || t - last_alert[s] >= window_short)
    if (alert) {
        print "EVENT", bestscore, scope_name[s], clean(bestreason)
        last_alert[s] = t; suspicious_events++
        if (!last_burst[s] || t - last_burst[s] > window_long) { bursts++; scope_bursts[s]++; last_burst[s] = t }
        if (!repeated_at[s] || repeated_ua[s] != bestu || repeated_path[s] != bestp || t - repeated_at[s] > window_history) {
            repeated_at[s] = t; repeated_ua[s] = bestu; repeated_path[s] = bestp
        }
    }
    clear(ip_counts); clear(eligible_counts); clear(ua_counts); clear(path_counts); clear(country_counts); clear(asn_counts)
    win = windows[bestw]
    for (id = tail[s]; id && e_time[id] > t - win; id = e_previous[id]) {
        ip = e_ip[id]; ip_counts[ip]++
        if (e_ua[id] != bestu || e_path[id] != bestp || !e_refknown[id] || !e_empty[id] || static_path(e_path[id])) continue
        eligible_counts[ip]++
        ua_counts[e_ua[id]]++; path_counts[e_path[id]]++
        if (ip in geo_country) country_counts[geo_country[ip]]++
        if (ip in geo_asn) asn_counts[geo_asn[ip]]++
        if (!e_flagged[id]) { e_flagged[id] = 1; suspicious_requests++; scope_suspicious[s]++ }
    }
    top_ua_json[s] = top_json(ua_counts); top_url_json[s] = top_json(path_counts)
    top_country_json[s] = top_json(country_counts); top_asn_json[s] = top_json(asn_counts)
    if (bestscore < score_block || !bestready) return
    for (ip in eligible_counts) {
        k = s SUBSEP ip
        if (eligible_counts[ip] != ip_counts[ip] || !(k in ip_first) || ip_first[k] <= t - win) continue
        # Re-emission is bounded; the driver additionally deduplicates active bans.
        if (candidate_at[k] && t - candidate_at[k] < window_history) continue
        candidate_at[k] = t
        print "CANDIDATE", ip, bestscore, scope_name[s], clean(bestreason)
    }
}

function stats(now,    s, out, sep, elapsed, r1, r2, r3) {
    out = "{\"requests\":" (total + 0) ",\"malformed\":" (malformed + 0) ",\"late_records\":" (late + 0) ",\"excluded\":" (excluded_total + 0) ",\"tracked_unique_scope_ips\":" (tracked + 0) ",\"suspicious_requests\":" (suspicious_requests + 0) ",\"suspicious_events\":" (suspicious_events + 0) ",\"bursts\":" (bursts + 0) ",\"capacity_dropped_events\":" (dropped + 0) ",\"capacity_skipped_scopes\":" (skipped_scopes + 0) ",\"timestamp\":" (now + 0) ",\"scopes\":["
    sep = ""
    for (s in scope_name) {
        r1 = (now - last_seen[s] < window_short ? rate_short[s] + 0 : 0)
        r2 = (now - last_seen[s] < window_medium ? rate_medium[s] + 0 : 0)
        r3 = (now - last_seen[s] < window_long ? rate_long[s] + 0 : 0)
        elapsed = maximum(1, last_seen[s] - first_seen[s])
        out = out sep "{\"scope\":" json(scope_name[s]) ",\"requests\":" (scope_total[s] + 0) ",\"tracked_unique_ips\":" (scope_tracked[s] + 0) ",\"suspicious_requests\":" (scope_suspicious[s] + 0) ",\"bursts\":" (scope_bursts[s] + 0) ",\"recent_score\":" (last_score[s] + 0) ",\"last_event\":" (last_burst[s] + 0) ",\"rate_short\":" sprintf("%.3f", r1) ",\"rate_medium\":" sprintf("%.3f", r2) ",\"rate_long\":" sprintf("%.3f", r3) ",\"rate_history\":" sprintf("%.3f", now - last_seen[s] < window_history ? rate_history[s] + 0 : 0) ",\"average_rate\":" sprintf("%.3f", scope_total[s] / elapsed) ",\"top_suspicious_user_agents\":" (top_ua_json[s] != "" ? top_ua_json[s] : "[]") ",\"top_suspicious_urls\":" (top_url_json[s] != "" ? top_url_json[s] : "[]") ",\"top_suspicious_countries\":" (top_country_json[s] != "" ? top_country_json[s] : "[]") ",\"top_suspicious_asns\":" (top_asn_json[s] != "" ? top_asn_json[s] : "[]") "}"
        sep = ","
    }
    print "STATS", out "]}"
    last_stats = now
}

# GNU and BusyBox tail -F use these headers for multiplexed log sources.
/^==> .* <==$/ {
    source = clean(substr($0, 5, length($0) - 8))
    next
}
/^[ \t]*$/ { next }
/^@BM_TICK\t[0-9]+$/ {
    # Driver heartbeat finalizes a burst even when the access log goes silent.
    if (!live) next
    tick = substr($0, 10) + 0
    if (start_epoch && tick < start_epoch) next
    wall_clock = maximum(wall_clock, tick)
    if (tick < clock_now) next
    clock_now = tick
    for (scope in scope_name) {
        while (head[scope] && e_time[head[scope]] <= tick - window_history) remove_event(head[scope], 0)
        if (head[scope]) evaluate(scope, tick)
    }
    prune(tick)
    if (tick - last_stats >= stats_interval) stats(tick)
    fflush()
    next
}
{
    if (!parse($0)) { malformed++; next }
    if (live && start_epoch && timestamp < start_epoch - window_long) { late++; next }
    if (live && wall_clock && timestamp > wall_clock + 5) { late++; next }
    total++
    if (is_excluded(path)) { excluded_total++; next }
    clock_now = maximum(clock_now, timestamp)
    prune(clock_now)
    scopekey = source (host != "" ? " [vhost=" host "]" : "")
    if (!(scopekey in scope_id)) {
        if (scopes >= max_scopes) { skipped_scopes++; next }
        scope = ++scope_serial; scope_id[scopekey] = scope; scope_name[scope] = scopekey
        first_seen[scope] = timestamp; scopes++
    } else scope = scope_id[scopekey]
    if (timestamp < last_seen[scope]) { late++; next }
    if (last_seen[scope] && timestamp > last_seen[scope]) {
        if (!live && unevaluated[scope]) evaluate(scope, last_seen[scope])
    }
    last_seen[scope] = timestamp; scope_total[scope]++
    add_event(scope, timestamp)
    unevaluated[scope] = 1
    if (!live && clock_now - last_stats >= stats_interval) {
        if (last_evaluated[scope] != timestamp) evaluate(scope, timestamp)
        stats(clock_now)
    }
    fflush()
}
END {
    for (scope in scope_name) evaluate(scope, maximum(last_seen[scope], clock_now))
    stats(clock_now)
    fflush()
}

BOT_DETECTOR_AWK
}

# All tests use temporary synthetic logs. They never invoke a firewall backend.
detector_self_test() (
    set -eu
    local test_dir detector failed=0 passed=0 label output mode
    test_dir=$(mktemp -d "${TMPDIR:-/tmp}/bot-mitigation-self-test.XXXXXXXX")
    trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM
    detector="$test_dir/detector.awk"
    emit_detector >"$detector"
    cat >"$test_dir/fixtures.awk" <<'BM_TEST_FIXTURES'
function emit(ip, second, path, ref, ua, host, common) {
    printf "%s%s - - [25/Sep/2026:10:%02d:%02d +0000] \"GET %s HTTP/1.1\" 200 512", (host != "" ? host " " : ""), ip, int(second / 60), second % 60, path
    if (!common) printf " \"%s\" \"%s\"", ref, ua
    printf "\n"
}
BEGIN {
    if (scenario == "normal") {
        for (i = 1; i <= 40; i++) emit("198.51.100." i, int(i / 4), "/page/" (i % 8), "https://example.org/", "Browser/" (i % 10), "", 0)
    } else if (scenario == "direct") emit("198.51.100.1", 0, "/", "-", "Browser/1", "", 0)
    else if (scenario == "small") { for (i = 1; i <= 8; i++) emit("198.51.100." i, 0, "/pricing", "-", "Browser/1", "", 0) }
    else if (scenario == "mixed") {
        for (i = 200; i <= 203; i++) emit("198.51.100." i, 0, "/help", "https://example.org/", "Human/" i, "", 0)
        for (i = 1; i <= 32; i++) emit("198.51.100." i, 0, "/pricing", "-", "Browser/1", "", 0)
    } else if (scenario == "navigation") {
        emit("198.51.100.1", 0, "/about", "https://example.org/", "Browser/1", "", 0)
        for (i = 1; i <= 40; i++) emit("198.51.100." i, 0, "/pricing", "-", "Browser/1", "", 0)
    } else if (scenario == "ipv6") {
        for (i = 1; i <= 40; i++) emit(sprintf("2001:db8::%x", i), 0, "/pricing", "-", "Browser/1", "", 0)
    } else if (scenario == "malformed") {
        print "not an access log"
        print "198.51.100.1 - - [31/Feb/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1"
        print "198.51.100.1 - - [25/Sep/2026:99:00:00 +0000] \"GET / HTTP/1.1\" 200 1"
        print "invalid - - [25/Sep/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1"
        emit("198.51.100.1", 0, "/", "-", "Browser/1", "", 0)
    } else if (scenario == "baseline") {
        for (i = 0; i < 240; i++) emit("192.0.2." (i % 200 + 1), i, "/page/" (i % 9), "https://example.org/", "Browser/" (i % 10), "", 0)
        for (i = 1; i <= 40; i++) emit("198.51.100." i, 301, "/pricing", "-", "Browser/1", "", 0)
    } else if (scenario == "warm") {
        emit("192.0.2.1", 0, "/", "https://example.org/", "Other/1", "", 0)
        for (i = 1; i <= 40; i++) emit("198.51.100." i, 301, "/pricing", "-", "Browser/1", "", 0)
    } else if (scenario == "repeated") {
        for (i = 1; i <= 40; i++) emit("198.51.100." i, 0, "/pricing", "-", "Browser/1", "", 0)
        for (i = 41; i <= 80; i++) emit("198.51.100." i, 200, "/pricing", "-", "Browser/1", "", 0)
    } else if (scenario == "scopes") {
        print "==> /var/log/nginx/one.log <=="
        for (i = 1; i <= 10; i++) emit("198.51.100." i, 0, "/pricing", "-", "Browser/1", "a.example", 0)
        for (i = 11; i <= 20; i++) emit("198.51.100." i, 0, "/pricing", "-", "Browser/1", "b.example", 0)
        print "==> /var/log/nginx/two.log <=="
        for (i = 21; i <= 30; i++) emit("198.51.100." i, 0, "/pricing", "-", "Browser/1", "", 0)
    } else if (scenario == "tick") {
        for (i = 1; i <= 40; i++) emit("198.51.100." i, 0, "/pricing", "-", "Browser/1", "", 0)
        printf "@BM_TICK\t1790330401\n"
    } else {
        for (i = 1; i <= 40; i++) emit("198.51.100." i, 0, (scenario == "static" ? "/logo.png" : "/pricing"), "-", (scenario == "crawler" ? "Googlebot/2.1" : scenario == "missingua" ? "-" : "Browser/1"), "", scenario == "common")
    }
}
BM_TEST_FIXTURES
    # Small helpers live only inside this test subshell.
    run_detector_case() {
        local scenario=$1
        shift
        awk -v scenario="$scenario" -f "$test_dir/fixtures.awk" >"$test_dir/input.log"
        awk -v warmup=0 "$@" -f "$detector" "$test_dir/input.log" >"$test_dir/result"
    }
    expect_detector() {
        local label=$1 rule=$2
        if awk -F '\t' "$rule" "$test_dir/result"; then
            printf 'PASS %s\n' "$label"
            passed=$((passed + 1))
        else
            printf 'FAIL %s\n' "$label" >&2
            failed=$((failed + 1))
        fi
    }
    run_detector_case normal
    expect_detector 'normal mixed visitors: no individual mitigation' '$1=="CANDIDATE" {n++} END {exit n!=0}'
    run_detector_case direct
    expect_detector 'one direct visitor: no individual mitigation' '$1=="CANDIDATE" {n++} END {exit n!=0}'
    run_detector_case small
    expect_detector 'small legitimate burst: no individual mitigation' '$1=="CANDIDATE" {n++} END {exit n!=0}'
    run_detector_case distributed
    expect_detector 'distributed campaign: 40 correlated candidates, score at least 80' '$1=="CANDIDATE" && $3>=80 {n++} END {exit n!=40}'
    run_detector_case mixed
    expect_detector 'mixed burst: only the 32 exact-cohort participants qualify' '$1=="CANDIDATE" {n++; if ($2 ~ /\.20[0-3]$/) bad++} END {exit n!=32 || bad}'
    run_detector_case navigation
    expect_detector 'known normal navigation excludes that individual from the campaign' '$1=="CANDIDATE" {n++; if ($2=="198.51.100.1") bad++} END {exit n!=39 || bad}'
    run_detector_case crawler
    expect_detector 'spoofed Googlebot UA does not bypass correlated detection' '$1=="CANDIDATE" {n++} END {exit n!=40}'
    run_detector_case ipv6
    expect_detector 'IPv6 addresses are preserved and detected' '$1=="CANDIDATE" && $2 ~ /^2001:db8::/ {n++} END {exit n!=40}'
    run_detector_case common
    expect_detector 'common logs without referrer or UA remain observe only' '$1=="CANDIDATE" {n++} $1=="EVENT" {e++} END {exit n!=0 || !e}'
    run_detector_case missingua
    expect_detector 'missing User-Agent cannot authorize individual mitigation' '$1=="CANDIDATE" {n++} END {exit n!=0}'
    run_detector_case static
    expect_detector 'static resource concentration cannot authorize mitigation' '$1=="CANDIDATE" {n++} END {exit n!=0}'
    run_detector_case malformed
    expect_detector 'malformed logs are rejected without terminating the parser' '$1=="CANDIDATE" {n++} $1=="STATS" && $2 ~ /"malformed":4/ && $2 ~ /"requests":1/ {ok=1} END {exit n!=0 || !ok}'
    run_detector_case distributed -v warmup=300
    expect_detector 'cold-start warmup prevents individual mitigation' '$1=="CANDIDATE" {n++} $1=="EVENT" && $4 ~ /warmup/ {ok=1} END {exit n!=0 || !ok}'
    run_detector_case warm -v warmup=300
    expect_detector 'completed warmup permits a correlated low-baseline campaign' '$1=="CANDIDATE" {n++} END {exit n!=40}'
    run_detector_case baseline -v warmup=300
    expect_detector 'busy-site baseline suppresses a proportionate traffic burst' '$1=="CANDIDATE" {n++} END {exit n!=0}'
    run_detector_case distributed -v max_events=10
    expect_detector 'event memory pressure fails open' '$1=="CANDIDATE" {n++} $1=="STATS" && $2 ~ /"capacity_dropped_events":30/ {ok=1} END {exit n!=0 || !ok}'
    run_detector_case distributed -v max_ips=10
    expect_detector 'IP tracking capacity cannot create high-confidence freshness' '$1=="CANDIDATE" {n++} END {exit n!=0}'
    run_detector_case distributed -v excluded_paths=/pricing
    expect_detector 'configured endpoint prefix is excluded' '$1=="CANDIDATE" {n++} $1=="STATS" && $2 ~ /"excluded":40/ {ok=1} END {exit n!=0 || !ok}'
    run_detector_case scopes
    expect_detector 'log files and virtual hosts have isolated campaign windows' '$1=="CANDIDATE" {n++} $1=="STATS" && $2 ~ /a.example/ && $2 ~ /b.example/ && $2 ~ /two.log/ {ok=1} END {exit n!=0 || !ok}'
    printf 'nonsense\tINVALID\tBROKEN\n198.51.100.1\tUS\tmalformed-ASN\n' >"$test_dir/broken.tsv"
    run_detector_case distributed -v geo_file="$test_dir/broken.tsv"
    expect_detector 'broken optional GeoIP data contributes no metadata score' '$1=="CANDIDATE" && $3==95 {n++} /ASN |country / {bad++} END {exit n!=40 || bad}'
    awk 'BEGIN {for(i=1;i<=80;i++) printf "198.51.100.%d\tUS\t64496\n",i}' >"$test_dir/geo.tsv"
    run_detector_case repeated -v geo_file="$test_dir/geo.tsv"
    expect_detector 'repeated simulated ASN campaign gains supporting confidence' '$1=="CANDIDATE" && $3>95 && $5 ~ /repeated correlated cohort/ && $5 ~ /AS64496/ {n++} END {exit n<40}'
    run_detector_case tick -v live=1 -v start_epoch=1790330400
    expect_detector 'heartbeat finalizes silent same-second campaign participants' '$1=="CANDIDATE" {n++} END {exit n!=40}'
    run_detector_case distributed -v live=1 -v start_epoch=1790330000
    expect_detector 'future timestamps fail open in live mode' '$1=="CANDIDATE" {n++} $1=="STATS" && $2 ~ /"late_records":40/ {ok=1} END {exit n!=0 || !ok}'
    run_detector_case distributed -v live=1 -v start_epoch=1790331000
    expect_detector 'stale pre-start events fail open in live mode' '$1=="CANDIDATE" {n++} END {exit n!=0}'
    printf 'Detector self-test: %s passed, %s failed. No firewall commands were run.\n' "$passed" "$failed"
    (( failed == 0 ))
)

# Exercises network decisions and early fail-open gates in a private subshell.
# Firewall command names are shadowed before any test, so no kernel firewall
# access is possible even when self-test runs as root on an enforcing server.
safety_self_test() (
    local sandbox checked=0
    sandbox=$(mktemp -d "${TMPDIR:-/tmp}/bot-mitigation-safety.XXXXXX") || return 1
    trap 'rm -rf -- "$sandbox"' EXIT
    CONFIG_DIR=$sandbox/config
    STATE_DIR=$sandbox/state
    mkdir -p "$CONFIG_DIR" "$STATE_DIR" || return 1
    TRUSTED_IPS='' TRUSTED_NETWORKS='' TRUSTED_PROXY_RANGES=''
    PROTECTED_PORTS='80 443' FIREWALL_BACKEND=none MODE=dry-run
    _safety_unexpected() { printf '%s\n' unexpected >> "$sandbox/firewall-calls"; return 1; }
    nft() { _safety_unexpected; }
    iptables() { _safety_unexpected; }
    ip6tables() { _safety_unexpected; }
    ipset() { _safety_unexpected; }
    _safety_expect() {
        local expected=$1 label=$2 actual=0
        shift 2
        "$@" >/dev/null 2>&1 || actual=1
        [[ "$actual" == "$expected" ]] || { printf 'FAIL safety: %s\n' "$label" >&2; return 1; }
        checked=$((checked+1))
    }
    _safety_expect 0 'IPv4 syntax' valid_target 8.8.8.8 || return 1
    _safety_expect 0 'IPv6 syntax' valid_target 2606:4700::1111 || return 1
    _safety_expect 0 'IPv6 dotted tail syntax' valid_target ::ffff:192.168.1.1 || return 1
    _safety_expect 1 'IPv4 invalid octet' valid_target 256.0.0.1 || return 1
    _safety_expect 1 'IPv4 ambiguous leading zero' valid_target 010.0.0.1 || return 1
    _safety_expect 1 'IPv6 invalid compression' valid_target 1::2::3 || return 1
    _safety_expect 1 'Invalid prefix' valid_target 8.8.8.8/33 || return 1
    _safety_expect 1 'Shell metacharacters rejected' valid_target '8.8.8.8;id' || return 1
    _safety_expect 0 'IPv4 global target' target_is_safe 8.8.8.8 || return 1
    _safety_expect 0 'IPv6 global target' target_is_safe 2606:4700::1111 || return 1
    _safety_expect 1 'IPv4 loopback protected' target_is_safe 127.0.0.1 || return 1
    _safety_expect 1 'IPv6 loopback protected' target_is_safe ::1 || return 1
    _safety_expect 1 'IPv4 internal protected' target_is_safe 10.0.0.1 || return 1
    _safety_expect 1 'IPv6 internal protected' target_is_safe fd00::1 || return 1
    _safety_expect 1 'IPv4 multicast protected' target_is_safe 224.0.0.1 || return 1
    _safety_expect 1 'IPv6 multicast protected' target_is_safe ff02::1 || return 1
    _safety_expect 1 'IPv4 wide network rejected' target_is_safe 8.8.8.0/23 || return 1
    _safety_expect 1 'IPv6 wide network rejected' target_is_safe 2606:4700::/63 || return 1
    _safety_expect 0 'Containing subnet overlap' network_tool overlap 8.8.8.0/24 8.8.8.8 || return 1
    _safety_expect 1 'Distinct subnet exclusion' network_tool overlap 8.8.8.0/24 1.1.1.1 || return 1
    [[ $(canonical_target 2606:4700::1234/64) == 2606:4700:0000:0000:0000:0000:0000:0000/64 ]] || return 1
    checked=$((checked+1))
    TRUSTED_IPS=8.8.8.8
    _safety_expect 1 'Trusted host protects containing network' target_is_safe 8.8.8.0/24 || return 1
    TRUSTED_IPS=''
    TRUSTED_PROXY_RANGES=2606:4700::/32
    _safety_expect 1 'Trusted IPv6 proxy protected' target_is_safe 2606:4700::1111 || return 1
    TRUSTED_PROXY_RANGES=''
    printf '%s\n' 8.8.8.8 > "$CONFIG_DIR/whitelist"
    _safety_expect 1 'Whitelist overlap protects network' target_is_safe 8.8.8.0/24 || return 1
    printf '%s\n' malformed > "$CONFIG_DIR/whitelist"
    _safety_expect 1 'Corrupt whitelist fails open' target_is_safe 1.1.1.1 || return 1
    : > "$CONFIG_DIR/whitelist"
    _safety_expect 1 'Dry-run refuses setup' firewall_setup || return 1
    _safety_expect 1 'Dry-run refuses ban' firewall_add 8.8.8.8 300 || return 1
    MODE=enforce
    _safety_expect 1 'Unavailable backend fails open' firewall_setup || return 1
    : > "$STATE_DIR/emergency-disabled"
    _safety_expect 1 'Emergency refuses setup' firewall_setup || return 1
    _safety_expect 1 'Emergency refuses ban' firewall_add 8.8.8.8 300 || return 1
    [[ ! -e "$sandbox/firewall-calls" && ! -e "$STATE_DIR/firewall.owner" ]] || {
        printf 'FAIL safety: a fail-open gate attempted a firewall operation.\n' >&2; return 1;
    }
    printf 'PASS safety: %s assertions; no firewall commands executed.\n' "$checked"
)


dispatch "$@"
}
bot_mitigation_main "$@"
