#!/usr/bin/env bash
# Safe lifecycle regression tests: all installation paths and privileged tools
# are isolated in a marked temporary directory. No host firewall is invoked.
set -Eeuo pipefail
umask 077
export LC_ALL=C
command -v python3 >/dev/null 2>&1 || { printf "Tests require Python 3 for the isolated firewall fixture (not the application).\n" >&2; exit 2; }
SCRIPT=${1:-"$(cd "$(dirname "$0")" && pwd)/script.sh"}
[[ -f $SCRIPT ]] || { printf 'Source script not found: %s\n' "$SCRIPT" >&2; exit 2; }
SCRIPT=$(cd "$(dirname "$SCRIPT")" && pwd)/$(basename "$SCRIPT")
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/bot-mitigation-tests.XXXXXX")
DAEMON_TEST_PID=''
test_cleanup() {
  if [[ -n $DAEMON_TEST_PID ]]; then kill "$DAEMON_TEST_PID" 2>/dev/null || :; wait "$DAEMON_TEST_PID" 2>/dev/null || :; fi
  rm -rf "$TEST_TMP"
}
trap test_cleanup EXIT
mkdir -p "$TEST_TMP/bin"
REAL_BASH=$(command -v bash)
cat > "$TEST_TMP/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
set -eu
state=$BOT_MITIGATION_ROOT/mock
mkdir -p "$state"
printf 'systemctl %s\n' "$*" >> "$state/calls"
case "$1" in
  start|restart)
    [[ ! -e $state/fail-start ]] || exit 1
    touch "$state/running" ;;
  stop) rm -f "$state/running" ;;
  enable) touch "$state/enabled" ;;
  disable) rm -f "$state/enabled" "$state/running" ;;
  is-active) [[ -e $state/running ]] ;;
  is-enabled) [[ -e $state/enabled ]] ;;
  daemon-reload) : ;;
  *) printf 'Unexpected mock systemctl command: %s\n' "$*" >&2; exit 2 ;;
esac
MOCK
cat > "$TEST_TMP/bin/rc-service" <<'MOCK'
#!/usr/bin/env bash
set -eu
state=$BOT_MITIGATION_ROOT/mock
mkdir -p "$state"
printf 'rc-service %s\n' "$*" >> "$state/calls"
case "$2" in
  start|restart) [[ ! -e $state/fail-start ]] || exit 1; touch "$state/running" ;;
  stop) rm -f "$state/running" ;;
  status) [[ -e $state/running ]] ;;
  *) exit 2 ;;
esac
MOCK
cat > "$TEST_TMP/bin/rc-update" <<'MOCK'
#!/usr/bin/env bash
set -eu
state=$BOT_MITIGATION_ROOT/mock
mkdir -p "$state"
printf 'rc-update %s\n' "$*" >> "$state/calls"
case "$1" in
  add) touch "$state/enabled" ;;
  del) rm -f "$state/enabled" ;;
  show) [[ ! -e $state/enabled ]] || printf 'bot-mitigation | default\n' ;;
  *) exit 2 ;;
esac
MOCK
cat > "$TEST_TMP/bin/flock" <<'MOCK'
#!/usr/bin/env bash
# Command mocks are never used by a real daemon; tests exercise lifecycle only.
exit 0
MOCK
cat > "$TEST_TMP/bin/nft" <<'MOCK'
#!/usr/bin/env bash
set -eu
state=$BOT_MITIGATION_ROOT/mock
mkdir -p "$state"
printf 'nft %s\n' "$*" >> "$state/calls"
[[ ! -e $state/fail-nft ]] || exit 1
case "$*" in
  '--version') printf 'nftables v1.0 mock\n' ;;
  'list tables') [[ ! -f $state/nft-table ]] || printf 'table inet bot_mitigation\n' ;;
  'list ruleset'|'list table inet bot_mitigation')
    [[ -f $state/nft-table ]] || exit 1
    cat "$state/nft-table"
    [[ ! -f $state/nft-elements ]] || cat "$state/nft-elements" ;;
  'delete table inet bot_mitigation')
    [[ -f $state/nft-table ]] || exit 1
    rm -f "$state/nft-table" "$state/nft-elements" ;;
  'list set inet bot_mitigation blocked4'|'list set inet bot_mitigation blocked6') [[ -f $state/nft-table ]] && cat "$state/nft-table" ;;
  'get element inet bot_mitigation '*|'delete element inet bot_mitigation '*)
    target=${6#\{ }; target=${target% \}}
    [[ -f $state/nft-elements ]] || exit 1
    if [[ $1 == get ]]; then grep -Fxq "$5|$target" "$state/nft-elements"
    else
      grep -Fxv "$5|$target" "$state/nft-elements" > "$state/nft-elements.new" || :
      mv "$state/nft-elements.new" "$state/nft-elements"
    fi ;;
  '-f -')
    input=$(cat)
    printf '%s\n' "$input" >> "$state/nft-input"
    case "$input" in
      *'create table inet bot_mitigation'*)
        [[ ! -e $state/nft-table ]] || exit 1
        line=${input%%$'\n'*}; marker=${line#*comment \"}; marker=${marker%%\"*}
        printf 'table inet bot_mitigation {\n comment "%s"\n}\n' "$marker" > "$state/nft-table"
        : > "$state/nft-elements" ;;
      *'add element inet bot_mitigation'*|*'delete element inet bot_mitigation'*)
        [[ -f $state/nft-table ]] || exit 1
        while read -r action element family table set brace target rest; do
          [[ $action == add ]] || continue
          printf '%s|%s\n' "$set" "$target" >> "$state/nft-elements"
        done <<< "$input" ;;
      *) printf 'Unexpected nft stdin\n' >&2; exit 2 ;;
    esac ;;
  *) printf 'Unexpected nft mock command: %s\n' "$*" >&2; exit 2 ;;
esac
MOCK
# Install mocks even for the unused backend: accidental real-firewall fallback
# must fail locally, never invoke a privileged executable from the host PATH.
for tool in iptables ip6tables ipset; do
  cat > "$TEST_TMP/bin/$tool" <<'MOCK'
#!/usr/bin/env bash
printf 'Unexpected fallback firewall call: %s %s\n' "$0" "$*" >&2
exit 1
MOCK
done
chmod +x "$TEST_TMP/bin/"*
export PATH="$TEST_TMP/bin:$PATH"
export BOT_MITIGATION_TESTING=1
TEST_COUNT=0
LAST=$TEST_TMP/last-output
new_root() {
  export BOT_MITIGATION_ROOT="$TEST_TMP/$1"
  mkdir -p "$BOT_MITIGATION_ROOT/mock" "$BOT_MITIGATION_ROOT/etc" "$BOT_MITIGATION_ROOT/var/log/nginx"
  printf 'bot-mitigation-test\n' > "$BOT_MITIGATION_ROOT/.bot-mitigation-test-root"
  printf 'ID=debian\n' > "$BOT_MITIGATION_ROOT/etc/os-release"
  : > "$BOT_MITIGATION_ROOT/var/log/nginx/access.log"
  if [[ ${2:-systemd} == systemd ]]; then mkdir -p "$BOT_MITIGATION_ROOT/run/systemd/system"; else mkdir -p "$BOT_MITIGATION_ROOT/run/openrc"; fi
}
run() { "$REAL_BASH" "$SCRIPT" "$@" > "$LAST" 2>&1 || { cat "$LAST" >&2; return 1; }; }
fail() { printf 'FAIL: %s\n' "$*" >&2; cat "$LAST" >&2; exit 1; }
pass() { TEST_COUNT=$((TEST_COUNT + 1)); printf 'ok %s - %s\n' "$TEST_COUNT" "$*"; }
expect_failure() { if "$REAL_BASH" "$SCRIPT" "$@" > "$LAST" 2>&1; then fail "Command unexpectedly succeeded: $*"; fi; }
contains() { grep -Eq -- "$1" "$2" || fail "Expected $1 in $2"; }
exists() { [[ -e $1 ]] || fail "Missing $1"; }
absent() { [[ ! -e $1 ]] || fail "Unexpected $1"; }
config_set() {
  local key=$1 value=$2 config=$BOT_MITIGATION_ROOT/etc/bot-mitigation/config.conf
  awk -v key="$key" -v val="$value" '$0 ~ "^"key"=" {print key"="val;found=1;next} {print} END{if(!found)print key"="val}' "$config" > "$config.new"
  mv "$config.new" "$config"
}

new_root primary
run version
contains '1\.0\.0' "$LAST"
run help
pass 'read-only version and help'
run install
exists "$BOT_MITIGATION_ROOT/usr/local/sbin/bot-mitigation"
exists "$BOT_MITIGATION_ROOT/etc/systemd/system/bot-mitigation.service"
exists "$BOT_MITIGATION_ROOT/mock/running"
exists "$BOT_MITIGATION_ROOT/mock/enabled"
contains '^MODE=dry-run$' "$BOT_MITIGATION_ROOT/etc/bot-mitigation/config.conf"
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
pass 'installation starts a dry-run service without firewall objects'
run install
contains '^MODE=dry-run$' "$BOT_MITIGATION_ROOT/etc/bot-mitigation/config.conf"
contains 'ExecStart=/usr/local/sbin/bot-mitigation daemon' "$BOT_MITIGATION_ROOT/etc/systemd/system/bot-mitigation.service"
pass 'repeat installation preserves configuration and service paths'
expect_failure enforce on
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
config_set LOG_IP_MODE direct
expect_failure enforce on
config_set FIREWALL_SCOPE host
pass 'enforcement requires direct-peer and host-wide safety acknowledgments'

config_set SCORE_THRESHOLD_OBSERVE 90
config_set SCORE_THRESHOLD_BLOCK 80
expect_failure doctor
contains 'SCORE_THRESHOLD_BLOCK' "$LAST"
config_set SCORE_THRESHOLD_OBSERVE 55
config_set PROTECTED_PORTS '"22 80"'
expect_failure doctor
contains 'management|SSH' "$LAST"
config_set PROTECTED_PORTS '"80 443"'
config_set ENABLE_CHALLENGE yes
expect_failure doctor
config_set ENABLE_CHALLENGE no
pass 'invalid thresholds, SSH scope, and unsupported challenge are rejected'
config_set MODE '"$(touch '"$TEST_TMP"'/config-code-executed)"'
expect_failure doctor
absent "$TEST_TMP/config-code-executed"
config_set MODE dry-run
config_set MAXMIND_LICENSE_KEY '"secret-test-license-value"'
run config
if grep -q 'secret-test-license-value' "$LAST"; then fail 'config output exposed the configured secret'; fi
config_set MAXMIND_LICENSE_KEY '""'
pass 'configuration is parsed as data and secrets are redacted'
run whitelist add 8.9.10.1
run whitelist add 2606:4700:9999::/64
run whitelist list
contains '8\.9\.10\.1' "$LAST"
contains '2606' "$LAST"
expect_failure blacklist add 8.9.10.1
expect_failure blacklist add 2606:4700:9999::5
expect_failure blacklist add 0.0.0.0/0
expect_failure blacklist add ::/0
expect_failure blacklist add 127.0.0.1
expect_failure blacklist add 10.0.0.1
expect_failure blacklist add 192.0.2.1
expect_failure blacklist add 8.9.0.0/16
expect_failure blacklist add 8.9.10.999
expect_failure blacklist add '8.9.10.2;id'
run whitelist remove 8.9.10.1
pass 'IP/CIDR validation and whitelist overlap protect trusted/internal addresses'
run blacklist add 8.9.10.2
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
pass 'dry-run manual blacklist does not create firewall objects'
run enforce on
contains '^MODE=enforce$' "$BOT_MITIGATION_ROOT/etc/bot-mitigation/config.conf"
run blacklist add 8.9.10.2
exists "$BOT_MITIGATION_ROOT/mock/nft-table"
run blacklist add 2606:4700:1000::2
run blacklist list
contains '8\.9\.10\.2' "$LAST"
run unblock 8.9.10.2
run blacklist remove 2606:4700:1000::2
pass 'explicit enforcement applies temporary IPv4/IPv6 blocks and unblocks'
run dry-run on
contains '^MODE=dry-run$' "$BOT_MITIGATION_ROOT/etc/bot-mitigation/config.conf"
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
run dry-run off
run blacklist add 8.9.10.3
run emergency-disable
absent "$BOT_MITIGATION_ROOT/mock/running"
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
contains '^MODE=dry-run$' "$BOT_MITIGATION_ROOT/etc/bot-mitigation/config.conf"
pass 'mode-off and emergency-disable immediately remove owned blocks'
run self-test
pass 'internal synthetic detector self-test'
SAMPLE=$TEST_TMP/sample.log
: > "$SAMPLE"
for ((i=1;i<=40;i++)); do
  printf '8.9.10.%s - - [25/Sep/2026:10:00:00 +0000] "GET /campaign HTTP/1.1" 200 100 "-" "SameBrowser/1.0"\n' "$i" >> "$SAMPLE"
done
printf 'malformed log content $(touch anything)\n' >> "$SAMPLE"
run analyze "$SAMPLE"
contains 'score|Score|EVENT|bursts' "$LAST"
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
pass 'offline analysis accepts campaign samples and malformed lines without firewall effects'
printf 'unrelated firewall state\n' > "$BOT_MITIGATION_ROOT/mock/unrelated-firewall"
run uninstall
absent "$BOT_MITIGATION_ROOT/usr/local/sbin/bot-mitigation"
absent "$BOT_MITIGATION_ROOT/etc/systemd/system/bot-mitigation.service"
exists "$BOT_MITIGATION_ROOT/etc/bot-mitigation/config.conf"
exists "$BOT_MITIGATION_ROOT/var/log/bot-mitigation.log"
contains '^unrelated firewall state$' "$BOT_MITIGATION_ROOT/mock/unrelated-firewall"
pass 'uninstall preserves configuration/logs and unrelated firewall fixture'
run uninstall --purge
absent "$BOT_MITIGATION_ROOT/etc/bot-mitigation"
absent "$BOT_MITIGATION_ROOT/var/lib/bot-mitigation"
absent "$BOT_MITIGATION_ROOT/var/log/bot-mitigation.log"
exists "$BOT_MITIGATION_ROOT/mock/unrelated-firewall"
pass 'purge removes retained application data only'

new_root failed-install
touch "$BOT_MITIGATION_ROOT/mock/fail-start"
expect_failure install
absent "$BOT_MITIGATION_ROOT/usr/local/sbin/bot-mitigation"
absent "$BOT_MITIGATION_ROOT/etc/systemd/system/bot-mitigation.service"
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
pass 'partial installation failure rolls back executable/service/firewall'

new_root openrc openrc
run install
exists "$BOT_MITIGATION_ROOT/etc/init.d/bot-mitigation"
contains 'supervise-daemon' "$BOT_MITIGATION_ROOT/etc/init.d/bot-mitigation"
exists "$BOT_MITIGATION_ROOT/mock/enabled"
run uninstall --purge
absent "$BOT_MITIGATION_ROOT/etc/init.d/bot-mitigation"
pass 'OpenRC installation and purge lifecycle'

new_root pipe-install
if ! cat "$SCRIPT" | "$REAL_BASH" -s -- install > "$LAST" 2>&1; then fail 'piped installer'; fi
"$REAL_BASH" "$BOT_MITIGATION_ROOT/usr/local/sbin/bot-mitigation" version > "$LAST" 2>&1
contains '1\.0\.0' "$LAST"
run uninstall --purge
pass 'piped installer creates a complete reusable executable'

new_root firewall-collision
run install
config_set LOG_IP_MODE direct
config_set FIREWALL_SCOPE host
printf 'table inet bot_mitigation { comment "someone-elses-table"; }\n' > "$BOT_MITIGATION_ROOT/mock/nft-table"
expect_failure enforce on
contains 'someone-elses-table' "$BOT_MITIGATION_ROOT/mock/nft-table"
pass 'foreign firewall object collision is refused without deleting it'
# Leave the foreign object in place; mock state is removed by the test trap.

new_root unowned-service
mkdir -p "$BOT_MITIGATION_ROOT/etc/systemd/system"
printf '# Third-party unit\n[Service]\nExecStart=/unrelated\n' > "$BOT_MITIGATION_ROOT/etc/systemd/system/bot-mitigation.service"
expect_failure install
contains 'Third-party unit' "$BOT_MITIGATION_ROOT/etc/systemd/system/bot-mitigation.service"
if [[ -f $BOT_MITIGATION_ROOT/mock/calls ]] && grep -Eq 'systemctl (stop|disable|start|restart)' "$BOT_MITIGATION_ROOT/mock/calls"; then fail 'unowned service was controlled'; fi
pass 'installer refuses an unowned service without stopping it'

new_root unowned-executable
mkdir -p "$BOT_MITIGATION_ROOT/usr/local/sbin"
printf 'Unrelated executable\n' > "$BOT_MITIGATION_ROOT/usr/local/sbin/bot-mitigation"
expect_failure install
contains '^Unrelated executable$' "$BOT_MITIGATION_ROOT/usr/local/sbin/bot-mitigation"
pass 'installer refuses an unowned executable path'

new_root denied-firewall
run install
config_set LOG_IP_MODE direct
config_set FIREWALL_SCOPE host
touch "$BOT_MITIGATION_ROOT/mock/fail-nft"
expect_failure enforce on
contains '^MODE=dry-run$' "$BOT_MITIGATION_ROOT/etc/bot-mitigation/config.conf"
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
rm "$BOT_MITIGATION_ROOT/mock/fail-nft"
run uninstall --purge
pass 'unavailable firewall refuses enforcement without changing policy'

new_root invalid-config-recovery
run install
config_set LOG_IP_MODE direct
config_set FIREWALL_SCOPE host
run enforce on
run blacklist add 8.9.10.8
exists "$BOT_MITIGATION_ROOT/mock/nft-table"
config_set SCORE_THRESHOLD_BLOCK 10
expect_failure restart
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
exists "$BOT_MITIGATION_ROOT/var/lib/bot-mitigation/emergency-disabled"
run emergency-disable
run uninstall --purge
pass 'invalid configuration fails open and still permits emergency recovery/purge'

# Exercise the real follower/parser pipeline with local files, while all
# privileged boundaries remain mocked. It must report during quiet periods
# and keep following an access-log filename after rotation.
new_root foreground-daemon
run install
config_set WARMUP_TIME 0
"$REAL_BASH" "$SCRIPT" daemon > "$TEST_TMP/daemon-output" 2>&1 &
DAEMON_TEST_PID=$!
sleep 1
log_file=$BOT_MITIGATION_ROOT/var/log/nginx/access.log
stamp=$(date -u '+%d/%b/%Y:%H:%M:%S +0000')
for ((i=1;i<=40;i++)); do
  printf '8.9.10.%s - - [%s] "GET /campaign HTTP/1.1" 200 100 "-" "SameBrowser/1.0"\n' "$i" "$stamp" >> "$log_file"
done
for ((i=0;i<15;i++)); do
  count=$(sed -n 's/^{"requests":\([0-9]*\).*/\1/p' "$BOT_MITIGATION_ROOT/var/lib/bot-mitigation/stats.json" 2>/dev/null || :)
  [[ ${count:-0} -ge 40 ]] && break
  kill -0 "$DAEMON_TEST_PID" 2>/dev/null || { cat "$TEST_TMP/daemon-output" >&2; fail 'foreground daemon exited'; }
  sleep 1
done
[[ ${count:-0} -ge 40 ]] || { cat "$TEST_TMP/daemon-output" >&2; fail 'idle heartbeat did not report all appended requests'; }
contains '\[DRY-RUN\]' "$BOT_MITIGATION_ROOT/var/log/bot-mitigation.log"
mv "$log_file" "$log_file.1"
: > "$log_file"
sleep 2
stamp=$(date -u '+%d/%b/%Y:%H:%M:%S +0000')
for ((i=41;i<=45;i++)); do
  printf '8.9.10.%s - - [%s] "GET /ordinary/%s HTTP/1.1" 200 100 "https://example.test/" "Browser/%s"\n' "$i" "$stamp" "$i" "$i" >> "$log_file"
done
for ((i=0;i<15;i++)); do
  count=$(sed -n 's/^{"requests":\([0-9]*\).*/\1/p' "$BOT_MITIGATION_ROOT/var/lib/bot-mitigation/stats.json" 2>/dev/null || :)
  [[ ${count:-0} -ge 45 ]] && break
  sleep 1
done
[[ ${count:-0} -ge 45 ]] || { cat "$TEST_TMP/daemon-output" >&2; fail 'log rotation stopped request monitoring'; }
kill "$DAEMON_TEST_PID"
wait "$DAEMON_TEST_PID" || { cat "$TEST_TMP/daemon-output" >&2; fail 'daemon shutdown returned failure'; }
DAEMON_TEST_PID=''
absent "$BOT_MITIGATION_ROOT/mock/nft-table"
run uninstall --purge
pass 'foreground daemon scores quiet bursts, follows rotation, and stops cleanly'

# Unit tests source the actual embedded firewall implementation from script.sh.
# They do not copy its logic into the test suite. The Python fixture models
# command state only, without opening sockets or invoking a host firewall.
new_root iptables-fixture
mkdir -p "$TEST_TMP/iptables-bin"
cat > "$TEST_TMP/iptables-bin/firewall-mock.py" <<'PY_MOCK'
#!/usr/bin/env python3
import os,sys,json,shlex
from pathlib import Path
cmd=Path(sys.argv[0]).name
args=sys.argv[1:]
p=Path(os.environ['MOCK_FIREWALL_STATE'])
s=json.loads(p.read_text()) if p.exists() else {'iptables':{'INPUT':[]},'ip6tables':{'INPUT':[]},'sets':{},'calls':[]}
s['calls'].append([cmd]+args)
def done(rc=0,out=''):
 p.write_text(json.dumps(s)); print(out,end=''); sys.exit(rc)
if os.environ.get('MOCK_FAIL_MATCH') and os.environ['MOCK_FAIL_MATCH'] in ' '.join([cmd]+args) and not s.get('injected'):
 s['injected']=True;done(1)
if cmd in ('iptables','ip6tables'):
 if args[:2]==['-w','5']:args=args[2:]
 chains=s[cmd];op=args.pop(0)
 name=args.pop(0) if args else None
 if op=='-S':
  if name not in chains:done(1)
  out=('-P INPUT ACCEPT\n' if name=='INPUT' else '-N '+name+'\n')
  for rule in chains[name]:out+='-A '+name+' '+shlex.join(rule)+'\n'
  done(0,out)
 if op=='-N':
  if name in chains:done(1)
  chains[name]=[];done()
 if name not in chains:done(1)
 if op=='-C':done(0 if args in chains[name] else 1)
 if op=='-A':chains[name].append(args);done()
 if op=='-I':args.pop(0);chains[name].insert(0,args);done()
 if op=='-D':
  if args not in chains[name]:done(1)
  chains[name].remove(args);done()
 if op=='-X':
  if chains[name] or any(name in rule for rules in chains.values() for rule in rules):done(1)
  del chains[name];done()
 done(2)
if cmd=='ipset':
 exist=False
 if args[0]=='-exist':exist=True;args.pop(0)
 op=args.pop(0);name=args.pop(0) if args else None
 sets=s['sets']
 if op=='list' and name=='-name':done(0,''.join(x+'\n' for x in sets))
 if op=='list':
  if name not in sets:done(1)
  done(0,'Name: '+name+'\nHeader: timeout 300\n')
 if op=='create':
  if name in sets:done(1)
  sets[name]={'definition':args,'entries':{}};done()
 if name not in sets:done(1)
 if op=='add':
  sets[name]['entries'][args[0]]=int(args[2]);done()
 if op=='del':
  if args[0] not in sets[name]['entries'] and not exist:done(1)
  sets[name]['entries'].pop(args[0],None);done()
 if op=='flush':sets[name]['entries']={};done()
 if op=='destroy':
  if any(name in rule for fam in ('iptables','ip6tables') for rules in s[fam].values() for rule in rules):done(1)
  del sets[name];done()
 done(2)
done(2)
PY_MOCK
chmod +x "$TEST_TMP/iptables-bin/firewall-mock.py"
for tool in iptables ip6tables ipset; do ln -s firewall-mock.py "$TEST_TMP/iptables-bin/$tool"; done
awk '/^network_awk\(\)/ {emit=1} /^emit_detector\(\)/ {emit=0} emit {print}' "$SCRIPT" > "$TEST_TMP/firewall-module.sh"
[[ -s $TEST_TMP/firewall-module.sh ]] || fail 'Embedded firewall module missing'
(
set -euo pipefail
# shellcheck source=/dev/null
source "$TEST_TMP/firewall-module.sh"
export PATH="$TEST_TMP/iptables-bin:$PATH"
TEMP_ROOT=$(mktemp -d "$TEST_TMP/iptables-unit.XXXXXX")
trap 'rm -rf "$TEMP_ROOT"' EXIT
export MOCK_FIREWALL_STATE="$TEMP_ROOT/firewall.json"
STATE_DIR="$TEMP_ROOT/state" CONFIG_DIR="$TEMP_ROOT/config"
mkdir -p "$STATE_DIR" "$CONFIG_DIR"
MODE=enforce FIREWALL_BACKEND=iptables PROTECTED_PORTS='80 443'
TRUSTED_IPS='' TRUSTED_NETWORKS='' TRUSTED_PROXY_RANGES=''
firewall_setup
first=$(cat "$STATE_DIR/firewall.owner")
firewall_setup
[[ "$first" == "$(cat "$STATE_DIR/firewall.owner")" ]]
firewall_add 8.8.8.8 300
firewall_add 2606:4700::1111 600
firewall_add 8.8.8.8 900
firewall_remove 8.8.8.8
for target in 127.0.0.1 192.168.1.1 8.8.8.8/23 2001:db8::1; do
 if firewall_add "$target" 300; then exit 20; fi
done
TRUSTED_IPS=8.8.8.8
if firewall_add 8.8.8.0/24 300; then exit 21; fi
TRUSTED_IPS=''
touch "$STATE_DIR/emergency-disabled"
if firewall_add 1.1.1.1 300; then exit 22; fi
rm "$STATE_DIR/emergency-disabled"
MODE=observe
if firewall_add 1.1.1.1 300; then exit 23; fi
MODE=enforce
python3 - <<'PY'
import json,os
p=os.environ['MOCK_FIREWALL_STATE'];s=json.load(open(p))
s['iptables']['UNRELATED']=[['-j','ACCEPT']]
s['iptables']['INPUT'].append(['-p','tcp','--dport','22','-j','ACCEPT'])
s['sets']['unrelated']={'definition':[],'entries':{'192.168.1.1':0}}
json.dump(s,open(p,'w'))
PY
firewall_clear
[[ ! -e "$STATE_DIR/firewall.owner" ]]
python3 - <<'PY'
import json,os
s=json.load(open(os.environ['MOCK_FIREWALL_STATE']))
assert s['iptables']=={'INPUT':[['-p','tcp','--dport','22','-j','ACCEPT']],'UNRELATED':[['-j','ACCEPT']]},s
assert s['ip6tables']=={'INPUT':[]}
assert list(s['sets'])==['unrelated']
assert all('-F' not in c for c in s['calls'])
PY
export MOCK_FAIL_MATCH='ip6tables -w 5 -I INPUT 1 -p tcp --dport 443'
if firewall_setup; then exit 24; fi
[[ ! -e "$STATE_DIR/firewall.owner" ]]
python3 - <<'PY'
import json,os
s=json.load(open(os.environ['MOCK_FIREWALL_STATE']))
assert list(s['sets'])==['unrelated']
assert s['ip6tables']=={'INPUT':[]}
assert set(s['iptables'])=={'INPUT','UNRELATED'}
PY
unset MOCK_FAIL_MATCH
firewall_setup
fw_load_owner
iptables -w 5 -A "$FW_CHAIN" -j ACCEPT
if firewall_clear; then exit 25; fi
[[ -f "$STATE_DIR/firewall.owner" ]]
ip6tables -w 5 -S INPUT >/dev/null
printf 'iptables mock tests passed: setup, idempotency, IPv4/6 timeout add/remove, duration renewal, public/trusted checks, emergency/mode gates, owned-only cleanup, partial failure rollback, collision refusal.\n'
) > "$LAST" 2>&1 || fail 'iptables/ipset isolated unit tests'
pass 'iptables/ipset lifecycle, timeouts, rollback, and foreign-rule preservation'

printf '\nAll %s safe lifecycle checks passed. No host firewall was used.\n' "$TEST_COUNT"
