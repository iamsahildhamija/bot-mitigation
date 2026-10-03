# Bot Mitigation Adaptive Layer 7 Script for Linux

This package is a standalone Linux security utility for detecting and mitigating correlated HTTP request bursts across many source addresses.

**A fresh installation monitors in dry-run mode. It does not block visitors.** Review its observations against your real traffic before enabling enforcement. The project favors website availability and false-positive avoidance. An empty referrer, a browser User-Agent, a country, or an ASN is never sufficient evidence of a bot.

This is application-layer bot mitigation, not full volumetric DDoS protection. It observes requests after the web server logs them; it cannot undo the first request, prevent a saturated uplink, or guarantee that analytics and live-chat scripts never run. Use upstream protection and application controls where those guarantees are needed.

## Architecture

A persistent Bash service follows supported access logs and feeds a long-running AWK detector. When enough independent behavioral signals agree, the module reports a campaign and can apply short, temporary firewall penalties to participating IP addresses on configured web ports.

## Recovery

Keep these commands available before enabling enforcement:

```sh
# Immediately stop mitigation and remove this application's active blocks.
sudo bot-mitigation emergency-disable
# Remove the service, executable, runtime files, and owned firewall objects.
# Keep configuration and logs for inspection.
sudo bot-mitigation uninstall
# Alternatively remove the installation and its retained data.
sudo bot-mitigation uninstall --purge
```

Recovery does not flush the machine's firewall or remove unrelated rules. [Manual recovery](#manual-recovery-if-the-executable-is-unavailable) is documented below.

## Environment

There is no hosting-panel dependency. A VPS, cloud VM, dedicated server, or server with cPanel, Plesk, or another panel uses the same core service.

| Component | Scope |
| --- | --- |
| Linux distributions | Targets Debian/Ubuntu, Fedora, RHEL-compatible families including AlmaLinux/Rocky Linux/CentOS, Alpine, openSUSE/SUSE, and Arch families. Distribution and package manager are detected. |
| Package managers | Recognizes apt, dnf, yum, apk, zypper, and pacman. Missing requirements are reported with installation guidance; unrelated packages and security settings are not changed. |
| Service managers | systemd and OpenRC. Installation fails clearly if neither can provide persistence. |
| Web servers | Nginx, Apache HTTP Server, LiteSpeed, and OpenLiteSpeed with supported text access logs. |
| Log formats | Standard combined and common access logs, optionally prefixed with a virtual host. Combined logs provide source IP, method, URL, status, referrer, and User-Agent; common logs provide fewer signals. |
| Firewalls | Native nftables preferred; iptables with ipset fallback. Both IPv4 and IPv6 are supported. |
| Runtime | Bash, a compatible AWK, GNU-compatible tail with `-F`, coreutils, and util-linux `flock`; no Python, Node.js, database, or container runtime. |

These are compatibility targets, not a claim that every distribution release, panel configuration, firewall manager, or proxy topology has been certified. Run `doctor`, the self-test, and an observation period on each deployment. Package names vary by distribution; on Alpine, install Bash and GNU coreutils rather than assuming every BusyBox applet provides the required behavior.

## Installation

The convenient one-command form is:

```sh
curl -fsSL https://raw.githubusercontent.com/iamsahildhamija/bot-mitigation/main/script.sh | sudo bash -s -- install
```

Downloading and inspecting first is safer:

```sh
curl -fsSL https://raw.githubusercontent.com/iamsahildhamija/bot-mitigation/main/script.sh -o script.sh
less script.sh
bash -n script.sh
sudo bash script.sh install
```

Piping a remote script to root executes whatever the publisher serves at that moment. Use your organization's trusted source review and checksum or signature verification process; HTTPS alone does not establish that a release is trustworthy.

Installation generates the executable, configuration, state directory, service, and log under these paths:

```text
/usr/local/sbin/bot-mitigation
/etc/bot-mitigation/config.conf
/var/lib/bot-mitigation/
/var/log/bot-mitigation.log
/etc/systemd/system/bot-mitigation.service    # systemd
/etc/init.d/bot-mitigation                    # OpenRC
```

The service starts immediately and is enabled at boot. Repeating installation repairs or upgrades the owned installation without duplicating rules or replacing an existing configuration. Installation failure triggers rollback. No virtual-host configuration is rewritten and no firewall manager, SELinux, AppArmor, or SSH setting is disabled.

Direct enforcement installation is available only by explicit request:

```sh
sudo bash script.sh install --enforce
```

An observation period is strongly recommended before using that option.

## Enforcement

```sh
sudo bot-mitigation status
sudo bot-mitigation doctor
sudo bot-mitigation self-test
sudo bot-mitigation stats
sudo bot-mitigation logs
```

Status identifies the service state, mode, selected backend, monitored logs, and recent detector state. Logs explain the score and signals behind each observation or proposed penalty. In dry-run mode, reported actions describe what would happen; they do not create firewall bans.

Before enabling enforcement, explicitly acknowledge two safety conditions in the configuration:

```ini
# The logged source IP is the actual connection peer, not a CDN/real-IP rewrite.
LOG_IP_MODE="direct"
# IP bans affect every hosted site and endpoint on the configured ports.
FIREWALL_SCOPE="host"
```

Defaults are `unknown` and `unconfirmed`; enforcement is refused until both conditions are acknowledged. This is also required for `install --enforce`. If either statement is false for your deployment, keep dry-run mode.

After reviewing observations against real visitor behavior:

```sh
sudo bot-mitigation enforce on
sudo bot-mitigation status
```

Return to observation and remove active mitigation:

```sh
sudo bot-mitigation enforce off
```

Equivalent mode controls are `dry-run on` and `dry-run off`. The latter explicitly enables enforcement. `emergency-disable` additionally stops the service and leaves an emergency lock. After investigating, clear it into observation mode with `sudo bot-mitigation emergency-enable`; enabling enforcement then requires a separate `sudo bot-mitigation enforce on`. Read the current status after every mode change.

## Service

```sh
sudo bot-mitigation start
sudo bot-mitigation stop
sudo bot-mitigation restart
```

For systemd:

```sh
sudo systemctl status bot-mitigation.service
sudo journalctl -u bot-mitigation.service -n 100 --no-pager
```

For OpenRC:

```sh
sudo rc-service bot-mitigation status
sudo rc-update show default
```

The service follows newly appended lines, including log rotation, and prevents concurrent daemon instances with a lock. A bounded restart policy is used under systemd. `stop` removes owned mitigation and leaves the emergency lock active. Resume observation with `sudo bot-mitigation emergency-enable`. A stopped daemon cannot issue new bans; kernel timeouts also limit the lifetime of penalties if cleanup fails. Use `emergency-disable` when you need immediate recovery.

## Configuration

```sh
sudo bot-mitigation config
sudoedit /etc/bot-mitigation/config.conf
sudo bot-mitigation doctor
sudo bot-mitigation restart
```

The generated configuration is the authoritative list of defaults. It uses one `KEY="value"` assignment per line and full-line `#` comments. It is **parsed as data**, never sourced or evaluated as shell code. Do not use commands, variable expansion, shell escapes, or inline comments. Lists are space-separated; paths containing whitespace are unsupported. Log and database paths must be absolute. Unknown or invalid values are rejected.

| Setting group | Purpose |
| --- | --- |
| `MODE` | `dry-run` or `enforce`; CLI mode commands update this safely. |
| `LOG_FILES`, `WEB_SERVER` | Explicit access logs, or discovery and web-server identification. |
| `LOG_IP_MODE`, `FIREWALL_SCOPE` | Safety acknowledgments required for enforcement: `direct` and `host`, respectively. |
| `FIREWALL_BACKEND` | `auto`, `nftables`, `iptables`, or `none`; `none` permits observation only. |
| `PROTECTED_PORTS`, `MANAGEMENT_PORTS` | TCP/UDP web ports eligible for mitigation (80 and 443), and management ports that must be excluded (22). Add any custom SSH/management port to the latter. |
| `WINDOW_SHORT`, `WINDOW_MEDIUM`, `WINDOW_LONG`, `WINDOW_HISTORY` | Rolling windows: 10, 30, 60, and 300 seconds by default. |
| `MIN_UNIQUE_IPS`, `BURST_MULTIPLIER` | Minimum distributed participation (20) and elevation above the adaptive request baseline (5×). |
| `SCORE_THRESHOLD_OBSERVE`, `SCORE_THRESHOLD_BLOCK` | Observation (55) and enforcement (80) thresholds; block must exceed observe. |
| `DEFAULT_BLOCK_TIME`, `MAX_BLOCK_TIME` | Temporary penalty bounds in seconds: 300 initially, at most 3,600. |
| `WARMUP_TIME` | Initial live observation period before automatic penalties; 300 seconds. |
| `MAX_EVENTS`, `MAX_SCOPES`, `MAX_TRACKED_IPS` | Bounded detector capacity: 20,000 events, 256 scopes, 50,000 tracked addresses. |
| `TRUSTED_IPS`, `TRUSTED_NETWORKS`, `TRUSTED_PROXY_RANGES` | Trusted exact addresses and networks that must not be mitigated. |
| `EXCLUDED_PATHS` | URL path prefixes excluded before detector scoring. |
| `ENABLE_GEOIP`, `GEOIP_COUNTRY_DB`, `GEOIP_ASN_DB` | Optional local GeoIP/ASN enrichment. |
| `ENABLE_NETWORK_ESCALATION`, `ENABLE_ASN_ESCALATION`, `ENABLE_COUNTRY_ESCALATION` | Reserved, disabled capabilities; broad automatic escalation is not implemented. |
| `ENABLE_CHALLENGE` | Reserved and disabled; generic HTTP challenge integration is not implemented. |
| `LOG_LEVEL`, `STATE_RETENTION` | Operational log verbosity and repeat-history lifetime (86,400 seconds). |
| `LOG_MAX_BYTES`, `LOG_KEEP` | Application-log rotation: 5 MiB and three archived logs. |

Set only documented fields. Configuration validation covers numbers, ranges, window ordering, thresholds, paths, ports, IP/CIDR values, backend selection, and unsupported feature switches. An invalid configuration must be corrected before enforcement can proceed.

### Multiple Websites

Discovery checks bounded common Nginx, Apache, LiteSpeed/OpenLiteSpeed, cPanel-style domain, and Plesk virtual-host access-log locations at startup; it does not continuously walk the entire filesystem. Unusual layouts should use explicit paths:

```ini
WEB_SERVER="nginx"
LOG_FILES="/var/log/nginx/example.access.log /var/log/nginx/shop.access.log"
PROTECTED_PORTS="80 443"
```

Use one log per virtual host for clear campaign attribution. A log shared by multiple domains cannot safely provide separate domain attribution except when it uses the supported first-field virtual-host prefix. The attribution key combines log source and that prefix when present. Access-log entries from unknown formats are skipped rather than guessed. JSON logs, custom field layouts, syslog prefixes, and arbitrary forwarded-header layouts may need a conventional dedicated access log.

Log files must exist and be readable by the service. Ensure rotation creates a new readable file at the configured path. The monitor follows replacement files with `tail -F`; it does not reprocess old historical logs at every service restart. New virtual hosts added after startup require a restart for discovery. Avoid feeding duplicate logs of the same requests.

Even with per-log campaign detection, a firewall ban applies to the source IP across all configured web ports on that machine. A visitor using the same IP on a different domain can be affected. If site-specific penalties are essential, use a site-aware reverse-proxy/WAF integration instead of this firewall backend.

### Reverse Proxies and CDNs

A firewall can block the source address actually arriving at the server. Behind a CDN or load balancer, that address is often the proxy, while an application access log may contain a rewritten client address. Banning the proxy can disrupt all visitors; banning the rewritten client at the origin may have no effect.

Configure trusted infrastructure before enabling enforcement:

```ini
TRUSTED_PROXY_RANGES="192.0.2.0/24 2001:db8:1234::/48"
TRUSTED_IPS="198.51.100.10"
TRUSTED_NETWORKS="198.51.100.128/25"
```

The example addresses are documentation ranges; replace them with your actual infrastructure. Only configure trusted networks you control or have verified from your provider's authoritative list. Localhost and private/internal addresses are protected automatically.

This tool does not infer trust from `X-Forwarded-For`, `X-Real-IP`, or `CF-Connecting-IP`, and it does not modify the web server's real-IP configuration. Standard access logs do not retain enough information to independently prove the relationship between a rewritten client IP and its connection peer. Audit that trust boundary yourself. Use observation mode where the true client cannot be attributed safely. Origin firewall mitigation is generally inappropriate for fully proxied traffic; apply controls at the trusted edge instead.

### Exclusions

```ini
EXCLUDED_PATHS="/.well-known/acme-challenge/ /health /payment-webhook"
```

Choose exclusions for your actual health checks, API callbacks, payment webhooks, and monitoring paths. Prefix exclusions bypass detection for matching paths, so avoid overly broad entries. A path exclusion cannot bypass an IP ban already enforced by the firewall; use trusted source IPs/networks where that is required.

```sh
sudo bot-mitigation whitelist add 198.51.100.10
sudo bot-mitigation whitelist add 2001:db8:abcd::/48
sudo bot-mitigation whitelist list
sudo bot-mitigation whitelist remove 198.51.100.10
```

Allowlists express administrator trust. A claimed `Googlebot` or `Bingbot` User-Agent does not confer trust. Automatic crawler DNS verification is not implemented; use independently verified official address ranges if you need crawler allowlisting and maintain them as providers change.

### Blacklists

```sh
read -r -p "Verified public source IP to block: " SUSPECT_IP
sudo bot-mitigation blacklist add "$SUSPECT_IP"
sudo bot-mitigation blacklist list
sudo bot-mitigation blacklist remove "$SUSPECT_IP"
sudo bot-mitigation unblock "$SUSPECT_IP"
```

Manual penalties follow the same web-port, timeout, address-validation, and trusted-network protections. Dry-run still applies. Normal blacklist commands reject default routes, localhost, private/internal ranges, trusted infrastructure, documentation/special-purpose addresses, and networks broader than IPv4 /24 or IPv6 /64. They never create automatic permanent bans.

### GeoIP and ASN

GeoIP is optional. The core detector works without a MaxMind database or subscription. Where configured, use local GeoLite2 Country and ASN databases from an authorized source and the optional `mmdblookup` utility. Obtain and refresh databases independently according to MaxMind's licensing and download requirements.

```ini
ENABLE_GEOIP="yes"
GEOIP_COUNTRY_DB="/usr/share/GeoIP/GeoLite2-Country.mmdb"
GEOIP_ASN_DB="/usr/share/GeoIP/GeoLite2-ASN.mmdb"
```

Lookups are cached and performed outside the per-request parsing hot path. Missing tools, unreadable or malformed databases, and lookup failures degrade to behavioral detection. Country and ASN labels are supporting context only; geography is never proof of malicious traffic. No country-wide or ASN-wide blocking is implemented. `MAXMIND_LICENSE_KEY` is accepted for configuration compatibility, kept out of output, and never used to download databases. Leave it empty: the application does not need this secret.

## Behavior

The detector maintains bounded rolling state for each log source. It combines distributed participation, unusual aggregate velocity relative to a lightweight baseline, fresh addresses, missing-referrer concentration, shared User-Agents, and concentrated URLs where the parsed format provides those fields. Human-readable events expose the score and contributing signals. No single weak indicator triggers a default automatic penalty.

The risk weights are fixed, auditable values in the embedded detector; participation, time windows, baseline multiplier, and decision thresholds are configurable. Country and ASN concentration together contribute at most six points. A live daemon evaluates on its one-second heartbeat, including after an isolated burst ends.

The first observation period has little historical context. The baseline is local and deterministic, not machine learning, and does not understand your business's marketing campaigns, flash sales, mobile-app traffic, or genuine breaking-news spikes. It is reset or rebuilt when the daemon restarts; automatic penalties have a 300-second default startup warmup. The 10-, 30-, and 60-second decision windows share a 300-second history. Configure conservative thresholds and keep observation enabled long enough to cover ordinary peaks. Capacity limits are intentional: saturation is counted and degrades detection toward observation rather than allowing unbounded memory growth. This implementation has no certified request-throughput limit; validate against your expected peak load.

The tool does not implement full request-sequence analysis, browser fingerprinting, cookie/session verification, TLS fingerprinting, a browser challenge, automatic search-engine verification, or upstream CDN APIs. It cannot distinguish all coordinated legitimate visitors from a bot campaign. Automatic CIDR, ASN, and country escalation switches reject enabling unsupported behavior instead of pretending that it is available.

The default candidate gate additionally requires a sufficiently large cohort sharing the same User-Agent and path, a high proportion of empty referrers within that cohort, synchronized arrivals or repeated correlated behavior, and no observed normal navigation by the candidate IP. Common logs lacking referrer/User-Agent evidence support observation but cannot satisfy that gate.

Automatic penalties target individual participating source addresses and expire in the kernel. Repeated detections can lengthen penalties up to the configured maximum; stored history is bounded. Firewall rules are scoped to configured HTTP/HTTPS ports. Existing firewall policy still applies, and external firewall-manager reloads can remove application-owned objects; inspect `doctor` after firewall changes.

### HTTP

`ENABLE_CHALLENGE="no"` is mandatory in this release. A generic, safe challenge requires application- or virtual-host-specific integration, signed cookie verification, careful caching, and full rollback of web-server changes. This project does not silently rewrite virtual hosts. Because mitigation observes completed access-log entries, it cannot guarantee suppression of third-party page scripts.

## Statistics

```sh
sudo bot-mitigation stats
sudo bot-mitigation logs
sudo bot-mitigation status
```

Detector counters describe this process's observed traffic and rolling windows, not analytics visitors. An address is not a person, especially behind NAT. A request count is not a session count. Logs include the score, source, proposed action, and available signals. Retention and rotation bound application state and log growth; access-log retention remains your web server's responsibility.

For false positives, start with the reason printed by the detector:

1. Confirm log format and client-IP attribution with `doctor`.
2. Add your verified management, proxy, monitoring, and callback sources to allowlists.
3. Exclude specific machine endpoints where appropriate.
4. Raise participation or score thresholds to accommodate known legitimate peaks.
5. Replay representative samples, including peaks and quiet traffic, before enforcing again.

Avoid tuning solely on a synthetic attack sample. Review business events and genuine traffic from every geography. Do not lower thresholds merely because traffic lacks referrers.

## Testing

These commands never apply firewall penalties:

```sh
bash script.sh self-test
bash script.sh analyze /absolute/path/to/access.log
```

`analyze` processes a sample through the same detector, prints scores and proposed actions, and is suitable for offline tuning. Synthetic self-tests cover legitimate direct traffic, small and mixed traffic, distributed correlated bursts, spoofed crawler User-Agents, IPv6, and malformed lines. They require no real website traffic.

The repository's integration checks use temporary directories and mock system/firewall commands, so they can exercise installation, repeat installation, service generation, validation, mode changes, emergency recovery, rollback, and uninstall without changing the development machine's firewall. Run the repository checks with:

```sh
bash -n script.sh
bash tests.sh
# If available:
shellcheck script.sh tests.sh
```

The tests require Python 3 solely for an isolated firewall command fixture; the application itself has no Python dependency. They also run a real local foreground log follower to verify idle-burst evaluation, log rotation, and clean termination. Mock tests do not substitute for Linux kernel, init-system, throughput, and real workload validation in a disposable VM.

## Updates

There is no unattended updater. Download a reviewed release over HTTPS, verify its publisher and integrity through a trusted channel, inspect it, and run:

```sh
bash -n script.sh
bash script.sh self-test
sudo bash script.sh install
sudo bot-mitigation doctor
sudo bot-mitigation status
```

Reinstallation preserves your existing configuration, allowlists, and compatible state; the executable is backed up before replacement. A failed installation rolls back its owned changes. Review release notes for configuration or state migrations before upgrading. Do not use an unverified URL supplied in a log entry, issue comment, or third-party message.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No requests analyzed | Confirm explicit `LOG_FILES` paths, readability, new appended traffic, and supported combined/common format. Run `doctor`. |
| Many malformed lines | Inspect a redacted line and compare its field order with a standard access log. Do not guess which field is the IP. |
| Service will not start | Run `doctor` and inspect systemd/OpenRC service logs. Correct configuration or missing prerequisites; keep enforcement off. |
| No usable firewall backend | Monitoring can still provide observations; install/configure nftables or the complete iptables/ipset fallback before enforcement. |
| Origin blocks have no effect | Confirm whether clients connect through a reverse proxy/CDN. Origin firewall rules cannot target a client address absent from origin packets. |
| Visitors are affected unexpectedly | Run `emergency-disable`, inspect the logged reasons, correct attribution/allowlists/thresholds, and return to dry-run. |
| GeoIP is unavailable | Verify local database paths and `mmdblookup`; behavior-only detection remains usable. |
| Application objects disappeared | A firewall reload or another administrator may have removed them. Inspect `doctor` and deliberately restart after confirming the current policy. |
| Unsupported init system | Install under systemd/OpenRC or manage a foreground daemon explicitly; the installer will not falsely claim boot persistence. |

`doctor` is read-only. It reports configuration, OS/package manager, service state, logs, parser availability, proxy concerns, and firewall capabilities; its output does not certify the correctness of an upstream proxy configuration.

## Manual Recovery

If you have a reviewed copy of this release's source, first use its normal recovery path even when the installed CLI is missing:

```sh
sudo bash script.sh emergency-disable
```

If that reports incomplete cleanup, use the manual steps below. First stop the service so it cannot recreate rules. These blocks verify the exact application ownership marker before changing a service; a coincidentally named, unowned service is left untouched. On systemd:

```sh
sudo bash <<'RECOVERY'
set -eu
unit=/etc/systemd/system/bot-mitigation.service
[[ -f $unit && ! -L $unit ]]
awk '/^# Managed by Linux Bot Mitigation$/ {owned=1} END {exit !owned}' "$unit"
systemctl disable bot-mitigation.service
# A missing executable can make ExecStopPost fail after the daemon has stopped.
systemctl stop bot-mitigation.service || true
state=$(systemctl show --property=ActiveState --value bot-mitigation.service)
[[ $state == inactive || $state == failed ]]
[[ $(systemctl show --property=MainPID --value bot-mitigation.service) == 0 ]]
rm -f -- "$unit"
systemctl daemon-reload
RECOVERY
```

On OpenRC:

```sh
sudo bash <<'RECOVERY'
set -eu
init_script=/etc/init.d/bot-mitigation
[[ -f $init_script && ! -L $init_script ]]
awk '/^# Managed by Linux Bot Mitigation$/ {owned=1} END {exit !owned}' "$init_script"
rc-service bot-mitigation stop
rc-update del bot-mitigation default
rm -f -- "$init_script"
RECOVERY
```

The OpenRC block deliberately stops on a service-stop error. If the missing executable causes its cleanup callback to fail, retain the init script, restore the missing CLI from the same reviewed source, and retry:

```sh
bash -n script.sh
bash script.sh self-test
sudo bash -c 'test ! -e /usr/local/sbin/bot-mitigation && install -m 755 "$1" /usr/local/sbin/bot-mitigation' bash "$PWD/script.sh"
sudo rc-service bot-mitigation stop
```

Do not remove a service definition while the daemon is still running. Confirm `rc-service bot-mitigation status` on OpenRC; investigate any continuing stop failure before proceeding.

Then inspect the ownership manifest. It records the backend, an eight-digit hexadecimal ownership token, comma-separated web ports, and enabled IP families:

```sh
sudo cat /var/lib/bot-mitigation/firewall.owner
```

For nftables, the sole table is `inet bot_mitigation`; its sets are `blocked4` and `blocked6`. Inspect it and confirm its table comment equals `bot-mitigation:` followed by the manifest token:

```sh
sudo nft list table inet bot_mitigation
```

After confirming that ownership and reviewing the table contents, remove exactly that table. This block also checks the token programmatically. The table is reserved exclusively for this application; review any administrator-added objects before deleting it.

```sh
sudo bash <<'RECOVERY'
set -eu
manifest=/var/lib/bot-mitigation/firewall.owner
[[ -f $manifest && ! -L $manifest ]]
read -r backend token ports families extra < "$manifest"
[[ $backend == nftables && -z ${extra:-} && $token =~ ^[0-9a-f]{8}$ ]]
table=$(nft list table inet bot_mitigation)
awk -v marker="\\"bot-mitigation:$token\\"" '$1=="comment" && $2==marker {owned=1} END {exit !owned}' <<< "$table"
nft delete table inet bot_mitigation
RECOVERY
```

For the iptables backend, owned chains are `BOT_MITIGATION_TOKEN` and sets are `bot_mitigation4_TOKEN` / `bot_mitigation6_TOKEN`, where `TOKEN` is the manifest token. The following recovery block reads the trusted local manifest, validates it, verifies marked chain rules, and deletes only exact application rules and sets. Run it **after stopping the service**, and only when the manifest still describes this installation. A failure should be investigated; do not replace a failing command with a global flush.

```sh
sudo bash <<'RECOVERY'
set -eu
manifest=/var/lib/bot-mitigation/firewall.owner
[[ -f $manifest && ! -L $manifest ]]
read -r backend token ports families extra < "$manifest"
[[ $backend == iptables && -z ${extra:-} ]]
[[ $token =~ ^[0-9a-f]{8}$ && $ports =~ ^[0-9]+(,[0-9]+)*$ ]]
[[ $families == 4 || $families == 4,6 ]]
chain="BOT_MITIGATION_$token"
marker="bot-mitigation:$token"
IFS=, read -r -a port_list <<< "$ports"
for family in 4 6; do
  [[ $family != 6 || $families == 4,6 ]] || continue
  command=iptables
  [[ $family != 6 ]] || command=ip6tables
  set_name="bot_mitigation${family}_$token"
  # Distinguish an absent chain from unavailable tools or denied access.
  "$command" -w 5 -S INPUT >/dev/null
  if rules=$("$command" -w 5 -S "$chain" 2>/dev/null); then
    # Refuse chains containing unrecognized rules before removing any hooks.
    while IFS= read -r rule; do
      case "$rule" in
        "-N $chain") ;;
        "-A $chain "*)
          [[ $rule == *"--comment $marker "* || $rule == *"--comment \\"$marker\\" "* ]] ;;
        *) exit 1 ;;
      esac
    done <<< "$rules"
    for port in "${port_list[@]}"; do
      for protocol in tcp udp; do
        while "$command" -w 5 -C INPUT -p "$protocol" --dport "$port" -m comment --comment "$marker" -j "$chain" 2>/dev/null; do
          "$command" -w 5 -D INPUT -p "$protocol" --dport "$port" -m comment --comment "$marker" -j "$chain"
        done
      done
    done
    for action in drop return; do
      if [[ $action == drop ]]; then
        rule_args=(-m set --match-set "$set_name" src -m comment --comment "$marker" -j DROP)
      else
        rule_args=(-m comment --comment "$marker" -j RETURN)
      fi
      while "$command" -w 5 -C "$chain" "${rule_args[@]}" 2>/dev/null; do
        "$command" -w 5 -D "$chain" "${rule_args[@]}"
      done
    done
    "$command" -w 5 -X "$chain"
  fi
  if ipset list "$set_name" >/dev/null 2>&1; then ipset destroy "$set_name"; fi
done
RECOVERY
```

Never use `nft flush ruleset`, a global iptables flush, or a global ipset destroy. If the manifest is missing or the names/markers disagree, inspect the remaining rules manually or use the verified source script's recovery commands; do not guess ownership.

The manual iptables block conservatively stops if unrelated rules were added inside the application's chain. The reviewed script's `emergency-disable` can still detach exact marked hooks and clear its token-owned sets while retaining those unrelated rules and the recovery manifest.

After stopping the service and removing its firewall objects, the executable and runtime directories may be removed. Preserve `/etc/bot-mitigation/` and `/var/log/bot-mitigation.log` until debugging is complete. Prefer reinstalling the reviewed script and using `uninstall` to get the normal ownership checks and cleanup. Dependencies are not removed by uninstall. After a non-purge uninstall has removed the CLI, remove retained data using your reviewed source copy: `sudo bash script.sh uninstall --purge`.

## Security

This is security-sensitive root software. Review it before deployment, validate in a disposable Linux environment, and maintain a recovery path. The project ships auditable source and repeatable tests; those are not a security audit or a guarantee of production suitability for every topology. A compromised root account, web server, or writable log source can undermine its evidence and controls. Access logs and security events contain IP addresses and request metadata: restrict permissions and set retention appropriate to your deployment.

Contributions should keep the single-script architecture understandable and avoid per-request subprocesses. Include a regression test for security boundaries, parser changes, and lifecycle changes. Run syntax validation, ShellCheck where available, internal self-tests, and safe integration tests. Document new configuration fields and explain their fail-open behavior. Never submit real credentials or unredacted production logs in public issues. Report vulnerabilities privately through the repository maintainer's published security contact before disclosing an exploit publicly.

## License

Licensed under the [MIT License](LICENSE).
