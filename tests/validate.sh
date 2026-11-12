#!/bin/zsh -f

set -euo pipefail
umask 022

unset IFS CDPATH ENV BASH_ENV ZDOTDIR DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH LD_PRELOAD
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export LC_ALL=C

readonly ROOT_DIR="${0:A:h:h}"

scripts=(
  "$ROOT_DIR/install.sh"
  "$ROOT_DIR/bin/zoog-cn-bypass"
  "$ROOT_DIR/src/daemon.sh"
  "$ROOT_DIR/scripts/install-local.sh"
  "$ROOT_DIR/scripts/update-data.sh"
  "$ROOT_DIR/tests/validate.sh"
)

/bin/zsh -f -n "${scripts[@]}"

for script_file in "${scripts[@]}"; do
  if [[ "$(/usr/bin/head -n 1 "$script_file")" != "#!/bin/zsh -f" ]]; then
    print -u 2 -- "Script missing '#!/bin/zsh -f' shebang: $script_file"
    exit 1
  fi
done

if /usr/bin/grep -q 'codeload\.github\.com' "$ROOT_DIR/install.sh"; then
  print -u 2 -- "install.sh must not download remote archives."
  exit 1
fi

/usr/bin/plutil -lint "$ROOT_DIR/launchd/com.local.zoog-cn-bypass.plist" >/dev/null
/usr/bin/plutil -lint "$ROOT_DIR/launchd/com.local.zoog-cn-dns.plist" >/dev/null

[[ "$(/usr/bin/wc -l < "$ROOT_DIR/data/cn-ipv4.txt" | /usr/bin/tr -d ' ')" -gt 5000 ]]
[[ "$(/usr/bin/wc -l < "$ROOT_DIR/data/cn-ipv6.txt" | /usr/bin/tr -d ' ')" -gt 1900 ]]
/usr/bin/grep -q '^server=/baidu\.com/223\.5\.5\.5$' "$ROOT_DIR/data/accelerated-domains.china.conf"
/usr/bin/grep -q '^server=/a1\.mzstatic\.com/223\.5\.5\.5$' "$ROOT_DIR/data/apple.china.conf"
/usr/bin/grep -q '^user=nobody$' "$ROOT_DIR/config/dnsmasq.conf"
/usr/bin/grep -q '^stop-dns-rebind$' "$ROOT_DIR/config/dnsmasq.conf"
/usr/bin/grep -q '^clear-on-reload$' "$ROOT_DIR/config/dnsmasq.conf"
/usr/bin/grep -q '^servers-file=/Library/Application Support/ZoogCNBypass/upstream-servers\.conf$' "$ROOT_DIR/config/dnsmasq.conf"

for domain_file in "$ROOT_DIR/data/accelerated-domains.china.conf" "$ROOT_DIR/data/apple.china.conf"; do
  /usr/bin/awk '
    /^[[:space:]]*$/ || /^#/ { next }
    /^server=\/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\/223\.5\.5\.5$/ { next }
    { exit 1 }
  ' "$domain_file"
done

/usr/bin/awk '
  /^[[:space:]]*$/ || /^#/ { next }
  /^server=[0-9]{1,3}(\.[0-9]{1,3}){3}$/ { found = 1; next }
  { bad = 1; exit 1 }
  END { exit(bad || !found) }
' "$ROOT_DIR/config/upstream-servers.conf"

/usr/bin/awk '
  /^[[:space:]]*$/ { next }
  /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|1\.1\.1\.|8\.8\.8\.)/ { exit 1 }
  /^[0-9]{1,3}(\.[0-9]{1,3}){3}\/([89]|[12][0-9]|3[0-2])$/ { next }
  { exit 1 }
' "$ROOT_DIR/data/cn-ipv4.txt"

/usr/bin/awk '
  /^[[:space:]]*$/ { next }
  /^[23][0-9a-fA-F:]+\/(1[6-9]|[2-9][0-9]|1[01][0-9]|12[0-8])$/ { next }
  { exit 1 }
' "$ROOT_DIR/data/cn-ipv6.txt"

# Ensure no China route has prefix length <= 9 so the 16 ZoogVPN override
# routes (/9../2) never shadow a China-direct prefix.
/usr/bin/awk -F/ '
  /^[[:space:]]*$/ { next }
  $2 <= 9 { exit 1 }
' "$ROOT_DIR/data/cn-ipv4.txt"

/usr/bin/awk '
  /^[[:space:]]*$/ || /^#/ { next }
  /^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+[ \t]+[0-9]{1,3}(\.[0-9]{1,3}){3}[ \t]*$/ { found = 1; next }
  { bad = 1; exit 1 }
  END { exit(bad || !found) }
' "$ROOT_DIR/config/corp-dns.conf"
/usr/bin/grep -q 'ensure_corp_dns' <(/usr/bin/sed -n '/^reconcile() {/,/^}/p' "$ROOT_DIR/src/daemon.sh")
/usr/bin/grep -q 'clear_corp_dns' "$ROOT_DIR/src/daemon.sh"
/usr/bin/grep -q 'clash_tun_interface' "$ROOT_DIR/src/daemon.sh"
/usr/bin/grep -q 'ensure_zoog_override_routes' "$ROOT_DIR/src/daemon.sh"
/usr/bin/grep -q 'ensure_core_network_health' "$ROOT_DIR/src/daemon.sh"
/usr/bin/grep -q 'ensure_physical_gateway_health' "$ROOT_DIR/src/daemon.sh"
/usr/bin/grep -q 'ensure_univpn_gateway_routes' "$ROOT_DIR/src/daemon.sh"
/usr/bin/grep -q 'clean_dead_local_proxies' "$ROOT_DIR/src/daemon.sh"
/usr/bin/grep -q 'clean_dead_service_dns' "$ROOT_DIR/src/daemon.sh"

if /usr/bin/grep -q '=~.*\\\.' "$ROOT_DIR/src/daemon.sh"; then
  print -u 2 -- "Use [.] instead of \\. inside zsh =~ regexes in src/daemon.sh"
  exit 1
fi

if /usr/bin/grep -q '=~.*\\\.' "$ROOT_DIR/bin/zoog-cn-bypass"; then
  print -u 2 -- "Use [.] instead of \\. inside zsh =~ regexes in bin/zoog-cn-bypass"
  exit 1
fi

# Runtime smoke checks (catches zsh regex parse errors that -n cannot detect).
"$ROOT_DIR/bin/zoog-cn-bypass" --help >/dev/null
[[ "$("$ROOT_DIR/bin/zoog-cn-bypass" --version)" == "$(<"$ROOT_DIR/VERSION")" ]]
/bin/zsh -f -c '
  eval "$(/usr/bin/awk '\''
    /^if \[\[ "\$\(\/usr\/bin\/id -u\)" -ne 0 \]\]/,/^fi$/ { next }
    /^case "\$\{1:-reconcile\}" in$/ { exit }
    { print }
  '\'' "$1")"
  set -e
  valid_ipv4_gateway "192.168.1.1"
  ! valid_ipv4_gateway "bad"
  valid_ipv6_gateway "fe80::1%en0"
  valid_interface "en0"
  valid_utun_interface "utun9"
  ! valid_utun_interface "en0"
  valid_service_name "Wi-Fi (en0)"
  valid_domain "xytdt.com"
  valid_ipv4_cidr "223.5.5.0/24"
  ! valid_ipv4_cidr "10.0.0.0/8"
  valid_ipv6_cidr "2400:3200::/32"
  [[ "$(normalize_netstat_cidr "192.168.1")" == "192.168.1.0/24" ]]
  [[ "$(normalize_netstat_cidr "10.23/16")" == "10.23.0.0/16" ]]
  [[ "$(normalize_netstat_cidr "192.168.1.1/32")" == "192.168.1.1/32" ]]

  host_sample=$'\''   route to: 61.157.75.133\ndestination: 61.157.75.133\n    gateway: 192.168.0.1\n  interface: en0'\''
  net_sample=$'\''   route to: 61.157.75.133\ndestination: 61.128.0.0\n       mask: 255.192.0.0\n    gateway: 172.20.10.1\n  interface: en0'\''
  utun_sample=$'\''   route to: 1.1.1.1\ndestination: default\n  interface: utun7'\''
  [[ "$(print -r -- "$host_sample" | parse_route_get_v4)" == "61.157.75.133|192.168.0.1|en0" ]]
  [[ "$(print -r -- "$net_sample" | parse_route_get_v4)" == "61.128.0.0|172.20.10.1|en0" ]]
  [[ "$(print -r -- "$utun_sample" | parse_route_get_v4)" == "default||utun7" ]]

  # Regression test: pinned UniVPN gateways update across same-interface gateway
  # changes, missing /32 host routes, interface switches, and .ini removals.
  tmp_pinned="$(/usr/bin/mktemp /tmp/zoog-pinned-test.XXXXXX)"
  trap '\''/bin/unlink "$tmp_pinned" "$tmp_pinned.$$" 2>/dev/null || true'\'' EXIT
  /bin/unlink "$tmp_pinned"
  typeset -A mock_routes=()
  typeset -a mock_ini=("61.157.75.133" "182.150.6.130")
  mock_iface_for_gw() {
    case "$1" in
      192.168.0.1|172.20.10.1) print -r -- "en0" ;;
      10.0.0.1) print -r -- "en5" ;;
      *) print -r -- "en0" ;;
    esac
  }
  log_message() { :; }
  discover_univpn_gateways() { print -r -l -- "${mock_ini[@]}"; }
  route_summary_v4() { print -r -- "${mock_routes[$1]:-61.128.0.0|172.20.10.1|en0}"; }
  run_route_cmd() {
    # Expect: -n <add|change|delete> (-host|-net) <ip> [gw]
    local op="$2" kind="$3" ip="${4%/*}" gw="${5:-}"
    case "$op" in
      add)
        [[ -z "${mock_routes[$ip]:-}" ]] || return 1
        mock_routes[$ip]="$ip|$gw|$(mock_iface_for_gw "$gw")"
        ;;
      change)
        [[ -n "${mock_routes[$ip]:-}" ]] || return 1
        local existing_iface="${mock_routes[$ip]##*|}"
        local target_iface="$(mock_iface_for_gw "$gw")"
        [[ "$existing_iface" == "$target_iface" ]] || return 1
        mock_routes[$ip]="$ip|$gw|$target_iface"
        ;;
      delete)
        unset "mock_routes[$ip]"
        ;;
    esac
  }

  # 1) Initial pin on Wi-Fi 192.168.0.1 (en0)
  ensure_univpn_gateway_routes "192.168.0.1" "en0" "$tmp_pinned"
  [[ "${mock_routes[61.157.75.133]}" == "61.157.75.133|192.168.0.1|en0" ]]
  [[ "${mock_routes[182.150.6.130]}" == "182.150.6.130|192.168.0.1|en0" ]]

  # 2) Same interface (en0) switches to hotspot gateway 172.20.10.1
  ensure_univpn_gateway_routes "172.20.10.1" "en0" "$tmp_pinned"
  [[ "${mock_routes[61.157.75.133]}" == "61.157.75.133|172.20.10.1|en0" ]]
  [[ "${mock_routes[182.150.6.130]}" == "182.150.6.130|172.20.10.1|en0" ]]

  # 3) External deletion of /32 host route (falls back to subnet route on en0) is restored
  unset "mock_routes[61.157.75.133]"
  ensure_univpn_gateway_routes "172.20.10.1" "en0" "$tmp_pinned"
  [[ "${mock_routes[61.157.75.133]}" == "61.157.75.133|172.20.10.1|en0" ]]

  # 4) Interface switch en0 -> en5 where route change fails falls back to delete+add
  ensure_univpn_gateway_routes "10.0.0.1" "en5" "$tmp_pinned"
  [[ "${mock_routes[61.157.75.133]}" == "61.157.75.133|10.0.0.1|en5" ]]

  # 5) Removing an IP from .ini prunes its pinned /32 route and state file
  mock_ini=("61.157.75.133")
  ensure_univpn_gateway_routes "10.0.0.1" "en5" "$tmp_pinned"
  [[ -z "${mock_routes[182.150.6.130]:-}" ]]
  [[ "$(<"$tmp_pinned")" == "61.157.75.133" ]]

  remove_univpn_gateway_routes "$tmp_pinned"
  [[ ! -e "$tmp_pinned" ]]
  [[ -z "${mock_routes[61.157.75.133]:-}" ]]
' _ "$ROOT_DIR/src/daemon.sh"

machine_home_prefix='/''Users/'
if /usr/bin/grep -R -n "$machine_home_prefix" "$ROOT_DIR" --exclude-dir=.git; then
  print -u 2 -- "A machine-specific home-directory path leaked into the repository."
  exit 1
fi

dnsmasq=""
for candidate in /opt/homebrew/opt/dnsmasq/sbin/dnsmasq /usr/local/opt/dnsmasq/sbin/dnsmasq; do
  if [[ -x "$candidate" ]]; then
    dnsmasq="$candidate"
    break
  fi
done

if [[ -n "$dnsmasq" ]]; then
  temporary_conf="$(/usr/bin/mktemp /tmp/zoog-cn-dnsmasq.XXXXXX)"
  trap '/bin/unlink "$temporary_conf" 2>/dev/null || true' EXIT INT TERM
  /usr/bin/sed \
    -e "s#/Library/Application Support/ZoogCNBypass/upstream-servers.conf#$ROOT_DIR/config/upstream-servers.conf#g" \
    -e "s#/Library/Application Support/ZoogCNBypass#$ROOT_DIR/data#g" \
    "$ROOT_DIR/config/dnsmasq.conf" > "$temporary_conf"
  "$dnsmasq" --test --conf-file="$temporary_conf" >/dev/null
fi

print -- "Validation passed."
