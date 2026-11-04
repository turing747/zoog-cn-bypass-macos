#!/bin/zsh -f

set -u
umask 022

unset IFS CDPATH ENV BASH_ENV ZDOTDIR DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH LD_PRELOAD
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export LC_ALL=C

if [[ "$(/usr/bin/id -u)" -ne 0 ]]; then
  exit 77
fi

readonly LABEL="com.local.zoog-cn-bypass"
readonly DNS_LABEL="com.local.zoog-cn-dns"
readonly INSTALL_DIR="/Library/Application Support/ZoogCNBypass"
readonly ROUTES_V4="$INSTALL_DIR/cn-ipv4.txt"
readonly ROUTES_V6="$INSTALL_DIR/cn-ipv6.txt"
readonly UPSTREAM_SERVERS_FILE="$INSTALL_DIR/upstream-servers.conf"
readonly RUN_DIR="/var/run/$LABEL"
readonly STATE_FILE="$RUN_DIR/state"
readonly ACTIVE_V4="$RUN_DIR/active-v4"
readonly ACTIVE_V6="$RUN_DIR/active-v6"
readonly ACTIVE_OVERRIDE_V4="$RUN_DIR/active-override-v4"
readonly OVERRIDE_STATE_FILE="$RUN_DIR/override-state"
readonly SUPPRESSED_PROXIES_FILE="$RUN_DIR/suppressed-proxies"
readonly ERROR_FILE="$RUN_DIR/error"
readonly LOCK_FILE="$RUN_DIR/lock"
readonly WORK_DIR="$RUN_DIR/chunks"
# Parallel route worker tuning (see compute_route_jobs).
readonly MAX_ROUTE_JOBS=32
readonly MIN_ROUTES_PER_JOB=64
readonly CHUNKS_PER_JOB=4
readonly VPN_SERVICE="ZoogVPN"
readonly CLASH_TUN_IP="198.18.0.1"
readonly CLASH_TUN_DNS="198.18.0.2"
readonly DNS_STATE_KEY="State:/Network/Service/com.local.zoog-cn-bypass/DNS"
readonly LOCAL_DNS="127.0.0.1"
# Corporate split-horizon DNS (see config/corp-dns.conf).
readonly CORP_DNS_CONF="$INSTALL_DIR/corp-dns.conf"
readonly CORP_DNS_KEY_PREFIX="State:/Network/Service/com.local.zoog-cn-bypass.corp"
readonly CORP_DNS_ORDER=50

# 16 prefixes that split Clash TUN's 8 routes (1/8, 2/7, 4/6, 8/5, 16/4, 32/3,
# 64/2, 128/1) as well as OpenVPN def1 (0/1, 128/1) into /(N+1) halves.
# Longest prefix here is /9, so all China routes (/10../32), Tailscale (/10),
# corporate VPN subnets (/8../32), loopback (/8), LAN, and multicast (/4) win.
readonly -a CLASH_OVERRIDE_PREFIXES=(
  1.0.0.0/9
  1.128.0.0/9
  2.0.0.0/8
  3.0.0.0/8
  4.0.0.0/7
  6.0.0.0/7
  8.0.0.0/6
  12.0.0.0/6
  16.0.0.0/5
  24.0.0.0/5
  32.0.0.0/4
  48.0.0.0/4
  64.0.0.0/3
  96.0.0.0/3
  128.0.0.0/2
  192.0.0.0/2
)

# Fractional seconds for timing route operations.
typeset -F SECONDS

log_message() {
  /usr/bin/logger -t ZoogCNBypass -- "$1"
}

flush_system_dns_cache() {
  /usr/bin/dscacheutil -flushcache >/dev/null 2>&1 || true
  /usr/bin/killall -HUP mDNSResponder >/dev/null 2>&1 || true
}

ensure_run_dir() {
  if [[ -L "$RUN_DIR" ]]; then
    log_message "Security error: $RUN_DIR is a symlink"
    exit 65
  fi
  if [[ ! -d "$RUN_DIR" ]]; then
    /usr/bin/install -d -o root -g wheel -m 0755 "$RUN_DIR" || exit 65
  fi
  if [[ "$(/usr/bin/stat -f '%u:%Lp' "$RUN_DIR" 2>/dev/null)" != "0:755" ]]; then
    log_message "Security error: $RUN_DIR has invalid ownership or permissions"
    exit 65
  fi
}

verify_safe_file() {
  local file_path="$1"

  [[ -f "$file_path" && ! -L "$file_path" ]] || return 1
  [[ "$(/usr/bin/stat -f '%u:%Lp' "$file_path" 2>/dev/null)" == "0:644" ]]
}

valid_ipv4_gateway() {
  local pattern='^[0-9]{1,3}([.]([0-9]{1,3})){3}$'
  [[ "$1" =~ $pattern ]]
}

valid_ipv6_gateway() {
  local pattern='^fe80:[0-9a-fA-F:%A-Za-z0-9._-]+$'
  [[ "$1" =~ $pattern ]]
}

valid_interface() {
  local pattern='^[A-Za-z0-9._-]+$'
  [[ "$1" =~ $pattern ]]
}

valid_utun_interface() {
  local pattern='^utun[0-9]+$'
  [[ "$1" =~ $pattern ]]
}

valid_service_name() {
  local pattern='^[A-Za-z0-9_.[:space:]/()-]+$'
  [[ "$1" =~ $pattern ]]
}

valid_domain() {
  local pattern='^[A-Za-z0-9]([A-Za-z0-9-]{0,62})([.][A-Za-z0-9]([A-Za-z0-9-]{0,62}))+$'
  [[ "$1" =~ $pattern ]]
}

valid_ipv4_cidr() {
  local cidr="$1"
  local cidr_pattern='^[0-9]{1,3}([.]([0-9]{1,3})){3}/([89]|[12][0-9]|3[0-2])$'
  local reserved_pattern='^(0[.]|10[.]|127[.]|169[.]254[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[0-1])[.]|100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.]|1[.]1[.]1[.]|8[.]8[.]8[.])'

  [[ "$cidr" =~ $cidr_pattern ]] || return 1
  [[ ! "$cidr" =~ $reserved_pattern ]]
}

valid_ipv6_cidr() {
  local pattern='^[23][0-9a-fA-F:]+/(1[6-9]|[2-9][0-9]|1[01][0-9]|12[0-8])$'
  [[ "$1" =~ $pattern ]]
}

log_once() {
  local message="$1"
  local previous=""

  if [[ -L "$ERROR_FILE" ]]; then
    /bin/unlink "$ERROR_FILE" 2>/dev/null || true
  fi
  if [[ -r "$ERROR_FILE" ]]; then
    previous="$(<"$ERROR_FILE")"
  fi
  if [[ "$previous" != "$message" ]]; then
    print -r -- "$message" >| "$ERROR_FILE"
    log_message "$message"
  fi
}

clear_error() {
  if [[ -e "$ERROR_FILE" || -L "$ERROR_FILE" ]]; then
    /bin/unlink "$ERROR_FILE" 2>/dev/null || true
  fi
}

# Lock handling lives at the top level of the script (see the bottom of this
# file). In zsh an EXIT trap set inside a function fires as soon as that
# function returns, which would release the lock immediately.
release_lock() {
  /bin/rm -rf -- "$WORK_DIR" 2>/dev/null || true
  /bin/unlink "$LOCK_FILE" 2>/dev/null || true
}

# PIDs of the parallel route workers; terminate() reaps them before exiting so
# no worker keeps adding routes after the lock is released.
typeset -a worker_pids=()

terminate() {
  if (( ${#worker_pids} > 0 )); then
    kill -TERM "${worker_pids[@]}" 2>/dev/null || true
    wait "${worker_pids[@]}" 2>/dev/null || true
    worker_pids=()
  fi
  exit 143
}

# --- Tunnel detection (ZoogVPN & Clash Pro TUN) ----------------------------

zoog_is_connected() {
  [[ "$(/usr/sbin/scutil --nc status "$VPN_SERVICE" 2>/dev/null | /usr/bin/head -n 1)" == "Connected" ]]
}

zoog_service_uuid() {
  /usr/sbin/scutil --nc list 2>/dev/null | /usr/bin/awk '
    /\(Connected\)/ && $0 ~ /"ZoogVPN"/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$/) {
          print $i
          exit
        }
      }
    }
  '
}

# Prints "<utun-interface>|<ipv4-gateway-or-empty>" for a connected ZoogVPN.
zoog_utun_info() {
  local uuid iface="" gw=""

  uuid="$(zoog_service_uuid)"
  if [[ -n "$uuid" ]]; then
    iface="$(/usr/bin/printf '%s\n' "show State:/Network/Service/$uuid/IPv4" quit \
      | /usr/sbin/scutil 2>/dev/null \
      | /usr/bin/awk '$1 == "InterfaceName" && $2 == ":" { print $3; exit }')"
  fi

  if ! valid_utun_interface "$iface"; then
    iface="$(/usr/sbin/netstat -rn -f inet | /usr/bin/awk -v clash_ip="$CLASH_TUN_IP" '
      ($1 == "0/1" || ($1 == "default" && $3 !~ /I/)) && $NF ~ /^utun[0-9]+$/ && $2 != clash_ip {
        print $NF
        exit
      }
    ')"
  fi

  valid_utun_interface "$iface" || return 1

  gw="$(/usr/sbin/netstat -rn -f inet | /usr/bin/awk -v target="$iface" '
    ($1 == "0/1" || $1 == "default") && $NF == target {
      if ($3 ~ /G/ && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        print $2
      }
      exit
    }
  ')"
  if [[ -n "$gw" ]] && ! valid_ipv4_gateway "$gw"; then
    gw=""
  fi

  print -r -- "$iface|$gw"
}

# Prints the Clash TUN utun interface (e.g. utun13) when Clash Enhanced Mode
# is active (interface owns 198.18.0.1 and has active TUN routes).
clash_tun_interface() {
  local iface

  iface="$(/sbin/ifconfig 2>/dev/null | /usr/bin/awk -v clash_ip="$CLASH_TUN_IP" '
    /^[a-z0-9]+:/ {
      current = $1
      sub(/:$/, "", current)
    }
    current ~ /^utun[0-9]+$/ && $1 == "inet" && $2 == clash_ip {
      print current
      exit
    }
  ')"
  valid_utun_interface "$iface" || return 1

  /usr/sbin/netstat -rn -f inet | /usr/bin/awk -v clash_ip="$CLASH_TUN_IP" -v target="$iface" '
    $2 == clash_ip && $NF == target { found = 1; exit }
    END { exit(found ? 0 : 1) }
  ' || return 1

  print -r -- "$iface"
}

physical_ipv4_route() {
  local route_line key iface router

  route_line="$(/usr/sbin/netstat -rn -f inet | /usr/bin/awk '
    $1 == "default" && $NF !~ /^utun/ && $2 ~ /^[0-9]+\./ {
      print $2 "|" $NF
      exit
    }
  ')"
  if [[ -n "$route_line" ]]; then
    print -r -- "$route_line"
    return 0
  fi

  # Fallback when a legacy VPN (e.g. UniVPN) deletes the unscoped default route
  # from the physical interface: read DHCP/static router state from configd.
  for key in $(/usr/bin/printf '%s\n' 'list State:/Network/Service/.*/IPv4' quit \
      | /usr/sbin/scutil 2>/dev/null \
      | /usr/bin/awk '$NF ~ /^State:\/Network\/Service\/.*\/IPv4$/ { print $NF }'); do
    route_line="$(/usr/bin/printf '%s\n' "show $key" quit | /usr/sbin/scutil 2>/dev/null | /usr/bin/awk '
      $1 == "InterfaceName" && $2 == ":" { iface = $3 }
      $1 == "Router" && $2 == ":" { router = $3 }
      END {
        if (iface != "" && iface !~ /^(utun|lo|ipsec|ppp|gif|stf)/ && router ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
          print router "|" iface
        }
      }
    ')"
    if [[ -n "$route_line" ]]; then
      print -r -- "$route_line"
      return 0
    fi
  done
  return 1
}

# Ensures the physical interface retains at least an interface-scoped default
# route (UGScI) so outbound sockets bound to en0 (ClashX Pro / NetworkExtension)
# never fail with ENETUNREACH if a full-tunnel corporate VPN removes default.
ensure_physical_scoped_default() {
  local gateway="$1"
  local interface="$2"

  valid_ipv4_gateway "$gateway" && valid_interface "$interface" || return 1

  if /usr/sbin/netstat -rn -f inet | /usr/bin/awk -v target="$interface" '
    $1 == "default" && $NF == target { found = 1; exit }
    END { exit(found ? 0 : 1) }
  '; then
    return 0
  fi

  if /sbin/route -n add -ifscope "$interface" default "$gateway" >/dev/null 2>&1; then
    log_message "Restored interface-scoped default route on $interface via $gateway"
  fi
}

physical_ipv6_route() {
  /usr/sbin/netstat -rn -f inet6 | /usr/bin/awk '
    $1 == "default" && $NF !~ /^utun/ && $2 ~ /^fe80:/ {
      print $2 "|" $NF
      exit
    }
  '
}

route_interface_v4() {
  /sbin/route -n get "$1" 2>/dev/null | /usr/bin/awk '/interface:/ { print $2; exit }'
}

route_interface_v6() {
  /sbin/route -n get -inet6 "$1" 2>/dev/null | /usr/bin/awk '/interface:/ { print $2; exit }'
}

# --- Tunnel priority override routes (ZoogVPN over Clash, or Clash over UniVPN def1) ---

has_competing_half_default() {
  local keep_iface="$1"

  /usr/sbin/netstat -rn -f inet | /usr/bin/awk -v keep="$keep_iface" '
    ($1 == "0/1" || $1 == "128.0/1") && $NF != keep { found = 1; exit }
    END { exit(found ? 0 : 1) }
  '
}

remove_zoog_override_routes() {
  local prefix removed=0

  if [[ ! -L "$ACTIVE_OVERRIDE_V4" && -r "$ACTIVE_OVERRIDE_V4" ]]; then
    while IFS= read -r prefix; do
      [[ -n "$prefix" ]] || continue
      /sbin/route -n delete -net "$prefix" >/dev/null 2>&1 || true
      removed=1
    done < "$ACTIVE_OVERRIDE_V4"
  fi
  /bin/unlink "$ACTIVE_OVERRIDE_V4" 2>/dev/null || true
  /bin/unlink "$OVERRIDE_STATE_FILE" 2>/dev/null || true

  if (( removed )); then
    flush_system_dns_cache
    log_message "Removed tunnel priority override routes"
  fi
}

ensure_zoog_override_routes() {
  local tunnel_iface="$1"
  local tunnel_gw="$2"
  local desired="$tunnel_iface|$tunnel_gw"
  local prefix added=0

  valid_utun_interface "$tunnel_iface" || return 1

  if [[ ! -L "$OVERRIDE_STATE_FILE" && -r "$OVERRIDE_STATE_FILE" && "$(<"$OVERRIDE_STATE_FILE")" == "$desired" ]] && \
     [[ "$(route_interface_v4 1.1.1.1)" == "$tunnel_iface" ]] && \
     [[ "$(route_interface_v4 8.8.8.8)" == "$tunnel_iface" ]] && \
     [[ "$(route_interface_v4 140.82.112.4)" == "$tunnel_iface" ]]; then
    return 0
  fi

  remove_zoog_override_routes
  : >| "$ACTIVE_OVERRIDE_V4"
  /bin/chmod 0644 "$ACTIVE_OVERRIDE_V4"

  for prefix in "${CLASH_OVERRIDE_PREFIXES[@]}"; do
    if [[ -n "$tunnel_gw" ]]; then
      if /sbin/route -n add -net "$prefix" "$tunnel_gw" >/dev/null 2>&1; then
        print -r -- "$prefix" >> "$ACTIVE_OVERRIDE_V4"
        (( added++ ))
      fi
    else
      if /sbin/route -n add -net "$prefix" -interface "$tunnel_iface" >/dev/null 2>&1; then
        print -r -- "$prefix" >> "$ACTIVE_OVERRIDE_V4"
        (( added++ ))
      fi
    fi
  done

  if [[ "$(route_interface_v4 1.1.1.1)" != "$tunnel_iface" ]]; then
    remove_zoog_override_routes
    return 1
  fi

  print -r -- "$desired" >| "$OVERRIDE_STATE_FILE"
  /bin/chmod 0644 "$OVERRIDE_STATE_FILE"
  flush_system_dns_cache
  log_message "Tunnel priority override active on $tunnel_iface ($added prefixes)"
  return 0
}

# --- Clash System Proxy suppression ----------------------------------------
# When Clash System Proxy (127.0.0.1:7890/7891) is enabled, browsers send all
# hostnames directly to Clash's HTTP/SOCKS port, bypassing kernel routes (both
# ZoogVPN and UniVPN) and corporate split-horizon DNS. While any TUN split is
# active we disable only Clash's local proxy ports (leaving debugging proxies
# such as Charles/Proxyman untouched) and restore them on disconnect/disable.

active_local_proxy_ports() {
  /usr/sbin/scutil --proxy 2>/dev/null | /usr/bin/awk '
    /__SCOPED__/ { exit }
    $1 == "HTTPEnable" { http_en = $3 }
    $1 == "HTTPProxy" { http_host = $3 }
    $1 == "HTTPPort" { http_port = $3 }
    $1 == "HTTPSEnable" { https_en = $3 }
    $1 == "HTTPSProxy" { https_host = $3 }
    $1 == "HTTPSPort" { https_port = $3 }
    $1 == "SOCKSEnable" { socks_en = $3 }
    $1 == "SOCKSProxy" { socks_host = $3 }
    $1 == "SOCKSPort" { socks_port = $3 }
    END {
      if (http_en == "1" && (http_host == "127.0.0.1" || http_host == "localhost") && http_port ~ /^[0-9]+$/)
        ports[http_port] = 1
      if (https_en == "1" && (https_host == "127.0.0.1" || https_host == "localhost") && https_port ~ /^[0-9]+$/)
        ports[https_port] = 1
      if (socks_en == "1" && (socks_host == "127.0.0.1" || socks_host == "localhost") && socks_port ~ /^[0-9]+$/)
        ports[socks_port] = 1
      for (p in ports) print p
    }
  '
}

is_clash_proxy_port() {
  local port="$1"

  [[ "$port" == <-> ]] && (( port >= 1 && port <= 65535 )) || return 1
  if (( port == 7890 || port == 7891 )); then
    return 0
  fi

  /usr/sbin/lsof -Pan -iTCP:"$port" -sTCP:LISTEN -F c 2>/dev/null | /usr/bin/awk '
    /^c([Cc]lash|[Mm]ihomo|[Vv]erge)/ { found = 1; exit }
    END { exit(found ? 0 : 1) }
  '
}

record_suppressed_proxy() {
  local entry="$1"
  local existing_line

  if [[ -L "$SUPPRESSED_PROXIES_FILE" ]]; then
    /bin/unlink "$SUPPRESSED_PROXIES_FILE" 2>/dev/null || return 1
  fi
  if [[ -r "$SUPPRESSED_PROXIES_FILE" ]]; then
    while IFS= read -r existing_line; do
      [[ "$existing_line" == "$entry" ]] && return 0
    done < "$SUPPRESSED_PROXIES_FILE"
  else
    : >| "$SUPPRESSED_PROXIES_FILE"
    /usr/sbin/chown root:wheel "$SUPPRESSED_PROXIES_FILE"
    /bin/chmod 0644 "$SUPPRESSED_PROXIES_FILE"
  fi
  print -r -- "$entry" >> "$SUPPRESSED_PROXIES_FILE"
}

suppress_service_proxy_kind() {
  local service="$1"
  local kind="$2"
  local get_flag set_flag info enabled server port

  case "$kind" in
    web)
      get_flag="-getwebproxy"
      set_flag="-setwebproxystate"
      ;;
    secureweb)
      get_flag="-getsecurewebproxy"
      set_flag="-setsecurewebproxystate"
      ;;
    socks)
      get_flag="-getsocksfirewallproxy"
      set_flag="-setsocksfirewallproxystate"
      ;;
    *)
      return 1
      ;;
  esac

  info="$(/usr/sbin/networksetup "$get_flag" "$service" 2>/dev/null)" || return 0
  enabled="$(print -r -- "$info" | /usr/bin/awk -F': ' '$1 == "Enabled" { print $2; exit }')"
  [[ "$enabled" == "Yes" ]] || return 0

  server="$(print -r -- "$info" | /usr/bin/awk -F': ' '$1 == "Server" { print $2; exit }')"
  port="$(print -r -- "$info" | /usr/bin/awk -F': ' '$1 == "Port" { print $2; exit }')"
  [[ "$server" == "127.0.0.1" || "$server" == "localhost" ]] || return 0
  is_clash_proxy_port "$port" || return 0

  if /usr/sbin/networksetup "$set_flag" "$service" off >/dev/null 2>&1; then
    record_suppressed_proxy "$service|$kind|$server|$port"
    log_message "Suppressed Clash $kind system proxy ($server:$port) on $service"
  fi
}

ensure_proxy_suppression() {
  local -a candidate_ports clash_ports
  local port service line_num=0

  candidate_ports=(${(@f)"$(active_local_proxy_ports)"})
  (( ${#candidate_ports} > 0 )) || return 0

  for port in "${candidate_ports[@]}"; do
    [[ -n "$port" ]] && is_clash_proxy_port "$port" && clash_ports+=("$port")
  done
  (( ${#clash_ports} > 0 )) || return 0

  while IFS= read -r service; do
    (( ++line_num == 1 )) && continue
    [[ -z "$service" || "$service" == \** ]] && continue
    valid_service_name "$service" || continue
    suppress_service_proxy_kind "$service" web
    suppress_service_proxy_kind "$service" secureweb
    suppress_service_proxy_kind "$service" socks
  done < <(/usr/sbin/networksetup -listallnetworkservices 2>/dev/null)
}

restore_suppressed_proxies() {
  local service kind server port get_flag set_flag info cur_enabled cur_server cur_port restored=0

  if ! verify_safe_file "$SUPPRESSED_PROXIES_FILE"; then
    /bin/unlink "$SUPPRESSED_PROXIES_FILE" 2>/dev/null || true
    return 0
  fi

  while IFS='|' read -r service kind server port; do
    valid_service_name "$service" || continue
    [[ "$server" == "127.0.0.1" || "$server" == "localhost" ]] || continue
    [[ "$port" == <-> ]] && (( port >= 1 && port <= 65535 )) || continue

    case "$kind" in
      web)
        get_flag="-getwebproxy"
        set_flag="-setwebproxystate"
        ;;
      secureweb)
        get_flag="-getsecurewebproxy"
        set_flag="-setsecurewebproxystate"
        ;;
      socks)
        get_flag="-getsocksfirewallproxy"
        set_flag="-setsocksfirewallproxystate"
        ;;
      *)
        continue
        ;;
    esac

    info="$(/usr/sbin/networksetup "$get_flag" "$service" 2>/dev/null)" || continue
    cur_enabled="$(print -r -- "$info" | /usr/bin/awk -F': ' '$1 == "Enabled" { print $2; exit }')"
    cur_server="$(print -r -- "$info" | /usr/bin/awk -F': ' '$1 == "Server" { print $2; exit }')"
    cur_port="$(print -r -- "$info" | /usr/bin/awk -F': ' '$1 == "Port" { print $2; exit }')"

    if [[ "$cur_enabled" == "No" && "$cur_server" == "$server" && "$cur_port" == "$port" ]]; then
      if /usr/sbin/networksetup "$set_flag" "$service" on >/dev/null 2>&1; then
        restored=1
      fi
    fi
  done < "$SUPPRESSED_PROXIES_FILE"

  /bin/unlink "$SUPPRESSED_PROXIES_FILE" 2>/dev/null || true
  if (( restored )); then
    log_message "Restored previously suppressed Clash system proxy settings"
  fi
}

# --- Dynamic dnsmasq upstream & macOS DNS override -------------------------

reload_local_dnsmasq() {
  local dns_pid

  dns_pid="$(/bin/launchctl print "system/$DNS_LABEL" 2>/dev/null \
    | /usr/bin/awk '$1 == "pid" && $2 == "=" { print $3; exit }')"
  if [[ "$dns_pid" == <-> ]] && (( dns_pid > 1 )); then
    kill -HUP "$dns_pid" 2>/dev/null || true
  else
    /bin/launchctl kickstart -k "system/$DNS_LABEL" >/dev/null 2>&1 || true
  fi
}

ensure_upstream_dns() {
  local mode="$1"
  local wanted current="" temporary="$UPSTREAM_SERVERS_FILE.$$"

  if [[ "$mode" == "clash" ]]; then
    wanted=$'# Managed by ZoogCNBypass daemon.sh\nserver='"$CLASH_TUN_DNS"
  else
    wanted=$'# Managed by ZoogCNBypass daemon.sh\nserver=1.1.1.1\nserver=8.8.8.8'
  fi

  if [[ -L "$UPSTREAM_SERVERS_FILE" ]]; then
    log_message "Security error: $UPSTREAM_SERVERS_FILE is a symlink"
    return 1
  fi
  if [[ -r "$UPSTREAM_SERVERS_FILE" ]]; then
    current="$(<"$UPSTREAM_SERVERS_FILE")"
  fi
  if [[ "$current" == "$wanted" ]]; then
    return 0
  fi

  /bin/unlink "$temporary" 2>/dev/null || true
  print -r -- "$wanted" >| "$temporary" || return 1
  /usr/sbin/chown root:wheel "$temporary"
  /bin/chmod 0644 "$temporary"
  /bin/mv -f "$temporary" "$UPSTREAM_SERVERS_FILE"

  reload_local_dnsmasq
  flush_system_dns_cache
  log_message "Updated dnsmasq foreign upstream for $mode tunnel"
  return 0
}

dns_override_definition() {
  /usr/bin/printf '%s\n' "show $DNS_STATE_KEY" quit | /usr/sbin/scutil 2>/dev/null
}

dns_override_exists() {
  [[ "$(dns_override_definition)" == *"<dictionary>"* ]]
}

dns_override_is_current() {
  local definition

  definition="$(dns_override_definition)"
  [[ "$definition" == *"ServerAddresses"* ]] || return 1
  [[ "$definition" == *"0 : $LOCAL_DNS"* ]] || return 1
  [[ "$definition" == *"SupplementalMatchDomains"* ]] || return 1
  [[ "$definition" == *"SupplementalMatchOrders"* ]] || return 1
}

clear_dns_override() {
  if dns_override_exists; then
    /usr/bin/printf '%s\n' "remove $DNS_STATE_KEY" quit | /usr/sbin/scutil >/dev/null 2>&1 || true
    flush_system_dns_cache
  fi
}

# --- Corporate split-horizon DNS -------------------------------------------
# Corporate VPNs (e.g. UniVPN) only register their DNS server as a scoped
# resolver, so the system default resolver (our dnsmasq, ZoogVPN, or Clash)
# never asks it and internal-only names fail to resolve. For every server
# listed in corp-dns.conf we publish a supplemental resolver whose match
# domains are more specific than our catch-all "" override, so macOS sends
# those domains straight to the corporate DNS server (bypassing dnsmasq and
# its stop-dns-rebind filter). The resolver exists only while the server is
# reachable through a dedicated corporate VPN route (never physical, ZoogVPN,
# or Clash TUN).

corp_dns_keys() {
  /usr/bin/printf '%s\n' "list ${CORP_DNS_KEY_PREFIX//./[.]}[.][0-9]+/DNS" quit \
    | /usr/sbin/scutil 2>/dev/null \
    | /usr/bin/awk '$NF ~ /^State:\/Network\/Service\/com[.]local[.]zoog-cn-bypass[.]corp[.][0-9]+\/DNS$/ { print $NF }'
}

clear_corp_dns() {
  local key removed=0

  for key in $(corp_dns_keys); do
    /usr/bin/printf '%s\n' "remove $key" quit | /usr/sbin/scutil >/dev/null 2>&1 || true
    removed=1
  done
  if (( removed )); then
    flush_system_dns_cache
    log_message "Corporate DNS resolvers removed"
  fi
}

# corp_dns_reachable <server> <default-iface> <physical-iface> <zoog-iface> <clash-iface> <probe-domain>
corp_dns_reachable() {
  local server="$1"
  local default_interface="$2"
  local physical_interface="$3"
  local zoog_interface="$4"
  local clash_interface="$5"
  local probe="$6"
  local interface

  interface="$(route_interface_v4 "$server")"
  [[ -n "$interface" ]] || return 1
  [[ "$interface" != "$default_interface" ]] || return 1
  [[ -z "$physical_interface" || "$interface" != "$physical_interface" ]] || return 1
  [[ -z "$zoog_interface" || "$interface" != "$zoog_interface" ]] || return 1
  [[ -z "$clash_interface" || "$interface" != "$clash_interface" ]] || return 1
  /usr/bin/dig +time=2 +tries=1 @"$server" "$probe" SOA >/dev/null 2>&1
}

# corp_dns_key_is_current <key> <server> <domain>...
corp_dns_key_is_current() {
  local key="$1"
  local server="$2"
  shift 2
  local definition index=0 domain

  definition="$(/usr/bin/printf '%s\n' "show $key" quit | /usr/sbin/scutil 2>/dev/null)"
  [[ "$definition" == *"ServerAddresses"* && "$definition" == *"0 : $server"$'\n'* ]] || return 1
  [[ "$definition" == *"SupplementalMatchDomains"* ]] || return 1
  # Do not add the corporate domains to the global search list.
  [[ "$definition" == *"SupplementalMatchDomainsNoSearch : 1"* ]] || return 1
  for domain in "$@"; do
    [[ "$definition" == *" $index : $domain"$'\n'* ]] || return 1
    (( index++ ))
  done
  [[ "$definition" != *" $index : "* ]]
}

ensure_corp_dns() {
  local zoog_interface="${1:-}"
  local clash_interface="${2:-}"
  local physical_interface="${3:-}"
  local -A domains_by_server
  local -a servers wanted_keys domains orders
  local domain server extra key default_interface index=0 changed=0

  if verify_safe_file "$CORP_DNS_CONF"; then
    while read -r domain server extra; do
      [[ -z "$domain" || "$domain" == \#* ]] && continue
      [[ -z "$extra" ]] && valid_domain "$domain" && valid_ipv4_gateway "$server" || continue
      if (( ! ${+domains_by_server[$server]} )); then
        servers+=("$server")
        domains_by_server[$server]=""
      fi
      domains_by_server[$server]+=" ${domain:l}"
    done < "$CORP_DNS_CONF"
  fi

  default_interface="$(route_interface_v4 1.1.1.1)"
  for server in "${servers[@]}"; do
    key="$CORP_DNS_KEY_PREFIX.$index/DNS"
    (( index++ ))
    domains=(${=domains_by_server[$server]})
    corp_dns_reachable "$server" "$default_interface" "$physical_interface" "$zoog_interface" "$clash_interface" "${domains[1]}" || continue

    wanted_keys+=("$key")
    corp_dns_key_is_current "$key" "$server" "${domains[@]}" && continue

    orders=()
    for domain in "${domains[@]}"; do
      orders+=("$CORP_DNS_ORDER")
    done
    /usr/bin/printf '%s\n' \
      d.init \
      "d.add ServerAddresses * $server" \
      "d.add SupplementalMatchDomains * ${domains[*]}" \
      "d.add SupplementalMatchOrders * ${orders[*]}" \
      'd.add SupplementalMatchDomainsNoSearch # 1' \
      "set $key" \
      quit | /usr/sbin/scutil >/dev/null 2>&1
    log_message "Corporate DNS active: ${domains[*]} -> $server"
    changed=1
  done

  for key in $(corp_dns_keys); do
    (( ${wanted_keys[(Ie)$key]} )) && continue
    /usr/bin/printf '%s\n' "remove $key" quit | /usr/sbin/scutil >/dev/null 2>&1 || true
    log_message "Corporate DNS inactive (server unreachable): $key removed"
    changed=1
  done

  if (( changed )); then
    flush_system_dns_cache
  fi
  return 0
}

local_dns_is_ready() {
  local domestic_answer foreign_answer attempt

  for attempt in 1 2 3; do
    domestic_answer="$(/usr/bin/dig +time=2 +tries=1 +short @"$LOCAL_DNS" www.baidu.com A 2>/dev/null)"
    foreign_answer=""
    if [[ -n "$domestic_answer" ]]; then
      foreign_answer="$(/usr/bin/dig +time=2 +tries=1 +short @"$LOCAL_DNS" example.com A 2>/dev/null)"
    fi
    if [[ -n "$domestic_answer" && -n "$foreign_answer" ]]; then
      return 0
    fi
    (( attempt < 3 )) && /bin/sleep 0.4
  done
  return 1
}

ensure_dns_override() {
  local active_tunnel="$1"
  local expected_utun="$2"
  local foreign_interface

  foreign_interface="$(route_interface_v4 1.1.1.1)"
  if [[ "$foreign_interface" != utun* ]] || [[ -n "$expected_utun" && "$foreign_interface" != "$expected_utun" ]]; then
    clear_dns_override
    log_once "Active tunnel ($active_tunnel) is connected, but foreign traffic ($foreign_interface) is not routed through $expected_utun"
    return 1
  fi

  if ! local_dns_is_ready; then
    clear_dns_override
    log_once "China split DNS is not ready for $active_tunnel tunnel; the system DNS override was removed"
    return 1
  fi

  if dns_override_is_current; then
    return 0
  fi

  /usr/bin/printf '%s\n' \
    d.init \
    "d.add ServerAddresses * $LOCAL_DNS" \
    'd.add SupplementalMatchDomains * ""' \
    'd.add SupplementalMatchOrders * 100' \
    "set $DNS_STATE_KEY" \
    quit | /usr/sbin/scutil >/dev/null 2>&1

  if ! dns_override_is_current; then
    clear_dns_override
    log_once "China split DNS could not become the default macOS resolver"
    return 1
  fi

  flush_system_dns_cache
  log_message "China split DNS active on $LOCAL_DNS (foreign tunnel: $active_tunnel via $expected_utun)"
}

# Deletes exactly the routes recorded in the active files, in parallel. If the
# run is interrupted, terminate() exits before the files are unlinked, so the
# next run retries the whole list (deleting an absent route is harmless).
remove_recorded_routes() {
  if [[ ! -L "$ACTIVE_V4" && -r "$ACTIVE_V4" ]]; then
    run_routes_parallel delete ipv4 "" "$ACTIVE_V4" ""
  fi
  /bin/unlink "$ACTIVE_V4" 2>/dev/null || true

  if [[ ! -L "$ACTIVE_V6" && -r "$ACTIVE_V6" ]]; then
    run_routes_parallel delete ipv6 "" "$ACTIVE_V6" ""
  fi
  /bin/unlink "$ACTIVE_V6" 2>/dev/null || true

  /bin/unlink "$STATE_FILE" 2>/dev/null || true
}

# Picks the number of parallel route workers for <count> routes.
compute_route_jobs() {
  local count="$1"
  local cpus load jobs floor by_work

  cpus="$(/usr/sbin/sysctl -n hw.activecpu 2>/dev/null)"
  if [[ "$cpus" != <-> ]] || (( cpus < 1 )); then
    cpus="$(/usr/sbin/sysctl -n hw.ncpu 2>/dev/null)"
  fi
  if [[ "$cpus" != <-> ]] || (( cpus < 1 )); then
    cpus=4
  fi

  # vm.loadavg looks like "{ 6.21 8.54 6.39 }".
  load="$(/usr/sbin/sysctl -n vm.loadavg 2>/dev/null | /usr/bin/awk '{ printf "%d", $2 + 0.5 }')"
  [[ "$load" == <-> ]] || load=0

  jobs=$(( cpus - load ))
  floor=$(( cpus / 4 ))
  (( floor < 2 )) && floor=2
  (( jobs < floor )) && jobs=$floor
  (( jobs > cpus )) && jobs=$cpus
  (( jobs > MAX_ROUTE_JOBS )) && jobs=$MAX_ROUTE_JOBS

  by_work=$(( (count + MIN_ROUTES_PER_JOB - 1) / MIN_ROUTES_PER_JOB ))
  (( jobs > by_work )) && jobs=$by_work
  (( jobs < 1 )) && jobs=1

  print -r -- "$jobs"
}

route_chunk_worker() {
  local action="$1"
  local family="$2"
  local gateway="$3"
  local queue_dir="$4"
  local record_file="$5"
  local network chunk claimed stop=0
  local -a family_flag=()

  [[ "$family" == ipv6 ]] && family_flag=(-inet6)

  # Do not inherit the parent's lock-release/terminate traps. On TERM finish
  # the current route (and record it) before stopping, so nothing is leaked.
  trap - EXIT INT
  trap 'stop=1' TERM

  [[ "$action" == add ]] && exec 3>>"$record_file"
  for chunk in "$queue_dir"/part.*(N); do
    (( stop )) && break
    claimed="${queue_dir:h}/claimed/${chunk:t}"
    /bin/mv "$chunk" "$claimed" 2>/dev/null || continue

    while (( ! stop )) && IFS= read -r network; do
      if [[ "$action" == add ]]; then
        if /sbin/route -n add "${family_flag[@]}" -net "$network" "$gateway" >/dev/null 2>&1; then
          print -u 3 -r -- "$network"
        fi
      else
        /sbin/route -n delete "${family_flag[@]}" -net "$network" >/dev/null 2>&1 || true
      fi
    done < "$claimed"
  done
  [[ "$action" == add ]] && exec 3>&-
  return 0
}

run_routes_parallel() {
  local action="$1"
  local family="$2"
  local gateway="$3"
  local source_file="$4"
  local record_file="$5"
  local network count jobs chunk_lines worker
  local started="$SECONDS"

  if [[ "$action" == add ]]; then
    /bin/unlink "$record_file" 2>/dev/null || true
    : >| "$record_file"
  fi

  /bin/rm -rf -- "$WORK_DIR"
  /usr/bin/install -d -o root -g wheel -m 0700 "$WORK_DIR" || return 1

  while IFS= read -r network; do
    [[ -n "$network" ]] || continue
    "valid_${family}_cidr" "$network" || continue
    print -r -- "$network"
  done < "$source_file" >| "$WORK_DIR/list"

  count="$(/usr/bin/wc -l < "$WORK_DIR/list" | /usr/bin/tr -d ' ')"
  if (( count > 0 )); then
    jobs="$(compute_route_jobs "$count")"
    chunk_lines=$(( (count + jobs * CHUNKS_PER_JOB - 1) / (jobs * CHUNKS_PER_JOB) ))
    /usr/bin/install -d -o root -g wheel -m 0700 "$WORK_DIR/queue" "$WORK_DIR/claimed" || return 1
    /usr/bin/split -l "$chunk_lines" "$WORK_DIR/list" "$WORK_DIR/queue/part."

    worker_pids=()
    for (( worker = 0; worker < jobs; worker++ )); do
      route_chunk_worker "$action" "$family" "$gateway" "$WORK_DIR/queue" "$record_file" &
      worker_pids+=($!)
    done
    wait "${worker_pids[@]}" 2>/dev/null || true
    worker_pids=()

    log_message "$(/usr/bin/printf '%s %d %s routes with %d workers in %.2fs' \
      "${(C)action}" "$count" "$family" "$jobs" "$(( SECONDS - started ))")"
  fi

  /bin/rm -rf -- "$WORK_DIR"
}

add_ipv4_routes() {
  local gateway="$1"

  valid_ipv4_gateway "$gateway" || return 1
  verify_safe_file "$ROUTES_V4" || return 1

  run_routes_parallel add ipv4 "$gateway" "$ROUTES_V4" "$ACTIVE_V4"
}

add_ipv6_routes() {
  local gateway="$1"

  valid_ipv6_gateway "$gateway" || return 1
  verify_safe_file "$ROUTES_V6" || return 1

  run_routes_parallel add ipv6 "$gateway" "$ROUTES_V6" "$ACTIVE_V6"
}

routes_are_current() {
  local expected_state="$1"
  local interface_v4="$2"
  local interface_v6="$3"

  [[ ! -L "$STATE_FILE" && -r "$STATE_FILE" && "$(<"$STATE_FILE")" == "$expected_state" ]] || return 1
  routes_are_current_without_state "$interface_v4" "$interface_v6"
}

routes_are_current_without_state() {
  local interface_v4="$1"
  local interface_v6="$2"

  [[ "$(route_interface_v4 223.5.5.5)" == "$interface_v4" ]] || return 1
  [[ "$(route_interface_v4 114.114.114.114)" == "$interface_v4" ]] || return 1

  if [[ -n "$interface_v6" ]]; then
    [[ "$(route_interface_v6 2400:3200::1)" == "$interface_v6" ]] || return 1
    [[ "$(route_interface_v6 240c::6666)" == "$interface_v6" ]] || return 1
  fi
}

write_state() {
  local state="$1"
  local temporary="$STATE_FILE.$$"

  /bin/unlink "$temporary" 2>/dev/null || true
  print -r -- "$state" >| "$temporary"
  /bin/chmod 0644 "$temporary"
  /bin/mv -f "$temporary" "$STATE_FILE"
}

reconcile() {
  local ipv4_info ipv6_info ipv4_gateway ipv4_interface=""
  local ipv6_gateway="" ipv6_interface="" expected_state
  local zoog_info="" zoog_iface="" zoog_gw="" clash_iface=""
  local active_tunnel="none" target_utun=""
  local installed_v4 installed_v6

  ipv4_info="$(physical_ipv4_route)"
  [[ -n "$ipv4_info" ]] && ipv4_interface="${ipv4_info##*|}"

  if zoog_is_connected; then
    active_tunnel="zoog"
    zoog_info="$(zoog_utun_info 2>/dev/null || true)"
    zoog_iface="${zoog_info%%|*}"
    zoog_gw="${zoog_info##*|}"
  fi
  clash_iface="$(clash_tun_interface 2>/dev/null || true)"
  if [[ "$active_tunnel" == "none" && -n "$clash_iface" ]]; then
    active_tunnel="clash"
  fi

  if [[ "$active_tunnel" == "none" ]]; then
    ensure_corp_dns "" "" "$ipv4_interface"
    clear_dns_override
    remove_zoog_override_routes
    restore_suppressed_proxies
    if [[ -e "$STATE_FILE" || -e "$ACTIVE_V4" || -e "$ACTIVE_V6" ]]; then
      ipv6_info="$(physical_ipv6_route)"
      expected_state="${ipv4_info%%|*}|${ipv4_info##*|}|${ipv6_info%%|*}|${ipv6_info##*|}"
      if [[ "$(route_interface_v4 1.1.1.1)" == utun* ]] || ! routes_are_current "$expected_state" "${ipv4_info##*|}" "${ipv6_info##*|}"; then
        remove_recorded_routes
        log_message "China-direct routes removed while ZoogVPN and Clash Pro TUN are disconnected"
      fi
    fi
    clear_error
    return 0
  fi

  if [[ -z "$ipv4_info" ]]; then
    clear_dns_override
    remove_zoog_override_routes
    log_once "Active tunnel ($active_tunnel) connected, but no physical IPv4 gateway was found"
    return 1
  fi
  ipv4_gateway="${ipv4_info%%|*}"
  ipv4_interface="${ipv4_info##*|}"

  if ! valid_ipv4_gateway "$ipv4_gateway" || ! valid_interface "$ipv4_interface"; then
    clear_dns_override
    remove_zoog_override_routes
    log_once "Invalid physical IPv4 gateway or interface format"
    return 1
  fi

  ensure_physical_scoped_default "$ipv4_gateway" "$ipv4_interface"

  # Suppress Clash System Proxy (127.0.0.1:7890/7891) so browser traffic uses
  # kernel routing (UniVPN intranet, China-direct en0, ZoogVPN / Clash TUN).
  ensure_proxy_suppression

  if [[ "$active_tunnel" == "zoog" ]]; then
    if [[ -z "$zoog_iface" ]]; then
      clear_dns_override
      remove_zoog_override_routes
      log_once "ZoogVPN is connected, but its utun interface could not be determined"
      return 1
    fi
    target_utun="$zoog_iface"
    if [[ -n "$clash_iface" || "$(route_interface_v4 1.1.1.1)" != "$zoog_iface" ]]; then
      if ! ensure_zoog_override_routes "$zoog_iface" "$zoog_gw"; then
        clear_dns_override
        log_once "Failed to install ZoogVPN priority routes"
        return 1
      fi
    else
      remove_zoog_override_routes
    fi
  else
    target_utun="$clash_iface"
    if [[ -r "$OVERRIDE_STATE_FILE" ]]; then
      if [[ "$(<"$OVERRIDE_STATE_FILE")" != "$clash_iface|$CLASH_TUN_IP" ]] || ! has_competing_half_default "$clash_iface"; then
        remove_zoog_override_routes
      fi
    fi
    if [[ "$(route_interface_v4 1.1.1.1)" != "$clash_iface" || "$(route_interface_v4 "$CLASH_TUN_DNS")" != "$clash_iface" ]]; then
      if ! ensure_zoog_override_routes "$clash_iface" "$CLASH_TUN_IP"; then
        clear_dns_override
        log_once "Failed to restore Clash Pro TUN priority over competing default route"
        return 1
      fi
    fi
  fi

  # Independent of ZoogVPN/Clash: corporate VPN DNS works whenever reachable
  # via its own dedicated interface (e.g. UniVPN).
  ensure_corp_dns "$zoog_iface" "$clash_iface" "$ipv4_interface"

  ipv6_info="$(physical_ipv6_route)"
  if [[ -n "$ipv6_info" ]]; then
    ipv6_gateway="${ipv6_info%%|*}"
    ipv6_interface="${ipv6_info##*|}"
    if ! valid_ipv6_gateway "$ipv6_gateway" || ! valid_interface "$ipv6_interface"; then
      ipv6_gateway=""
      ipv6_interface=""
    fi
  fi

  expected_state="$ipv4_gateway|$ipv4_interface|$ipv6_gateway|$ipv6_interface"
  if ! routes_are_current "$expected_state" "$ipv4_interface" "$ipv6_interface"; then
    remove_recorded_routes
    add_ipv4_routes "$ipv4_gateway"
    if [[ -n "$ipv6_gateway" ]]; then
      add_ipv6_routes "$ipv6_gateway"
    fi

    if ! zoog_is_connected && [[ -z "$(clash_tun_interface 2>/dev/null || true)" ]]; then
      remove_zoog_override_routes
      remove_recorded_routes
      return 0
    fi

    if ! routes_are_current_without_state "$ipv4_interface" "$ipv6_interface"; then
      remove_recorded_routes
      log_once "China-direct route verification failed; all added routes were rolled back"
      return 1
    fi

    write_state "$expected_state"
    installed_v4="$(/usr/bin/wc -l < "$ACTIVE_V4" | /usr/bin/tr -d ' ')"
    installed_v6=0
    if [[ -r "$ACTIVE_V6" ]]; then
      installed_v6="$(/usr/bin/wc -l < "$ACTIVE_V6" | /usr/bin/tr -d ' ')"
    fi
    log_message "China-direct routing active on $ipv4_interface: $installed_v4 IPv4 and $installed_v6 IPv6 routes"
  fi

  if ! ensure_upstream_dns "$active_tunnel"; then
    clear_dns_override
    log_once "Could not configure dnsmasq upstream for $active_tunnel tunnel"
    return 1
  fi

  if ensure_dns_override "$active_tunnel" "$target_utun"; then
    clear_error
    return 0
  fi
  return 1
}

main() {
  case "${1:-reconcile}" in
    reconcile)
      reconcile
      ;;
    stop)
      clear_corp_dns
      clear_dns_override
      remove_zoog_override_routes
      remove_recorded_routes
      restore_suppressed_proxies
      ensure_upstream_dns "zoog" >/dev/null 2>&1 || true
      clear_error
      ;;
    *)
      print -u 2 -- "Usage: $0 [reconcile|stop]"
      return 64
      ;;
  esac
}

case "${1:-reconcile}" in
  reconcile|stop) ;;
  *)
    print -u 2 -- "Usage: $0 [reconcile|stop]"
    exit 64
    ;;
esac

ensure_run_dir
if [[ -L "$LOCK_FILE" ]]; then
  /bin/unlink "$LOCK_FILE" 2>/dev/null || exit 0
fi

# "stop" must not silently do nothing while a reconcile run holds the lock, so
# it waits briefly; a periodic "reconcile" simply yields to the running one.
lock_attempts=1
[[ "${1:-reconcile}" == "stop" ]] && lock_attempts=15
until /usr/bin/shlock -p $$ -f "$LOCK_FILE"; do
  (( --lock_attempts > 0 )) || {
    [[ "${1:-reconcile}" == "stop" ]] && exit 75
    exit 0
  }
  /bin/sleep 1
done

# Only installed after the lock is held, so a losing instance never removes
# another instance's lock. TERM/INT must exit explicitly: in zsh a trap handler
# otherwise returns and the script keeps running (launchd would then SIGKILL it).
trap release_lock EXIT
trap terminate TERM INT

main "$@"
