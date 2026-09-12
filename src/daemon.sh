#!/bin/zsh

set -u
umask 022

readonly LABEL="com.local.zoog-cn-bypass"
readonly INSTALL_DIR="/Library/Application Support/ZoogCNBypass"
readonly ROUTES_V4="$INSTALL_DIR/cn-ipv4.txt"
readonly ROUTES_V6="$INSTALL_DIR/cn-ipv6.txt"
readonly STATE_FILE="/var/run/$LABEL.state"
readonly ACTIVE_V4="/var/run/$LABEL.active-v4"
readonly ACTIVE_V6="/var/run/$LABEL.active-v6"
readonly ERROR_FILE="/var/run/$LABEL.error"
readonly LOCK_FILE="/var/run/$LABEL.lock"
readonly VPN_SERVICE="ZoogVPN"
readonly DNS_STATE_KEY="State:/Network/Service/com.local.zoog-cn-bypass/DNS"
readonly LOCAL_DNS="127.0.0.1"

log_message() {
  /usr/bin/logger -t ZoogCNBypass -- "$1"
}

log_once() {
  local message="$1"
  local previous=""

  if [[ -r "$ERROR_FILE" ]]; then
    previous="$(<"$ERROR_FILE")"
  fi
  if [[ "$previous" != "$message" ]]; then
    print -r -- "$message" >| "$ERROR_FILE"
    log_message "$message"
  fi
}

clear_error() {
  if [[ -e "$ERROR_FILE" ]]; then
    /bin/unlink "$ERROR_FILE" 2>/dev/null || true
  fi
}

acquire_lock() {
  /usr/bin/shlock -p $$ -f "$LOCK_FILE" || exit 0
  trap '/bin/unlink "/var/run/com.local.zoog-cn-bypass.lock" 2>/dev/null || true' EXIT INT TERM
}

zoog_is_connected() {
  [[ "$(/usr/sbin/scutil --nc status "$VPN_SERVICE" 2>/dev/null | /usr/bin/head -n 1)" == "Connected" ]]
}

physical_ipv4_route() {
  /usr/sbin/netstat -rn -f inet | /usr/bin/awk '
    $1 == "default" && $NF !~ /^utun/ && $2 ~ /^[0-9]+\./ {
      print $2 "|" $NF
      exit
    }
  '
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

other_vpn_is_connected() {
  /usr/sbin/scutil --nc list 2>/dev/null | /usr/bin/awk '
    /\(Connected\)/ && $0 !~ /"ZoogVPN"/ { found = 1 }
    END { exit(found ? 0 : 1) }
  '
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
    /usr/bin/dscacheutil -flushcache >/dev/null 2>&1 || true
  fi
}

local_dns_is_ready() {
  local domestic_answer foreign_answer

  domestic_answer="$(/usr/bin/dig +time=2 +tries=1 +short @"$LOCAL_DNS" www.baidu.com A 2>/dev/null)"
  [[ -n "$domestic_answer" ]] || return 1

  foreign_answer="$(/usr/bin/dig +time=2 +tries=1 +short @"$LOCAL_DNS" example.com A 2>/dev/null)"
  [[ -n "$foreign_answer" ]]
}

ensure_dns_override() {
  local foreign_interface

  foreign_interface="$(route_interface_v4 1.1.1.1)"
  if [[ "$foreign_interface" != utun* ]]; then
    clear_dns_override
    log_once "ZoogVPN is connected, but foreign traffic is not routed through a utun interface"
    return 1
  fi

  if ! local_dns_is_ready; then
    clear_dns_override
    log_once "China split DNS is not ready; the system DNS override was removed"
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

  /usr/bin/dscacheutil -flushcache >/dev/null 2>&1 || true
  log_message "China split DNS active on $LOCAL_DNS"
}

remove_recorded_routes() {
  local network

  if [[ -r "$ACTIVE_V4" ]]; then
    while IFS= read -r network; do
      [[ -n "$network" ]] || continue
      /sbin/route -n delete -net "$network" >/dev/null 2>&1 || true
    done < "$ACTIVE_V4"
    /bin/unlink "$ACTIVE_V4" 2>/dev/null || true
  fi

  if [[ -r "$ACTIVE_V6" ]]; then
    while IFS= read -r network; do
      [[ -n "$network" ]] || continue
      /sbin/route -n delete -inet6 -net "$network" >/dev/null 2>&1 || true
    done < "$ACTIVE_V6"
    /bin/unlink "$ACTIVE_V6" 2>/dev/null || true
  fi

  /bin/unlink "$STATE_FILE" 2>/dev/null || true
}

add_ipv4_routes() {
  local gateway="$1"
  local network

  : >| "$ACTIVE_V4"
  exec 3> "$ACTIVE_V4"
  while IFS= read -r network; do
    [[ -n "$network" ]] || continue
    if /sbin/route -n add -net "$network" "$gateway" >/dev/null 2>&1; then
      print -u 3 -r -- "$network"
    fi
  done < "$ROUTES_V4"
  exec 3>&-
}

add_ipv6_routes() {
  local gateway="$1"
  local network

  : >| "$ACTIVE_V6"
  exec 3> "$ACTIVE_V6"
  while IFS= read -r network; do
    [[ -n "$network" ]] || continue
    if /sbin/route -n add -inet6 -net "$network" "$gateway" >/dev/null 2>&1; then
      print -u 3 -r -- "$network"
    fi
  done < "$ROUTES_V6"
  exec 3>&-
}

routes_are_current() {
  local expected_state="$1"
  local interface_v4="$2"
  local interface_v6="$3"

  [[ -r "$STATE_FILE" && "$(<"$STATE_FILE")" == "$expected_state" ]] || return 1
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

  print -r -- "$state" >| "$temporary"
  /bin/chmod 0644 "$temporary"
  /bin/mv -f "$temporary" "$STATE_FILE"
}

reconcile() {
  local ipv4_info ipv6_info ipv4_gateway ipv4_interface
  local ipv6_gateway="" ipv6_interface="" expected_state
  local installed_v4 installed_v6

  if ! zoog_is_connected; then
    clear_dns_override
    if [[ -e "$STATE_FILE" || -e "$ACTIVE_V4" || -e "$ACTIVE_V6" ]]; then
      ipv4_info="$(physical_ipv4_route)"
      ipv6_info="$(physical_ipv6_route)"
      expected_state="${ipv4_info%%|*}|${ipv4_info##*|}|${ipv6_info%%|*}|${ipv6_info##*|}"
      if other_vpn_is_connected || ! routes_are_current "$expected_state" "${ipv4_info##*|}" "${ipv6_info##*|}"; then
        remove_recorded_routes
        log_message "China-direct routes removed while ZoogVPN is disconnected"
      fi
    fi
    clear_error
    return 0
  fi

  ipv4_info="$(physical_ipv4_route)"
  if [[ -z "$ipv4_info" ]]; then
    clear_dns_override
    log_once "ZoogVPN connected, but no physical IPv4 gateway was found"
    return 1
  fi
  ipv4_gateway="${ipv4_info%%|*}"
  ipv4_interface="${ipv4_info##*|}"

  ipv6_info="$(physical_ipv6_route)"
  if [[ -n "$ipv6_info" ]]; then
    ipv6_gateway="${ipv6_info%%|*}"
    ipv6_interface="${ipv6_info##*|}"
  fi

  expected_state="$ipv4_gateway|$ipv4_interface|$ipv6_gateway|$ipv6_interface"
  if routes_are_current "$expected_state" "$ipv4_interface" "$ipv6_interface"; then
    if ensure_dns_override; then
      clear_error
      return 0
    fi
    return 1
  fi

  remove_recorded_routes
  add_ipv4_routes "$ipv4_gateway"
  if [[ -n "$ipv6_gateway" ]]; then
    add_ipv6_routes "$ipv6_gateway"
  fi

  if ! zoog_is_connected; then
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

  if ensure_dns_override; then
    clear_error
    return 0
  fi
  return 1
}

main() {
  acquire_lock
  case "${1:-reconcile}" in
    reconcile)
      reconcile
      ;;
    stop)
      clear_dns_override
      remove_recorded_routes
      clear_error
      ;;
    *)
      print -u 2 -- "Usage: $0 [reconcile|stop]"
      return 64
      ;;
  esac
}

main "$@"
