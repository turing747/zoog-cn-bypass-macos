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
readonly INSTALL_DIR="/Library/Application Support/ZoogCNBypass"
readonly ROUTES_V4="$INSTALL_DIR/cn-ipv4.txt"
readonly ROUTES_V6="$INSTALL_DIR/cn-ipv6.txt"
readonly RUN_DIR="/var/run/$LABEL"
readonly STATE_FILE="$RUN_DIR/state"
readonly ACTIVE_V4="$RUN_DIR/active-v4"
readonly ACTIVE_V6="$RUN_DIR/active-v6"
readonly ERROR_FILE="$RUN_DIR/error"
readonly LOCK_FILE="$RUN_DIR/lock"
readonly WORK_DIR="$RUN_DIR/chunks"
# Parallel route worker tuning (see compute_route_jobs).
readonly MAX_ROUTE_JOBS=32
readonly MIN_ROUTES_PER_JOB=64
readonly CHUNKS_PER_JOB=4
readonly VPN_SERVICE="ZoogVPN"
readonly DNS_STATE_KEY="State:/Network/Service/com.local.zoog-cn-bypass/DNS"
readonly LOCAL_DNS="127.0.0.1"

# Fractional seconds for timing route operations.
typeset -F SECONDS

log_message() {
  /usr/bin/logger -t ZoogCNBypass -- "$1"
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
  [[ "$1" =~ ^[0-9]{1,3}([.]([0-9]{1,3})){3}$ ]]
}

valid_ipv6_gateway() {
  [[ "$1" =~ ^fe80:[0-9a-fA-F:%A-Za-z0-9._-]+$ ]]
}

valid_interface() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]
}

valid_ipv4_cidr() {
  local cidr="$1"

  [[ "$cidr" =~ ^[0-9]{1,3}([.]([0-9]{1,3})){3}/([89]|[12][0-9]|3[0-2])$ ]] || return 1
  [[ ! "$cidr" =~ ^(0[.]|10[.]|127[.]|169[.]254[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[0-1])[.]|100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.]|1[.]1[.]1[.]|8[.]8[.]8[.]) ]]
}

valid_ipv6_cidr() {
  [[ "$1" =~ ^[23][0-9a-fA-F:]+/(1[6-9]|[2-9][0-9]|1[01][0-9]|12[0-8])$ ]]
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
#
# Each route change is a fork/exec of /sbin/route, so throughput scales with
# the CPU cores that are actually free and flattens once they are saturated
# (measured: gains stop around the number of idle cores). Therefore:
#   jobs = online cores - 1-minute load average (rounded)
# bounded below by max(2, cores/4) so a busy machine still makes progress,
# bounded above by the core count and MAX_ROUTE_JOBS, and never more than one
# worker per MIN_ROUTES_PER_JOB routes (small lists are not worth forking for).
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

# Worker: repeatedly claims a chunk from the queue directory $4 and applies $1
# (add|delete) to every prefix in it. Claiming is an atomic rename into the
# sibling "claimed" directory (outside the queue glob), so each chunk is
# processed by exactly one worker, and faster workers (e.g. on
# performance cores) simply take more chunks instead of waiting on a slow one.
# For "add", only prefixes that /sbin/route accepted are appended to $5, so the
# active file always lists exactly the routes this tool installed (and
# therefore the only ones it may delete later).
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

# run_routes_parallel <add|delete> <ipv4|ipv6> <gateway> <source> <record_file>
# Validates every prefix in <source>, splits the list into a queue of small
# chunks and lets compute_route_jobs() workers drain it concurrently.
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

  if ! valid_ipv4_gateway "$ipv4_gateway" || ! valid_interface "$ipv4_interface"; then
    clear_dns_override
    log_once "Invalid physical IPv4 gateway or interface format"
    return 1
  fi

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
