#!/bin/zsh -f

set -euo pipefail
umask 022

unset IFS CDPATH ENV BASH_ENV ZDOTDIR DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH LD_PRELOAD
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export LC_ALL=C

readonly VERSION="1.0.0"
readonly SOURCE_DIR="${1:A}"
readonly DNSMASQ="$2"
readonly ROUTE_LABEL="com.local.zoog-cn-bypass"
readonly DNS_LABEL="com.local.zoog-cn-dns"
readonly TARGET_DIR="/Library/Application Support/ZoogCNBypass"
readonly RUN_DIR="/var/run/$ROUTE_LABEL"
readonly ROUTE_PLIST="/Library/LaunchDaemons/$ROUTE_LABEL.plist"
readonly DNS_PLIST="/Library/LaunchDaemons/$DNS_LABEL.plist"
readonly CLI_PATH="/usr/local/bin/zoog-cn-bypass"
readonly TARGET_CLI_PATH="$TARGET_DIR/zoog-cn-bypass"

if [[ "$(/usr/bin/id -u)" -ne 0 ]]; then
  print -u 2 -- "install-local.sh must run with administrator privileges."
  exit 77
fi

required_files=(
  bin/zoog-cn-bypass
  src/daemon.sh
  config/dnsmasq.conf
  launchd/com.local.zoog-cn-bypass.plist
  launchd/com.local.zoog-cn-dns.plist
  data/cn-ipv4.txt
  data/cn-ipv6.txt
  data/accelerated-domains.china.conf
  data/apple.china.conf
)

for relative_path in "${required_files[@]}"; do
  if [[ -L "$SOURCE_DIR/$relative_path" || ! -f "$SOURCE_DIR/$relative_path" || ! -r "$SOURCE_DIR/$relative_path" ]]; then
    print -u 2 -- "Missing or unsafe installer payload: $relative_path"
    exit 66
  fi
done

if [[ ! -x "$DNSMASQ" ]] || ! /usr/bin/file -b -L "$DNSMASQ" | /usr/bin/grep -q 'Mach-O.*executable'; then
  print -u 2 -- "Valid dnsmasq Mach-O executable not found: $DNSMASQ"
  exit 69
fi

validate_data_files() {
  local domain_file

  for domain_file in "$SOURCE_DIR/data/accelerated-domains.china.conf" "$SOURCE_DIR/data/apple.china.conf"; do
    if ! /usr/bin/awk '
      /^[[:space:]]*$/ || /^#/ { next }
      /^server=\/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\/223\.5\.5\.5$/ { next }
      { exit 1 }
    ' "$domain_file"; then
      print -u 2 -- "Security check failed: unexpected directive in $domain_file"
      exit 65
    fi
  done

  if ! /usr/bin/awk '
    /^[[:space:]]*$/ { next }
    /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|1\.1\.1\.|8\.8\.8\.)/ { exit 1 }
    /^[0-9]{1,3}(\.[0-9]{1,3}){3}\/([89]|[12][0-9]|3[0-2])$/ { next }
    { exit 1 }
  ' "$SOURCE_DIR/data/cn-ipv4.txt"; then
    print -u 2 -- "Security check failed: invalid or unsafe IPv4 prefix in data/cn-ipv4.txt"
    exit 65
  fi

  if ! /usr/bin/awk '
    /^[[:space:]]*$/ { next }
    /^[23][0-9a-fA-F:]+\/(1[6-9]|[2-9][0-9]|1[01][0-9]|12[0-8])$/ { next }
    { exit 1 }
  ' "$SOURCE_DIR/data/cn-ipv6.txt"; then
    print -u 2 -- "Security check failed: invalid or unsafe IPv6 prefix in data/cn-ipv6.txt"
    exit 65
  fi
}

validate_data_files

/usr/bin/plutil -lint "$SOURCE_DIR/launchd/com.local.zoog-cn-bypass.plist" >/dev/null
/usr/bin/plutil -lint "$SOURCE_DIR/launchd/com.local.zoog-cn-dns.plist" >/dev/null
"$DNSMASQ" --test --conf-file="$SOURCE_DIR/data/accelerated-domains.china.conf" >/dev/null
"$DNSMASQ" --test --conf-file="$SOURCE_DIR/data/apple.china.conf" >/dev/null

/bin/launchctl bootout "system/$ROUTE_LABEL" >/dev/null 2>&1 || true
/bin/launchctl bootout "system/$DNS_LABEL" >/dev/null 2>&1 || true

if [[ -L "$TARGET_DIR" || -L "$RUN_DIR" ]]; then
  print -u 2 -- "Security check failed: target or runtime directory is a symlink."
  exit 65
fi

routes_changed=true
if [[ -f "$TARGET_DIR/cn-ipv4.txt" && -f "$TARGET_DIR/cn-ipv6.txt" ]] && \
   /usr/bin/cmp -s "$SOURCE_DIR/data/cn-ipv4.txt" "$TARGET_DIR/cn-ipv4.txt" && \
   /usr/bin/cmp -s "$SOURCE_DIR/data/cn-ipv6.txt" "$TARGET_DIR/cn-ipv6.txt"; then
  routes_changed=false
  if [[ -r "$RUN_DIR/active-v4" ]] && [[ "$(/usr/bin/wc -l < "$RUN_DIR/active-v4" | /usr/bin/tr -d ' ')" != "$(/usr/bin/wc -l < "$SOURCE_DIR/data/cn-ipv4.txt" | /usr/bin/tr -d ' ')" ]]; then
    routes_changed=true
  fi
fi

if $routes_changed && [[ ! -L "$TARGET_DIR/daemon.sh" && -x "$TARGET_DIR/daemon.sh" ]]; then
  "$TARGET_DIR/daemon.sh" stop || true
fi

/usr/bin/install -d -o root -g wheel -m 0755 "$TARGET_DIR"
/usr/bin/install -d -o root -g wheel -m 0755 "$RUN_DIR"
/usr/bin/install -d -m 0755 /usr/local/bin

for item in daemon.sh zoog-cn-bypass cn-ipv4.txt cn-ipv6.txt dnsmasq.conf accelerated-domains.china.conf apple.china.conf dnsmasq VERSION; do
  /bin/unlink "$TARGET_DIR/$item" 2>/dev/null || true
done

/usr/bin/install -o root -g wheel -m 0755 "$SOURCE_DIR/src/daemon.sh" "$TARGET_DIR/daemon.sh"
/usr/bin/install -o root -g wheel -m 0755 "$SOURCE_DIR/bin/zoog-cn-bypass" "$TARGET_CLI_PATH"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/data/cn-ipv4.txt" "$TARGET_DIR/cn-ipv4.txt"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/data/cn-ipv6.txt" "$TARGET_DIR/cn-ipv6.txt"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/config/dnsmasq.conf" "$TARGET_DIR/dnsmasq.conf"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/data/accelerated-domains.china.conf" "$TARGET_DIR/accelerated-domains.china.conf"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/data/apple.china.conf" "$TARGET_DIR/apple.china.conf"

# Copy dnsmasq binary into root-owned directory (do NOT symlink to user-writable Homebrew directory)
/usr/bin/install -o root -g wheel -m 0755 "$DNSMASQ" "$TARGET_DIR/dnsmasq"
if ! /usr/bin/codesign --verify "$TARGET_DIR/dnsmasq" >/dev/null 2>&1; then
  /usr/bin/codesign --force --sign - "$TARGET_DIR/dnsmasq" >/dev/null 2>&1
fi

/usr/bin/chflags nouchg "$CLI_PATH" 2>/dev/null || true
/bin/unlink "$CLI_PATH" 2>/dev/null || true
/usr/bin/install -o root -g wheel -m 0755 "$SOURCE_DIR/bin/zoog-cn-bypass" "$CLI_PATH"
/usr/bin/chflags uchg "$CLI_PATH"

/bin/unlink "$ROUTE_PLIST" 2>/dev/null || true
/bin/unlink "$DNS_PLIST" 2>/dev/null || true
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/launchd/com.local.zoog-cn-bypass.plist" "$ROUTE_PLIST"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/launchd/com.local.zoog-cn-dns.plist" "$DNS_PLIST"

print -r -- "$VERSION" >| "$TARGET_DIR/VERSION"
/usr/sbin/chown root:wheel "$TARGET_DIR/VERSION"
/bin/chmod 0644 "$TARGET_DIR/VERSION"

"$TARGET_DIR/dnsmasq" --test --conf-file="$TARGET_DIR/dnsmasq.conf" >/dev/null
"$TARGET_CLI_PATH" enable

print -- "Installation complete. Commands: zoog-cn-bypass enable|disable|status|uninstall"
