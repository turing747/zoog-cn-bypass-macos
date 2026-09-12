#!/bin/zsh

set -euo pipefail
umask 022

readonly VERSION="1.0.0"
readonly SOURCE_DIR="${1:A}"
readonly DNSMASQ="$2"
readonly ROUTE_LABEL="com.local.zoog-cn-bypass"
readonly DNS_LABEL="com.local.zoog-cn-dns"
readonly TARGET_DIR="/Library/Application Support/ZoogCNBypass"
readonly ROUTE_PLIST="/Library/LaunchDaemons/$ROUTE_LABEL.plist"
readonly DNS_PLIST="/Library/LaunchDaemons/$DNS_LABEL.plist"
readonly CLI_PATH="/usr/local/bin/zoog-cn-bypass"

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
  if [[ ! -r "$SOURCE_DIR/$relative_path" ]]; then
    print -u 2 -- "Missing installer payload: $relative_path"
    exit 66
  fi
done

if [[ ! -x "$DNSMASQ" ]]; then
  print -u 2 -- "dnsmasq executable not found: $DNSMASQ"
  exit 69
fi

/usr/bin/plutil -lint "$SOURCE_DIR/launchd/com.local.zoog-cn-bypass.plist" >/dev/null
/usr/bin/plutil -lint "$SOURCE_DIR/launchd/com.local.zoog-cn-dns.plist" >/dev/null
"$DNSMASQ" --test --conf-file="$SOURCE_DIR/data/accelerated-domains.china.conf" >/dev/null
"$DNSMASQ" --test --conf-file="$SOURCE_DIR/data/apple.china.conf" >/dev/null

/bin/launchctl bootout "system/$ROUTE_LABEL" >/dev/null 2>&1 || true
/bin/launchctl bootout "system/$DNS_LABEL" >/dev/null 2>&1 || true

routes_changed=true
if /usr/bin/cmp -s "$SOURCE_DIR/data/cn-ipv4.txt" "$TARGET_DIR/cn-ipv4.txt" && \
   /usr/bin/cmp -s "$SOURCE_DIR/data/cn-ipv6.txt" "$TARGET_DIR/cn-ipv6.txt"; then
  routes_changed=false
fi

if $routes_changed && [[ -x "$TARGET_DIR/daemon.sh" ]]; then
  "$TARGET_DIR/daemon.sh" stop || true
fi

/usr/bin/install -d -o root -g wheel -m 0755 "$TARGET_DIR"
/usr/bin/install -d -o root -g wheel -m 0755 /usr/local/bin
/usr/bin/install -o root -g wheel -m 0755 "$SOURCE_DIR/src/daemon.sh" "$TARGET_DIR/daemon.sh"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/data/cn-ipv4.txt" "$TARGET_DIR/cn-ipv4.txt"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/data/cn-ipv6.txt" "$TARGET_DIR/cn-ipv6.txt"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/config/dnsmasq.conf" "$TARGET_DIR/dnsmasq.conf"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/data/accelerated-domains.china.conf" "$TARGET_DIR/accelerated-domains.china.conf"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/data/apple.china.conf" "$TARGET_DIR/apple.china.conf"
/usr/bin/install -o root -g wheel -m 0755 "$SOURCE_DIR/bin/zoog-cn-bypass" "$CLI_PATH"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/launchd/com.local.zoog-cn-bypass.plist" "$ROUTE_PLIST"
/usr/bin/install -o root -g wheel -m 0644 "$SOURCE_DIR/launchd/com.local.zoog-cn-dns.plist" "$DNS_PLIST"

/bin/unlink "$TARGET_DIR/dnsmasq" 2>/dev/null || true
/bin/ln -s "$DNSMASQ" "$TARGET_DIR/dnsmasq"
print -r -- "$VERSION" >| "$TARGET_DIR/VERSION"
/usr/sbin/chown root:wheel "$TARGET_DIR/VERSION"
/bin/chmod 0644 "$TARGET_DIR/VERSION"

"$TARGET_DIR/dnsmasq" --test --conf-file="$TARGET_DIR/dnsmasq.conf" >/dev/null
"$CLI_PATH" enable

print -- "Installation complete. Commands: zoog-cn-bypass enable|disable|status|uninstall"
