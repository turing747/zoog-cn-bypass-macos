#!/bin/zsh

set -euo pipefail

readonly ROOT_DIR="${0:A:h:h}"

/bin/zsh -n \
  "$ROOT_DIR/install.sh" \
  "$ROOT_DIR/bin/zoog-cn-bypass" \
  "$ROOT_DIR/src/daemon.sh" \
  "$ROOT_DIR/scripts/install-local.sh" \
  "$ROOT_DIR/scripts/update-data.sh"

/usr/bin/plutil -lint "$ROOT_DIR/launchd/com.local.zoog-cn-bypass.plist" >/dev/null
/usr/bin/plutil -lint "$ROOT_DIR/launchd/com.local.zoog-cn-dns.plist" >/dev/null

[[ "$(/usr/bin/wc -l < "$ROOT_DIR/data/cn-ipv4.txt" | /usr/bin/tr -d ' ')" -gt 5000 ]]
[[ "$(/usr/bin/wc -l < "$ROOT_DIR/data/cn-ipv6.txt" | /usr/bin/tr -d ' ')" -gt 1900 ]]
/usr/bin/grep -q '^server=/baidu\.com/223\.5\.5\.5$' "$ROOT_DIR/data/accelerated-domains.china.conf"
/usr/bin/grep -q '^server=/a1\.mzstatic\.com/223\.5\.5\.5$' "$ROOT_DIR/data/apple.china.conf"

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
  /usr/bin/sed "s#/Library/Application Support/ZoogCNBypass#$ROOT_DIR/data#g" \
    "$ROOT_DIR/config/dnsmasq.conf" > "$temporary_conf"
  "$dnsmasq" --test --conf-file="$temporary_conf" >/dev/null
fi

print -- "Validation passed."
