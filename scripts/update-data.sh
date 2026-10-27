#!/bin/zsh -f

set -euo pipefail
umask 022

unset IFS CDPATH ENV BASH_ENV ZDOTDIR DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH LD_PRELOAD
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export LC_ALL=C

readonly ROOT_DIR="${0:A:h:h}"
temporary_dir="$(/usr/bin/mktemp -d /tmp/zoog-cn-data.XXXXXX)"

cleanup() {
  if [[ "$temporary_dir" == /tmp/zoog-cn-data.* && -d "$temporary_dir" ]]; then
    /bin/rm -rf -- "$temporary_dir"
  fi
}
trap cleanup EXIT INT TERM

if ! command -v python3 >/dev/null 2>&1; then
  print -u 2 -- "python3 is required to regenerate route data."
  exit 69
fi

delegated="$temporary_dir/delegated-apnic-latest"
accelerated="$temporary_dir/accelerated-domains.china.conf"
apple="$temporary_dir/apple.china.conf"

/usr/bin/curl --proto '=https' --tlsv1.2 -fL --retry 3 --connect-timeout 15 --max-time 120 \
  https://ftp.apnic.net/stats/apnic/delegated-apnic-latest -o "$delegated"
/usr/bin/curl --proto '=https' --tlsv1.2 -fL --retry 3 --connect-timeout 15 --max-time 120 \
  https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf -o "$accelerated"
/usr/bin/curl --proto '=https' --tlsv1.2 -fL --retry 3 --connect-timeout 15 --max-time 120 \
  https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf -o "$apple"

python3 "$ROOT_DIR/scripts/generate-routes.py" \
  "$delegated" "$temporary_dir/cn-ipv4.txt" "$temporary_dir/cn-ipv6.txt"

/usr/bin/sed 's/114\.114\.114\.114/223.5.5.5/g' "$accelerated" > "$temporary_dir/accelerated-domains.alidns.conf"
/usr/bin/sed 's/114\.114\.114\.114/223.5.5.5/g' "$apple" > "$temporary_dir/apple.alidns.conf"

for domain_file in "$temporary_dir/accelerated-domains.alidns.conf" "$temporary_dir/apple.alidns.conf"; do
  if ! /usr/bin/awk '
    /^[[:space:]]*$/ || /^#/ { next }
    /^server=\/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\/223\.5\.5\.5$/ { next }
    { exit 1 }
  ' "$domain_file"; then
    print -u 2 -- "Security check failed: unexpected directive in downloaded $domain_file"
    exit 65
  fi
done

/bin/mv -f "$temporary_dir/cn-ipv4.txt" "$ROOT_DIR/data/cn-ipv4.txt"
/bin/mv -f "$temporary_dir/cn-ipv6.txt" "$ROOT_DIR/data/cn-ipv6.txt"
/bin/mv -f "$temporary_dir/accelerated-domains.alidns.conf" "$ROOT_DIR/data/accelerated-domains.china.conf"
/bin/mv -f "$temporary_dir/apple.alidns.conf" "$ROOT_DIR/data/apple.china.conf"
/bin/chmod 0644 "$ROOT_DIR/data/cn-ipv4.txt" "$ROOT_DIR/data/cn-ipv6.txt" \
  "$ROOT_DIR/data/accelerated-domains.china.conf" "$ROOT_DIR/data/apple.china.conf"

snapshot="$(/usr/bin/awk -F'|' '$1 == "2" && $2 == "apnic" { print $3; exit }' "$delegated")"
domain_commit="$(/usr/bin/curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 30 https://api.github.com/repos/felixonmars/dnsmasq-china-list/commits/master | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')"
print -- "APNIC snapshot: ${snapshot:-unknown}"
print -- "dnsmasq-china-list commit: $domain_commit"
/usr/bin/wc -l "$ROOT_DIR/data/"*
