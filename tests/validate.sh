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

for domain_file in "$ROOT_DIR/data/accelerated-domains.china.conf" "$ROOT_DIR/data/apple.china.conf"; do
  /usr/bin/awk '
    /^[[:space:]]*$/ || /^#/ { next }
    /^server=\/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\/223\.5\.5\.5$/ { next }
    { exit 1 }
  ' "$domain_file"
done

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

if /usr/bin/grep -q '=~.*\\\.' "$ROOT_DIR/src/daemon.sh"; then
  print -u 2 -- "Use [.] instead of \\. inside zsh =~ regexes in src/daemon.sh"
  exit 1
fi

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
