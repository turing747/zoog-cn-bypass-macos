#!/bin/zsh

set -euo pipefail
umask 022

readonly REPOSITORY="SkyHro/zoog-cn-bypass-macos"
readonly REF="${ZOOG_CN_BYPASS_REF:-main}"
readonly SCRIPT_DIR="${0:A:h}"
temporary_dir=""
source_directory=""

cleanup() {
  if [[ -n "$temporary_dir" && "$temporary_dir" == /tmp/zoog-cn-bypass-install.* && -d "$temporary_dir" ]]; then
    /bin/rm -rf -- "$temporary_dir"
  fi
}
trap cleanup EXIT INT TERM

locate_dnsmasq() {
  local candidate

  for candidate in \
    /opt/homebrew/opt/dnsmasq/sbin/dnsmasq \
    /usr/local/opt/dnsmasq/sbin/dnsmasq; do
    if [[ -x "$candidate" ]]; then
      print -r -- "$candidate"
      return 0
    fi
  done
  return 1
}

locate_brew() {
  local candidate

  for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [[ -x "$candidate" ]]; then
      print -r -- "$candidate"
      return 0
    fi
  done
  return 1
}

prepare_source() {
  local archive

  if [[ -r "$SCRIPT_DIR/scripts/install-local.sh" ]]; then
    source_directory="$SCRIPT_DIR"
    return 0
  fi

  temporary_dir="$(/usr/bin/mktemp -d /tmp/zoog-cn-bypass-install.XXXXXX)"
  archive="$temporary_dir/source.tar.gz"
  print -u 2 -- "Downloading $REPOSITORY ($REF)..."
  /usr/bin/curl --proto '=https' --tlsv1.2 -fL --retry 3 --connect-timeout 15 \
    "https://codeload.github.com/$REPOSITORY/tar.gz/refs/heads/$REF" \
    -o "$archive"
  /usr/bin/tar -xzf "$archive" -C "$temporary_dir"

  source_directory="$(/usr/bin/find "$temporary_dir" -mindepth 1 -maxdepth 1 -type d -name 'zoog-cn-bypass-macos-*' | /usr/bin/head -n 1)"
  if [[ -z "$source_directory" || ! -r "$source_directory/scripts/install-local.sh" ]]; then
    print -u 2 -- "Downloaded archive does not contain the expected installer."
    return 65
  fi
}

run_privileged_installer() {
  local source_directory="$1"
  local dnsmasq_path="$2"
  local installer="$source_directory/scripts/install-local.sh"

  if [[ "$(/usr/bin/id -u)" -eq 0 ]]; then
    /bin/zsh "$installer" "$source_directory" "$dnsmasq_path"
    return
  fi

  /usr/bin/osascript \
    -e 'on run argv' \
    -e 'set installerPath to item 1 of argv' \
    -e 'set sourcePath to item 2 of argv' \
    -e 'set dnsmasqPath to item 3 of argv' \
    -e 'return do shell script ("/bin/zsh " & quoted form of installerPath & " " & quoted form of sourcePath & " " & quoted form of dnsmasqPath) with administrator privileges' \
    -e 'end run' \
    -- "$installer" "$source_directory" "$dnsmasq_path"
}

prepare_source

if ! dnsmasq_path="$(locate_dnsmasq)"; then
  if ! brew_path="$(locate_brew)"; then
    print -u 2 -- "Homebrew is required to install dnsmasq. Install Homebrew from https://brew.sh and run this command again."
    exit 69
  fi
  print -- "Installing the dnsmasq dependency with Homebrew..."
  "$brew_path" install dnsmasq
  dnsmasq_path="$(locate_dnsmasq)"
fi

run_privileged_installer "$source_directory" "$dnsmasq_path"
