#!/bin/zsh -f

set -euo pipefail
umask 022

unset IFS CDPATH ENV BASH_ENV ZDOTDIR DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH LD_PRELOAD
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export LC_ALL=C

readonly SCRIPT_DIR="${0:A:h}"
source_directory=""

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
  if [[ -L "$SCRIPT_DIR/scripts/install-local.sh" || ! -r "$SCRIPT_DIR/scripts/install-local.sh" ]]; then
    print -u 2 -- "Local installer scripts/install-local.sh not found in $SCRIPT_DIR."
    print -u 2 -- "Remote code download is disabled for security. Run ./install.sh from a local repository checkout."
    return 65
  fi
  source_directory="$SCRIPT_DIR"
}

run_privileged_installer() {
  local source_directory="$1"
  local dnsmasq_path="$2"
  local installer="$source_directory/scripts/install-local.sh"

  if [[ "$(/usr/bin/id -u)" -eq 0 ]]; then
    /bin/zsh -f "$installer" "$source_directory" "$dnsmasq_path"
    return
  fi

  /usr/bin/osascript \
    -e 'on run argv' \
    -e 'set installerPath to item 1 of argv' \
    -e 'set sourcePath to item 2 of argv' \
    -e 'set dnsmasqPath to item 3 of argv' \
    -e 'return do shell script ("/bin/zsh -f " & quoted form of installerPath & " " & quoted form of sourcePath & " " & quoted form of dnsmasqPath) with administrator privileges' \
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
