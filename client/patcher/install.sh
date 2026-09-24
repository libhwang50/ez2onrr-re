#!/usr/bin/env bash
# Install / restore the drop-in `version.dll` that rewrites `zf.publicKey`.
#
#   bash client/patcher/install.sh status    # what is installed right now
#   bash client/patcher/install.sh patcher   # install the RSA-key patcher (Frida-free)
#   bash client/patcher/install.sh gadget    # restore the Frida Gadget
#
# The game directory is the Steam install (the repo's "EZ2ON REBOOT R" is a
# symlink to it).  The Gadget is preserved as `version.dll.gadget` and is never
# lost.  Override the directory with EZ2_GAME_DIR.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GAME="${EZ2_GAME_DIR:-$ROOT/EZ2ON REBOOT R}"
PATCHER="$HERE/version.dll"
GADGET="$GAME/version.dll.gadget"
LIVE="$GAME/version.dll"

[ -f "$LIVE" ] || { echo "no $LIVE" >&2; exit 1; }

sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
kind() {
  if [ -f "$PATCHER" ] && [ "$(sha "$1")" = "$(sha "$PATCHER")" ]; then echo patcher
  elif [ -f "$GADGET" ] && [ "$(sha "$1")" = "$(sha "$GADGET")" ]; then echo gadget
  else echo unknown; fi
}

cmd="${1:-status}"
case "$cmd" in
  status)
    printf 'game dir : %s\n' "$GAME"
    printf 'live     : %s bytes, %s\n' "$(stat -c%s "$LIVE")" "$(kind "$LIVE")"
    [ -f "$GADGET" ] && printf 'gadget   : %s bytes (backup)\n' "$(stat -c%s "$GADGET")"
    if [ -f "$PATCHER" ]; then
      printf 'patcher  : %s bytes\n' "$(stat -c%s "$PATCHER")"
    else
      printf 'patcher  : NOT BUILT (bash client/patcher/build.sh)\n'
    fi
    ;;
  patcher)
    [ -f "$PATCHER" ] || { echo "build it first: bash client/patcher/build.sh" >&2; exit 1; }
    # preserve the Gadget before overwriting the live slot
    if [ "$(kind "$LIVE")" = gadget ] && [ ! -f "$GADGET" ]; then
      cp -f "$LIVE" "$GADGET"
    fi
    cp -f "$PATCHER" "$LIVE"
    echo "installed patcher -> $LIVE"
    ;;
  gadget)
    [ -f "$GADGET" ] || { echo "no gadget backup at $GADGET" >&2; exit 1; }
    cp -f "$GADGET" "$LIVE"
    echo "restored gadget -> $LIVE"
    ;;
  *) echo "usage: $0 {status|patcher|gadget}" >&2; exit 1 ;;
esac
