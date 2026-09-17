#!/usr/bin/env bash
# Regenerate runnable drivers into tools/build/.
# Convention:  <driver>.js  ->  build/<driver>_run.js  =  _il2cpp_bridge.js + <driver>.js
# The bridge must be concatenated *after* nothing and *before* the driver, because
# rpc.exports.* must be defined after Il2Cpp exists.  Re-run after editing a driver.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"      # tools/
OUT="$ROOT/build"
BRIDGE="$ROOT/il2cpp/_il2cpp_bridge.js"
mkdir -p "$OUT"
n=0
for d in il2cpp probes legacy; do
  [ -d "$ROOT/$d" ] || continue
  for f in "$ROOT/$d"/*.js; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in _il2cpp_bridge.js|*_run.js) continue ;; esac
    cat "$BRIDGE" "$f" > "$OUT/${b%.js}_run.js"
    n=$((n+1))
  done
done
echo "generated $n runnable driver(s) in tools/build/"
