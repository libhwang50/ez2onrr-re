#!/usr/bin/env bash
# Intercept the game's RAW, UN-PROXIED TLS channel to game1-rank.ez2game.co.kr:443.
#
# Background (see README "The raw channel"): the game makes direct TLS
# connections to that host that never pass through mitmproxy (our addon proven
# not to dial upstream), clustered right before a chart load. All HTTP-level
# stubbing cannot affect them, and the bundleCryptKey verdict matches their
# timing exactly. This script redirects that channel into a second mitmproxy
# instance (TLS-terminating reverse mode) that runs the SAME addon, so the
# requests show up in server/pserver.log and can be answered.
#
#   sudo server/_rawchannel.sh on     # redirect + start the 443 listener
#   sudo server/_rawchannel.sh off    # stop listener, undo redirects
#   server/_rawchannel.sh status
#
# Requires sudo (port 443 + /etc/hosts + iptables). The normal proxy instance on
# 8080 is untouched and must keep running.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST='game1-rank.ez2game.co.kr'
IP='3.37.247.33'
HOSTS_BAK='/tmp/ez2_hosts.bak'
PIDFILE='/tmp/ez2_rawchannel.pid'
LOG='/tmp/ez2_rawchannel.log'

die() { echo "error: $*" >&2; exit 1; }

need_root() { [ "$(id -u)" = 0 ] || die "run with sudo"; }

case "${1:-status}" in
on)
  need_root
  [ -f "$HOSTS_BAK" ] || cp /etc/hosts "$HOSTS_BAK"
  grep -q "$HOST" /etc/hosts || echo "127.0.0.1 $HOST" >> /etc/hosts
  # catch IP-literal connections too (the game may dial 3.37.247.33 directly,
  # with the hostname only as TLS SNI)
  iptables -t nat -C OUTPUT -p tcp -d "$IP" --dport 443 -j REDIRECT --to-ports 443 2>/dev/null \
    || iptables -t nat -A OUTPUT -p tcp -d "$IP" --dport 443 -j REDIRECT --to-ports 443
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "listener already running (pid $(cat "$PIDFILE"))"
  else
    nohup mitmdump -q --mode "reverse:https://$HOST" --listen-port 443 \
      -s "$ROOT/server/_pserver.py" >"$LOG" 2>&1 &
    echo $! >"$PIDFILE"
    sleep 3
    kill -0 "$(cat "$PIDFILE")" 2>/dev/null || { echo "listener failed:"; tail -5 "$LOG"; exit 1; }
    echo "listener up (pid $(cat "$PIDFILE")), log: $LOG"
  fi
  echo
  echo "hosts:   $(grep -c "$HOST" /etc/hosts) entry for $HOST -> 127.0.0.1"
  echo "iptables: $(iptables -t nat -S OUTPUT | grep -c "$IP.*REDIRECT") redirect rule"
  echo "now do a HYBRID load (python server/_exp.py hybrid on, no knobs) and then:"
  echo "    grep -E '^\\[[0-9:]+\] rank ' $ROOT/server/pserver.log | tail -20"
  ;;
off)
  need_root
  if [ -f "$PIDFILE" ]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null && echo "listener stopped"
    rm -f "$PIDFILE"
  fi
  iptables -t nat -D OUTPUT -p tcp -d "$IP" --dport 443 -j REDIRECT --to-ports 443 2>/dev/null \
    && echo "iptables redirect removed" || true
  if [ -f "$HOSTS_BAK" ]; then
    cp "$HOSTS_BAK" /etc/hosts && echo "hosts restored from $HOSTS_BAK"
  else
    sed -i "/$HOST/d" /etc/hosts && echo "hosts entry removed"
  fi
  ;;
status)
  echo "hosts entry: $(grep "$HOST" /etc/hosts || echo none)"
  echo "iptables   : $(iptables -t nat -S OUTPUT 2>/dev/null | grep "$IP.*REDIRECT" || echo none)"
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "listener   : running (pid $(cat "$PIDFILE"))"
  else
    echo "listener   : not running"
  fi
  ;;
*)
  sed -n '2,20p' "$0"
  ;;
esac
