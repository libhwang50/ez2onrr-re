#!/usr/bin/env bash
# Intercept the game's RAW, UN-PROXIED TLS channel to game1-rank.ez2game.co.kr:443.
#
# Background (see README "The raw channel"): the game opens direct TLS connections
# to that host which never pass through mitmproxy (proven: the addon never dials
# upstream, yet tcpdump shows Sectigo-certified TLS handshakes to it around login
# and song entry). No amount of HTTP-level stubbing can touch them.
#
# This redirects both the hostname and the raw IP to a small loop-proof stub
# (server/_stub443.py) that terminates TLS with a certificate signed by *your*
# mitmproxy CA, logs every request byte-for-byte, and never connects upstream.
#
#   sudo server/_rawchannel.sh on      # redirect + start the stub on 443
#   sudo server/_rawchannel.sh test    # prove the stub answers (prints the IP:port)
#   sudo server/_rawchannel.sh status  # redirect state + how many packets hit it
#   sudo server/_rawchannel.sh off     # stop stub, restore hosts + iptables
#
# Note: mitmproxy in reverse mode must NOT be used here — with the hostname
# redirected to 127.0.0.1 its "upstream" resolves to itself, so every request it
# does not intercept loops until it runs out of file descriptors.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST='game1-rank.ez2game.co.kr'
IP='3.37.247.33'
HOSTS_BAK='/tmp/ez2_hosts.bak'
PIDFILE='/tmp/ez2_rawchannel.pid'
LOG='/tmp/ez2_rawchannel.log'
STUBLOG="$ROOT/server/stub443.log"

die() { echo "error: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "run with sudo"; }

case "${1:-status}" in
on)
  need_root
  [ -f "$HOSTS_BAK" ] || cp /etc/hosts "$HOSTS_BAK"
  grep -q "$HOST" /etc/hosts || echo "127.0.0.1 $HOST" >> /etc/hosts
  iptables -t nat -C OUTPUT -p tcp -d "$IP" --dport 443 -j REDIRECT --to-ports 443 2>/dev/null \
    || iptables -t nat -A OUTPUT -p tcp -d "$IP" --dport 443 -j REDIRECT --to-ports 443
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    kill "$(cat "$PIDFILE")" 2>/dev/null; sleep 1
  fi
  PYTHONUNBUFFERED=1 nohup /usr/bin/python3 "$ROOT/server/_stub443.py" 443 \
    >"$LOG" 2>&1 &
  echo $! >"$PIDFILE"
  sleep 3
  kill -0 "$(cat "$PIDFILE")" 2>/dev/null || { echo "stub failed to start:"; tail -5 "$LOG"; exit 1; }
  echo "stub up (pid $(cat "$PIDFILE")), log: $STUBLOG"
  echo "hosts   : $(grep -c "$HOST" /etc/hosts) entry ($HOST -> 127.0.0.1)"
  echo "iptables: redirect for $IP:443 -> local :443"
  echo
  echo "self-test (should print $IP:9902):"
  echo "    sudo server/_rawchannel.sh test"
  echo "then relaunch the game, log in, load a song, and check:"
  echo "    sudo server/_rawchannel.sh status"
  echo "    tail -40 $STUBLOG"
  ;;
test)
  need_root
  curl -sk --max-time 10 --resolve "$HOST:443:127.0.0.1" \
    "https://$HOST/?data=get_battle_server_ip" -w ' [http %{http_code}]\n'
  ;;
off)
  need_root
  if [ -f "$PIDFILE" ]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null && echo "stub stopped"
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
  echo "packets    : $(iptables -t nat -L OUTPUT -v -n 2>/dev/null | awk '/REDIRECT/ {print $1}') matched by the redirect"
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "stub       : running (pid $(cat "$PIDFILE"))"
  else
    echo "stub       : not running"
  fi
  [ -f "$STUBLOG" ] && { echo "--- last stub log lines ---"; tail -15 "$STUBLOG"; }
  ;;
*)
  sed -n '2,26p' "$0"
  ;;
esac
