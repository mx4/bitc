#!/bin/sh
# Quick probe: connect to a single pinned peer and report its service bits,
# without doing a full sync. Usage: ./probe-peer.sh <ip>

set -e
IP="$1"
LOG="/tmp/bitc-$USER.log"

pkill -9 bitc 2>/dev/null || true
rm -f "$HOME/.bitc/txdb/LOCK"
rm -f "$LOG"

./bitc -d --connect "$IP" --stop-after-height 1 >/dev/null 2>&1 &
BPID=$!

i=0
while [ "$i" -lt 15 ]; do
   if grep -q "svc=" "$LOG" 2>/dev/null; then
      break
   fi
   sleep 1
   i=$((i + 1))
done

kill -9 "$BPID" 2>/dev/null || true
grep -E "svc=|does not serve|compact filters" "$LOG"
