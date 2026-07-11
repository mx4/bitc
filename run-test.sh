#!/bin/sh
# Test helper: run bitc with --stop-after-height and poll for completion,
# exiting as soon as the daemon stops instead of sleeping a fixed duration.
#
# NOTE: this script passes -n 30 to widen the peer pool for faster test
# turnaround. bitc's own shipped default (when run without -n) is still 5,
# unchanged from upstream.
#
# Usage: ./run-test.sh <stop-height> [max-seconds]

set -e

STOP_HEIGHT="${1:-282000}"
MAX_SECONDS="${2:-240}"
LOG="/tmp/bitc-$USER.log"

pkill -9 bitc 2>/dev/null || true
rm -f "$HOME/.bitc/txdb/LOCK"

./bitc -d -n 30 --stop-after-height "$STOP_HEIGHT" >/dev/null 2>&1 &
BPID=$!

i=0
while [ "$i" -lt "$MAX_SECONDS" ]; do
   if ! kill -0 "$BPID" 2>/dev/null; then
      echo "daemon exited on its own after ~${i}s"
      break
   fi
   if grep -q "matched blocks drained; stopping" "$LOG" 2>/dev/null; then
      echo "stop marker seen after ~${i}s"
      sleep 1
      break
   fi
   # Report live progress every ~10s so a long wait isn't silent.
   if [ $((i % 10)) -eq 0 ]; then
      PENDING=$(grep -c "requesting full block" "$LOG" 2>/dev/null || echo 0)
      RECEIVED=$(grep -c "received matched block" "$LOG" 2>/dev/null || echo 0)
      echo "...${i}s elapsed: requested=$PENDING received=$RECEIVED"
   fi
   sleep 2
   i=$((i + 2))
done

kill -9 "$BPID" 2>/dev/null || true

echo "=== results ==="
grep -E "cfilter match|received matched block|reached stop|drained|BIP157: received|matched blocks drained" "$LOG" | tail -20
echo "=== coins/balance ==="
grep -E "balance|coins|txdb_print" "$LOG" | tail -10
echo "=== pending counter trace ==="
grep -E "cfBlocksPending|BIP157: received matched" "$LOG" | tail -10
