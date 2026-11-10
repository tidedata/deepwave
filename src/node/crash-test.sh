#!/usr/bin/env bash
# Crash test of deepwave: follow a contiguous window, kill -9 the node at random moments
# (mid-checkpoint: during verification, the batch write with its read set, the fsync, live-index
# flushes, run sealing, the end-of-epoch committee hand-over), restart it on the same directory,
# repeat until it reaches the end, then compare everything stored with the checkpoint blobs
# (`deepwave check`, including read sets when the source has aux records).
#
#   src/node/crash-test.sh [min-kills] [from] [to] [max-sleep-ms]
#
# Defaults: the corpus dense window 342446161..342456160 (10,000 checkpoints across the epoch
# 1303 -> 1304 change, protocol 140 -> 141). Needs a release deepwave (`./zig build node
# -Doptimize=ReleaseFast`). Env:
#   ZUI_CRASH_DIR      work directory (default a new temp dir)
#   ZUI_CRASH_SOURCE   chk (corpus .chk, followed directly) | binpb (corpus archive protos through
#                      the spool, with read sets) | s3 (Mysten's archive, spool kept for the check)
#   ZUI_CRASH_WORKERS (3), ZUI_CRASH_SYNC (data), ZUI_CRASH_BUDGET (s3 dollars per run, 0.05)
#   ZUI_CRASH_EXEC=1   execute mode (corpus packages/ and deny/ as --packages and --deny-state);
#                      a mismatch stops the node with exit 3, which fails the test
# Kills only the node it started. A kill counts only when the run still had checkpoints to apply
# when it was killed (it started at or below `to` and had not printed its final line). Exit 0 only
# when no run rejected a checkpoint and the final check has 0 failures.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=/dev/null
source "$ROOT/tools/env.sh"
BIN="$ROOT/zig-out/bin/deepwave"
C="$ZUI_CORPUS"
MIN_KILLS="${1:-25}"
FROM="${2:-342446161}"
TO="${3:-342456160}"
MAXMS="${4:-1500}"
WORK="${ZUI_CRASH_DIR:-$(mktemp -d)}"
DIR="$WORK/node"
LOG="$WORK/crash.log"
SRC="${ZUI_CRASH_SOURCE:-chk}"
rm -rf "$DIR"; : >"$LOG"
[ -x "$BIN" ] || { echo "build deepwave first" >&2; exit 2; }
case "$SRC" in
  chk) source_args=(--source "dir:$C/chk"); against="$C/chk" ;;
  binpb) source_args=(--source "dir:$C/binpb-done" --fetchers 6); against="$C/binpb-done" ;;
  s3) source_args=(--source s3 --keep-spool --fetchers 8 --s3-budget "${ZUI_CRASH_BUDGET:-0.05}"); against="$DIR/node/spool" ;;
  *) echo "ZUI_CRASH_SOURCE: chk | binpb | s3" >&2; exit 2 ;;
esac
common=("${source_args[@]}" --genesis "$C/vectors/bls-cert/upstream/genesis.blob" --epochs "$C/epochs.jsonl" --trust-dir "$C/chk" --to "$TO" --workers "${ZUI_CRASH_WORKERS:-3}" --status-every 0 --sync "${ZUI_CRASH_SYNC:-data}")
if [ "${ZUI_CRASH_EXEC:-0}" = 1 ]; then
  common+=(--mode execute --packages "$C/packages" --deny-state "$C/deny/objects.bin.zst")
fi
kills=0; runs=0; t0=$(date +%s)
echo "crash test $FROM..$TO from $SRC into $DIR (log $LOG)"
while :; do
  runs=$((runs + 1))
  started=$( (grep -c 'following from checkpoint' "$LOG" 2>/dev/null || true) | tail -1)
  finals=$( (grep -c 'final: applied' "$LOG" 2>/dev/null || true) | tail -1)
  "$BIN" run --dir "$DIR" --from "$FROM" "${common[@]}" >>"$LOG" 2>&1 &
  pid=$!
  # Kill only once this run is applying checkpoints (not during the start-up trust walk), so every
  # kill lands in the follow/commit path.
  while kill -0 "$pid" 2>/dev/null && [ "$( (grep -c 'following from checkpoint' "$LOG" || true) | tail -1)" -le "${started:-0}" ]; do sleep 0.01; done
  # A run that starts past TO has nothing to apply: killing it would only count a no-op kill.
  next=$( (grep -o 'following from checkpoint [0-9]*' "$LOG" || true) | tail -1 | awk '{print $4}')
  if [ "${next:-0}" -le "$TO" ] && { [ "$kills" -lt "$MIN_KILLS" ] || [ $((RANDOM % 4)) -ne 0 ]; }; then
    ms=$(( (RANDOM * 32768 + RANDOM) % MAXMS + 1 ))
    sleep "$(printf '%d.%03d' $((ms / 1000)) $((ms % 1000)))"
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      # A run that already printed its final line was shutting down cleanly: not a mid-follow kill.
      if [ "$( (grep -c 'final: applied' "$LOG" || true) | tail -1)" -gt "${finals:-0}" ]; then
        echo "kill after ${ms} ms hit a finished run (not counted)"; continue
      fi
      kills=$((kills + 1))
      echo "kill $kills after ${ms} ms (run $runs, started at ${next})"
      continue
    fi
  fi
  set +e; wait "$pid"; rc=$?; set -e
  if [ "$rc" -ne 0 ]; then echo "node exited $rc on run $runs (see $LOG)"; tail -5 "$LOG"; exit 1; fi
  if grep -q "final: applied $TO " "$LOG"; then break; fi
done
echo "reached $TO after $runs runs and $kills kills (all mid-follow) in $(( $(date +%s) - t0 )) s"
if grep -q REJECTED "$LOG"; then echo "a run rejected a checkpoint"; exit 1; fi
if [ "${ZUI_CRASH_EXEC:-0}" = 1 ]; then
  grep -h "final: applied" "$LOG" | grep -o "exec: [^|]*" | tail -1
  if grep -q "execute: checkpoint .* tx " "$LOG"; then echo "a run had an execute mismatch or exec error"; exit 1; fi
fi
starts=$( (grep -o 'following from checkpoint [0-9]*' "$LOG" || true) | awk '{print $4}' | tr '\n' ' ')
echo "resume points: $starts"
"$BIN" check --dir "$DIR" --against "$against" --from "$FROM" --to "$TO" 2>&1 | tail -1
