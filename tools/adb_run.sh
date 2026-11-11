#!/bin/bash
# Manual ADB runner. The app is the normal launcher; this is the dev fallback.
# usage: tools/adb_run.sh [stage|run|MODE]
set -u

D=${D:-R5CYA0Q7AYL}
W=/data/local/tmp/wr
MODE=${1:-run}
BUILD=${BUILD:-S731BXXU9CZIF}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/build/payload/$BUILD"
HELPER="$ROOT/payloads/ksud"

say() { printf '%s\n' "$*"; }

case "$MODE" in
    stage|run) ;;
    *)
        if [ ! -x "$BIN/wr_timerfd" ]; then
            say "missing $BIN/wr_timerfd; run exploit/build.sh first"
            exit 1
        fi
        ;;
esac

adb -s "$D" get-state >/dev/null 2>&1 || { say "DEVICE_OFFLINE ($D)"; exit 1; }

say "== device =="
# one plant per boot; a parked run needs a reboot, killing it can panic
adb -s "$D" shell 'echo "uptime=$(cut -d" " -f1 /proc/uptime)"; echo "kernelsu=$(grep -c "^kernelsu " /proc/modules 2>/dev/null)"; echo "parked=$(pidof wr_timerfd timer_s25fe timer_s731b | wc -w)"'

if [ "$MODE" = "run" ] || [ "$MODE" = "stage" ]; then
    if [ ! -x "$BIN/wr_timerfd" ] || [ ! -x "$BIN/wr_exec" ] || [ ! -f "$HELPER" ]; then
        say "== build =="
        PROFILE="$ROOT/payloads/$BUILD/profile.json" BUILD="$BUILD" \
            "$ROOT/exploit/build.sh" || exit 1
    fi
fi

say "== stage =="
adb -s "$D" shell "mkdir -p $W" || exit 1
adb -s "$D" push "$BIN/wr_timerfd" $W/wr_timerfd 2>&1 | tail -1
adb -s "$D" push "$BIN/wr_exec"     $W/wr_exec     2>&1 | tail -1
adb -s "$D" push "$HELPER"          $W/ksud        2>&1 | tail -1
adb -s "$D" shell "chmod 755 $W/wr_timerfd $W/wr_exec $W/ksud 2>/dev/null; ls -l $W; sha256sum $W/wr_timerfd $W/wr_exec $W/ksud"

if [ "$MODE" = "stage" ]; then
    say "staged only; not running"
    exit 0
fi

if [ "$MODE" = "run" ]; then
    say "== run: wr_timerfd as uid 2000 =="
    # ignore HUP/PIPE so an adb/app disconnect does not terminate the plant
    adb -s "$D" shell "cd $W && trap '' 1 13 && export TK_SPRAY=socket && exec ./wr_timerfd" 2>&1 | tee "$ROOT/wr-last.log"
else
    say "== run: wr_timerfd $MODE =="
    adb -s "$D" shell "cd $W && trap '' 1 13 && exec ./wr_timerfd $MODE" 2>&1 | tee "$ROOT/wr-last-$MODE.log"
fi

say "== post =="
adb -s "$D" shell "echo modules=\$(grep -ci kernelsu /proc/modules 2>/dev/null); tail -25 $W/wr_load.log 2>/dev/null; echo '-- procs --'; pidof wr_timerfd timer_s25fe" 2>&1
