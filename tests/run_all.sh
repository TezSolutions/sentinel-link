#!/usr/bin/env bash
# Sentinel regression suite: unit tests, then every end-to-end suite against ONE node, paced to stay under the login rate limit.
#   tests/run_all.sh <node-host> [admin-user] [--quick] [--net]
# Needs: python3 venv with pytest aiohttp pyotp pyyaml (REGRESSION_PY, default python3), HA_UI_PASS in the environment (admin password).
# Safe by design: throwaway users and virtual switches only, never real devices; a real restore/restart is never run.
# --quick: unit tests only.  --net: also run a real network apply/revert (keeps the IP; use only with physical access).
#
# Status updates (optional, off unless a target is given):
#   NOTIFY_TO=whatsapp          send through `hermes send --to <target>` ("whatsapp" = home chat; or whatsapp:+91..., telegram:..., email)
#   NOTIFY_CMD='my-sender'      alternative: any command that reads the message from stdin
#   HEARTBEAT=300               seconds between "still running" messages while one suite is long (0 = off)
#   Messages: start, one line per finished suite, an immediate alert with the FAIL lines on any failure, a heartbeat, final summary.
#   A failing sender never fails the run.
set -u
HOST=${1:?usage: run_all.sh <node-host> [admin-user] [--quick] [--net]}; ADMIN=${2:-admin}; shift 2 2>/dev/null || shift $#
PY=${REGRESSION_PY:-python3}; cd "$(dirname "$0")/.."; PAUSE=${PAUSE:-65}; HEARTBEAT=${HEARTBEAT:-300}; FAIL=0; QUICK=0; NET=0
for a in "$@"; do [ "$a" = --quick ] && QUICK=1; [ "$a" = --net ] && NET=1; done

notify() {  # notify "message"
  [ -n "${NOTIFY_CMD:-}" ] || [ -n "${NOTIFY_TO:-}" ] || return 0
  if [ -n "${NOTIFY_CMD:-}" ]; then printf '%s\n' "$1" | timeout 60 sh -c "$NOTIFY_CMD" >/dev/null 2>&1 || true
  else timeout 60 hermes send -q --to "$NOTIFY_TO" "$1" >/dev/null 2>&1 || true; fi
}
fmt() { printf '%dm%02ds' $(($1/60)) $(($1%60)); }
T0=$(date +%s); NODE="$HOST"
NETFLAG="--no-net-apply"; [ $NET = 1 ] && NETFLAG=""
SUITES=("e2e_users.py" "e2e_integrations.py $NETFLAG" "e2e_areas.py" "e2e_devices.py" "e2e_scenes.py" "e2e_system.py" "e2e_setup.py" "e2e_portal.py" "e2e_linkapi.py")
TOTAL=$(( ${#SUITES[@]} + 1 )); [ $QUICK = 1 ] && TOTAL=1
SUMMARY=""; DONE=0
notify "Regression started on $NODE: $TOTAL step(s), about $(( QUICK==1 ? 1 : (${#SUITES[@]} * (PAUSE + 70)) / 60 )) min."

echo "== unit tests"; UOUT=$($PY -m pytest tests -q 2>&1 | tail -1); echo "$UOUT"
DONE=1
if echo "$UOUT" | grep -qE "failed|error"; then FAIL=1; notify "FAILED [1/$TOTAL] unit tests on $NODE: $UOUT"; else SUMMARY="unit: $UOUT"; notify "[1/$TOTAL] unit tests OK: $UOUT"; fi
if [ $QUICK = 1 ]; then
  [ $FAIL = 0 ] && notify "Regression ALL GREEN on $NODE ($(fmt $(( $(date +%s) - T0 ))))" || notify "REGRESSION FAILED on $NODE"
  exit $FAIL
fi
[ -z "${HA_UI_PASS:-}" ] && echo "HA_UI_PASS not set: e2e suites need the admin password" >&2 && notify "Regression aborted on $NODE: HA_UI_PASS not set" && exit 2

for t in "${SUITES[@]}"; do
  set -- $t; f=$1; shift; extra="$*"
  [ "$f" = e2e_linkapi.py ] && extra="https"
  name=${f#e2e_}; name=${name%.py}; DONE=$((DONE+1))
  echo "== $f"; sleep "$PAUSE"
  S0=$(date +%s)
  if [ "$HEARTBEAT" -gt 0 ] 2>/dev/null && { [ -n "${NOTIFY_CMD:-}" ] || [ -n "${NOTIFY_TO:-}" ]; }; then
    ( while sleep "$HEARTBEAT"; do notify "...still running: $name ($DONE/$TOTAL), $(fmt $(( $(date +%s) - S0 ))) in this suite, $(fmt $(( $(date +%s) - T0 ))) total"; done ) &
    HB=$!
  else HB=""; fi
  out=$(timeout 600 $PY tests/$f "$HOST" "$ADMIN" $extra 2>&1); rc=$?
  [ -n "$HB" ] && kill "$HB" 2>/dev/null && wait "$HB" 2>/dev/null
  echo "$out" | grep -E "FAIL|passed|Traceback"
  res=$(echo "$out" | grep -E "^[0-9]+/[0-9]+ passed" | tail -1)
  if [ -n "$res" ] && ! echo "$out" | grep -qE "^FAIL|Traceback" && [ $rc = 0 ]; then
    SUMMARY="$SUMMARY, $name $res"; notify "[$DONE/$TOTAL] $name OK: $res ($(fmt $(( $(date +%s) - S0 ))))"
  else
    FAIL=1; bad=$(echo "$out" | grep -E "^FAIL|Traceback|Error" | head -6 | cut -c1-160)
    SUMMARY="$SUMMARY, $name FAILED"; notify "FAILED [$DONE/$TOTAL] $name on $NODE (exit $rc):
${bad:-no result line, see run log}"
  fi
done
if [ $FAIL = 0 ]; then echo "ALL GREEN"; notify "Regression ALL GREEN on $NODE in $(fmt $(( $(date +%s) - T0 ))): ${SUMMARY#, }"
else echo "REGRESSION FAILED"; notify "REGRESSION FAILED on $NODE after $(fmt $(( $(date +%s) - T0 ))): ${SUMMARY#, }"; fi
exit $FAIL
