#!/usr/bin/env bash
# Sentinel regression suite: unit tests, then every end-to-end suite against ONE node, paced to stay under the login rate limit.
#   tests/run_all.sh <node-host> [admin-user] [--quick] [--net]
# Needs: python3 venv with pytest aiohttp pyotp pyyaml (REGRESSION_PY, default python3), HA_UI_PASS in the environment (admin password).
# Safe by design: throwaway users and virtual switches only, never real devices; a real restore/restart is never run.
# --quick: unit tests only.  --net: also run a real network apply/revert (keeps the IP; use only with physical access).
set -u
HOST=${1:?usage: run_all.sh <node-host> [admin-user] [--quick] [--net]}; ADMIN=${2:-admin}; shift 2 2>/dev/null || shift $#
PY=${REGRESSION_PY:-python3}; cd "$(dirname "$0")/.."; PAUSE=${PAUSE:-65}; FAIL=0; QUICK=0; NET=0
for a in "$@"; do [ "$a" = --quick ] && QUICK=1; [ "$a" = --net ] && NET=1; done
echo "== unit tests"; $PY -m pytest tests -q 2>&1 | tail -1 | tee /dev/stderr | grep -q failed && FAIL=1
[ $QUICK = 1 ] && exit $FAIL
[ -z "${HA_UI_PASS:-}" ] && echo "HA_UI_PASS not set: e2e suites need the admin password" >&2 && exit 2
NETFLAG="--no-net-apply"; [ $NET = 1 ] && NETFLAG=""
for t in "e2e_users.py" "e2e_integrations.py $NETFLAG" "e2e_areas.py" "e2e_devices.py" "e2e_scenes.py" "e2e_system.py" "e2e_setup.py" "e2e_portal.py" "e2e_linkapi.py"; do
  set -- $t; f=$1; shift; extra="$*"
  [ "$f" = e2e_linkapi.py ] && extra="https"
  echo "== $f"; sleep "$PAUSE"
  out=$(timeout 600 $PY tests/$f "$HOST" "$ADMIN" $extra 2>&1); echo "$out" | grep -E "FAIL|passed|Traceback"
  echo "$out" | grep -qE "^[0-9]+/[0-9]+ passed" && ! echo "$out" | grep -qE "^FAIL|Traceback" || FAIL=1
done
[ $FAIL = 0 ] && echo "ALL GREEN" || echo "REGRESSION FAILED"; exit $FAIL
