# Sentinel regression suite

Lives in `sentinel-link/tests` (git) and ships inside every image as `stack/regression/` (-> `/home/<user>/TezSentinel/regression` on a node).
Run it after ANY change to the stack, the Sentinel OS, hub core, the portal, nginx, integrations or the Link API:

    HA_UI_PASS=... tests/run_all.sh <node-host> admin           # everything (about 15 min, paced for the login rate limit)
    tests/run_all.sh <node-host> admin --quick                  # unit tests only
    REGRESSION_PY=/path/to/venv/bin/python ...                  # needs pytest aiohttp pyotp pyyaml

What it covers: Link API (RBAC, OAuth, SSE/WS), portal login + two-step, devices, areas, users/2FA, integrations + network,
scenes/rules, System (settings, backups, logs). Rules: throwaway users and virtual template switches only; never real devices;
a real restore or restart is never run; always clean up in `finally`.

## Status updates while it runs
Off by default. Set a target and the script reports progress by itself:

    NOTIFY_TO=whatsapp tests/run_all.sh <node> admin            # `hermes send --to whatsapp` (home chat); or whatsapp:+91..., telegram:..., email
    NOTIFY_CMD='mail -s regression me@x.com' ...                # alternative: any command reading the message on stdin
    HEARTBEAT=300                                               # seconds between "still running" messages inside a long suite (0 = off)

Messages: start (with time estimate and finish time in IST), `[n/total] suite OK: x/x passed - ran 1m23s + 1m05s pause, 6m40s elapsed, ETA 9m10s (~09:41 IST)` per suite (run time, pacing pause and elapsed are shown separately; the ETA is the average finished-step time x steps left), `FAILED [n/total] suite` at once with the FAIL
lines, `...still running` heartbeats, and a final ALL GREEN / FAILED summary of every suite. A sender that fails never fails the run.
Run it detached (`nohup ... &` or tmux) so a closed session does not kill it.

## Keeping it current (do this with every feature or update)
1. New command/page -> add unit tests (`test_*_util.py`) and an `e2e_<feature>.py` that covers allowed AND forbidden roles.
2. A suite that fails after a stack/OS/hub update is either a real regression (fix the stack) or an intended change (fix the test, say why in the commit).
3. Add the new e2e to the list in `run_all.sh`.
4. Bump nothing silently: the suite output ("N/N passed") is the release gate for an ISO build.
5. `tools/sync-regression.sh` (image repo) copies tests + integrations into `stack/` before `build-iso.sh`.
