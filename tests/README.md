# Sentinel regression suite

Lives in `sentinel-link/tests` (git) and ships inside every image as `stack/regression/` (-> `/home/<user>/TezSentinel/regression` on a node).
Run it after ANY change to the stack, the Sentinel OS, hub core, the portal, nginx, integrations or the Link API:

    HA_UI_PASS=... tests/run_all.sh <node-host> admin           # everything (about 15 min, paced for the login rate limit)
    tests/run_all.sh <node-host> admin --quick                  # unit tests only
    REGRESSION_PY=/path/to/venv/bin/python ...                  # needs pytest aiohttp pyotp pyyaml

What it covers: Link API (RBAC, OAuth, SSE/WS), portal login + two-step, devices, areas, users/2FA, integrations + network,
scenes/rules, System (settings, backups, logs). Rules: throwaway users and virtual template switches only; never real devices;
a real restore or restart is never run; always clean up in `finally`.

## Keeping it current (do this with every feature or update)
1. New command/page -> add unit tests (`test_*_util.py`) and an `e2e_<feature>.py` that covers allowed AND forbidden roles.
2. A suite that fails after a stack/OS/hub update is either a real regression (fix the stack) or an intended change (fix the test, say why in the commit).
3. Add the new e2e to the list in `run_all.sh`.
4. Bump nothing silently: the suite output ("N/N passed") is the release gate for an ISO build.
5. `tools/sync-regression.sh` (image repo) copies tests + integrations into `stack/` before `build-iso.sh`.
