"""Unit tests for hub_mgmt/remote_access_log.py (pure) against entries built the way tez-access-collector builds them."""
import importlib.util
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
C = next(p for p in (HERE.parent / "custom_components" / "hub_mgmt", HERE.parent / "HA" / "config" / "custom_components" / "hub_mgmt", HERE / "hubmgmt", HERE.parent / "work" / "hubmgmt-demo", pathlib.Path.home() / "work" / "hubmgmt-demo") if (p / "remote_access_log.py").exists())
spec = importlib.util.spec_from_file_location("ra_under_test", C / "remote_access_log.py")
R = importlib.util.module_from_spec(spec)
sys.modules["ra_under_test"] = R
spec.loader.exec_module(R)

NOW = 1_800_000_000.0


def build(n=5, start=NOW - 5000):
    es, prev = [], R.GENESIS
    for i in range(1, n + 1):
        e = {"seq": i, "ts": start + i * 60, "operator": "op:tejas" if i % 2 else "node:x", "operator_kind": "operator", "method": "ssh" if i % 3 else "sudo",
             "action": "login" if i % 3 else "sudo", "account": "tez-admin", "source": "tez-agent", "detail": "", "duration_s": None, "ref": None,
             "reason": R.REASON_PLACEHOLDER, "prev": prev, "time_iso": "x", "time_ist": "y"}
        e["hash"] = R.digest(e)
        prev = e["hash"]
        es.append(e)
    return {"version": 1, "anchor": R.GENESIS, "head": {"seq": es[-1]["seq"], "hash": es[-1]["hash"]}, "entries": es, "generated_ts": NOW, "retention_days": 400}


def test_intact():
    d = build()
    assert R.verify(d)["ok"]
    integ, pin = R.assess(d, None, NOW)
    assert integ["status"] == "ok" and not integ["stale"] and pin == {"seq": 5, "hash": d["entries"][-1]["hash"]}


def test_edit_remove_reorder_detected():
    for mutate in (lambda d: d["entries"][1].update(operator="op:other"),
                   lambda d: d["entries"].pop(2),
                   lambda d: d["entries"].reverse(),
                   lambda d: d["entries"].pop(),            # newest removed: head no longer matches
                   lambda d: d["entries"][3].update(hash="0" * 64)):
        d = build()
        mutate(d)
        assert R.assess(d, None, NOW)[0]["status"] == "broken"


def test_pin_catches_truncation_and_rewrite():
    d = build()
    _, pin = R.assess(d, None, NOW)
    short = build(3)                                          # valid chain, but shorter than what the hub saw
    assert R.assess(short, pin, NOW)[0]["status"] == "broken"
    rewritten = build(5, start=NOW - 9999)                    # valid chain, different history
    assert R.assess(rewritten, pin, NOW)[0]["status"] == "broken"
    longer = build(7)                                         # honest growth keeps the pin valid and advances it
    integ, new = R.assess(longer, pin, NOW)
    assert integ["status"] == "ok" and new["seq"] == 7


def test_stale_and_unavailable():
    d = build()
    assert R.assess(d, None, NOW + 3600)[0]["stale"]
    assert R.assess(None, None, NOW)[0]["status"] == "unavailable"
    assert R.assess({"version": 2}, None, NOW)[0]["status"] == "unavailable"


def test_query_and_summary():
    d = build(9)
    q = R.query(d["entries"], limit=4)
    assert [r["seq"] for r in q["entries"]] == [9, 8, 7, 6] and q["total"] == 9 and q["next_before"] == 6
    assert all(r["reason"].startswith("Reason: not recorded") for r in q["entries"])
    assert {r["method"] for r in R.query(d["entries"], method="sudo")["entries"]} == {"sudo"}
    s = R.summary(d["entries"], R.month_of(d["entries"][0]["ts"]))
    assert sum(r["events"] for r in s["rows"]) == 9 and s["totals"]["sudo"] == 3 and s["totals"]["logins"] == 6


def test_roles():
    assert R.ALLOWED_ROLES == ("admin", "homeowner")
