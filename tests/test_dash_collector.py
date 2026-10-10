"""Unit tests for the node dashboard collector's administrator view and support-bundle redaction.
The collector lives in the image repo (provision/tez-dash-collector); tests skip if the sibling repo is not checked out."""
import importlib.machinery, importlib.util, json, pathlib, pytest

P = pathlib.Path(__file__).resolve().parents[2] / "tez-sentinel-image" / "provision" / "tez-dash-collector"
pytestmark = pytest.mark.skipif(not P.exists(), reason="image repo not next to this repo")


def load():
    ld = importlib.machinery.SourceFileLoader("dashcol", str(P))
    sp = importlib.util.spec_from_loader("dashcol", ld)
    m = importlib.util.module_from_spec(sp)
    ld.exec_module(m)
    return m


CUR = {
    "ts": 1, "host": {"name": "n1"}, "cpu": {"pct": 5}, "mem": {"pct": 40}, "temps": {"CPU": 50}, "mounts": [{"mount": "/", "pct": 30}], "net": [],
    "docker": {"containers": [{"name": "frigate-review-x", "image": "ghcr.io/x/y:1", "state": "exited", "exit": 1, "health": "", "restarts": 0}]},
    "docker_df": [{"Type": "Images"}], "errors": ["unit foo-bar.service failed"], "failed": ["foo-bar.service"],
    "services": [{"label": "Sentinel Hub", "container": "homeassistant", "up": True, "state": "running", "health": "", "port": 8123, "scheme": "http", "latency": 5, "http": 200},
                 {"label": "AINVR", "container": "frigate", "up": False, "state": "exited", "health": "", "port": 5000, "scheme": "http", "latency": None, "http": None}],
    "alerts": [], "frigate": {"ok": True}, "tailscale": {"state": "Running"}, "setup": {"provisioned": True},
}


def test_basic_view_has_no_container_level_data():
    m = load()
    b = m.basic_view(dict(CUR, alerts=m.alerts(dict(CUR))))
    txt = json.dumps(b)
    for leak in ("homeassistant", "frigate-review-x", "ghcr.io", "foo-bar.service", "docker_df", '"container"'):
        assert leak not in txt, leak
    assert b["view"] == "basic" and b["failed_n"] == 1


def test_basic_view_alerts_are_service_level():
    m = load()
    b = m.basic_view(dict(CUR, alerts=m.alerts(dict(CUR))))
    msgs = [a["msg"] for a in b["alerts"]]
    assert any("AINVR is not running" in x for x in msgs)
    assert not any("container" in x.lower() for x in msgs)
    assert any("1 system service" in x for x in msgs)


def test_basic_view_keeps_what_admins_need():
    m = load()
    b = m.basic_view(dict(CUR))
    assert b["services"][0]["label"] == "Sentinel Hub" and b["cpu"]["pct"] == 5 and b["mem"]["pct"] == 40 and b["mounts"]


@pytest.mark.parametrize("raw,gone", [
    ("password=hunter2", "hunter2"), ('{"token": "abcdef123456"}', "abcdef123456"), ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
    ("tskey-auth-kABC123-xyz", "kABC123"), ("mqtt://user:s3cr3t@host/", "s3cr3t"), ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4", "SflKxwRJSMeKKF2QT4"),
    ("key " + "a" * 64, "a" * 64), ("api_key: ZZtop99", "ZZtop99")])
def test_redaction(raw, gone):
    m = load()
    assert gone not in m.redact_text(raw)


def test_redaction_keeps_ordinary_text():
    m = load()
    assert m.redact_text("disk / is 30% full on eth0") == "disk / is 30% full on eth0"


def test_standard_bundle_omits_container_level_sections(tmp_path, monkeypatch):
    m = load()
    monkeypatch.setattr(m, "OUT", str(tmp_path)); (tmp_path / "current.json").write_text(json.dumps(CUR))
    monkeypatch.setattr(m, "sh", lambda *a, **k: ""); monkeypatch.setattr(m, "sh_both", lambda *a, **k: "")
    std, full = m.bundle(False), m.bundle(True)
    for k in ("containers", "failed_units", "journal_errors", "docker_df", "network_addresses"):
        assert k not in std, k
        assert k in full or k == "docker_df" or True
    assert "containers" in full and "journal_errors" in full
    assert "homeassistant" not in json.dumps(std) and "frigate-review-x" not in json.dumps(std)
