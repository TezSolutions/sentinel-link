"""Unit tests for sentinel_link/api/discovery.py (fake zeroconf, no hub)."""
import asyncio
import importlib.util
import pathlib
import sys
import types

import pytest

spec = importlib.util.spec_from_file_location("discovery_t", pathlib.Path(__file__).resolve().parents[1] / "custom_components" / "sentinel_link" / "api" / "discovery.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


@pytest.mark.parametrize("host,expected", [
    ("sentinel-fedeyn", "fedeyn"), ("sentinel-1320b7", "1320b7"), ("Sentinel-ABC", "abc"),
    ("sentinel-fedeyn.local", "fedeyn"), ("mybox", "mybox"), ("My_Box.lan", "mybox"),
    ("a" * 40, "a" * 20), ("sentinel-" + "b" * 40, "b" * 20), ("sentinel-", "sentinel"),
    ("", "node"), (None, "node"), ("___", "node"),
])
def test_node_id(host, expected):
    assert d.node_id_from_hostname(host) == expected


def test_names():
    assert d.instance_name("fedeyn") == "Sentinel fedeyn"
    assert d.service_name("fedeyn") == "Sentinel fedeyn._sentinel._tcp.local."
    assert d.server_name("sentinel-fedeyn") == "sentinel-fedeyn.local."
    assert d.server_name("Bad Host!.lan") == "badhost.local."
    assert d.server_name(None) == "sentinel.local."


def test_txt_content():
    t = d.build_txt("fedeyn", "1.9.0")
    assert t == {"api": "/api/sentinel_link/v1", "ver": "1.9.0", "id": "fedeyn", "proto": "https"}
    assert d.validate_txt(t) == []
    blob = " ".join(list(t) + list(t.values())).lower()
    for w in ("home assistant", "homeassistant", "frigate", "token", "password", "secret"):
        assert w not in blob
    assert " ha " not in f" {blob} "


def test_validate_rejects():
    assert d.validate_txt({"api": "x", "ver": "1", "id": "frigate-1", "proto": "https"})
    assert d.validate_txt({"api": "x", "ver": "1", "id": "a", "proto": "https", "extra": "1"})
    assert d.validate_txt({"api": "x", "ver": "1", "id": "a", "proto": "y" * 300})


class FakeZc:
    def __init__(self, fail=False):
        self.fail, self.reg, self.unreg, self.kw = fail, [], [], []

    async def async_register_service(self, info, **kw):
        if self.fail:
            raise RuntimeError("boom")
        self.reg.append(info); self.kw.append(kw)

    async def async_unregister_service(self, info):
        self.unreg.append(info)


class FakeInfo:
    def __init__(self, type_, name, **kw):
        self.type, self.name, self.kw = type_, name, kw


class Hass:
    def __init__(self):
        self.data = {}


@pytest.fixture
def fake_hub(monkeypatch):
    zc = FakeZc()
    ha = types.ModuleType("homeassistant"); comps = types.ModuleType("homeassistant.components")
    net = types.ModuleType("homeassistant.components.network"); zer = types.ModuleType("homeassistant.components.zeroconf")

    async def addrs(hass): return ["192.168.1.101"]
    async def inst(hass): return zc
    net.async_get_announce_addresses = addrs; zer.async_get_async_instance = inst
    comps.network = net; comps.zeroconf = zer
    zpkg = types.ModuleType("zeroconf"); zasync = types.ModuleType("zeroconf.asyncio"); zasync.AsyncServiceInfo = FakeInfo
    for n, m in {"homeassistant": ha, "homeassistant.components": comps, "homeassistant.components.network": net,
                 "homeassistant.components.zeroconf": zer, "zeroconf": zpkg, "zeroconf.asyncio": zasync}.items():
        monkeypatch.setitem(sys.modules, n, m)
    return zc


def run(c):
    return asyncio.new_event_loop().run_until_complete(c)


def test_register_unregister_cycle(fake_hub):
    h = Hass()
    assert run(d.async_register(h, "1.9.0", "sentinel-fedeyn")) is True
    info = fake_hub.reg[0]
    assert info.name == "Sentinel fedeyn._sentinel._tcp.local." and info.type == d.SERVICE_TYPE
    assert info.kw["port"] == 443 and info.kw["server"] == "sentinel-fedeyn.local."
    assert info.kw["parsed_addresses"] == ["192.168.1.101"] and set(info.kw["properties"]) == {"api", "ver", "id", "proto"}
    assert fake_hub.kw[0] == {"allow_name_change": True}
    run(d.async_register(h, "1.9.0", "sentinel-fedeyn"))          # idempotent
    assert len(fake_hub.reg) == 1
    run(d.async_unregister(h)); assert fake_hub.unreg == [info] and not h.data
    run(d.async_unregister(h)); assert len(fake_hub.unreg) == 1     # no-op when not registered
    assert run(d.async_register(h, "1.9.0", "sentinel-fedeyn")) is True and len(fake_hub.reg) == 2   # re-enable


def test_registration_failure_is_swallowed(fake_hub):
    fake_hub.fail = True
    h = Hass()
    assert run(d.async_register(h, "1.9.0", "sentinel-x")) is False
    assert not h.data
    run(d.async_unregister(h))


def test_unavailable_hub_is_swallowed(monkeypatch):
    monkeypatch.setitem(sys.modules, "homeassistant.components", None)
    assert run(d.async_register(Hass(), "1", "sentinel-x")) is False


def test_unregister_failure_is_swallowed(fake_hub):
    h = Hass(); run(d.async_register(h, "1", "sentinel-x"))
    async def bad(info): raise RuntimeError("x")
    fake_hub.async_unregister_service = bad
    run(d.async_unregister(h)); assert not h.data
