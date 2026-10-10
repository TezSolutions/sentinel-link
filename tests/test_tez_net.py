"""Unit tests for provision/tez-net (pure validators, rendering, plan, and the apply/revert state machine in a sandbox)."""
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import sys

import pytest

SRC = pathlib.Path(__import__("os").environ.get("IMAGE_REPO") or (pathlib.Path.home() / "tez-sentinel-image")) / "provision" / "tez-net"


def load(env):
    for k, v in env.items():
        os.environ[k] = v
    os.environ["TEZ_NET_TEST"] = "1"
    loader = importlib.machinery.SourceFileLoader("tez_net_t", str(SRC))
    spec = importlib.util.spec_from_loader("tez_net_t", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


@pytest.fixture()
def tn(tmp_path):
    sysfs = tmp_path / "sys"
    (sysfs / "enp4s0").mkdir(parents=True)
    (sysfs / "tailscale0").mkdir()
    np = tmp_path / "netplan"
    np.mkdir()
    (np / "00-installer-config.yaml").write_text("network:\n  version: 2\n  ethernets:\n    enp4s0:\n      dhcp4: true\n      optional: true\n    tailscale0:\n      dhcp4: true\n")
    (np / "00-installer-config.yaml").chmod(0o600)
    st = tmp_path / "state"
    st.mkdir()
    return load({"TEZ_STATE": str(st), "TEZ_NETPLAN_DIR": str(np), "TEZ_SYSFS_NET": str(sysfs)})


OK = ["enp4s0"]


def test_dhcp_ok(tn):
    c = tn.clean_request({"iface": "enp4s0", "mode": "dhcp", "dns": ["1.1.1.1", "1.1.1.1", "9.9.9.9"]}, OK)
    assert c["dns"] == ["1.1.1.1", "9.9.9.9"] and c["revert_s"] == 90


def test_static_ok_and_default_dns(tn):
    c = tn.clean_request({"iface": "enp4s0", "mode": "static", "address": "192.168.1.50/24", "gateway": "192.168.1.1"}, OK)
    assert c["address"] == "192.168.1.50/24" and c["dns"] == ["192.168.1.1"]


@pytest.mark.parametrize("req", [
    {"iface": "wlo1", "mode": "dhcp"}, {"iface": "tailscale0", "mode": "dhcp"}, {"iface": "../x", "mode": "dhcp"}, {"mode": "dhcp"},
    {"iface": "enp4s0", "mode": "wat"}, {"iface": "enp4s0", "mode": "dhcp", "dns": ["notanip"]},
    {"iface": "enp4s0", "mode": "dhcp", "dns": ["1.1.1.1"] * 2 + ["8.8.8.8", "9.9.9.9"]}, {"iface": "enp4s0", "mode": "dhcp", "dns": ["0.0.0.0"]},
    {"iface": "enp4s0", "mode": "dhcp", "dns": ["127.0.0.1"]}, {"iface": "enp4s0", "mode": "dhcp", "revert_s": 5},
    {"iface": "enp4s0", "mode": "dhcp", "revert_s": 9999}, {"iface": "enp4s0", "mode": "dhcp", "revert_s": "x"},
    {"iface": "enp4s0", "mode": "static", "address": "192.168.1.50", "gateway": "192.168.1.1"},
    {"iface": "enp4s0", "mode": "static", "address": "192.168.1.50/24", "gateway": "10.0.0.1"},
    {"iface": "enp4s0", "mode": "static", "address": "192.168.1.50/24", "gateway": "192.168.1.50"},
    {"iface": "enp4s0", "mode": "static", "address": "192.168.1.0/24", "gateway": "192.168.1.1"},
    {"iface": "enp4s0", "mode": "static", "address": "192.168.1.255/24", "gateway": "192.168.1.1"},
    {"iface": "enp4s0", "mode": "static", "address": "127.0.0.2/8", "gateway": "127.0.0.1"},
    {"iface": "enp4s0", "mode": "static", "address": "169.254.1.5/16", "gateway": "169.254.1.1"},
    {"iface": "enp4s0", "mode": "static", "address": "192.168.1.50/31", "gateway": "192.168.1.51"},
    {"iface": "enp4s0", "mode": "static", "address": "192.168.1.50/4", "gateway": "192.168.1.1"},
    {"iface": "enp4s0", "mode": "static", "address": "fe80::5/64", "gateway": "fe80::1"},
    {"iface": "enp4s0", "mode": "static", "address": "192.168.1.50/24", "gateway": "192.168.1.0"},
    {"iface": "enp4s0", "mode": "static", "address": "224.0.0.5/24", "gateway": "224.0.0.1"}, "text", None,
])
def test_bad_requests(tn, req):
    with pytest.raises(tn.Bad):
        tn.clean_request(req, OK)


def test_render_keeps_unmanaged_keys(tn):
    old = {"dhcp4": True, "optional": True, "dhcp6": False, "gateway4": "1.2.3.4"}
    n = tn.render_iface(old, {"mode": "static", "address": "10.0.0.5/24", "gateway": "10.0.0.1", "dns": ["10.0.0.1"]})
    assert n["dhcp4"] is False and n["optional"] is True and n["dhcp6"] is False and "gateway4" not in n
    assert n["addresses"] == ["10.0.0.5/24"] and n["routes"] == [{"to": "default", "via": "10.0.0.1"}]
    d = tn.render_iface({"addresses": ["10.0.0.5/24"], "routes": [{"to": "default", "via": "10.0.0.1"}], "dhcp4": False}, {"mode": "dhcp", "dns": []})
    assert d == {"dhcp4": True}


def test_describe_and_view(tn):
    c = {"mode": "static", "address": "10.0.0.5/24", "gateway": "10.0.0.1", "dns": ["10.0.0.1"]}
    d = tn.describe({"dhcp4": True}, c)
    assert d["before"].startswith("automatic") and "10.0.0.5/24" in d["after"] and d["address_changes"]
    assert not tn.describe({"addresses": ["10.0.0.5/24"]}, c)["address_changes"]
    doc = {"network": {"ethernets": {"e": {"addresses": ["10.0.0.5/24"], "routes": [{"to": "default", "via": "10.0.0.1"}], "nameservers": {"addresses": ["1.1.1.1"]}}}}}
    assert tn.current_view(doc, "e") == {"mode": "static", "address": "10.0.0.5/24", "gateway": "10.0.0.1", "dns": ["1.1.1.1"]}


def test_editable_only_real_wired(tn):
    path, doc, why = tn.load_netplan()
    assert not why and tn.editable_ifaces(doc) == ["enp4s0"]   # tailscale0 skipped, missing sysfs dirs skipped


def test_multiple_netplan_files_refused(tn):
    (pathlib.Path(tn.NETPLAN_DIR) / "99-extra.yaml").write_text("network:\n  version: 2\n")
    _, _, why = tn.load_netplan()
    assert "custom network setup" in why
    with pytest.raises(tn.Bad):
        tn.plan({"iface": "enp4s0", "mode": "dhcp"})


class Cmds:
    """Records commands and fakes netplan/systemd results."""
    def __init__(self, tn, gen_fail=False, apply_fail=False, timer_fail=False):
        self.calls, self.gen_fail, self.apply_fail, self.timer_fail = [], gen_fail, apply_fail, timer_fail
        tn.run = self

    def __call__(self, cmd, timeout=40, inp=None):
        self.calls.append(cmd)
        if cmd[:2] == ["netplan", "generate"] and self.gen_fail:
            self.gen_fail = False   # fail the first generate only (the restore path calls it again)
            return 1, "bad yaml"
        if cmd[:2] == ["netplan", "apply"] and self.apply_fail:
            self.apply_fail = False
            return 1, "apply boom"
        if cmd[0] == "systemd-run" and self.timer_fail:
            return 1, "no systemd"
        return 0, ""

    def has(self, *start):
        return any(c[:len(start)] == list(start) for c in self.calls)


def cfg(tn):
    return open(tn.netplan_files()[0]).read()


def test_apply_success_then_confirm(tn):
    c = Cmds(tn)
    orig = cfg(tn)
    tn.do_apply({"iface": "enp4s0", "mode": "static", "address": "10.9.9.5/24", "gateway": "10.9.9.1", "revert_s": 60})
    j = tn.sj(tn.JOB)
    assert j["state"] == "waiting" and "10.9.9.5/24" in cfg(tn) and "optional: true" in cfg(tn)
    assert c.has("systemd-run") and c.has("netplan", "apply") and oct(os.stat(tn.netplan_files()[0]).st_mode & 0o777) == "0o600"
    assert tn.pending()["seconds_left"] > 0 and glob_backup(tn)
    assert open(glob_backup(tn)[0]).read() == orig
    assert tn.confirm() is True and tn.pending() is None and not os.path.exists(tn.PENDING)
    assert tn.sj(tn.JOB)["state"] == "done" and tn.confirm() is False


def glob_backup(tn):
    import glob
    return sorted(glob.glob(tn.NETDIR + "/backup-*.yaml"))


def test_timer_revert_restores_original(tn):
    c = Cmds(tn)
    orig = cfg(tn)
    tn.do_apply({"iface": "enp4s0", "mode": "static", "address": "10.9.9.5/24", "gateway": "10.9.9.1"})
    assert cfg(tn) != orig
    mark = len(c.calls)
    sys.argv = ["tez-net", "revert-now"]
    tn.main()
    assert cfg(tn) == orig and not os.path.exists(tn.PENDING) and tn.sj(tn.JOB)["state"] == "reverted"
    # the timer's own service must not be stopped from inside itself; the timer is disarmed
    during = c.calls[mark:]
    assert ["systemctl", "stop", tn.UNIT + ".service"] not in during and ["systemctl", "stop", tn.UNIT + ".timer"] in during


def test_revert_now_after_confirm_is_a_noop(tn):
    Cmds(tn)
    tn.do_apply({"iface": "enp4s0", "mode": "dhcp", "dns": ["9.9.9.9"]})
    new = cfg(tn)
    tn.confirm()
    sys.argv = ["tez-net", "revert-now"]
    tn.main()
    assert cfg(tn) == new


def test_generate_failure_restores_and_applies_nothing(tn):
    c = Cmds(tn, gen_fail=True)
    orig = cfg(tn)
    tn.do_apply({"iface": "enp4s0", "mode": "dhcp", "dns": ["9.9.9.9"]})
    assert cfg(tn) == orig and tn.sj(tn.JOB)["state"] == "error" and "nothing was changed" in tn.sj(tn.JOB)["message"].lower()
    assert not c.has("netplan", "apply") and not c.has("systemd-run") and not os.path.exists(tn.PENDING)


def test_timer_arm_failure_restores_before_applying(tn):
    c = Cmds(tn, timer_fail=True)
    orig = cfg(tn)
    tn.do_apply({"iface": "enp4s0", "mode": "dhcp", "dns": ["9.9.9.9"]})
    assert cfg(tn) == orig and tn.sj(tn.JOB)["state"] == "error" and not c.has("netplan", "apply")


def test_apply_failure_reverts_immediately(tn):
    c = Cmds(tn, apply_fail=True)
    orig = cfg(tn)
    tn.do_apply({"iface": "enp4s0", "mode": "dhcp", "dns": ["9.9.9.9"]})
    assert cfg(tn) == orig and tn.sj(tn.JOB)["state"] == "reverted"


def test_second_apply_blocked_while_pending(tn):
    Cmds(tn)
    tn.do_apply({"iface": "enp4s0", "mode": "dhcp", "dns": ["9.9.9.9"]})
    tn.do_apply({"iface": "enp4s0", "mode": "dhcp", "dns": ["8.8.8.8"]})
    assert "still waiting" in tn.sj(tn.JOB)["message"]


def test_manual_revert_without_pending_uses_latest_backup(tn):
    Cmds(tn)
    orig = cfg(tn)
    tn.do_apply({"iface": "enp4s0", "mode": "dhcp", "dns": ["9.9.9.9"]})
    tn.confirm()
    tn.do_revert("Restored the previous settings.")
    assert cfg(tn) == orig and tn.sj(tn.JOB)["state"] == "reverted"


def test_revert_with_no_backup_is_an_error(tn):
    Cmds(tn)
    tn.do_revert()
    assert tn.sj(tn.JOB)["state"] == "error"


def test_plan_does_not_touch_anything(tn):
    Cmds(tn)
    orig = cfg(tn)
    clean, d = tn.plan({"iface": "enp4s0", "mode": "static", "address": "10.9.9.5/24", "gateway": "10.9.9.1"})
    assert cfg(tn) == orig and d["address_changes"] and not glob_backup(tn)


def test_status_survives_unreadable_speed(tn, monkeypatch):
    """A downed NIC raises OSError (EINVAL) when its speed file is read: seen on real hardware."""
    sysfs = pathlib.Path(tn.SYSFS)
    (sysfs / "enp4s0" / "speed").mkdir()      # open() on a directory raises OSError, like EINVAL
    monkeypatch.setattr(tn, "ip_json", lambda: [{"ifname": "enp4s0", "operstate": "DOWN", "address": "aa:bb", "addr_info": []}])
    monkeypatch.setattr(tn, "dns_now", lambda: {})
    monkeypatch.setattr(tn, "default_gw", lambda: None)
    st = tn.status()
    assert st["interfaces"][0]["speed"] is None and st["interfaces"][0]["editable"] and st["editable"]


WILD = "# subiquity\nnetwork:\n  ethernets:\n    any-eth:\n      dhcp4: true\n      dhcp6: false\n      match:\n        name: e*\n      optional: true\n  version: 2\n"


def test_expand_wildcard_to_explicit_entries(tn, tmp_path):
    pathlib.Path(tn.netplan_files()[0]).write_text(WILD)
    for n in ("enp5s0", "wlo1", "docker0"):
        (pathlib.Path(tn.SYSFS) / n).mkdir()
    path, doc, why = tn.load_netplan()
    eth = doc["network"]["ethernets"]
    assert not why and set(eth) == {"enp4s0", "enp5s0"}      # wlo1/docker0/tailscale0 never matched or are skipped
    assert eth["enp4s0"] == {"dhcp4": True, "dhcp6": False, "optional": True} and "match" not in eth["enp5s0"]
    assert tn.editable_ifaces(doc) == ["enp4s0", "enp5s0"]


def test_expand_keeps_explicit_entries_and_other_matches(tn):
    doc = {"network": {"version": 2, "ethernets": {
        "enp4s0": {"dhcp4": False, "addresses": ["10.0.0.2/24"]},
        "any": {"match": {"name": "en*"}, "dhcp4": True},
        "byname": {"match": {"name": "enp9s0", "macaddress": "aa"}, "set-name": "lan0"}}}}
    out = tn.expand_wildcards(doc, ["enp4s0", "enp5s0"])
    e = out["network"]["ethernets"]
    assert e["enp4s0"]["addresses"] == ["10.0.0.2/24"] and e["enp5s0"] == {"dhcp4": True} and "any" not in e
    assert "byname" in e                                     # exact match + set-name is not a wildcard: untouched
    assert doc["network"]["ethernets"]["any"]["match"]["name"] == "en*"   # input not mutated


def test_apply_on_wildcard_node_writes_explicit_entries_and_reverts(tn):
    pathlib.Path(tn.netplan_files()[0]).write_text(WILD)
    (pathlib.Path(tn.SYSFS) / "enp5s0").mkdir()
    c = Cmds(tn)
    tn.do_apply({"iface": "enp4s0", "mode": "static", "address": "10.9.9.5/24", "gateway": "10.9.9.1"})
    new = cfg(tn)
    assert "any-eth" not in new and "enp5s0" in new and "10.9.9.5/24" in new and "match" not in new
    assert tn.sj(tn.JOB)["state"] == "waiting"
    sys.argv = ["tez-net", "revert-now"]
    tn.main()
    assert cfg(tn) == WILD and tn.sj(tn.JOB)["state"] == "reverted"
