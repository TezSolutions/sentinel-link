"""Unit tests for hub_mgmt/setup_util.py."""
import importlib.util
import pathlib

import pytest

spec = importlib.util.spec_from_file_location("setup_util_t", pathlib.Path(__file__).resolve().parents[1] / "custom_components" / "hub_mgmt" / "setup_util.py")
su = importlib.util.module_from_spec(spec)
spec.loader.exec_module(su)

READY = {"name": "Villa 12", "time_zone": "Asia/Kolkata", "areas": 4, "devices": 9, "unplaced": 0, "homeowners": 1, "staff_without_2fa": [],
         "backups": 2, "backup_schedule": "daily", "link_enabled": True, "link_clients": 1, "link_tokens": 0, "cameras": 2}


def by(items):
    return {i["id"]: i for i in items}


def test_fresh_node_nothing_done():
    items = su.steps({"name": "Home", "time_zone": "UTC"})
    assert not any(i["done"] for i in items if i["id"] in ("name", "zone", "areas", "devices", "owner", "backup"))
    p = su.progress(items)
    assert not p["ready"] and p["next"] == "name" and p["total"] == 8


def test_ready_node():
    items = su.steps(READY)
    assert all(i["done"] for i in items)
    p = su.progress(items)
    assert p["ready"] and p["done"] == p["total"] == 8 and p["next"] is None


def test_optional_steps_do_not_block():
    f = dict(READY, link_enabled=False, cameras=0)
    items = su.steps(f)
    assert su.progress(items)["ready"] and not by(items)["app"]["done"] and by(items)["app"]["optional"] and by(items)["cameras"]["optional"]


@pytest.mark.parametrize("name,done", [("Home", False), ("", False), ("  sentinel ", False), ("Villa 12", True)])
def test_name_step(name, done):
    assert by(su.steps(dict(READY, name=name)))["name"]["done"] is done


def test_zone_and_unplaced_and_2fa_and_backup():
    assert not by(su.steps(dict(READY, time_zone="UTC")))["zone"]["done"]
    assert by(su.steps(dict(READY, unplaced=3)))["placed"]["detail"] == "3 device(s) without a room"
    assert not by(su.steps(dict(READY, devices=0)))["placed"]["done"]
    x = by(su.steps(dict(READY, staff_without_2fa=["a", "b"])))["2fa"]
    assert not x["done"] and "a, b" in x["detail"]
    assert not by(su.steps(dict(READY, backup_schedule="never")))["backup"]["done"]
    assert not by(su.steps(dict(READY, backups=0)))["backup"]["done"]


def test_next_follows_order():
    assert su.progress(su.steps(dict(READY, areas=0, homeowners=0)))["next"] == "areas"


@pytest.mark.parametrize("raw,out", [("https://villa.mgmt.tezsolutions.in", "https://villa.mgmt.tezsolutions.in"),
                                     ("https://villa.mgmt.tezsolutions.in/", "https://villa.mgmt.tezsolutions.in"),
                                     ("https://10.0.0.5:8443/portal/", "https://10.0.0.5:8443/portal")])
def test_public_url_ok(raw, out):
    assert su.valid_public_url(raw) == out


@pytest.mark.parametrize("raw", ["http://x.com", "https://u:p@x.com", "https://x.com/?token=abc", "https://x.com/#a", "javascript:alert(1)", "", None,
                                 "https://" + "a" * 250 + ".com", "https://bad host.com", "ftp://x.com"])
def test_public_url_rejected(raw):
    assert su.valid_public_url(raw) is None


@pytest.mark.parametrize("v,ok", [("camera.front_door", True), ("camera.a1", True), ("light.x", False), ("camera.", False), ("camera.Front", False),
                                  ("camera.x/../y", False), ("camera.x y", False), (None, False), ("camera." + "a" * 81, False)])
def test_camera_id(v, ok):
    assert su.is_camera_id(v) is ok


def test_related_sensors():
    s = [{"device_id": "d1", "device_class": "motion", "id": "a"}, {"device_id": "d1", "device_class": "door", "id": "b"},
         {"device_id": "d2", "device_class": "motion", "id": "c"}]
    assert [x["id"] for x in su.related_sensors("d1", s)] == ["a"]
    assert su.related_sensors(None, s) == []


def test_camera_state_text():
    assert su.camera_state_text("idle") == ("Online", "ok")
    assert su.camera_state_text("recording") == ("Recording", "ok")
    assert su.camera_state_text("unavailable") == ("Not reachable", "bad")
    assert su.camera_state_text(None)[1] == "bad"
