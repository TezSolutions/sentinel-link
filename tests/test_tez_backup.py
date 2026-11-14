"""Unit + sandbox tests for provision/tez-backup (validators, schedule logic, and a real archive build in a temp tree)."""
import importlib.machinery
import importlib.util
import os
import pathlib
import sqlite3
import tarfile
import datetime

import pytest

SRC = pathlib.Path(os.environ.get("IMAGE_REPO") or (pathlib.Path.home() / "tez-sentinel-image")) / "provision" / "tez-backup"


@pytest.fixture()
def tb(tmp_path, monkeypatch):
    stack, state, fs = tmp_path / "TezSentinel", tmp_path / "state", tmp_path / "frigate-storage"
    for p in (stack, state, fs):
        p.mkdir()
    monkeypatch.setenv("TEZ_BACKUP_TEST", "1")
    monkeypatch.setenv("TEZ_STACK", str(stack)); monkeypatch.setenv("TEZ_STATE", str(state))
    monkeypatch.setenv("TEZ_FRIGATE_STORAGE", str(fs)); monkeypatch.setenv("TEZ_MATTER", str(tmp_path / "nomatter"))
    ld = importlib.machinery.SourceFileLoader("tez_backup_t", str(SRC))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader("tez_backup_t", ld))
    ld.exec_module(m)
    m.tmp = tmp_path
    return m


def test_schedule_validation(tb):
    ok, err = tb.valid_sched({"recurrence": "daily", "time": "03:30", "copies": 3})
    assert err is None and ok["copies"] == 3
    for bad in ({"recurrence": "hourly"}, {"time": "25:00"}, {"time": "3:5"}, {"copies": 0}, {"copies": 99}, {"copies": "x"},
                {"recurrence": "custom_days", "days": []}, "x", None):
        assert tb.valid_sched(bad)[1], bad
    assert tb.valid_sched({"recurrence": "custom_days", "days": ["mon", "evil"], "copies": 2})[0]["days"] == ["mon"]


def test_is_due(tb):
    at = datetime.datetime(2026, 10, 14, 4, 0)       # a Wednesday
    d = {"recurrence": "daily", "time": "03:30"}
    assert tb.is_due(d, 0, at)
    assert not tb.is_due(d, at.timestamp() - 600, at)                       # already ran today
    assert tb.is_due(d, at.timestamp() - 86400, at)
    assert not tb.is_due(d, 0, at.replace(hour=3, minute=0))                # before the set time
    assert not tb.is_due({"recurrence": "never"}, 0, at)
    assert tb.is_due({"recurrence": "custom_days", "days": ["wed"], "time": "03:30"}, 0, at)
    assert not tb.is_due({"recurrence": "custom_days", "days": ["mon"], "time": "03:30"}, 0, at)


def test_archive_has_models_training_faces_and_consistent_db(tb):
    cfg = pathlib.Path(os.environ["TEZ_STACK"]) / "Frigate" / "config"
    (cfg / "model_cache" / "Main Door").mkdir(parents=True)
    (cfg / "model_cache" / "Main Door" / "model.tflite").write_bytes(b"tflite")
    for stock in ("jinaai", "facedet", "bird"):
        (cfg / "model_cache" / stock).mkdir(); (cfg / "model_cache" / stock / "x.onnx").write_bytes(b"stock")
    db = sqlite3.connect(cfg / "frigate.db"); db.execute("create table t(a)"); db.execute("insert into t values (1)"); db.commit(); db.close()
    (cfg / "config.yml").write_text("classification: {}")
    fs = pathlib.Path(os.environ["TEZ_FRIGATE_STORAGE"]) / "clips"
    (fs / "Main Door" / "train").mkdir(parents=True); (fs / "Main Door" / "train" / "a.webp").write_bytes(b"img")
    (fs / "faces" / "Vani").mkdir(parents=True); (fs / "faces" / "Vani" / "1.webp").write_bytes(b"f")
    for skip in ("previews", "thumbs", "review", "cache", "triggers"):
        (fs / skip).mkdir(); (fs / skip / "junk.jpg").write_bytes(b"x")
    (fs.parent / "recordings").mkdir(); (fs.parent / "recordings" / "r.mp4").write_bytes(b"v")

    name, s = tb.create()
    assert s["models"] == ["Main Door"] and s["training"] == ["Main Door"] and s["faces"] == 1
    names = tarfile.open(os.path.join(tb.DEST, name)).getnames()
    j = "\n".join(names)
    assert "model_cache/Main Door/model.tflite" in j and "clips/Main Door/train/a.webp" in j and "clips/faces/Vani/1.webp" in j
    assert "config.yml" in j
    assert not any(x in j for x in ("jinaai", "facedet", "/bird", "previews", "thumbs", "junk.jpg", "recordings"))
    # the database inside is a readable snapshot
    t = tarfile.open(os.path.join(tb.DEST, name)); m = [x for x in t.getmembers() if x.name.endswith("Frigate/config/frigate.db")][0]
    out = tb.tmp / "x.db"; out.write_bytes(t.extractfile(m).read())
    assert sqlite3.connect(out).execute("select a from t").fetchone() == (1,)
    assert (os.stat(os.path.join(tb.DEST, name)).st_mode & 0o777) == 0o600


def test_prune_keeps_newest(tb):
    os.makedirs(tb.DEST, exist_ok=True)
    for i in range(5):
        p = os.path.join(tb.DEST, "n-full-%d.tar.gz" % i); open(p, "wb").write(b"x"); os.utime(p, (1000 + i, 1000 + i))
    tb.prune(2)
    assert [a["name"] for a in tb.list_archives()] == ["n-full-4.tar.gz", "n-full-3.tar.gz"]


def test_delete_rejects_traversal(tb):
    tb.jset(tb.REQ, {"action": "delete", "name": "../../etc/passwd"})
    assert tb.job() == 1 and tb.jget(tb.JOB, {})["state"] == "failed"


def test_locked_database_does_not_hang_backup(tb):
    import time
    cfg = pathlib.Path(os.environ["TEZ_STACK"]) / "data"; cfg.mkdir()
    db = sqlite3.connect(cfg / "auth.db", isolation_level=None); db.execute("create table t(a)")
    db.execute("begin exclusive")                              # a writer holds the lock for the whole backup
    t0 = time.time()
    name, s = tb.create()
    assert time.time() - t0 < 60 and os.path.exists(os.path.join(tb.DEST, name))
    db.execute("rollback"); db.close()
