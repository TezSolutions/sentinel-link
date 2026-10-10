"""Pure helpers for portal scenes and simple rules (no hub-core imports, unit-tested).

Scenes: a captured set of entity states. Rules: "when <trigger> then <actions>" from a FIXED catalog; nothing free-form
is ever copied into the generated automation, so a client cannot smuggle in templates, services or scripts.
"""
from __future__ import annotations

import json
import re
from typing import Any

PREFIX = "portal_"
MAX_SCENES, MAX_RULES, MAX_SCENE_ENTITIES, MAX_ACTIONS = 100, 100, 40, 8
TAG = "[portal] "

# domains a scene / rule may operate (no locks, alarms, covers of garage doors are covers: allowed, same as the device page)
SCENE_DOMAINS = ("light", "switch", "fan", "cover", "climate", "media_player", "input_boolean")
RULE_ACTION_DOMAINS = ("light", "switch", "fan", "cover", "input_boolean", "media_player")
_EID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_STATE = re.compile(r"^[a-z_]{1,24}$")
_TOSTATE = re.compile(r"^[A-Za-z0-9_ .:-]{1,40}$")
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
NAME_MAX = 60


class Invalid(ValueError):
    pass


def clean_name(v: Any) -> str:
    if not isinstance(v, str):
        raise Invalid("A name is required")
    n = " ".join(v.split())
    if not n:
        raise Invalid("A name is required")
    if len(n) > NAME_MAX:
        raise Invalid(f"Name is too long (max {NAME_MAX})")
    if any(c in n for c in "<>{}\\`"):
        raise Invalid("Name contains characters that are not allowed")
    return n


def _num(v: Any, lo: float, hi: float, what: str) -> int | float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise Invalid(f"{what} must be between {lo} and {hi}")
    return v


def capture(domain: str, state: str, attrs: dict[str, Any]) -> dict[str, Any] | None:
    """What to remember about one entity right now. None when the entity cannot be part of a scene."""
    if domain not in SCENE_DOMAINS or state in ("unavailable", "unknown", ""):
        return None
    out: dict[str, Any] = {"state": state}
    a = attrs or {}
    if domain == "light" and state == "on":
        for k in ("brightness", "color_temp_kelvin"):
            if isinstance(a.get(k), (int, float)) and not isinstance(a.get(k), bool):
                out[k] = a[k]
        rgb = a.get("rgb_color")
        if isinstance(rgb, (list, tuple)) and len(rgb) == 3 and all(isinstance(x, (int, float)) for x in rgb):
            out["rgb_color"] = [int(x) for x in rgb]
    elif domain == "fan" and state == "on":
        if isinstance(a.get("percentage"), (int, float)):
            out["percentage"] = a["percentage"]
    elif domain == "cover" and isinstance(a.get("current_position"), (int, float)):
        out["current_position"] = a["current_position"]
    elif domain == "climate" and isinstance(a.get("temperature"), (int, float)):
        out["temperature"] = a["temperature"]
    return out


def clean_scene_entities(raw: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, dict) or not raw:
        raise Invalid("Pick at least one device")
    if len(raw) > MAX_SCENE_ENTITIES:
        raise Invalid(f"A scene can hold at most {MAX_SCENE_ENTITIES} entities")
    out: dict[str, dict[str, Any]] = {}
    for eid, spec in raw.items():
        if not isinstance(eid, str) or not _EID.match(eid) or eid.split(".")[0] not in SCENE_DOMAINS:
            raise Invalid(f"{str(eid)[:40]} cannot be part of a scene")
        if not isinstance(spec, dict) or not isinstance(spec.get("state"), str) or not _STATE.match(spec["state"]):
            raise Invalid(f"Bad state for {eid}")
        item: dict[str, Any] = {"state": spec["state"]}
        for k, lo, hi in (("brightness", 1, 255), ("color_temp_kelvin", 1000, 12000), ("percentage", 0, 100),
                          ("current_position", 0, 100), ("temperature", -30, 100)):
            if k in spec and spec[k] is not None:
                item[k] = _num(spec[k], lo, hi, k.replace("_", " "))
        if spec.get("rgb_color") is not None:
            rgb = spec["rgb_color"]
            if not (isinstance(rgb, list) and len(rgb) == 3):
                raise Invalid("rgb color must have three values")
            item["rgb_color"] = [int(_num(x, 0, 255, "rgb value")) for x in rgb]
        out[eid] = item
    return out


def scene_config(scene_id: str, name: str, entities: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {"id": scene_id, "name": name, "entities": entities}


def scene_view(cfg: dict[str, Any]) -> dict[str, Any]:
    sid = str(cfg.get("id", ""))
    ents = cfg.get("entities") if isinstance(cfg.get("entities"), dict) else {}
    return {"id": sid, "name": str(cfg.get("name", ""))[:NAME_MAX * 2], "editable": sid.startswith(PREFIX),
            "entities": {k: v for k, v in ents.items() if isinstance(v, (dict, str))} if sid.startswith(PREFIX) else None,
            "count": len(ents)}


# ---------------------------------------------------------------- rules

def clean_rule(raw: Any) -> dict[str, Any]:
    """Validate a client rule spec against the catalog and return a normalised copy."""
    if not isinstance(raw, dict):
        raise Invalid("Bad rule")
    name = clean_name(raw.get("name"))
    t = raw.get("trigger")
    if not isinstance(t, dict):
        raise Invalid("Pick when this should happen")
    typ = t.get("type")
    trig: dict[str, Any]
    if typ == "time":
        at = t.get("at")
        if not isinstance(at, str) or not _HHMM.match(at):
            raise Invalid("Time must look like 07:30")
        days = t.get("days") or list(DAYS)
        if not isinstance(days, list) or not days or any(d not in DAYS for d in days):
            raise Invalid("Pick the days")
        trig = {"type": "time", "at": at, "days": [d for d in DAYS if d in days]}
    elif typ == "sun":
        if t.get("event") not in ("sunrise", "sunset"):
            raise Invalid("Pick sunrise or sunset")
        off = _num(t.get("offset_min", 0), -180, 180, "offset")
        trig = {"type": "sun", "event": t["event"], "offset_min": int(off)}
    elif typ == "state":
        eid = t.get("entity_id")
        if not isinstance(eid, str) or not _EID.match(eid) or eid.split(".")[0] in ("person", "device_tracker", "zone", "scene", "automation"):
            raise Invalid("Pick the device to watch")
        to = t.get("to")
        if not isinstance(to, str) or not _TOSTATE.match(to):
            raise Invalid("Pick the state to wait for")
        trig = {"type": "state", "entity_id": eid, "to": to}
        if t.get("for_min"):
            trig["for_min"] = int(_num(t["for_min"], 1, 1440, "duration"))
    elif typ == "presence":
        eid = t.get("entity_id")
        if not isinstance(eid, str) or not _EID.match(eid) or eid.split(".")[0] not in ("person", "device_tracker"):
            raise Invalid("Pick a person")
        if t.get("to") not in ("home", "not_home"):
            raise Invalid("Pick arrives or leaves")
        trig = {"type": "presence", "entity_id": eid, "to": t["to"]}
    else:
        raise Invalid("Unknown trigger")
    acts_raw = raw.get("actions")
    if not isinstance(acts_raw, list) or not 1 <= len(acts_raw) <= MAX_ACTIONS:
        raise Invalid(f"Pick 1 to {MAX_ACTIONS} actions")
    acts = []
    for a in acts_raw:
        if not isinstance(a, dict):
            raise Invalid("Bad action")
        if a.get("type") == "scene":
            sid = a.get("scene_id")
            if not isinstance(sid, str) or not _EID.match(sid) or not sid.startswith("scene."):
                raise Invalid("Pick a scene")
            acts.append({"type": "scene", "scene_id": sid})
        elif a.get("type") == "entity":
            eid = a.get("entity_id")
            if not isinstance(eid, str) or not _EID.match(eid) or eid.split(".")[0] not in RULE_ACTION_DOMAINS:
                raise Invalid("That device cannot be used in a rule")
            if a.get("command") not in ("turn_on", "turn_off"):
                raise Invalid("Pick on or off")
            acts.append({"type": "entity", "entity_id": eid, "command": a["command"]})
        else:
            raise Invalid("Unknown action")
    out: dict[str, Any] = {"name": name, "trigger": trig, "actions": acts, "enabled": bool(raw.get("enabled", True))}
    ob = raw.get("only_between")
    if ob:
        if not (isinstance(ob, dict) and isinstance(ob.get("from"), str) and isinstance(ob.get("to"), str)
                and _HHMM.match(ob["from"]) and _HHMM.match(ob["to"])):
            raise Invalid("Time window must look like 18:00 to 23:00")
        out["only_between"] = {"from": ob["from"], "to": ob["to"]}
    return out


def _hms(hhmm: str) -> str:
    return hhmm + ":00"


def build_automation(rule_id: str, spec: dict[str, Any]) -> dict[str, Any]:
    t = spec["trigger"]
    conds: list[dict[str, Any]] = []
    if t["type"] == "time":
        trig = {"trigger": "time", "at": _hms(t["at"])}
        if len(t["days"]) < 7:
            conds.append({"condition": "time", "weekday": list(t["days"])})
    elif t["type"] == "sun":
        o = t["offset_min"]
        trig = {"trigger": "sun", "event": t["event"], "offset": f"{'-' if o < 0 else ''}{abs(o) // 60:02d}:{abs(o) % 60:02d}:00"}
    elif t["type"] == "state":
        trig = {"trigger": "state", "entity_id": t["entity_id"], "to": t["to"]}
        if t.get("for_min"):
            trig["for"] = {"minutes": t["for_min"]}
    else:
        trig = {"trigger": "state", "entity_id": t["entity_id"], "to": t["to"]}
    ob = spec.get("only_between")
    if ob:
        conds.append({"condition": "time", "after": _hms(ob["from"]), "before": _hms(ob["to"])})
    acts = []
    for a in spec["actions"]:
        if a["type"] == "scene":
            acts.append({"action": "scene.turn_on", "target": {"entity_id": a["scene_id"]}})
        else:
            acts.append({"action": a["entity_id"].split(".")[0] + "." + a["command"], "target": {"entity_id": a["entity_id"]}})
    return {"id": rule_id, "alias": spec["name"], "description": TAG + json.dumps(spec, separators=(",", ":"), sort_keys=True),
            "mode": "single", "triggers": [trig], "conditions": conds, "actions": acts}


def rule_spec_from(cfg: dict[str, Any]) -> dict[str, Any] | None:
    """The simple spec stored in a portal-made automation, re-validated; None when absent or edited by hand."""
    d = cfg.get("description")
    if not (isinstance(cfg.get("id"), str) and cfg["id"].startswith(PREFIX) and isinstance(d, str) and d.startswith(TAG)):
        return None
    try:
        spec = clean_rule(json.loads(d[len(TAG):]))
    except (ValueError, TypeError):
        return None
    return spec if build_automation(cfg["id"], spec) == _normal(cfg) else None


def _normal(cfg: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "alias", "description", "mode", "triggers", "conditions", "actions")
    return {k: cfg.get(k) for k in keys}


def describe(spec: dict[str, Any], scene_names: dict[str, str] | None = None) -> str:
    t, names = spec["trigger"], scene_names or {}
    if t["type"] == "time":
        days = "every day" if len(t["days"]) == 7 else ", ".join(d.capitalize() for d in t["days"])
        when = f"At {t['at']} ({days})"
    elif t["type"] == "sun":
        o = t["offset_min"]
        when = f"At {t['event']}" if not o else f"{abs(o)} min {'before' if o < 0 else 'after'} {t['event']}"
    elif t["type"] == "state":
        when = f"When {t['entity_id']} is {t['to']}" + (f" for {t['for_min']} min" if t.get("for_min") else "")
    else:
        when = f"When {t['entity_id']} {'arrives home' if t['to'] == 'home' else 'leaves'}"
    if spec.get("only_between"):
        when += f", only between {spec['only_between']['from']} and {spec['only_between']['to']}"
    what = []
    for a in spec["actions"]:
        what.append(f"run {names.get(a['scene_id'], a['scene_id'])}" if a["type"] == "scene"
                    else f"turn {a['entity_id']} {'on' if a['command'] == 'turn_on' else 'off'}")
    return when + ": " + ", ".join(what)
