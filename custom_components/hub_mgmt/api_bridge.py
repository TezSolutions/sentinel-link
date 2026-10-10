"""Bridge to the Sentinel Link command allowlist (pure Python file shipped by the sentinel_link integration).

hub_mgmt and sentinel_link are separate integrations, so the allowlist is loaded by file path (cached). If sentinel_link
is not installed the portal simply offers no controls (`commands_for` returns [], `validate` refuses everything).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_MOD = None
_TRIED = False


def _load():
    global _MOD, _TRIED
    if _TRIED:
        return _MOD
    _TRIED = True
    path = Path(__file__).resolve().parent.parent / "sentinel_link" / "api" / "commands.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("hub_mgmt_link_commands", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hub_mgmt_link_commands"] = mod
    spec.loader.exec_module(mod)
    _MOD = mod
    return mod


class CommandError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def commands_for(domain: str) -> list[str]:
    m = _load()
    return m.commands_for(domain) if m else []


def validate(domain: str, command: str, data):
    m = _load()
    if m is None:
        raise CommandError("unavailable", "Device control is not available on this node")
    try:
        return m.validate(domain, command, data)
    except m.CommandError as err:
        raise CommandError(err.code, err.message) from None
