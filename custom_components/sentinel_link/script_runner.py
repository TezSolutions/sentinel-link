"""Script runner for Sentinel Link — always called via executor, never blocks event loop."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


# ---------------------------------------------------------------------------
# Bundled script resolution
# ---------------------------------------------------------------------------
_BUNDLED: dict[str, str] = {
    "vigi_alarm": str(Path(__file__).parent / "scripts" / "vigi_alarm.py"),
}


def _resolve_command(command: str) -> list[str]:
    """Return a command list ready for subprocess.

    Accepts:
    - ``bundled:<name>``  → resolved to the scripts/ sub-directory and run with python3.
    - Absolute / relative path  → run directly (chmod +x assumed) or with python3 for .py.
    """
    if command.startswith("bundled:"):
        key = command.split(":", 1)[1]
        script_path = _BUNDLED.get(key)
        if script_path is None:
            raise ValueError(f"Unknown bundled script: {key!r}")
        return ["python3", script_path]

    path = Path(command)
    if path.suffix == ".py":
        return ["python3", str(path)]
    return [str(path)]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_script(command: str, args: str) -> tuple[int, str, str]:
    """Run a script command synchronously.

    This function is **blocking** and must be called via
    ``hass.async_add_executor_job``.

    Args:
        command: Either ``bundled:<name>`` or an absolute path.
        args:    A single argument string (e.g. ``"status"``, ``"enable"``).

    Returns:
        ``(returncode, stdout, stderr)``
    """
    cmd = _resolve_command(command) + [args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Script timed out after 30 seconds"
    except FileNotFoundError as exc:
        return 1, "", f"Command not found: {exc}"
    except OSError as exc:
        return 1, "", f"OS error: {exc}"


def parse_status(stdout: str, stderr: str, returncode: int, parse_rule: str) -> str:
    """Parse script output according to *parse_rule* and return a state string.

    Supported parse_rule values
    ---------------------------
    ``exitcode``
        Returns ``"on"`` if *returncode* is 0, otherwise ``"off"``.
    ``stdout``
        Returns ``stdout.strip()``.
    ``regex:<pattern>``
        Applies *pattern* to *stdout*.  Returns group(1) if a capture group
        exists, otherwise the whole match.  Returns ``"unknown"`` on no match.
    ``jsonpath:<dot.path>``
        Parses *stdout* as JSON and walks a dot-separated path.
        Returns the value as a string, or ``"unknown"`` on any error.
    """
    rule = parse_rule.strip()

    if rule == "exitcode":
        return "on" if returncode == 0 else "off"

    if rule == "stdout":
        return stdout.strip() or "unknown"

    if rule.startswith("regex:"):
        pattern = rule[len("regex:"):]
        match = re.search(pattern, stdout)
        if match is None:
            return "unknown"
        try:
            return match.group(1)
        except IndexError:
            return match.group(0)

    if rule.startswith("jsonpath:"):
        path = rule[len("jsonpath:"):]
        try:
            obj = json.loads(stdout)
            for key in path.split("."):
                if isinstance(obj, dict):
                    obj = obj[key]
                elif isinstance(obj, list):
                    obj = obj[int(key)]
                else:
                    return "unknown"
            return str(obj)
        except (json.JSONDecodeError, KeyError, IndexError, ValueError, TypeError):
            return "unknown"

    # Fallback — treat unknown rule like stdout
    return stdout.strip() or "unknown"
