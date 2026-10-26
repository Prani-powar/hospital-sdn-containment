"""Fail early on runtime mismatch or legacy Ryu import failure."""
import importlib
import json
import sys
import time
from importlib.metadata import version


def check(runtime: str) -> dict:
    """Import runtime-specific dependencies and report actual installed versions."""
    expected = {"ryu": (3, 9), "services": (3, 11)}[runtime]
    if sys.version_info[:2] != expected:
        raise RuntimeError(f"{runtime} requires Python {expected}, got {sys.version}")
    modules = (
        ["eventlet", "ryu.base.app_manager", "ryu.app.wsgi", "ryu.app.simple_switch_13"]
        if runtime == "ryu"
        else ["fastapi", "uvicorn", "pydantic", "httpx", "yaml", "pytest"]
    )
    for module in modules:
        importlib.import_module(module)
    packages = ["ryu", "eventlet", "greenlet"] if runtime == "ryu" else [
        "fastapi", "uvicorn", "pydantic", "httpx", "PyYAML", "pytest"
    ]
    return {"check": runtime, "status": "PASS", "timestamp_ns": time.monotonic_ns(),
            "python": sys.version, "versions": {p: version(p) for p in packages}}


if __name__ == "__main__":
    try:
        print(json.dumps(check(sys.argv[1])))
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
