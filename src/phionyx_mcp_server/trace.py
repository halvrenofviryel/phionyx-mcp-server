"""Shared-trace coordination — per ADR-0006.

Both ``phionyx-mcp-server`` and ``phionyx-pipeline`` MCPs agree on a
single ``trace_id`` per Claude Code session so their telemetry can be
joined without merging the packages.

Resolution order:

    1. ``PHIONYX_TRACE_ID`` env var (highest precedence).
    2. ``PHIONYX_ACTIVE_TRACE_FILE`` (default: ``~/.phionyx/active_trace``).
    3. Generate a new UUID-derived trace id and persist it to that file.

The active-trace file is a single line of text; both MCPs treat it as
read-mostly. A new Claude Code session SHOULD clear the file (via a
``SessionStart`` hook — see ADR-0006 open follow-ups).
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

DEFAULT_ACTIVE_TRACE_FILE = "~/.phionyx/active_trace"


def active_trace_file() -> Path:
    """Return the configured active-trace file path (expanded)."""
    return Path(
        os.environ.get("PHIONYX_ACTIVE_TRACE_FILE", DEFAULT_ACTIVE_TRACE_FILE)
    ).expanduser()


def resolve_active_trace_id(persist_if_missing: bool = True) -> str:
    """Return the active trace id, creating one if necessary.

    Args:
        persist_if_missing: When True (default), generate + persist a new
            trace id if neither the env var nor the file is set. When
            False, return a generated id without writing it — useful for
            tests that want determinism without side-effects.
    """
    env_value = os.environ.get("PHIONYX_TRACE_ID")
    if env_value:
        return env_value

    path = active_trace_file()
    if path.exists():
        text = path.read_text(encoding="utf-8").strip()
        if text:
            return text

    new_id = "trace-" + uuid.uuid4().hex[:16]
    if persist_if_missing:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_id, encoding="utf-8")
    return new_id


__all__ = ["DEFAULT_ACTIVE_TRACE_FILE", "active_trace_file", "resolve_active_trace_id"]
