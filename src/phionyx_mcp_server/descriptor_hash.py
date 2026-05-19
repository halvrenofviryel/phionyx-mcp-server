"""Tool descriptor hashing — Capability 1.

Implements RGE v0.2 founder decision Q3 (2026-05-19):

    tool_descriptor_hash = sha256:<64-hex> over canonical-JSON encoding
    of the COMPLETE MCP tool descriptor INCLUDING the `protocolVersion`
    field.

Rationale: a tool descriptor identical in name/schema but received
under a different MCP protocol version is materially a different
trust object (spec semantics may have shifted). Hashing the full
descriptor catches spec-version drift in addition to descriptor
content drift.

Canonical-JSON encoding follows RFC 8785 / Phionyx canonical:
    - keys sorted lexicographically at every depth
    - no whitespace
    - ensure_ascii (UTF-8 escaped as \\uXXXX)
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


HASH_PREFIX = "sha256:"


def canonical_json(obj: Any) -> str:
    """Encode ``obj`` as canonical JSON.

    Identical to the encoding used in
    ``docs/strategic/launch_drafts/governance_wrapper_demo/wrapper.py``
    so the launch wrapper and the MCP server produce hashes computable
    against the same canonical bytes.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def hash_descriptor(descriptor: dict[str, Any]) -> str:
    """Hash an MCP tool descriptor per RGE v0.2 Q3.

    The descriptor MUST include the MCP ``protocolVersion`` field if
    the host knows it; otherwise the hash binds only to the descriptor
    body and a later spec-version-drift check is impossible.

    Returns: ``sha256:`` + 64-hex SHA-256 digest of canonical-JSON.

    Example:
        >>> hash_descriptor({"name": "github.get_issue", "protocolVersion": "2025-11-25"})
        'sha256:...'

    Raises:
        TypeError: if ``descriptor`` is not a dict.
        ValueError: if ``descriptor`` is empty (descriptors must have at
            least a ``name`` field per MCP spec).
    """
    if not isinstance(descriptor, dict):
        raise TypeError(f"descriptor must be a dict, got {type(descriptor).__name__}")
    if not descriptor:
        raise ValueError("descriptor is empty; MCP tool descriptors require at minimum a 'name'")
    payload = canonical_json(descriptor)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{HASH_PREFIX}{digest}"


def compare_descriptor_hashes(
    current_hash: str,
    baseline_hash: str | None,
) -> dict[str, Any]:
    """Compare a current descriptor hash against the user-approved baseline.

    Capability 2: descriptor change detection.

    Returns a dict with:
        - ``change_detected``: bool — True when current != baseline.
        - ``baseline_exists``: bool — False when this is first observation.
        - ``current_hash``: str — echoed for telemetry.
        - ``baseline_hash``: str | None — echoed.

    NULL ``baseline_hash`` means "no prior approval to compare against"
    and is reported as ``change_detected=False`` (no change relative to
    a non-existent baseline) — but with ``baseline_exists=False`` so
    downstream policy can require approval before allowing the call.
    """
    if not current_hash.startswith(HASH_PREFIX):
        raise ValueError(f"current_hash must start with {HASH_PREFIX!r}")
    if baseline_hash is None:
        return {
            "change_detected": False,
            "baseline_exists": False,
            "current_hash": current_hash,
            "baseline_hash": None,
        }
    if not baseline_hash.startswith(HASH_PREFIX):
        raise ValueError(f"baseline_hash must start with {HASH_PREFIX!r} or be None")
    return {
        "change_detected": current_hash != baseline_hash,
        "baseline_exists": True,
        "current_hash": current_hash,
        "baseline_hash": baseline_hash,
    }
