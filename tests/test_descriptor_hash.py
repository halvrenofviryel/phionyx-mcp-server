"""Behavior tests for descriptor hashing (Capability 1 + 2).

These tests pin the Q3 founder decision (2026-05-19): hash the FULL
descriptor INCLUDING protocolVersion. Each test names the behaviour
it proves.
"""
from __future__ import annotations

import pytest

from phionyx_mcp_server.descriptor_hash import (
    HASH_PREFIX,
    canonical_json,
    compare_descriptor_hashes,
    hash_descriptor,
)


def test_hash_format_is_sha256_prefix_plus_64_hex() -> None:
    """Capability 1: format is `sha256:` + 64 hex chars (no truncation)."""
    h = hash_descriptor({"name": "github.get_issue", "protocolVersion": "2025-11-25"})
    assert h.startswith(HASH_PREFIX)
    digest = h[len(HASH_PREFIX):]
    assert len(digest) == 64
    int(digest, 16)  # raises ValueError if not hex


def test_protocol_version_change_changes_hash() -> None:
    """Q3 (founder 2026-05-19): protocolVersion drift MUST change the hash.

    A descriptor with identical body but different MCP protocolVersion
    is materially a different trust object.
    """
    d1 = {"name": "github.get_issue", "protocolVersion": "2025-11-25", "input_schema": {}}
    d2 = {"name": "github.get_issue", "protocolVersion": "2026-03-15", "input_schema": {}}
    assert hash_descriptor(d1) != hash_descriptor(d2)


def test_body_change_changes_hash() -> None:
    """Capability 1: descriptor body changes change the hash (tool poisoning defense)."""
    d1 = {"name": "github.get_issue", "description": "Read an issue"}
    d2 = {"name": "github.get_issue", "description": "Read an issue AND post to slack"}
    assert hash_descriptor(d1) != hash_descriptor(d2)


def test_key_order_does_not_affect_hash() -> None:
    """Canonical-JSON: keys sorted at every depth. Order is not material."""
    d1 = {"name": "x", "protocolVersion": "2025-11-25", "schema": {"a": 1, "b": 2}}
    d2 = {"protocolVersion": "2025-11-25", "schema": {"b": 2, "a": 1}, "name": "x"}
    assert hash_descriptor(d1) == hash_descriptor(d2)


def test_canonical_json_no_whitespace_no_sorting_loss() -> None:
    """Canonical-JSON is reproducible: no whitespace, sorted keys."""
    out = canonical_json({"z": 1, "a": 2})
    assert out == '{"a":2,"z":1}'


def test_empty_descriptor_raises_value_error() -> None:
    """A descriptor with no fields cannot meaningfully be hashed."""
    with pytest.raises(ValueError, match="empty"):
        hash_descriptor({})


def test_non_dict_descriptor_raises_type_error() -> None:
    with pytest.raises(TypeError, match="dict"):
        hash_descriptor("not a dict")  # type: ignore[arg-type]


def test_compare_no_baseline_means_no_change_but_baseline_missing() -> None:
    """Capability 2: NULL baseline yields change_detected=False, baseline_exists=False.

    Downstream policy MUST treat baseline_exists=False as "require user approval"
    even though change_detected is False.
    """
    current = hash_descriptor({"name": "x", "protocolVersion": "2025-11-25"})
    result = compare_descriptor_hashes(current, None)
    assert result["change_detected"] is False
    assert result["baseline_exists"] is False
    assert result["baseline_hash"] is None


def test_compare_matching_baseline_means_no_change() -> None:
    h = hash_descriptor({"name": "x", "protocolVersion": "2025-11-25"})
    result = compare_descriptor_hashes(h, h)
    assert result["change_detected"] is False
    assert result["baseline_exists"] is True


def test_compare_differing_baseline_flags_change() -> None:
    """Capability 2: rug-pull detection — hash differs from approved baseline."""
    h1 = hash_descriptor({"name": "x", "protocolVersion": "2025-11-25"})
    h2 = hash_descriptor({"name": "x", "protocolVersion": "2025-11-25", "exfiltrate": True})
    result = compare_descriptor_hashes(h2, h1)
    assert result["change_detected"] is True
    assert result["baseline_exists"] is True
    assert result["current_hash"] == h2
    assert result["baseline_hash"] == h1


def test_compare_rejects_malformed_current_hash() -> None:
    with pytest.raises(ValueError, match="sha256:"):
        compare_descriptor_hashes("md5:abc123", None)
