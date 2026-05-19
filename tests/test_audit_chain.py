"""Behavior tests for the audit chain — envelope emission + verification.

These tests prove:
    - Emitted envelopes conform to the RGE v0.2 schema.
    - The chain links turn-to-turn correctly.
    - verify_chain detects tamper at any link.
    - verify_chain refuses mixed-schema chains.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from phionyx_mcp_server.audit_chain import (
    GENESIS_HASH,
    FilesystemEnvelopeStore,
    HmacSigner,
    ToolCallContext,
    build_envelope,
    verify_chain,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "specs/rge_v0_2/rge_v0_2.schema.json"


@pytest.fixture(scope="module")
def rge_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


@pytest.fixture(scope="module")
def validator(rge_schema: dict) -> Draft202012Validator:
    return Draft202012Validator(rge_schema)


@pytest.fixture
def store(tmp_path: Path) -> FilesystemEnvelopeStore:
    return FilesystemEnvelopeStore(root=tmp_path)


@pytest.fixture
def signer() -> HmacSigner:
    return HmacSigner(secret="test.fixed.secret")


def _ctx(turn: int, trace: str = "t-abc") -> ToolCallContext:
    return ToolCallContext(
        trace_id=trace,
        turn_index=turn,
        user_text=f"call number {turn}",
        producer="tests.fixture",
        tool_descriptor_hash="sha256:" + "a" * 64,
        descriptor_change_detected=False,
        tool_permission_scope=["read_only"],
        input_hash="sha256:" + "b" * 64,
        output_hash="sha256:" + "c" * 64,
        approval_state={"approved": True, "approval_ref": None, "approved_at_utc": None},
        anomaly_flag={"anomaly": False, "source": "behavioral_drift", "severity": "info", "detail": None},
        decision="release",
        decision_reason="test fixture",
        runtime_policy_basis=["input_safety_gate", "action_intent_gate"],
    )


def test_first_envelope_uses_genesis_previous(store, signer, validator):
    """Behavior: a new trace's first envelope chains from GENESIS_HASH."""
    env = build_envelope(_ctx(1), previous_hash=store.head("t-abc"), server_version="0.1.0-dev", signer=signer)
    assert env["integrity"]["previous"] == GENESIS_HASH
    assert list(validator.iter_errors(env)) == []


def test_envelope_validates_against_rge_v0_2_schema(store, signer, validator):
    """Behavior: emitted envelopes MUST validate against the canonical schema."""
    env = build_envelope(_ctx(1), previous_hash=GENESIS_HASH, server_version="0.1.0-dev", signer=signer)
    errors = list(validator.iter_errors(env))
    assert errors == [], "\n".join(f"{list(e.absolute_path)}: {e.message}" for e in errors)


def test_mcp_tool_audit_block_is_active_and_self_referencing(store, signer):
    """Capability 7: signed_envelope_ref points back to this envelope's own hash."""
    env = build_envelope(_ctx(1), previous_hash=GENESIS_HASH, server_version="0.1.0-dev", signer=signer)
    assert env["mcp_tool_audit"]["status"] == "active"
    assert env["mcp_tool_audit"]["signed_envelope_ref"] == f"envelope://{env['integrity']['current']}"


def test_chain_verify_command_includes_trace_and_turn(store, signer):
    """Capability 8: chain_verify_command is invocation-ready."""
    env = build_envelope(_ctx(7, trace="trace-xyz"), previous_hash=GENESIS_HASH, server_version="0.1.0-dev", signer=signer)
    cmd = env["mcp_tool_audit"]["chain_verify_command"]
    assert "phionyx-mcp verify-chain" in cmd
    assert "--trace trace-xyz" in cmd
    assert "--turn 7" in cmd


def test_chain_persistence_round_trip(store, signer, validator):
    """Behavior: append + iter_chain returns envelopes in turn order; chain links match."""
    trace = "trace-roundtrip"
    for turn in range(1, 4):
        prev = store.head(trace)
        env = build_envelope(_ctx(turn, trace=trace), previous_hash=prev, server_version="0.1.0-dev", signer=signer)
        assert list(validator.iter_errors(env)) == []
        store.append(trace, env)

    envelopes = list(store.iter_chain(trace))
    assert len(envelopes) == 3
    assert envelopes[0]["integrity"]["previous"] == GENESIS_HASH
    for i in range(1, 3):
        assert envelopes[i]["integrity"]["previous"] == envelopes[i - 1]["integrity"]["current"]


def test_verify_chain_accepts_intact_chain(store, signer):
    """Capability 8: verify_chain returns valid=True for an intact chain."""
    trace = "trace-intact"
    for turn in range(1, 4):
        env = build_envelope(_ctx(turn, trace=trace), previous_hash=store.head(trace), server_version="0.1.0-dev", signer=signer)
        store.append(trace, env)

    result = verify_chain(list(store.iter_chain(trace)))
    assert result["valid"] is True
    assert result["checked"] == 3
    assert result["broken_at"] is None


def test_verify_chain_detects_tampered_content(store, signer):
    """Capability 8: tampering with envelope content breaks the chain at the tamper point."""
    trace = "trace-tampered"
    for turn in range(1, 4):
        env = build_envelope(_ctx(turn, trace=trace), previous_hash=store.head(trace), server_version="0.1.0-dev", signer=signer)
        store.append(trace, env)

    envelopes = list(store.iter_chain(trace))
    # Tamper: change the user_text on envelope #2 without recomputing hashes.
    envelopes[1]["input"]["user_text"] = "TAMPERED"
    result = verify_chain(envelopes)
    assert result["valid"] is False
    assert result["broken_at"] == 1
    assert "hash mismatch" in result["reason"]


def test_verify_chain_detects_reordering(store, signer):
    """Capability 8: swapping two envelopes breaks previous-hash linkage."""
    trace = "trace-reorder"
    for turn in range(1, 4):
        env = build_envelope(_ctx(turn, trace=trace), previous_hash=store.head(trace), server_version="0.1.0-dev", signer=signer)
        store.append(trace, env)

    envelopes = list(store.iter_chain(trace))
    envelopes[0], envelopes[2] = envelopes[2], envelopes[0]
    result = verify_chain(envelopes)
    assert result["valid"] is False
    assert result["broken_at"] == 0


def test_verify_chain_refuses_mixed_schemas(store, signer):
    """Migration §5.3: refuse to walk across a schema boundary."""
    env_v2 = build_envelope(_ctx(1), previous_hash=GENESIS_HASH, server_version="0.1.0-dev", signer=signer)
    env_v1_shape = json.loads(json.dumps(env_v2))
    env_v1_shape["schema"] = "phionyx.governed_response_envelope.v0_1"

    result = verify_chain([env_v1_shape, env_v2])
    assert result["valid"] is False
    assert "mixed schemas" in result["reason"]


def test_verify_empty_chain_is_trivially_valid():
    result = verify_chain([])
    assert result["valid"] is True
    assert result["checked"] == 0


def test_signer_signature_format(signer):
    sig = signer.sign("sha256:abc")
    assert sig.startswith("demo-hmac:")
    assert len(sig) == len("demo-hmac:") + 16
