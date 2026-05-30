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
    RetrievalContext,
    RetrievalDocument,
    ToolCallContext,
    build_envelope,
    build_retrieval_block,
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


# ── v0.7.0 W2.1 (F4) — reasoning surface extension ────────────────────────

def test_w2_1_envelope_carries_new_reasoning_fields_with_null_defaults(
    validator, signer
):
    """Envelopes built without explicit reasoning surface population MUST
    include the three new fields (rationale_summary, knowledge_sources_consulted,
    constraints_acknowledged) at their null/empty defaults so the schema
    validates and downstream consumers can read them unconditionally."""
    envelope = build_envelope(
        ctx=_ctx(turn=1),
        previous_hash=GENESIS_HASH,
        signer=signer,
        server_version="0.1.0",
    )
    reasoning = envelope["reasoning"]
    assert "rationale_summary" in reasoning
    assert "knowledge_sources_consulted" in reasoning
    assert "constraints_acknowledged" in reasoning
    assert reasoning["rationale_summary"] is None
    assert reasoning["knowledge_sources_consulted"] == []
    assert reasoning["constraints_acknowledged"] == []
    validator.validate(envelope)  # schema-valid


def test_w2_1_envelope_with_populated_reasoning_surface_validates(
    validator, signer
):
    """When a producer populates the three new fields, the envelope must
    still validate. Tests the actual fields, not just presence."""
    envelope = build_envelope(
        ctx=_ctx(turn=2),
        previous_hash=GENESIS_HASH,
        signer=signer,
        server_version="0.1.0",
    )
    # Simulate a post-build producer extension (the dict is mutable until
    # hash is finalized; in real usage the producer would extend before
    # build_envelope is called). For this test we mutate post-hoc and
    # re-validate against the schema only — we are not re-signing.
    envelope["reasoning"]["rationale_summary"] = (
        "Tool call required to retrieve user account balance; declined per HITL gate."
    )
    envelope["reasoning"]["knowledge_sources_consulted"] = [
        {"kind": "retrieval_corpus", "ref": "vector://kb-banking", "hash": "sha256:" + "c" * 64},
        {"kind": "memory_block", "ref": "letta://user-prefs/risk-tolerance"},
    ]
    envelope["reasoning"]["constraints_acknowledged"] = [
        {"kind": "policy", "ref": "kill_switch_gate", "satisfied": True},
        {"kind": "regulatory", "ref": "EU AI Act Article 14 (human oversight)", "satisfied": None},
    ]
    validator.validate(envelope)  # populated form schema-valid


def test_w2_1_invalid_kind_value_rejected_by_schema(validator, signer):
    """Schema validates the enum on `kind` for knowledge_sources_consulted +
    constraints_acknowledged — typos / unknown sources must be rejected."""
    envelope = build_envelope(
        ctx=_ctx(turn=3),
        previous_hash=GENESIS_HASH,
        signer=signer,
        server_version="0.1.0",
    )
    envelope["reasoning"]["knowledge_sources_consulted"] = [
        {"kind": "not_a_valid_kind", "ref": "x"},
    ]
    with pytest.raises(Exception):  # jsonschema.ValidationError or similar
        validator.validate(envelope)


# ── v0.7.0 W2.2 (F8) — RAG retrieval audit ────────────────────────────────


def test_w2_2_envelope_without_retrieval_kwarg_omits_retrieval_block(
    validator, signer
):
    """Backward-compat: callers that don't pass retrieval get an envelope
    with no retrieval key — schema-valid because the block is optional."""
    envelope = build_envelope(
        ctx=_ctx(turn=1),
        previous_hash=GENESIS_HASH,
        signer=signer,
        server_version="0.1.0",
    )
    assert "retrieval" not in envelope
    validator.validate(envelope)


def test_w2_2_retrieval_context_produces_active_status_block(validator, signer):
    """When RetrievalContext is provided, the envelope MUST carry a
    `retrieval` block with `status='active'` and the documents the caller
    surfaced. Schema MUST validate."""
    rctx = RetrievalContext(
        documents=[
            RetrievalDocument(
                id="doc-001",
                role="cited",
                score=0.92,
                hash="sha256:" + "f" * 64,
                chunk_offset=3,
                source_url="https://example.com/banking-policy/2026-01.pdf",
                retrieved_at="2026-05-27T10:15:30+00:00",
            ),
            RetrievalDocument(
                id="doc-002",
                role="rejected",
                score=0.51,
                chunk_offset=0,
            ),
        ],
        store_id="vector://kb-banking",
        corpus_name="banking-policy-2026",
        corpus_version="2026-Q1-snapshot-a3f7",
        corpus_language="en",
        similarity_threshold=0.55,
        query_text_hash="sha256:" + "a" * 64,
    )
    envelope = build_envelope(
        ctx=_ctx(turn=2),
        previous_hash=GENESIS_HASH,
        signer=signer,
        server_version="0.1.0",
        retrieval=rctx,
    )
    assert envelope["retrieval"]["status"] == "active"
    assert len(envelope["retrieval"]["documents"]) == 2
    assert envelope["retrieval"]["documents"][0]["role"] == "cited"
    assert envelope["retrieval"]["documents"][0]["chunk_offset"] == 3
    assert envelope["retrieval"]["corpus"]["name"] == "banking-policy-2026"
    assert envelope["retrieval"]["similarity_threshold"] == 0.55
    validator.validate(envelope)


def test_w2_2_retrieval_minimal_doc_validates(validator, signer):
    """Per-doc minimum is just `id` + `role`. Builder must emit a valid
    envelope even when all optional doc fields are None."""
    rctx = RetrievalContext(
        documents=[RetrievalDocument(id="doc-only", role="retrieved")],
    )
    envelope = build_envelope(
        ctx=_ctx(turn=3),
        previous_hash=GENESIS_HASH,
        signer=signer,
        server_version="0.1.0",
        retrieval=rctx,
    )
    assert envelope["retrieval"]["status"] == "active"
    assert envelope["retrieval"]["documents"][0]["id"] == "doc-only"
    assert "corpus" not in envelope["retrieval"]  # not provided → not emitted
    validator.validate(envelope)


def test_w2_2_invalid_document_role_rejected(validator, signer):
    """Schema enum on `role` enforced — typo/unknown role rejected."""
    rctx = RetrievalContext(
        documents=[RetrievalDocument(id="doc-bad", role="not_a_real_role")],
    )
    envelope = build_envelope(
        ctx=_ctx(turn=4),
        previous_hash=GENESIS_HASH,
        signer=signer,
        server_version="0.1.0",
        retrieval=rctx,
    )
    with pytest.raises(Exception):
        validator.validate(envelope)


def test_w2_2_similarity_threshold_out_of_range_rejected(validator, signer):
    """Schema enforces 0.0 ≤ similarity_threshold ≤ 1.0."""
    rctx = RetrievalContext(
        documents=[RetrievalDocument(id="d", role="admitted")],
        similarity_threshold=1.5,  # invalid
    )
    envelope = build_envelope(
        ctx=_ctx(turn=5),
        previous_hash=GENESIS_HASH,
        signer=signer,
        server_version="0.1.0",
        retrieval=rctx,
    )
    with pytest.raises(Exception):
        validator.validate(envelope)


def test_w2_2_chain_verifies_with_retrieval_blocks(signer, store):
    """A multi-turn chain where some turns carry retrieval blocks and
    others don't must still verify end-to-end. Retrieval is additive;
    the hash chain doesn't care which optional blocks are present."""
    rctx = RetrievalContext(
        documents=[RetrievalDocument(id="d1", role="cited", score=0.8)],
        corpus_name="test-corpus",
    )
    e1 = build_envelope(
        ctx=_ctx(turn=1),
        previous_hash=GENESIS_HASH,
        signer=signer,
        server_version="0.1.0",
    )
    store.append("t-abc", e1)
    e2 = build_envelope(
        ctx=_ctx(turn=2),
        previous_hash=store.head("t-abc"),
        signer=signer,
        server_version="0.1.0",
        retrieval=rctx,
    )
    store.append("t-abc", e2)
    e3 = build_envelope(
        ctx=_ctx(turn=3),
        previous_hash=store.head("t-abc"),
        signer=signer,
        server_version="0.1.0",
    )
    store.append("t-abc", e3)

    chain = list(store.iter_chain("t-abc"))
    assert len(chain) == 3
    result = verify_chain(chain)
    assert result["valid"] is True
    assert result["checked"] == 3
    # The middle envelope carries retrieval; verify it's there
    assert "retrieval" in chain[1]
    assert "retrieval" not in chain[0]
    assert "retrieval" not in chain[2]
