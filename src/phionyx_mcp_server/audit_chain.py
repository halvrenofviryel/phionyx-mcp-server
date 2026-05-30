"""Audit chain — RGE v0.2 envelope emission + chain continuity.

Produces Reasoned Governance Envelope v0.2 envelopes that conform to
``examples/envelopes/rge_v0_2/rge_v0_2.schema.json``. The
``mcp_tool_audit`` block is populated (Capability 7: signed evidence
envelope) and the integrity hash chain is maintained turn-to-turn
(Capability 8 prerequisites).

Persistence is filesystem-backed for v0.4.0 MVP — one JSON file per
envelope under ``~/.phionyx/mcp_audit/<trace_id>/<turn_index>.json``,
with a per-trace ``chain.jsonl`` index. Production deployments can
swap the persistence layer via the ``EnvelopeStore`` protocol.

Hash-domain discipline
----------------------

``mcp_tool_audit.signed_envelope_ref`` is a self-reference
(``envelope://<integrity.current>``) — it would create a hash-fixpoint
paradox if included in the hashed payload. It is therefore EXCLUDED
from the hash domain: builder + verifier both treat it as ``None``
when hashing. The field is preserved in the persisted envelope so
external consumers can resolve it directly, but it is NOT covered by
``integrity.signature``. This is documented in
``examples/envelopes/rge_v0_2/rge_v0_2.md`` §4.1 (signature scope).
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

from .descriptor_hash import canonical_json


GENESIS_HASH = "sha256:" + "0" * 64
RGE_SCHEMA = "phionyx.governed_response_envelope.v0_2"
RUNTIME = "phionyx-mcp-server"


def envelope_hash(payload: dict[str, Any], previous_hash: str) -> str:
    """Compute SHA-256 over canonical JSON of ``payload`` + previous hash.

    Matches the wrapper convention: the hashed object is
    ``{"record": payload, "previous": previous_hash}``. Result is the
    full 64-hex digest (the launch wrapper truncated to 16 hex for
    demo legibility; Core uses the full digest).

    NOTE: callers SHOULD use :func:`payload_for_hash` to normalise the
    self-referential ``mcp_tool_audit.signed_envelope_ref`` field
    before passing to this function. Otherwise the hash and the
    persisted envelope will diverge.
    """
    blob = canonical_json({"record": payload, "previous": previous_hash})
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def payload_for_hash(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``payload`` with self-referential fields nulled.

    Currently only ``mcp_tool_audit.signed_envelope_ref`` is
    self-referential. Both the builder and the verifier must call this
    before hashing so their views agree.
    """
    p = copy.deepcopy(payload)
    block = p.get("mcp_tool_audit")
    if isinstance(block, dict) and "signed_envelope_ref" in block:
        block["signed_envelope_ref"] = None
    return p


@dataclass(frozen=True)
class ToolCallContext:
    """The minimum a host must surface for a v0.2-compliant MCP audit envelope."""

    trace_id: str
    turn_index: int
    user_text: str
    producer: str  # e.g. "claude-desktop.mcp.github_server"
    tool_descriptor_hash: str | None  # capability 1
    descriptor_change_detected: bool | None  # capability 2
    tool_permission_scope: list[str] | None  # capability 3
    input_hash: str | None  # capability 4 (paired with output_hash)
    output_hash: str | None  # capability 4
    approval_state: dict[str, Any] | None  # capability 5
    anomaly_flag: dict[str, Any] | None  # capability 6
    decision: str  # "release" | "block" | "defer" | "redact"
    decision_reason: str
    runtime_policy_basis: list[str]


# ── v0.7.0 W2.2 (F8) — RAG retrieval audit ─────────────────────────────


@dataclass(frozen=True)
class RetrievalDocument:
    """One document in a RAG retrieval audit chain.

    Maps 1:1 to the per-document object inside `retrieval.documents[]` in
    the RGE v0.2 schema. `id` and `role` are required; the rest are
    optional and surface only when the producer tracks them.
    """

    id: str
    role: str  # retrieved | admitted | cited | contradicted | rejected
    score: float | None = None
    hash: str | None = None
    signed_evidence_ref: str | None = None
    chunk_offset: int | None = None  # v0.7.0 W2.2
    source_url: str | None = None  # v0.7.0 W2.2
    retrieved_at: str | None = None  # v0.7.0 W2.2 — ISO-8601 UTC

    def to_dict(self) -> dict[str, Any]:
        """Schema-compliant dict — only includes fields the schema permits.

        `hash` and `signed_evidence_ref` are skipped when None because the
        schema allows them but doesn't require null; the v0.2 schema's
        `additionalProperties=false` enforces no other keys. Mandatory
        fields (`id`, `role`) are always present.
        """
        d: dict[str, Any] = {"id": self.id, "role": self.role}
        # Schema permits null for these; emit explicitly so consumers can
        # distinguish "tracked but absent" from "not tracked at all".
        d["score"] = self.score
        if self.hash is not None:
            d["hash"] = self.hash
        d["signed_evidence_ref"] = self.signed_evidence_ref
        d["chunk_offset"] = self.chunk_offset
        d["source_url"] = self.source_url
        d["retrieved_at"] = self.retrieved_at
        return d


@dataclass(frozen=True)
class RetrievalContext:
    """The minimum a host must surface for an active retrieval audit block.

    `status='active'` is set implicitly when this context is passed to
    `build_envelope`. Producers that have not implemented retrieval audit
    can omit the kwarg entirely; the envelope will not carry a retrieval
    block and the schema will still validate.
    """

    documents: list[RetrievalDocument]
    store_id: str | None = None
    corpus_name: str | None = None  # v0.7.0 W2.2
    corpus_version: str | None = None
    corpus_language: str | None = None
    similarity_threshold: float | None = None  # v0.7.0 W2.2
    query_hash: str | None = None
    query_text_hash: str | None = None  # v0.7.0 W2.2


def build_retrieval_block(ctx: RetrievalContext) -> dict[str, Any]:
    """Build the v0.2 `retrieval` block dict from a RetrievalContext.

    Schema-conformant output ready to drop into envelope["retrieval"].
    Always emits `status="active"` because the caller has actual
    documents to record; `reserved-for-v0.4.1-f8` is the absent-block
    sentinel and is never produced by this builder.
    """
    block: dict[str, Any] = {
        "status": "active",
        "documents": [d.to_dict() for d in ctx.documents],
    }
    if ctx.store_id is not None:
        block["store_id"] = ctx.store_id
    if ctx.corpus_name is not None:
        corpus: dict[str, Any] = {"name": ctx.corpus_name}
        corpus["version"] = ctx.corpus_version
        corpus["language"] = ctx.corpus_language
        block["corpus"] = corpus
    block["similarity_threshold"] = ctx.similarity_threshold
    if ctx.query_hash is not None:
        block["query_hash"] = ctx.query_hash
    block["query_text_hash"] = ctx.query_text_hash
    return block


class EnvelopeStore(Protocol):
    """Pluggable persistence for envelopes + chain head per trace."""

    def head(self, trace_id: str) -> str: ...
    """Return integrity.current of the most recent envelope for ``trace_id``, or GENESIS_HASH."""

    def append(self, trace_id: str, envelope: dict[str, Any]) -> None: ...
    """Persist ``envelope`` and update the trace head atomically."""

    def iter_chain(self, trace_id: str) -> Iterable[dict[str, Any]]: ...
    """Yield envelopes for ``trace_id`` in turn-index order."""


class FilesystemEnvelopeStore:
    """Default filesystem-backed envelope store.

    Layout::

        <root>/<trace_id>/chain.jsonl       (turn_index, current_hash, path)
        <root>/<trace_id>/<turn_index>.json (full envelope)

    The ``chain.jsonl`` index is append-only; corrupted or truncated
    indices raise ``RuntimeError`` on read.
    """

    def __init__(self, root: Path | str | None = None) -> None:
        if root is None:
            root = Path(os.environ.get("PHIONYX_MCP_AUDIT_ROOT", "~/.phionyx/mcp_audit")).expanduser()
        self.root = Path(root)

    def _trace_dir(self, trace_id: str) -> Path:
        # trace_id is host-supplied; sanitize against path traversal.
        safe = trace_id.replace("/", "_").replace("..", "__")
        return self.root / safe

    def head(self, trace_id: str) -> str:
        chain = self._trace_dir(trace_id) / "chain.jsonl"
        if not chain.exists():
            return GENESIS_HASH
        # Chain files are O(turns); read all lines and take the last
        # non-empty one. Simpler than backward-walking and correct.
        with chain.open("r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        if not lines:
            return GENESIS_HASH
        try:
            entry = json.loads(lines[-1])
            return str(entry["current_hash"])
        except (json.JSONDecodeError, KeyError) as e:
            raise RuntimeError(f"corrupt chain index for trace {trace_id!r}: {e}") from e

    def append(self, trace_id: str, envelope: dict[str, Any]) -> None:
        td = self._trace_dir(trace_id)
        td.mkdir(parents=True, exist_ok=True)
        turn = int(envelope["subject"]["turn_index"])
        envelope_path = td / f"{turn:06d}.json"
        envelope_path.write_text(canonical_json(envelope), encoding="utf-8")
        index_entry = {
            "turn_index": turn,
            "current_hash": envelope["integrity"]["current"],
            "previous_hash": envelope["integrity"]["previous"],
            "envelope_path": str(envelope_path.relative_to(self.root)),
        }
        with (td / "chain.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(index_entry, sort_keys=True) + "\n")

    def iter_chain(self, trace_id: str) -> Iterable[dict[str, Any]]:
        chain = self._trace_dir(trace_id) / "chain.jsonl"
        if not chain.exists():
            return
        with chain.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                envelope_path = self.root / entry["envelope_path"]
                yield json.loads(envelope_path.read_text(encoding="utf-8"))


def build_envelope(
    ctx: ToolCallContext,
    *,
    previous_hash: str,
    server_version: str,
    signer: "Signer",
    retrieval: RetrievalContext | None = None,
) -> dict[str, Any]:
    """Build a v0.2 RGE envelope with the ``mcp_tool_audit`` block populated.

    ``previous_hash`` is the chain head for ``ctx.trace_id``. ``signer``
    produces the ``integrity.signature`` (Ed25519 in production, HMAC
    in demo mode).

    Optional ``retrieval`` (v0.7.0 W2.2, F8): when provided, populates
    the v0.2 ``retrieval`` block with ``status='active'`` and the
    documents/corpus/threshold metadata from the RetrievalContext.
    Omitting the kwarg keeps backward-compat — the envelope simply has
    no retrieval block (schema-valid because the block is optional).
    """
    path_steps = [
        {"block": "input_safety_gate", "disposition": "admit", "reason": None},
        {
            "block": "mcp_tool_descriptor_verify",
            "disposition": "admit" if not (ctx.descriptor_change_detected or False) else "block",
            "reason": (
                "descriptor hash matches user-approved baseline"
                if not (ctx.descriptor_change_detected or False)
                else "descriptor change detected — re-approval required"
            ),
        },
        {
            "block": "action_intent_gate",
            "disposition": "admit",
            "reason": f"scope: {ctx.tool_permission_scope}" if ctx.tool_permission_scope else None,
        },
        {"block": "audit_layer", "disposition": "record"},
    ]

    mcp_tool_audit = {
        "status": "active",
        "tool_descriptor_hash": ctx.tool_descriptor_hash,
        "descriptor_change_detected": ctx.descriptor_change_detected,
        "tool_permission_scope": ctx.tool_permission_scope,
        "tool_call_io_hash": (
            {"input_hash": ctx.input_hash, "output_hash": ctx.output_hash}
            if ctx.input_hash and ctx.output_hash
            else None
        ),
        "user_approval_state": ctx.approval_state,
        "runtime_anomaly_flag": ctx.anomaly_flag,
        # signed_envelope_ref is filled below once we know our own hash.
        "signed_envelope_ref": None,
        "chain_verify_command": (
            f"phionyx-mcp verify-chain --trace {ctx.trace_id} --turn {ctx.turn_index}"
        ),
    }

    payload: dict[str, Any] = {
        "schema": RGE_SCHEMA,
        "subject": {
            "runtime": RUNTIME,
            "version": server_version,
            "producer": ctx.producer,
            "turn_index": ctx.turn_index,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        },
        "input": {
            "user_text": ctx.user_text,
            "state_vector": {
                "valence": 0.0,
                "arousal": 0.5,
                "stability": 0.85,
                "entropy": 0.2,
                "time_delta": 0.1,
                "amplitude": 5.0,
                "context_profile": "STRICT_GOVERNANCE",
                "gamma": 0.15,
            },
            "safety": {"allowed": True, "reason": None},
        },
        "path": path_steps,
        "output": {"redacted": ctx.decision != "release", "text": None},
        "metrics": {
            "phi_cognitive": 0.5,
            "phi_physical": 0.5,
            "phi_total": 0.5,
            "cognitive_verdict": "coherent",
        },
        "reasoning": {
            "model_proposed_action": None,
            "model_stated_rationale": None,
            "runtime_policy_basis": ctx.runtime_policy_basis,
            "runtime_decision": ctx.decision,
            "decision_reason": ctx.decision_reason,
            "rationale_action_consistency": None,
            "policy_alignment_score": None,
            "confidence_delta": None,
            "evidence_links": [],
            "scoring_method": f"{RUNTIME}.v{server_version}.placeholder",
            # v0.7.0 W2.1 (F4) — reasoning surface extension. Default
            # null/empty so envelopes from producers that do not surface
            # reasoning metadata stay valid; producers that do surface it
            # populate via the BuildEnvelopeContext extension or by
            # post-processing the dict before signing.
            "rationale_summary": None,
            "knowledge_sources_consulted": [],
            "constraints_acknowledged": [],
        },
        "mcp_tool_audit": mcp_tool_audit,
    }

    # v0.7.0 W2.2 (F8) — populate optional retrieval block when the
    # producer surfaced retrieval evidence for this turn. Block is
    # opt-in: builder callers without RAG evidence omit the kwarg and
    # the envelope simply has no `retrieval` key (schema permits absence).
    if retrieval is not None:
        payload["retrieval"] = build_retrieval_block(retrieval)

    # Compute hash with signed_envelope_ref normalised to None (self-
    # referential field is OUTSIDE the hash domain — see module docstring).
    current_hash = envelope_hash(payload_for_hash(payload), previous_hash)

    # NOW populate the self-reference. Persisted alongside the
    # envelope; resolvable by external consumers; not signature-covered.
    payload["mcp_tool_audit"]["signed_envelope_ref"] = f"envelope://{current_hash}"

    payload["integrity"] = {
        "previous": previous_hash,
        "current": current_hash,
        "signature": signer.sign(current_hash),
        "canonical_json": True,
    }
    return payload


class Signer(Protocol):
    """Minimal signer surface so the envelope builder can stay backend-agnostic."""

    def sign(self, current_hash: str) -> str: ...


class HmacSigner:
    """Demo signer (HMAC over current_hash). Production uses Ed25519."""

    def __init__(self, secret: str = "phionyx.demo.replace.in.production") -> None:
        self._secret = secret.encode("utf-8")

    def sign(self, current_hash: str) -> str:
        digest = hashlib.sha256(current_hash.encode("utf-8") + self._secret).hexdigest()
        return f"demo-hmac:{digest[:16]}"


def verify_chain(envelopes: list[dict[str, Any]]) -> dict[str, Any]:
    """Walk a chain of envelopes and verify integrity.

    Returns ``{"valid": bool, "checked": int, "broken_at": int | None, "reason": str | None}``.

    Refuses to walk across schema boundaries (per RGE v0.2 migration
    doc §5.3 — mixed-schema chains break by design).
    """
    if not envelopes:
        return {"valid": True, "checked": 0, "broken_at": None, "reason": None}

    schemas = {e.get("schema", "<missing>") for e in envelopes}
    if len(schemas) > 1:
        return {
            "valid": False,
            "checked": 0,
            "broken_at": 0,
            "reason": f"mixed schemas in chain: {schemas}",
        }

    expected_previous = GENESIS_HASH
    for i, env in enumerate(envelopes):
        try:
            integrity = env["integrity"]
            previous = integrity["previous"]
            current = integrity["current"]
        except KeyError as e:
            return {"valid": False, "checked": i, "broken_at": i, "reason": f"missing field: {e}"}

        if previous != expected_previous:
            return {
                "valid": False,
                "checked": i,
                "broken_at": i,
                "reason": (
                    f"previous hash mismatch at turn {env.get('subject', {}).get('turn_index')}: "
                    f"expected {expected_previous}, got {previous}"
                ),
            }

        # Recompute current from the envelope content (excluding the integrity block
        # itself and normalising the self-referential signed_envelope_ref to None).
        payload = {k: v for k, v in env.items() if k != "integrity"}
        recomputed = envelope_hash(payload_for_hash(payload), previous)
        if recomputed != current:
            return {
                "valid": False,
                "checked": i,
                "broken_at": i,
                "reason": (
                    f"content hash mismatch at turn {env.get('subject', {}).get('turn_index')}: "
                    f"recomputed {recomputed}, stored {current}"
                ),
            }

        expected_previous = current

    return {"valid": True, "checked": len(envelopes), "broken_at": None, "reason": None}
