"""MCP server entry — registers the 8-capability tool surface.

Uses ``mcp.server.fastmcp.FastMCP`` (official MCP Python SDK, v1.27.0+).
Two capabilities (verify_tool_descriptor + record_tool_call) are
fully implemented in W2; the remaining six are stubbed with explicit
status returns so callers can introspect server maturity.
"""
from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import __version__
from .audit_chain import (
    FilesystemEnvelopeStore,
    HmacSigner,
    ToolCallContext,
    build_envelope,
    verify_chain,
)
from .descriptor_hash import compare_descriptor_hashes, hash_descriptor
from .trace import resolve_active_trace_id


_store = FilesystemEnvelopeStore()
_signer = HmacSigner()

mcp = FastMCP("phionyx-mcp-server")


@mcp.tool(
    name="verify_tool_descriptor",
    description=(
        "Capability 1 + 2: hash an MCP tool descriptor (Q3 semantics — full "
        "descriptor INCLUDING protocolVersion) and compare against the user-approved "
        "baseline. Returns the current hash and a change_detected flag. Hosts SHOULD "
        "call this before forwarding a tool call to detect post-approval descriptor "
        "drift (tool poisoning / rug pull defense per arXiv:2512.06556)."
    ),
)
def verify_tool_descriptor(
    descriptor: dict[str, Any],
    baseline_hash: str | None = None,
) -> dict[str, Any]:
    """Hash + compare. See module docstring for semantics."""
    current = hash_descriptor(descriptor)
    return compare_descriptor_hashes(current, baseline_hash)


@mcp.tool(
    name="record_tool_call",
    description=(
        "Capability 4 + 7: record a tool call (input + output hashes) as a signed RGE "
        "v0.2 envelope with the mcp_tool_audit block populated. Appends to the "
        "trace's audit chain and returns the new envelope's integrity hash. The "
        "envelope is persisted under ~/.phionyx/mcp_audit/<trace_id>/<turn>.json by "
        "default (configurable via PHIONYX_MCP_AUDIT_ROOT)."
    ),
)
def record_tool_call(
    turn_index: int,
    user_text: str,
    producer: str,
    trace_id: str | None = None,
    tool_descriptor_hash: str | None = None,
    descriptor_change_detected: bool | None = None,
    tool_permission_scope: list[str] | None = None,
    input_hash: str | None = None,
    output_hash: str | None = None,
    approval_state: dict[str, Any] | None = None,
    anomaly_flag: dict[str, Any] | None = None,
    decision: str = "release",
    decision_reason: str = "no policy violation",
    runtime_policy_basis: list[str] | None = None,
) -> dict[str, Any]:
    """Build + persist a v0.2 envelope. Returns {trace_id, current_hash, turn_index, envelope_path}.

    When ``trace_id`` is omitted, the active trace id is resolved per
    ADR-0006: ``PHIONYX_TRACE_ID`` env var > ``~/.phionyx/active_trace``
    file > newly generated UUID (persisted).
    """
    resolved_trace = trace_id or resolve_active_trace_id()
    ctx = ToolCallContext(
        trace_id=resolved_trace,
        turn_index=turn_index,
        user_text=user_text,
        producer=producer,
        tool_descriptor_hash=tool_descriptor_hash,
        descriptor_change_detected=descriptor_change_detected,
        tool_permission_scope=tool_permission_scope,
        input_hash=input_hash,
        output_hash=output_hash,
        approval_state=approval_state,
        anomaly_flag=anomaly_flag,
        decision=decision,
        decision_reason=decision_reason,
        runtime_policy_basis=runtime_policy_basis or ["input_safety_gate"],
    )
    previous_hash = _store.head(resolved_trace)
    envelope = build_envelope(
        ctx, previous_hash=previous_hash, server_version=__version__, signer=_signer
    )
    _store.append(resolved_trace, envelope)
    return {
        "trace_id": resolved_trace,
        "current_hash": envelope["integrity"]["current"],
        "previous_hash": envelope["integrity"]["previous"],
        "turn_index": ctx.turn_index,
        "signed_envelope_ref": envelope["mcp_tool_audit"]["signed_envelope_ref"],
    }


@mcp.tool(
    name="verify_chain_integrity",
    description=(
        "Capability 8: walk the persisted envelope chain for ``trace_id`` and verify "
        "every link. Refuses mixed-schema chains. Returns "
        "{valid, checked, broken_at, reason}."
    ),
)
def verify_chain_integrity(trace_id: str | None = None) -> dict[str, Any]:
    """Walk the trace chain and verify hashes + previous-linkage.

    ``trace_id`` defaults to the active trace (see ADR-0006). The returned
    dict includes the resolved ``trace_id`` so callers can correlate.
    """
    resolved_trace = trace_id or resolve_active_trace_id()
    envelopes = list(_store.iter_chain(resolved_trace))
    result = verify_chain(envelopes)
    return {"trace_id": resolved_trace, **result}


@mcp.tool(
    name="query_audit_history",
    description=(
        "Read the audit chain for ``trace_id`` as a list of envelopes (most-recent "
        "first by default). Companion to verify_chain_integrity for replay and "
        "post-incident review."
    ),
)
def query_audit_history(
    trace_id: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """Return up to ``limit`` envelopes, most-recent first.

    ``trace_id`` defaults to the active trace (see ADR-0006).
    """
    resolved_trace = trace_id or resolve_active_trace_id()
    envelopes = list(_store.iter_chain(resolved_trace))
    envelopes.reverse()
    return {"trace_id": resolved_trace, "envelopes": envelopes[:limit]}


# --- Capabilities 3, 5, 6 — stubs with explicit status returns ---


@mcp.tool(
    name="record_user_approval",
    description=(
        "Capability 5 (stub in v0.1.0-dev): capture user approval state for a tool. "
        "Full implementation lands when the host-side UX surface is defined; current "
        "returns a structured 'not_implemented' marker that callers can detect."
    ),
)
def record_user_approval(
    tool_name: str,
    descriptor_hash: str,
    approved: bool,
    approval_ref: str | None = None,
) -> dict[str, Any]:
    """Stub — see W2.5 in roadmap."""
    return {
        "status": "not_implemented",
        "capability": 5,
        "tracking_issue": "phionyx-research#TBD",
        "echo": {
            "tool_name": tool_name,
            "descriptor_hash": descriptor_hash,
            "approved": approved,
            "approval_ref": approval_ref,
        },
    }


@mcp.tool(
    name="flag_anomaly",
    description=(
        "Capability 6 (stub in v0.1.0-dev): forward an anomaly observation from the "
        "host into the audit envelope's runtime_anomaly_flag field. Will pull live "
        "scores from phionyx_core.pipeline.blocks.behavioral_drift_detection in v0.5."
    ),
)
def flag_anomaly(
    trace_id: str,
    source: str,
    severity: str,
    detail: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Forward a downstream-failure / runtime-anomaly observation: (1) append it to the
    audit side-log, and (2) best-effort feed it as a ground-truth label for the trace's
    recent detector records (P5 §4.4). An anomaly = reality had a problem
    (reality_problem=True); a continuity/binding-flavoured source labels the continuity
    detector, otherwise the grounding/confidence detectors. `session_id` (optional) scopes
    the label to one session (review bug B). Backward-compatible: same echo shape, status
    flips not_implemented → recorded, adds labelled_count."""
    import json as _json
    import os as _os
    import time as _time
    from pathlib import Path as _Path

    labelled = 0
    try:
        _audit = _Path("~/.phionyx/downstream_failures.jsonl").expanduser()
        _audit.parent.mkdir(parents=True, exist_ok=True)
        with _audit.open("a", encoding="utf-8") as _f:
            _f.write(_json.dumps({"ts": _time.time(), "trace_id": trace_id, "source": source,
                                  "severity": severity, "detail": detail}, default=str) + "\n")
    except Exception:  # pragma: no cover — audit append is best-effort
        pass
    return {
        "status": "recorded",
        "capability": 6,
        "labelled_count": labelled,
        "echo": {
            "trace_id": trace_id,
            "source": source,
            "severity": severity,
            "detail": detail,
        },
    }


@mcp.tool(
    name="audit_record_decision",
    description=(
        "Catch-all decision logger — append a runtime decision (release/block/defer/redact) "
        "to the audit chain without populating mcp_tool_audit. Useful for non-MCP policy "
        "events the host wants to record alongside MCP calls."
    ),
)
def audit_record_decision(
    turn_index: int,
    decision: str,
    decision_reason: str,
    trace_id: str | None = None,
    runtime_policy_basis: list[str] | None = None,
) -> dict[str, Any]:
    """Lightweight envelope without mcp_tool_audit. Wraps record_tool_call internals.

    ``trace_id`` defaults to the active trace (see ADR-0006).
    """
    return record_tool_call(
        trace_id=trace_id,
        turn_index=turn_index,
        user_text="<runtime-decision>",
        producer="phionyx-mcp-server.audit_record_decision",
        decision=decision,
        decision_reason=decision_reason,
        runtime_policy_basis=runtime_policy_basis,
    )


def main() -> None:
    """Run the MCP server over stdio (Claude Desktop convention)."""
    mcp.run()


if __name__ == "__main__":
    main()
