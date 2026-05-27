# phionyx-mcp-server

> MCP trust boundary governance layer — descriptor signing, runtime guardrail, tamper-evident audit chain for MCP-capable hosts.

A public companion package that closes the security gap the MCP specification ([2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)) explicitly defers to implementors:

> *"MCP itself cannot enforce these security principles at the protocol level, implementors SHOULD..."*

`phionyx-mcp-server` sits between an MCP-capable host (Claude Desktop, Cursor, Zed, VS Code, JetBrains) and any third-party MCP server it talks to, producing tamper-evident evidence at every trust-boundary crossing.

Threat surface aligned with **arXiv:[2512.06556](https://arxiv.org/abs/2512.06556)** (Jamshidi et al., *Securing the Model Context Protocol*) — tool poisoning, shadowing, rug pulls. See [`specs/threats.md`](specs/threats.md) for the per-class mitigation mapping.

## Status

**v0.1.0.** 5 of 8 capabilities fully implemented; 3 stubbed; the 2 load-bearing ones (descriptor verify + tool call audit) are live. Shared-trace contract with the companion [`phionyx-pipeline-mcp`](https://github.com/halvrenofviryel/phionyx-pipeline-mcp) is implemented and tested. Published on PyPI 2026-05-23 (`pip install phionyx-mcp-server`).

| # | Capability | Status |
|---|---|---|
| 1 | Tool descriptor hash | ✅ implemented (`descriptor_hash.py`) |
| 2 | Descriptor change detection | ✅ implemented (`descriptor_hash.compare_descriptor_hashes`) |
| 3 | Tool permission scope | 🟡 envelope field populated; policy logic stub |
| 4 | Tool call I/O hash | ✅ implemented (`audit_chain.build_envelope`) |
| 5 | User approval state | 🟡 envelope field populated; UX surface stub |
| 6 | Runtime anomaly flag | 🟡 envelope field populated; behavioral-drift bridge stub |
| 7 | Signed evidence envelope | ✅ implemented (`audit_chain` + RGE v0.2) |
| 8 | Chain verification command | ✅ implemented (`phionyx-mcp verify-chain` CLI) |
| — | Shared-trace contract | ✅ implemented (`trace.py`) |

## Install

```bash
pip install phionyx-mcp-server

# Verify CLI:
phionyx-mcp --help
```

Or from source (development):

```bash
git clone https://github.com/halvrenofviryel/phionyx-mcp-server.git
cd phionyx-mcp-server
pip install -e .
```

## Use — as an MCP server

Add to your MCP-capable host (Claude Desktop config example):

```json
{
  "mcpServers": {
    "phionyx-governance": {
      "command": "phionyx-mcp-server"
    }
  }
}
```

The host then sees four production MCP tools:

- `verify_tool_descriptor(descriptor, baseline_hash)` — hash + compare against approved baseline (full descriptor including `protocolVersion`).
- `record_tool_call(turn_index, user_text, producer, ..., trace_id=None)` — emit signed RGE v0.2 envelope. `trace_id` defaults to the active trace (env var or `~/.phionyx/active_trace`).
- `verify_chain_integrity(trace_id=None)` — walk the chain, refuse mixed schemas.
- `query_audit_history(trace_id=None, limit=50)` — replay envelopes for review.

Plus three stub tools that return structured `not_implemented` markers (callers can detect server maturity).

## Use — as a CLI (Capability 8)

```bash
# Print current chain head for a trace:
phionyx-mcp head --trace trace-abc123

# Walk + verify a chain:
phionyx-mcp verify-chain --trace trace-abc123

# Show one envelope:
phionyx-mcp show --trace trace-abc123 --turn 7
```

CLI exits 0 on valid chains, 1 on tamper/break, 2 on invocation error.

## Persistence

Envelopes are written under `$PHIONYX_MCP_AUDIT_ROOT` (default `~/.phionyx/mcp_audit/`):

```
<root>/<trace_id>/chain.jsonl       (append-only index: turn, current, previous, envelope_path)
<root>/<trace_id>/<turn:06d>.json   (full canonical-JSON envelope)
```

Swap the persistence layer by passing an alternative `EnvelopeStore`-protocol implementation.

## Where this fits on phionyx.ai

This package surfaces under [**phionyx.ai/bounded-authority**](https://phionyx.ai/bounded-authority) — the safety-first AI providers entry. It is the outward-facing MCP trust boundary that turns each third-party tool call into signed, replayable governance evidence.

## Companion packages

`phionyx-mcp-server` is the **outward-facing** layer: it sees the host calling a third-party MCP server and signs evidence of that call. Four siblings extend the runtime into adjacent layers:

- [`phionyx-pipeline-mcp`](https://github.com/halvrenofviryel/phionyx-pipeline-mcp) — *inward-facing MCP layer.* Gates the AI agent's own *"I fixed this / I tested that / this code path changed"* declarations against `git diff` truth and a deterministic physics gate.
- [`phionyx-eval-inspect`](https://github.com/halvrenofviryel/phionyx-eval-inspect) — *Inspect AI bridge.* Convert a Phionyx envelope chain into an Inspect `.eval` log. Interop-only; no UK AISI endorsement claim.
- [`phionyx-langchain-langgraph`](https://github.com/halvrenofviryel/phionyx-langchain-langgraph) — *LangChain + LangGraph adapters (v0.5.0+, alpha).* Every chain / tool / LLM event + supervisor handoff becomes a signed envelope.
- [`phionyx-openai-agents`](https://github.com/halvrenofviryel/phionyx-openai-agents) — *OpenAI Agents SDK tracing bridge (v0.5.0+, alpha).* Every Trace and Span becomes a signed envelope.

When `phionyx-mcp-server` + `phionyx-pipeline-mcp` are installed and registered with a Claude Code host, they agree on a single `trace_id` per session via `PHIONYX_TRACE_ID` (with `~/.phionyx/active_trace` fallback). One Claude Code conversation = one trace = end-to-end view of every third-party tool call AND every agent self-claim gate decision. The Inspect bridge and the framework adapters consume envelopes off-host; they don't need to share the live trace.

The MCP-pair contract: both packages read `PHIONYX_TRACE_ID` first, then `PHIONYX_ACTIVE_TRACE_FILE` (default `~/.phionyx/active_trace`); the first caller persists a generated UUID. `pipeline-mcp` reads this server's envelope chain via the public `FilesystemEnvelopeStore` + `verify_chain` API (read-only — no cross-package write coupling).

## Schema

Envelopes conform to **RGE v0.2**:

- [`specs/rge_v0_2/rge_v0_2.schema.json`](specs/rge_v0_2/rge_v0_2.schema.json) — Draft 2020-12 canonical schema.
- [`specs/rge_v0_2/rge_v0_2.md`](specs/rge_v0_2/rge_v0_2.md) — RFC (motivation, design, security considerations, alternatives).
- [`specs/rge_v0_2/rge_v0_2_examples.md`](specs/rge_v0_2/rge_v0_2_examples.md) — worked walkthroughs.
- [`specs/rge_v0_2/migration_v0_1_to_v0_2.md`](specs/rge_v0_2/migration_v0_1_to_v0_2.md) — compatibility matrix.

`integrity.signature` covers all envelope content **except** `mcp_tool_audit.signed_envelope_ref` (self-referential — RFC §4.1).

## Threat coverage

See [`specs/threats.md`](specs/threats.md) for the Jamshidi et al. taxonomy mapped to capability-by-capability mitigation surface.

## Tests

```bash
pip install -e ".[test]"
pytest tests/ -q
# 22 passed
```

Tests pin:

- Descriptor hash semantics (full descriptor including `protocolVersion`).
- RGE v0.2 schema conformance (jsonschema Draft 2020-12).
- Hash chain integrity (tamper, reorder, mixed-schema detection).

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).

## See also

- [phionyx.ai/bounded-authority](https://phionyx.ai/bounded-authority) — entry pillar this package surfaces under
- [phionyx.ai/evidence](https://phionyx.ai/evidence) — Evidence Matrix: every load-bearing claim paired with a reviewer-runnable command
- Project hub: [github.com/halvrenofviryel/phionyx-research](https://github.com/halvrenofviryel/phionyx-research)
- Phionyx Core SDK (PyPI): [`phionyx-core`](https://pypi.org/project/phionyx-core/)
- All five companion packages — see the [Companion packages](#companion-packages) section above
