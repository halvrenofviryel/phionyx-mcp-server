"""Phionyx MCP trust boundary governance layer.

Public companion package for MCP-capable hosts (Claude Desktop, Cursor,
Zed, VS Code, JetBrains, ...). Provides eight capabilities that, taken
together, close the security gap the MCP specification 2025-11-25
explicitly defers to implementors:

    "MCP itself cannot enforce these security principles at the
     protocol level, implementors SHOULD..."

The eight MVP capabilities (Phionyx Feature F1, v0.4.0 hot lane W2):

    1. Tool descriptor hash       (Ed25519-signed snapshot)
    2. Descriptor change detection (post-approval rug-pull defense)
    3. Tool permission scope       (capability profile per-tool)
    4. Tool call I/O hash          (per-call signed evidence)
    5. User approval state         (consent capture + audit)
    6. Runtime anomaly flag        (behavioral_drift + action_intent_gate)
    7. Signed evidence envelope    (RGE v0.2 mcp_tool_audit block)
    8. Chain verification command  (phionyx-mcp verify-chain CLI)

Evidence is persisted as Reasoned Governance Envelope (RGE) v0.2
envelopes; see ``examples/envelopes/rge_v0_2/`` in the phionyx-research
repo for the schema and the RFC.

Threat model: arXiv:2512.06556 (Jamshidi et al., "Securing the Model
Context Protocol") three-class taxonomy — Tool Poisoning, Shadowing,
Rug Pulls. See ``docs/security/mcp_threats.md`` for the per-class
mitigation mapping.
"""
from __future__ import annotations

__version__ = "0.2.0"
__all__ = ["__version__"]
