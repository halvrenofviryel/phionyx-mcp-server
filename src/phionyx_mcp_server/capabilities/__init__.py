"""F1 MCP trust boundary 8-capability surface.

Modules:

    user_approval     — Capability 5: consent capture + audit
    permission_scope  — Capability 3: tool permission scope enforcement
    anomaly_flag      — Capability 6: runtime anomaly (Core bridge)

Capabilities 1, 2, 4, 7, 8 live one level up in the package:

    descriptor_hash.py  — Capabilities 1 + 2
    audit_chain.py      — Capabilities 4 + 7
    cli.py              — Capability 8
"""
from __future__ import annotations

__all__: list[str] = []
