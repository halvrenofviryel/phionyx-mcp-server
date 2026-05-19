# MCP Trust Boundary Threats — Phionyx Mitigation Surface

> Companion document to `phionyx-mcp-server` (F1 v0.4.0). Maps the
> [arXiv:2512.06556](https://arxiv.org/abs/2512.06556) (Jamshidi et al.,
> *Securing the Model Context Protocol*) three-class threat taxonomy
> onto the Phionyx mitigation surface, capability-by-capability.
> Last verified: 2026-05-19.

## 1. Spec-Level Context

The Model Context Protocol specification ([2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)) is explicit about its scope limit:

> *"MCP itself cannot enforce these security principles at the protocol level, implementors SHOULD:*
> - *Build robust consent and authorization flows into their applications,*
> - *Provide clear documentation of security implications,*
> - *Implement appropriate access controls and data protections,*
> - *Follow security best practices in their integrations,*
> - *Consider privacy implications in their feature designs."*

The protocol leaves trust enforcement to *implementors*. `phionyx-mcp-server` is an implementor: it sits between the MCP host (Claude Desktop, Cursor, Zed, VS Code, JetBrains) and the MCP server it is talking to, producing tamper-evident evidence at every trust-boundary crossing.

## 2. Jamshidi et al. Threat Taxonomy

The paper identifies three classes of semantic attacks against MCP-integrated systems. Each row in this table maps a threat class to the Phionyx capability (1-8) that addresses it and the RGE v0.2 envelope field that records the evidence.

| Threat class | Attack mechanism | Phionyx capability | RGE v0.2 field | Mitigation discipline |
|---|---|---|---|---|
| **Tool Poisoning** | Adversarial instructions hidden inside the tool descriptor itself (e.g. a `description` field that re-targets the LLM's behaviour). | **#1** Tool descriptor hash | `mcp_tool_audit.tool_descriptor_hash` | Compute SHA-256 over canonical-JSON of the FULL descriptor (including `protocolVersion` — Q3, 2026-05-19) at first observation. Persist alongside user approval. Any subsequent descriptor whose hash differs is a NEW trust object that requires fresh approval. |
| **Tool Poisoning (latent)** | Adversarial content present at first observation; user approves without noticing. | **#5** User approval state + **#6** Runtime anomaly flag | `mcp_tool_audit.user_approval_state`, `mcp_tool_audit.runtime_anomaly_flag` | Phionyx does NOT claim to detect content the user approved. The capability is *evidence-of-approval* — the user is on the record approving descriptor hash `X` at time `T`. If `X` is later shown to be malicious, the audit chain identifies blast radius. Complementary defense: arXiv:2512.06556 proposes LLM-on-LLM semantic vetting; Phionyx leaves that to upstream tooling. |
| **Shadowing** | Trusted tool's runtime behaviour shifted by contaminated shared context (e.g. earlier turn injected adversarial instructions; trusted tool then acts on them). | **#6** Runtime anomaly flag (behavioral_drift + action_intent_gate) | `mcp_tool_audit.runtime_anomaly_flag` | Phionyx pipeline blocks `behavioral_drift_detection` (block #23) and `action_intent_gate` observe runtime divergence from baseline. When anomaly score exceeds threshold, `runtime_anomaly_flag.anomaly = true` and `severity` ∈ {warn, block}. The envelope chain shows precisely when the shadowing took effect. |
| **Shadowing (preventive)** | Context contamination at admission time. | **#3** Tool permission scope | `mcp_tool_audit.tool_permission_scope` | Each tool is bound to a Capability Profile (`phionyx_core.profiles`); shared context cannot escalate a tool beyond its declared scope. A read-only tool stays read-only no matter what the upstream context says. |
| **Rug Pulls** | Descriptor altered AFTER user approval; tool now does something different than what was approved. | **#2** Descriptor change detection | `mcp_tool_audit.descriptor_change_detected` | At every call, compare current descriptor hash against the approved-baseline hash. `descriptor_change_detected = true` flips the action to `block` and requires re-approval. The baseline hash is anchored by `user_approval_state.approved_at_utc` — temporal evidence of when the trust was established. |
| **Rug Pulls (silent retry)** | Adversary keeps mutating descriptor; user approves new version each time. | **#7** Signed evidence envelope + **#8** Chain verification | `mcp_tool_audit.signed_envelope_ref`, `integrity.*`, `phionyx-mcp verify-chain` | Every approval is its own envelope in the audit chain. Chain replay shows the *pattern* of repeated re-approvals, which is itself a detectable signal a human auditor can investigate. |

## 3. Capability-by-Capability Mitigation

For each of the 8 capabilities, what attack it stops and what attack it does NOT stop.

### #1 Tool descriptor hash

- **Stops:** content drift between first-observation and any subsequent call. *"The descriptor I see right now is the descriptor I approved."*
- **Does NOT stop:** approval of a malicious-at-first-observation descriptor. The user is still in the loop for that decision.
- **Q3 (2026-05-19) discipline:** hash the FULL descriptor including `protocolVersion`. Spec-version drift IS material because spec semantics can shift the meaning of identical-looking descriptors.

### #2 Descriptor change detection

- **Stops:** rug pulls (post-approval mutation). Trip-wire is a single boolean.
- **Does NOT stop:** descriptor mutation that the user approves anyway (re-approval fatigue). Defense: chain replay (capability #8) makes the pattern visible.

### #3 Tool permission scope

- **Stops:** capability escalation via context (shadowing). A read-only tool cannot become write-capable mid-session.
- **Does NOT stop:** scope creep at design time (over-broad scope declared upfront). Defense: capability profile review at server-add time (out of MVP scope).

### #4 Tool call input/output hash

- **Stops:** post-hoc denial. *"I did not call X with arguments Y."* The envelope's `tool_call_io_hash` is signed evidence.
- **Does NOT stop:** the call itself. This capability is *evidence*, not *enforcement*.

### #5 User approval state

- **Stops:** post-hoc denial of consent. *"I did not authorise this tool."*
- **Does NOT stop:** approval fatigue (user clicks "yes" without reading). Defense: capability #6 anomaly flag for behavior divergence from approval terms.

### #6 Runtime anomaly flag

- **Stops:** silent behaviour drift (shadowing, behavioural rug pulls). Anomaly source identifies which Phionyx gate raised the flag.
- **Does NOT stop:** zero-day behaviours below the detection threshold. Defense: chain replay + downstream LLM-on-LLM semantic vetting (out of MVP scope, arXiv:2512.06556 mitigation #2).

### #7 Signed evidence envelope

- **Stops:** tampering with the audit record itself. RGE v0.2 hash chain + signature is tamper-evident.
- **Does NOT stop:** evidence loss (envelope file deleted). Defense: external evidence store replication (out of MVP scope).

### #8 Chain verification command

- **Stops:** undetected chain corruption. The CLI walks the chain end-to-end and reports `valid` / `broken_at` / `reason`.
- **Does NOT stop:** chains that were never created (user disabled `phionyx-mcp-server`). Defense: enforce server presence via host configuration policy.

## 4. What Phionyx Does NOT Claim

Several attack classes are EXPLICITLY out of scope for `phionyx-mcp-server`:

1. **Semantic vetting of approved descriptors.** arXiv:2512.06556's mitigation #2 (LLM-on-LLM review) sits upstream. Phionyx records the descriptor's hash and the approval; it does not opine on whether the content is malicious. Hosts wanting this layer should run an LLM-based descriptor reviewer before invoking `verify_tool_descriptor`.
2. **Network-level transport security.** MCP transport (stdio, HTTP, sandbox) is the host's concern. Phionyx assumes the host's transport layer is intact; if not, the descriptor `phionyx-mcp-server` sees is already compromised and no capability protects against that.
3. **MCP server-side compromise.** If the MCP server itself is malicious from day one, Phionyx records the activity faithfully but does not prevent it. Defense: server allow-listing at host configuration time.
4. **Hardware-level attacks.** Out of scope.

## 5. Compliance Mapping

The capabilities map onto external compliance frameworks Phionyx already publishes mappings for:

| Capability | OWASP Agentic AI v1.0 | EU AI Act (Art 9-15, Dec 2027) | NIST AI RMF 1.0 | ISO/IEC 42001:2023 |
|---|---|---|---|---|
| #1 Descriptor hash | T01 (Memory Poisoning) defense surface | Art. 10 (data governance) | MAP 4 | A.5.2 |
| #2 Change detection | T01 + T03 (Authority Hijacking) | Art. 12 (record-keeping) | MEASURE 2 | A.6.2 |
| #3 Permission scope | T03 + T04 (Resource Hijacking) | Art. 14 (human oversight) | MANAGE 1 | A.5.4 |
| #4 I/O hash | T07 (Misalignment & Deception) audit | Art. 12 + Art. 15 (accuracy/robustness) | MEASURE 1 | A.7.4 |
| #5 User approval | T15 (Human Manipulation) | Art. 14 (human oversight) + Art. 13 (transparency) | GOVERN 4 | A.6.1 |
| #6 Anomaly flag | T05 (Cascading Hallucination) | Art. 15 + Art. 9 (risk management) | MEASURE 4 | A.7.5 |
| #7 Signed envelope | T11 (Unexpected RCE) evidence | Art. 12 (record-keeping) | MANAGE 4 | A.7.7 |
| #8 Chain verify | All — tamper-evidence anchor | Art. 12 (5-year audit) | MANAGE 4 | A.7.8 |

Detailed crosswalks live in `phionyx-research/standards/`.

## 6. References

- **MCP Specification 2025-11-25** — https://modelcontextprotocol.io/specification/2025-11-25 (Security & Trust section)
- **Jamshidi et al. 2025** — *Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks.* arXiv:2512.06556. (Polytechnique Montréal, Concordia, Brock University.)
- **RGE v0.2 RFC** — `specs/rge_v0_2/rge_v0_2.md` (signature scope §4.1, mcp_tool_audit threat model §4.3)
- **OWASP Agentic AI v1.0** — Threat catalogue
- **EU AI Act** — Articles 9-15 (high-risk obligations, applicable 2 December 2027 per 7 May 2026 Council/Parliament agreement)

---

*Document author: Phionyx Research (founder@phionyx.ai, ORCID 0009-0002-3718-4010). W2 deliverable, F1 v0.4.0 hot lane.*
