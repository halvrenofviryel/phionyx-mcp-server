"""WP-11 — production signer/verifier contract.

Asserts the five requirements:
  1. demo HMAC is used ONLY under PHIONYX_MCP_DEMO=1 (never silently);
  2. production mode uses no fixed secret (Ed25519 from an operator key);
  3. with no key provisioned the signer is explicitly UNSIGNED (alg='unsigned'), not demo-signed;
  4. verify_chain's result separates the assurance dimensions (schema / hash-continuity /
     signature-performed / signature-valid / algorithm / key-id / key-trust / revocation / overall);
  5. the CLI exit code matches that contract (0 only when signatures verify).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phionyx_mcp_server import audit_chain as A


def _keypair():
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption()).hex()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw).hex()
    return seed, pub


def _chain(signer, n=2):
    kw = dict(user_text="hi", producer="test", tool_descriptor_hash="sha256:" + "a" * 64,
              descriptor_change_detected=False, tool_permission_scope=["x"],
              input_hash="sha256:" + "b" * 64, output_hash="sha256:" + "c" * 64,
              approval_state=None, anomaly_flag=None, decision="release",
              decision_reason="ok", runtime_policy_basis=["p"])
    envs, prev = [], A.GENESIS_HASH
    for t in range(n):
        e = A.build_envelope(A.ToolCallContext(trace_id="tr", turn_index=t, **kw),
                             previous_hash=prev, server_version="0.0.0-test", signer=signer)
        envs.append(e)
        prev = e["integrity"]["current"]
    return envs


# ── req 1-3: signer selection is env-driven and never silently demo ────────────
def test_get_signer_unsigned_by_default(monkeypatch):
    monkeypatch.delenv("PHIONYX_MCP_SIGNING_KEY", raising=False)
    monkeypatch.delenv("PHIONYX_MCP_DEMO", raising=False)
    s = A.get_signer()
    assert isinstance(s, A.UnsignedSigner)
    assert s.sign("sha256:x") == "unsigned"  # explicit sentinel, not a demo signature


def test_get_signer_demo_only_under_flag(monkeypatch):
    monkeypatch.delenv("PHIONYX_MCP_SIGNING_KEY", raising=False)
    monkeypatch.setenv("PHIONYX_MCP_DEMO", "1")
    assert isinstance(A.get_signer(), A.HmacSigner)


def test_get_signer_ed25519_from_key(monkeypatch):
    seed, _ = _keypair()
    monkeypatch.setenv("PHIONYX_MCP_SIGNING_KEY", seed)
    monkeypatch.delenv("PHIONYX_MCP_DEMO", raising=False)
    s = A.get_signer()
    assert isinstance(s, A.Ed25519Signer)
    assert s.algorithm == "ed25519"
    assert s.sign("sha256:x").startswith("ed25519:")


def test_signing_key_wins_over_demo(monkeypatch):
    seed, _ = _keypair()
    monkeypatch.setenv("PHIONYX_MCP_SIGNING_KEY", seed)
    monkeypatch.setenv("PHIONYX_MCP_DEMO", "1")
    assert isinstance(A.get_signer(), A.Ed25519Signer)  # a real key is never downgraded to demo


def test_signing_key_from_file(monkeypatch, tmp_path):
    seed, _ = _keypair()
    p = tmp_path / "key.hex"
    p.write_text("# seed\n" + seed + "\n")
    monkeypatch.setenv("PHIONYX_MCP_SIGNING_KEY", str(p))
    assert isinstance(A.get_signer(), A.Ed25519Signer)


# ── req 4: verify_chain separates the assurance dimensions ─────────────────────
_DIMS = {"schema", "hash_continuity", "signature_performed", "signature_valid",
         "algorithm", "key_id", "key_trust", "revocation", "overall_assurance"}


def test_ed25519_verified_is_E2():
    seed, pub = _keypair()
    r = A.verify_chain(_chain(A.Ed25519Signer(seed)), verifier=A.Ed25519Verifier(pub))
    assert r["valid"] is True
    assert _DIMS <= set(r["assurance"])
    a = r["assurance"]
    assert a["overall_assurance"] == "E2"
    assert a["algorithm"] == "ed25519"
    assert a["signature_performed"] is True
    assert a["signature_valid"] == "PASS"
    assert a["key_id"] == "phionyx-mcp-ed25519"
    # RGE v0.2 carries no key_trust profile / no revocation source: reported, never faked.
    assert a["key_trust"] == "NOT_MEASURED"
    assert a["revocation"] == "NOT_MEASURED"


def test_ed25519_without_verifier_is_E1_not_measured():
    seed, _ = _keypair()
    r = A.verify_chain(_chain(A.Ed25519Signer(seed)))  # no verifier
    assert r["valid"] is None
    assert r["measurement_status"] == "NOT_MEASURED"
    assert r["assurance"]["overall_assurance"] == "E1"
    assert r["assurance"]["signature_valid"] == "NOT_MEASURED"


def test_tampered_signature_is_invalid():
    seed, pub = _keypair()
    envs = _chain(A.Ed25519Signer(seed))
    envs[1]["integrity"]["signature"] = "ed25519:" + "00" * 64
    r = A.verify_chain(envs, verifier=A.Ed25519Verifier(pub))
    assert r["valid"] is False
    assert r["assurance"]["overall_assurance"] == "INVALID"
    assert r["assurance"]["signature_valid"] == "FAIL"
    assert r["broken_at"] == 1


def test_unsigned_is_E0_no_signature_performed():
    r = A.verify_chain(_chain(A.UnsignedSigner()))
    assert r["assurance"]["algorithm"] == "unsigned"
    assert r["assurance"]["signature_performed"] is False
    assert r["assurance"]["overall_assurance"] == "E0"


def test_demo_hmac_is_E0_even_when_verified():
    envs = _chain(A.HmacSigner())
    r = A.verify_chain(envs, verifier=A.HmacSigner())
    assert r["valid"] is True  # the demo signature does verify...
    assert r["assurance"]["overall_assurance"] == "E0"  # ...but the secret ships, so E0 not E2


def test_tampered_content_hash_fails_before_signature():
    seed, pub = _keypair()
    envs = _chain(A.Ed25519Signer(seed))
    envs[1]["output"]["text"] = "mutated after signing"  # breaks the content hash
    r = A.verify_chain(envs, verifier=A.Ed25519Verifier(pub))
    assert r["valid"] is False
    assert r["assurance"]["hash_continuity"] == "FAIL"


# ── req 5: CLI exit code matches the assurance contract ────────────────────────
def _persist_chain(root: Path, signer):
    os.environ["PHIONYX_MCP_AUDIT_ROOT"] = str(root)
    store = A.FilesystemEnvelopeStore(root)
    for e in _chain(signer):
        store.append("tr", e)


def _cli(env_extra):
    env = dict(os.environ)
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "phionyx_mcp_server.cli", "verify-chain", "--trace", "tr"],
        capture_output=True, text=True, env=env)


def test_cli_exit0_only_when_signatures_verify(tmp_path, monkeypatch):
    seed, pub = _keypair()
    root = tmp_path / "audit"
    _persist_chain(root, A.Ed25519Signer(seed))
    base = {"PHIONYX_MCP_AUDIT_ROOT": str(root)}
    # with a verify key -> signatures verify -> exit 0, overall E2
    r = _cli({**base, "PHIONYX_MCP_VERIFY_KEY": pub})
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["assurance"]["overall_assurance"] == "E2"
    # without a verify key -> signatures NOT measured -> exit 1 (never a silent pass)
    r2 = _cli({k: v for k, v in base.items()})
    assert r2.returncode == 1
    assert json.loads(r2.stdout)["measurement_status"] == "NOT_MEASURED"


def test_cli_exit1_on_tamper(tmp_path):
    seed, pub = _keypair()
    root = tmp_path / "audit"
    _persist_chain(root, A.Ed25519Signer(seed))
    # corrupt the persisted turn-1 envelope's signature
    env_path = root / "tr" / "000001.json"
    doc = json.loads(env_path.read_text())
    doc["integrity"]["signature"] = "ed25519:" + "00" * 64
    env_path.write_text(json.dumps(doc))
    r = _cli({"PHIONYX_MCP_AUDIT_ROOT": str(root), "PHIONYX_MCP_VERIFY_KEY": pub})
    assert r.returncode == 1
    assert json.loads(r.stdout)["valid"] is False
