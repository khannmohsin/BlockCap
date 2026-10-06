"""Deterministic C08/C09 checks; no network or application entry point."""
import time
from types import SimpleNamespace

from orchestrator import Orchestrator, ROLE, _ctx_hash


def test_policy_cache_revalidation_rejects_moved_resource_context():
    policy = {
        "fromRole": ROLE["Edge"], "toRole": ROLE["Fog"],
        "opsAllowed": 1, "ctxSchema": _ctx_hash("api:GET:/new"),
        "isDeprecated": False,
    }
    assert not Orchestrator._policy_matches_request(
        policy, "Edge", "Fog", "READ", "api:GET:/old"
    )


def test_chain_state_freshness_fails_closed_for_stale_or_missing_head():
    orch = object.__new__(Orchestrator)
    orch.MAX_CHAIN_STATE_AGE_SECONDS = 15.0
    orch._should_use_js = lambda: False
    orch._w3 = SimpleNamespace(eth=SimpleNamespace(
        get_block=lambda _name: {"timestamp": int(time.time()) - 16}
    ))
    assert orch._chain_state_is_fresh() is False
    orch._w3 = SimpleNamespace(eth=SimpleNamespace(
        get_block=lambda _name: {"timestamp": int(time.time())}
    ))
    assert orch._chain_state_is_fresh() is True
    orch._w3 = SimpleNamespace(eth=SimpleNamespace(
        get_block=lambda _name: (_ for _ in ()).throw(RuntimeError("offline"))
    ))
    assert orch._chain_state_is_fresh() is False
