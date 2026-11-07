#!/usr/bin/env python3
"""SRCT guard middleware for popular AI frameworks.

One line to SRCT-enable an existing agent — no cryptography, no chain
internals:

    from srct_frameworks import SrctGuard, langchain_tool

    guard = SrctGuard(node="http://127.0.0.1:8080", agent_id_hex="...",
                      policy_portable_json="...", max_amount_sat=400)
    safe_search = langchain_tool(my_search_fn, guard=guard, amount_sat=50,
                                 recipient_hex="...", name="web_search",
                                 description="Search the web.")

Every wrapped call checks the spend policy *before* your function runs: the
client budget first (max amount, recipient/service allow-lists), then the
node's `POST /v1/policy/decide` (read-only, commits nothing). Only `allow`
executes your code. A `deny` or `needs_approval` raises `SrctDenied` before
anything runs — no key is used, nothing is spent.

The same shape ships for CrewAI (`crewai_tool`) and LlamaIndex
(`llamaindex_tool`). Frameworks are imported lazily inside their factories,
so this file imports cleanly with none of them installed; a missing
framework raises an error naming the exact `pip install` instead of an
ImportError traceback.

Stdlib only: urllib + json. No new dependencies.
"""

import json
import sys
import urllib.request

_DECIDE = "/v1/policy/decide"


class SrctDenied(Exception):
    """The guard refused before the wrapped function ran."""

    def __init__(self, decision, reason=None):
        super().__init__(f"srct guard refused: {decision}"
                         + (f" ({reason})" if reason else ""))
        self.decision = decision
        self.reason = reason


class SrctGuard:
    """Client-side budget plus node-backed policy check.

    `policy_portable_json` (from `srct-worker grant` / `policy.export`) is
    the usual grant shape; `policy_hex` + `policy_sigs_hex` +
    `policy_keys_hex` is the raw alternative. One of the two is required.
    """

    def __init__(self, node, agent_id_hex, policy_portable_json=None,
                 policy_hex=None, policy_sigs_hex=None, policy_keys_hex=None,
                 max_amount_sat=None, allowed_recipients=None,
                 allowed_services=None, approval_threshold_sat=None):
        if not policy_portable_json and not (
                policy_hex and policy_sigs_hex and policy_keys_hex):
            raise ValueError("supply policy_portable_json or "
                             "policy_hex + policy_sigs_hex + policy_keys_hex")
        self.node = node.rstrip("/")
        self.agent_id_hex = agent_id_hex
        self.policy_portable_json = policy_portable_json
        self.policy_hex = policy_hex
        self.policy_sigs_hex = policy_sigs_hex
        self.policy_keys_hex = policy_keys_hex
        self.max_amount_sat = max_amount_sat
        self.allowed_recipients = allowed_recipients
        self.allowed_services = allowed_services
        self.approval_threshold_sat = approval_threshold_sat

    # -- transport (no keys anywhere near here) -------------------------

    def _post(self, path, payload):
        import urllib.error
        req = urllib.request.Request(
            self.node + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8")
                doc = json.loads(body) if body else {}
            except Exception:
                doc = {}
            return e.code, doc
        except Exception as e:
            raise SrctDenied("node_unreachable", str(e))

    # -- the check -----------------------------------------------------

    def check(self, amount_sat, recipient_hex, service_hex=None):
        """Allow or refuse a spend before it happens. Returns the decision.

        Raises `SrctDenied` on anything but `allow` — including a client
        budget refusal, which never touches the network.
        """
        if (self.max_amount_sat is not None
                and amount_sat > self.max_amount_sat):
            raise SrctDenied("deny", "client budget: amount over max_amount_sat")
        if (self.allowed_recipients is not None
                and recipient_hex not in self.allowed_recipients):
            raise SrctDenied("deny", "client budget: recipient not allow-listed")
        if service_hex is not None and self.allowed_services is not None \
                and service_hex not in self.allowed_services:
            raise SrctDenied("deny", "client budget: service not allow-listed")
        payload = {
            "agent_id_hex": self.agent_id_hex,
            "recipient_hex": recipient_hex,
            "amount_sat": amount_sat,
        }
        if self.policy_portable_json is not None:
            payload["policy_portable_json"] = self.policy_portable_json
        else:
            payload["policy_hex"] = self.policy_hex
            payload["policy_sigs_hex"] = self.policy_sigs_hex
            payload["policy_keys_hex"] = self.policy_keys_hex
        if service_hex is not None:
            payload["service_hex"] = service_hex
        if self.approval_threshold_sat is not None:
            payload["approval_threshold_sat"] = self.approval_threshold_sat
        status, body = self._post(_DECIDE, payload)
        if status != 200:
            raise SrctDenied("node_error",
                             body.get("reason", f"HTTP {status}"))
        decision = body.get("decision", "deny")
        if decision != "allow":
            raise SrctDenied(decision, body.get("reason"))
        return body


def guarded(guard, amount_sat, recipient_hex, service_hex=None):
    """Decorator: run the guard before the function, every call."""

    def wrap(fn):
        def inner(*args, **kwargs):
            guard.check(amount_sat, recipient_hex, service_hex)
            return fn(*args, **kwargs)

        inner.__name__ = getattr(fn, "__name__", "srct_guarded")
        inner.__doc__ = fn.__doc__
        return inner

    return wrap


def _refuse_missing(framework, package):
    raise ImportError(
        f"{framework} is not installed: pip install {package}, "
        "then call this factory again")


def langchain_tool(fn, *, guard, amount_sat, recipient_hex,
                   service_hex=None, name, description):
    """Wrap `fn` as a LangChain tool that clears the SRCT guard first."""
    try:
        from langchain_core.tools import tool as lc_tool
    except ImportError:
        _refuse_missing("LangChain", "langchain-core")

    @lc_tool(name, description=description)
    def srct_guarded_tool(*args, **kwargs):
        guard.check(amount_sat, recipient_hex, service_hex)
        return fn(*args, **kwargs)

    return srct_guarded_tool


def crewai_tool(fn, *, guard, amount_sat, recipient_hex,
                service_hex=None, name, description):
    """Wrap `fn` as a CrewAI `BaseTool` that clears the SRCT guard first."""
    try:
        from crewai.tools import BaseTool
    except ImportError:
        _refuse_missing("CrewAI", "crewai")

    def _run(*args, **kwargs):
        guard.check(amount_sat, recipient_hex, service_hex)
        return fn(*args, **kwargs)

    return type("SrctGuardedTool", (BaseTool,), {
        "name": name,
        "description": description,
        "_run": _run,
    })()


def llamaindex_tool(fn, *, guard, amount_sat, recipient_hex,
                    service_hex=None, name, description):
    """Wrap `fn` as a LlamaIndex `FunctionTool` that clears the guard first."""
    try:
        from llama_index.core.tools import FunctionTool
    except ImportError:
        _refuse_missing("LlamaIndex", "llama-index-core")

    def srct_guarded_fn(*args, **kwargs):
        guard.check(amount_sat, recipient_hex, service_hex)
        return fn(*args, **kwargs)

    return FunctionTool.from_defaults(
        fn=srct_guarded_fn, name=name, description=description)


def _selftest():
    """Offline self-test: fake node + stub frameworks, real guard logic.

    Run:  python templates/srct_frameworks.py --selftest
    """
    import types

    calls = {"decide": 0}

    guard = SrctGuard(node="http://fake", agent_id_hex="aa",
                      policy_portable_json='{"fake": true}',
                      max_amount_sat=400,
                      allowed_recipients=["rr"],
                      allowed_services=["ss"])

    def fake_post(path, payload):
        calls["decide"] += 1
        assert path == _DECIDE, path
        assert payload["agent_id_hex"] == "aa", payload
        return 200, {"decision": "allow", "reason": None}

    guard._post = fake_post
    ran = []

    @guarded(guard, 50, "rr", "ss")
    def work():
        ran.append(True)
        return "done"

    assert work() == "done"
    assert ran == [True] and calls["decide"] == 1

    # Client budget refuses before any network call.
    before = calls["decide"]
    try:
        guard.check(401, "rr", "ss")
        raise AssertionError("over-budget check must refuse")
    except SrctDenied as e:
        assert e.decision == "deny", e
    assert calls["decide"] == before, "budget refusal must not call the node"

    try:
        guard.check(50, "other", "ss")
        raise AssertionError("off-allow-list check must refuse")
    except SrctDenied:
        pass

    # Node deny surfaces without running the function.
    def deny_post(path, payload):
        return 200, {"decision": "deny", "reason": "window_exhausted"}

    guard._post = deny_post
    ran.clear()
    try:
        work()
        raise AssertionError("node deny must refuse")
    except SrctDenied as e:
        assert e.reason == "window_exhausted", e
    assert ran == [], "denied call must not run the function"

    # needs_approval gates too.
    def approval_post(path, payload):
        return 200, {"decision": "needs_approval",
                     "reason": "human_approval_required"}

    guard._post = approval_post
    try:
        work()
        raise AssertionError("needs_approval must gate")
    except SrctDenied as e:
        assert e.decision == "needs_approval", e

    # Factories work against stub frameworks (no real deps needed).
    lc_mod = types.ModuleType("langchain_core.tools")

    def fake_lc_tool(name, description=None):
        def deco(fn):
            fn.tool_name = name
            fn.tool_description = description
            return fn
        return deco

    lc_mod.tool = fake_lc_tool
    lc_pkg = types.ModuleType("langchain_core")
    sys.modules["langchain_core"] = lc_pkg
    sys.modules["langchain_core.tools"] = lc_mod
    try:
        t = langchain_tool(lambda: "lc", guard=guard, amount_sat=50,
                           recipient_hex="rr", service_hex="ss",
                           name="t", description="d")
        assert t.tool_name == "t", t
    finally:
        del sys.modules["langchain_core"]
        del sys.modules["langchain_core.tools"]

    crewai_mod = types.ModuleType("crewai.tools")

    class FakeBaseTool:
        def __init__(self):
            pass

    crewai_mod.BaseTool = FakeBaseTool
    sys.modules["crewai"] = types.ModuleType("crewai")
    sys.modules["crewai.tools"] = crewai_mod
    try:
        ct = crewai_tool(lambda: "crew", guard=guard, amount_sat=50,
                         recipient_hex="rr", name="ct", description="d")
        assert ct.name == "ct" and ct.description == "d", ct
    finally:
        del sys.modules["crewai"]
        del sys.modules["crewai.tools"]

    li_mod = types.ModuleType("llama_index.core.tools")

    class FakeFunctionTool:
        @classmethod
        def from_defaults(cls, fn=None, name=None, description=None):
            inst = cls()
            inst.fn = fn
            inst.name = name
            inst.description = description
            return inst

    li_mod.FunctionTool = FakeFunctionTool
    li_pkg = types.ModuleType("llama_index")
    li_core = types.ModuleType("llama_index.core")
    sys.modules["llama_index"] = li_pkg
    sys.modules["llama_index.core"] = li_core
    sys.modules["llama_index.core.tools"] = li_mod
    try:
        lt = llamaindex_tool(lambda: "li", guard=guard, amount_sat=50,
                             recipient_hex="rr", name="lt", description="d")
        assert lt.name == "lt", lt
    finally:
        del sys.modules["llama_index"]
        del sys.modules["llama_index.core"]
        del sys.modules["llama_index.core.tools"]

    # Missing frameworks name their package instead of ImportError noise.
    for factory, kw in ((langchain_tool, {}), (crewai_tool, {}),
                        (llamaindex_tool, {})):
        try:
            factory(lambda: None, guard=guard, amount_sat=1,
                    recipient_hex="rr", name="x", description="y", **kw)
            raise AssertionError("missing framework must refuse")
        except ImportError as e:
            assert "pip install" in str(e), e

    print("srct_frameworks selftest: ok "
          f"({calls['decide']} node decide calls)")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        print(__doc__)
