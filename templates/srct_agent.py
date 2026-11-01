#!/usr/bin/env python3
"""Plug-and-play SRCT worker: turn any AI function into a paid agent.

Two lines to a working agent — no cryptography, no chain internals:

    from srct_agent import SrctAgent

    SrctAgent(node="http://127.0.0.1:8080", wallet="agent.json",
              policy_hex="<hex from `srct-worker grant`>").serve(my_task_fn)

`my_task_fn(task) -> bytes` is *your* framework call. Three adapters ship
below as documentation — LangChain, CrewAI, OpenClaw — each is the same
shape: take the task dict, return result bytes. The template handles
discovery, claiming, submission and polling; `srct-worker` (a required binary
on PATH, or pass `binary=...`) holds the only signing step, so this file
never sees a private key.

Setup (once, by the operator):
  1. `srct-worker generate --out-file agent.json` — the agent wallet.
  2. Fund it, then deposit to L2 (or use a trial: `trial-request`).
  3. `srct-worker grant ... --policy-hex` — the bounded spending authority.
  4. Point this template at the node, wallet and policy hex. Done.

Stdlib only: urllib + subprocess + json + time. No new dependencies.
"""

import json
import subprocess
import time
import urllib.request

_OPEN_TASKS = "/v1/tasks/open?limit=25"


class SrctError(Exception):
    """Anything that stops the loop from making progress."""


class SrctAgent:
    """An agent that earns SRCT for work any verifier can check."""

    def __init__(self, node, wallet, policy_hex=None, network="mini",
                 binary="srct-worker"):
        self.node = node.rstrip("/")
        self.wallet = wallet
        self.policy_hex = policy_hex
        self.network = network
        self.binary = binary

    # -- node reads (no keys anywhere near here) -------------------------

    def _get(self, path):
        import urllib.error
        req = urllib.request.Request(self.node + path, method="GET")
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
            raise SrctError(f"node unreachable for {path}: {e}")

    def open_tasks(self):
        """Open tasks, highest paid first. Returns a list of task dicts."""
        try:
            status, body = self._get(_OPEN_TASKS)
        except SrctError:
            raise
        except Exception as e:
            raise SrctError(f"node unreachable: {e}")
        if status != 200:
            raise SrctError(f"node answered {status} for open tasks")
        tasks = body.get("tasks", [])
        return sorted(tasks, key=lambda t: t.get("payment_sat", 0), reverse=True)

    def check(self, task_id):
        """Verify a settled task: quorum-backed or merely unchallenged?

        Returns (exit_code, output). 0 = verified, 2 = paid-not-verified,
        3 = no certificate.
        """
        return self._run(["verify-cert", "--node", self.node,
                          "--task", task_id, "--network", self.network])

    # -- signed steps (each shells out; the key never enters Python) -----

    def _run(self, argv):
        proc = subprocess.run(
            [self.binary] + argv,
            capture_output=True, text=True, timeout=120,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def claim(self, task_id):
        """Claim one open task. Raises SrctError on refusal."""
        code, out = self._run(["claim", "--node", self.node,
                               "--from-file", self.wallet,
                               "--task", task_id, "--network", self.network])
        if code != 0:
            raise SrctError(f"claim refused:\n{out}")
        return out

    def submit(self, task_id, result: bytes):
        """Submit result bytes for a claimed task. Raises on refusal.

        Large outputs go through a temp file (`--result @file`): command
        lines have length caps, chain state does not.
        """
        if not result:
            raise SrctError("refusing to submit an empty result")
        import os
        import tempfile
        fd, path = tempfile.mkstemp(prefix="srct-result-", suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(bytes(result))
            code, out = self._run(["submit-result", "--node", self.node,
                                   "--from-file", self.wallet,
                                   "--task", task_id,
                                   "--result", "@" + path,
                                   "--network", self.network])
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        if code != 0:
            raise SrctError(f"submit refused:\n{out}")
        return out

    def grant(self, spender, per_tx, cumulative, recipients=(),
              services=(), window=100):
        """Publish a bounded grant from this agent's wallet. The owner's
        convenience wrapper around `srct-worker grant`; prints policy_hex."""
        argv = ["grant", "--node", self.node, "--from-file", self.wallet,
                "--spender", spender, "--per-tx", str(per_tx),
                "--cumulative", str(cumulative), "--window", str(window),
                "--network", self.network]
        if recipients:
            argv += ["--recipients", ",".join(recipients)]
        if services:
            argv += ["--services", ",".join(services)]
        code, out = self._run(argv)
        if code != 0:
            raise SrctError(f"grant refused:\n{out}")
        return out

    # -- the loop ---------------------------------------------------------

    def serve(self, task_fn, poll_secs=10, max_tasks=0, max_polls=0):
        """Poll open tasks forever (or `max_tasks` paid / `max_polls` polls):
        claim, run `task_fn(task_dict) -> bytes`, submit. `task_fn` raising
        skips that task after logging — a failed execution must never be
        retried blindly, because the claim deposit is already committed on
        chain. Returns the paid count.
        """
        done = polls = 0
        try:
            while True:
                polls += 1
                try:
                    tasks = self.open_tasks()
                except SrctError as exc:
                    print(f"[poll] node unreadable, retrying: {exc}")
                    if max_polls and polls >= max_polls:
                        return done
                    time.sleep(poll_secs)
                    continue
                for task in tasks:
                    task_id = task.get("task_id")
                    if not task_id:
                        continue
                    try:
                        self.claim(task_id)
                    except SrctError as exc:
                        print(f"[skip] {task_id[:12]}: {exc}")
                        continue
                    print(f"[claim] {task_id[:12]} "
                          f"pays {task.get('payment_sat')} sat")
                    try:
                        result = task_fn(task)
                    except Exception as exc:  # noqa: BLE001 - operator sees it
                        print(f"[fail] {task_id[:12]}: framework raised: {exc}")
                        continue
                    if not isinstance(result, (bytes, bytearray)):
                        print(f"[fail] {task_id[:12]}: task_fn must return bytes")
                        continue
                    try:
                        self.submit(task_id, bytes(result))
                    except SrctError as exc:
                        print(f"[fail] {task_id[:12]}: {exc}")
                        continue
                    print(f"[paid] {task_id[:12]} submitted")
                    done += 1
                    if max_tasks and done >= max_tasks:
                        return done
                if max_polls and polls >= max_polls:
                    return done
                time.sleep(poll_secs)
        except KeyboardInterrupt:
            print("stopped by operator.")
            return done


# -- framework adapters: same shape, your framework in the middle ---------
#
# LangChain:
#     from langchain.chains import load_chain
#     chain = load_chain("chain.json")
#     def my_task(task):
#         return chain.run(task["task_id"]).encode()
#
# CrewAI:
#     from crewai import Crew
#     crew = Crew(agents=[...], tasks=[...])
#     def my_task(task):
#         return str(crew.kickoff(inputs={"brief": task["task_id"]})).encode()
#
# OpenClaw (external process / webhook worker):
#     import urllib.request as u
#     def my_task(task):
#         req = u.Request("http://claw:1877/run",
#                         data=json.dumps(task).encode())
#         with u.urlopen(req, timeout=300) as r:
#             return r.read()  # raw result bytes, hashed and attested as-is
#
# In every case the loop above is the same:
#     SrctAgent(...).serve(my_task)


def _selftest():
    """Offline self-test: fake node + fake binary, real orchestration.

    Run:  python templates/srct_agent.py --selftest
    """
    calls = []
    agent = SrctAgent(node="http://fake", wallet="w.json", network="mini")
    tasks = [{"task_id": "aa", "payment_sat": 5},
             {"task_id": "bb", "payment_sat": 3}]

    def fake_get(path):
        assert path == "/v1/tasks/open?limit=25", path
        return 200, {"tasks": list(tasks)}

    def fake_run(argv):
        calls.append(argv)
        if argv[0] == "claim":
            return 0, "claimed\n"
        if argv[0] == "submit-result":
            ref = argv[argv.index("--result") + 1]
            assert ref.startswith("@"), argv
            with open(ref[1:], "rb") as f:
                assert f.read() == b"r", argv
            return 0, "submitted\n"
        raise AssertionError(argv)

    agent._get = fake_get
    agent._run = fake_run

    # 1. Highest paid first, fn output submitted per task, stops at max.
    seen = []
    n = agent.serve(lambda t: seen.append(t["task_id"]) or b"r",
                    poll_secs=0, max_tasks=2)
    assert n == 2, n
    assert seen == ["aa", "bb"], seen
    assert [c[0] for c in calls] == ["claim", "submit-result"] * 2, calls

    # 2. A failing framework fn skips the task without submitting.
    calls.clear()
    n = agent.serve(_boom, poll_secs=0, max_polls=1)
    assert n == 0, n
    assert [c[0] for c in calls] == ["claim", "claim"], calls

    # 3. Non-bytes output is refused, never submitted.
    calls.clear()
    n = agent.serve(lambda t: "not-bytes", poll_secs=0, max_polls=1)
    assert n == 0, n
    assert all(c[0] == "claim" for c in calls), calls

    # 4. A refused claim skips the task without calling the framework.
    def fake_run_refused(argv):
        assert argv[0] == "claim", argv
        return 1, "refused: unknown task"
    agent._run = fake_run_refused
    ran = []
    n = agent.serve(lambda t: ran.append(1) or b"r", poll_secs=0, max_polls=1)
    assert n == 0 and ran == [], (n, ran)
    print("srct_agent selftest: ok (serve, skip, refuse paths)")


def _boom(task):
    raise RuntimeError("framework exploded")


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--selftest"]:
        _selftest()
    else:
        print(__doc__)
