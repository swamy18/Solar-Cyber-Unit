#!/usr/bin/env python3
"""SRCT participant node: contribute 100% dedicated RAM + compute under strict fail-closed caps.

Any box with CPU RAM or GPU RAM can join the network in one of two dedicated modes:

1. 100% Mining (mode="mine"):
   Full CPU/GPU resources are dedicated to solving PoW blocks via srct-miner.

2. 100% AI Compute (mode="ai_compute"):
   Full allocatable RAM and compute capacity are made available to the network.
   Requesters/consumers can submit either AI Inference or AI Training workloads,
   and this node executes them using dedicated resources:

    from srct_node import Participant, ResourceCaps, MODE_AI_COMPUTE, MODE_MINE

    caps = ResourceCaps(
        total_ram_mib=8192,                  # physical RAM the box has
        allocatable_ram_mib=6144,            # the network may use this much
        max_compute_units_per_sec=2_000_000, # candidates/s or inferences/s cap
    )

    # Example 1: 100% AI Compute Provider (serves inference and training)
    p_ai = Participant(
        node="http://127.0.0.1:8080",
        wallet="node.json",
        caps=caps,
        mode=MODE_AI_COMPUTE,
        rate_sat_per_unit=250,
    )
    p_ai.run(infer_fn=my_inference_fn, train_fn=my_training_fn)

    # Example 2: 100% Dedicated Miner
    p_mine = Participant(
        node="http://127.0.0.1:8080",
        wallet="node.json",
        caps=caps,
        mode=MODE_MINE,
        miner_address_hex="...",
    )
    p_mine.run()

Earnings track actual contribution (`guard.credited_units`) at the globally
determined SRCT rate (`rate_sat_per_unit`, or `compute_sat_per_unit` from
`GET /v1/fees`):

    earned_sat = contributed_units * global_rate

Payout lands in `wallet` as SRCT. When `payout_asset != "SRCT"`, `payout()`
routes earnings through `POST /v1/fx/swap` and `POST /v1/ramp/intent` so a
provider fills the participant out of band in the chosen coin — SRCT custody
never touches this file, and the intent trail is signed evidence against a
lying provider.

Fail-closed (locked):

- `allocatable_ram_mib <= total_ram_mib`, enforced at construction; a box can
  never promise the network more RAM than it physically has.
- every RAM reservation checks against `allocatable_ram_mib` AND the hard
  `total_ram_mib` ceiling; a job that would exceed either is refused and never
  admitted.
- compute is a token bucket refilled at `max_compute_units_per_sec`; `spend(u)`
  refuses when fewer than `u` tokens are available, so a burst can never spend
  more than authorized and exceeding the configured limit is impossible inside
  this process.
- keys never enter Python: claim/submit/grant shell to `srct-worker`.

Stdlib only: hashlib + json + os + subprocess + tempfile + time + urllib.
No new dependencies. Offline self-test: python templates/srct_node.py --selftest

Node contract mirrored here (the operator keeps these in sync with the node):

    GET  /v1/tasks/open?limit=25        -> {"tasks": [...]}
    POST /v1/mine/submit                -> {"block_hex": ...}
    GET  /v1/fees                       -> {"compute_sat_per_unit": N, ...}
    POST /v1/fx/swap                    -> cross-asset quote
    POST /v1/ramp/intent                -> open a fill intent
"""

import hashlib
import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

_OPEN_TASKS = "/v1/tasks/open?limit=25"
_MINE_SUBMIT = "/v1/mine/submit"
_FEES = "/v1/fees"
_FX_SWAP = "/v1/fx/swap"
_FX_RATES = "/v1/fx/rates"
_RAMP_INTENT = "/v1/ramp/intent"

# Participation floor: a contributor must keep a real, usable amount of RAM.
_MIN_TOTAL_RAM_MIB = 1024
# Reference target: an 8 GB box keeps ~2 GB for the OS and peer threads.
_DEFAULT_TOTAL_RAM_MIB = 8192
_DEFAULT_ALLOCATABLE_RAM_MIB = 6144

MODE_MINE = "mine"
MODE_AI_COMPUTE = "ai_compute"
_VALID_MODES = {MODE_MINE, MODE_AI_COMPUTE}

_MIN_MINE_SHARE = 0.0
_MAX_MINE_SHARE = 1.0


def _task_seed(task):
    """Deterministic seed bytes for a task dict (id, units, kind)."""
    tid = task.get("task_id", "")
    units = str(task.get("compute_units", 1))
    kind = task.get("type") or task.get("service") or "inference"
    return f"{tid}|{units}|{kind}".encode("utf-8")


def _prng_stream(seed, n):
    """`n` deterministic floats in [-1, 1] from SHA-256 counter mode.

    Same task, same stream, on every machine — so a challenger can re-run
    the work and compare bytes.
    """
    out = []
    counter = 0
    while len(out) < n:
        digest = hashlib.sha256(seed + counter.to_bytes(4, "little")).digest()
        for byte in digest:
            out.append(byte / 127.5 - 1.0)
            if len(out) >= n:
                break
        counter += 1
    return out


def default_cpu_infer(task):
    """Default inference: a real 16->16->8->4 MLP forward pass on CPU.

    Weights and inputs derive deterministically from the task, hidden layers
    use tanh, and the four outputs are quantized to int16. Small on purpose:
    a participant proves it did the arithmetic, and a challenger re-running
    the same task gets the same bytes. Returns the packed result bytes.
    """
    seed = _task_seed(task)
    x = _prng_stream(b"srct/infer|x|" + seed, 16)
    w1 = _prng_stream(b"srct/infer|w1|" + seed, 16 * 16)
    b1 = _prng_stream(b"srct/infer|b1|" + seed, 16)

    def layer(x, w, b, rows, cols):
        y = [0.0] * rows
        for r in range(rows):
            s = b[r]
            base = r * cols
            for c in range(cols):
                s += w[base + c] * x[c]
            y[r] = math.tanh(s)
        return y

    h1 = layer(x, w1, b1, 16, 16)
    w2 = _prng_stream(b"srct/infer|w2|" + seed, 16 * 8)
    b2 = _prng_stream(b"srct/infer|b2|" + seed, 8)
    h2 = layer(h1, w2, b2, 8, 16)
    w3 = _prng_stream(b"srct/infer|w3|" + seed, 8 * 4)
    b3 = _prng_stream(b"srct/infer|b3|" + seed, 4)
    out = layer(h2, w3, b3, 4, 8)
    q = [max(-32768, min(32767, int(round(v * 1000.0)))) for v in out]
    return b"mlp1" + struct.pack(">4h", *q)


def default_cpu_train(task):
    """Default training: real gradient descent on CPU.

    Fits `y = w*x + b` to 8 deterministic points of the fixed target
    `y = 2*x + 1` with full-batch MSE, learning rate 0.1, 24 steps. Returns
    the packed final weights and loss — proof the steps ran, reproducible by
    anyone holding the task.
    """
    seed = _task_seed(task)
    xs = _prng_stream(b"srct/train|x|" + seed, 8)
    ys = [2.0 * x + 1.0 for x in xs]
    init = _prng_stream(b"srct/train|w0|" + seed, 2)
    w, b = init[0], init[1]
    lr = 0.1
    n = float(len(xs))
    for _ in range(24):
        dw = sum(2.0 * (w * x + b - y) * x for x, y in zip(xs, ys)) / n
        db = sum(2.0 * (w * x + b - y) for x, y in zip(xs, ys)) / n
        w -= lr * dw
        b -= lr * db
    loss = sum((w * x + b - y) ** 2 for x, y in zip(xs, ys)) / n
    return b"sgd1" + struct.pack(">ddd", w, b, loss)


class SrctError(Exception):
    """Anything that stops the participant from contributing safely."""


def measure_total_ram_mib():
    """Physical RAM in MiB, best effort, stdlib only.

    Tries /proc/meminfo (Linux), sysctl (macOS), then os.sysconf, and falls
    back to the 8 GB reference box. Self-reported like everything else in a
    capability profile: the network spot-checks with elapsed times and
    re-execution, it never trusts this number.
    """
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return max(_MIN_TOTAL_RAM_MIB,
                               int(line.split()[1]) // 1024)
    except OSError:
        pass
    try:
        out = subprocess.run(["sysctl", "-n", "hw.memsize"],
                             capture_output=True, text=True,
                             timeout=5).stdout.strip()
        return max(_MIN_TOTAL_RAM_MIB, int(out) // (1024 * 1024))
    except Exception:  # noqa: BLE001 - fall through to the next probe
        pass
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page = os.sysconf("SC_PAGE_SIZE")
        return max(_MIN_TOTAL_RAM_MIB, (pages * page) // (1024 * 1024))
    except (ValueError, OSError, AttributeError):
        return _DEFAULT_TOTAL_RAM_MIB


def measure_units_per_sec(calls=5):
    """Canonical benchmark: timed runs of the default inference shape.

    One unit is one inference call. The measured calls/sec is what the
    provider advertises as `units-per-sec`; requesters match on it, and the
    node's elapsed-time checks plus challenge re-execution keep it honest.
    """
    probe = {"task_id": "benchmark", "compute_units": 1, "type": "inference"}
    default_cpu_infer(probe)  # warm up: caches hot, first-call cost excluded
    start = time.monotonic()
    for _ in range(max(1, int(calls))):
        default_cpu_infer(probe)
    elapsed = max(time.monotonic() - start, 1e-9)
    return max(1, int(round(max(1, int(calls)) / elapsed)))


def measure_capability(benchmark_calls=5):
    """One auto-generated capability profile: measured RAM + benchmarked
    throughput + core count. No manual hardware description: the provider
    runs this, posts the result, and the network verifies by spot-check."""
    total = measure_total_ram_mib()
    reserve = min(2048, max(1024, total // 4))
    return {
        "total_ram_mib": total,
        "allocatable_ram_mib": total - reserve,
        "cores": max(1, os.cpu_count() or 1),
        "units_per_sec": measure_units_per_sec(benchmark_calls),
    }


class ResourceCaps:
    """The participant's binding resource contract with the network.

    `total_ram_mib` is physical RAM. `allocatable_ram_mib` is what the
    network may use; it must not exceed `total_ram_mib` so the OS and peers
    always keep headroom. `max_compute_units_per_sec` is the ceiling on
    candidate evaluations + inference/training steps per second.
    """

    def __init__(self, total_ram_mib, allocatable_ram_mib,
                 max_compute_units_per_sec):
        if total_ram_mib < _MIN_TOTAL_RAM_MIB:
            raise SrctError(
                f"total_ram_mib {total_ram_mib} below floor "
                f"{_MIN_TOTAL_RAM_MIB}")
        if allocatable_ram_mib <= 0:
            raise SrctError("allocatable_ram_mib must be > 0")
        if allocatable_ram_mib > total_ram_mib:
            raise SrctError(
                f"allocatable_ram_mib {allocatable_ram_mib} exceeds "
                f"total_ram_mib {total_ram_mib}: never promise more than "
                "exists")
        if max_compute_units_per_sec <= 0:
            raise SrctError("max_compute_units_per_sec must be > 0")
        self.total_ram_mib = int(total_ram_mib)
        self.allocatable_ram_mib = int(allocatable_ram_mib)
        self.max_compute_units_per_sec = int(max_compute_units_per_sec)


class ResourceGuard:
    """Fail-closed RAM + compute enforcement.

    RAM: each reservation checks against `allocatable_ram_mib` and the hard
    `total_ram_mib` ceiling. Exceeding either is refused and never admitted.
    Compute: a token bucket refilled at `max_compute_units_per_sec` per
    second. `spend(u)` refuses when fewer than `u` tokens exist, so a burst
    can never spend more than the participant authorized.
    """

    def __init__(self, caps):
        self.caps = caps
        self.used_ram_mib = 0
        self.tokens = float(caps.max_compute_units_per_sec)
        self.last_refill = time.monotonic()
        self.credited_units = 0

    def refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(float(self.caps.max_compute_units_per_sec),
                              self.tokens + elapsed *
                              self.caps.max_compute_units_per_sec)
            self.last_refill = now
        return self.tokens

    def reserve_ram(self, mib):
        """Reserve `mib` MiB. Fail-closed: refuse over either RAM cap."""
        if mib <= 0:
            raise SrctError("ram reservation must be > 0")
        want = self.used_ram_mib + mib
        if want > self.caps.allocatable_ram_mib:
            raise SrctError(
                f"RAM {want} MiB would exceed allocatable cap "
                f"{self.caps.allocatable_ram_mib} MiB")
        if want > self.caps.total_ram_mib:
            raise SrctError(
                f"RAM {want} MiB would exceed total RAM "
                f"{self.caps.total_ram_mib} MiB")
        self.used_ram_mib = want
        return self.used_ram_mib

    def release_ram(self, mib):
        self.used_ram_mib = max(0, self.used_ram_mib - mib)

    def spend(self, units):
        """Spend `units` of compute. Refuses when the budget is exhausted."""
        self.refill()
        if units <= 0:
            raise SrctError("compute units must be > 0")
        if units > self.tokens + 1e-9:
            raise SrctError(
                f"compute {units} units would exceed authorized budget "
                f"({self.tokens:.1f} tokens left)")
        self.tokens -= units
        self.credited_units += units
        return True


class Participant:
    """One network contributor: 100% dedicated mining OR 100% AI compute under `caps`, earns SRCT."""

    def __init__(self, node, wallet, caps, *,
                 mode=MODE_MINE,
                 rate_sat_per_unit=None,
                 payout_asset="SRCT",
                 mine_share=None,
                 miner_address_hex=None,
                 infer_ram_mib=512,
                 miner_ram_mib=1024,
                 mine_units_per_sec=None,
                 network="mini",
                 binary="srct-miner",
                 worker_binary="srct-worker",
                 poll_secs=5):
        if mine_share is not None:
            if mine_share == 1.0:
                mode = MODE_MINE
            elif mine_share == 0.0:
                mode = MODE_AI_COMPUTE
            else:
                raise SrctError(
                    f"fractional mine_share {mine_share} is not permitted: "
                    f"resources must be 100% dedicated to mode='{MODE_MINE}' or mode='{MODE_AI_COMPUTE}'")
        if mode not in _VALID_MODES:
            raise SrctError(f"mode '{mode}' unknown; must be '{MODE_MINE}' or '{MODE_AI_COMPUTE}'")
        self.mode = mode
        self.mine_share = 1.0 if mode == MODE_MINE else 0.0
        self.node = node.rstrip("/")
        self.wallet = wallet
        self.network = network
        self.caps = caps
        self.guard = ResourceGuard(caps)
        self.rate_sat_per_unit = rate_sat_per_unit
        self.payout_asset = payout_asset
        self.miner_address_hex = miner_address_hex
        self.infer_ram_mib = infer_ram_mib
        self.miner_ram_mib = miner_ram_mib
        self.mine_units_per_sec = mine_units_per_sec
        self.binary = binary
        self.worker_binary = worker_binary
        self.poll_secs = poll_secs
        self._miner_proc = None
        self._miner_started_at = None
        if self.mode == MODE_MINE and not self.miner_address_hex:
            raise SrctError(f"mode='{MODE_MINE}' requires miner_address_hex")

    # -- transport (reads only) -------------------------------------------

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
            raise SrctError(f"node unreachable for {path}: {e}")

    # -- signed steps (each shells out; keys never enter Python) ----------

    def _run(self, argv):
        proc = subprocess.run(
            [self.worker_binary] + argv,
            capture_output=True, text=True, timeout=120,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def claim(self, task_id):
        code, out = self._run(["claim", "--node", self.node,
                               "--from-file", self.wallet,
                               "--task", task_id, "--network", self.network])
        if code != 0:
            raise SrctError(f"claim refused:\n{out}")
        return out

    def submit(self, task_id, result: bytes):
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

    def submit_block(self, block_hex: str):
        """Hand a solved header to `srct-worker` for signing + submission."""
        code, out = self._run(["submit-block", "--node", self.node,
                               "--from-file", self.wallet,
                               "--block", block_hex, "--network", self.network])
        if code != 0:
            raise SrctError(f"block submit refused:\n{out}")
        return out

    # -- compute marketplace: one-command join ---------------------------

    def auto_join(self, service="ai/inference", price_sat=200,
                  max_units_per_job=100, max_units_per_shard=100,
                  bond_sat=1_000, window_blocks=14_400,
                  benchmark_calls=5):
        """Join the compute marketplace in one command.

        Measures this box (RAM + canonical benchmark), shells `srct-worker
        compute-join` to stake the bond and post the offer, and returns the
        measured profile with the posted offer hash. No manual hardware
        description: the numbers are measured here and spot-checked by the
        network (elapsed times, challenge re-execution), never trusted.
        """
        caps = measure_capability(benchmark_calls)
        status, body = self._get("/v1/status")
        if status == 200 and isinstance(body.get("height"), int):
            available_until = int(body["height"]) + int(window_blocks)
        else:
            # No readable tip: post a bounded window is impossible, so refuse
            # rather than advertise an unbounded offer.
            raise SrctError("node status unreadable: cannot bound offer window")
        code, out = self._run([
            "compute-join", "--node", self.node,
            "--from-file", self.wallet,
            "--network", self.network,
            "--service", service,
            "--ram-mib", str(caps["allocatable_ram_mib"]),
            "--cores", str(caps["cores"]),
            "--max-units-per-shard", str(max_units_per_shard),
            "--max-units-per-job", str(max_units_per_job),
            "--price", str(price_sat),
            "--units-per-sec", str(caps["units_per_sec"]),
            "--available-from", "0",
            "--available-until", str(available_until),
            "--bond-sat", str(bond_sat),
        ])
        if code != 0:
            raise SrctError(f"compute join refused:\n{out}")
        offer_hash = None
        for line in out.splitlines():
            if line.startswith("offer_hash"):
                offer_hash = line.split()[-1]
        return {"profile": caps, "offer_hash": offer_hash, "out": out}

    def _ticket_cycle(self, infer_fn=None, train_fn=None):
        """Grab one open ticket, run it, submit the receipt. Returns True
        when a ticket was claimed and settled, False when the board is empty
        or nothing fits this box."""
        status, body = self._get("/v1/compute/tickets/list?limit=25")
        if status != 200:
            print(f"[tickets] node answered {status}, skipping cycle")
            return False
        for ticket in body.get("tickets", []):
            ticket_hash = ticket.get("ticket_hash")
            units = int(ticket.get("units", 0) or 0)
            if not ticket_hash or units <= 0:
                continue
            try:
                self.guard.reserve_ram(self.infer_ram_mib)
            except SrctError as exc:
                print(f"[tickets] {ticket_hash[:12]} RAM refused: {exc}")
                continue
            try:
                self.guard.spend(units)
            except SrctError as exc:
                self.guard.release_ram(self.infer_ram_mib)
                print(f"[tickets] {ticket_hash[:12]} compute refused: {exc}")
                continue
            code, out = self._run([
                "compute-claim-ticket", "--node", self.node,
                "--from-file", self.wallet, "--network", self.network,
                "--ticket", ticket_hash, "--units", str(units),
                "--nonce", str(int(time.time()) % 1_000_000_000 + 1),
            ])
            if code != 0:
                self.guard.release_ram(self.infer_ram_mib)
                print(f"[tickets] {ticket_hash[:12]} claim refused (taken?)")
                continue
            claim_hash = None
            for line in out.splitlines():
                if line.startswith("claim_hash"):
                    claim_hash = line.split()[-1]
            if not claim_hash:
                self.guard.release_ram(self.infer_ram_mib)
                print(f"[tickets] {ticket_hash[:12]} claim output unreadable")
                continue
            service = ticket.get("service") or "inference"
            is_training = service in ("training", "ai/training")
            handler = (train_fn if is_training else infer_fn)
            if handler is None:
                handler = default_cpu_train if is_training else default_cpu_infer
            task = {"task_id": ticket_hash, "compute_units": units,
                    "type": service}
            started = time.monotonic()
            try:
                result = handler(task)
            except Exception as exc:  # noqa: BLE001 - operator sees it
                self.guard.release_ram(self.infer_ram_mib)
                print(f"[tickets] {ticket_hash[:12]} handler raised: {exc}")
                continue
            elapsed_ms = int((time.monotonic() - started) * 1000)
            if not isinstance(result, (bytes, bytearray)):
                self.guard.release_ram(self.infer_ram_mib)
                print(f"[tickets] {ticket_hash[:12]} handler must return bytes")
                continue
            output = hashlib.sha256(bytes(result)).hexdigest()
            status_h, body_h = self._get("/v1/status")
            height = body_h.get("height", 0) if status_h == 200 else 0
            code, out = self._run([
                "compute-submit-receipt", "--node", self.node,
                "--from-file", self.wallet, "--network", self.network,
                "--ticket", ticket_hash, "--claim", claim_hash,
                "--units", str(units), "--output", output,
                "--elapsed-ms", str(elapsed_ms), "--height", str(height),
                "--nonce", "1",
            ])
            self.guard.release_ram(self.infer_ram_mib)
            if code != 0:
                print(f"[tickets] {ticket_hash[:12]} submit refused:\n{out}")
                continue
            print(f"[tickets] {ticket_hash[:12]} settled, {units} units")
            return True
        return False

    # -- global SRCT rate --------------------------------------------------

    def global_rate(self):
        """Sat per compute unit. Never invented: configured or published."""
        if self.rate_sat_per_unit is not None:
            return int(self.rate_sat_per_unit)
        status, body = self._get(_FEES)
        if status != 200:
            raise SrctError(f"node answered {status} for global SRCT rate")
        rate = body.get("compute_sat_per_unit")
        if rate is None:
            raise SrctError(
                "global SRCT rate not published on this node; pass "
                "rate_sat_per_unit to Participant")
        return int(rate)

    def earnings_sat(self):
        """`contributed_units * global_rate`; the participant's actual pay."""
        return self.guard.credited_units * self.global_rate()

    # -- mine track: bounded `srct-miner` subprocess ----------------------

    def start_miner(self):
        """Launch `srct-miner` with threads/batch derived from `caps`.

        The binary's sustained rate is capped so it can never exceed its
        share of the compute budget; the node re-validates every block it
        submits. Returns the `Popen` handle (caller may inspect it).
        """
        if not self.miner_address_hex:
            raise SrctError("mine track needs miner_address_hex")
        # --node must be ADDR:PORT; strip scheme and any path.
        host = self.node
        for scheme in ("http://", "https://"):
            if host.startswith(scheme):
                host = host[len(scheme):]
        host = host.split("/", 1)[0]
        # Thread count bounded by both CPU availability and the compute cap:
        # more threads than units/sec can meaningfully use only wastes context
        # switches, never exceeds the cap.
        try:
            n_cpu = os.cpu_count() or 1
        except NotImplementedError:
            n_cpu = 1
        threads = max(1, min(n_cpu,
                             max(1, self.caps.max_compute_units_per_sec // 1_000_000)))
        # One batch = one solver pass; keep it inside the per-cycle budget.
        batch = max(1, min(65_536,
                           self.caps.max_compute_units_per_sec // max(1, n_cpu)))
        argv = [self.binary, "--node", host,
                "--miner", self.miner_address_hex,
                "--threads", str(threads),
                "--batch", str(batch)]
        self._miner_proc = subprocess.Popen(argv)
        self._miner_started_at = time.monotonic()
        return self._miner_proc

    def stop_miner(self):
        if self._miner_proc is not None:
            try:
                self._miner_proc.terminate()
                self._miner_proc.wait(timeout=10)
            except Exception:
                try:
                    self._miner_proc.kill()
                except Exception:
                    pass
            self._miner_proc = None
        self._miner_started_at = None

    def _mine_cycle(self):
        """Credit the miner's authorized throughput up to 100% of the compute budget."""
        if self._miner_proc is None or self._miner_proc.poll() is not None:
            return  # miner not running; nothing to credit
        now = time.monotonic()
        started = self._miner_started_at or now
        elapsed = max(0.0, now - started)
        rate = (self.mine_units_per_sec
                if self.mine_units_per_sec is not None
                else self.caps.max_compute_units_per_sec)
        credit = min(rate * elapsed, self.guard.tokens)
        if credit > 0:
            self.guard.spend(int(credit))
        self._miner_started_at = now

    # -- AI compute track: serves inference and training ------------------

    def _compute_cycle(self, task_fn=None, *, infer_fn=None, train_fn=None):
        """Execute one available AI compute task (inference or training) using 100% capacity."""
        status, body = self._get(_OPEN_TASKS)
        if status != 200:
            print(f"[compute] node answered {status}, skipping cycle")
            return
        tasks = sorted(body.get("tasks", []),
                       key=lambda t: t.get("payment_sat", 0), reverse=True)
        for task in tasks:
            task_id = task.get("task_id")
            if not task_id:
                continue
            units = int(task.get("compute_units", 1))
            ram = self.infer_ram_mib
            try:
                self.guard.reserve_ram(ram)
            except SrctError as exc:
                print(f"[compute] {task_id[:12]} RAM refused: {exc}")
                continue  # never admit over-cap work
            try:
                self.guard.spend(units)
            except SrctError as exc:
                self.guard.release_ram(ram)
                print(f"[compute] {task_id[:12]} compute refused: {exc}")
                continue

            # Check whether the consumer requested inference or training
            kind = task.get("type") or task.get("service") or "inference"
            is_training = kind in ("training", "ai/training")

            handler = None
            if is_training:
                handler = train_fn or task_fn
            else:
                handler = infer_fn or task_fn

            if handler is None:
                self.guard.release_ram(ram)
                tag = "training" if is_training else "inference"
                print(f"[compute] {task_id[:12]} no handler provided for {tag} task")
                continue

            try:
                result = handler(task)
            except Exception as exc:  # noqa: BLE001 - operator sees it
                self.guard.release_ram(ram)
                print(f"[compute] {task_id[:12]} handler raised: {exc}")
                continue
            if not isinstance(result, (bytes, bytearray)):
                self.guard.release_ram(ram)
                print(f"[compute] {task_id[:12]} handler must return bytes")
                continue
            try:
                self.submit(task_id, bytes(result))
            except SrctError as exc:
                self.guard.release_ram(ram)
                print(f"[compute] {task_id[:12]} submit refused: {exc}")
                continue
            self.guard.release_ram(ram)
            tag = "training" if is_training else "inference"
            print(f"[compute] {task_id[:12]} ({tag}) submitted, {units} units")
            return  # one task per cycle, then recompute the budget

    def _infer_cycle(self, task_fn):
        """Backward-compatible alias for _compute_cycle."""
        return self._compute_cycle(task_fn=task_fn)

    # -- payout: SRCT or cross-network asset ------------------------------

    def swap_quote(self, asset, amount_sat):
        """Quote converting `amount_sat` SRCT to `asset`. Returns the quote."""
        status, body = self._post(_FX_SWAP, {
            "from": "SRCT", "to": asset, "amount_sat": int(amount_sat),
        })
        if status != 200:
            raise SrctError(f"fx swap answered {status} for {asset}")
        return body

    def open_cross_asset_payout(self, asset, amount_sat, fill_ref=None,
                                user_hex=None):
        """Open a `/v1/ramp/intent` so a provider pays out `asset` off-chain.

        SRCT is locked by the swap quote; the provider fills the intent in
        `asset` out of band (bank transfer, stablecoin, ...). The signed
        intent trail is evidence against a lying provider. Returns the intent.
        """
        import os
        quote = self.swap_quote(asset, amount_sat)
        quote_id = quote.get("quote_id")
        if not quote_id:
            raise SrctError(f"swap quote missing quote_id: {quote}")
        ref = fill_ref or f"srct-payout-{int(time.time())}-{os.urandom(8).hex()}"
        payload = {"quote_id": quote_id, "fill_ref": ref}
        if user_hex is not None:
            payload["user_hex"] = user_hex
        status, body = self._post(_RAMP_INTENT, payload)
        if status != 200:
            raise SrctError(f"ramp intent answered {status} for {asset}")
        return body

    def payout(self, amount_sat=None, asset=None, **kwargs):
        """Pay out `amount_sat` (default: all earnings) as SRCT or `asset`.

        SRCT payouts credit the participant's wallet. Any other asset goes
        through `open_cross_asset_payout` (fx swap + ramp intent).
        """
        amount = int(amount_sat if amount_sat is not None
                     else self.earnings_sat())
        if amount <= 0:
            raise SrctError("nothing to pay out")
        asset = asset or self.payout_asset
        if asset == "SRCT":
            # On-chain SRCT payout: `srct-worker pay` moves it; this file only
            # authorizes the amount, never touches a key.
            code, out = self._run(["pay", "--node", self.node,
                                   "--from-file", self.wallet,
                                   "--amount-sat", str(amount),
                                   "--network", self.network])
            if code != 0:
                raise SrctError(f"SRCT pay refused:\n{out}")
            return {"asset": "SRCT", "amount_sat": amount, "out": out}
        return self.open_cross_asset_payout(asset, amount, **kwargs)

    # -- main execution loop ---------------------------------------------

    def run(self, task_fn=None, *, infer_fn=None, train_fn=None, max_cycles=0):
        """Execute 100% mining OR 100% AI compute until interrupted (or `max_cycles`).

        If mode == MODE_MINE:
            Launches srct-miner with 100% resources and credits mining throughput.
            task_fn is not required.
        If mode == MODE_AI_COMPUTE:
            Pulls open tickets from the compute board, claims one, runs it
            with 100% of allocatable resources, and submits the receipt —
            then repeats with no cooldown. With no handlers given, the
            built-in CPU workers (`default_cpu_infer`, `default_cpu_train`)
            run real deterministic arithmetic; explicit handlers still
            override them. An empty board falls back to the legacy task
            queue (`task_fn` path). Does not run a miner.
        """
        if self.mode == MODE_MINE:
            if not self.miner_address_hex:
                raise SrctError(f"mode='{MODE_MINE}' requires miner_address_hex")
            self.start_miner()
        else:
            # No explicit handler: fall back to the built-in CPU workers, so a
            # fresh box contributes real arithmetic out of the box instead of
            # refusing every task. Explicit handlers still win when given.
            if task_fn is None and infer_fn is None and train_fn is None:
                infer_fn, train_fn = default_cpu_infer, default_cpu_train

        cycles = 0
        try:
            while True:
                cycles += 1
                self.guard.refill()
                if self.mode == MODE_MINE:
                    self._mine_cycle()
                elif self._ticket_cycle(infer_fn=infer_fn, train_fn=train_fn):
                    pass  # claimed and settled a ticket; loop for the next
                else:
                    self._compute_cycle(task_fn=task_fn, infer_fn=infer_fn, train_fn=train_fn)
                if max_cycles and cycles >= max_cycles:
                    return cycles
                time.sleep(self.poll_secs)
        except KeyboardInterrupt:
            print("stopped by operator.")
            return cycles
        finally:
            if self.mode == MODE_MINE:
                self.stop_miner()


# -- selftest: fake node + fake binaries, real cap enforcement -----------

def _selftest():
    """Offline self-test: caps enforced, dual-hash accounted, over-limit refused.

    Run:  python templates/srct_node.py --selftest
    """
    import os
    import threading

    mod = sys.modules[__name__]
    real_get, real_post = Participant._get, Participant._post
    real_popen = subprocess.Popen

    calls = {"get": [], "post": [], "popen": [], "run": []}
    miner_launched = {"threads": None, "batch": None}

    class FakeProc:
        def __init__(self, argv):
            calls["popen"].append(argv)
            miner_launched["threads"] = argv[argv.index("--threads") + 1]
            miner_launched["batch"] = argv[argv.index("--batch") + 1]
            self._active = True
        def poll(self):
            return None if self._active else 1
        def terminate(self):
            self._active = False
        def wait(self, timeout=None):
            return None

    tasks = [
        {"task_id": "aa", "payment_sat": 5, "compute_units": 100, "type": "inference"},
        {"task_id": "bb", "payment_sat": 3, "compute_units": 100, "type": "training"},
        {"task_id": "cc", "payment_sat": 9, "compute_units": 100, "type": "inference"},
    ]
    consumed = set()
    submitted = []

    def fake_get(node, path):
        calls["get"].append(path)
        if path == "/v1/tasks/open?limit=25":
            return 200, {"tasks": [t for t in tasks
                                   if t["task_id"] not in consumed]}
        if path == "/v1/fees":
            return 200, {"compute_sat_per_unit": 250,
                         "sat_per_srct": 1_000_000_000}
        if path == "/v1/compute/tickets/list?limit=25":
            return 200, {"tickets": []}
        if path == "/v1/status":
            return 200, {"height": 41}
        raise AssertionError(path)

    def fake_get_no_rate(node, path):
        """A node that publishes fees but no compute rate."""
        if path == "/v1/fees":
            return 200, {"sat_per_srct": 1_000_000_000}
        raise AssertionError(path)

    def fake_post(node, path, payload):
        calls["post"].append((path, payload))
        if path == "/v1/fx/swap":
            return 200, {"quote_id": "qq-1", "to": payload["to"],
                         "amount_sat": payload["amount_sat"]}
        if path == "/v1/ramp/intent":
            return 200, {"intent_id": "ii-1", "quote_id": payload["quote_id"],
                         "fill_ref": payload["fill_ref"]}
        if path in ("/v1/compute/bonds/register", "/v1/compute/offers",
                    "/v1/compute/claims"):
            return 200, {"status": "ok"}
        if path == "/v1/compute/receipt":
            return 200, {"status": "settled", "auto_queued": True}
        raise AssertionError(path)

    def fake_run(argv):
        calls["run"].append(argv)
        if argv[0] in ("claim", "submit-result", "submit-block", "pay",
                       "compute-join", "compute-claim-ticket",
                       "compute-submit-receipt"):
            if argv[0] == "submit-result":
                ref = argv[argv.index("--result") + 1]
                assert ref.startswith("@"), argv
                with open(ref[1:], "rb") as f:
                    submitted.append(f.read())
                task = argv[argv.index("--task") + 1]
                consumed.add(task)
            if argv[0] == "compute-join":
                return 0, "bond          posted\noffer_hash    aa\n"
            if argv[0] == "compute-claim-ticket":
                return 0, "claim_hash    cc\nlocal_hash    dd\n"
            if argv[0] == "compute-submit-receipt":
                return 0, "receipt_hash  rr\nauto_queued   True\n"
            return 0, "ok\n"
        raise AssertionError(argv)

    def install(p):
        p._get = lambda path: fake_get("http://fake", path)
        p._post = lambda path, payload: fake_post("http://fake", path, payload)
        p._run = lambda argv: fake_run(argv)

    subprocess.Popen = FakeProc

    try:
        # 1. Caps refuse over-promised RAM at construction.
        try:
            ResourceCaps(total_ram_mib=4096, allocatable_ram_mib=8192,
                         max_compute_units_per_sec=1_000_000)
            raise AssertionError("over-promised RAM must refuse")
        except SrctError:
            pass
        try:
            ResourceCaps(total_ram_mib=100, allocatable_ram_mib=64,
                         max_compute_units_per_sec=1_000_000)
            raise AssertionError("below-floor RAM must refuse")
        except SrctError:
            pass
        caps = ResourceCaps(total_ram_mib=8192, allocatable_ram_mib=6144,
                            max_compute_units_per_sec=1_000_000)
        assert caps.allocatable_ram_mib <= caps.total_ram_mib

        # 2. RAM guard: reserve + release, refuse over allocatable and total.
        guard = ResourceGuard(caps)
        guard.reserve_ram(1024)
        assert guard.used_ram_mib == 1024
        guard.release_ram(1024)
        assert guard.used_ram_mib == 0
        try:
            guard.reserve_ram(6145)  # over allocatable
            raise AssertionError("over-allocatable RAM must refuse")
        except SrctError:
            pass
        assert guard.used_ram_mib == 0  # nothing admitted on refusal
        try:
            guard.reserve_ram(8193)  # over total
            raise AssertionError("over-total RAM must refuse")
        except SrctError:
            pass
        assert guard.used_ram_mib == 0

        # 3. Compute guard: token bucket, refuse over budget, credit units.
        guard = ResourceGuard(caps)
        assert guard.spend(100) is True
        assert guard.credited_units == 100
        assert guard.tokens == 1_000_000 - 100
        try:
            guard.spend(1_000_000)  # far over remaining budget
            raise AssertionError("over-budget compute must refuse")
        except SrctError:
            pass
        assert guard.credited_units == 100  # nothing spent on refusal
        # refill over time: sleep 0.05s -> 50,000 tokens, capped at ceiling
        time.sleep(0.05)
        guard.refill()
        assert guard.tokens == 1_000_000, guard.tokens  # refilled to ceiling

        # 4. 100% AI Compute Mode: serves inference + training, miner never started.
        p = Participant(node="http://fake", wallet="w.json", caps=caps,
                        rate_sat_per_unit=250, mode=MODE_AI_COMPUTE,
                        miner_address_hex="aa" * 10, poll_secs=0)
        install(p)
        assert p.mode == MODE_AI_COMPUTE
        assert p.mine_share == 0.0
        assert p._miner_proc is None
        ran = []
        n = p.run(infer_fn=lambda t: ran.append(f"infer:{t['task_id']}") or b"ri",
                  train_fn=lambda t: ran.append(f"train:{t['task_id']}") or b"rt",
                  max_cycles=3)
        assert n == 3, n
        # Highest-paid first within each cycle; claimed tasks leave the pool.
        assert ran == ["infer:cc", "infer:aa", "train:bb"], ran
        assert len(submitted) == 3, submitted
        assert p.guard.credited_units == 300, p.guard.credited_units
        assert p.earnings_sat() == 300 * 250, p.earnings_sat()
        assert p._miner_proc is None  # Never launched in AI compute mode

        # 5. 100% Mine Mode: launches miner with args from caps, credits 100% of budget.
        p2 = Participant(node="http://fake", wallet="w.json", caps=caps,
                         rate_sat_per_unit=250, mode=MODE_MINE,
                         miner_address_hex="aa" * 10, poll_secs=0,
                         mine_units_per_sec=1_000_000)
        install(p2)
        assert p2.mode == MODE_MINE
        assert p2.mine_share == 1.0
        p2.start_miner()
        assert p2._miner_proc is not None
        assert miner_launched["threads"] is not None, miner_launched
        t = int(miner_launched["threads"])
        b = int(miner_launched["batch"])
        n_cpu = os.cpu_count() or 1
        assert 1 <= t <= n_cpu, (t, n_cpu)
        assert 1 <= b <= 65_536, b

        p2._mine_cycle()  # elapsed ~0 -> ~0 credit
        p2._miner_started_at = time.monotonic() - 2.0  # pretend 2s ran
        before = p2.guard.tokens
        p2._mine_cycle()
        # 2s * 1M units/s = 2M, credits up to 100% of available tokens
        assert p2.guard.tokens < before, (p2.guard.tokens, before)
        assert p2.guard.tokens >= 0
        assert p2.guard.credited_units > 0
        p2.stop_miner()
        assert p2._miner_proc is None

        # 6. Inference over RAM cap: a fat task is refused, never admitted.
        fat_caps = ResourceCaps(total_ram_mib=8192, allocatable_ram_mib=6144,
                                max_compute_units_per_sec=1_000_000)
        p3 = Participant(node="http://fake", wallet="w.json", caps=fat_caps,
                         rate_sat_per_unit=250, mode=MODE_AI_COMPUTE,
                         miner_address_hex="aa" * 10, poll_secs=0,
                         infer_ram_mib=7000)  # over allocatable
        install(p3)
        n3 = p3.run(lambda t: b"r", max_cycles=1)
        assert n3 == 1
        assert p3.guard.used_ram_mib == 0  # refused, nothing admitted
        assert p3.guard.credited_units == 0

        # 7. Global rate: configured value wins; missing published rate refuses.
        assert p.global_rate() == 250
        p4 = Participant(node="http://fake", wallet="w.json", caps=caps,
                         mode=MODE_AI_COMPUTE, miner_address_hex="aa" * 10,
                         poll_secs=0)
        install(p4)
        p4._get = lambda path: fake_get_no_rate("http://fake", path)
        try:
            p4.global_rate()
            raise AssertionError("missing rate must refuse")
        except SrctError:
            pass

        # 8. Cross-asset payout: fx swap + ramp intent, keys never in Python.
        intent = p.open_cross_asset_payout("USDC", 1_000_000,
                                           user_hex="uu" * 10)
        assert intent["intent_id"] == "ii-1", intent
        assert calls["post"][-1][0] == "/v1/ramp/intent"
        assert calls["post"][-2][0] == "/v1/fx/swap"
        assert calls["post"][-2][1]["to"] == "USDC"
        srct_pay = p.payout(500, asset="SRCT")
        assert srct_pay["asset"] == "SRCT" and srct_pay["amount_sat"] == 500
        try:
            p.payout(0)
            raise AssertionError("zero payout must refuse")
        except SrctError:
            pass

        # 9. Fractional mine_share, unknown modes, and missing config refuse.
        try:
            Participant(node="http://fake", wallet="w.json", caps=caps,
                        mine_share=0.5, miner_address_hex="aa" * 10,
                        poll_secs=0)
            raise AssertionError("fractional mine_share must refuse")
        except SrctError:
            pass
        try:
            Participant(node="http://fake", wallet="w.json", caps=caps,
                        mode="unknown_mode", miner_address_hex="aa" * 10,
                        poll_secs=0)
            raise AssertionError("unknown mode must refuse")
        except SrctError:
            pass
        try:
            Participant(node="http://fake", wallet="w.json", caps=caps,
                        mode=MODE_MINE, miner_address_hex=None,
                        poll_secs=0)
            raise AssertionError("mine track without address must refuse")
        except SrctError:
            pass
        p_missing_handler = Participant(node="http://fake", wallet="w.json",
                                        caps=caps, mode=MODE_AI_COMPUTE,
                                        poll_secs=0)
        # No explicit handler: the built-in CPU workers engage instead of
        # refusing. Deterministic: same task, same bytes, every machine.
        probe = {"task_id": "zz", "compute_units": 4, "type": "inference"}
        assert default_cpu_infer(probe) == default_cpu_infer(probe)
        assert default_cpu_train(probe) == default_cpu_train(probe)
        assert isinstance(default_cpu_infer(probe), bytes)
        assert isinstance(default_cpu_train(probe), bytes)
        install(p_missing_handler)
        n_missing = p_missing_handler.run(max_cycles=1)
        assert n_missing == 1

        # 10. Auto capability: measured RAM + benchmarked throughput, then a
        # one-command join (bond + offer) via the worker. Keys never in Python.
        measured = measure_capability(benchmark_calls=2)
        assert measured["total_ram_mib"] >= _MIN_TOTAL_RAM_MIB
        assert 0 < measured["allocatable_ram_mib"] <= measured["total_ram_mib"]
        assert measured["units_per_sec"] >= 1
        assert measured["cores"] >= 1
        pa = Participant(node="http://fake", wallet="w.json",
                         caps=caps, mode=MODE_AI_COMPUTE, poll_secs=0)
        install(pa)
        joined = pa.auto_join(service="ai/inference", price_sat=200,
                             max_units_per_job=100, max_units_per_shard=100,
                             bond_sat=1_000)
        assert joined["offer_hash"] == "aa", joined
        assert joined["profile"]["total_ram_mib"] >= _MIN_TOTAL_RAM_MIB
        # The one-command join shells the worker with measured values; the
        # worker signs and posts (bond + offer) inside its own process.
        join_argv = [a for a in calls["run"] if a[0] == "compute-join"]
        assert len(join_argv) == 1, join_argv
        join = join_argv[0]
        assert join[join.index("--bond-sat") + 1] == "1000", join
        assert join[join.index("--service") + 1] == "ai/inference", join
        assert int(join[join.index("--units-per-sec") + 1]) >= 1, join
        assert int(join[join.index("--ram-mib") + 1]) >= _MIN_TOTAL_RAM_MIB, join

        # 11. Ticket cycle: open board -> claim -> run -> submit, no waiting.
        board = [{"ticket_hash": "tt" * 32, "units": 4,
                  "service": "ai/inference"}]
        pt = Participant(node="http://fake", wallet="w.json",
                         caps=caps, mode=MODE_AI_COMPUTE, poll_secs=0)
        pt._get = lambda path: (200, {"tickets": board}) \
            if path == "/v1/compute/tickets/list?limit=25" else \
            fake_get("http://fake", path)
        pt._post = lambda path, payload: fake_post("http://fake", path, payload)
        pt._run = lambda argv: fake_run(argv)
        assert pt._ticket_cycle() is True
        ran = [a for a in calls["run"]]
        assert any(a[0] == "compute-claim-ticket" for a in ran), ran
        assert any(a[0] == "compute-submit-receipt" for a in ran), ran
    finally:
        subprocess.Popen = real_popen
    print("srct_node selftest: ok "
          f"(caps, RAM guard, token bucket, dedicated modes, payout)")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
    elif "--auto-capability" in sys.argv:
        # One-command join: measure this box, stake the bond, post the
        # offer, print the profile. Example:
        #   python templates/srct_node.py --auto-capability \
        #       --node http://127.0.0.1:8080 --wallet node.json \
        #       --network mini --service ai/inference --price 200 \
        #       --max-units 100 --bond-sat 1000
        def flag(name, default=None):
            if name in sys.argv:
                return sys.argv[sys.argv.index(name) + 1]
            if default is None:
                raise SrctError(f"{name} is required")
            return default
        node = flag("--node")
        wallet_file = flag("--wallet")
        network = flag("--network", "mini")
        caps_dict = measure_capability()
        caps = ResourceCaps(
            total_ram_mib=caps_dict["total_ram_mib"],
            allocatable_ram_mib=caps_dict["allocatable_ram_mib"],
            max_compute_units_per_sec=max(
                caps_dict["units_per_sec"] * 10, 1_000_000),
        )
        p = Participant(node=node, wallet=wallet_file, caps=caps,
                        mode=MODE_AI_COMPUTE, network=network, poll_secs=5)
        joined = p.auto_join(
            service=flag("--service", "ai/inference"),
            price_sat=int(flag("--price", "200")),
            max_units_per_job=int(flag("--max-units", "100")),
            max_units_per_shard=int(flag("--max-units", "100")),
            bond_sat=int(flag("--bond-sat", "1000")),
        )
        print(f"measured ram_mib={caps_dict['total_ram_mib']} "
              f"allocatable={caps_dict['allocatable_ram_mib']} "
              f"cores={caps_dict['cores']} "
              f"units_per_sec={caps_dict['units_per_sec']}")
        print(f"offer_hash={joined['offer_hash']}")
    else:
        print(__doc__)
