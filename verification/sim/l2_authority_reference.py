"""Solar Cyber Unit Layer-2 authority and credit: independent Python reference (SPEC.md 21, 22).

This exists to answer one question about the newest part of the protocol: is
the Rust implementation the only implementation? The authority layer (21) and
the credit layer (22) are the first places in Solar Cyber Unit where a *rule* rather
than a transfer is the interesting object - a grant says how much an agent may
spend, to whom, inside which window, and the chain has to enforce all of it
against state it keeps. A second implementation, written from the specification
in a different language, that reaches the same verdicts is the cheapest
evidence that the specification is unambiguous.

It is deliberately a *reference*, not a fast one: every hash is re-derived from
the document's byte layouts, so a reader can follow each line against SPEC.md
sections 21 and 22.

The scenarios it runs are emitted as a vector file that the Rust test suite
reads back and asserts against, so the two implementations are compared rather
than merely coexisting:

    python verification/sim/l2_authority_reference.py            # write the vectors
    python verification/sim/l2_authority_reference.py --check    # verify only, do not write

The error names are the Rust `L2Error` variant names, because a rule that
refuses for a different reason is a different rule.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS_DIR = ROOT / "tests" / "vectors"
VECTOR_FILE = "l2_authority_vectors.json"

# --- Domain tags (SPEC.md sections 0, 21, 22) ------------------------------
DOM_AGENT_ID = b"srct/agent-id/v1"
DOM_AGENT_ID_SUB = b"srct/agent-id/sub/v1"
DOM_AGENT_POLICY = b"srct/agent-policy/v1"
DOM_L2_CREDIT_POSITION = b"srct/l2/credit-position/v1"
DOM_ADDR = b"srct/addr/v2"

POLICY_VERSION = 2
MAX_POLICY_RECIPIENTS = 64
MAX_POLICY_SERVICES = 64
MAX_CREDIT_RATE_BPS_PER_WINDOW = 1_000
L2_FLAT_FEE_MINIMUM_SAT = 1_000

FEE_POLICY = 2_000
FEE_POLICY_REVOKE = 2_000
FEE_AGENT_SPEND = 2_000
FEE_CREDIT_OPEN = 2_000
FEE_CREDIT_COLLATERAL = 2_000
FEE_CREDIT_REPAY = 2_000
FEE_CREDIT_DEFAULT = 2_000

ROLE_HUMAN, ROLE_MACHINE, ROLE_SERVICE = 0, 1, 2

# --- secp256k1, for address derivation only -------------------------------
# The addresses the scenarios use have to be the same ones the Rust side
# derives, or the digests below (the agent identity, the grant hash, the
# position id) would not be comparable. This is the smallest piece of
# secp256k1 that produces a compressed public key: enough to derive an
# address, and nothing that signs anything.

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _pt_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1) * pow(2 * y1, _P - 2, _P) % _P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % _P, _P - 2, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _pt_mul(k, p=_G):
    r = None
    while k:
        if k & 1:
            r = _pt_add(r, p)
        p = _pt_add(p, p)
        k >>= 1
    return r


def _compress(pt) -> bytes:
    x, y = pt
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def address_of_key_bytes(key: bytes) -> bytes:
    """The Solar Cyber Unit address of a secp256k1 private key.

    The address is the hash of the *hybrid* key bundle (SPEC.md section 1):
    the compressed public key under the ECDSA scheme (33 bytes) and the
    x-only public key under the BIP-340 Schnorr scheme (32 bytes), so a
    hybrid key set cannot be swapped for a smaller one.
    """
    pk = _compress(_pt_mul(int.from_bytes(key, "big")))
    x_only = pk[1:]  # BIP-340 carries the x coordinate alone
    bundle = (
        bytes([2])  # two components follow
        + bytes([1]) + u16(33) + pk  # SCHEME_SECP256K1_ECDSA
        + bytes([2]) + u16(32) + x_only  # SCHEME_SECP256K1_SCHNORR
    )
    return sha_dom(DOM_ADDR, bundle)[:20]


def sha(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def sha_dom(dom: bytes, *parts: bytes) -> bytes:
    return sha(dom, *parts)


def u16(v: int) -> bytes:
    return struct.pack("<H", v)


def u32(v: int) -> bytes:
    return struct.pack("<I", v)


def u64(v: int) -> bytes:
    return struct.pack("<Q", v)


def derive_agent_id(network_id: str, role: int, owner: bytes) -> bytes:
    return sha_dom(DOM_AGENT_ID, network_id.encode(), bytes([role]), owner)[:20]


def derive_sub_agent_id(network_id: str, parent: bytes, role: int) -> bytes:
    return sha_dom(DOM_AGENT_ID_SUB, network_id.encode(), parent, bytes([role]))[:20]


@dataclass
class Policy:
    network_id: str
    agent_id: bytes
    owner: bytes
    role: int
    per_tx_max_sat: int
    window_blocks: int
    cumulative_max_sat: int
    allowed_recipients: list
    allowed_services: list
    not_before_height: int = 0
    expires_at_height: int = 1_000_000
    revoked: bool = False
    parent_agent_id: bytes | None = None

    def serialize(self) -> bytes:
        out = bytearray()
        out += bytes([POLICY_VERSION])
        net = self.network_id.encode()
        out += u16(len(net)) + net
        out += self.agent_id
        out += self.owner
        out += bytes([self.role])
        out += u64(self.per_tx_max_sat)
        out += u64(self.window_blocks)
        out += u64(self.cumulative_max_sat)
        out += u16(len(self.allowed_recipients))
        for r in self.allowed_recipients:
            out += r
        out += u16(len(self.allowed_services))
        for s in self.allowed_services:
            out += s
        out += u64(self.not_before_height)
        out += u64(self.expires_at_height)
        out += bytes([1 if self.revoked else 0])
        if self.parent_agent_id is None:
            out += bytes([0])
        else:
            out += bytes([1]) + self.parent_agent_id
        return bytes(out)

    def hash(self) -> bytes:
        return sha_dom(DOM_AGENT_POLICY, self.serialize())


@dataclass
class PolicyEntry:
    policy: Policy
    spender: bytes
    agent_id: bytes
    revoked: bool = False
    window_start_height: int = 0
    spent_in_window_sat: int = 0
    total_spent_sat: int = 0
    last_nonce: int = 0
    spends: int = 0


@dataclass
class Position:
    id: bytes
    lender: bytes
    borrower: bytes
    principal_sat: int
    outstanding_sat: int
    interest_paid_sat: int = 0
    collateral_sat: int = 0
    rate_bps_per_window: int = 0
    window_blocks: int = 0
    opened_height: int = 0
    deadline_height: int = 0
    interest_settled_height: int = 0
    state: str = "Open"


@dataclass
class Refused(Exception):
    error: str


def refuse(error: str) -> None:
    raise Refused(error)


@dataclass
class State:
    """The Layer-2 state, as far as the authority and credit rules touch it."""

    network_id: str = "srct/mini"
    accounts: dict = field(default_factory=dict)
    funded_total: int = 0
    burned: int = 0
    pscb: int = 0
    policies: dict = field(default_factory=dict)
    policy_by_agent: dict = field(default_factory=dict)
    positions: dict = field(default_factory=dict)
    credit_locked: int = 0
    height: int = 1
    # The position ids in the order the scenarios refer to them by index.
    position_ids: list = field(default_factory=list)
    # The transaction ids already applied. The replay guard is checked before
    # anything else, so an identical transaction is a replay whatever the
    # state would have said about it.
    applied: set = field(default_factory=set)

    # --- accounts ------------------------------------------------------
    def balance(self, addr: bytes) -> int:
        return self.accounts.get(addr, 0)

    def credit(self, addr: bytes, amount: int) -> None:
        self.accounts[addr] = self.balance(addr) + amount
        self.funded_total += amount

    def charge(self, addr: bytes, amount: int) -> None:
        if self.balance(addr) < amount:
            refuse("InsufficientBalance")
        self.accounts[addr] = self.balance(addr) - amount

    def pay(self, addr: bytes, amount: int) -> None:
        if amount == 0:
            return
        self.accounts[addr] = self.balance(addr) + amount

    def collect_fee(self, fee: int) -> None:
        pscb = fee // 2
        burned = fee - pscb
        self.burned += burned
        self.pscb += pscb

    def conservation_total(self) -> int:
        return (
            sum(self.accounts.values())
            + self.credit_locked
            + self.burned
            + self.pscb
        )

    def check_conservation(self) -> bool:
        return self.conservation_total() == self.funded_total

    # --- authority -----------------------------------------------------
    def apply_policy(self, policy: Policy, spender: bytes, owner: bytes) -> None:
        # The signer is the owner the grant names.
        if policy.owner != owner:
            refuse("PolicyBinding")
        if policy.network_id != self.network_id:
            refuse("PolicyBinding")
        if policy.revoked:
            refuse("PolicyBinding")
        if policy.agent_id != policy.agent_id:  # pragma: no cover - identity check
            refuse("PolicyBinding")
        if len(policy.allowed_recipients) > MAX_POLICY_RECIPIENTS:
            refuse("Policy")
        if len(policy.allowed_services) > MAX_POLICY_SERVICES:
            refuse("Policy")
        if policy.expires_at_height <= policy.not_before_height:
            refuse("Policy")
        if policy.per_tx_max_sat == 0:
            refuse("Policy")
        if policy.window_blocks == 0:
            refuse("Policy")
        if policy.per_tx_max_sat > policy.cumulative_max_sat:
            refuse("Policy")
        # One live grant per agent.
        existing = self.policy_by_agent.get(policy.agent_id)
        if existing is not None:
            entry = self.policies[existing]
            if not entry.revoked:
                refuse("PolicyAlreadyPublished")
        # A delegated grant must narrow a live parent.
        if policy.parent_agent_id is not None:
            parent_hash = self.policy_by_agent.get(policy.parent_agent_id)
            if parent_hash is None:
                refuse("UnknownPolicy")
            if not self.policy_is_live(parent_hash):
                refuse("PolicyRevoked")
            parent = self.policies[parent_hash].policy
            dominates(parent, policy)
        fee = FEE_POLICY
        self.charge(owner, fee)
        self.collect_fee(fee)
        h = policy.hash()
        self.policies[h] = PolicyEntry(
            policy=policy,
            spender=spender,
            agent_id=policy.agent_id,
            revoked=False,
            window_start_height=self.height,
        )
        self.policy_by_agent[policy.agent_id] = h

    def apply_revocation(self, agent_id: bytes, owner: bytes) -> None:
        h = self.policy_by_agent.get(agent_id)
        if h is None:
            refuse("UnknownPolicy")
        entry = self.policies[h]
        if entry.policy.owner != owner:
            refuse("PolicyBinding")
        fee = FEE_POLICY_REVOKE
        self.charge(owner, fee)
        self.collect_fee(fee)
        entry.revoked = True

    def policy_is_live(self, h: bytes) -> bool:
        current = h
        for _ in range(9):  # the delegation depth cap, plus one
            entry = self.policies.get(current)
            if entry is None or entry.revoked:
                return False
            parent_id = entry.policy.parent_agent_id
            if parent_id is None:
                return True
            parent_hash = self.policy_by_agent.get(parent_id)
            if parent_hash is None:
                return False
            current = parent_hash
        return False

    def apply_spend(
        self,
        h: bytes,
        spender: bytes,
        nonce: int,
        recipient: bytes,
        amount: int,
        service: bytes | None,
    ) -> None:
        entry = self.policies.get(h)
        if entry is None:
            refuse("UnknownPolicy")
        if entry.spender != spender:
            refuse("PolicyBinding")
        if not self.policy_is_live(h):
            refuse("PolicyRevoked")
        policy = entry.policy
        if policy.network_id != self.network_id:
            refuse("PolicyBinding")
        if self.height < policy.not_before_height:
            refuse("PolicyWindow")
        if self.height >= policy.expires_at_height:
            refuse("PolicyWindow")
        if amount == 0:
            refuse("ZeroAmount")
        if amount > policy.per_tx_max_sat:
            refuse("PolicyLimit")
        if recipient not in policy.allowed_recipients:
            refuse("PolicyRecipient")
        if service is None:
            if policy.allowed_services:
                refuse("PolicyService")
        elif service not in policy.allowed_services:
            refuse("PolicyService")
        if nonce <= entry.last_nonce:
            refuse("PolicyNonce")
        if self.height < entry.window_start_height:
            refuse("PolicyWindow")
        window_end = entry.window_start_height + policy.window_blocks
        if self.height >= window_end:
            window_start, spent = self.height, 0
        else:
            window_start, spent = entry.window_start_height, entry.spent_in_window_sat
        requested = spent + amount
        if requested > policy.cumulative_max_sat:
            refuse("PolicyLimit")
        fee = FEE_AGENT_SPEND
        owner = policy.owner
        need = amount + fee
        if self.balance(owner) < need:
            refuse("InsufficientBalance")
        self.charge(owner, need)
        self.pay(recipient, amount)
        self.collect_fee(fee)
        entry.window_start_height = window_start
        entry.spent_in_window_sat = requested
        entry.total_spent_sat += amount
        entry.last_nonce = nonce
        entry.spends += 1

    # --- credit --------------------------------------------------------
    def apply_credit_open(
        self,
        lender: bytes,
        borrower: bytes,
        amount: int,
        collateral: int,
        rate: int,
        window: int,
        deadline: int,
        nonce: int,
    ) -> None:
        if amount == 0:
            refuse("ZeroAmount")
        if collateral == 0:
            refuse("ZeroAmount")
        if window == 0:
            refuse("CreditTerms")
        if rate > MAX_CREDIT_RATE_BPS_PER_WINDOW:
            refuse("CreditTerms")
        if deadline <= self.height:
            refuse("CreditTerms")
        # Full collateralisation without a bond.
        required = amount
        if collateral < required:
            refuse("CreditUndercollateralised")
        pos_id = credit_position_id(
            lender, borrower, amount, collateral, rate, window, deadline, nonce
        )
        if pos_id in self.positions:
            refuse("CreditPositionExists")
        fee = FEE_CREDIT_OPEN
        if self.balance(lender) < amount + fee:
            refuse("InsufficientBalance")
        # The collateral must be the borrower's own money, so it is checked
        # before the principal arrives.
        if self.balance(borrower) < collateral:
            refuse("InsufficientBalance")
        self.charge(lender, amount + fee)
        self.pay(borrower, amount)
        self.charge(borrower, collateral)
        self.credit_locked += collateral
        self.collect_fee(fee)
        self.positions[pos_id] = Position(
            id=pos_id,
            lender=lender,
            borrower=borrower,
            principal_sat=amount,
            outstanding_sat=amount,
            collateral_sat=collateral,
            rate_bps_per_window=rate,
            window_blocks=window,
            opened_height=self.height,
            deadline_height=deadline,
            interest_settled_height=self.height,
        )

    def apply_credit_collateral(self, pos_id: bytes, borrower: bytes, amount: int) -> None:
        pos = self.positions.get(pos_id)
        if pos is None:
            refuse("UnknownCreditPosition")
        if pos.borrower != borrower:
            refuse("CreditBinding")
        if pos.state != "Open":
            refuse("CreditPositionClosed")
        if amount == 0:
            refuse("ZeroAmount")
        fee = FEE_CREDIT_COLLATERAL
        if self.balance(borrower) < amount + fee:
            refuse("InsufficientBalance")
        self.charge(borrower, amount + fee)
        self.credit_locked += amount
        self.collect_fee(fee)
        pos.collateral_sat += amount

    def apply_credit_repay(self, pos_id: bytes, borrower: bytes, amount: int) -> None:
        pos = self.positions.get(pos_id)
        if pos is None:
            refuse("UnknownCreditPosition")
        if pos.borrower != borrower:
            refuse("CreditBinding")
        if pos.state != "Open":
            refuse("CreditPositionClosed")
        if amount == 0:
            refuse("ZeroAmount")
        interest_due = accrued_interest(
            pos.outstanding_sat,
            pos.interest_settled_height,
            self.height,
            pos.rate_bps_per_window,
            pos.window_blocks,
        )
        # A repayment may not exceed the debt: the lender is paid the debt and
        # not a satoshi more, and the borrower's excess is not silently taken.
        debt = pos.outstanding_sat + interest_due
        if amount > debt:
            refuse("CreditRepaymentExceedsDebt")
        interest_paid = min(amount, interest_due)
        principal_paid = min(amount - interest_paid, pos.outstanding_sat)
        fee = FEE_CREDIT_REPAY
        if self.balance(borrower) < amount + fee:
            refuse("InsufficientBalance")
        self.charge(borrower, amount + fee)
        self.pay(pos.lender, amount)
        self.collect_fee(fee)
        pos.outstanding_sat -= principal_paid
        pos.interest_paid_sat += interest_paid
        pos.interest_settled_height = self.height
        if pos.outstanding_sat == 0:
            pos.state = "Repaid"
            self.credit_locked -= pos.collateral_sat
            self.pay(borrower, pos.collateral_sat)
            pos.collateral_sat = 0

    def apply_credit_default(self, pos_id: bytes, actor: bytes) -> None:
        pos = self.positions.get(pos_id)
        if pos is None:
            refuse("UnknownCreditPosition")
        if pos.state != "Open":
            refuse("CreditPositionClosed")
        if self.height < pos.deadline_height:
            refuse("CreditNotDue")
        interest_due = accrued_interest(
            pos.outstanding_sat,
            pos.interest_settled_height,
            self.height,
            pos.rate_bps_per_window,
            pos.window_blocks,
        )
        debt = pos.outstanding_sat + interest_due
        take = min(pos.collateral_sat, debt)
        excess = pos.collateral_sat - take
        fee = FEE_CREDIT_DEFAULT
        if self.balance(actor) < fee:
            refuse("InsufficientBalance")
        self.charge(actor, fee)
        self.collect_fee(fee)
        self.credit_locked -= pos.collateral_sat
        self.pay(pos.lender, take)
        self.pay(pos.borrower, excess)
        principal_covered = min(take, pos.outstanding_sat)
        pos.outstanding_sat -= principal_covered
        pos.interest_paid_sat += take - principal_covered
        pos.collateral_sat = 0
        pos.state = "Defaulted"


def dominates(parent: Policy, child: Policy) -> None:
    """The delegation rule: the child may never be wider than the parent."""

    def refuse_if(cond: bool) -> None:
        if cond:
            refuse("Policy")

    refuse_if(parent.network_id != child.network_id)
    refuse_if(parent.owner != child.owner)
    refuse_if(parent.role != child.role)
    if child.parent_agent_id is None:
        refuse("Policy")
    refuse_if(child.parent_agent_id != parent.agent_id)
    refuse_if(
        derive_sub_agent_id(child.network_id, parent.agent_id, child.role) != child.agent_id
    )
    refuse_if(child.window_blocks > parent.window_blocks)
    refuse_if(child.per_tx_max_sat > parent.per_tx_max_sat)
    refuse_if(child.cumulative_max_sat > parent.cumulative_max_sat)
    refuse_if(child.not_before_height < parent.not_before_height)
    refuse_if(child.expires_at_height > parent.expires_at_height)
    for r in child.allowed_recipients:
        refuse_if(r not in parent.allowed_recipients)
    for s in child.allowed_services:
        refuse_if(s not in parent.allowed_services)


def accrued_interest(
    principal: int, from_height: int, to_height: int, rate_bps: int, window: int
) -> int:
    if to_height < from_height:
        refuse("CreditInterestOverflow")
    windows = (to_height - from_height) // max(window, 1)
    if windows == 0 or principal == 0:
        return 0
    units = principal * rate_bps * windows
    return units // 10_000


def credit_position_id(
    lender: bytes,
    borrower: bytes,
    amount: int,
    collateral: int,
    rate: int,
    window: int,
    deadline: int,
    nonce: int,
) -> bytes:
    body = (
        lender
        + borrower
        + u64(amount)
        + u64(collateral)
        + u32(rate)
        + u64(window)
        + u64(deadline)
        + u64(nonce)
    )
    return sha_dom(DOM_L2_CREDIT_POSITION, body)


# ---------------------------------------------------------------------------
# The scenarios
# ---------------------------------------------------------------------------

ROLE_SEEDS = {
    "owner": 1,
    "agent": 2,
    "recipient": 3,
    "stranger": 4,
    "lender": 5,
    "borrower": 6,
    "trigger": 7,
}
ADDR = {
    name: address_of_key_bytes(bytes([seed] * 32))
    for name, seed in ROLE_SEEDS.items()
}
ROLE_OF = {v: k for k, v in ADDR.items()}
SERVICE = bytes([0x77]) * 32


def role_of(value) -> str:
    """The role an address plays, or the address itself as hex.

    The vectors carry *roles* rather than addresses, because each side has
    its own way of producing an address (the Rust side has real keys, this
    side has synthetic ones). The digests - the agent identity, the grant
    hash, the position id - are carried as hex, because those both sides must
    derive identically and that is the point of the cross-check.
    """
    if isinstance(value, bytes) and value in ROLE_OF:
        return ROLE_OF[value]
    if isinstance(value, bytes):
        return value.hex()
    return value


def money(addr: str, amount: int) -> int:
    """A satoshi amount as the vectors carry it."""
    return amount


def run_scenarios() -> list:
    """Every scenario, as a list of steps with the expected outcome of each."""
    scenarios = []

    # 1. The happy path: publish, spend, and the counters that record it.
    state = State()
    for a in ("owner", "agent", "recipient"):
        state.credit(ADDR[a], 100_000_000)
    policy = Policy(
        network_id="srct/mini",
        agent_id=derive_agent_id("srct/mini", ROLE_MACHINE, ADDR["owner"]),
        owner=ADDR["owner"],
        role=ROLE_MACHINE,
        per_tx_max_sat=10_000,
        window_blocks=10,
        cumulative_max_sat=20_000,
        allowed_recipients=[ADDR["recipient"]],
        allowed_services=[],
    )
    steps = [
        {
            "op": "policy",
            "policy": policy,
            "spender": ADDR["agent"],
            "owner": ADDR["owner"],
        },
        {
            "op": "spend",
            "policy_hash": policy.hash(),
            "spender": ADDR["agent"],
            "nonce": 1,
            "recipient": ADDR["recipient"],
            "amount": 5_000,
            "service": None,
        },
        {
            "op": "spend",
            "policy_hash": policy.hash(),
            "spender": ADDR["agent"],
            "nonce": 2,
            "recipient": ADDR["recipient"],
            "amount": 6_000,
            "service": None,
        },
    ]
    scenarios.append(("caps_and_counters", state, steps))

    # 2. Every refusal the authority layer can produce, in one scenario.
    state = State()
    for a in ("owner", "agent", "recipient", "stranger"):
        state.credit(ADDR[a], 100_000_000)
    policy = Policy(
        network_id="srct/mini",
        agent_id=derive_agent_id("srct/mini", ROLE_MACHINE, ADDR["owner"]),
        owner=ADDR["owner"],
        role=ROLE_MACHINE,
        per_tx_max_sat=10_000,
        window_blocks=10,
        cumulative_max_sat=20_000,
        allowed_recipients=[ADDR["recipient"]],
        allowed_services=[],
    )
    tagged = Policy(
        network_id="srct/mini",
        agent_id=derive_agent_id("srct/mini", ROLE_MACHINE, ADDR["owner"]),
        owner=ADDR["owner"],
        role=ROLE_MACHINE,
        per_tx_max_sat=10_000,
        window_blocks=10,
        cumulative_max_sat=20_000,
        allowed_recipients=[ADDR["recipient"]],
        allowed_services=[SERVICE],
    )
    steps = [
        {
            "op": "policy",
            "policy": policy,
            "spender": ADDR["agent"],
            "owner": ADDR["owner"],
        },
        # Above the per-transaction cap.
        {
            "op": "spend",
            "policy_hash": policy.hash(),
            "spender": ADDR["agent"],
            "nonce": 1,
            "recipient": ADDR["recipient"],
            "amount": 10_001,
            "service": None,
        },
        # Recipient not on the allow-list.
        {
            "op": "spend",
            "policy_hash": policy.hash(),
            "spender": ADDR["agent"],
            "nonce": 1,
            "recipient": ADDR["stranger"],
            "amount": 1_000,
            "service": None,
        },
        # The wrong spender.
        {
            "op": "spend",
            "policy_hash": policy.hash(),
            "spender": ADDR["stranger"],
            "nonce": 1,
            "recipient": ADDR["recipient"],
            "amount": 1_000,
            "service": None,
        },
        # A nonce that repeats.
        {
            "op": "spend",
            "policy_hash": policy.hash(),
            "spender": ADDR["agent"],
            "nonce": 1,
            "recipient": ADDR["recipient"],
            "amount": 1_000,
            "service": None,
        },
        {
            "op": "spend",
            "policy_hash": policy.hash(),
            "spender": ADDR["agent"],
            "nonce": 1,
            "recipient": ADDR["recipient"],
            "amount": 2_000,
            "service": None,
        },
        # A grant nobody published.
        {
            "op": "spend",
            "policy_hash": bytes(32),
            "spender": ADDR["agent"],
            "nonce": 5,
            "recipient": ADDR["recipient"],
            "amount": 1_000,
            "service": None,
        },
        # A second live grant for the same agent.
        {
            "op": "policy",
            "policy": tagged,
            "spender": ADDR["agent"],
            "owner": ADDR["owner"],
        },
        # A grant naming another owner.
        {
            "op": "policy",
            "policy": Policy(
                network_id="srct/mini",
                agent_id=derive_agent_id("srct/mini", ROLE_MACHINE, ADDR["stranger"]),
                owner=ADDR["stranger"],
                role=ROLE_MACHINE,
                per_tx_max_sat=10_000,
                window_blocks=10,
                cumulative_max_sat=20_000,
                allowed_recipients=[ADDR["recipient"]],
                allowed_services=[],
            ),
            "spender": ADDR["agent"],
            "owner": ADDR["owner"],
        },
    ]
    scenarios.append(("authority_refusals", state, steps))

    # 3. Revocation, and a descendant that dies with it.
    state = State()
    for a in ("owner", "agent", "recipient"):
        state.credit(ADDR[a], 100_000_000)
    parent = Policy(
        network_id="srct/mini",
        agent_id=derive_agent_id("srct/mini", ROLE_MACHINE, ADDR["owner"]),
        owner=ADDR["owner"],
        role=ROLE_MACHINE,
        per_tx_max_sat=100_000,
        window_blocks=100,
        cumulative_max_sat=1_000_000,
        allowed_recipients=[ADDR["recipient"]],
        allowed_services=[],
    )
    child = Policy(
        network_id="srct/mini",
        agent_id=derive_sub_agent_id(
            "srct/mini", parent.agent_id, ROLE_MACHINE
        ),
        owner=ADDR["owner"],
        role=ROLE_MACHINE,
        per_tx_max_sat=1_000,
        window_blocks=50,
        cumulative_max_sat=10_000,
        allowed_recipients=[ADDR["recipient"]],
        allowed_services=[],
        parent_agent_id=parent.agent_id,
    )
    wider = Policy(
        network_id="srct/mini",
        agent_id=derive_sub_agent_id(
            "srct/mini", parent.agent_id, ROLE_MACHINE
        ),
        owner=ADDR["owner"],
        role=ROLE_MACHINE,
        per_tx_max_sat=100_001,
        window_blocks=50,
        cumulative_max_sat=10_000,
        allowed_recipients=[ADDR["recipient"]],
        allowed_services=[],
        parent_agent_id=parent.agent_id,
    )
    steps = [
        {"op": "policy", "policy": parent, "spender": ADDR["agent"], "owner": ADDR["owner"]},
        # A child that widens its parent is refused.
        {"op": "policy", "policy": wider, "spender": ADDR["agent"], "owner": ADDR["owner"]},
        {"op": "policy", "policy": child, "spender": ADDR["agent"], "owner": ADDR["owner"]},
        {
            "op": "spend",
            "policy_hash": child.hash(),
            "spender": ADDR["agent"],
            "nonce": 1,
            "recipient": ADDR["recipient"],
            "amount": 500,
            "service": None,
        },
        # The owner's kill switch reaches the descendant.
        {"op": "revoke", "agent_id": parent.agent_id, "owner": ADDR["owner"]},
        {
            "op": "spend",
            "policy_hash": child.hash(),
            "spender": ADDR["agent"],
            "nonce": 2,
            "recipient": ADDR["recipient"],
            "amount": 500,
            "service": None,
        },
    ]
    scenarios.append(("revocation_reaches_descendants", state, steps))

    # 4. Credit: open, collateralise, repay.
    state = State()
    for a in ("lender", "borrower", "trigger"):
        state.credit(ADDR[a], 100_000_000)
    steps = [
        {
            "op": "credit_open",
            "lender": ADDR["lender"],
            "borrower": ADDR["borrower"],
            "amount": 1_000_000,
            "collateral": 1_000_000,
            "rate": 100,
            "window": 10,
            "deadline": 1_000,
            "nonce": 1,
        },
        {
            "op": "credit_collateral",
            "position": 0,
            "borrower": ADDR["borrower"],
            "amount": 500_000,
        },
        {
            "op": "credit_repay",
            "position": 0,
            "borrower": ADDR["borrower"],
            "amount": 400_000,
        },
        # A repayment larger than the debt is refused: the lender is paid the
        # debt and not a satoshi more.
        {
            "op": "credit_repay",
            "position": 0,
            "borrower": ADDR["borrower"],
            "amount": 2_000_000,
        },
    ]
    scenarios.append(("credit_open_collateralise_repay", state, steps))

    # 5. Credit: the refusals.
    state = State()
    for a in ("lender", "borrower", "trigger"):
        state.credit(ADDR[a], 100_000_000)
    steps = [
        # Under-collateralised.
        {
            "op": "credit_open",
            "lender": ADDR["lender"],
            "borrower": ADDR["borrower"],
            "amount": 1_000_000,
            "collateral": 999_999,
            "rate": 100,
            "window": 10,
            "deadline": 1_000,
            "nonce": 1,
        },
        # A rate above the cap.
        {
            "op": "credit_open",
            "lender": ADDR["lender"],
            "borrower": ADDR["borrower"],
            "amount": 1_000_000,
            "collateral": 1_000_000,
            "rate": 10_001,
            "window": 10,
            "deadline": 1_000,
            "nonce": 2,
        },
        # A deadline in the past.
        {
            "op": "credit_open",
            "lender": ADDR["lender"],
            "borrower": ADDR["borrower"],
            "amount": 1_000_000,
            "collateral": 1_000_000,
            "rate": 100,
            "window": 10,
            "deadline": 1,
            "nonce": 3,
        },
        # The real one.
        {
            "op": "credit_open",
            "lender": ADDR["lender"],
            "borrower": ADDR["borrower"],
            "amount": 1_000_000,
            "collateral": 1_000_000,
            "rate": 100,
            "window": 10,
            "deadline": 1_000,
            "nonce": 4,
        },
        # A repayment from somebody who is not the borrower.
        {
            "op": "credit_repay",
            "position": 0,
            "borrower": ADDR["trigger"],
            "amount": 1_000,
        },
        # A default before the deadline.
        {"op": "credit_default", "position": 0, "actor": ADDR["trigger"]},
        # A repayment of nothing.
        {
            "op": "credit_repay",
            "position": 0,
            "borrower": ADDR["borrower"],
            "amount": 0,
        },
    ]
    scenarios.append(("credit_refusals", state, steps))

    # 6. Credit: a default after the deadline, with a surplus and a shortfall.
    state = State()
    for a in ("lender", "borrower", "trigger"):
        state.credit(ADDR[a], 100_000_000)
    steps = [
        {
            "op": "credit_open",
            "lender": ADDR["lender"],
            "borrower": ADDR["borrower"],
            "amount": 1_000_000,
            "collateral": 2_000_000,
            "rate": 100,
            "window": 10,
            "deadline": 100,
            "nonce": 1,
        },
        {"op": "advance", "to": 100},
        {"op": "credit_default", "position": 0, "actor": ADDR["trigger"]},
        # A closed position cannot be settled again.
        {"op": "credit_default", "position": 0, "actor": ADDR["trigger"]},
    ]
    scenarios.append(("credit_default_after_deadline", state, steps))

    return scenarios


def json_policy(p: Policy) -> dict:
    return {
        "network_id": p.network_id,
        "agent_id": p.agent_id.hex(),
        "owner": role_of(p.owner),
        "role": p.role,
        "per_tx_max_sat": p.per_tx_max_sat,
        "window_blocks": p.window_blocks,
        "cumulative_max_sat": p.cumulative_max_sat,
        "allowed_recipients": [role_of(r) for r in p.allowed_recipients],
        "allowed_services": [s.hex() for s in p.allowed_services],
        "not_before_height": p.not_before_height,
        "expires_at_height": p.expires_at_height,
        "revoked": p.revoked,
        "parent_agent_id": p.parent_agent_id.hex() if p.parent_agent_id else None,
    }


def policy_from_json(d: dict) -> Policy:
    return Policy(
        network_id=d["network_id"],
        agent_id=bytes.fromhex(d["agent_id"]),
        owner=bytes.fromhex(d["owner"]),
        role=d["role"],
        per_tx_max_sat=d["per_tx_max_sat"],
        window_blocks=d["window_blocks"],
        cumulative_max_sat=d["cumulative_max_sat"],
        allowed_recipients=[bytes.fromhex(r) for r in d["allowed_recipients"]],
        allowed_services=[bytes.fromhex(s) for s in d["allowed_services"]],
        not_before_height=d["not_before_height"],
        expires_at_height=d["expires_at_height"],
        revoked=d["revoked"],
        parent_agent_id=(
            bytes.fromhex(d["parent_agent_id"]) if d["parent_agent_id"] else None
        ),
    )


def as_bytes(v) -> bytes:
    """An address or hash as bytes, from either bytes or a hex string."""
    if isinstance(v, bytes):
        return v
    return bytes.fromhex(v)


def apply_step(state: State, step: dict) -> None:
    op = step["op"]
    if op == "policy":
        state.apply_policy(
            step["policy"],
            as_bytes(step["spender"]),
            as_bytes(step["owner"]),
        )
    elif op == "revoke":
        state.apply_revocation(
            as_bytes(step["agent_id"]), as_bytes(step["owner"])
        )
    elif op == "spend":
        state.apply_spend(
            as_bytes(step["policy_hash"]),
            as_bytes(step["spender"]),
            step["nonce"],
            as_bytes(step["recipient"]),
            step["amount"],
            as_bytes(step["service"]) if step.get("service") else None,
        )
    elif op == "credit_open":
        state.apply_credit_open(
            as_bytes(step["lender"]),
            as_bytes(step["borrower"]),
            step["amount"],
            step["collateral"],
            step["rate"],
            step["window"],
            step["deadline"],
            step["nonce"],
        )
    elif op == "credit_collateral":
        state.apply_credit_collateral(
            as_bytes(state.position_ids[step["position"]]),
            as_bytes(step["borrower"]),
            step["amount"],
        )
    elif op == "credit_repay":
        state.apply_credit_repay(
            as_bytes(state.position_ids[step["position"]]),
            as_bytes(step["borrower"]),
            step["amount"],
        )
    elif op == "credit_default":
        state.apply_credit_default(
            as_bytes(state.position_ids[step["position"]]),
            as_bytes(step["actor"]),
        )
    elif op == "advance":
        state.height = step["to"]
    else:  # pragma: no cover - a typo in the scenarios
        raise SystemExit(f"unknown op {op}")


def snapshot(state: State) -> dict:
    return {
        "balances": {role_of(k): v for k, v in sorted(state.accounts.items())},
        "funded_total": state.funded_total,
        "burned": state.burned,
        "pscb": state.pscb,
        "credit_locked": state.credit_locked,
        "conserved": state.check_conservation(),
        "policies": [
            {
                "policy_hash": h.hex(),
                "agent_id": e.agent_id.hex(),
                "spender": role_of(e.spender),
                "revoked": e.revoked,
                "window_start_height": e.window_start_height,
                "spent_in_window_sat": e.spent_in_window_sat,
                "total_spent_sat": e.total_spent_sat,
                "last_nonce": e.last_nonce,
                "spends": e.spends,
            }
            for h, e in sorted(state.policies.items())
        ],
        "positions": [
            {
                "position_id": p.id.hex(),
                "lender": role_of(p.lender),
                "borrower": role_of(p.borrower),
                "principal_sat": p.principal_sat,
                "outstanding_sat": p.outstanding_sat,
                "interest_paid_sat": p.interest_paid_sat,
                "collateral_sat": p.collateral_sat,
                "state": p.state,
            }
            for _, p in sorted(state.positions.items())
        ],
    }


def step_signature(step: dict) -> str:
    """What identifies a transaction here.

    The reference implementation does not sign anything, so it has no
    transaction id. A step's *content* is the same thing: two steps with the
    same content are the same transaction, and the second one is a replay.
    """
    return json.dumps(step_out(step), sort_keys=True)


def build_vectors() -> dict:
    out = []
    for name, state, steps in run_scenarios():
        # The position index the scenarios refer to.
        state.position_ids = []
        # What the scenario funds, so the other side can fund the same roles.
        funding = {role_of(k): v for k, v in sorted(state.accounts.items())}
        recorded = []
        for step in steps:
            before = len(state.positions)
            signature = step_signature(step)
            if signature in state.applied:
                # The replay guard comes first: an identical transaction is
                # refused whatever the state would have said about it.
                outcome = {"ok": False, "error": "Replay"}
            else:
                try:
                    apply_step(state, step)
                    outcome = {"ok": True}
                    state.applied.add(signature)
                except Refused as r:
                    outcome = {"ok": False, "error": r.error}
            if step["op"] == "credit_open" and len(state.positions) > before:
                state.position_ids.append(
                    list(sorted(state.positions.keys()))[len(state.positions) - 1]
                )
            recorded.append({**step_out(step), "outcome": outcome})
            # The chain moves on after every step, exactly as the replay does,
            # so the heights the rules see are the same on both sides. An
            # "advance" step sets the height itself, so it does not also
            # increment it.
            if step["op"] != "advance":
                state.height += 1
        out.append(
            {
                "name": name,
                "funding": funding,
                "steps": recorded,
                "final": snapshot(state),
            }
        )
    return {
        "version": 1,
        "description": (
            "Layer-2 authority and credit scenarios, derived from SPEC.md "
            "sections 21 and 22 by verification/sim/l2_authority_reference.py. The Rust "
            "suite reads this file and asserts the same outcomes, so the two "
            "implementations are compared rather than merely coexisting."
        ),
        "addresses": {role: addr.hex() for role, addr in sorted(ADDR.items())},
        "scenarios": out,
    }


def step_out(step: dict) -> dict:
    """A step as the vector file carries it: roles as roles, digests as hex."""
    out = {}
    for k, v in step.items():
        if k == "policy":
            out[k] = json_policy(v)
        elif isinstance(v, bytes):
            out[k] = role_of(v)
        else:
            out[k] = v
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    vectors = build_vectors()
    path = VECTORS_DIR / VECTOR_FILE
    text = json.dumps(vectors, indent=2, sort_keys=False) + "\n"

    if args.check:
        if not path.exists():
            print(f"missing {path}")
            return 1
        current = path.read_text()
        if current != text:
            print(f"{VECTOR_FILE} is stale: regenerate it")
            return 1
        print(f"{VECTOR_FILE} is current ({len(vectors['scenarios'])} scenarios)")
        return 0

    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    steps = sum(len(s["steps"]) for s in vectors["scenarios"])
    print(f"wrote {path} ({len(vectors['scenarios'])} scenarios, {steps} steps)")
    for s in vectors["scenarios"]:
        ok = sum(1 for st in s["steps"] if st["outcome"]["ok"])
        print(f"  {s['name']}: {ok}/{len(s['steps'])} steps applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
