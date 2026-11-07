//! `delegation`: attenuated delegation chains (roadmap item 3).
//!
//! ```text
//! Owner ──▶ Agent ──▶ Sub-agent ──▶ ...
//! ```
//!
//! Each level inherits a **strict subset** of its parent's `SpendPolicy`. A
//! sub-agent cannot widen anything: not the per-transaction cap, not the
//! cumulative cap, not the recipient set, not the service set, not the expiry,
//! not the window. This module is the one place that rule lives, so the
//! narrowing is the same code everywhere and is audited once.
//!
//! ## Why domination, not inheritance-shaped-like
//!
//! The obvious implementation inherits *what is not overridden*. That is the
//! wrong default here: a child that sets nothing inherits everything, so the
//! safe configuration is silence, and a mistake reads as a narrower policy. The
//! check here is the opposite — **every field must be dominated, or the chain
//! is refused** — so the safe configuration is the default and widening is
//! impossible to do by omission.
//!
//! ## What this module is not
//!
//! Not a consensus rule, and not a new transaction type. The policy layer it
//! extends (`crate::agent`) is pure library and is not consulted by any
//! consensus path — nothing in `submit_at` reads a `PolicyBook`, and nothing
//! here changes that. Delegation narrows what an *offline* authorization may
//! grant; it decides no block's validity.
//!
//! ## The order of a chain
//!
//! A chain is a slice of policies, **root first**, ending at the policy that
//! will actually authorize a spend:
//!
//! ```text
//! [root, child, grandchild]   // grandchild spends, under both above it
//! ```
//!
//! `assert_chain` checks every adjacent pair with `dominates`, so the rule
//! composes: a chain is valid exactly when every link narrows.

use crate::agent::{AgentId, Authorization, AuthorizationRequest, PolicyBook, SpendPolicy};
use std::collections::BTreeMap;

/// Longest chain accepted. Bounded because a chain's verification cost is its
/// length, and an unbounded chain is a resource-exhaustion surface dressed up
/// as trust.
pub const MAX_DELEGATION_DEPTH: usize = 8;

/// Why a delegation was refused. Named and `PartialEq`, so a caller (and a
/// test) can assert the exact clause — the same discipline `agent::PolicyError`
/// follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    /// A refusal under the spending rule, passed through unchanged so the clause
    /// the spender hit is not flattened into a delegation-shaped one.
    Policy(crate::agent::PolicyError),
    /// The chain is empty. There is nothing to delegate.
    EmptyChain,
    /// The chain is longer than [`MAX_DELEGATION_DEPTH`].
    TooDeep { got: usize, cap: usize },
    /// A child policy carries no parent link, so it is a root and cannot be
    /// anyone's child.
    ChildHasNoParent,
    /// The child's parent link does not name the policy above it in the chain.
    WrongParentLink { expected: AgentId, got: AgentId },
    /// A child would not be dominated by its parent on some field.
    NotDominated(&'static str),
    /// The child's network differs from the parent's. A delegate cannot hop
    /// networks mid-chain.
    NetworkMismatch { parent: String, child: String },
    /// The child's owner differs from the parent's. Delegation attenuates one
    /// owner's authority; it does not create a co-spender.
    OwnerMismatch,
    /// The child's role differs from the parent's. A role names the *kind* of
    /// authority; delegation redistributes authority, it does not convert a
    /// spender into a receiver.
    RoleMismatch,
    /// The child's identity is not `derive_sub_agent_id(parent, role)` — its
    /// bytes claim a parent it is not derived from.
    IdentityMismatch,
    /// The child's window is longer than the parent's, so a budget period could
    /// outlive the one that grants it.
    WindowWidened { parent: u64, child: u64 },
    /// The child's per-transaction cap exceeds the parent's.
    PerTxWidened { parent: u64, child: u64 },
    /// The child's cumulative cap exceeds the parent's.
    CumulativeWidened { parent: u64, child: u64 },
    /// The child activates before its parent does.
    StartsEarlier { parent: u64, child: u64 },
    /// The child outlives its parent.
    OutlivesParent { parent: u64, child: u64 },
    /// The child allows a recipient the parent does not.
    RecipientWidened,
    /// The child allows a service tag the parent does not.
    ServiceWidened,
    /// An ancestor of this policy is revoked, so the whole chain is dead. The
    /// root's kill switch has to reach every leaf.
    AncestorRevoked { at: AgentId },
    /// Registering this link twice, or a second lineage for one agent id.
    AlreadyLinked,
}

impl std::fmt::Display for DelegationError {
    /// A named refusal, so every caller — a payment, a node, an operator —
    /// reports the clause that was actually violated rather than "invalid".
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationError::Policy(e) => write!(f, "policy refused: {e}"),
            DelegationError::EmptyChain => write!(f, "delegation chain is empty"),
            DelegationError::TooDeep { got, cap } => {
                write!(f, "delegation chain depth {got} exceeds cap {cap}")
            }
            DelegationError::ChildHasNoParent => {
                write!(f, "a root policy cannot be anyone's child")
            }
            DelegationError::WrongParentLink { expected, got } => write!(
                f,
                "parent link names {} but the policy above it is {}",
                hex(expected),
                hex(got)
            ),
            DelegationError::NotDominated(w) => {
                write!(f, "child is not dominated by its parent: {w}")
            }
            DelegationError::NetworkMismatch { parent, child } => {
                write!(f, "child is on network {child}, parent on {parent}")
            }
            DelegationError::OwnerMismatch => write!(f, "child has a different owner"),
            DelegationError::RoleMismatch => write!(f, "child has a different role"),
            DelegationError::IdentityMismatch => {
                write!(f, "child id is not derived from the parent it names")
            }
            DelegationError::WindowWidened { parent, child } => {
                write!(f, "window {child} is wider than the parent's {parent}")
            }
            DelegationError::PerTxWidened { parent, child } => write!(
                f,
                "per-transaction cap {child} exceeds the parent's {parent}"
            ),
            DelegationError::CumulativeWidened { parent, child } => {
                write!(f, "cumulative cap {child} exceeds the parent's {parent}")
            }
            DelegationError::StartsEarlier { parent, child } => {
                write!(f, "child starts at {child}, before the parent's {parent}")
            }
            DelegationError::OutlivesParent { parent, child } => {
                write!(f, "child expires at {parent}, after the parent's {child}")
            }
            DelegationError::RecipientWidened => {
                write!(f, "child allows a recipient the parent does not")
            }
            DelegationError::ServiceWidened => {
                write!(f, "child allows a service the parent does not")
            }
            DelegationError::AncestorRevoked { at } => {
                write!(f, "an ancestor {} is revoked", hex(at))
            }
            DelegationError::AlreadyLinked => {
                write!(f, "this child is already linked under another lineage")
            }
        }
    }
}

impl std::error::Error for DelegationError {}

/// Short hex for a message. Full ids are not worth half a line of output.
fn hex(id: &AgentId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// True when every field of `child` is inside every field of `parent`.
///
/// Field by field, and each check independent, because "narrower on average" is
/// not a thing: a child with a tighter per-transaction cap but a *longer* window
/// can out-spend its parent, and a child that allows a recipient the parent
/// revoked must be refused even if every number is smaller.
///
/// The rule set, and the refusal clause for each:
///
/// | Field | Rule |
/// |---|---|
/// | `version` | equal (the chain speaks one encoding) |
/// | `network_id` | equal — no network hopping mid-chain |
/// | `owner` | equal — delegation is one owner's authority, attenuated |
/// | `role` | equal — delegation does not change what kind of actor spends |
/// | `agent_id` | the child derives from the parent ([`crate::agent::derive_sub_agent_id`]) |
/// | `parent_agent_id` | names the parent the child is being checked against |
/// | `window_blocks` | child ≤ parent |
/// | `per_tx_max_sat` | child ≤ parent |
/// | `cumulative_max_sat` | child ≤ parent |
/// | `not_before_height` | child ≥ parent |
/// | `expires_at_height` | child ≤ parent |
/// | `allowed_recipients` | child ⊆ parent |
/// | `allowed_services` | child ⊆ parent |
/// | `revoked` | both live (handled by the caller holding the chain) |
///
/// Note what the subset rule means for an empty child list: an empty
/// `allowed_recipients` is a subset of anything, and it authorizes nothing. A
/// useless child is legal; a wider one is not.
pub fn dominates(parent: &SpendPolicy, child: &SpendPolicy) -> Result<(), DelegationError> {
    if parent.version != child.version {
        return Err(DelegationError::NotDominated("version"));
    }
    if parent.network_id != child.network_id {
        return Err(DelegationError::NetworkMismatch {
            parent: parent.network_id.clone(),
            child: child.network_id.clone(),
        });
    }
    if parent.owner != child.owner {
        return Err(DelegationError::OwnerMismatch);
    }
    if parent.role != child.role {
        return Err(DelegationError::RoleMismatch);
    }
    // The child must actually be derived from this parent. A chain is only as
    // trustworthy as the links its bytes claim.
    match child.parent_agent_id {
        None => return Err(DelegationError::ChildHasNoParent),
        Some(link) => {
            if link != parent.agent_id {
                return Err(DelegationError::WrongParentLink {
                    expected: parent.agent_id,
                    got: link,
                });
            }
        }
    }
    let expected =
        crate::agent::derive_sub_agent_id(&child.network_id, &parent.agent_id, child.role);
    if expected != child.agent_id {
        return Err(DelegationError::IdentityMismatch);
    }
    if child.window_blocks > parent.window_blocks {
        return Err(DelegationError::WindowWidened {
            parent: parent.window_blocks,
            child: child.window_blocks,
        });
    }
    if child.per_tx_max_sat > parent.per_tx_max_sat {
        return Err(DelegationError::PerTxWidened {
            parent: parent.per_tx_max_sat,
            child: child.per_tx_max_sat,
        });
    }
    if child.cumulative_max_sat > parent.cumulative_max_sat {
        return Err(DelegationError::CumulativeWidened {
            parent: parent.cumulative_max_sat,
            child: child.cumulative_max_sat,
        });
    }
    if child.not_before_height < parent.not_before_height {
        return Err(DelegationError::StartsEarlier {
            parent: parent.not_before_height,
            child: child.not_before_height,
        });
    }
    if child.expires_at_height > parent.expires_at_height {
        return Err(DelegationError::OutlivesParent {
            parent: parent.expires_at_height,
            child: child.expires_at_height,
        });
    }
    for r in &child.allowed_recipients {
        if !parent.allowed_recipients.contains(r) {
            return Err(DelegationError::RecipientWidened);
        }
    }
    for s in &child.allowed_services {
        if !parent.allowed_services.contains(s) {
            return Err(DelegationError::ServiceWidened);
        }
    }
    Ok(())
}

/// A whole chain, root first, checked link by link.
///
/// Every policy is checked against its parent with [`dominates`], and the whole
/// chain is refused if any policy in it is revoked — an ancestor's kill switch
/// must reach its leaves, or a chain is only as strong as its root at the moment
/// it was formed.
///
/// The chain's length is bounded by [`MAX_DELEGATION_DEPTH`] because verification
/// cost is proportional to it: an unbounded chain lets a caller choose the
/// verifier's work.
pub fn assert_chain(chain: &[&SpendPolicy]) -> Result<(), DelegationError> {
    if chain.is_empty() {
        return Err(DelegationError::EmptyChain);
    }
    if chain.len() > MAX_DELEGATION_DEPTH {
        return Err(DelegationError::TooDeep {
            got: chain.len(),
            cap: MAX_DELEGATION_DEPTH,
        });
    }
    for policy in chain {
        if policy.revoked {
            return Err(DelegationError::AncestorRevoked {
                at: policy.agent_id,
            });
        }
    }
    for pair in chain.windows(2) {
        dominates(pair[0], pair[1])?;
    }
    Ok(())
}

/// The recorded shape of delegation: which policy is whose child.
///
/// The book exists for the question a chain alone cannot answer — *is this link
/// already spoken for?* A child policy can be presented under two different
/// chains, and without a registry nothing notices that one agent id now has two
/// lineages. The book refuses a second registration of the same child, and
/// refuses a link that would make a chain its own ancestor.
#[derive(Debug, Clone, Default)]
pub struct DelegationBook {
    /// child policy hash → parent policy hash.
    parents: BTreeMap<[u8; 32], [u8; 32]>,
    /// child agent id → child policy hash, so one agent cannot appear twice.
    agents: BTreeMap<AgentId, [u8; 32]>,
    /// Every recorded policy, keyed by its own hash.
    ///
    /// The book is not a table of hashes: to answer "does this chain still hold?"
    /// a node has to walk *policies*, and a walk that only has hashes can be fed
    /// a chain it never saw. Storing the bytes beside the link means the chain a
    /// node reconstructs is made of policies it recorded, each of which still
    /// hashes to the key it is stored under.
    policies: BTreeMap<[u8; 32], SpendPolicy>,
}

impl DelegationBook {
    pub fn new() -> Self {
        DelegationBook::default()
    }

    /// How many links are registered.
    pub fn len(&self) -> usize {
        self.parents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parents.is_empty()
    }

    /// Record a **root** policy — one whose owner authorized it directly, with
    /// no parent. A root has no link to check, so structural soundness is
    /// checked here instead: a malformed or versioned-out root is refused
    /// rather than stored, so the registry only ever holds policies the
    /// node verified.
    pub fn record_root(&mut self, policy: &SpendPolicy) -> Result<(), DelegationError> {
        policy.validate().map_err(DelegationError::Policy)?;
        self.policies.insert(policy.hash(), policy.clone());
        Ok(())
    }

    /// Every policy this book has recorded, root-first by hash order.
    ///
    /// Used by a node to answer a chain-request from its own records rather than
    /// trusting the caller's bytes.
    pub fn recorded(&self) -> impl Iterator<Item = &SpendPolicy> {
        self.policies.values()
    }

    /// Register that `child` (keyed by its policy hash) descends from `parent`.
    ///
    /// Refuses a duplicate child and a second lineage for one agent id — a
    /// child policy can be presented under two different chains, and without a
    /// registry nothing notices that a single agent now has two ancestries. It
    /// also enforces the depth cap on registration, so a chain that is too long
    /// is never recorded rather than checked later.
    ///
    /// A *cycle* needs no check here: [`dominates`] requires the child to derive
    /// from the parent it names, and that derivation is one-way — a set of
    /// policies that approve of each other as parent and child is not
    /// constructible, because the ids do not close into a loop. The book's job
    /// is the questions a chain cannot answer alone; this is not one of them.
    pub fn link(
        &mut self,
        parent: &SpendPolicy,
        child: &SpendPolicy,
    ) -> Result<(), DelegationError> {
        dominates(parent, child)?;
        let parent_hash = parent.hash();
        let child_hash = child.hash();
        if self.parents.contains_key(&child_hash) {
            return Err(DelegationError::AlreadyLinked);
        }
        // One agent id, one lineage. Re-negotiating the parent is how an agent
        // would get a second set of ancestors, and nothing would settle which
        // chain it actually belongs to.
        if let Some(existing) = self.agents.get(&child.agent_id) {
            if existing != &child_hash {
                return Err(DelegationError::AlreadyLinked);
            }
        }
        self.parents.insert(child_hash, parent_hash);
        self.agents.insert(child.agent_id, child_hash);
        // The bytes are recorded with the link so the chain can be walked later
        // out of the book's own records rather than out of a caller's memory.
        self.policies.insert(parent_hash, parent.clone());
        self.policies.insert(child_hash, child.clone());
        // Depth is enforced here, not only at inspection: a walk bounded by the
        // same cap cannot be stalled by a pathological registration order.
        let depth = self.depth_of(child);
        if depth > MAX_DELEGATION_DEPTH {
            self.parents.remove(&child_hash);
            self.agents.remove(&child.agent_id);
            self.policies.remove(&child_hash);
            return Err(DelegationError::TooDeep {
                got: depth,
                cap: MAX_DELEGATION_DEPTH,
            });
        }
        Ok(())
    }

    /// The registered parent of a policy, if any.
    pub fn parent_of(&self, child: &SpendPolicy) -> Option<[u8; 32]> {
        self.parents.get(&child.hash()).copied()
    }

    /// How many registered ancestors a policy has. `0` for an unregistered one.
    pub fn depth_of(&self, child: &SpendPolicy) -> usize {
        let mut cursor = child.hash();
        let mut depth = 0usize;
        while let Some(next) = self.parents.get(&cursor) {
            cursor = *next;
            depth += 1;
            if depth > MAX_DELEGATION_DEPTH {
                break;
            }
        }
        depth
    }

    /// The ancestry a node can prove for `child`, oldest first, or `None` if the
    /// recorded links do not reach a root.
    ///
    /// This is the difference between a chain a node *trusts* and a chain a node
    /// was *handed*: the walk visits recorded policies only, so a link that was
    /// never registered cannot be manufactured by presenting bytes. A walk that
    /// runs into the depth cap or an unrecorded parent returns `None` — the
    /// chain is unprovable, which is the same answer as "there is none".
    pub fn chain_of(&self, child: &SpendPolicy) -> Option<Vec<SpendPolicy>> {
        let mut out: Vec<SpendPolicy> = vec![child.clone()];
        let mut cursor = child.hash();
        for _ in 0..=MAX_DELEGATION_DEPTH {
            let Some(parent_hash) = self.parents.get(&cursor).copied() else {
                // No registered parent: the walk reached the head of the chain.
                // It is only a root if the policy itself says so.
                if out.len() > 1 || child.parent_agent_id.is_none() {
                    out.reverse();
                    return Some(out);
                }
                return None;
            };
            let parent = self.policies.get(&parent_hash)?.clone();
            if parent.hash() != parent_hash {
                return None;
            }
            if parent.parent_agent_id.is_none() {
                out.push(parent);
                out.reverse();
                return Some(out);
            }
            out.push(parent);
            cursor = parent_hash;
        }
        None
    }

    /// Every recorded policy that descends from `parent_hash`, the parent's own
    /// hash included.
    ///
    /// Revocation propagation needs exactly this: killing an ancestor has to
    /// reach every link below it, and the only way to know what is below it is
    /// to walk the recorded edges. Bounded by the book's own size.
    pub fn descendants_of(&self, parent_hash: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut out = vec![*parent_hash];
        let mut frontier = vec![*parent_hash];
        while let Some(current) = frontier.pop() {
            for (child, parent) in &self.parents {
                if *parent == current && !out.contains(child) {
                    out.push(*child);
                    frontier.push(*child);
                }
            }
        }
        out
    }

    /// Whether the book has a recorded link below `parent_hash`. Used to tell an
    /// operator that revoking a policy will (or will not) affect anyone else.
    pub fn has_descendants(&self, parent_hash: &[u8; 32]) -> bool {
        self.parents.values().any(|p| p == parent_hash)
    }
}

/// Largest entry count the delegation-book codec will read back per map.
/// Checked before any allocation; real books hold one link per delegated
/// policy, far below this.
const MAX_DELEGATION_READ: usize = 1 << 20;

/// Restart recovery for the whole book: the recorded lineage links, the agent
/// ids they belong to, and the policy bytes each link was proven against.
///
/// The book is node-local and non-consensus, but losing it loses who descends
/// from whom - a node would re-admit a chain it had already refused. The
/// encoding stores all three maps and, on the way back, re-checks the
/// invariants [`DelegationBook::link`] maintains: every stored policy hashes
/// to the key it is stored under, and no link or agent entry names a policy
/// the book does not hold.
impl DelegationBook {
    /// Canonical encoding of the whole book: policies first, then the links
    /// and agent entries that name them, so the decoder can re-check every
    /// reference as it reads.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(
            12 + self.parents.len() * 64 + self.policies.len() * 256,
        );
        w.u32le(self.policies.len() as u32);
        for (hash, policy) in &self.policies {
            w.fixed(hash);
            let bytes = policy.serialize();
            w.u32le(bytes.len() as u32).raw(&bytes);
        }
        w.u32le(self.parents.len() as u32);
        for (child, parent) in &self.parents {
            w.fixed(child).fixed(parent);
        }
        w.u32le(self.agents.len() as u32);
        for (agent, child) in &self.agents {
            w.fixed(agent).fixed(child);
        }
        w.into_vec()
    }

    /// Decode what [`DelegationBook::encode`] wrote. Bounded and fail-closed:
    /// a count above the cap, a policy that does not decode or hashes to a
    /// different key, a link naming a policy the book does not hold, or
    /// trailing bytes produce an error rather than a half-built book.
    pub fn decode(r: &mut crate::ser::Reader<'_>) -> Result<Self, crate::error::Error> {
        use crate::error::Error;
        let malformed = Error::Malformed;

        let policy_count = r.u32le()? as usize;
        if policy_count > MAX_DELEGATION_READ {
            return Err(malformed("policy count over codec cap"));
        }
        let mut book = DelegationBook::new();
        for _ in 0..policy_count {
            let hash: [u8; 32] = r.fixed()?;
            let len = r.u32le()? as usize;
            let bytes = r.fixed_slice(len)?;
            let policy = SpendPolicy::deserialize(bytes)
                .map_err(|_| malformed("stored policy does not decode"))?;
            if policy.hash() != hash {
                return Err(malformed("stored policy hashes to another key"));
            }
            book.policies.insert(hash, policy);
        }
        if book.policies.len() != policy_count {
            return Err(malformed("duplicate policy in book"));
        }

        let link_count = r.u32le()? as usize;
        if link_count > MAX_DELEGATION_READ {
            return Err(malformed("link count over codec cap"));
        }
        for _ in 0..link_count {
            let child: [u8; 32] = r.fixed()?;
            let parent: [u8; 32] = r.fixed()?;
            // `link` records both endpoints beside every edge; a link whose
            // policy is missing cannot be walked back to what it descends from.
            if !book.policies.contains_key(&child) || !book.policies.contains_key(&parent) {
                return Err(malformed("link names a policy the book does not hold"));
            }
            if book.parents.insert(child, parent).is_some() {
                return Err(malformed("duplicate link for one child"));
            }
        }

        let agent_count = r.u32le()? as usize;
        if agent_count > MAX_DELEGATION_READ {
            return Err(malformed("agent count over codec cap"));
        }
        for _ in 0..agent_count {
            let agent: AgentId = r.fixed()?;
            let child: [u8; 32] = r.fixed()?;
            // `link` writes the agent entry only for a child it also linked.
            if !book.parents.contains_key(&child) {
                return Err(malformed("agent entry without a link"));
            }
            if book.agents.insert(agent, child).is_some() {
                return Err(malformed("duplicate agent id"));
            }
        }
        Ok(book)
    }
}

/// Authorize a spend at the end of a delegation chain.
///
/// The composition is deliberate: this function owns the chain, and
/// [`PolicyBook`] owns the spending rule (caps, windows, nonces). Neither learns
/// the other's business, so there is no second implementation of either — the
/// narrowing rule is `delegation`'s and the budget rule is `agent`'s, and they
/// compose in exactly one place.
///
/// Order matters: the chain is proven *before* any accounting is committed, so a
/// refused delegation leaves the policy book exactly as it was.
pub fn authorize_with_chain(
    book: &mut PolicyBook,
    chain: &[&SpendPolicy],
    network_id: &str,
    req: &AuthorizationRequest,
) -> Result<Authorization, DelegationError> {
    assert_chain(chain)?;
    let spend = chain.last().copied().ok_or(DelegationError::EmptyChain)?;
    book.authorize(spend, network_id, req)
        .map_err(DelegationError::Policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{derive_agent_id, derive_sub_agent_id, AgentRole, POLICY_VERSION};

    const NET: &str = "srct/testnet";

    fn owner() -> crate::hash::Address {
        [7u8; 20]
    }

    /// A root policy: full collateral-free-for-nothing spending envelope, wide
    /// enough that any child below it is meaningfully narrower.
    fn root() -> SpendPolicy {
        SpendPolicy {
            version: POLICY_VERSION,
            network_id: NET.to_string(),
            agent_id: [0u8; 20],
            owner: owner(),
            role: AgentRole::Machine,
            per_tx_max_sat: 1_000,
            window_blocks: 100,
            cumulative_max_sat: 5_000,
            allowed_recipients: vec![[1u8; 20], [2u8; 20], [3u8; 20]],
            allowed_services: vec![[4u8; 32], [5u8; 32]],
            not_before_height: 10,
            expires_at_height: 1_000,
            revoked: false,
            parent_agent_id: None,
        }
    }

    /// A child of `parent`, narrowed on every field the parent can narrow.
    fn child_of(parent: &SpendPolicy) -> SpendPolicy {
        let agent_id = derive_sub_agent_id(&parent.network_id, &parent.agent_id, parent.role);
        SpendPolicy {
            agent_id,
            parent_agent_id: Some(parent.agent_id),
            per_tx_max_sat: parent.per_tx_max_sat / 2,
            window_blocks: parent.window_blocks / 2,
            cumulative_max_sat: parent.cumulative_max_sat / 2,
            allowed_recipients: parent.allowed_recipients[..1].to_vec(),
            allowed_services: parent.allowed_services[..1].to_vec(),
            not_before_height: parent.not_before_height + 5,
            expires_at_height: parent.expires_at_height - 5,
            ..parent.clone()
        }
    }

    fn grandchild_of(parent: &SpendPolicy) -> SpendPolicy {
        child_of(parent)
    }

    fn req(agent: AgentId, amount: u64, height: u64, nonce: u64) -> AuthorizationRequest {
        AuthorizationRequest {
            agent_id: agent,
            recipient: [1u8; 20],
            amount_sat: amount,
            service: Some([4u8; 32]),
            height,
            nonce,
        }
    }

    #[test]
    fn a_wellformed_chain_is_dominated_link_by_link() {
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let c = child_of(&r);
        assert_eq!(dominates(&r, &c), Ok(()));
        let g = grandchild_of(&c);
        assert_eq!(dominates(&c, &g), Ok(()));
        assert_chain(&[&r, &c, &g]).unwrap();
    }

    #[test]
    fn no_child_may_widen_anything() {
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);

        // Every widening is a named refusal, not a general one, so the clause a
        // spender hit is the clause it actually broke.
        let mut c = child_of(&r);
        c.per_tx_max_sat = r.per_tx_max_sat + 1;
        assert_eq!(
            dominates(&r, &c),
            Err(DelegationError::PerTxWidened {
                parent: 1_000,
                child: 1_001,
            })
        );

        let mut c = child_of(&r);
        c.cumulative_max_sat = r.cumulative_max_sat + 1;
        assert_eq!(
            dominates(&r, &c),
            Err(DelegationError::CumulativeWidened {
                parent: 5_000,
                child: 5_001
            })
        );

        let mut c = child_of(&r);
        c.window_blocks = r.window_blocks + 1;
        assert_eq!(
            dominates(&r, &c),
            Err(DelegationError::WindowWidened {
                parent: 100,
                child: 101
            })
        );

        let mut c = child_of(&r);
        c.not_before_height = r.not_before_height - 1;
        assert_eq!(
            dominates(&r, &c),
            Err(DelegationError::StartsEarlier {
                parent: 10,
                child: 9
            })
        );

        let mut c = child_of(&r);
        c.expires_at_height = r.expires_at_height + 1;
        assert_eq!(
            dominates(&r, &c),
            Err(DelegationError::OutlivesParent {
                parent: 1_000,
                child: 1_001
            })
        );

        let mut c = child_of(&r);
        c.allowed_recipients.push([9u8; 20]);
        assert_eq!(dominates(&r, &c), Err(DelegationError::RecipientWidened));

        let mut c = child_of(&r);
        c.allowed_services.push([9u8; 32]);
        assert_eq!(dominates(&r, &c), Err(DelegationError::ServiceWidened));
    }

    #[test]
    fn a_child_cannot_change_owner_role_or_network() {
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);

        // A different owner is a co-spender, not a delegate: the parent's
        // authority ends where the parent's owner's does.
        let mut c = child_of(&r);
        c.owner = [8u8; 20];
        assert_eq!(dominates(&r, &c), Err(DelegationError::OwnerMismatch));

        // A different role converts a spender into a receiver, which is a
        // different authority, not a narrower one.
        let mut c = child_of(&r);
        c.role = AgentRole::Service;
        assert_eq!(dominates(&r, &c), Err(DelegationError::RoleMismatch));

        let mut c = child_of(&r);
        c.network_id = "srct/mini".to_string();
        assert_eq!(
            dominates(&r, &c),
            Err(DelegationError::NetworkMismatch {
                parent: NET.to_string(),
                child: "srct/mini".to_string()
            })
        );
    }

    #[test]
    fn a_child_must_be_derived_from_the_parent_it_names() {
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);

        // Claiming a parent it is not derived from: the link is a lie.
        let mut c = child_of(&r);
        c.parent_agent_id = Some([42u8; 20]);
        assert_eq!(
            dominates(&r, &c),
            Err(DelegationError::WrongParentLink {
                expected: r.agent_id,
                got: [42u8; 20]
            })
        );

        // Naming the right parent but deriving the id from anything else.
        let mut c = child_of(&r);
        c.agent_id = derive_agent_id(NET, AgentRole::Machine, &c.owner);
        assert_eq!(dominates(&r, &c), Err(DelegationError::IdentityMismatch));

        // A root policy is not a child of anything, whatever it claims.
        let mut c = child_of(&r);
        c.parent_agent_id = None;
        assert_eq!(dominates(&r, &c), Err(DelegationError::ChildHasNoParent));
    }

    #[test]
    fn a_narrower_child_that_widens_one_field_is_refused() {
        // The average-is-narrower trap: smaller on four fields, wider on the
        // fifth. Each field is independent, so the fifth refuses.
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let mut c = child_of(&r);
        c.per_tx_max_sat = 10;
        c.cumulative_max_sat = 100;
        c.window_blocks = 1;
        c.allowed_recipients = vec![];
        // But the child now allows a recipient the parent does not.
        c.allowed_recipients.push([9u8; 20]);
        assert_eq!(dominates(&r, &c), Err(DelegationError::RecipientWidened));
    }

    #[test]
    fn an_empty_child_list_authorizes_nothing_and_is_still_a_subset() {
        // The one widening that narrows: an empty set is inside any set, and it
        // allows nothing. Useless, not unsafe.
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let mut c = child_of(&r);
        c.allowed_recipients = vec![];
        c.allowed_services = vec![];
        assert_eq!(dominates(&r, &c), Ok(()));
    }

    #[test]
    fn a_revoked_ancestor_kills_the_whole_chain() {
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let mut c = child_of(&r);
        c.revoked = true;
        let g_below_revoked = grandchild_of(&c);
        assert_eq!(
            assert_chain(&[&r, &c, &g_below_revoked]),
            Err(DelegationError::AncestorRevoked { at: c.agent_id })
        );
        // With the child un-revoked the same chain is fine, so it is the
        // revocation and not the shape that refused it.
        c.revoked = false;
        let g = grandchild_of(&c);
        assert_chain(&[&r, &c, &g]).unwrap();
        // The root's kill switch reaches the leaf too.
        let mut r2 = r.clone();
        r2.revoked = true;
        assert_eq!(
            assert_chain(&[&r2, &c, &g]),
            Err(DelegationError::AncestorRevoked { at: r2.agent_id })
        );
    }

    #[test]
    fn a_chain_cannot_be_empty_or_unbounded() {
        assert_eq!(assert_chain(&[]), Err(DelegationError::EmptyChain));
        // A chain deeper than the cap is refused whatever its shape: the
        // verifier's work must not be the caller's choice.
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let mut policies = vec![r.clone()];
        let mut parent = r;
        let mut extra = 0usize;
        loop {
            let c = child_of(&parent);
            policies.push(c.clone());
            parent = c;
            extra += 1;
            if extra >= MAX_DELEGATION_DEPTH {
                break;
            }
        }
        let refs: Vec<&SpendPolicy> = policies.iter().collect();
        assert_eq!(
            assert_chain(&refs),
            Err(DelegationError::TooDeep {
                got: MAX_DELEGATION_DEPTH + 1,
                cap: MAX_DELEGATION_DEPTH
            })
        );
    }

    #[test]
    fn the_delegation_book_survives_restart_round_trip() {
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let c = child_of(&r);
        let mut book = DelegationBook::new();
        book.link(&r, &c).unwrap();

        let bytes = book.encode();
        let mut cursor = crate::ser::Reader::new(&bytes);
        let back = DelegationBook::decode(&mut cursor).expect("book decodes");
        assert!(cursor.is_done(), "decode must consume exactly its bytes");
        assert_eq!(back.encode(), bytes, "re-encode must be byte-identical");
        assert_eq!(back.len(), 1);
        assert_eq!(back.parent_of(&c), book.parent_of(&c));
        assert_eq!(back.chain_of(&c), book.chain_of(&c));
        assert_eq!(back.depth_of(&c), book.depth_of(&c));
        assert!(back.has_descendants(&r.hash()));

        // Policy bytes that hash to another key are refused: the last byte of
        // the last (policy) section is either a decode failure or a key
        // mismatch, and both are refusals.
        let mut lying = bytes.clone();
        *lying.last_mut().unwrap() ^= 0xFF;
        assert!(DelegationBook::decode(&mut crate::ser::Reader::new(&lying)).is_err());
    }

    #[test]
    fn a_link_cannot_reparent_or_be_its_own_ancestor() {
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let c = child_of(&r);
        let mut book = DelegationBook::new();
        book.link(&r, &c).unwrap();
        assert_eq!(book.depth_of(&c), 1);

        // Re-parenting the root under its own child fails the link check: the
        // root names no parent, and a child must name the policy above it.
        assert!(book.link(&c, &r).is_err());

        // A duplicate link is refused by name, not by a general error.
        assert_eq!(book.link(&r, &c), Err(DelegationError::AlreadyLinked));

        // The same agent re-issuing its policy is a second lineage: the ids
        // match but the policies differ, and nothing settles which one the
        // agent spends under.
        let reissued = SpendPolicy {
            revoked: true,
            ..c.clone()
        };
        assert_eq!(
            book.link(&r, &reissued),
            Err(DelegationError::AlreadyLinked)
        );
        assert_eq!(book.len(), 1, "only the honest link is registered");
    }

    #[test]
    fn the_book_refuses_a_chain_deeper_than_the_cap() {
        // The cap is enforced at registration, so an over-long chain is never
        // recorded: the walk that inspects depth cannot be stalled by the order
        // links arrive in.
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let mut book = DelegationBook::new();
        let mut parent = r;
        let mut depth = 0usize;
        loop {
            let c = child_of(&parent);
            if depth < MAX_DELEGATION_DEPTH {
                book.link(&parent, &c).unwrap();
                depth += 1;
            } else {
                assert_eq!(
                    book.link(&parent, &c),
                    Err(DelegationError::TooDeep {
                        got: MAX_DELEGATION_DEPTH + 1,
                        cap: MAX_DELEGATION_DEPTH
                    })
                );
                break;
            }
            parent = c;
        }
        assert_eq!(book.len(), MAX_DELEGATION_DEPTH);
    }

    #[test]
    fn a_spend_at_the_end_of_a_chain_is_authorized_under_every_cap_above_it() {
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let c = child_of(&r);
        let g = grandchild_of(&c);
        // The leaf's own envelope: a quarter of the root's per transaction, and
        // an eighth of its cumulative. The chain is what the spender sees.
        assert_eq!(g.per_tx_max_sat, 250);
        assert_eq!(g.cumulative_max_sat, 1_250);

        let mut book = PolicyBook::default();
        let mut delegation = DelegationBook::new();
        delegation.link(&r, &c).unwrap();
        delegation.link(&c, &g).unwrap();

        let auth =
            authorize_with_chain(&mut book, &[&r, &c, &g], NET, &req(g.agent_id, 100, 200, 1))
                .unwrap();
        assert_eq!(auth.agent_id, g.agent_id);
        assert_eq!(
            auth.owner, r.owner,
            "the root owner's authority, attenuated"
        );

        // A broken chain refuses before any accounting is committed: the window
        // did not move and the nonce is still available.
        let mut widened = grandchild_of(&c);
        widened.cumulative_max_sat = 9_999;
        let err = authorize_with_chain(
            &mut book,
            &[&r, &c, &widened],
            NET,
            &req(widened.agent_id, 100, 200, 2),
        );
        assert!(err.is_err());
        assert_eq!(book.state(&g.hash()).unwrap().authorizations, 1);

        // And a legitimate spend on the honest chain still works afterwards.
        let auth2 =
            authorize_with_chain(&mut book, &[&r, &c, &g], NET, &req(g.agent_id, 100, 200, 2))
                .unwrap();
        assert_eq!(auth2.nonce, 2);
    }

    #[test]
    fn a_spend_the_leaf_policy_allows_but_the_chain_does_not_is_refused() {
        // The point of the whole module: the leaf alone would permit this, the
        // chain above it does not, and the chain wins.
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        // A child narrowed to a recipient the parent allows.
        let mut c = child_of(&r);
        c.allowed_recipients = vec![[1u8; 20]];
        // A leaf that claims to allow a recipient the parent does not.
        let mut g = grandchild_of(&c);
        g.allowed_recipients = vec![[9u8; 20]];
        g.agent_id = derive_sub_agent_id(&g.network_id, &c.agent_id, g.role);
        assert_eq!(
            dominates(&c, &g),
            Err(DelegationError::RecipientWidened),
            "the leaf cannot widen the recipient set"
        );
        // And the spend request itself names a recipient only the leaf allows.
        let mut bad_req = req(g.agent_id, 100, 200, 1);
        bad_req.recipient = [9u8; 20];
        let mut book = PolicyBook::default();
        let err = authorize_with_chain(&mut book, &[&r, &c, &g], NET, &bad_req);
        assert!(err.is_err());
    }

    #[test]
    fn a_chain_that_never_narrows_is_still_a_chain() {
        // Equal is dominated: a child identical to its parent is a valid (if
        // pointless) delegate, so equality is not refused as widening. What is
        // refused is strictly more.
        let mut r = root();
        r.agent_id = derive_agent_id(NET, AgentRole::Machine, &r.owner);
        let mut c = child_of(&r);
        c.per_tx_max_sat = r.per_tx_max_sat;
        c.cumulative_max_sat = r.cumulative_max_sat;
        c.window_blocks = r.window_blocks;
        c.not_before_height = r.not_before_height;
        c.expires_at_height = r.expires_at_height;
        c.allowed_recipients = r.allowed_recipients.clone();
        c.allowed_services = r.allowed_services.clone();
        assert_eq!(dominates(&r, &c), Ok(()));
        assert_chain(&[&r, &c]).unwrap();
    }
}
