//! Provenance graph and automatic royalty settlement.
//!
//! Registration enforces lineage integrity: signatures, network, existing and
//! reusable parents, parents no newer than the child, and no replays. Cycles
//! are impossible by construction — every parent must already be registered,
//! and artifact hashes commit to their parent list, so no registered artifact
//! can reach back to a new one. Revenue on an artifact flows upstream recursively:
//! each artifact keeps its share minus its licensed royalty, the royalty pool
//! splits equally among its direct parents, dust stays with the child owner,
//! and the walk stops at [`crate::artifact::MAX_ROYALTY_DEPTH`]. Every split
//! sums exactly to the revenue in.

use std::collections::{BTreeMap, BTreeSet};

use srct_core::hash::{Address, Hash};

use crate::artifact::{SignedArtifact, MAX_ROYALTY_DEPTH};
use crate::WorkError;

/// The provenance book for one network. Stores signed registrations only;
///
/// content lives with its owner, proofs with their issuing crates.
#[derive(Clone, Debug, Default)]
pub struct WorkGraph {
    network_id: String,
    artifacts: BTreeMap<Hash, SignedArtifact>,
}

impl WorkGraph {
    pub fn new(network_id: impl Into<String>) -> Self {
        WorkGraph {
            network_id: network_id.into(),
            artifacts: BTreeMap::new(),
        }
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn get(&self, hash: &Hash) -> Option<&SignedArtifact> {
        self.artifacts.get(hash)
    }

    /// Register an artifact. Refuses bad signatures, wrong networks, unknown
    /// or non-reusable parents, self-parenting, parents newer than the child,
    /// and replays.
    pub fn register(&mut self, artifact: &SignedArtifact) -> Result<Hash, WorkError> {
        artifact.verify()?;
        let a = &artifact.artifact;
        if a.network_id != self.network_id {
            return Err(WorkError::WrongNetwork);
        }
        let hash = artifact.hash();
        if self.artifacts.contains_key(&hash) {
            return Err(WorkError::Replay);
        }
        for parent in &a.parents {
            let parent_artifact = self.artifacts.get(parent).ok_or(WorkError::UnknownParent)?;
            if !parent_artifact.artifact.license.reusable {
                return Err(WorkError::NotReusable);
            }
            if parent_artifact.artifact.created_height > a.created_height {
                return Err(WorkError::Malformed(
                    "artifact parent is newer than the child".into(),
                ));
            }
        }
        self.artifacts.insert(hash, artifact.clone());
        Ok(hash)
    }

    /// Split `revenue_sat` earned by `child`: the child's owner keeps its
    /// share minus royalty, the royalty pool splits equally among direct
    /// parents, and each parent's share recurses upward. Dust from integer
    /// division stays with the child owner at each level. Payouts are merged
    /// per owner, sorted by address, and sum exactly to `revenue_sat`.
    pub fn settle_revenue(
        &self,
        child: &Hash,
        revenue_sat: u64,
    ) -> Result<Vec<(Address, u64)>, WorkError> {
        if revenue_sat == 0 {
            return Err(WorkError::Malformed("revenue must be positive".into()));
        }
        if !self.artifacts.contains_key(child) {
            return Err(WorkError::UnknownArtifact);
        }
        let mut payouts: BTreeMap<Address, u64> = BTreeMap::new();
        self.pay(*child, revenue_sat, 0, &mut payouts);
        Ok(payouts.into_iter().collect())
    }

    fn pay(&self, hash: Hash, amount: u64, depth: usize, payouts: &mut BTreeMap<Address, u64>) {
        let artifact = match self.artifacts.get(&hash) {
            Some(a) => a,
            None => return,
        };
        let a = &artifact.artifact;
        if depth > MAX_ROYALTY_DEPTH || a.parents.is_empty() || a.license.royalty_bps == 0 {
            Self::credit(payouts, a.owner, amount);
            return;
        }
        let pool = (amount as u128 * a.license.royalty_bps as u128 / 10_000) as u64;
        let per_parent = pool / a.parents.len() as u64;
        // Dust (`pool % parents`) stays with this artifact's owner.
        Self::credit(
            payouts,
            a.owner,
            amount - pool + (pool % a.parents.len() as u64),
        );
        for parent in &a.parents {
            self.pay(*parent, per_parent, depth + 1, payouts);
        }
    }

    fn credit(payouts: &mut BTreeMap<Address, u64>, owner: Address, amount: u64) {
        if amount == 0 {
            return;
        }
        *payouts.entry(owner).or_default() += amount;
    }

    /// All artifacts that (transitively) derive from `ancestor`, sorted.
    /// Useful for usage tracking: who builds on whose work.
    pub fn descendants(&self, ancestor: &Hash) -> Vec<Hash> {
        let mut out = Vec::new();
        for hash in self.artifacts.keys() {
            if *hash != *ancestor && self.reaches(hash, ancestor, &mut BTreeSet::new()) {
                out.push(*hash);
            }
        }
        out.sort();
        out
    }

    fn reaches(&self, from: &Hash, target: &Hash, seen: &mut BTreeSet<Hash>) -> bool {
        let artifact = match self.artifacts.get(from) {
            Some(a) => a,
            None => return false,
        };
        for parent in &artifact.artifact.parents {
            if parent == target {
                return true;
            }
            if seen.insert(*parent) && self.reaches(parent, target, seen) {
                return true;
            }
        }
        false
    }
}
