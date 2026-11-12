//! Sender-key group messaging (non-consensus).
//!
//! A group is a shared conversation id with per-sender chains. Every member
//! owns one sending chain: message `n` from a member is encrypted under a
//! key derived from that member's chain, the chain advances, and the old key
//! is forgotten — forward secrecy within the group, per sender,
//! independently. Messages are signed with the sender's static hybrid bundle,
//! so membership (not a server) is the root of trust: a relay that is not a
//! member cannot read, and a non-member cannot write.
//!
//! Membership changes bump the epoch. Adding a member starts their chain;
//! removing one rotates *every remaining* chain, so a removed member's state
//! decrypts nothing new (post-compromise security on removal). Envelopes
//! from a past epoch are refused rather than buffered — resend after sync.
//!
//! Key distribution rides the existing pairwise envelopes: the creator ships
//! each member's chain seed encrypted to that member. Transport, presence
//! and fan-out are the operator's layers; this crate defines the bytes and
//! the guards.

use std::collections::{BTreeMap, BTreeSet};

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use srct_core::agent::{derive_agent_id, AgentId, AgentRole};
use srct_core::hash::{sha256_dom, Hash};
use srct_core::l2::Auth;
use srct_core::ser::Writer;
use srct_core::sig::{verify_bundle, Bundle};
use srct_core::wallet::Wallet;

use crate::message::MessageError;

pub const GROUP_VERSION: u8 = 1;
/// Most members one group may hold.
pub const MAX_GROUP_MEMBERS: usize = 128;
/// Most bytes one group message body may hold.
pub const MAX_GROUP_BODY: usize = 32 * 1024;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const DOM_GROUP_ID: &[u8] = b"srct/agentnet/group-id/v1";
const DOM_GROUP_KDF: &[u8] = b"srct/agentnet/group-kdf/v1";
const DOM_GROUP_SIGN: &[u8] = b"srct/agentnet/group-msg/v1";

/// Why a group operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupError {
    Message(MessageError),
    NotMember,
    UnknownGroup,
    BadEpoch,
    Replay,
    TooLarge,
    Malformed(String),
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupError::Message(e) => write!(f, "{e}"),
            GroupError::NotMember => write!(f, "sender is not a group member"),
            GroupError::UnknownGroup => write!(f, "unknown group"),
            GroupError::BadEpoch => write!(f, "message is from a past epoch"),
            GroupError::Replay => write!(f, "group sequence was already consumed"),
            GroupError::TooLarge => write!(f, "group message exceeds its size cap"),
            GroupError::Malformed(detail) => write!(f, "malformed group message: {detail}"),
        }
    }
}

impl std::error::Error for GroupError {}

impl From<MessageError> for GroupError {
    fn from(e: MessageError) -> Self {
        GroupError::Message(e)
    }
}

/// A group message on the wire. The sender is named (groups authenticate by
/// static signature); the body is encrypted to the group epoch key derived
/// from the sender's chain.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupMessage {
    pub version: u8,
    pub group: Hash,
    pub epoch: u64,
    pub sender: AgentId,
    pub sender_role: AgentRole,
    pub seq: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub sigs: Bundle,
    pub keys: Bundle,
}

fn group_id(network: &str, creator: &AgentId, nonce: u64) -> Hash {
    sha256_dom(
        DOM_GROUP_ID,
        &[network.as_bytes(), creator, &nonce.to_le_bytes()],
    )
}

fn chain_key(seed: &[u8; 32], group: &Hash, epoch: u64, member: &AgentId) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&group[..]), seed);
    let mut info = Vec::with_capacity(DOM_GROUP_KDF.len() + 8 + 20);
    info.extend_from_slice(DOM_GROUP_KDF);
    info.extend_from_slice(&epoch.to_le_bytes());
    info.extend_from_slice(member);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("group kdf expand");
    out
}

fn msg_key(chain: &[u8; 32], seq: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, chain);
    let mut out = [0u8; 32];
    hk.expand(&seq.to_le_bytes(), &mut out)
        .expect("group message kdf expand");
    out
}

fn next_chain(chain: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, chain);
    let mut out = [0u8; 32];
    hk.expand(b"next", &mut out)
        .expect("group chain kdf expand");
    out
}

fn group_aad(
    network: &str,
    group: &Hash,
    epoch: u64,
    sender: &AgentId,
    sender_role: AgentRole,
    seq: u64,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut w = Writer::with_capacity(160 + network.len());
    w.u8(GROUP_VERSION)
        .u16le(network.len() as u16)
        .raw(network.as_bytes())
        .fixed(group)
        .u64le(epoch)
        .fixed(sender)
        .u8(sender_role.as_u8())
        .u64le(seq)
        .fixed(nonce);
    w.into_vec()
}

#[allow(clippy::too_many_arguments)]
fn group_signing_hash(
    network: &str,
    group: &Hash,
    epoch: u64,
    sender: &AgentId,
    sender_role: AgentRole,
    sender_address: &srct_core::hash::Address,
    seq: u64,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Hash {
    let mut w = Writer::with_capacity(192 + network.len() + ciphertext.len());
    w.raw(DOM_GROUP_SIGN)
        .u16le(network.len() as u16)
        .raw(network.as_bytes())
        .fixed(group)
        .u64le(epoch)
        .fixed(sender)
        .u8(sender_role.as_u8())
        .fixed(sender_address)
        .u64le(seq)
        .fixed(nonce)
        .u32le(ciphertext.len() as u32)
        .raw(ciphertext);
    sha256_dom(DOM_GROUP_SIGN, &[w.as_slice()])
}

/// One member's view of one group: its own sending chain plus every
/// member's current chain tip for verification-free receiving (receiving
/// needs only the message key per sequence, derived on demand from the
/// stored chain and advanced past).
#[derive(Clone, Debug)]
struct MemberView {
    chain: [u8; 32],
    next_seq: u64,
}

/// A creator-signed membership snapshot to broadcast after every change.
/// Carries the full member set with every member's current chain seed, so a
/// survivor replaces its view wholesale instead of merging gossip.
///
/// Authenticity comes from the pairwise layer: syncs travel inside signed
/// (or sealed) pairwise envelopes from the creator. This crate checks shape,
/// group binding and epoch order; the transport proves authorship.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSync {
    pub group: Hash,
    pub epoch: u64,
    pub creator: AgentId,
    pub members: Vec<AgentId>,
    pub seeds: Vec<(AgentId, [u8; 32])>,
}

/// A participant's group state.
#[derive(Clone, Debug)]
pub struct GroupSession {
    group: Hash,
    network_id: String,
    epoch: u64,
    creator: AgentId,
    members: BTreeSet<AgentId>,
    /// Chain seeds by member. The creator knows all; a joiner learns them
    /// from syncs. Seeds are what make every member's messages readable to
    /// every other member — and why removal rotates all of them.
    seeds: BTreeMap<AgentId, [u8; 32]>,
    /// My sending chain plus expected sequence.
    my_chain: [u8; 32],
    my_seq: u64,
    /// Per-member receive state, including my own (self-messages verify).
    receive: BTreeMap<AgentId, MemberView>,
    me: AgentId,
}

impl GroupSession {
    /// Create a group. The creator is member zero; the group id commits to
    /// the network, creator and nonce.
    pub fn create(
        network_id: impl Into<String>,
        creator: AgentId,
        creator_seed: [u8; 32],
        nonce: u64,
    ) -> Self {
        let network_id = network_id.into();
        let group = group_id(&network_id, &creator, nonce);
        let mut members = BTreeSet::new();
        members.insert(creator);
        let mut seeds = BTreeMap::new();
        seeds.insert(creator, creator_seed);
        let mut receive = BTreeMap::new();
        receive.insert(
            creator,
            MemberView {
                chain: chain_key(&creator_seed, &group, 0, &creator),
                next_seq: 1,
            },
        );
        GroupSession {
            group,
            network_id,
            epoch: 0,
            creator,
            members,
            seeds,
            my_chain: chain_key(&creator_seed, &group, 0, &creator),
            my_seq: 1,
            receive,
            me: creator,
        }
    }

    pub fn group_id(&self) -> Hash {
        self.group
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn members(&self) -> Vec<AgentId> {
        self.members.iter().copied().collect()
    }

    pub fn is_member(&self, agent: &AgentId) -> bool {
        self.members.contains(agent)
    }

    /// Admit a member at the current epoch. Creator-only; the newcomer
    /// starts a fresh chain while existing chains are unaffected. Returns
    /// the sync to broadcast: every member's current seeds, so recipients
    /// replace their view wholesale.
    pub fn add_member(
        &mut self,
        caller: &AgentId,
        member: AgentId,
        member_seed: [u8; 32],
    ) -> Result<GroupSync, GroupError> {
        if *caller != self.creator {
            return Err(GroupError::NotMember);
        }
        if self.members.len() >= MAX_GROUP_MEMBERS {
            return Err(GroupError::TooLarge);
        }
        if !self.members.insert(member) {
            return Err(GroupError::Replay);
        }
        self.seeds.insert(member, member_seed);
        self.receive.insert(
            member,
            MemberView {
                chain: chain_key(&member_seed, &self.group, self.epoch, &member),
                next_seq: 1,
            },
        );
        Ok(self.snapshot())
    }

    /// Join from a creator sync. The sync must name this device's agent
    /// and carry its seed; anything else is refused before any state exists.
    pub fn join(
        network_id: impl Into<String>,
        sync: &GroupSync,
        me: AgentId,
    ) -> Result<Self, GroupError> {
        if sync.members.is_empty() || sync.members.len() > MAX_GROUP_MEMBERS {
            return Err(GroupError::Malformed("sync member set is bad".into()));
        }
        if !sync.members.contains(&me) || !sync.members.contains(&sync.creator) {
            return Err(GroupError::NotMember);
        }
        if sync.members.len() != sync.seeds.len() {
            return Err(GroupError::Malformed(
                "sync seeds do not match members".into(),
            ));
        }
        let mut members = BTreeSet::new();
        let mut seeds = BTreeMap::new();
        for (m, (sm, seed)) in sync.members.iter().zip(sync.seeds.iter()) {
            if m != sm {
                return Err(GroupError::Malformed(
                    "sync seeds do not match members".into(),
                ));
            }
            members.insert(*m);
            seeds.insert(*m, *seed);
        }
        if !seeds.contains_key(&me) {
            return Err(GroupError::NotMember);
        }
        let mut receive = BTreeMap::new();
        for (m, seed) in &seeds {
            receive.insert(
                *m,
                MemberView {
                    chain: chain_key(seed, &sync.group, sync.epoch, m),
                    next_seq: 1,
                },
            );
        }
        let my_seed = seeds[&me];
        Ok(GroupSession {
            group: sync.group,
            network_id: network_id.into(),
            epoch: sync.epoch,
            creator: sync.creator,
            members,
            seeds,
            my_chain: chain_key(&my_seed, &sync.group, sync.epoch, &me),
            my_seq: 1,
            receive,
            me,
        })
    }

    /// Apply a creator sync: replace the member set, seeds and epoch
    /// wholesale. Stale epochs are refused, the current epoch re-applied is
    /// a replay, and a sync that drops this device refuses with NotMember.
    /// Syncs must travel over authenticated pairwise envelopes — shape and
    /// order are checked here, authorship on the transport.
    pub fn sync_from_creator(&mut self, sync: &GroupSync) -> Result<(), GroupError> {
        if sync.group != self.group || sync.creator != self.creator {
            return Err(GroupError::UnknownGroup);
        }
        if sync.epoch < self.epoch {
            return Err(GroupError::BadEpoch);
        }
        if sync.epoch == self.epoch {
            return Err(GroupError::Replay);
        }
        if sync.members.is_empty() || sync.members.len() > MAX_GROUP_MEMBERS {
            return Err(GroupError::Malformed("sync member set is bad".into()));
        }
        if !sync.members.contains(&self.me) {
            return Err(GroupError::NotMember);
        }
        if sync.members.len() != sync.seeds.len() {
            return Err(GroupError::Malformed(
                "sync seeds do not match members".into(),
            ));
        }
        let mut members = BTreeSet::new();
        let mut seeds = BTreeMap::new();
        for (m, (sm, seed)) in sync.members.iter().zip(sync.seeds.iter()) {
            if m != sm {
                return Err(GroupError::Malformed(
                    "sync seeds do not match members".into(),
                ));
            }
            members.insert(*m);
            seeds.insert(*m, *seed);
        }
        let my_seed = seeds.get(&self.me).copied().ok_or(GroupError::NotMember)?;
        let mut receive = BTreeMap::new();
        for (m, seed) in &seeds {
            receive.insert(
                *m,
                MemberView {
                    chain: chain_key(seed, &sync.group, sync.epoch, m),
                    next_seq: 1,
                },
            );
        }
        self.epoch = sync.epoch;
        self.members = members;
        self.seeds = seeds;
        self.my_chain = chain_key(&my_seed, &sync.group, sync.epoch, &self.me);
        self.my_seq = 1;
        self.receive = receive;
        Ok(())
    }

    /// Remove a member. Creator-only; bumps the epoch and rotates every
    /// remaining chain, so removed state decrypts nothing new. Returns the
    /// sync to broadcast to the survivors.
    pub fn remove_member(
        &mut self,
        caller: &AgentId,
        member: &AgentId,
        fresh: impl FnOnce() -> [u8; 32],
    ) -> Result<GroupSync, GroupError> {
        if *caller != self.creator {
            return Err(GroupError::NotMember);
        }
        if member == &self.creator {
            return Err(GroupError::Malformed("cannot remove the creator".into()));
        }
        if !self.members.remove(member) {
            return Err(GroupError::UnknownGroup);
        }
        self.seeds.remove(member);
        self.receive.remove(member);
        self.epoch += 1;
        let base = fresh();
        for m in self.members.iter().copied().collect::<Vec<_>>() {
            // Fresh seed per survivor, bound to the member and the new epoch.
            let seed: [u8; 32] = sha256_dom(
                b"srct/agentnet/group-reseed/v1",
                &[&base, &m[..], &self.epoch.to_le_bytes()],
            );
            self.seeds.insert(m, seed);
            let chain = chain_key(&seed, &self.group, self.epoch, &m);
            if m == self.me {
                self.my_chain = chain;
                self.my_seq = 1;
            }
            self.receive.insert(m, MemberView { chain, next_seq: 1 });
        }
        Ok(self.snapshot())
    }

    /// The current full view, to broadcast after local changes.
    fn snapshot(&self) -> GroupSync {
        let mut members: Vec<AgentId> = self.members.iter().copied().collect();
        members.sort();
        let seeds = members
            .iter()
            .map(|m| (*m, self.seeds[m]))
            .collect::<Vec<_>>();
        GroupSync {
            group: self.group,
            epoch: self.epoch,
            creator: self.creator,
            members,
            seeds,
        }
    }

    /// Encrypt the next message on my chain. The chain advances; the used
    /// key is forgotten on drop of this call frame.
    pub fn encrypt(
        &mut self,
        sender_wallet: &Wallet,
        sender_role: AgentRole,
        sender_address: &srct_core::hash::Address,
        body: &[u8],
    ) -> Result<GroupMessage, GroupError> {
        if body.len() > MAX_GROUP_BODY {
            return Err(GroupError::TooLarge);
        }
        if !self.members.contains(&self.me) {
            return Err(GroupError::NotMember);
        }
        if derive_agent_id(&self.network_id, sender_role, sender_address) != self.me {
            return Err(GroupError::Malformed(
                "sender identity does not match".into(),
            ));
        }
        let seq = self.my_seq;
        let key = msg_key(&self.my_chain, seq);
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = group_aad(
            &self.network_id,
            &self.group,
            self.epoch,
            &self.me,
            sender_role,
            seq,
            &nonce,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| GroupError::Message(MessageError::Crypto("cipher init".into())))?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: body,
                    aad: &aad,
                },
            )
            .map_err(|_| GroupError::Message(MessageError::Crypto("encrypt".into())))?;
        let signing_hash = group_signing_hash(
            &self.network_id,
            &self.group,
            self.epoch,
            &self.me,
            sender_role,
            sender_address,
            seq,
            &nonce,
            &ciphertext,
        );
        let auth = Auth::sign(sender_wallet, &signing_hash)
            .map_err(|e| GroupError::Message(MessageError::BadSignature(e.to_string())))?;
        self.my_chain = next_chain(&self.my_chain);
        self.my_seq += 1;
        // My own receive view tracks my chain for self-verification.
        if let Some(view) = self.receive.get_mut(&self.me) {
            view.chain = next_chain(&view.chain);
            view.next_seq = seq + 1;
        }
        Ok(GroupMessage {
            version: GROUP_VERSION,
            group: self.group,
            epoch: self.epoch,
            sender: self.me,
            sender_role,
            seq,
            nonce,
            ciphertext,
            sigs: auth.sigs,
            keys: auth.keys,
        })
    }

    /// Decrypt and verify a group message. The sender must be a current
    /// member at the current epoch with the exact next sequence; anything
    /// else is refused, never buffered.
    pub fn decrypt(&mut self, msg: &GroupMessage) -> Result<Vec<u8>, GroupError> {
        if msg.version != GROUP_VERSION {
            return Err(GroupError::Malformed("group version is unknown".into()));
        }
        if msg.group != self.group {
            return Err(GroupError::UnknownGroup);
        }
        if msg.epoch != self.epoch {
            return Err(GroupError::BadEpoch);
        }
        if !self.members.contains(&msg.sender) {
            return Err(GroupError::NotMember);
        }
        // Static signature first: a non-member's bytes fail here even with a
        // guessed chain. The claimed sender address comes from the key bundle
        // the message carries, and the claimed agent id must derive from it —
        // otherwise anyone could speak as any member.
        let signer = msg
            .keys
            .address()
            .map_err(|e| GroupError::Message(MessageError::BadKey(e.to_string())))?;
        if derive_agent_id(&self.network_id, msg.sender_role, &signer) != msg.sender {
            return Err(GroupError::Message(MessageError::BadSignature(
                "sender identity does not match its address".into(),
            )));
        }
        let signing_hash = group_signing_hash(
            &self.network_id,
            &msg.group,
            msg.epoch,
            &msg.sender,
            msg.sender_role,
            &signer,
            msg.seq,
            &msg.nonce,
            &msg.ciphertext,
        );
        verify_bundle(&msg.sigs, &msg.keys, &signing_hash).map_err(|_| {
            GroupError::Message(MessageError::BadSignature(
                "signature does not verify".into(),
            ))
        })?;
        let (chain, expected_seq) = {
            let view = self.receive.get(&msg.sender).ok_or(GroupError::NotMember)?;
            (view.chain, view.next_seq)
        };
        if msg.seq != expected_seq {
            return Err(GroupError::Replay);
        }
        let key = msg_key(&chain, msg.seq);
        let aad = group_aad(
            &self.network_id,
            &msg.group,
            msg.epoch,
            &msg.sender,
            msg.sender_role,
            msg.seq,
            &msg.nonce,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| GroupError::Message(MessageError::Crypto("cipher init".into())))?;
        let plain = cipher
            .decrypt(
                &XNonce::from(msg.nonce),
                AeadPayload {
                    msg: &msg.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                GroupError::Message(MessageError::Crypto(
                    "wrong key, wrong metadata or tampered ciphertext".into(),
                ))
            })?;
        if plain.len() > MAX_GROUP_BODY {
            return Err(GroupError::TooLarge);
        }
        let view = self
            .receive
            .get_mut(&msg.sender)
            .ok_or(GroupError::NotMember)?;
        view.chain = next_chain(&view.chain);
        view.next_seq += 1;
        Ok(plain)
    }
}

impl GroupSync {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128 + self.members.len() * 56);
        w.u8(GROUP_VERSION)
            .fixed(&self.group)
            .u64le(self.epoch)
            .fixed(&self.creator)
            .u32le(self.members.len() as u32);
        for m in &self.members {
            w.fixed(m);
        }
        w.u32le(self.seeds.len() as u32);
        for (m, s) in &self.seeds {
            w.fixed(m).fixed(s);
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        use srct_core::ser::Reader;
        let bad = |d: &str| GroupError::Malformed(format!("group sync {d}"));
        if bytes.len() > 8 + 32 + 8 + 20 + 4 + MAX_GROUP_MEMBERS * (20 + 20 + 32) {
            return Err(GroupError::TooLarge);
        }
        let mut r = Reader::new(bytes);
        if r.u8().map_err(|_| bad("version is missing"))? != GROUP_VERSION {
            return Err(bad("version is unknown"));
        }
        let group: Hash = r.fixed().map_err(|_| bad("group is missing"))?;
        if group == [0u8; 32] {
            return Err(bad("group is zero"));
        }
        let epoch = r.u64le().map_err(|_| bad("epoch is missing"))?;
        let creator: AgentId = r.fixed().map_err(|_| bad("creator is missing"))?;
        let count = r.u32le().map_err(|_| bad("member count is missing"))? as usize;
        if count == 0 || count > MAX_GROUP_MEMBERS {
            return Err(bad("member set is bad"));
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(r.fixed().map_err(|_| bad("member is missing"))?);
        }
        let scount = r.u32le().map_err(|_| bad("seed count is missing"))? as usize;
        if scount != count {
            return Err(bad("seeds do not match members"));
        }
        let mut seeds = Vec::with_capacity(scount);
        for _ in 0..scount {
            let m: AgentId = r.fixed().map_err(|_| bad("seed member is missing"))?;
            let s: [u8; 32] = r.fixed().map_err(|_| bad("seed is missing"))?;
            seeds.push((m, s));
        }
        r.expect_end().map_err(|_| bad("has trailing bytes"))?;
        Ok(GroupSync {
            group,
            epoch,
            creator,
            members,
            seeds,
        })
    }
}

impl GroupMessage {
    pub fn encode(&self) -> Vec<u8> {
        let sigs = self.sigs.to_bytes();
        let keys = self.keys.to_bytes();
        let mut w = Writer::with_capacity(256 + self.ciphertext.len() + sigs.len() + keys.len());
        w.u8(self.version)
            .fixed(&self.group)
            .u64le(self.epoch)
            .fixed(&self.sender)
            .u8(self.sender_role.as_u8())
            .u64le(self.seq)
            .fixed(&self.nonce)
            .u32le(self.ciphertext.len() as u32)
            .raw(&self.ciphertext)
            .u32le(sigs.len() as u32)
            .raw(&sigs)
            .u32le(keys.len() as u32)
            .raw(&keys);
        w.into_vec()
    }

    /// Strict inverse of [`GroupMessage::encode`], verified against the
    /// network it will be read on: structure, sender binding and sender
    /// signature. Tampered bytes fail here instead of entering a session.
    pub fn decode(bytes: &[u8], network: &str) -> Result<Self, GroupError> {
        use srct_core::ser::Reader;
        let bad = |d: &str| GroupError::Malformed(format!("group message {d}"));
        if bytes.len() > 128 + MAX_GROUP_BODY + 16 * 1024 {
            return Err(GroupError::TooLarge);
        }
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| bad("version is missing"))?;
        if version != GROUP_VERSION {
            return Err(GroupError::Malformed("group version is unknown".into()));
        }
        let group: Hash = r.fixed().map_err(|_| bad("group is missing"))?;
        let epoch = r.u64le().map_err(|_| bad("epoch is missing"))?;
        let sender: AgentId = r.fixed().map_err(|_| bad("sender is missing"))?;
        let sender_role = AgentRole::from_u8(r.u8().map_err(|_| bad("sender role is missing"))?)
            .ok_or_else(|| GroupError::Malformed("group sender role is unknown".into()))?;
        let seq = r.u64le().map_err(|_| bad("sequence is missing"))?;
        if seq == 0 {
            return Err(GroupError::Malformed("sequence is zero".into()));
        }
        let nonce: [u8; NONCE_LEN] = r.fixed().map_err(|_| bad("nonce is missing"))?;
        let ct_len = r.u32le().map_err(|_| bad("body length is missing"))? as usize;
        if !(TAG_LEN..=MAX_GROUP_BODY + TAG_LEN).contains(&ct_len) {
            return Err(GroupError::TooLarge);
        }
        let ciphertext = r
            .fixed_slice(ct_len)
            .map_err(|_| bad("body is missing"))?
            .to_vec();
        let sigs_len = r.u32le().map_err(|_| bad("sigs length is missing"))? as usize;
        if sigs_len > 8 * 1024 {
            return Err(GroupError::TooLarge);
        }
        let sigs = Bundle::deserialize(
            r.fixed_slice(sigs_len)
                .map_err(|_| bad("sigs are missing"))?,
        )
        .map_err(|e| GroupError::Message(MessageError::BadSignature(e.to_string())))?;
        let keys_len = r.u32le().map_err(|_| bad("keys length is missing"))? as usize;
        if keys_len > 8 * 1024 {
            return Err(GroupError::TooLarge);
        }
        let keys = Bundle::deserialize(
            r.fixed_slice(keys_len)
                .map_err(|_| bad("keys are missing"))?,
        )
        .map_err(|e| GroupError::Message(MessageError::BadSignature(e.to_string())))?;
        r.expect_end().map_err(|_| bad("has trailing bytes"))?;
        let msg = GroupMessage {
            version,
            group,
            epoch,
            sender,
            sender_role,
            seq,
            nonce,
            ciphertext,
            sigs,
            keys,
        };
        // Verify-before-store, like the pairwise envelope: structure,
        // sender binding and sender signature, all against the reading
        // network. A relay that re-homes the bytes breaks verification.
        let signer = msg
            .keys
            .address()
            .map_err(|e| GroupError::Message(MessageError::BadKey(e.to_string())))?;
        if derive_agent_id(network, msg.sender_role, &signer) != msg.sender {
            return Err(GroupError::Message(MessageError::BadSignature(
                "sender identity does not match its address".into(),
            )));
        }
        let signing_hash = group_signing_hash(
            network,
            &msg.group,
            msg.epoch,
            &msg.sender,
            msg.sender_role,
            &signer,
            msg.seq,
            &msg.nonce,
            &msg.ciphertext,
        );
        verify_bundle(&msg.sigs, &msg.keys, &signing_hash).map_err(|_| {
            GroupError::Message(MessageError::BadSignature(
                "signature does not verify".into(),
            ))
        })?;
        Ok(msg)
    }
}
