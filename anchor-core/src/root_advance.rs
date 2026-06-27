//! Root advance objects: the DSM transition package `Δ`, the transition digest
//! `D` (Def. 14), the MACANDD witness input `X` (Def. 16), the witness signing
//! seed `K` (Def. 17), the committed public-key handle `P_hw`, the certificate
//! message `M` (Def. 21), and the on-wire release artifacts.
//!
//! NOTE on the bound-field order: the source spec's equations for `X` (Def. 16),
//! `K` (Def. 17), and `M` (Def. 21) are truncated at the page margin. The field
//! set here is reconstructed from Theorem 25, which states it completely: the
//! witness binds `hᵢ, hᵢ₊₁, uᵢ, uᵢ+1, D, recipient, object, policy, anchor, slot,
//! receiver-challenge`. As the reference implementation, this canonical encoder
//! is the de-facto definition; producer and verifier use the same functions.

extern crate alloc;
use alloc::vec::Vec;

use crate::domain;
use crate::hash::{h, kdf};
use crate::util::{push_var, u16_le, u32_le, u64_le};

/// The canonical DSM transition package `Δᵢ₊₁` (the wire `TransitionPackage`).
/// It carries everything the receiver needs to verify `hᵢ → hᵢ₊₁` and to bind
/// the witness; the appliance does not verify the SMT proofs itself (§1).
pub struct Transition<'a> {
    pub relationship_id: &'a [u8; 32],
    pub object_id: &'a [u8; 32],
    pub sender_device_id: &'a [u8; 32],
    pub recipient_device_id: &'a [u8; 32],
    /// Parent SMT root `hᵢ`.
    pub parent_root: &'a [u8; 32],
    /// Proposed successor SMT root `hᵢ₊₁`.
    pub next_root: &'a [u8; 32],
    /// Anchor index `uᵢ` committed by the parent state.
    pub parent_index: u64,
    /// Next index `uᵢ+1`.
    pub next_index: u64,
    pub action_type: u32,
    pub action_fields: &'a [u8],
    pub payload_hash: &'a [u8; 32],
    /// DSM SMT proof of the spent leaf at `hᵢ`.
    pub old_leaf_proof: &'a [u8],
    /// DSM SMT proof of the produced leaf at `hᵢ₊₁`.
    pub new_leaf_proof: &'a [u8],
    pub authority_policy_hash: &'a [u8; 32],
}

/// Canonical byte encoding `enc(Δ)` (proto field order 1..14). Fixed-width
/// fields raw, integers little-endian, variable-length fields u32-length-prefixed.
pub fn enc_transition(t: &Transition) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 * 32 + t.action_fields.len() + t.old_leaf_proof.len() + t.new_leaf_proof.len() + 32);
    v.extend_from_slice(t.relationship_id);
    v.extend_from_slice(t.object_id);
    v.extend_from_slice(t.sender_device_id);
    v.extend_from_slice(t.recipient_device_id);
    v.extend_from_slice(t.parent_root);
    v.extend_from_slice(t.next_root);
    v.extend_from_slice(&u64_le(t.parent_index));
    v.extend_from_slice(&u64_le(t.next_index));
    v.extend_from_slice(&u32_le(t.action_type));
    push_var(&mut v, t.action_fields);
    v.extend_from_slice(t.payload_hash);
    push_var(&mut v, t.old_leaf_proof);
    push_var(&mut v, t.new_leaf_proof);
    v.extend_from_slice(t.authority_policy_hash);
    v
}

/// Transition digest `D = H("DSM/root-advance/transition-digest/v1" ‖ enc(Δ))`.
pub fn transition_digest(t: &Transition) -> [u8; 32] {
    h(domain::TRANSITION_DIGEST_V1, &[&enc_transition(t)])
}

/// MACANDD witness input `X` (Def. 16). Binds the full Theorem-25 field set.
pub fn witness_input(
    t: &Transition,
    d: &[u8; 32],
    anchor_id: &[u8; 32],
    q: u16,
    receiver_challenge: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::ROOT_ADVANCE_INPUT_V1,
        &[
            t.parent_root,
            t.next_root,
            &u64_le(t.parent_index),
            &u64_le(t.next_index),
            d,
            t.recipient_device_id,
            t.object_id,
            t.authority_policy_hash,
            anchor_id,
            &u16_le(q),
            receiver_challenge,
        ],
    )
}

/// Witness signing seed `K = HKDF(secret = W, context = "…witness-key…" ‖ …)`
/// (Def. 17), keyed by the MACANDD output `W`.
pub fn witness_key_material(
    w: &[u8; 32],
    x: &[u8; 32],
    t: &Transition,
    anchor_id: &[u8; 32],
    q: u16,
) -> [u8; 32] {
    kdf(
        w,
        domain::ROOT_ADVANCE_WITNESS_KEY_V1,
        &[
            x,
            t.parent_root,
            t.next_root,
            &u64_le(t.parent_index),
            &u64_le(t.next_index),
            anchor_id,
            &u16_le(q),
            t.authority_policy_hash,
        ],
    )
}

/// Committed public-witness-key handle `P_hw = H("DSM/tropic/pk-hash/v1" ‖ pk_hw)`.
pub fn pk_hash(pk_hw: &[u8]) -> [u8; 32] {
    h(domain::PK_HASH_V1, &[pk_hw])
}

/// Root advance certificate message `M` (Def. 21) — the digest StepSign covers.
#[allow(clippy::too_many_arguments)]
pub fn cert_message(
    t: &Transition,
    d: &[u8; 32],
    x: &[u8; 32],
    p_hw: &[u8; 32],
    anchor_id: &[u8; 32],
    q: u16,
    receiver_challenge: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::CERT_MESSAGE_V1,
        &[
            t.parent_root,
            t.next_root,
            &u64_le(t.parent_index),
            &u64_le(t.next_index),
            d,
            x,
            p_hw,
            t.recipient_device_id,
            t.object_id,
            t.authority_policy_hash,
            anchor_id,
            &u16_le(q),
            receiver_challenge,
        ],
    )
}

/// An owned copy of a [`Transition`], stored in the live record and carried in
/// the release so the certificate can be reconstructed without the borrow.
#[derive(Clone)]
pub struct OwnedTransition {
    pub relationship_id: [u8; 32],
    pub object_id: [u8; 32],
    pub sender_device_id: [u8; 32],
    pub recipient_device_id: [u8; 32],
    pub parent_root: [u8; 32],
    pub next_root: [u8; 32],
    pub parent_index: u64,
    pub next_index: u64,
    pub action_type: u32,
    pub action_fields: Vec<u8>,
    pub payload_hash: [u8; 32],
    pub old_leaf_proof: Vec<u8>,
    pub new_leaf_proof: Vec<u8>,
    pub authority_policy_hash: [u8; 32],
}

impl OwnedTransition {
    pub fn from(t: &Transition) -> Self {
        Self {
            relationship_id: *t.relationship_id,
            object_id: *t.object_id,
            sender_device_id: *t.sender_device_id,
            recipient_device_id: *t.recipient_device_id,
            parent_root: *t.parent_root,
            next_root: *t.next_root,
            parent_index: t.parent_index,
            next_index: t.next_index,
            action_type: t.action_type,
            action_fields: t.action_fields.to_vec(),
            payload_hash: *t.payload_hash,
            old_leaf_proof: t.old_leaf_proof.to_vec(),
            new_leaf_proof: t.new_leaf_proof.to_vec(),
            authority_policy_hash: *t.authority_policy_hash,
        }
    }

    pub fn as_transition(&self) -> Transition<'_> {
        Transition {
            relationship_id: &self.relationship_id,
            object_id: &self.object_id,
            sender_device_id: &self.sender_device_id,
            recipient_device_id: &self.recipient_device_id,
            parent_root: &self.parent_root,
            next_root: &self.next_root,
            parent_index: self.parent_index,
            next_index: self.next_index,
            action_type: self.action_type,
            action_fields: &self.action_fields,
            payload_hash: &self.payload_hash,
            old_leaf_proof: &self.old_leaf_proof,
            new_leaf_proof: &self.new_leaf_proof,
            authority_policy_hash: &self.authority_policy_hash,
        }
    }
}

/// The root advance certificate `Cert` (Def. 21 / wire `RootAdvanceCertificate`).
#[derive(Clone)]
pub struct Certificate {
    pub parent_root: [u8; 32],
    pub next_root: [u8; 32],
    pub parent_index: u64,
    pub next_index: u64,
    pub transition_digest: [u8; 32],
    pub witness_input: [u8; 32],
    pub pk_hash: [u8; 32],
    pub pk_hw: Vec<u8>,
    pub sigma: Vec<u8>,
    pub anchor_id: [u8; 32],
    pub slot: u16,
    pub receiver_challenge: [u8; 32],
}

/// TROPIC01 counter evidence (Def. 10 / wire `CounterEvidence`). The receiver
/// obtains the authoritative counter value from the chip (verifier pairing slot)
/// by authenticating `verifier_transcript`. The `*_claim` fields are untrusted
/// transport conveniences (§22) — the acceptance predicate never trusts them.
#[derive(Clone)]
pub struct CounterEvidence {
    pub anchor_id: [u8; 32],
    pub enrolled_counter: u64,
    /// Untrusted host claim of the live counter `H` (§7); proof comes from
    /// `verifier_transcript`, not this field.
    pub live_counter_claim: u64,
    /// Untrusted host claim of the derived index `u = H₀ − H`.
    pub derived_index_claim: u64,
    pub verifier_transcript: Vec<u8>,
}

/// The exported release package `Pkg = (Δ, Cert, counter-evidence)` (§10).
#[derive(Clone)]
pub struct OfflineRelease {
    pub transition: OwnedTransition,
    pub cert: Certificate,
    pub counter: CounterEvidence,
}
