//! The receiver acceptance predicate (§12, Def. 22). An honest receiver accepts
//! an offline-bearer root advance only if all sixteen checks hold.
//!
//! anchor-core verifies the cryptographic recomputations and the counter
//! arithmetic itself; the two checks that need DSM-specific knowledge — the SMT
//! transition proof (checks 3, 7, 8) and the authenticity of the TROPIC01
//! counter read (the trust half of check 14) — are receiver-supplied traits, so
//! this crate stays DSM- and chip-session-agnostic. The receiver never trusts an
//! RP2350 claim that the root advanced (§13).

use crate::root_advance::{
    cert_message, pk_hash, transition_digest, witness_input, CounterEvidence, OfflineRelease,
    Transition,
};
use crate::tropic::WitnessSig;
use crate::util::ct_eq_32;

/// The DSM-state verifier the receiver supplies. These are the checks anchor-core
/// cannot perform without the DSM SMT and relationship state.
pub trait DsmVerifier {
    /// Check 3: the parent DSM state at `parent_root` commits to `parent_index`.
    fn parent_commits_index(&self, parent_root: &[u8; 32], parent_index: u64) -> bool;
    /// Check 7: the DSM transition proof verifies `parent_root → next_root`
    /// (via the package's `old_leaf_proof` / `new_leaf_proof`).
    fn verify_transition(&self, t: &Transition) -> bool;
    /// Check 8: the transfer delivers the claimed object/value to this receiver.
    fn delivers_to_receiver(&self, t: &Transition) -> bool;
}

/// The counter-evidence verifier the receiver supplies. It returns the live
/// TROPIC01 counter value the receiver *itself* read over an authenticated L3
/// verifier-pairing-slot session — derived from `ev.verifier_transcript`, NOT
/// from the host-supplied numeric `ev.live_counter_claim`. Returns `None` if the
/// transcript is absent or inauthentic for the pinned anchor.
///
/// This is the trust boundary of Def. 22 check 14 (and §13/Thm 26): the
/// arithmetic comparison `H == H0 − (uᵢ+1)` in [`accept_offline`] is performed
/// against the value returned here, so a breached RP2350 cannot have a forged
/// `live_counter` accepted — only a genuine chip read decides.
pub trait CounterVerifier {
    fn read_authentic_counter(&self, anchor_id: &[u8; 32], ev: &CounterEvidence) -> Option<u64>;
}

/// Receiver-side context: the values this receiver pinned/supplied for the
/// transfer, plus the policy gates (checks 2, 5, 9, 15, 16).
pub struct VerifierContext<'a> {
    /// Check 2: the parent root this receiver accepts for the received object.
    pub accepted_parent_root: &'a [u8; 32],
    /// The enrolled anchor identity this receiver pinned (Track 1c).
    pub pinned_anchor_id: &'a [u8; 32],
    /// Check 5: the receiver challenge `r_R` this receiver supplied.
    pub expected_receiver_challenge: &'a [u8; 32],
    /// Check 9: the authority policy hash bound to the parent state.
    pub expected_policy_hash: &'a [u8; 32],
    /// Enrolled counter `H0` for the pinned anchor.
    pub enrolled_counter: u64,
    /// Check 15: the maximum offline-exposure index; `next_index` must not exceed it.
    pub exposure_cap_index: u64,
    /// Check 16: `true` iff no known firmware-boundary or physical-compromise
    /// event invalidates the anchor.
    pub anchor_uncompromised: bool,
}

/// Which Def. 22 check failed (1-indexed to match the spec).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcceptError {
    /// (1) Δ and Cert disagree on the advance they describe.
    NonCanonical,
    /// (2) Parent root is not the receiver's accepted parent / anchor not pinned.
    ParentNotAccepted,
    /// (3) Parent DSM state does not commit to `parent_index`.
    ParentIndexUncommitted,
    /// (4) `next_index != parent_index + 1`.
    BadNextIndex,
    /// (5) Receiver challenge is not the one this receiver supplied.
    ChallengeMismatch,
    /// (6) `D` does not recompute from Δ.
    DigestMismatch,
    /// (7) DSM transition proof does not verify `hᵢ → hᵢ₊₁`.
    TransitionProofInvalid,
    /// (8) The transfer does not deliver the object/value to this receiver.
    NotDeliveredToReceiver,
    /// (9) Authority policy hash does not match the parent state.
    PolicyMismatch,
    /// (10) `X` does not recompute from the bound fields.
    WitnessInputMismatch,
    /// (11) `P_hw != H(tag ‖ pk_hw)`.
    PkHashMismatch,
    /// (13) `StepVerify(pk_hw, M, σ) = 0`.
    WitnessSigInvalid,
    /// (14) Counter evidence does not prove `H = H0 − (uᵢ+1)`, or is inauthentic.
    CounterEvidenceInvalid,
    /// (15) Transfer is beyond the offline exposure cap.
    ExposureCapExceeded,
    /// (16) A firmware-boundary / physical-compromise event invalidates the anchor.
    AnchorCompromised,
}

/// `Accept_off(Pkg) = 1` iff every Def. 22 check holds. Returns the first failing
/// check as an [`AcceptError`].
pub fn accept_offline<S, D, C>(
    rel: &OfflineRelease,
    ctx: &VerifierContext,
    dsm: &D,
    counter: &C,
) -> Result<(), AcceptError>
where
    S: WitnessSig,
    D: DsmVerifier,
    C: CounterVerifier,
{
    let t = rel.transition.as_transition();
    let cert = &rel.cert;
    let ev = &rel.counter;

    // (1) Δ and Cert must describe the same advance. Wire bytes are length- and
    // type-validated on decode (proto.rs); every field the witness commits to is
    // recomputed from these structured values below (D, X, M), so protobuf
    // non-minimality is replay-equivalent (Thm 28), not a forgery surface. This
    // guard rejects a Cert spliced onto a different Δ.
    if !ct_eq_32(&cert.parent_root, t.parent_root)
        || !ct_eq_32(&cert.next_root, t.next_root)
        || cert.parent_index != t.parent_index
        || cert.next_index != t.next_index
    {
        return Err(AcceptError::NonCanonical);
    }

    // (2) hᵢ is the receiver's accepted parent root, and the anchor is pinned.
    if !ct_eq_32(t.parent_root, ctx.accepted_parent_root)
        || !ct_eq_32(&cert.anchor_id, ctx.pinned_anchor_id)
    {
        return Err(AcceptError::ParentNotAccepted);
    }

    // (3) Parent DSM state commits to uᵢ.
    if !dsm.parent_commits_index(t.parent_root, t.parent_index) {
        return Err(AcceptError::ParentIndexUncommitted);
    }

    // (4) next index = uᵢ + 1 (checked: parent_index is attacker-supplied).
    if t.parent_index.checked_add(1) != Some(t.next_index) {
        return Err(AcceptError::BadNextIndex);
    }

    // (5) r_R is the challenge this receiver supplied.
    if !ct_eq_32(&cert.receiver_challenge, ctx.expected_receiver_challenge) {
        return Err(AcceptError::ChallengeMismatch);
    }

    // (6) D recomputes from Δ.
    let d = transition_digest(&t);
    if !ct_eq_32(&d, &cert.transition_digest) {
        return Err(AcceptError::DigestMismatch);
    }

    // (7) DSM transition proof verifies hᵢ → hᵢ₊₁.
    if !dsm.verify_transition(&t) {
        return Err(AcceptError::TransitionProofInvalid);
    }

    // (8) The transfer gives the claimed object/value to the receiver.
    if !dsm.delivers_to_receiver(&t) {
        return Err(AcceptError::NotDeliveredToReceiver);
    }

    // (9) Authority policy hash matches the parent state.
    if !ct_eq_32(t.authority_policy_hash, ctx.expected_policy_hash) {
        return Err(AcceptError::PolicyMismatch);
    }

    // (10) X recomputes from the bound fields.
    let x = witness_input(&t, &d, &cert.anchor_id, cert.slot, &cert.receiver_challenge);
    if !ct_eq_32(&x, &cert.witness_input) {
        return Err(AcceptError::WitnessInputMismatch);
    }

    // (11) P_hw = H(tag ‖ pk_hw).
    let p_hw = pk_hash(&cert.pk_hw);
    if !ct_eq_32(&p_hw, &cert.pk_hash) {
        return Err(AcceptError::PkHashMismatch);
    }

    // (12) M recomputes from the certificate fields; (13) StepVerify(pk_hw,M,σ)=1.
    let m = cert_message(
        &t,
        &d,
        &x,
        &p_hw,
        &cert.anchor_id,
        cert.slot,
        &cert.receiver_challenge,
    );
    if !S::verify(&cert.pk_hw, &m, &cert.sigma) {
        return Err(AcceptError::WitnessSigInvalid);
    }

    // (14) Counter evidence proves the pinned counter reached H0 − (uᵢ+1). The
    // counter counts down, so the live value must equal the enrolled counter
    // minus the next index. The value compared is the one the receiver read for
    // itself from the chip (the transcript), never the host-supplied number.
    let expects_live = ctx
        .enrolled_counter
        .checked_sub(t.next_index)
        .ok_or(AcceptError::CounterEvidenceInvalid)?;
    let attested = counter
        .read_authentic_counter(ctx.pinned_anchor_id, ev)
        .ok_or(AcceptError::CounterEvidenceInvalid)?;
    if !ct_eq_32(&ev.anchor_id, ctx.pinned_anchor_id) || attested != expects_live {
        return Err(AcceptError::CounterEvidenceInvalid);
    }

    // (15) Within the offline exposure cap.
    if t.next_index > ctx.exposure_cap_index {
        return Err(AcceptError::ExposureCapExceeded);
    }

    // (16) No firmware-boundary / physical-compromise event.
    if !ctx.anchor_uncompromised {
        return Err(AcceptError::AnchorCompromised);
    }

    Ok(())
}
