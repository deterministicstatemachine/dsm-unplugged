//! The compact 3-state appliance (§11) and power-loss recovery (§14–15).
//!
//! `Active = (hᵢ, uᵢ, status, record)` with `status ∈ {Ready, Prepared,
//! Committed}`. The anchor index `uᵢ` is committed by the parent DSM root, so a
//! valid offline transfer advances to exactly `uᵢ+1` — there is no offered /
//! pending precommit table. The flow is: prepare (one MACANDD witness call, no
//! export, no counter move) → commit (sign `M`, move the counter, erase `sk_hw`)
//! → emit (export after commit) → finalize (advance the active root).

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::root_advance::{
    cert_message, pk_hash, transition_digest, witness_input, witness_key_material, Certificate,
    CounterEvidence, OfflineRelease, OwnedTransition, Transition,
};
use crate::tropic::{Tropic, TropicError, WitnessSig};
use crate::util::ct_eq_32;

/// Securely wipe a secret buffer: volatile writes the optimizer may not elide,
/// fenced so the zeroing is not reordered past the buffer's last use.
fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, writable `u8`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Wipe a secret `Vec` and empty it, so an `is_empty()` "key lost?" check reads
/// false only while a live key is present.
fn zeroize_vec(v: &mut Vec<u8>) {
    zeroize(v);
    v.clear();
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Ready,
    Prepared,
    Committed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApplianceError {
    /// Operation not valid in the current status.
    WrongState,
    /// Requested parent root is not the active root.
    PrevRootMismatch,
    /// `next_anchor_counter != anchor_counter + 1`, or `anchor_counter != active.u`.
    IndexMismatch,
    /// `active.u != H₀ − H` — the appliance is not offline-ready.
    CounterMismatch,
    /// The prepared record's witness key was lost (power-loss write race).
    WitnessKeyLost,
    /// `MCounter_Update` on an exhausted counter (`H == 0`) — online only.
    CounterExhausted,
    /// A committed release is not yet present to emit/finalize.
    NotCommitted,
    Tropic(TropicError),
}

/// Prepared record (§11.1): witness material + the cert message, retained with
/// `sk_hw` until commit signs and erases it. No counter has moved.
pub struct PreparedRecord {
    pub txn: OwnedTransition,
    /// Transition digest D.
    pub digest: [u8; 32],
    /// Witness input X.
    pub witness_input: [u8; 32],
    /// Cert message M (the StepSign digest).
    pub cert_message: [u8; 32],
    pub pk_hw: Vec<u8>,
    pub p_hw: [u8; 32],
    /// SECRET witness signing key; erased at commit/cancel.
    pub sk_hw: Vec<u8>,
    pub receiver_challenge: [u8; 32],
}

impl Drop for PreparedRecord {
    /// Defense-in-depth: wipe `sk_hw` if the record is dropped without going
    /// through commit/cancel (e.g. an `Appliance` torn down while Prepared).
    fn drop(&mut self) {
        zeroize(&mut self.sk_hw);
    }
}

/// Committed record (§11.2): the signed release + the counter-committed flag.
pub struct CommittedRecord {
    pub prev_root: [u8; 32],
    pub next_root: [u8; 32],
    pub anchor_counter: u64,
    pub next_anchor_counter: u64,
    pub release: OfflineRelease,
    pub committed: bool,
}

pub enum Record {
    Empty,
    Prepared(Box<PreparedRecord>),
    Committed(Box<CommittedRecord>),
}

/// The single active state.
pub struct Active {
    pub root: [u8; 32],
    pub u: u64,
    pub status: Status,
    pub record: Record,
}

/// Recovery outcomes (§15).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoverOutcome {
    /// Nothing pending; offline-bearer accepts at the carried active root.
    Accept([u8; 32]),
    /// A committed successor (carried `hᵢ₊₁`) is pending: the record is left
    /// `Committed{committed:true}` so the caller re-emits it with [`Appliance::emit`]
    /// and advances with [`Appliance::finalize`] — recovery re-emits the *same*
    /// release, never signs a new one (§14.4/§14.5).
    ReemitCommitted([u8; 32]),
    DowngradeOnline,
    FailClosed,
    ExhaustedOnlineOnly,
    AcceptPreparedCanComplete,
    OnlineCancelOrResolve,
}

/// The offline-bearer appliance for one active root.
pub struct Appliance<T: Tropic, S: WitnessSig> {
    pub h0: u32,
    pub anchor_id: [u8; 32],
    pub slot: u16,
    pub active: Active,
    /// Set by recovery when `firmware_boundary_invalid` / `rmemory_map_invalid`.
    pub firmware_boundary_invalid: bool,
    pub rmemory_map_invalid: bool,
    tropic: T,
    _sig: PhantomData<S>,
}

impl<T: Tropic, S: WitnessSig> Appliance<T, S> {
    pub fn new(tropic: T, h0: u32, active_root: [u8; 32], anchor_id: [u8; 32], slot: u16) -> Self {
        Self {
            h0,
            anchor_id,
            slot,
            active: Active { root: active_root, u: 0, status: Status::Ready, record: Record::Empty },
            firmware_boundary_invalid: false,
            rmemory_map_invalid: false,
            tropic,
            _sig: PhantomData,
        }
    }

    /// Live anchor index `u = H₀ − H` from the chip counter. The counter only
    /// counts down, so `H ≤ H₀` always holds; a reported `H > H₀` is impossible
    /// under the counter assumption and is rejected rather than wrapping.
    pub fn live_index(&mut self) -> Result<u64, ApplianceError> {
        let h = self.tropic.counter_get().map_err(ApplianceError::Tropic)?;
        let u = self.h0.checked_sub(h).ok_or(ApplianceError::CounterMismatch)?;
        Ok(u as u64)
    }

    /// §11.1 Prepare: one MACANDD witness call for the exact root advance; build
    /// the cert material; store a durable Prepared record. No counter move, no
    /// export. Refused unless Ready and offline-ready (`active.u = H₀ − H`).
    pub fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
    ) -> Result<(), ApplianceError> {
        if self.active.status != Status::Ready {
            return Err(ApplianceError::WrongState);
        }
        if !ct_eq_32(&self.active.root, t.prev_root) {
            return Err(ApplianceError::PrevRootMismatch);
        }
        if t.anchor_counter != self.active.u {
            return Err(ApplianceError::IndexMismatch);
        }
        if t.next_anchor_counter != t.anchor_counter + 1 {
            return Err(ApplianceError::IndexMismatch);
        }
        let live_u = self.live_index()?;
        if self.active.u != live_u {
            return Err(ApplianceError::CounterMismatch);
        }

        let d = transition_digest(t);
        let x = witness_input(t, &d, &self.anchor_id, self.slot, receiver_challenge);
        let mut w = self
            .tropic
            .mac_and_destroy(self.slot, &x)
            .map_err(ApplianceError::Tropic)?;
        let mut k = witness_key_material(&w, &x, t, &self.anchor_id, self.slot);
        let (sk_hw, pk_hw) = S::keygen(&k);
        let p_hw = pk_hash(&pk_hw);
        let m = cert_message(t, &d, &x, &p_hw, &self.anchor_id, self.slot, receiver_challenge);

        // The raw witness output and key seed are not needed past key derivation.
        w.iter_mut().for_each(|b| *b = 0);
        k.iter_mut().for_each(|b| *b = 0);

        self.active.status = Status::Prepared;
        self.active.record = Record::Prepared(Box::new(PreparedRecord {
            txn: OwnedTransition::from(t),
            digest: d,
            witness_input: x,
            cert_message: m,
            pk_hw,
            p_hw,
            sk_hw,
            receiver_challenge: *receiver_challenge,
        }));
        Ok(())
    }

    /// §11.2 Commit, in the spec's three durable phases:
    ///   1. sign `M`, assemble the release, persist a `committed = false`
    ///      candidate, and erase `sk_hw` (σ is now in the release);
    ///   2. move the counter (`H ← H − 1`);
    ///   3. mark the candidate counter-committed.
    ///
    /// The release exists durably *before* the counter moves, so an interrupted
    /// commit is completable by [`recover`]. Nothing is exported before phase 2.
    pub fn commit(&mut self) -> Result<(), ApplianceError> {
        let p = match &self.active.record {
            Record::Prepared(p) => p,
            _ => return Err(ApplianceError::WrongState),
        };
        if p.sk_hw.is_empty() {
            return Err(ApplianceError::WitnessKeyLost);
        }
        let t = p.txn.as_transition();
        if !ct_eq_32(&p.txn.prev_root, &self.active.root) {
            return Err(ApplianceError::PrevRootMismatch);
        }

        // The counter must be movable AND still pinned to this transfer's parent
        // index — the RP2350 may have moved it out of band since prepare. The
        // counter counts down, so `live_u = H0 − H` must equal `anchor_counter`.
        let h = self.tropic.counter_get().map_err(ApplianceError::Tropic)?;
        if h == 0 {
            return Err(ApplianceError::CounterExhausted);
        }
        let live_u = self.h0.checked_sub(h).ok_or(ApplianceError::CounterMismatch)? as u64;
        if live_u != p.txn.anchor_counter {
            return Err(ApplianceError::CounterMismatch);
        }

        let sigma = S::sign(&p.sk_hw, &p.cert_message);
        let cert = Certificate {
            prev_root: p.txn.prev_root,
            next_root: p.txn.next_root,
            anchor_counter: p.txn.anchor_counter,
            next_anchor_counter: p.txn.next_anchor_counter,
            transition_digest: p.digest,
            witness_input: p.witness_input,
            pk_hash: p.p_hw,
            pk_hw: p.pk_hw.clone(),
            sigma,
            anchor_id: self.anchor_id,
            slot: self.slot,
            receiver_challenge: p.receiver_challenge,
        };
        let next_anchor_counter = p.txn.next_anchor_counter;
        let prev_root = p.txn.prev_root;
        let next_root = p.txn.next_root;
        let anchor_counter = p.txn.anchor_counter;
        let release = OfflineRelease {
            transition: OwnedTransition::from(&t),
            cert,
            // Appliance's own counter view (untrusted transport claims). The
            // receiver reads its own counter evidence over a verifier pairing
            // slot. The counter counts down: after phase 2 it will read `h - 1`
            // (safe, since `h ≥ 1` was just checked).
            counter: CounterEvidence {
                anchor_id: self.anchor_id,
                enrolled_counter: self.h0 as u64,
                live_counter_claim: (h - 1) as u64,
                derived_index_claim: next_anchor_counter,
                verifier_transcript: Vec::new(),
            },
        };

        // Phase 1: persist the committed candidate and erase the witness key.
        if let Record::Prepared(p) = &mut self.active.record {
            zeroize_vec(&mut p.sk_hw);
        }
        self.active.status = Status::Committed;
        self.active.record = Record::Committed(Box::new(CommittedRecord {
            prev_root,
            next_root,
            anchor_counter,
            next_anchor_counter,
            release,
            committed: false,
        }));

        // Phase 2: move the counter. On failure nothing is exported; the durable
        // candidate (committed = false, counter not moved) is completed by recovery.
        self.tropic
            .counter_update()
            .map_err(|_| ApplianceError::CounterExhausted)?;

        // Phase 3: mark counter-committed; the index now reflects the moved counter.
        if let Record::Committed(c) = &mut self.active.record {
            c.committed = true;
        }
        self.active.u = next_anchor_counter;
        Ok(())
    }

    /// §11.4 Emit: export the committed release (Δ + Cert). The receiver attaches
    /// its own counter evidence and verifies.
    pub fn emit(&self) -> Result<&OfflineRelease, ApplianceError> {
        match &self.active.record {
            Record::Committed(c) if c.committed => Ok(&c.release),
            _ => Err(ApplianceError::NotCommitted),
        }
    }

    /// §11.5 Finalize: advance the active root to `hᵢ₊₁` and return to Ready.
    pub fn finalize(&mut self) -> Result<[u8; 32], ApplianceError> {
        let next_root = match &self.active.record {
            Record::Committed(c) if c.committed => c.next_root,
            _ => return Err(ApplianceError::NotCommitted),
        };
        // §19 TLA+ Finalize guard: the active index must equal the live counter
        // index before advancing, so a breached or partially-restored state
        // cannot install a successor root out of step with the physical counter.
        let live_u = self.live_index()?;
        if self.active.u != live_u {
            return Err(ApplianceError::CounterMismatch);
        }
        self.active = Active {
            root: next_root,
            u: self.active.u,
            status: Status::Ready,
            record: Record::Empty,
        };
        Ok(next_root)
    }

    /// Cancel a prepared (not yet committed) record, erasing its witness key.
    pub fn cancel(&mut self) -> Result<(), ApplianceError> {
        match &mut self.active.record {
            Record::Prepared(p) => {
                zeroize_vec(&mut p.sk_hw);
                self.active.status = Status::Ready;
                self.active.record = Record::Empty;
                Ok(())
            }
            _ => Err(ApplianceError::WrongState),
        }
    }

    /// §15 power-loss recovery. Operates on the durable active record and never
    /// signs a new successor — a committed record is re-emitted and finalized as
    /// the *same* successor (the caller drives [`emit`]/[`finalize`] on a
    /// [`RecoverOutcome::ReemitCommitted`]).
    pub fn recover(&mut self) -> RecoverOutcome {
        if self.firmware_boundary_invalid || self.rmemory_map_invalid {
            return RecoverOutcome::DowngradeOnline;
        }
        let live_u = match self.live_index() {
            Ok(u) => u,
            Err(_) => return RecoverOutcome::DowngradeOnline,
        };

        match self.active.status {
            Status::Committed => {
                let (committed, rec_u, next_root, prev_root) = match &self.active.record {
                    Record::Committed(c) => (c.committed, c.next_anchor_counter, c.next_root, c.prev_root),
                    _ => return RecoverOutcome::DowngradeOnline,
                };
                if committed {
                    // §14.4/§14.5: counter already moved. Re-emit + finalize the
                    // same successor; leave the record intact for emit()/finalize().
                    if rec_u != live_u {
                        return RecoverOutcome::DowngradeOnline;
                    }
                    self.active.u = rec_u;
                    RecoverOutcome::ReemitCommitted(next_root)
                } else if rec_u == live_u + 1 {
                    // §14.3: durable release, counter not yet moved. Complete the
                    // counter commit only if the parent/policy still matches the
                    // active root (the SMT root commits authority_policy_hash).
                    if !ct_eq_32(&prev_root, &self.active.root) {
                        return RecoverOutcome::DowngradeOnline;
                    }
                    if self.tropic.counter_update().is_err() {
                        return RecoverOutcome::DowngradeOnline;
                    }
                    if let Record::Committed(c) = &mut self.active.record {
                        c.committed = true;
                    }
                    self.active.u = rec_u;
                    RecoverOutcome::ReemitCommitted(next_root)
                } else if rec_u == live_u {
                    // §14.4 corner: counter already moved but the committed flag
                    // was not persisted (crash between the step and the flag).
                    // Mark it and re-emit; the counter must NOT move again.
                    if let Record::Committed(c) = &mut self.active.record {
                        c.committed = true;
                    }
                    self.active.u = rec_u;
                    RecoverOutcome::ReemitCommitted(next_root)
                } else {
                    // rec_u < live_u (stale) or rec_u > live_u + 1 (impossible jump).
                    RecoverOutcome::DowngradeOnline
                }
            }
            Status::Prepared => {
                if self.active.u != live_u {
                    return RecoverOutcome::DowngradeOnline;
                }
                // §15(2): the prepared record's parent must still be the active
                // root (no intervening online advance) before it may complete.
                let parent_ok = matches!(
                    &self.active.record,
                    Record::Prepared(p) if ct_eq_32(&p.txn.prev_root, &self.active.root)
                );
                if !parent_ok {
                    return RecoverOutcome::DowngradeOnline;
                }
                let key_present = matches!(&self.active.record, Record::Prepared(p) if !p.sk_hw.is_empty());
                if key_present {
                    RecoverOutcome::AcceptPreparedCanComplete
                } else {
                    RecoverOutcome::OnlineCancelOrResolve
                }
            }
            Status::Ready => {
                if self.active.u < live_u {
                    return RecoverOutcome::DowngradeOnline;
                }
                if self.active.u > live_u {
                    return RecoverOutcome::FailClosed;
                }
                let h = match self.tropic.counter_get() {
                    Ok(h) => h,
                    Err(_) => return RecoverOutcome::DowngradeOnline,
                };
                if h == 0 {
                    return RecoverOutcome::ExhaustedOnlineOnly;
                }
                RecoverOutcome::Accept(self.active.root)
            }
        }
    }
}
