//! End-to-end tests for the Root Advance MACANDD appliance: the 3-state
//! lifecycle, the §12 receiver acceptance predicate (valid + every check
//! tampered), §15 recovery, and the protobuf wire protocol.

use anchor_core::accept::{accept_offline, AcceptError, CounterVerifier, DsmVerifier, VerifierContext};
use anchor_core::appliance::{
    Appliance, ApplianceError, CommittedRecord, RecoverOutcome, Record, Status,
};
use anchor_core::proto::{decode_request, decode_response, encode_request, pb};
use anchor_core::root_advance::{CounterEvidence, OfflineRelease, OwnedTransition, Transition};
use anchor_core::service::handle;
use anchor_core::sig::WotsBlake3;
use anchor_core::tropic::{Tropic, TropicError};

const H0: u32 = 100;
const ANCHOR: [u8; 32] = [0xAA; 32];
const SLOT: u16 = 1;
const ROOT0: [u8; 32] = [0x11; 32];
const ROOT1: [u8; 32] = [0x22; 32];
const POLICY: [u8; 32] = [0x33; 32];
const RECIP: [u8; 32] = [0x44; 32];
const RCHAL: [u8; 32] = [0x55; 32];

/// A deterministic TROPIC01 stand-in: a down-counter and an internal MACANDD
/// secret the host cannot see.
struct MockTropic {
    h: u32,
    secret: [u8; 32],
}
impl MockTropic {
    fn with_h(h: u32) -> Self {
        Self { h, secret: [0xC0; 32] }
    }
}
impl Tropic for MockTropic {
    fn mac_and_destroy(&mut self, q: u16, x: &[u8; 32]) -> Result<[u8; 32], TropicError> {
        Ok(anchor_core::hash::kdf(&self.secret, "test/macandd", &[&q.to_le_bytes(), x]))
    }
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        Ok(self.h)
    }
    fn counter_update(&mut self) -> Result<(), TropicError> {
        if self.h == 0 {
            return Err(TropicError::CounterExhausted);
        }
        self.h -= 1;
        Ok(())
    }
}

fn app(h: u32) -> Appliance<MockTropic, WotsBlake3> {
    Appliance::new(MockTropic::with_h(h), H0, ROOT0, ANCHOR, SLOT)
}

fn make_transition(prev_root: [u8; 32], next_root: [u8; 32], anchor_counter: u64) -> OwnedTransition {
    OwnedTransition {
        relationship_id: [1; 32],
        object_id: [2; 32],
        sender_device_id: [3; 32],
        recipient_device_id: RECIP,
        prev_root,
        next_root,
        anchor_counter,
        next_anchor_counter: anchor_counter + 1,
        action_type: 0,
        action_fields: vec![9, 9, 9],
        payload_hash: [6; 32],
        old_leaf_proof: vec![0xAB; 40],
        new_leaf_proof: vec![0xCD; 40],
        authority_policy_hash: POLICY,
    }
}

/// Build a fully valid release: prepare → commit → emit on a fresh appliance.
fn valid_release() -> OfflineRelease {
    let mut a = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap();
    a.emit().unwrap().clone()
}

fn ctx() -> VerifierContext<'static> {
    VerifierContext {
        accepted_prev_root: &ROOT0,
        pinned_anchor_id: &ANCHOR,
        expected_receiver_challenge: &RCHAL,
        expected_policy_hash: &POLICY,
        enrolled_counter: H0 as u64,
        exposure_cap_index: 1_000,
        anchor_uncompromised: true,
    }
}

struct OkDsm;
impl DsmVerifier for OkDsm {
    fn root_commits_counter(&self, _r: &[u8; 32], _i: u64) -> bool {
        true
    }
    fn verify_transition(&self, _t: &Transition) -> bool {
        true
    }
    fn delivers_to_receiver(&self, _t: &Transition) -> bool {
        true
    }
}
struct OkCounter;
impl CounterVerifier for OkCounter {
    // Simulate a genuine verifier-pairing-slot read that attests the evidence's
    // claimed live counter (a faithful transcript).
    fn read_authentic_counter(&self, _a: &[u8; 32], ev: &CounterEvidence) -> Option<u64> {
        Some(ev.live_counter_claim)
    }
}

fn check(rel: &OfflineRelease, c: &VerifierContext) -> Result<(), AcceptError> {
    accept_offline::<WotsBlake3, OkDsm, OkCounter>(rel, c, &OkDsm, &OkCounter)
}

// --- 3-state lifecycle ---

#[test]
fn full_lifecycle_prepare_commit_emit_finalize() {
    let mut a = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);

    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    assert_eq!(a.active.status, Status::Prepared);
    // Root stays at the parent until finalize; no counter move yet.
    assert_eq!(a.active.root, ROOT0);

    a.commit().unwrap();
    assert_eq!(a.active.status, Status::Committed);
    assert_eq!(a.active.u, 1);
    assert_eq!(a.active.root, ROOT0); // still the parent until finalize

    let rel = a.emit().unwrap().clone();
    assert_eq!(rel.cert.next_root, ROOT1);
    assert_eq!(rel.cert.next_anchor_counter, 1);

    let h_next = a.finalize().unwrap();
    assert_eq!(h_next, ROOT1);
    assert_eq!(a.active.root, ROOT1);
    assert_eq!(a.active.u, 1);
    assert_eq!(a.active.status, Status::Ready);
}

#[test]
fn two_sequential_transfers() {
    let mut a = app(H0);
    let t0 = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t0.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap();
    a.finalize().unwrap();

    // Second advance from the new root at index 1; live_u = H0 - 99 = 1.
    let root2 = [0x77; 32];
    let t1 = make_transition(ROOT1, root2, 1);
    a.prepare(&t1.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap();
    assert_eq!(a.active.u, 2);
    assert_eq!(a.finalize().unwrap(), root2);
}

#[test]
fn prepare_twice_is_rejected() {
    let mut a = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    assert_eq!(a.prepare(&t.as_transition(), &RCHAL), Err(ApplianceError::WrongState));
}

#[test]
fn commit_without_prepare_is_rejected() {
    let mut a = app(H0);
    assert_eq!(a.commit(), Err(ApplianceError::WrongState));
}

#[test]
fn emit_without_commit_is_rejected() {
    let a = app(H0);
    assert_eq!(a.emit().err(), Some(ApplianceError::NotCommitted));
}

#[test]
fn prepare_rejects_wrong_parent_and_bad_index() {
    let mut a = app(H0);
    let bad_parent = make_transition([0xEE; 32], ROOT1, 0);
    assert_eq!(
        a.prepare(&bad_parent.as_transition(), &RCHAL),
        Err(ApplianceError::PrevRootMismatch)
    );
    // anchor_counter 0 ok, but force next_anchor_counter != anchor_counter + 1.
    let mut skip = make_transition(ROOT0, ROOT1, 0);
    skip.next_anchor_counter = 5;
    assert_eq!(a.prepare(&skip.as_transition(), &RCHAL), Err(ApplianceError::IndexMismatch));
}

#[test]
fn cancel_returns_to_ready_and_clears_record() {
    let mut a = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    a.cancel().unwrap();
    assert_eq!(a.active.status, Status::Ready);
    assert!(matches!(a.active.record, Record::Empty));
    // Cancelling with nothing prepared is rejected.
    assert_eq!(a.cancel(), Err(ApplianceError::WrongState));
}

#[test]
fn commit_on_exhausted_counter_exports_nothing() {
    // The counter has counted all the way down: enrolled H0 = 100, live H = 0,
    // so u = 100. Offline-ready at index 100, but the counter cannot move, so
    // commit refuses and exports nothing.
    let mut a = Appliance::<MockTropic, WotsBlake3>::new(MockTropic::with_h(0), H0, ROOT0, ANCHOR, SLOT);
    a.active.u = H0 as u64; // live_u = H0 - 0 = 100
    let t = make_transition(ROOT0, ROOT1, H0 as u64);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    assert_eq!(a.commit(), Err(ApplianceError::CounterExhausted));
    // No release was produced.
    assert_eq!(a.emit().err(), Some(ApplianceError::NotCommitted));
}

// --- §12 acceptance predicate ---

#[test]
fn accept_valid_release() {
    check(&valid_release(), &ctx()).unwrap();
}

#[test]
fn accept_rejects_noncanonical_cert_disagreement() {
    let mut rel = valid_release();
    rel.cert.next_anchor_counter += 1; // cert disagrees with Δ
    assert_eq!(check(&rel, &ctx()), Err(AcceptError::NonCanonical));
}

#[test]
fn accept_rejects_unaccepted_parent_and_unpinned_anchor() {
    let rel = valid_release();
    let other = [0xFE; 32];
    let mut c = ctx();
    c.accepted_prev_root = &other;
    assert_eq!(check(&rel, &c), Err(AcceptError::PrevRootNotAccepted));
    let mut c = ctx();
    c.pinned_anchor_id = &other;
    assert_eq!(check(&rel, &c), Err(AcceptError::PrevRootNotAccepted));
}

#[test]
fn accept_rejects_wrong_challenge_and_policy() {
    let rel = valid_release();
    let other = [0xFD; 32];
    let mut c = ctx();
    c.expected_receiver_challenge = &other;
    assert_eq!(check(&rel, &c), Err(AcceptError::ChallengeMismatch));
    let mut c = ctx();
    c.expected_policy_hash = &other;
    assert_eq!(check(&rel, &c), Err(AcceptError::PolicyMismatch));
}

#[test]
fn accept_rejects_tampered_digest_input_pkhash_and_sig() {
    let mut rel = valid_release();
    rel.cert.transition_digest[0] ^= 0xFF;
    assert_eq!(check(&rel, &ctx()), Err(AcceptError::DigestMismatch));

    let mut rel = valid_release();
    rel.cert.witness_input[0] ^= 0xFF;
    assert_eq!(check(&rel, &ctx()), Err(AcceptError::WitnessInputMismatch));

    let mut rel = valid_release();
    rel.cert.pk_hash[0] ^= 0xFF;
    assert_eq!(check(&rel, &ctx()), Err(AcceptError::PkHashMismatch));

    let mut rel = valid_release();
    rel.cert.sigma[0] ^= 0xFF;
    assert_eq!(check(&rel, &ctx()), Err(AcceptError::WitnessSigInvalid));
}

#[test]
fn accept_rejects_dsm_proof_failures() {
    struct FailParent;
    impl DsmVerifier for FailParent {
        fn root_commits_counter(&self, _: &[u8; 32], _: u64) -> bool {
            false
        }
        fn verify_transition(&self, _: &Transition) -> bool {
            true
        }
        fn delivers_to_receiver(&self, _: &Transition) -> bool {
            true
        }
    }
    struct FailTransition;
    impl DsmVerifier for FailTransition {
        fn root_commits_counter(&self, _: &[u8; 32], _: u64) -> bool {
            true
        }
        fn verify_transition(&self, _: &Transition) -> bool {
            false
        }
        fn delivers_to_receiver(&self, _: &Transition) -> bool {
            true
        }
    }
    struct FailDeliver;
    impl DsmVerifier for FailDeliver {
        fn root_commits_counter(&self, _: &[u8; 32], _: u64) -> bool {
            true
        }
        fn verify_transition(&self, _: &Transition) -> bool {
            true
        }
        fn delivers_to_receiver(&self, _: &Transition) -> bool {
            false
        }
    }
    let rel = valid_release();
    let c = ctx();
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &c, &FailParent, &OkCounter),
        Err(AcceptError::AnchorCounterUncommitted)
    );
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &c, &FailTransition, &OkCounter),
        Err(AcceptError::TransitionProofInvalid)
    );
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &c, &FailDeliver, &OkCounter),
        Err(AcceptError::NotDeliveredToReceiver)
    );
}

#[test]
fn accept_rejects_counter_evidence_problems() {
    // A transcript attesting the wrong value (claim is consistent but the chip
    // read disagrees with H0 - next_anchor_counter).
    let mut rel = valid_release();
    rel.counter.live_counter_claim += 1;
    assert_eq!(check(&rel, &ctx()), Err(AcceptError::CounterEvidenceInvalid));

    // Correct arithmetic but an inauthentic transcript (no chip read).
    struct FailCounter;
    impl CounterVerifier for FailCounter {
        fn read_authentic_counter(&self, _: &[u8; 32], _: &CounterEvidence) -> Option<u64> {
            None
        }
    }
    let rel = valid_release();
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &ctx(), &OkDsm, &FailCounter),
        Err(AcceptError::CounterEvidenceInvalid)
    );

    // A breached RP2350 forges live_counter to the expected value but the
    // receiver's own chip read disagrees -> rejected (the trust seam, #3).
    struct LyingChip;
    impl CounterVerifier for LyingChip {
        fn read_authentic_counter(&self, _: &[u8; 32], _: &CounterEvidence) -> Option<u64> {
            Some(42) // the real chip value, != H0 - next_anchor_counter
        }
    }
    let rel = valid_release(); // ships live_counter == expected (99)
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &ctx(), &OkDsm, &LyingChip),
        Err(AcceptError::CounterEvidenceInvalid)
    );
}

#[test]
fn accept_rejects_exposure_cap_and_compromise() {
    let rel = valid_release();
    let mut c = ctx();
    c.exposure_cap_index = 0; // next_anchor_counter 1 exceeds the cap
    assert_eq!(check(&rel, &c), Err(AcceptError::ExposureCapExceeded));

    let mut c = ctx();
    c.anchor_uncompromised = false;
    assert_eq!(check(&rel, &c), Err(AcceptError::AnchorCompromised));
}

// --- §15 recovery ---

#[test]
fn recover_ready_accepts_current_root() {
    let mut a = app(H0);
    assert_eq!(a.recover(), RecoverOutcome::Accept(ROOT0));
}

#[test]
fn recover_committed_reemits_and_advances() {
    let mut a = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap(); // counter -> 99, active.u = 1, committed
    // Recovery preserves the committed record so the SAME release re-emits.
    assert_eq!(a.recover(), RecoverOutcome::ReemitCommitted(ROOT1));
    let rel = a.emit().unwrap().clone();
    assert_eq!(rel.cert.next_root, ROOT1);
    check(&rel, &ctx()).unwrap();
    // Then finalize advances to the same successor.
    assert_eq!(a.finalize().unwrap(), ROOT1);
    assert_eq!(a.active.root, ROOT1);
    assert_eq!(a.active.status, Status::Ready);
}

#[test]
fn recover_prepared_can_complete() {
    let mut a = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    assert_eq!(a.recover(), RecoverOutcome::AcceptPreparedCanComplete);
}

#[test]
fn recover_prepared_downgrades_when_parent_diverged() {
    // §15(2): a prepared record whose parent no longer equals the active root
    // (e.g. an intervening online advance) must not complete offline.
    let mut a = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    a.active.root = [0x9E; 32];
    assert_eq!(a.recover(), RecoverOutcome::DowngradeOnline);
}

#[test]
fn recover_ready_stale_downgrades_and_ahead_fails_closed() {
    // Complete a transfer so the counter is at 99 (live_u = 1), then restore a
    // stale active index 0 -> downgrade.
    let mut a = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap();
    a.finalize().unwrap(); // Ready, u = 1, counter 99
    a.active.u = 0; // stale restore
    assert_eq!(a.recover(), RecoverOutcome::DowngradeOnline);

    // Active index ahead of the physical counter -> fail closed.
    let mut a = app(H0);
    a.active.u = 5;
    assert_eq!(a.recover(), RecoverOutcome::FailClosed);
}

#[test]
fn recover_completes_durable_release_before_counter_commit() {
    // §14.3: committed candidate written, counter NOT yet moved (still 100,
    // live_u = 0), record.next_anchor_counter = 1 = live_u + 1 -> recovery moves the
    // counter once, then re-emits + finalizes the same successor.
    let mut a = app(H0);
    let rel = valid_release();
    a.active.status = Status::Committed;
    a.active.u = 0;
    a.active.record = Record::Committed(Box::new(CommittedRecord {
        prev_root: ROOT0,
        next_root: ROOT1,
        anchor_counter: 0,
        next_anchor_counter: 1,
        release: rel,
        committed: false,
    }));
    assert_eq!(a.recover(), RecoverOutcome::ReemitCommitted(ROOT1));
    assert_eq!(a.live_index().unwrap(), 1, "counter moved exactly once");
    a.emit().unwrap();
    assert_eq!(a.finalize().unwrap(), ROOT1);
    assert_eq!(a.active.status, Status::Ready);
}

#[test]
fn recover_marks_committed_when_counter_moved_but_flag_lost() {
    // §14.4 corner: counter already moved (h = 99, live_u = 1) but committed flag
    // not persisted; record.next_anchor_counter = 1 = live_u -> mark committed, re-emit,
    // counter must NOT move again.
    let mut a = Appliance::<MockTropic, WotsBlake3>::new(MockTropic::with_h(99), H0, ROOT0, ANCHOR, SLOT);
    let rel = valid_release();
    a.active.status = Status::Committed;
    a.active.u = 0;
    a.active.record = Record::Committed(Box::new(CommittedRecord {
        prev_root: ROOT0,
        next_root: ROOT1,
        anchor_counter: 0,
        next_anchor_counter: 1,
        release: rel,
        committed: false,
    }));
    assert_eq!(a.recover(), RecoverOutcome::ReemitCommitted(ROOT1));
    assert_eq!(a.live_index().unwrap(), 1, "counter must not move again");
    a.emit().unwrap();
    assert_eq!(a.finalize().unwrap(), ROOT1);
}

#[test]
fn recover_downgrades_when_parent_diverged() {
    // §14.3 guard (#8): durable candidate, counter not moved, but active.root no
    // longer matches the record's prev_root -> do not burn a counter step.
    let mut a = app(H0);
    let rel = valid_release();
    a.active.root = [0x9E; 32]; // diverged (e.g. an intervening online advance)
    a.active.status = Status::Committed;
    a.active.u = 0;
    a.active.record = Record::Committed(Box::new(CommittedRecord {
        prev_root: ROOT0,
        next_root: ROOT1,
        anchor_counter: 0,
        next_anchor_counter: 1,
        release: rel,
        committed: false,
    }));
    assert_eq!(a.recover(), RecoverOutcome::DowngradeOnline);
    assert_eq!(a.live_index().unwrap(), 0, "counter not burned");
}

#[test]
fn recover_downgrades_on_invalid_boundary() {
    let mut a = app(H0);
    a.firmware_boundary_invalid = true;
    assert_eq!(a.recover(), RecoverOutcome::DowngradeOnline);
}

// --- wire protocol ---

#[test]
fn proto_request_roundtrip() {
    let t = make_transition(ROOT0, ROOT1, 0);
    let req = pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(t.to_pb()),
        receiver_challenge: RCHAL.to_vec(),
    };
    let back = decode_request(&encode_request(&req)).unwrap();
    assert_eq!(back.op, pb::Op::Prepare as i32);
    let owned = back.transition.unwrap().to_owned_transition().unwrap();
    assert_eq!(owned.prev_root, ROOT0);
    assert_eq!(owned.next_root, ROOT1);
    assert_eq!(owned.next_anchor_counter, 1);
    assert_eq!(back.receiver_challenge, RCHAL.to_vec());
}

#[test]
fn proto_release_roundtrip() {
    let rel = valid_release();
    let back = rel.to_pb().to_release().unwrap();
    assert_eq!(back.cert.sigma, rel.cert.sigma);
    assert_eq!(back.cert.pk_hw, rel.cert.pk_hw);
    assert_eq!(back.cert.slot, SLOT);
    assert_eq!(back.counter.derived_index_claim, 1);
    assert_eq!(back.transition.next_root, ROOT1);
    // A decoded release still accepts.
    check(&back, &ctx()).unwrap();
}

#[test]
fn service_handle_full_flow() {
    let mut a = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);

    let prep = pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(t.to_pb()),
        receiver_challenge: RCHAL.to_vec(),
    };
    let r = decode_response(&handle(&mut a, &encode_request(&prep))).unwrap();
    assert!(r.ok, "prepare failed: error {}", r.error);

    let commit = pb::ApplianceRequest { op: pb::Op::Commit as i32, ..Default::default() };
    let r = decode_response(&handle(&mut a, &encode_request(&commit))).unwrap();
    assert!(r.ok, "commit failed: error {}", r.error);

    let emit = pb::ApplianceRequest { op: pb::Op::Emit as i32, ..Default::default() };
    let r = decode_response(&handle(&mut a, &encode_request(&emit))).unwrap();
    assert!(r.ok);
    let rel = r.release.unwrap().to_release().unwrap();
    check(&rel, &ctx()).unwrap();

    let fin = pb::ApplianceRequest { op: pb::Op::Finalize as i32, ..Default::default() };
    let r = decode_response(&handle(&mut a, &encode_request(&fin))).unwrap();
    assert!(r.ok);
    assert_eq!(r.active_root, ROOT1.to_vec());

    let status = pb::ApplianceRequest { op: pb::Op::Status as i32, ..Default::default() };
    let r = decode_response(&handle(&mut a, &encode_request(&status))).unwrap();
    assert_eq!(r.active_root, ROOT1.to_vec());
    assert_eq!(r.active_index, 1);
    assert_eq!(r.status, 0); // Ready
}

#[test]
fn service_rejects_oversized_and_malformed_frames() {
    let mut a = app(H0);
    let huge = vec![0u8; anchor_core::service::MAX_FRAME_LEN + 1];
    let r = decode_response(&handle(&mut a, &huge)).unwrap();
    assert!(!r.ok);
    assert_eq!(r.error, anchor_core::service::err::FRAME_TOO_LARGE);

    let r = decode_response(&handle(&mut a, &[0xFF, 0xFF, 0xFF])).unwrap();
    assert!(!r.ok);
}
