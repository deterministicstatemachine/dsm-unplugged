//! The TROPIC01 secure-element abstraction the root-advance witness flow needs,
//! plus the pluggable witness signature scheme (StepKeyGen / StepSign /
//! StepVerify), "fixed by the appliance profile" (§4); the profile is WOTS over
//! BLAKE3 (`sig::WotsBlake3`).
//!
//! Keeping both as traits lets the protocol core stay hardware- and
//! scheme-agnostic and unit-test on the host with a deterministic mock; the
//! firmware wires the real libtropic `MAC_And_Destroy` / `MCounter` and the
//! chosen signature scheme.

extern crate alloc;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TropicError {
    /// SPI / L3-session failure, or chip absent.
    Comm,
    /// The selected MACANDD slot is not in the expected armed state.
    NotArmed,
    /// `MCounter_Update` on an exhausted counter (`H == 0`) — online only.
    CounterExhausted,
}

/// TROPIC01 primitives used over an authenticated L3 session, mediated by the
/// RP2350 secure partition. The non-secure partition/host cannot invoke these.
pub trait Tropic {
    /// `W = MACANDD(q, X)` — one call evolves slot `q`'s state and returns the
    /// 32-byte witness output (Def. 12/13). A slot must be armed first.
    fn mac_and_destroy(&mut self, q: u16, x: &[u8; 32]) -> Result<[u8; 32], TropicError>;

    /// Live monotonic down-counter value `H` (§4); `u = H₀ − H`.
    fn counter_get(&mut self) -> Result<u32, TropicError>;

    /// `MCounter_Update`: `H ← H − 1`. Returns [`TropicError::CounterExhausted`]
    /// if `H == 0`.
    fn counter_update(&mut self) -> Result<(), TropicError>;
}

/// The hardware-witness signature scheme (deterministic from a 32-byte seed).
/// `keygen` is StepKeyGen, `sign` is StepSign, `verify` is StepVerify (§4, §9).
/// `pk`/`sig` are scheme-sized byte strings.
pub trait WitnessSig {
    /// Deterministic `(sk, pk)` from a 32-byte seed (the witness key material K).
    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>);
    /// Deterministic signature over a 32-byte digest under `sk`.
    fn sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8>;
    /// Verify a signature over a 32-byte digest under `pk`.
    fn verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool;
}
