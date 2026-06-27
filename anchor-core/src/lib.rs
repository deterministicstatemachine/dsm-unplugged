//! `dsm-anchor-core` — hardware-free core of the DSM **Root Advance MACANDD**
//! offline-bearer anchor (Pico 2 W + Secure Tropic Click / TROPIC01).
//!
//! The secure element is NOT the transaction authorizer. The authority is to
//! *certify exactly one root advance from the current DSM root, then move the
//! counter*. The anchor index `uᵢ` is committed by the parent DSM SMT root, so
//! the only valid successor index is `uᵢ+1` — this replaces any precommit table.
//! The TROPIC01 **MAC-And-Destroy** output is an unclonable hardware *witness*
//! bound into the advance (`P_hw = H(pk_hw)`); a monotonic **down-counter**
//! (`u = H₀ − H`) gives the non-rewind index; the receiver reads **counter
//! evidence** directly from the chip over an authenticated L3 verifier session;
//! and **Tripwire** exposes any divergent closed branch on reconciliation.
//!
//! This crate is `no_std` (+`alloc`) so the protocol math unit-tests on the host
//! (`cargo test -p dsm-anchor-core`) and builds for the RP2350 secure partition.
//! The firmware wires the real libtropic `MAC_And_Destroy`/`MCounter` and the
//! chosen witness signature scheme behind the [`tropic::Tropic`] and
//! [`tropic::WitnessSig`] traits.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod accept;
pub mod appliance;
pub mod domain;
pub mod hash;
pub mod proto;
pub mod root_advance;
pub mod service;
pub mod sig;
pub mod tropic;
pub mod util;
