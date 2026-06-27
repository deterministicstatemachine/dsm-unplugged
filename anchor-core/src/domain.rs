//! Canonical domain tags for the Root Advance MACANDD construction.
//! These strings are normative: the receiver recomputes every value with the
//! exact same tag, so they must match across the appliance and all verifiers.

// --- Root advance objects ---
/// Transition digest D (Def. 14): D = H(tag ‖ enc(Δ)).
pub const TRANSITION_DIGEST_V1: &str = "DSM/root-advance/transition-digest/v1";
/// MACANDD witness input X (Def. 16).
pub const ROOT_ADVANCE_INPUT_V1: &str = "DSM/tropic/root-advance-input/v1";
/// Witness signing seed K (Def. 17): keyed by the MACANDD output W.
pub const ROOT_ADVANCE_WITNESS_KEY_V1: &str = "DSM/tropic/root-advance-witness-key/v1";
/// Committed public-witness-key handle P_hw (Def. 17).
pub const PK_HASH_V1: &str = "DSM/tropic/pk-hash/v1";
/// Root advance certificate message M (Def. 21): the signed digest.
pub const CERT_MESSAGE_V1: &str = "DSM/root-advance/cert-message/v1";

// --- WOTS-over-BLAKE3 witness signature (Defs. 18–20) ---
/// WOTS chain step function F.
pub const WOTS_CHAIN_V1: &str = "DSM/anchor/wots-chain/v1";
/// WOTS per-chain secret derivation from the seed.
pub const WOTS_SK_V1: &str = "DSM/anchor/wots-sk/v1";
/// WOTS public-key compression of the chain tops.
pub const WOTS_PK_V1: &str = "DSM/anchor/wots-pk/v1";
