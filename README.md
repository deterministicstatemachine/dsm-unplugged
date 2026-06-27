# dsm-unplugged

A **DSM offline-bearer anchor**: a **Raspberry Pi Pico 2 W** (RP2350) driving a
**TROPIC01** secure element (MIKROE *Secure Tropic Click*, MIKROE-6559) over SPI
at 3.3 V, so a Deterministic State Machine wallet can accept a transfer **while
offline** — no network, validator, sequencer, or clock on the path.

This implements the **Root Advance MACANDD Authority** design. The authority is
one rule:

> **certify one root advance from the current DSM root, then move the counter.**

The secure element is **not** the transaction authorizer. The object being
authorized is a normal DSM sparse-Merkle-tree (SMT) root advance

```
(hᵢ, uᵢ) ──► (hᵢ₊₁, uᵢ+1)
```

where `hᵢ` is the parent root the receiver recognizes and `uᵢ` is the anchor
index the parent state **commits to**. Because the parent root commits `uᵢ`, the
only valid offline successor index is `uᵢ+1` — this replaces any table of
offered/pending precommits. The pieces:

| Job | Mechanism | Role |
|---|---|---|
| Valid state transition | **DSM SMT proof** `hᵢ → hᵢ₊₁` | the actual authorizer (public, receiver-verified) |
| Original-hardware presence | TROPIC01 **MAC-And-Destroy** witness `W` | unclonable hardware *witness* |
| Non-rewind index | TROPIC01 **monotonic down-counter**, `u = H₀ − H` | exact next-step proof |
| Counterparty binding | fresh **receiver challenge** `r_R` | freshness + recipient binding |
| Fork exclusion | DSM **Tripwire** (per-device SMT) | exposure on reconciliation |

The key point: **`W` is never accepted by itself.** It is folded into a witness
signing key whose public key is bound into the root-advance certificate, and the
receiver accepts only on a publicly valid DSM root advance plus an
**authenticated** TROPIC01 counter read it performs itself:

```
W = MACANDD(q, X) ──► K = HKDF(W, …) ──► (sk_hw, pk_hw) = StepKeyGen(K) ──► P_hw = H(pk_hw)
σ = StepSign(sk_hw, M)      M = H("…/cert-message/v1" ‖ hᵢ ‖ hᵢ₊₁ ‖ uᵢ ‖ uᵢ+1 ‖ D ‖ X ‖ P_hw ‖ … ‖ r_R)
```

The full design (definitions, theorems, TLA⁺ model, wire schema, validation
plan) is the companion paper *Root Advance MACANDD Authority for DSM Offline
Bearer State*.

## Why the receiver is safe

A software clone gets every host-readable file but **not** the TROPIC01 internal
MAC-And-Destroy state or live counter, so it cannot produce the witness
(Theorem 24). A breached RP2350 can waste counter steps, emit invalid packages,
or brick the appliance, but **cannot** make an honest receiver accept anything,
because the receiver:

1. verifies the DSM transition proof `hᵢ → hᵢ₊₁` itself,
2. verifies the WOTS witness signature under the committed `pk_hw`,
3. requires the parent-committed index `uᵢ` and next index `uᵢ+1`,
4. binds its own fresh challenge `r_R`, and
5. reads the live TROPIC01 counter over its **own** authenticated L3 verifier
   session and checks `H = H₀ − (uᵢ+1)` — it never trusts a host-supplied
   counter field.

After one counter commit the physical down-counter can never again present the
evidence for a second transfer from the same parent (Theorem 26), so an RP2350
breach is a denial of service, not a double-spend.

## Layout

```
anchor-core/      hardware-free protocol core + receiver predicate (no_std + alloc, host-testable)
  src/domain.rs       canonical "DSM/.../v1" domain-separation tags
  src/hash.rs         H = BLAKE3-256 and the keyed-BLAKE3 KDF
  src/util.rs         ct_eq, little-endian int encoders, push_var (u32-length-prefixed fields)
  src/root_advance.rs Δ transition package, transition digest D, witness input X,
                      witness key K, P_hw, cert message M, Certificate / CounterEvidence / OfflineRelease
  src/tropic.rs       `Tropic` trait (mac_and_destroy / counter) + `WitnessSig`
                      trait (StepKeyGen / StepSign / StepVerify) — firmware-pluggable
  src/sig.rs          WOTS-over-BLAKE3 one-time witness signature (n=32, w=16, ℓ=67; σ=2144 B, pk=32 B)
  src/appliance.rs    the compact 3-state machine (Ready→Prepared→Committed) + §15 power-loss recovery
  src/accept.rs       accept_offline: the §12 (Def. 22) 17-check receiver predicate,
                      with DsmVerifier + CounterVerifier supplied by the receiver
  src/proto.rs        prost wire bindings for proto/dsm_anchor.proto + conversions
  src/service.rs      the secure-core `handle(bytes) -> bytes` op dispatch
  tests/integration.rs  full lifecycle, the 17-check predicate (valid + each check tampered),
                        recovery, and wire round-trips (33 tests)
firmware/         RP2350 (Pico 2 W) binary (no_std) — TROPIC01 via official libtropic-rs (tropic01)
  src/main.rs         HAL init, SPI0, USB-CDC; T1–T6 ladder; the SecureCore seam; USB serve loop
  memory.x            RP2350 memory layout + bootrom blocks
  .cargo/config.toml  target + linker (build from INSIDE firmware/ so this is read)
proto/dsm_anchor.proto  the on-wire appliance protocol (TransitionPackage / RootAdvanceCertificate /
                        CounterEvidence / OfflineRelease / Op / ApplianceRequest / ApplianceResponse)
tools/anchor_host_test.py  dependency-free host driver: drives one full root advance over USB-CDC
```

## Protocol surface (anchor-core)

The core is a deterministic, allocation-light reference for both the appliance
(producer) and the verifier (receiver). Every object has **one canonical
encoder** used by both sides, so the receiver recomputes — never trusts — carried
values.

- **Produce** (`appliance::Appliance`): `prepare → commit → emit → finalize`.
  `prepare` makes the single MAC-And-Destroy witness call, builds the
  certificate material, and stores a durable Prepared record — no counter move,
  no export. `commit` signs `M`, persists the committed candidate, moves the
  counter (`H ← H − 1`), and erases `sk_hw` (the three durable phases of §11.2).
  `emit` exports the release **only after** the counter commit. `finalize`
  advances the active root to `hᵢ₊₁` (guarded by `Active.u = H₀ − H`).
- **Verify** (`accept::accept_offline`): the Def. 22 17-check predicate. The
  cryptographic recomputations (transition digest `D`, witness input `X`, `P_hw`,
  cert message `M`, WOTS verify) and the counter arithmetic are done in-crate;
  the two checks needing receiver context — the DSM SMT proof (`DsmVerifier`) and
  the authenticity of the chip counter read (`CounterVerifier`, which returns the
  transcript-attested value, never the host claim) — are receiver-supplied traits.
- **Recover** (`Appliance::recover`): at boot, re-emits a durable committed
  release and finalizes the **same** successor (never signs a new one); completes
  an interrupted counter commit only if the parent still matches; downgrades to
  online recovery on a stale/ahead/diverged state.

### Encoding & invariants

- **BLAKE3** for all hashing, domain-separated (`H("DSM/.../v1" ‖ …)`); keyed
  BLAKE3 for the KDF. No raw hashing.
- The counter **counts down**: `u = H₀ − H`, computed with checked subtraction
  (`H > H₀` is impossible and rejected). It is **not** wall-clock time.
- **protobuf** on the wire; no JSON. Base32 Crockford for text; no hex.
- Variable-length fields are length-prefixed with a **u32** prefix
  (`util::push_var`) so deep SMT proofs can't alias field boundaries.
- The witness key signs exactly one digest, so a **one-time** signature
  (WOTS-over-BLAKE3) is the right, MCU-practical, post-quantum choice.

## Build & test

Host core — the full produce→verify round trip, the 17-check predicate (valid +
each check tampered), recovery, and wire round-trips:

```sh
cargo test -p dsm-anchor-core      # 33 tests (4 unit + 29 integration)
cargo clippy -p dsm-anchor-core --all-targets
```

The core is `no_std` and also builds for the RP2350 secure partition:

```sh
cargo build -p dsm-anchor-core --target thumbv8m.main-none-eabihf
```

### Firmware

The firmware drives TROPIC01 through the official **[libtropic-rs]** (`tropic01`)
embedded-hal driver — pure Rust, no C toolchain / pico-sdk. It expects
`libtropic-rs` checked out as a sibling of this repo (the path dependency in
`firmware/Cargo.toml` is `../../libtropic-rs/tropic01`):

```
workspace/
  dsm-unplugged/      ← this repo
  libtropic-rs/       ← https://github.com/tropicsquare/libtropic-rs
```

The RP2350 has dual Cortex-M33 (ARM) **and** dual Hazard3 (RISC-V); ARM is the
default. **Build from inside `firmware/`** so its `.cargo/config.toml` (linker
script, `cortex-m33`) is read — Cargo takes config from the CWD and its
ancestors, not from a workspace member passed with `-p`. Use the rustup toolchain
(Homebrew's `rust` has no cross std):

```sh
export PATH="$HOME/.rustup/toolchains/stable-<host>/bin:$PATH"
cd firmware
cargo build                                          # ARM thumbv8m.main-none-eabihf
# RISC-V: cargo build --target riscv32imac-unknown-none-elf
```

Flash via **picotool** (writes the correct RP2350 family id; `elf2uf2-rs` writes
the RP2040 id and is rejected). Hold BOOTSEL + replug, then:

```sh
picotool load -v -x -t elf ../target/thumbv8m.main-none-eabihf/debug/dsm-anchor-firmware
```

Read the USB-CDC log from `/dev/cu.usbmodem*`, then drive a full root advance
over USB:

```sh
python3 tools/anchor_host_test.py     # STATUS → PREPARE → COMMIT → EMIT → FINALIZE → STATUS
```

> **Firmware gotcha:** libtropic-rs's L1 layer issues an `Operation::DelayNs`
> between read retries. Build the SPI device with
> `ExclusiveDevice::new(bus, cs, timer)` (a real `DelayNs`) — `new_no_delay`
> *panics* on that delay, which looks exactly like a chip/wiring hang.

## Wiring (SPI0)

| Signal | TROPIC01 / Click | Pico 2 W |
|---|---|---|
| SCK | SCK | GP18 (pin 24) |
| MOSI (SDI) | SDI | GP19 (pin 25) |
| MISO (SDO) | SDO | GP16 (pin 21) |
| CS (manual) | CS | GP17 (pin 22) |
| Power | 3V3 | 3V3 (pin 36) |
| Ground | GND | GND (pin 23 / 38) |

The #1 bring-up fault is swapped SDO/SDI; the #2 is a missing common ground or
5 V instead of 3V3. A raw-SPI probe (clock out `0xAA`, print MISO) isolates the
link before the L2 driver: all `FF` = MISO not driven, all `00` = shorted, varied
= alive.

## Hardware validation (real silicon)

Validated on a live Pico 2 W + Secure Tropic Click + TROPIC01 (production-
provisioned: pairing slot 0 holds `SH0_PROD0`):

| Rung | Proves |
|---|---|
| **T1** | SPI link + L2 `GET_INFO` chip-id — genuine TROPIC01 |
| **T2** | X25519 handshake → encrypted L3 channel (PROD0 key) |
| **T3** | monotonic down-counter `init/get/update` — `u = H₀ − H` |
| **T3b** | MAC-And-Destroy `W = MACANDD(q, X)` — reproducible per arm, self-destroying without re-arm |
| **T4** | the Root Advance witness flow on-chip (prepare→commit→emit→finalize) |
| **T5** | the full appliance protocol over the protobuf wire through the `SecureCore::handle` seam, release verified under Def. 22 |
| **T6** | USB-CDC transport: an external host drives a full root advance |

## Status

- [x] **anchor-core complete** — root-advance objects, the 3-state appliance,
      §15 recovery, the Def. 22 receiver predicate, WOTS-over-BLAKE3 witness, the
      protobuf wire protocol. 33 tests green, clippy-clean, `no_std` for
      `thumbv8m`. Hardened by multi-agent adversarial review (recovery re-emit,
      two-phase commit, the counter trust seam, the counter-down arithmetic).
- [x] **Firmware on the Root Advance protocol** — bridges the `Tropic` /
      `WitnessSig` traits to libtropic-rs, runs prepare→commit→emit→finalize on
      the chip, verifies the release under Def. 22, serves it over USB-CDC, and
      calls `recover()` at boot.
- [ ] **Durable recovery** — persist `Active` to TROPIC01 R-memory
      (`r_mem_data_write`/`read`) so an interrupted transfer completes across a
      power loss; the boot `recover()` is wired but RAM-only in this build.
- [ ] **Enrollment / provisioning ceremony** — fix `H₀`, the MACANDD slot, the
      R-memory map, the verifier pairing slot, and firmware-boundary policy into
      the DSM authority state.
- [ ] **TrustZone-M** hardware enforcement of the secure-core seam (today the
      boundary is enforced by ownership).
- [ ] **DSM app integration** — wire the receiver `DsmVerifier` to the DSM SMT
      and the `CounterVerifier` to a real verifier-pairing-slot session.

## License

Dual-licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.

[libtropic-rs]: https://github.com/tropicsquare/libtropic-rs
