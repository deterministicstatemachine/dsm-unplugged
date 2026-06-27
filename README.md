# dsm-anchor-pico

A **DSM offline-bearer anchor** built from a **Raspberry Pi Pico 2 W** (RP2350)
driving a **TROPIC01** secure element (MIKROE *Secure Tropic Click*, MIKROE-6559)
over SPI at 3.3 V.

This implements the **Precommit-Bound MACANDD Authority** design (see the design
note *DSM Offline Anchor — Precommit-Bound MACANDD*). The secure element is **not**
the transaction authorizer. Authority is split into four jobs:

| Job | Mechanism | Role |
|---|---|---|
| Exact transfer binding | counterparty **co-signed precommit** `C_pre` | the actual authorizer |
| No appliance equivocation | **one live offered/pending precommit** per spendable frontier | liveness / anti-double-offer |
| Original-hardware presence | TROPIC01 **MAC-And-Destroy** witness `W` | unclonable hardware *witness* |
| Local non-rewind index | TROPIC01 **monotonic down-counter** `u = H₀ − H` | stale-state detection |
| Fork exclusion | DSM **Tripwire** (per-device sparse Merkle tree) | cross-relationship, in DSM core |

The key point: **`W` is never accepted by itself.** The MAC-And-Destroy output is
folded into a precommit-scoped witness *key*, whose public-key *hash* is committed
inside the counterparty co-signed precommit:

```
W ──► K = HKDF(W, …) ──► (sk_hw, pk_hw) = StepKeyGen(K) ──► P_hw = H(pk_hw) ──► C_pre
```

A release later reveals `pk_hw` and a signature `StepSign(sk_hw, H(Q))`; the
verifier checks `H(pk_hw)` opens the committed `P_hw` and that the signature
verifies — needing no secret of its own. Reproducing the same witness for the
same precommit is *idempotent* (it repeats the same release); it cannot authorize
a different recipient, amount, parent, entropy, policy, index, or successor.

## DSM authorship root

DSM keeps a software secret root for authorship and recovery, independent of the
hardware-presence layer:

```
s0  ←$ {0,1}^λ                                   (device secret, at provisioning)
S_master = HKDF(secret = s0, "DSM/Smaster/v1" ‖ G ‖ DevID ‖ policy)
```

`S_master` drives ordinary DSM authorship, recovery, and non-bearer functions.
Offline-bearer authority adds the precommit-scoped hardware-witness signature on
top — it does not replace `S_master`.

## Layout

```
anchor-core/     hardware-free protocol core + host verifier (no_std + alloc, host-testable)
  src/domain.rs      canonical "DSM/.../v1" domain-separation tags
  src/hash.rs        H = BLAKE3-256, keyed-BLAKE3 KDF, hash_bytes (d = H(Q))
  src/util.rs        ct_eq, LE int encoders, push_var (u32-length-prefixed fields)
  src/precommit.rs   Core (Def.22), X (Def.14), K/P_hw (Def.15), C_pre (Def.23),
                     PendingKey (Def.27), U_next (§15.3)
  src/tropic.rs      `Tropic` trait (mac_and_destroy / counter) + `WitnessSig`
                     trait (StepKeyGen / StepSign / StepVerify) — firmware-pluggable
  src/witness.rs     generate_offered_witness: the single MACANDD call + re-arm (§15.2–15.3)
  src/skeleton.rs    successor skeleton B, release hash R, successor frontier h_{i+1} (Def.32/33)
  src/release.rs     release preimage Q (§16.3), ReleasePackage, build_release_package
  src/verify.rs      accept_offline: the Def.52 acceptance predicate (all 21 checks)
  src/lifecycle.rs   Appliance state machine: Offered→Pending→Armed→Released,
                     one-live-precommit (Def.28–30), sk_hw zeroization (Assumption 19)
  src/recovery.rs    power-loss recovery (§18–19): re-emit / commit-complete / downgrade
  tests/roundtrip.rs full produce→verify round trip + Theorem 56–60 negative properties
firmware/        RP2350 binary (no_std, no_main) — TROPIC01 via official libtropic-rs (tropic01)
  src/main.rs        HAL init, SPI0, USB-CDC, the validation-ladder bringup (T1…T3b)
  memory.x           RP2350 memory layout + bootrom blocks
  .cargo/config.toml target + linker (build from INSIDE firmware/ so this is read)
```

## Protocol surface (anchor-core)

The core is a deterministic, allocation-light reference for both the appliance
(producer) and any verifier (receiver). Every object has **one canonical encoder**
used by both sides, so a verifier recomputes — never trusts — carried values.

- **Produce** (`lifecycle::Appliance`): `offer → cosign → release → commit →
  publish → finalize`. `offer` runs the single MAC-And-Destroy witness call and
  re-arms the slot; it is refused while any live/armed/published release exists
  for the frontier (one-live-precommit). `release` *consumes* the pending record,
  signs `σ = StepSign(sk_hw, H(Q))`, and arms the release. `commit` advances the
  monotonic counter (`H ← H − 1`). `finalize` recomputes the successor frontier
  `h_{i+1} = H("DSM/successor/v1" ‖ B ‖ R)` and advances the active state.
- **Verify** (`verify::accept_offline`): the Def.52 21-check predicate. The
  recomputable checks (Core / X / P_hw / C_pre / skeleton / Q / R / frontier /
  witness-signature) are done in-crate; the checks needing the receiver's DSM
  context (co-signature validity, DSM proofs, action validity, relationship
  membership, nonce freshness, exposure cap, anchor-compromise status) are supplied
  as `VerifierPolicy` booleans and still gated. Returns the recomputed successor
  frontier to pin.
- **Recover** (`recovery::recover`): completes a one-step counter commit for a
  durable armed release whose predecessor still matches, re-emits the durable
  release for the current counter index, or downgrades to online-checked recovery.
  A restored stale active record (index below the live counter index) is detected
  as a rollback and downgraded (Theorem 60).

### Encoding & invariants

- **BLAKE3** for all hashing, domain-separated (`H("DSM/.../v1" ‖ …)`); keyed
  BLAKE3 for the KDF. No raw hashing.
- Variable-length fields (witness public key, signatures, co-signature) are
  length-prefixed with a **u32** prefix via `util::push_var` — `u16` would
  truncate post-quantum **SPHINCS+** co-signatures (tens of KiB) and alias field
  boundaries.  Fixed-width fields are concatenated raw.
- Witness signature scheme is the appliance profile's `WitnessSig`
  (post-quantum SPHINCS+ per DSM's signing stance; the trait is generic).
- No hex on protocol paths (Base32 Crockford), no JSON (protobuf on the wire),
  no wall-clock — the counter index `u = H₀ − H` is *not* time.

## Hardware validation (real silicon)

Validated on a live Pico 2 W + Secure Tropic Click + TROPIC01 (production-
provisioned: pairing slot 0 holds the production key `SH0_PROD0`):

| Rung | Proves | Result |
|---|---|---|
| **T1** | SPI link + L2 `GET_INFO` chip-id | genuine TROPIC01 (silicon-rev `ACAB`) |
| **T2** | X25519 handshake → encrypted L3 channel | `ping` echo + 16-byte chip TRNG, PROD0 key |
| **T3** | monotonic counter `init/get/update` | non-rewind index `u = H₀ − H` |
| **T3b** | MAC-And-Destroy witness `W = MACANDD(q, X)` | reproducible per arm **and** self-destroying (no preview) |
| **T4** | **full witness flow on-chip** (offer→release→commit→finalize→verify) | counter 1000→999, WOTS `pk_hw` 32 B / `σ` 2144 B, Def-52 **accepted**, frontier matches |
| **T5** | **full appliance protocol over the wire** (protobuf, secure-core seam) | all 7 ops via `handle()`, release carried (exported only post-commit) + Def-52 **accepted**, counter 1000→999 |
| **T6** | **USB transport, external host** (framed protobuf over USB-CDC) | a separate host driver drove `STATUS→OFFER→STATUS`; `OFFER` ran a real on-chip M&D; state mutated over the wire (`has_live` 0→1) |

T3b confirms the core anti-clone property on hardware: with the slot armed by
`u`, a witness for input `v` is reproducible after re-arming (`Wa == Wb`), but
querying `v` again **without** re-arming yields a different output (`Wc ≠ Wa`) —
the slot evolves on every call, so the witness cannot be previewed or recomputed
without consuming a fresh arm.

> **Firmware gotcha:** the libtropic-rs L1 layer issues an `Operation::DelayNs`
> between read retries. Build the `embedded-hal-bus` SPI device with
> `ExclusiveDevice::new(bus, cs, timer)` (a real `DelayNs`) — `new_no_delay`
> *panics* on that delay, which looks exactly like a chip/wiring hang.

## Build & test

Host core (runs the produce→verify round trip and the Theorem 56–60 properties):

```sh
cargo test -p dsm-anchor-core      # 12 tests (8 unit + 4 integration)
```

The core is `no_std` and also builds for the RP2350 secure partition:

```sh
cargo build -p dsm-anchor-core --target thumbv8m.main-none-eabihf
```

Firmware (the RP2350 has dual Cortex-M33 **and** dual Hazard3 RISC-V; ARM is the
default). **Build from inside `firmware/`** so its `.cargo/config.toml` (linker
script, `cortex-m33`) is picked up — Cargo reads config from the CWD and its
ancestors, not from a workspace member passed with `-p`:

```sh
export PATH="$HOME/.rustup/toolchains/stable-<host>/bin:$PATH"   # rustup rust, not Homebrew
cd firmware
cargo build                                                      # ARM thumbv8m.main-none-eabihf
# RISC-V: cargo build --target riscv32imac-unknown-none-elf
```

Flash via **picotool** (writes the correct RP2350 family id; `elf2uf2-rs` writes
the wrong RP2040 id and is rejected). Hold BOOTSEL + replug to enter the
bootloader, then:

```sh
picotool load -v -x -t elf ../target/thumbv8m.main-none-eabihf/debug/dsm-anchor-firmware
```

Read the USB-CDC bringup log from `/dev/cu.usbmodem*` (the device enumerates only
because the USB device sets `.max_packet_size_0(64)`; the rp235x USB driver will
not enumerate with the default EP0 size of 8).

## Wiring (SPI0)

| Signal | TROPIC01 / Click | Pico 2 W |
|---|---|---|
| SCK | SCK | GP18 (pin 24) |
| MOSI (SDI) | SDI | GP19 (pin 25) |
| MISO (SDO) | SDO | GP16 (pin 21) |
| CS (manual) | CS | GP17 (pin 22) |
| Power | 3V3 | 3V3 (pin 36) |
| Ground | GND | GND (pin 23 / 38) |

The #1 bring-up fault is swapped SDO/SDI (MISO/MOSI); the #2 is a missing common
ground or 5 V instead of 3V3. A raw-SPI probe firmware (clock out `0xAA`, print
the MISO bytes) isolates the physical link before reaching for the L2 driver: all
`FF` = MISO not driven, all `00` = shorted/held low, varied = link alive.

## Status

- [x] **anchor-core complete** — precommit, witness flow, skeleton/release,
      Def.52 verifier, one-live-precommit lifecycle, §19 recovery. 12 tests green,
      clippy-clean, builds `no_std` for `thumbv8m`. Two rounds of multi-agent
      adversarial review against the spec (a critical equivocation, a key-leak, and
      encoding/lifecycle defects found and fixed; the global invariant
      `armed ⇒ no-live` re-verified).
- [x] **Hardware ladder T1–T3b** validated on real silicon (chip-id, encrypted
      L3 session, monotonic counter, MAC-And-Destroy witness).
- [x] **On-device witness flow (T4)** — the firmware bridges anchor-core's
      `Tropic` / `WitnessSig` traits to libtropic-rs (real `mac_and_destroy` /
      `mcounter`) with the **WOTS-over-BLAKE3** one-time witness signature
      (`anchor_core::sig::WotsBlake3`, host-tested), and runs the full
      offer→cosign→release→commit→publish→finalize on the chip; `accept_offline`
      (Def.52) accepts and recomputes the matching successor frontier. The
      witness key is one-time-per-precommit, so a one-time signature — not a
      many-time SPHINCS+ — is the right, MCU-practical, PQ-consistent choice.
- [x] **On-device appliance protocol (T5)** — prost wire format from the shared
      [`proto/dsm_anchor.proto`](proto/dsm_anchor.proto) (same tooling as the DSM
      repo's `proto/dsm_app.proto`); every op driven through the `SecureCore::handle`
      seam on the chip, with `mac_and_destroy`/`mcounter` reachable only through it;
      the release package is exported only after the counter commit (§16.4) and
      verifies under Def-52 over the wire.
- [x] **USB transport (T6)** — the non-secure serve loop frames LE32-length-prefixed
      protobuf over USB-CDC into `SecureCore::handle` (receive-edge cap). An external
      host driver ([`tools/anchor_host_test.py`](tools/anchor_host_test.py), hand-encoded
      protobuf, no deps) drives the appliance over USB end to end. Remaining: TrustZone-M
      *hardware* enforcement of the seam.
- [ ] **Enrollment / provisioning ceremony** — initialize `H₀`, fix the MACANDD
      slot assignment, R-memory map, pairing-slot policy, and firmware-boundary
      policy into the DSM authority state (§14).

> This is a separate embedded target from the main DSM repo (not a git repo of its
> own); nothing here pushes to any remote.
