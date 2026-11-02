# Independent Rust OM31 numerical GKR oracle

The pinned Rust Stwo verifier algorithm now agrees with native Zig on three
small OM31 fixtures and the actual current Sail CPU child, under both control
and beta2 candidate contexts. This is a **partial numerical oracle**. It does
not authenticate the supplied starting channel, terminal bindings, PCS, AIR,
execution statement or whole-protocol security. It cannot accept execution.

## Reused primary authority

The existing `tools/stwo-interop-rs` crate remains pinned to Stwo
`a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`. Its upstream GKR, sumcheck and channel
APIs fix `SecureField` to QM31; this is not an upstream OM31 feature. The new bin
uses the independently pinned Rust M31/QM31 implementation and raw Blake2s
channel. An oracle-only OM type extends QM31 with `v²=u`, using schoolbook outer
multiplication and the quartic norm inverse. The numerical GKR verifier and
sumcheck equations come from a reproducible mechanical lift of the pinned Rust
source. No upstream checkout is modified and no new crate is introduced.

`regenerate_om_gkr_reference.py --check` validates the upstream revision and
source hashes, then reproduces the imported code. Changes are imports/type
aliases, exclusion of prover/test code, and exposing the polynomial coefficient
vector to the bounded decoder. Proof vectors are preserved **without** calling
upstream `UnivariatePoly::new`, which trims zeros and changes transcript bytes.
No GKR equation is rewritten from Zig. The provenance file records each input
and resulting source hash.

The pinned upstream toolchain is `nightly-2025-07-14`. A newer nightly rejected
the upstream `array_chunks` feature; that was resolved by selecting the pinned
toolchain, rather than patching upstream field/SIMD code. The existing Cargo
lock changes only to list the already locked `thiserror2.0.18` as a direct
dependency of this bin's package.

## Diagnostic boundary

Input is a bounded16MiB JSON sidecar: public initial Blake digest/draw counter,
gates, exact coefficient vectors, masks, outputs and expected native artifact
(point, terminal claims, variable counts and ending channel). The Rust decoder
checks canonical coordinates, instance/layer/round/mask shape and resource caps
before invoking the lifted verifier. Every LogUp root denominator must be
nonzero. Actual Sail children additionally require local rational closure.
The ordinary CPU/RAM/manifest/PCS proof remains native and outside Rust.

The raw-mod channel uses pinned Rust Blake draws and reduces all eight u32
words modulo M31. It compares every coordinate, ending digest and draw counter.
Inherited counters reset when the first claims are mixed; changing only that
inherited counter is intentionally an accepting equivalence control, not an
assertion of starting-state authentication.

The qualification-only native exporter provides tiny dense, all-zero and
constant fixtures, including independent public input arrays. Rust evaluates
their terminal MLEs separately. For the real Sail child, export first performs
full native acceptance from the independently expected image and freshly built
setup, then emits the public numerical fragment. Real production terminal
bindings are explicitly still pending in the Rust result, even for fixtures
whose public arrays were independently checked.

Every result reports `accepting_execution_receiver=false`,
`physical_pcs_verified=false`, `starting_channel_state_authenticated=false`,
`production_terminal_binding_pending=true` and `whole_protocol_128=false`.
Successful fragment arithmetic is never an execution acceptance bit.

## Evidence

- Three native fixtures: mixed GrandProduct/LogUp with8/4 rows and dense values
  in every coordinate; all-zero polynomials with empty coefficient vectors;
  constant polynomials with short vectors. All match Rust exactly.
- Forty-seven qualification cases: five honest/equivalence controls and42
  rejections. Mutations cover every coordinate of coefficients, masks,
  expected terminals and independent input arrays; channel digest/counter,
  malformed shapes, noncanonical words, root poles and polynomial vector
  lengths. Appending a zero coefficient changes only framing, and is rejected.
- Actual Sail control and candidate children:15 local instances,24 layers,
  exact OODS point/terminal claims/digest/counter agreement and local closure.
  The native complete workload has1,032,240 independently compared retirements
  and12,903 Sail cases; Rust does not reverify that execution or its PCS.
- Two Rust unit tests pass for dense tower inverses/high coordinates and the
  modulo boundaries `p−1,p,p+1,2p−1,2p,2p+1`.

These are correctness checks, not proving-speed or security estimates. The
existing five-instruction Rust ISA/PCS adapter remains separately scoped; this
oracle does not extend its ISA coverage or establish an OM PCS receiver.

## Reproduction

```sh
CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/rv64-om-rust-gkr-target \
  cargo +nightly-2025-07-14 build --offline --release \
  --manifest-path tools/stwo-interop-rs/Cargo.toml --bin rv64_om_gkr_oracle
zig build rv64-om-sail-qualification -Doptimize=ReleaseFast -j2
zig-out/bin/rv64-om-sail-qualification fixture NEW_FIXTURE_DIRECTORY
zig-out/bin/rv64-om-sail-qualification export-candidate SAIL_CONFIG SAIL_BUNDLE
python3 scripts/riscv64_om_rust_gkr_qualify.py \
  --oracle /tmp/rv64-om-rust-gkr-target/release/rv64_om_gkr_oracle \
  --fixtures NEW_FIXTURE_DIRECTORY \
  --sail SAIL_BUNDLE/rust-gkr-child.json --output REPORT.json
```

Use `export-control` for the control bundle. The sidecars are diagnostic public
inputs, not receiver-admitted keys or substitute proof files. A GPU kernel can
use these as independent arithmetic/transcript oracles; GPU execution remains
unqualified and was not performed here.
