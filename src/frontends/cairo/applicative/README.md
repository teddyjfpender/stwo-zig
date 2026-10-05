# Circuit-applicative Cairo program

This Cairo 0 program proves the final relationship in the Starknet PIE tree. It
runs the Starknet aggregator task and the pinned Cairo 1 circuit-verifier task,
reconstructs the ordered circuit tree from its public leaf preimages, and
requires the reconstructed root to equal the verifier's output. It also copies
the reconstructed task outputs onto the aggregator's input memory. Cairo memory
is write-once, so every cell must equal what the aggregator consumed. The final
output publishes the modified aggregator program hash, the production circuit
registry commitment, and the aggregator's result.

Apollo's transaction-proof verification PRs cover a different, one-transaction
proof-facts feature. This program handles a root over multiple OS PIEs.

The program uses the `CircuitApplicativeBootloaderInput` and hint names in
`starkware-libs/proving` commit `5a7c5ed`. The upstream checkout contains
those hints but no compiled circuit-applicative program, so this source is our
auditable implementation of that interface. It pins all six production
circuit hashes, the aggregator program hash, the Cairo 1 verifier program hash,
and the production registry commitment. A registry, verifier, or aggregator
upgrade requires a new compiled program and qualification.

Build with `cairo-lang==0.14.3a3` and the source tree of that exact release:

```sh
cairo-compile src/frontends/cairo/applicative/main.cairo \
  --proof_mode \
  --cairo_path src/frontends/cairo/applicative:/path/to/cairo-lang-0.14.3a3/src \
  --output /tmp/circuit_applicative_compiled.json
shasum -a 256 /tmp/circuit_applicative_compiled.json
```

The expected compiled SHA-256 is
`7abe1d0f6ac73996d29ae07fc4f4938b1d43e6f028f10c6ae73f842cbf44fca6`.
The compiled program and a two-leaf proof are in
[`vectors/starknet/mainnet/pipeline/15627902-15627907_x2`](../../../../vectors/starknet/mainnet/pipeline/15627902-15627907_x2).
The two leaves are contiguous PIEs `15627902-15627904` and
`15627905-15627907`. The adapted applicative execution used 5,877,151 Cairo
steps. The Zig CPU proof uses 70 FRI queries and 26 PoW bits; it passed Zig's
verification and the independent pinned Rust `verify_cairo` implementation.
On the measured local machine the CPU proof phase took 6.43 seconds, the
complete adapted-input-to-proof command took 7.54 seconds, and peak physical
memory was 16.9 GB. Metal produced the **same proof bytes**; its proof phase
took 4.51 seconds and its command took 5.63 seconds with a 13.0 GB process
peak. Metal logged two composition host admissions for missing evaluation
functions, so this is backend parity rather than a claim that every composition
operation executed on the GPU.

The saved 128-PIE root has also reached a matching, independently verified
final applicative proof. The packed tree supplied the aggregator input without
re-reading 128 PIE ZIPs. The CPU and Metal proof bytes were identical at
SHA-256 `458c71504db6b10f342d5725bd5c83551bc66fca7202d395e15ca953b3193c74`.
The local staged-input-to-verified-publication command took 18.624 seconds on
CPU and 16.605 seconds on Metal; proof phases were 10.298 and 7.343 seconds,
respectively. Process peaks were 31.188 and 24.623 GB. The proof and receipts
are in the `proving-service` repository's
`data/h200-api-128-512/h200-api-128-001/applicative-final` directory.

The 512-PIE packed aggregator and final Cairo execution succeeded. Metal
could not prove the 44,250,309-step execution on the local 64 GB M5: resident
barycentric evaluation exhausted GPU memory. A saved PR #17 CUDA runtime then
proved the same adapted input on one H200. Its 2.29 GB JSON transport took
24.605 seconds from CPI to proof JSON; re-encoding the same execution as a
909 MB canonical compact input reduced that to **8.059 seconds** cold, with
byte-identical proof output. Compact source preparation fell to 2.785 seconds
from 20.570 seconds with JSON. A same-input warm repeat took 4.746 seconds.
Direct `adapt-program --input-format compact` reproduced the converted input
byte for byte and the same public output; local Cairo execution/adaptation
took 9.22 seconds on the M5.
The final proof SHA-256 is
`c49a6fe9da397a1a545deae90ef3294ba111fb6e9a079112b9dcc7027bafde43`;
the independent Rust verifier accepted it and all 58,548 public output cells
match the Cairo execution. The proof, qualification and capacity evidence are
committed under the proving-service 512-PIE trial dataset.

## Pinned Rust prover comparison

The two-leaf adapted input (SHA-256
`8a2591ab7abb007ec55a791b31920fee16871c8f4dbfd4db8cb38b514eda8b50`)
was also proved twice with the pinned Rust `stwo-circuit-oracle prove-cairo`
using `production.json`'s 70-query/26-PoW `cairo_prover_params`. Rust's own
verifier accepted both runs; the canonical extended proof SHA-256 was
`dab9ac2539b80501bc32d55cfd33f35e592195c01cf61a6c067adc0ce3f085ad`
in each run. Rust and Zig had the **same first trace commitment**,
`a98e22423bf5d235981f0b36d939ae56ef3be2751c58b032b2831e6e24ba0364`,
but their subsequent proof bytes differed. Rust's interaction PoW nonce was
`55834600113`; Zig's was `8590366531`. Replacing Zig's nonce with Rust's in
the Zig proof failed the pinned Rust verifier's PoW check, confirming that the
pre-interaction transcripts differ, rather than merely the nonce search order.

The claims explain the difference. The pinned Rust leaf lane uses the
`Blake2sM31MerkleChannel` and its registry parameters, including 16
`memory_id_to_big` slots and disabled fixed-range/bitwise component claims.
The standalone Zig CPU/Metal Cairo product uses its official plain-Blake2s
profile and natural memory component count; on this fixture it has one
`memory_id_to_big` slot and enables those fixed components. These are
different valid proving profiles over the same Cairo execution. The final
proofs must match the Cairo public output and pass independent verification;
proof-byte equality with Rust requires explicitly selecting the pinned Rust
leaf lane on every backend. The CUDA product supports that lane with
`--circuit-registry`, while the standalone CPU/Metal product commands used
here do not expose it. No Rust proof-byte equality is claimed for the saved
applicative final proofs.

Changing a leaf output or reversing the two leaves causes the Cairo execution
to fail at the verifier-output equality assertion. The complete output segment
is public in the adapted input. The final proof does not shorten the underlying
leaf/fold tree: one-PIE leaves still require `N-1` pairwise folds.
