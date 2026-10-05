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
On the measured local machine the CPU proof phase took 6.57 seconds, the
complete adapted-input-to-proof command took 7.61 seconds, and peak physical
memory was 16.9 GB. Metal produced the **same proof bytes**; its proof phase
took 4.49 seconds and its command took 5.57 seconds with a 13.0 GB process
peak. Metal logged two composition host admissions for missing evaluation
functions, so this is backend parity rather than a claim that every composition
operation executed on the GPU. These are two-leaf measurements, not a
128/512-leaf timing.

Changing a leaf output or reversing the two leaves causes the Cairo execution
to fail at the verifier-output equality assertion. The complete output segment
is public in the adapted input. The final proof does not shorten the underlying
leaf/fold tree: one-PIE leaves still require `N-1` pairwise folds.
