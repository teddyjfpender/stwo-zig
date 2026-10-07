# S31 circuit and chip relation compiler

S31 compiles a fixed-size relation into Stwo circuit AIR and, for a supported recurrence, a repeated-step AIR chip. Every `s31 build` package contains a prover, an independently runnable native STARK verifier, a pinned verification key, the typed public ABI, and a cost report. The verifier checks all proof components through `core.verifier`; it does not execute the recursive verifier circuit on the host.

## Source layout

The root contains the package build files and [`mod.zig`](mod.zig), the Zig module interface. Source files are grouped by responsibility:

| Directory | Contents |
| --- | --- |
| [`language/`](language/) | Canonical program model, relation parser, and circuit compiler. |
| [`library/`](library/) | Built-in hash implementations used by the language and circuits. |
| [`sha/`](sha/) | SHA AIRs, proof profiles, provers, native verifiers, package transport, and focused tests. |
| [`bitcoin/`](bitcoin/) | Consensus arithmetic, recursive chain folds, CLI, verifiers, and tests. |
| [`recursion/`](recursion/) | Generic state-fold and recursive proof relations. |
| [`runtime/`](runtime/) | Package runtime, prover and verifier entry points. |
| [`python/`](python/) | Text frontend, oracle, and standard/math library implementation; invoke `python/s31.py`. |
| [`tests/`](tests/) | Acceptance, Python unit, and cross-component proof tests. |
| [`benchmarks/`](benchmarks/) | Repeatable comparison and measurement drivers. |
| [`tools/`](tools/) | Source generators, inspectors, and record utilities. |
| [`entry/`](entry/) | Small Zig build entry files; `build.zig` selects these while implementation stays in the domain folders. |
| [`examples/`](examples/README.md), [`docs/`](docs/) | Subject-grouped sample programs and reader-facing language documentation. |

The matching [design dossier](../../../design/s31/README.md) keeps proposals and measurements separate from maintained source. Historical measurements remain pinned records; moved records retain their original contents.

**Start with the [S31 documentation](docs/README.md).** It follows handwritten programs through typed source, normalized relations, circuit gates, AIR rows and polynomials, hashes, proof artifacts, and native verification. Its examples and local links are checked by `python3 src/frontends/s31/docs/check.py`.

For `.s31` editor support, see the [S31 TextMate grammar and neon theme](../../../editors/vscode-s31/README.md). GitHub currently highlights `.s31` files through a Cairo language override; a distinct S31 name and pink language color require upstream Linguist registration.

The earlier [source-to-AIR implementation guide](docs/reference/LANGUAGE_AND_AIR.md) remains available for backend detail.

The compiler accepts normalized JSON and a [limited typed `.s31` text language](docs/reference/TEXT_LANGUAGE.md) that lowers to the same relation. Inputs have `u16` or `m31` relation type, fixed length, and public or private visibility. The text language has nominal `Bytes32`, `UInt256`, and `BlockHash` values backed by sixteen `u16` limbs and `Bytes80` backed by forty. Nodes are topologically ordered. Supported normalized operations include arithmetic, constrained 256-bit addition/subtraction/comparison, static repeats, selection, BLAKE2s and Poseidon2 hashes, byte-exact Bitcoin header SHA256d, and mainnet compact-target decoding. BLAKE2s hash inputs are canonical M31 words encoded little endian as 32-bit words; its eight digest words are reduced modulo M31. Poseidon2 outputs eight canonical M31 state words directly. Assertions constrain equal arrays. Public inputs and outputs occupy at most eight direct words: `u32` in the original profile, canonical M31 in direct-v4. Witnesses cannot change graph shape.

To use the text frontend and inspect its exact lowering:

```sh
python3 src/frontends/s31/python/s31.py lower src/frontends/s31/examples/arithmetic/arith4_m31.s31
python3 src/frontends/s31/python/s31.py oracle src/frontends/s31/examples/arithmetic/lane_stats4.s31 src/frontends/s31/examples/arithmetic/lane_stats4.valid.json
python3 src/frontends/s31/python/s31.py build src/frontends/s31/examples/arithmetic/arith4_m31.s31 --lowering direct-chip --out zig-out/s31/text-arith4
python3 src/frontends/s31/python/s31.py explain zig-out/s31/text-arith4
python3 src/frontends/s31/python/s31.py equations zig-out/s31/text-arith4
```

For a single source-to-proof audit, `trial` builds or reuses a package, proves an
assignment, runs its native verifier, checks that a changed public word is
rejected, and writes a compact machine-readable report:

```sh
python3 src/frontends/s31/python/s31.py trial \
  src/frontends/s31/examples/arithmetic/lane_stats4.s31 \
  src/frontends/s31/examples/arithmetic/lane_stats4.valid.json \
  --lowering direct-gate --out zig-out/s31/lane-stats4-trial
```

The output contains `proof.bin`, public and changed statements,
`trial-report.json`, `explain.json`, and `equations.json`. The report records
canonical IR, raw and padded geometry, proof bytes, hashes, and local timings;
it does not copy the private assignment. It also runs an independent Python
value oracle before proving, checking arithmetic and current hash/Merkle
nodes against the relation and claimed output without using the Zig runtime.
`s31 oracle` runs that check without building a proof. It uses Python's
BLAKE2s and a separate Poseidon2 permutation implementation with the
repository's pinned constants. Unknown future nodes fail explicitly. The
oracle checks values, not circuit equivalence or proof soundness. `equations`
shows source-level field equations, not every term in the pinned circuit AIR.
Trial and tune reports record the oracle source and Poseidon2 constant hashes
used for those checks.
Timing is a single local observation, so use repeated measurements before
making a speed claim.

`s31 tune` compares explicit proof lowerings for **one source** against the
same assignment files. It builds each package, proves and verifies every
assignment, checks a changed public statement, and writes
`tune-report.json` with per-profile trace geometry, proof sizes, wall time,
prover-reported time excluding logged proof-of-work, and normalized visible
FRI settings. It flags whether the compared profiles use the same visible
FRI settings; matching values alone do not establish equal soundness across
different AIRs. Supply distinct
valid assignments for a useful timing sample; `--warmup ASSIGNMENT.json`
adds an unmeasured proof per profile. The command records observations and
does not choose a profile automatically:

```sh
python3 src/frontends/s31/python/s31.py tune \
  src/frontends/s31/examples/arithmetic/arith4_m31.s31 \
  src/frontends/s31/examples/arithmetic/arith4.valid.json \
  --lowering direct-gate --lowering direct-chip \
  --out zig-out/s31/arith4-tune
```

This one-assignment command exercises the workflow. Supply several distinct
valid assignments before interpreting timing medians.

The text package includes the original `.s31`, normalized JSON, typed
interface, and source map. Package inspection re-lowers the text and checks
that these files agree with the sealed relation; the manifest hashes package
artifacts and the native verifier binds its key. The native verifier also
recompiles its embedded source to check the key's fixed circuit commitment;
this closes a source/circuit key mismatch and adds verifier work on every
invocation. The manifest is unsigned, so verifier and key authenticity still
depend on a trusted distribution path.
`explain` joins source locations to the existing gate-row cost report. See
[the text language guide](docs/reference/TEXT_LANGUAGE.md) for implemented syntax, typed
library functions, constraints, examples, and limits. The [standard/math
library brief](../../../design/s31/language/STDLIB_MATHLIB.md) records qualified
library operations and the remaining work for a useful release.

The [standard/math library chapter](docs/library.md) covers `use std@1;`,
static `sum`/`dot`, Horner polynomial evaluation, hand calculations, and the
source-hashed library lock embedded in text packages. The complete
[`mathlib4.s31` example](examples/arithmetic/mathlib4.s31) builds under `direct-gate`
and produces a native verifier. [`lane_stats4.s31`](examples/arithmetic/lane_stats4.s31)
computes the sum and weighted dot product of private array lanes, returning
one public M31 word. Its `sum_lanes` operations use constrained packed-lane
projection; `dot_lanes` adds one pointwise multiplication.
[`field_div4.s31`](examples/arithmetic/field_div4.s31) adds checked field inversion and
division. `std::math::div` reuses the checked inverse and remains on the
`direct-gate` profile; a zero denominator is unsatisfiable. Run
`python3 src/frontends/s31/tests/acceptance/acceptance_field_div_v1.py` for the proof and
native-verifier adversarial checks. [`computed_choice.s31`](examples/control/computed_choice.s31)
uses a constrained `std::field::is_zero` bit to choose between two values;
`python3 src/frontends/s31/tests/acceptance/acceptance_computed_bit_v1.py` proves both branches.
`equations` exposes semantic field equations and source positions, with the
generic AIR's lookup and public-binding terms documented separately in
[the guide](docs/walkthrough.md).

The [`wide_order.s31` example](examples/wide/wide_order.s31) uses typed 32-byte
values, constrained 256-bit addition and comparison, and a Poseidon2 public
commitment. The [worked wide-value chapter](docs/wide-values.md) derives its
carry and borrow equations by hand. Use `--lowering sparse-wide-gate` for this
example. For an actual Bitcoin header proof, see
[`bitcoin_header_pow.s31`](examples/bitcoin/bitcoin_header_pow.s31) and its
[worked walkthrough](docs/bitcoin-sha256d.md): three constrained SHA-256
compression blocks, mainnet `nBits` decoding, and a hash ≤ target assertion.
[`bitcoin_header_pair_typed.s31`](examples/bitcoin/bitcoin_header_pair_typed.s31) extends this
to two real, linked headers with a mainnet genesis checkpoint, both PoW
checks, equal `nBits`, and the strict first-step median-time-past rule. It still uses the generic
SHA circuit. The [header-link leaf](examples/bitcoin/bitcoin_header_link.s31) proves
one fresh header's SHA256d, previous-hash link, and PoW against a claimed
`BlockHash`, then commits to the ordered old/new hashes. Its proof does not
authenticate the prior hash or enforce full chain policy; that linkage belongs
inside a changing-header fold. The
[`sha_chip_plan.zig` boundary](sha/config/sha_chip_plan.zig) prepares three SHA AIR calls
per header and tests their byte-level linkage. Its 96-word private caller
tape closes the SHA graph's lookups for one or two headers, and the
[SHA chip profile](sha/config/sha_chip_profile.zig) pins the corresponding AIR identities
and row geometry. A focused [joint proof test](sha/tests/sha_joint_prover_test.zig) now
connects one private header and digest through a caller AIR, two lookup buses,
and one native STARK verifier. `s31 build examples/bitcoin/bitcoin_header_pow.s31
--lowering sha-joint --out zig-out/s31/bitcoin-sha-joint` packages this sealed
one-header profile with a source and topology derived key, the eight-word
public root ABI, a cost report, and an independently runnable native verifier.
The verifier rebuilds the value-free circuit, including all 56 private SHA
boundary addresses, before admitting a proof. The default lowering remains
`gate`; the [matched measurement](../../../design/s31/measurements/sha/bitcoin-sha-joint-v1-2026-10-07.json)
shows a 721,880-byte joint proof versus 338,282 bytes for generic sparse-wide
and a larger prover cost for one header. Run
`python3 acceptance_sha_joint_package.py` to build both packages from the same
normalized fixture, prove the same assignment, and test changed root, key,
boundary, generic-proof replay, and proof corruption rejection. The
`sha-shift` lowering packages the newer shift-register SHA AIR in the same
source-bound format:

```sh
python3 src/frontends/s31/python/s31.py build src/frontends/s31/examples/bitcoin/bitcoin_header_pow.s31.json --lowering sha-shift --out zig-out/s31/bitcoin-sha-shift
python3 src/frontends/s31/tests/acceptance/acceptance_sha_shift_package.py
```

Its generated verifier recompiles the embedded source without witness values,
derives the private-digest SHA boundary and fixed-column root, checks the
embedded sealed key, then verifies the one-STARK circuit and SHA proof. The
public statement contains only the eight-word Poseidon root. The package pins
FRI to 26 proof-of-work bits, 70 queries, blowup 2, last-layer log-degree
bound 0, and fold step 1. A local production-profile acceptance generated a 502,783-byte
proof and rejected changed public roots, damaged proofs, altered keys, and
proof replay under the same relation with different source bytes. Trust in the
program identity requires a trusted verifier binary or independently
authenticated package hash; an arbitrary package supplied by the prover does
not establish which source the verifier intended to check. Private statement
values are not guaranteed confidential by this unmasked proof.

The `sha-fused` lowering packages the three-call fused schedule and round AIR
with the same sealed source and value-free topology checks:

```sh
python3 src/frontends/s31/python/s31.py build src/frontends/s31/examples/bitcoin/bitcoin_header_pow.s31.json --lowering sha-fused --out zig-out/s31/bitcoin-sha-fused
python3 src/frontends/s31/tests/acceptance/acceptance_sha_fused_package.py
```

It uses a distinct `sha-fused-v4` key and `S31FCJ04` proof envelope. The native
verifier rebuilds all fixed columns, derives the key from embedded source,
requires FRI 26/70 with fold step 1, and accepts only eight canonical public
Poseidon root words. SHA digest bytes stay in committed witness columns and
are connected to the circuit by the closed Gate lookup. This proof is not
zero knowledge for the header.

The [sparse-wide recursive verifier](docs/recursion-sparse-wide.md)
wraps the generic Bitcoin circuit profile through two depth-specific gate proofs. The
[header-link acceptance gate](tests/acceptance/acceptance_header_link.py) also wraps one fresh
header-link proof and checks its authenticated child statement. A direct
[header-step circuit kernel](bitcoin/fold/bitcoin_fold_step.zig) constrains a new header
inside the Bitcoin chain fold; its [worked chapter](docs/bitcoin-sha256d.md) gives the
gate-inspection command and cost. The [candidate chain-fold circuit](bitcoin/fold/bitcoin_chain_fold.zig)
combines one verified prior proof with that header step. Its
[inspector](tools/inspect/inspect_bitcoin_chain_fold.zig) checks same-key AIR geometry and
checkpoint binding against a [checkpoint anchor circuit](bitcoin/fold/bitcoin_chain_anchor.zig);
the [opt-in proof test](bitcoin/tests/bitcoin_chain_anchor_proof_test.zig) now proves and
natively verifies two changing-header steps under that one AIR root. A
[standalone CLI](bitcoin/cli/bitcoin_chain_cli.zig) verifies saved proofs against a
SHA-256-pinned Bitcoin fold key and a step-specific statement; its
[acceptance script](tests/acceptance/acceptance_bitcoin_chain_cli.py) checks replay and changed
claims. The [proof chapter](docs/bitcoin-sha256d.md) gives the commands,
trust boundary, and measured cost.
The distinct [first-retarget v4 fold](../../../design/s31/bitcoin/BITCOIN_FIRST_RETARGET_FOLD.md)
constrains height-2016 nBits from the verified child timestamp and has a
sealed key capped at step 2015. Its opt-in test proves the first two real
headers recursively; a height-2016 chain proof has not yet been generated.
The [`verify-retarget` CLI](bitcoin/cli/bitcoin_chain_cli.zig) and
[acceptance script](tests/acceptance/acceptance_bitcoin_retarget_chain_cli.py) check this
profile separately from the earlier first-epoch key.

The packed SHA AIR has a focused six-call proof test for two SHA256d headers:

```sh
zig build --build-file src/frontends/s31/build.zig test-sha-batch -Doptimize=ReleaseSafe -j2
```

It proves one STARK against trusted public compression boundaries and rejects
a substituted digest boundary. The separate private-header joint proof can be
exercised with:

```sh
zig build --build-file src/frontends/s31/build.zig test-sha-joint -Doptimize=ReleaseSafe -j2
```

That test derives the verifier key from value-free circuit topology, proves
one genesis-header PoW statement with the circuit and SHA AIR in one proof,
and checks native verification and adversarial changes. The
[integration contract](../../../design/s31/sha/SHA_CHIP_INTEGRATION.md) explains the
56-wire boundary, lookup signs, soundness assumptions, and measured cost.
For one header, the current chip is slower and produces a larger proof than
the existing generic circuit; chip lowering is not selected automatically.

The [recursion chapter](docs/recursion.md) demonstrates a `gate`-profile
wrapper: a saved S31 proof is natively authenticated, verified inside a
circuit, and wrapped in an outer proof checked by a generated native verifier.
The [two-level chapter](docs/recursion-chain.md) wraps that first outer proof
again. Gate packages seal both recursive verification keys at build time, so
routine outer verification does not rebuild the large verifier topology.
Sparse-wide packages also seal two wrapper keys, and the
[sparse-wide chapter](docs/recursion-sparse-wide.md) shows this path with a
256-bit arithmetic source, ten direct verifier mutations, and measured costs.
The sparse-wide child defaults to FRI fold step 1 and also supports
`--fri-fold-step 4`; its two gate wrappers use step 4. The leaf key and v3
recursive keys bind their schedules. In the local two-header Bitcoin fixture,
fourfold child FRI halved the first verifier circuit's raw variables and cut
first-wrap wall time by about 40% relative to a onefold child in local runs. A separate
concrete-security analysis is still needed for each schedule.
The [fixed-key fold chapter](docs/recursion-fold.md) shows repeatable proof
verification under one sealed key and a constrained `u32` step counter.
The [sparse-wide fixed-key fold](docs/recursion-wide-fold.md) extends this
to wide-integer and two-header Bitcoin leaf proofs by using the second
wrapper as its base; repeated fold proofs use the same sealed key.
`fold-advance` runs several steps in one process, reusing the sealed
preprocessed circuit and commitment while checking each child proof and
each value-bearing gate topology. Checkpoints support resume.
`audit-fold-chain` natively verifies a saved checkpoint sequence from step
zero and checks its public claim continuity. `audit-state-fold-chain` also
replays each sealed four-lane M31 transition. Both accept `--max-step`.
`inspect_recursive_claim.py PACKAGE TOP-PROOF` verifies the top proof and
prints its complete public digest/key chain as JSON for review.
The [state-fold chapter](docs/state-fold.md) extracts a typed four-lane
recurrence with square, addition and multiplication by constants from source
and proves one more computation step in each fold. Its `u32` step counter
supports up to 2³²−1 added steps. `state-fold-advance` runs
multiple steps with optional checkpoints for resume.
The [coupled `mix4` example](examples/arithmetic/mix4_square4.s31) adds a four-lane
linear diffusion step to that source-derived recurrence while keeping the
same padded verifier AIR size.
`inspect_state_fold_claim.py PACKAGE TOP-PROOF` verifies an isolated top
proof and independently replays its public recurrence, subject to a bounded
local step limit.
For recursive packages, `s31 build SOURCE --out PACKAGE --fri-fold-step 4`
uses four FRI folds per commitment with the same 26 PoW bits, blowup factor 2,
and 70 queries. For `gate` packages it selects leaf, wrapper, and fold FRI;
for `sparse-wide-gate` it selects the leaf while wrappers already use step 4.
It is a distinct, key-bound proof schedule: the affine-square
state-fold circuit has 5.59 million raw variables versus 11.82 million at the
default fold step 1. The [state-fold chapter](docs/state-fold.md#choose-the-fri-schedule)
explains the proof and verifier boundary.
The [recursive cost map](../../../design/s31/recursion/RECURSION_PERFORMANCE.md) breaks
the verifier circuit down by stage and records the current proving bottleneck.
The v2 wrapper fixes the child AIR root with equality gates and embeds the
SHA-256 digest of the exact child key as constants in its personalized
one-block BLAKE2s public claim. A same-AIR, different-key replay fixture
checks that this changes the outer AIR and rejects the old outer proof.
`wrap --low-memory` trades some proving time for lower peak RAM while
producing the same proof bytes.
The claim-only fold repeats one leaf claim, including a sparse-wide Bitcoin
pair when selected; the state fold adds a constrained four-lane M31
transition. A Bitcoin header-chain state transition remains to be built.

From the repository root:

```sh
zig build --build-file src/frontends/s31/build.zig test -Doptimize=ReleaseSafe
python3 src/frontends/s31/python/s31.py check src/frontends/s31/examples/hashes/preimage4.s31.json
python3 src/frontends/s31/python/s31.py build src/frontends/s31/examples/hashes/preimage4.s31.json --out zig-out/s31/preimage4
python3 src/frontends/s31/python/s31.py inspect zig-out/s31/preimage4
python3 src/frontends/s31/python/s31.py run zig-out/s31/preimage4 src/frontends/s31/examples/hashes/preimage4.valid.json
python3 src/frontends/s31/python/s31.py prove zig-out/s31/preimage4 src/frontends/s31/examples/hashes/preimage4.valid.json zig-out/s31/preimage4.proof
python3 src/frontends/s31/python/s31.py verify zig-out/s31/preimage4 zig-out/s31/preimage4.proof
```

`prove` writes a public-only statement beside the proof. `verify` uses that statement by default. The generated verifier can also run directly from another directory with `PROOF STATEMENT.json VERIFICATION-KEY.json`. Package manifests hash every artifact. A local cache key includes the program source, compiler inputs, pinned AIR assets, and Zig version. Builds are staged and published atomically.

For the 256-round recurrence, choose a lowering explicitly:

```sh
python3 src/frontends/s31/python/s31.py build src/frontends/s31/examples/arithmetic/arith4.s31.json --lowering sparse-chip --out zig-out/s31/arith4-sparse-chip
python3 src/frontends/s31/python/s31.py inspect zig-out/s31/arith4-sparse-chip
python3 src/frontends/s31/python/s31.py prove zig-out/s31/arith4-sparse-chip src/frontends/s31/examples/arithmetic/arith4.valid.json zig-out/s31/arith4-sparse-chip.proof
python3 src/frontends/s31/python/s31.py verify zig-out/s31/arith4-sparse-chip zig-out/s31/arith4-sparse-chip.proof
```

The ten modes are `gate` (the original eleven-component circuit), `chip` (that circuit plus one linked step AIR), `sparse-gate`/`sparse-chip` (three arithmetic circuit components, optionally with the step AIR), `sparse-wide-gate` (Eq plus those three components for wide integers), `direct-gate`/`direct-chip` (one QM31 arithmetic component, optionally with the step AIR), and `sha-joint`, `sha-shift`, and `sha-fused` (one private Bitcoin header joined to three SHA compression calls). The repeated-step chip modes accept only the exact four-lane square-then-add recurrence and 16–32768 power-of-two rounds. `direct-chip` also accepts a private four-lane input: source-derived circuit wires connect to the chip endpoints inside the same proof, while the public statement contains only declared output claims. Sparse arithmetic retains M31-to-`u32` conversion and the 16-bit range table. Direct mode accepts all-M31 arithmetic relations, binds canonical public M31 words directly, and omits that converter and table. Each selected chip and circuit share one STARK proof and one native verifier invocation.

The direct-M31 example is [`examples/arithmetic/arith4_m31.s31.json`](examples/arithmetic/arith4_m31.s31.json). Build it with `--lowering direct-chip` and use [`examples/arithmetic/arith4.valid.json`](examples/arithmetic/arith4.valid.json) as the assignment. The [source-to-AIR guide](docs/reference/LANGUAGE_AND_AIR.md#direct-m31-public-values) explains the different public encoding and constraint profile.

The private-boundary example is [`examples/boundary/private_step16.s31`](examples/boundary/private_step16.s31), with [`examples/boundary/private_step16.valid.json`](examples/boundary/private_step16.valid.json) as its assignment and a [checked normalized relation](examples/boundary/private_step16.s31.json). Build the text source with `--lowering direct-chip`. Its sealed `direct-m31-private-v5` key records the eight circuit wire addresses, and its public statement contains one aggregate output rather than the four input and four final values. The [private-boundary guide](docs/private-boundary.md) specifies the lookup connection and source restrictions.

The hash suite includes [`examples/hashes/merkle2.s31.json`](examples/hashes/merkle2.s31.json), which hashes two private leaves into a public root, and [`examples/hashes/merkle_path1.s31.json`](examples/hashes/merkle_path1.s31.json), which proves a one-level path with a constrained direction bit. Use `--lowering gate` for both. The [hash section of the language guide](docs/reference/LANGUAGE_AND_AIR.md#hashes-tree-nodes-and-conditional-paths) specifies every byte and field conversion.
The [hash library brief](../../../design/s31/language/HASH_LIBRARY.md) records the cryptographic encoding, proof cost and next efficiency work.

The field-native suite has matching tree and one-level-path examples: [`examples/hashes/merkle2_poseidon.s31.json`](examples/hashes/merkle2_poseidon.s31.json) and [`examples/hashes/merkle_path1_poseidon.s31.json`](examples/hashes/merkle_path1_poseidon.s31.json). Build them with `--lowering direct-gate`. This uses the repository's pinned Stark-V M31 Poseidon2 permutation and eight-column QM31 arithmetic AIR; each build still emits its own native verifier. Direct-mode `select` currently requires a directly referenced `m31[1]` input selector, constrained by `b²=b`. The two hash families produce different roots for the same leaves.

```sh
python3 src/frontends/s31/python/s31.py build src/frontends/s31/examples/hashes/merkle_path1_poseidon.s31.json --lowering direct-gate --out zig-out/s31/merkle-path1-poseidon
python3 src/frontends/s31/python/s31.py prove zig-out/s31/merkle-path1-poseidon src/frontends/s31/examples/hashes/merkle_path1_poseidon.valid.json zig-out/s31/merkle-path1-poseidon.proof
python3 src/frontends/s31/python/s31.py verify zig-out/s31/merkle-path1-poseidon zig-out/s31/merkle-path1-poseidon.proof
```

```sh
python3 src/frontends/s31/python/s31.py build src/frontends/s31/examples/hashes/merkle_path1.s31.json --lowering gate --out zig-out/s31/merkle-path1
python3 src/frontends/s31/python/s31.py prove zig-out/s31/merkle-path1 src/frontends/s31/examples/hashes/merkle_path1.valid.json zig-out/s31/merkle-path1.proof
python3 src/frontends/s31/python/s31.py verify zig-out/s31/merkle-path1 zig-out/s31/merkle-path1.proof
```

[`generate_merkle_path.py`](tools/generate/generate_merkle_path.py) expands a fixed-depth path into normalized S31 source plus an independently calculated assignment. For example:

```sh
python3 src/frontends/s31/tools/generate/generate_merkle_path.py --depth 4 --seed 1 --out zig-out/s31/merkle-path4-generated
python3 src/frontends/s31/python/s31.py check zig-out/s31/merkle-path4-generated/merkle_path4.s31.json
python3 src/frontends/s31/python/s31.py build zig-out/s31/merkle-path4-generated/merkle_path4.s31.json --lowering gate --out zig-out/s31/merkle-path4
python3 src/frontends/s31/python/s31.py prove zig-out/s31/merkle-path4 zig-out/s31/merkle-path4-generated/merkle_path4.valid.json zig-out/s31/merkle-path4.proof
python3 src/frontends/s31/python/s31.py verify zig-out/s31/merkle-path4 zig-out/s31/merkle-path4.proof
```

Pass `--hash poseidon2` to generate a field-native path instead, and build its source with `--lowering direct-gate`. A generated depth-eight path with seed 1 was proved and accepted by its native verifier; the [smoke record](../../../design/s31/measurements/hash/poseidon-depth8-smoke-v6-2026-10-06.json) has 23,055 raw arithmetic rows, 262,144 fixed cells, and a 189,460-byte proof. Its 0.184 s proving time is one run with stochastic proof-of-work.

Run the package acceptance and matched Cairo benchmarks with:

```sh
python3 src/frontends/s31/tests/acceptance/acceptance_v1.py
python3 src/frontends/s31/tests/acceptance/acceptance_profiles_v2.py
python3 src/frontends/s31/tests/acceptance/acceptance_direct_v4.py
python3 src/frontends/s31/tests/acceptance/acceptance_hash_suite_v5.py
python3 src/frontends/s31/benchmarks/benchmark_hash_suite_v5.py --trials 3
python3 src/frontends/s31/tests/acceptance/acceptance_poseidon_v6.py
python3 -m unittest discover -s src/frontends/s31 -p 'test_text_frontend.py' -v
python3 src/frontends/s31/tests/acceptance/acceptance_text_v1.py
python3 src/frontends/s31/benchmarks/benchmark_poseidon_v6.py --trials 5
python3 src/frontends/s31/benchmarks/randomized_proofs_v1.py
python3 src/frontends/s31/benchmarks/benchmark_v1.py --trials 3
python3 src/frontends/s31/benchmarks/benchmark_profiles_v2.py --trials 7
python3 src/frontends/s31/benchmarks/benchmark_direct_v4.py --trials 9
python3 src/frontends/s31/benchmarks/measure_direct_memory_v4.py
python3 src/frontends/s31/benchmarks/compare_direct_cairo_v4.py --rounds 32768 --trials 5
```

The v1 acceptance suite proves arithmetic, Blake2s, mixed, three-lane, and private-witness relations. It rejects bad witnesses, changed public statements, altered keys, malformed proofs, and proofs sent to the wrong program verifier. The profile suites prove shared recurrences across the profile families and reject changed statements, keys, proof bytes, cross-profile replay, and chip-witness mutations. The [BLAKE2s acceptance](../../../design/s31/measurements/hash/hash-suite-acceptance-v5-2026-10-06.json) and [Poseidon2 acceptance](../../../design/s31/measurements/hash/poseidon-acceptance-v6-2026-10-06.json) verify independently calculated tree roots, both valid direction bits, and negative source/witness/proof cases. The [matched hash comparison](../../../design/s31/measurements/hash/poseidon-comparison-v6-2026-10-06.json) records distinct verified inputs and proof costs. The randomized run compiles three generated programs and checks nine proofs against an independent Python M31 oracle. The [engineering brief](../../../design/s31/README.md) explains the architecture and the limits of comparisons with Cairo.

The direct/Cairo comparison also requires the compiled Cairo executable and VM adapter input from `S31_TRIALS=1 src/frontends/s31/benchmarks/scale.sh 32768`, plus a direct profile benchmark including 32,768 rounds. It checks the same public values under both native verifiers; its recorded time ratio applies only to this recurrence and the selected proof implementations.

The default v1 profile still pays for all eleven circuit AIR components and 45 preprocessed columns. The arithmetic-only sparse v3 profile uses three components and 12 preprocessed columns; direct-M31 v4 uses one and eight. The sparse-wide v5 profile adds equality rows for wide-integer and SHA gadgets. Each has a distinct verification key and native verifier. The public ABI is limited to eight words. Poseidon2 and, by default, SHA256d use the generic arithmetic circuit. The opt-in `sha-joint`, `sha-shift`, and `sha-fused` profiles join one private Bitcoin header to three SHA compression calls in one proof. There is no general control flow, automatic chip extraction, or recursive verifier generation for arbitrary S31 profiles. The established fixed-key claim fold handles `gate` and `sparse-wide-gate` leaf claims. The Bitcoin chain-fold prototype updates a hash root across two proved headers and has a checkpoint-bound sealed key and standalone native verifier; full consensus state and an analyzed recursive depth bound remain. The older v0 `showcase`, `compare.sh`, and `scale.sh` paths remain available for the large repeated-arithmetic Cairo comparison. The [engineering brief](../../../design/s31/README.md) and [MVP roadmap](../../../design/s31/MVP_ROADMAP.md) describe the remaining work.

The [sealed fused Bitcoin verifier](../../../design/s31/bitcoin/BITCOIN_FUSED_SEALED_VERIFIER.md) authenticates one header after genesis with a source-derived key, a named public block hash and timestamp, and one 21-component proof joining the generic circuit to the SHA AIR. The [matched production-parameter sample](../../../design/s31/measurements/sha/bitcoin-fold-generic-vs-fused-sha-production-fri-2026-10-07.json) measured 16.66 s and 519,597 bytes for generic SHA versus 12.45 s and 659,942 bytes for fused SHA; it is one sequential machine run. The [checked Bitcoin work primitive](../../../design/s31/bitcoin/BITCOIN_WORK_DIVISION.md) supplies 256-bit division, block work, and chain-work addition as constrained circuit operations. `std::bitcoin::block_work(UInt256)` also lowers from `.s31` source; its [production-parameter trial](../../../design/s31/measurements/bitcoin/bitcoin-block-work-gate-2026-10-07.json) passed native verification. Fused-proof recursion and a same-key block-two proof remain open.
