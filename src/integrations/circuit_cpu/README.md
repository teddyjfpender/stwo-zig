# `stwo_circuit_cpu_integration`

`stwo_circuit_cpu_integration` is the circuit prover of the circuit recursion
stage on the CPU backend: the Zig port of `crates/circuit_prover` of
[starkware-libs/proving](https://github.com/starkware-libs/proving) at
commit `5a7c5ede4299c91a61df19a07cba4f7502c14230` (milestone M7 of the
[recursion design](../../../design/starknet-proving-pipeline/recursion/02-design.md),
§4). Given a finalized circuit's value table and its preprocessed circuit, it
produces the same proof bytes as upstream `prove_circuit_assignment`, on
either channel profile, and converts the proof into the in-circuit verifier's
CircuitSerialize format or the Cairo verifier's felt stream. On top of the
prover, `recursion` folds leaf proofs into a root exactly as
`stwo_run_and_prove_recursive_tree` does and generates circuit registries as
`circuit-params --registry` does (milestone M9).

| Property | Value |
| :--- | :--- |
| Version | `0.1.0` |
| Layer | `integration` |
| Owner | `circuit-cpu-integration` |
| Public Zig module | `stwo_circuit_cpu_integration` |
| Focused CI host | Linux |
| Upstream | `proving@5a7c5ed` |

See the [package contract](package.contract.json) and the
[public facade](mod.zig) for the exact package boundary.

## Architecture

```mermaid
flowchart LR
    Circuit[`stwo_circuit_frontend`: builder, preprocessing, witness] --> Prove[prove.zig]
    Bundle[circuit_air.air_programs_v1.bin] --> Air[air.zig]
    Cairo[`stwo_cairo_frontend`: captured-AIR component] --> Air
    Air --> Prove
    Engine[`stwo_prover_engine` + `stwo_cpu_backend`] --> Prove
    Prove --> Proof[CircuitProof]
    Proof --> VerifierProof[verifier_proof.zig]
    Proof --> CairoProof[cairo_verifier_proof.zig]
    Wire[`stwo_circuit_recursion_wire`: CircuitSerialize, felt stream] --> VerifierProof
    Wire --> CairoProof
    VerifierProof --> Recursion[recursion: canonical, fold, tree, circuit_params]
    CairoProof --> Recursion
```

The integration owns only composition:

- **Witness** comes from `stwo_circuit_frontend.witness`: the eleven
  components' base columns and LogUp lookups, and the interaction trace built
  with the prover engine's `air.logup_columns` (the `LogupTraceGenerator`
  port).
- **Constraints** are not ported. The oracle records the eleven
  `circuit_air` `FrameworkEval`s into `STWZEVA/1` evaluation programs
  (`vectors/circuit/official/circuit_air.air_programs_v1.bin`, design §4.2),
  and the Cairo lane's generic captured-AIR component evaluates them. `air.zig`
  rebinds the recorded instance to a proof's component log sizes and
  preprocessed layout: trace and evaluation log sizes, denominator inverses
  and preprocessed indices change; constraint, mask and relation order do not.
- **Transcript**: `prove.zig` is the only place that sequences channel
  operations (salt, FRI config, preprocessed commit, circuit hash, claim,
  base commit, 20-bit interaction grind, lookup draw, claimed sums,
  interaction commit, `prove_ex` with every preprocessed column sampled and
  the FRI grind). Both grinds use the Rust `SimdBackend` nonce order.
- **Profiles**: `Internal` is `Prover(Blake2sM31MerkleChannel)` (leaves and
  internal folds), `Root` is `Prover(Blake2sMerkleChannel)`. Both commit
  with the plain Blake2s Merkle hasher, so one preprocessed tree serves both.

## Public API

```zig
const circuit_cpu = @import("stwo_circuit_cpu_integration");

var bundle = try circuit_cpu.air.parse(allocator, bundle_bytes);
var proof = try circuit_cpu.Internal.prove(allocator, values, &preprocessed_circuit, &bundle, pcs_config, .{}, {});
var verifier_proof = try circuit_cpu.verifier_proof.prepare(allocator, &proof);
const bytes = try verifier_proof.serialize(allocator);
```

| Export | Responsibility |
| :--- | :--- |
| `air` | Parse the circuit AIR bundle and bind it to a proof's geometry |
| `prove` | `Prover(MC)`, `Options`, `Step`, `defaultPcsConfig` and the transcript |
| `Internal` | The prover on the internal (M31 channel) profile |
| `Root` | The prover on the root (plain Blake2s channel) profile |
| `verifier_proof` | `prepare_circuit_proof_for_circuit_verifier`, the generic `proof_from_stark_proof` (`fromStarkProof`, for circuit and Cairo proofs), CircuitSerialize bytes, and `circuitVerifierValues` (a decoded proof as the in-circuit verifier's `Proof(QM31)`) |
| `cairo_verifier_proof` | `prepare_circuit_proof_for_cairo_verifier`: a root proof as the Cairo circuit verifier's felt stream (`root.proof`) |
| `verify` | `verify_circuit` on a `CircuitSerialize` proof and a `wire.verify_request` request: decode, convert, build the verification circuit with values; a `Verdict` (accepted with the output digest, or the rejecting stage) |
| `recursion` | Orchestration (design §7): `leaf_wrap` (`prove_leaf` steps 4-8), `topology_key` (design §3.5), `topology_cache` (the byte-bounded per-topology LRU), `canonical` (`CanonicalCircuit::build`), `fold` (`LayerEntry`, `reduce_pair`, `reduce_root_single`), `tree` (`fold_entries`, `foldLeaves`, `write_root_outputs`) and `circuit_params` (registry generation) |
| `repeated_step_chip` | S31's four-lane indexed repeated-step AIR (`out = in² + c`), linked to the circuit by LogUp in the same proof |
| `private_boundary_bridge` | S31's private four-lane circuit/chip boundary: chip endpoints joined to private Gate wires in one LogUp closure |
| `private_pair_boundary` | Isolated checked two-call plan: source-owned repeated-address Gate counts, tagged seven-field tuples, exact five-component layout, closure oracle, and transcript order guard. No pair proof API yet. |
| `tagged_pair_chip` | Staged two-call affine-square chip AIR with a component-constant call ID in its seven-field LogUp tuple; source binding awaits verifier integration. |
| `tagged_pair_bridge` | Staged bridge AIR for each pair call: eight cyclic row equalities and five mixed-arity LogUp constraints; not yet in a native proof profile. |
| `sparse_arithmetic` | S31 sparse-v3 prover: QM31, M31-to-u32 and range-16 circuit AIRs, optionally with the step chip, in one transcript |
| `sparse_wide` | S31 sparse-wide-v5 prover: Eq, QM31, M31-to-u32 and range-16 circuit AIRs |
| `direct_arithmetic` | S31 direct-M31 v4 prover: one QM31 circuit component and an optional step chip |

### Two-call private boundary staging

`private_pair_boundary.Plan` has exactly two calls with IDs 0 and 1. Each
call names four input and four output circuit addresses, a power-of-two round
count, and a field constant. A shared address is allowed: `PairBoundary`
raises the authenticated preprocessed Gate multiplicity once per appearance.
The plan checks that each named address is a private, uniquely produced wire.
`Plan.preprocessed` constructs the actual direct circuit columns with those
counts. The existing direct prover rejects that circuit with
`UnsupportedPairBoundaryProfile` so it cannot silently use the one-call
protocol.

The planned pair roster is exactly circuit, chip 0, chip 1, bridge 0, bridge 1.
It has 46 main and 64 interaction columns. With `C` circuit constraints, the
five component counts are `C, 6, 6, 13, 13`, at offsets
`0, C, C+6, C+12, C+25`; total `C+38`. Chip relation tuples are
`(relation, call_id, step, lane0, lane1, lane2, lane3)`. The existing Gate
relation keeps its six-field tuple `(relation, address, value, 0, 0, 0)`.
Both arities use the same `(z, alpha)` challenges and their fractions join
the same LogUp sum. The prover draws this pair once after all main columns
are committed, mixes the five claimed sums, then commits the interaction
columns. `effectiveDigest` binds the true source
digest and generated manifest digest with a pair-specific domain before the
preprocessed commitment. The pair profile tag is `0x5333315041495201`;
`S31NAT8P` and `S31NAT8C` are reserved for its eventual proof envelopes.

The `Plan.extract`, `checkTraceRows`, `closure`, roster, and transcript-order
functions are deterministic admission and test oracles. **They do not by
themselves make a pair proof.** Tagged chip and bridge AIR implementations are
staged as isolated components with row and quotient differential tests. The
one-call proof format and verifier are unchanged.

An unexported `direct_pair_arithmetic.zig` experiment now constructs and
verifies an in-memory five-component proof using one lookup challenge and five
claimed sums. Its native test covers two different constants and round counts,
coherent repeated endpoint addresses, and public outputs depending on both
calls. It also mutates the source and manifest digests, plan, public statement,
sums, nonce, and commitment roots. This engine test accepts a caller-provided
typed manifest digest and a caller-provided source plan; it does not reconstruct
either from S31 source. There is no versioned pair proof envelope or released
S31 pair compiler/verifier path. Those source correspondence and package checks
remain required before the pair profile is enabled.

`prove` takes an optional observer (`onStep`, `onLookupElements`,
`onTraces`) for conformance tests and an `Options` value whose fields change
only execution: a stage-profile recorder and compact polynomial storage,
which drops each tree's blown-up evaluations after hashing and evaluates the
constraints from coefficients.

## Leaf wrap (milestone M8)

`recursion.leaf_wrap.wrapCairoProof` ports steps 4-8 of upstream
`prove_leaf` and `prepare_cairo_proof_for_circuit_verifier`: it reads the
trace log size off the Cairo proof's lifting heights, looks up the
registry's leaf verifier, converts the Cairo proof with `fromStarkProof`,
builds the leaf circuit with values (`buildCairoVerifierCircuit`), pads it
to the registry target, requires it to be satisfied, proves it on the
`Internal` profile and requires the proof's circuit hash to equal the
registry's. The input is the Cairo CPU integration's in-memory leaf proof
(`proveLeafCairo`), which R10c pins byte for byte to upstream `prove_cairo`.

The preprocessed circuit is cached per `TopologyKey`: built on a key's first
wrap and published only after that wrap's proof passes the registry check.
A hit skips preprocessing and still checks the proof's circuit hash and the
rebuilt circuit's variable count. Before proving, the builder context is
reduced to its value table (`Context.intoValues`), and the prover frees the
base columns once the interaction trace is written.

The product `stwo-circuit-recursion-cpu leaf-wrap`
([README](../../products/circuit_recursion_cpu/README.md)) drives it; its
`circuit-parity-r8` rung requires the output file to equal upstream
`leaf-prover`'s `expected_output.json` byte for byte.

## Dependencies

- `stwo_cairo_frontend`: the captured-AIR component and `STWZEVA/1` bundle
  reader (`proving.air.component`, `witness.composition_bundle`).
- `stwo_circuit_frontend`: builder, component list, preprocessing, circuit
  hash and witness.
- `stwo_circuit_recursion_wire`: the CircuitSerialize proof format.
- `stwo_core`: fields, channel profiles, PCS configuration and proofs.
- `stwo_cpu_backend`: the CPU backend.
- `stwo_prover_api`: the engine contract.
- `stwo_prover_engine`: the PCS, FRI and composition engine.

## Build, test, and run

```sh
zig build test --build-file src/integrations/circuit_cpu/build.zig -Doptimize=ReleaseSafe -j2
zig build circuit-parity-r7 --build-file src/integrations/circuit_cpu/build.zig -Doptimize=ReleaseSafe -j2
zig build circuit-parity-r4-values --build-file src/integrations/circuit_cpu/build.zig -Doptimize=ReleaseSafe -j2
zig build circuit-parity-r6-leaf --build-file src/integrations/circuit_cpu/build.zig -Doptimize=ReleaseSafe -j2
zig build circuit-parity-r9 --build-file src/integrations/circuit_cpu/build.zig -Doptimize=ReleaseFast -j2
zig build circuit-parity-registry --build-file src/integrations/circuit_cpu/build.zig -Doptimize=ReleaseFast -j2
zig build circuit-parity-r11 --build-file src/integrations/circuit_cpu/build.zig -Doptimize=ReleaseSafe -j2
STWO_CIRCUIT_MULTIVERIFIER_INPUTS=<path> \
  zig build circuit-parity-r7-multiverifier --build-file src/integrations/circuit_cpu/build.zig -Doptimize=ReleaseFast -j2
```

`circuit-parity-r7` proves the six `prover_test.rs` circuits under the
upstream tests' default config and two of them under the 26-bit circuit FRI
config on both profiles, and compares every transcript digest, nonce, lookup
element, claimed sum, commitment, FRI root, last layer and per-column trace
digest with the oracle (`vectors/circuit/r7/prove_small.json`,
`prove_profiles.json`), plus the CircuitSerialize bytes and upstream
`verify_circuit`'s verdicts on them (`vectors/circuit/r7/verify/`).

`circuit-parity-r4-values` is the value half of the frontend's R4 rung: it
decodes `test_data/circuit_multiverifier/{proof,proof_cairo}.bin`, builds
the multiverifier over them with the frontend's in-circuit verifier and
compares every stage's gate summary, the value digest and the output digest
with `vectors/circuit/r4/verifier_stages.json`, and requires the circuit to
be satisfied. It also builds the multiverifier of two copies of the Cairo
verifier proof, the circuit `proof.bin` proves, and matches its gate and
value digests with `vectors/circuit/r7/multiverifier_inputs.json`. The R7
circuits come from the frontend's shared `circuit_testing.contexts`.

`circuit-parity-r6-leaf` is the leaf half of rung R6 (labelled large: a
2^23-row circuit, about 3.3 GB and 15 s in ReleaseSafe). It rebuilds the
leaf verifier of `vectors/circuit/official/registries/leaf_prover_canonical_small.json`
as `circuit-params --registry` does: `leaf_verifier_config` over the
registry's `cairo_prover_params` at trace log size 20, the leaf test program
(`vectors/circuit/official/programs/use_all_opcodes_and_builtins_compiled.json`,
loaded by the Cairo frontend's `programFeltsFromCompiledJson`), the committed
canonical_small Cairo preprocessed root (`vectors/circuit/r6/topology.json`),
the frontend's `buildCairoVerifierTopology`, padding to the registry target
and preprocessing. The preprocessed root and circuit hash must equal the
registry's.

`circuit-parity-r7-multiverifier` reproduces
`test_data/circuit_multiverifier/proof.bin` byte for byte. Its input, the
179 MB multiverifier circuit and value table, is written by
`stwo-circuit-oracle multiverifier-inputs --proving-root <proving>
--inputs-output <path>` and pinned by `vectors/circuit/r7/multiverifier_inputs.json`;
without the environment variable the test is skipped.
`STWO_CIRCUIT_STAGE_PROFILE=1` prints the stage times and
`STWO_CIRCUIT_COMPACT_MIN_LOG` (default 18, `off` to disable) selects compact
storage. `STWO_CIRCUIT_R7_EMIT_DIR` makes both steps write the proofs and the
oracle's `verify-circuit` requests.

`circuit-parity-r9` is rung R9 (labelled large). It folds 1, 2, 3, 4 and 5
copies of the upstream golden leaf
(`vectors/circuit/official/recursive_tree/four_leaves/leaf.json`) under the
recursive-tree test registry with `recursion.tree.foldLeaves` and compares
`root.proof`, `root_outputs.json` and `root_packed.json` as raw bytes: the
four-leaf tree against the upstream goldens, the others against the oracle's
`fold-tree` checkpoint (`vectors/circuit/r9/fold_tree.json`). Every
reduction proves a 2^23-row multiverifier; the five trees are 15 reductions.

`circuit-parity-r11` is rung R11, acceptance and tamper. `verify.zig` is
upstream `verify_circuit` on a `CircuitSerialize` proof: it decodes the proof
under `circuit_verifier_proof_config` of a request (the verified circuit's
`PcsConfig`, preprocessed layout, root and claimed output digest; the
oracle's `verify-circuit --request` format, `wire.verify_request`), converts
it with `verifier_proof.circuitVerifierValues` and builds the frontend's
verification circuit (`statements.circuit_verifier`) with values. The rung
verifies upstream's multiverifier `proof.bin`, the Rust golden leaf under the
recursive-tree canonical config and a Zig proof of the R7 fibonacci circuit,
each untouched and after each of eight tamperings (output digest,
preprocessed root, circuit hash via the layout, a claimed sum, the channel
salt, both PoW nonces, a FRI witness). The Zig verdicts must be accept,
then reject; upstream's verdicts on the same bytes are committed under
`vectors/circuit/r11/verify/` and must agree (`STWO_CIRCUIT_R11_EMIT_DIR`
writes the cases for `generate_circuit_oracle_vectors.py --r11-emit-dir`).
About 30 s and under 1 GB in ReleaseSafe.

`circuit-parity-registry` generates both canonical_small test registries from
their upstream definitions (`vectors/circuit/official/registry_definitions`)
with `recursion.circuit_params.generate` and compares them with the committed
registries byte for byte, trailing newline included.

The product `stwo-circuit-recursion-cpu` (`src/products/circuit_recursion_cpu`,
`zig build stwo-circuit-recursion-cpu`) runs the leaf wrap and both of these
from the command line, the last two with upstream's flags
(`fold-tree --program_input ... --circuit_registry_json ...`,
`circuit-params --definition D --registry [--output-path P]`).

## Measurements

Apple M4 Max, AC power, `ReleaseFast`, compact storage from log 18:

| Circuit | Build (Rust, value mode) | Preprocess | Prove (Zig) | Peak RSS |
| :--- | ---: | ---: | ---: | ---: |
| multiverifier of two Cairo proofs (2^21 qm31_ops rows, blowup 3, 27-bit FRI grind) | 0.05 s | 0.2 s (Rust), 0.15 s (Zig, from the dump) | 39.8 s | 5 GB |
| leaf wrap of `use_all_opcodes_and_builtins` (canonical_small, 2^23 qm31_ops and blake_g_gate rows, blowup 1, 26-bit FRI grind) | 0.4 s (Zig) | 0.3 s (Zig) | 36-44 s | 11-17 GB |

The leaf wrap is timed by `stwo-circuit-recursion-cpu leaf-wrap` on
2026-09-30 with other agents' jobs running and 8-14 GB of swap in use, so its
numbers are an upper band, not a benchmark. Upstream `leaf-prover` on the
same input, same host: 30.4 s for the whole leaf (Cairo proof included; the
circuit `prove_ex` is 13.7 s), 12.6 GB maximum RSS and 25.4 GB peak
footprint. The Zig wrap's memory is the circuit prover's (composition
evaluation from coefficients peaks at about 16 GB); its reduction is M11
work (design §9.3).

The builder share of a fold is small: upstream's builder takes about 0.1%
of this proof's wall time (0.7% with preprocessing), and the Zig builder
about 0.6 s of a 50-68 s reduction (about 1%, the recursive-tree table
below). Both are far below the 10% at which design §9.1 would schedule the
topology tape.

Grinds, measured separately (`STWO_CIRCUIT_STAGE_PROFILE=1`; the CPU search
runs about 26-30 million Blake2s hashes per second on this host, and the
time is set by the Rust-order position `hi * 2^20 + lo` of the nonce):

| Proof | Interaction grind (20 bits) | FRI grind |
| :--- | ---: | ---: |
| multiverifier, internal profile | 3 ms (`hi = 0`) | 11.3 s at 27 bits (`hi = 276`), 28% of the proof |
| `blake_g_gate`, internal profile | 51 ms (`hi = 1`) | 1.23 s at 26 bits (`hi = 35`) |
| `fibonacci`, root profile | 45 ms (`hi = 1`) | 1.28 s at 26 bits (`hi = 35`) |
| `blake_g_gate`, root profile | 17 ms (`hi = 0`) | 3.34 s at 26 bits (`hi = 95`) |
| `fibonacci`, internal profile | 3 ms (`hi = 0`) | 14 ms at 26 bits (`hi = 0`) |

The expected cost of a 26-bit grind is about 2^26 hashes (2.2 s here); of a
20-bit grind, about 2^20 (35 ms).

Recursive tree and registry (2026-09-30, same host, AC power, ReleaseFast,
run alone under the host's heavy-command semaphore; upstream is the release
binary of `proving@5a7c5ed`):

| Run | Zig | Upstream |
| :--- | ---: | ---: |
| one fold of the test registry (2^23-row multiverifier, 26-bit FRI grind), product CLI, `fold-tree` of one leaf | 68 s wall, 92 s CPU, 9.9 GB peak | 22 s wall, 192 s CPU, 22.9 GB peak |
| `circuit-parity-r9` (15 reductions, scoped worker pool) | 627 s, 18.1 GB peak | 364 s for the same 15 (`fold-tree` oracle), 22.7 GB peak |
| `circuit-params --registry`, recursive-tree definition | 3.5 s, 3.4 GB peak | 5.0 s, 7.7 GB peak |

Per reduction the Zig builder takes about 0.6 s; the rest is the prover,
which runs mostly on one core in this path (about 2 cores of CPU time per
wall second against upstream's 8.5). It is 2.5-3x slower than upstream and
above the 8 GB per-process budget of the development host; both are
milestone M11 work (design §9), not parity issues.

## Contract and invariants

- Proof bytes equal upstream's for the same inputs on both profiles; every
  field is covered by R7.
- The circuit AIR bundle is authenticated by SHA-256 (`air.bundle_sha256`)
  before it is used and must list the eleven components in `ComponentList`
  order.
- `Options` never changes proof bytes.
- The lookup sum of every proof is checked to be zero before the
  interaction trace is committed.

## Change checklist

- Run `circuit-parity-r7` after any change to the witness, the bundle
  binding, the transcript or the engine paths it uses.
- Run `circuit-parity-r7-multiverifier` after any change that affects
  blowup above 1, the FRI fold step, lifting, or compact storage.
- Regenerate an oracle vector only from `tools/stwo-circuit-oracle-rs` and
  record it in `vectors/circuit/provenance.json`.

## Related documentation

- [Recursion design](../../../design/starknet-proving-pipeline/recursion/02-design.md)
- [Rust porting map](../../../design/starknet-proving-pipeline/recursion/01-rust-map.md)
- [Circuit frontend](../../frontends/circuit/README.md)
- [Circuit oracle](../../../tools/stwo-circuit-oracle-rs/README.md)
