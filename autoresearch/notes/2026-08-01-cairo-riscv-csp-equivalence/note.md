# Exact Cairo / RISC-V CSP function equivalence

## Problem-match brief

Task and required semantics:

Construct a differential whole-pipeline benchmark in which Cairo and RISC-V
prove the same deterministic function on the same logical input and publish the
same canonical output. The required output is an authenticated comparison row,
not merely a proof that two differently named programs both ran.

Inputs, measured scale/provenance, encoding, and computational model:

- The input authority is `vectors/riscv_csp/manifest-v2.json`, pinned to CSP
  commit `269c43cc32d3127e3d9ce74d20652887d894cca3` (**sourced**).
- The first basket is SHA-256 and Keccak-256 over the exact CSP-seeded 2,048
  bytes. The RISC-V container is a little-endian `u32` length followed by the
  message; the logical input is the payload after that framing (**sourced**).
- Poseidon2-M31 uses 16 canonical M31 elements and returns eight canonical M31
  state elements. ECDSA uses a 32-byte digest, 65-byte uncompressed secp256k1
  SEC1 key, and 64-byte compact `r || s` signature (**sourced**).
- Frontend-only encoding/decoding is linear work, `O(n)` time and `O(n)` output
  storage for byte-array construction, and is included in execution when the
  production frontend performs it. Program compilation and fixture derivation
  are outside timed samples (**derived contract**).
- The paired measurement is wall time on the same qualified host. Its proving
  interval is execution plus witness/ProverInput construction plus proof
  generation; verification is reported separately (**derived contract**).

Constraints, promises, invariants, and exploitable structure:

- The logical input must be public and its encoding, size, and SHA-256 digest
  must be bound by the verifier-accepted statement.
- The SHA-256 digest of the normalized 2 KiB input is also that row's expected
  function output. This deliberate equality is distinct from the SHA-256 of the
  RISC-V length-prefixed container.
- The program digest and canonical output encoding/value must be bound by that
  same statement.
- Host-generated values and syscall transcripts are not implementations of the
  function unless the AIR constrains the relevant syscall semantics.
- The proof uses the same secure PCS parameters and is accepted by a separate
  verifier invocation.
- Output equality is byte-exact after an explicit frontend projection. A
  successful execution or proof without output equality is failure.
- Inputs are static, pinned fixtures. Their framing can be validated once before
  timing; no dynamic search or optimization problem is present.

Candidate matches, relationship, and evidence status:

| Candidate | Relationship | Evidence | Fit and risk |
| --- | --- | --- | --- |
| Cairo corelib `compute_sha256_byte_array` | analogy only / semantic reference | Pinned [SHA-256 corelib source](https://github.com/starkware-libs/cairo/blob/eef8857c3a279f7f0208efa258d74a7ed2bf6357/corelib/src/sha256.cairo) delegates compression to a Starknet syscall (**sourced**) | The current AIR does not constrain that host-executed syscall's SHA-256 semantics; a wrapper is not proof-sound computation evidence |
| Cairo corelib `compute_keccak_byte_array` | analogy only / semantic reference | Pinned [Keccak corelib source](https://github.com/starkware-libs/cairo/blob/eef8857c3a279f7f0208efa258d74a7ed2bf6357/corelib/src/keccak.cairo) delegates the permutation to a Starknet syscall (**sourced**) | The current AIR does not constrain that host-executed syscall's Keccak semantics; a wrapper is not proof-sound computation evidence |
| PR 171 Cairo-0 SHA2/SHA3 programs | constrained adaptation base | Authenticated programs call `finalize_sha256` / `finalize_keccak`; original inputs use `iterations` and neither original publishes its digest (**sourced**) | Exact source adaptations are now prepared and authenticated; compiled/proof evidence remains pending |
| Prepared exact Cairo-0 SHA-256/Keccak sources | exact constrained source, proof pending | SHA embeds 512 BE-u32 words and publishes eight words; Keccak embeds 256 LE-u64 words and publishes two LE-u128 limbs; both retain their mandatory finalizer and reject host input (**derived and tested**) | Semantic source gap is closed; cannot be timed until compilation, ProverInput, statement, proof, and verifier pins exist |
| Cairo corelib `poseidon_hash_span` | analogy only | Pinned [Poseidon corelib source](https://github.com/starkware-libs/cairo/blob/eef8857c3a279f7f0208efa258d74a7ed2bf6357/corelib/src/poseidon.cairo) uses classic Poseidon over `felt252` (**sourced**) | Wrong permutation, field, input/output contract |
| Cairo corelib `check_ecdsa_signature` | analogy only | Pinned [ECDSA corelib source](https://github.com/starkware-libs/cairo/blob/eef8857c3a279f7f0208efa258d74a7ed2bf6357/corelib/src/ecdsa.cairo) is explicitly STARK-curve ECDSA (**sourced**) | Wrong curve and key encoding for secp256k1 CSP vector |

Chosen canonical problem and exact variant:

This is deterministic differential conformance with authenticated test vectors:
for each row and frontend, prove `y = f(x)` for the same exact `f` and `x`, then
compare a canonical serialization of `y`. It is not a generic constraint
satisfaction problem and not an algorithm-selection opportunity. The useful
algorithmic transfer is the conformance-oracle pattern: normalize only at a
declared boundary, pin both representations, and reject any lossy or ambiguous
mapping.

Project -> canonical mapping and solution recovery:

The RISC-V container is decoded to a logical value `x`; each prepared Cairo
program embeds the same `x` as fixed words and takes an authenticated empty
arguments object. Each frontend's output is projected to canonical bytes `y`.
A comparison solution exists exactly when both verifier-accepted public
statements bind the same `(f, x, y)` tuple. Recovery is the manifest row plus
its program, arguments, derived ProverInput, VM-step count, statement
projection, proof, and verifier receipt.

Complexity/limits, named parameters, and citations:

Let `n` be input bytes or fixed-width field elements. Framing validation and
byte-array conversion cost `Theta(n)` work; SHA-256 and Keccak have linear block
counts in `n`. At `n = 2,048` this glue is bounded and must remain visible in
the execution stage, but compile/derivation work is excluded. Poseidon2 has 16
fixed inputs for this row; ECDSA has one fixed verification tuple. No
asymptotic claim is used to infer proving performance; end-to-end paired wall
time is the falsifier.

Prior algorithms, solvers, and implementations:

Use the pinned PR 171 constrained Cairo-0 SHA2/SHA3 programs as the adaptation
base for byte hashes. The prepared sources replace synthesized iteration-count
data with exact 2 KiB constants, retain mandatory `finalize_sha256` /
`finalize_keccak`, and publish the digest. Do not use the modern host-syscall
corelib APIs as proof-sound implementations. For Poseidon2-M31 and secp256k1, a
separately audited exact Cairo implementation or compatible maintained library
is needed; the existing builtins are not substitutions. No solver is relevant.

Selected transfer, integration boundary, and rejected alternatives:

The selected first slice is a versioned manifest and strict stdlib-only driver,
[`autoresearch/benchmarks/cairo_csp_comparison.py`](../../benchmarks/cairo_csp_comparison.py),
which authenticates the RISC-V manifest, exact input files, retained verified
outputs, proof/statement digests, PR 171 provenance, corelib pins, field/curve
classification, and future Cairo artifact requirements. It refuses timing when
no row is `exact_runnable`. The second slice is
[`fixture-provenance-v1.json`](../../../vectors/cairo/csp/fixture-provenance-v1.json),
the exact constrained Cairo-0 sources, and
[`scripts/cairo_csp_fixtures.py`](../../../scripts/cairo_csp_fixtures.py). That
validator reconstructs every embedded word from the normalized RISC-V payload,
checks finalizer/output structure, authenticates all pins, and keeps the
source/compiled/derived/runnable stages distinct. `zig build
cairo-csp-fixtures` validates now and is wired to derive compiled-ready rows
through the pinned adapter later as review candidates. That derivation is not a
promotion gate and never overwrites an authenticated `exact_runnable` fixture.

Rejected alternatives are: timing PR 171 iteration workloads under CSP labels;
wrapping the unconstrained modern SHA-256/Keccak host syscalls; removing or
bypassing the Cairo-0 finalizers; calling felt252 Poseidon “Poseidon2-M31”;
calling STARK-curve ECDSA “secp256k1”; or accepting a Cairo row whose logical
input/output is absent from the public statement.

End-to-end prediction, crossover, and falsifier:

The measured current state is zero runnable Cairo rows, two exact constrained
sources awaiting compilation/proof promotion, and two algorithm/curve
near-matches awaiting exact implementations. SHA-256/Keccak become runnable
only after compiled and derived evidence is added; Poseidon2/ECDSA require new
exact implementations first (**hypothesis**). Any mutation of an embedded
word, source/input/output pin, required finalizer, output projection, encoding,
public binding, negative ECDSA result, or relationship classification must
fail the validator. A measurement that omits execution/ProverInput construction
or uses a different host/protocol falsifies comparability even when the proof
verifies.

Correctness and benchmark plan:

1. Authenticate every committed authority by SHA-256 and reject duplicate JSON
   keys or schema drift.
2. Decode the binary framing and independently recompute SHA-256 and all
   deterministic byte/word projections.
3. Bind each RISC-V row to retained verified proof, public-values, and statement
   digests; require the invalid ECDSA signature to return all zero.
4. Promote a Cairo hash row only when its constrained program keeps the required
   finalizer and public digest output, and every row only with exact executable,
   arguments, derived ProverInput digest/size, VM steps, public-statement
   projection, exact output, and separate verifier evidence.
5. Measure CPU and Metal pairwise on the same host/power state with identical
   secure protocol settings, reporting execution, witness/ProverInput, proving,
   verification, proof bytes, and peak memory separately.

Performance integration boundary:

- This fixture contract and its SHA-256 reconstruction are validation/control
  plane work, never part of a timed proof sample. The Cairo program's input
  materialization and output writes remain inside execution and are therefore
  visible in the frontend comparison.
- Fixture conversion is deterministic `Theta(n)` work with one pass over the
  2 KiB payload. No new allocation, dispatch, command-buffer, Metal residency,
  or synchronization mechanism enters production proving code.
- CPU and Metal verdicts must reuse the production persistent session/arena and
  secure protocol. A backend optimization is admissible only if this canonical
  output and the verifier-accepted statement remain bit-exact.
- The falsifier for a performance result is any changed work definition,
  precomputed value hidden outside the interval, backend-specific input, or
  source-only row presented as a proof benchmark.

Open uncertainty:

- The exact `cairo-compile 0.14.0.1` environment must be provisioned and its
  full dependency resolution captured. This host has Python 3.12 plus `pipx`
  but no installed Cairo-0 compiler or container runtime.
- The prepared sources have structural and projection validation but are not
  promoted until compilation, VM execution, output observation, exact
  ProverInput/step pins, proof generation, and independent verification finish.
- The v1 contract hard-rejects every `exact_runnable` status. The current
  official-verifier receipt does not expose the accepted public-statement
  digest, so a v2 schema must cryptographically cross-bind that statement to
  the program, ProverInput, logical input/output, secure protocol, and proof
  before any row can be promoted.
- Production Cairo already includes its output segment in public data and
  transcript mixing; the fixture-specific stable projection document and
  digest remain to be emitted from the first verified run.
- An audited exact Cairo implementation is still needed for Poseidon2-M31 and
  secp256k1; until then their corelib links remain research leads only.
