# RV64 authenticated execution AIR contract

The bounded `rv64` API and the full-execution `rv64_full` API both prove
execution constraints rather than host validation of a receipt. The initial
sections describe the retained bounded format; the full-execution architecture
is described below. It uses concrete columns and a single QM31 polynomial
evaluator for native quotient evaluation and verifier OODS evaluation. Existing
commitment, transcript, FRI and proof-wire implementations remain protocol
authority. There is no generic CPU or parallel handwritten constraint evaluator.

## Statement and authority

The verifier receives expected program bytes, initial/final PC and register
values, and an explicit sorted memory aperture with initial/final values and
permissions. Full 64-bit addresses and values use eight canonical bytes.
No architectural word is reduced to one M31 element. Initial/final x0 is zero.
Mutable memory cannot overlap the immutable program. All unused public fields,
padding rows and disabled access witnesses have canonical encodings.

The proof carries a bounded public PC path and final access clocks. The verifier
reconstructs the fixed trace by decoding its own expected program at each PC;
it does not execute instructions or read private witness rows. Polynomial PC
constraints prove each transition to the next path entry and the expected final
PC. This first profile exposes the path. The concrete CPU integration owns a
`PreparedSetup` that independently derives the fixed root and physical layout
once per immutable program/path/final-PC identity. It owns copies of the program
and path. Subsequent requests may change register values, RAM and permissions,
and final access clocks; all remain separately bound by each fresh transcript.
The convenience verifier constructs setup afresh. No producer-supplied key/root
or serialized setup is accepted. The separate `rv64_full` profile below replaces this path-specific setup
with an immutable ROM lookup. This is a partial-execution statement, not an implicit
halt or a claim that an arbitrary OP guest completed.

## Authenticated register and memory relation

Each instruction has four distinct ordered ticks: rs1, rs2, rd, memory. Source
reads consume and re-emit exactly the same value. An enabled destination consumes
the previous value and emits the constrained result. Memory consumes/emits its
whole aligned eight-byte word and immutable permission bits; subword accesses
constrain the selected bytes and preserve every neighbour. Register aliases
within one instruction therefore form a real chain rather than duplicate reads
at one clock. x0 produces no mutable state event and always supplies zero.

The tuple is `(space, address[8], clock, value[8], read, write)`. Current ticks
are fixed; predecessor ticks and strict gaps are range constrained. Their sums
are smaller than the base-field prime, so time is a strictly increasing integer,
not a modular cycle. One LogUp relation joins all before/after events to public
initial cells at clock zero and public final cells at bounded final clocks.
Unique current ticks plus strict predecessor order prevent unanchored cycles,
forks and invented initial cells. Final clocks are transcript bound before
relation challenges. Permissions cannot change across an authenticated chain.

Interaction denominators are drawn after the main commitment. Every inverse,
disabled inverse, prefix recurrence, row-zero correction and terminal closure
is constrained. The closure target is derived from expected public boundaries,
not accepted as a free prover claim. Fixed roots are independently reconstructed
and compared before sampled-point verification.

## Arithmetic and failure policy

Bytes have explicit Boolean decompositions. Carry chains implement modular
64-bit and W arithmetic; signed extension and zero-divisor/overflow behaviour
must be explicit. Integer multiplication uses bounded byte-wise carries for a
128-bit product. Division proves quotient/product/remainder and strict remainder
bounds, with explicit zero-divisor and signed-normalization cases. Shifts use
bounded barrel stages. Unsupported instructions fail at profile admission;
they never fall back to an execution check or an unconstrained hint.

The first resource envelope is at most 256 retirements, 4,096 program words,
and 128 explicitly authenticated memory words. This deliberately does not claim
full CSP or OP block proofs. Memory-root compression, continuation, recursion,
SP1 syscalls, architecture conformance and large-trace qualification remain
separate work. The execution profile keeps its existing capability flags.

## Ownership, cost and tests

Statement slices are borrowed during a request. Witness and column owners free
all allocations on failure; the verifier never receives a witness pointer.
Fallible preparation precedes trace publication. Main data is committed before
challenge-dependent interaction columns. The shared polynomial evaluator uses bounded reusable scratch on the prover
domain. Verifier OODS constraints stream directly into the core accumulator,
without a constraint-vector allocation or a hidden page allocator. Execution and wide hint
rows are constructed once; the normal prover releases these rows after projecting
them into physical columns. PCS preparation owns its copies, allowing the source
fixed/main/interaction buffers to be released before quotient construction.
`provePrepared` borrows caller-owned rows instead. Initial use is CPU only.

The logical reference contains 2,371 main, 229 fixed and 36 interaction columns.
Protocol version 2 does not commit that layout indiscriminately. The verifier
independently derives a concrete linear projection from its program and bounded
PC path: always-disabled words/carries/product/shift/clock auxiliaries become
zero; word bytes and bounded scalar values become linear combinations of their
committed bits; fixed columns are constant-folded and exactly deduplicated.
Domain and OODS evaluation inflate the same logical view and invoke the same
constraint authority. Projection never consults witness values. This is a
restriction to a canonical witness representation, not a probabilistic search
for redundant constraints. No randomized dependency inference is used.

For the five-instruction arithmetic/store/load fixture, physical trees have
21 fixed + 643 main + 36 interaction columns at 32 rows: 22,400 committed trace
cells instead of 84,352. The composition tree additionally has 16 columns at
32 rows in both layouts. Opening masks request 704 trace samples (four extra
previous-prefix samples) and 16 composition samples instead of 2,640 + 16.
The full binary proof shrank from 512,424 to 127,224 bytes at unchanged q=70,
PoW=26 and FRI settings. These are fixture-specific representation results,
not CSP, precompile, recursion or block proving speedups. Proof-work accounting
must continue to include interaction/provider tables, padding, composition,
openings, commitment buffers and immutable setup as those components are added.

Qualification requires complete native proofs and independent verifier replay,
plus substituted program/initial/final state, permission and upper-address-bit
rejections. Local mutation tests cover range bits, carries, source-read custody,
aliased registers, subword neighbours, predecessor clocks and cyclic-prefix
closure. State forgeries that preserve local arithmetic must still fail global
relation closure. Proof-byte corruption and fresh decode/verification are tested
separately from witness rejection. No opcode is called proof-qualified solely
because the execution frontend supports it.


## Architecture gates for the next stages

Register consistency is local to this bounded proof; register events do not
become a separately sorted global RAM table. The register and RAM namespaces
are distinct in the state relation. All current obligations close inside one
STARK against independently expected initial/final state. There are no deferred
provider claims, companion proofs or recursion wrappers in this profile.

Continuation must explicitly connect memory commitments, CPU state, snapshots,
initial input and terminal output. Persisted physical relation claims must enter
the transcript and every provider must close. Releasing a witness must retain
sufficient authenticated relation metadata to discharge those obligations;
individually valid leaves cannot establish global consistency by themselves.

Execution, RAM and crypto providers will need independently sized domains and
whole-job cost comparisons. Do not enlarge all components to one height to avoid
implementing domain geometry. Do not add a separate proof for each component
when compatible families can share a commitment/composition/FRI transaction.
Recursion needs specialized verifier operations and explicit coverage/adjacency
checks, not a larger fan-in around an unchanged expensive child verifier.
Immutable provider setup should be derived once per identity; request and witness
bindings must remain fresh, and the final receiver must derive authority itself.

These are design requirements, not measurements. Word16, circuit-wrapper,
admission-cache and complete retained-block results from the separate RV32
worktree are not imported or claimed as qualified RV64 improvements.


## Second-pass audit

The [2026-10-30 audit evidence](../../vectors/reports/rv64-air-audit-20261030/README.md)
records a real execution-tool dependency regression found by rerunning the
independent oracle. `riscv.rv64` now exports only standalone execution;
`riscv.rv64_air` is a separate full-frontend entry point. The execution gate
compiles diagnostic, CSP execution and benchmark tools without injected proof
modules, alongside their tests. Focused roots select ordinary tests under the
appropriate `tests/` directories.

The native verifier rejects inconsistent tree counts, column counts, opening
masks and empty/oversized query columns before cryptographic processing. Core
PCS still authenticates query positions, values and decommitments; the shape
check does not replace any protocol check.

Additional evidence covers 1,792 deterministic random arithmetic cases,
projection round-trips including padding, streaming/buffered accumulation
parity, failed interaction publication, malformed metadata, complete 128/256-step
proofs with 4,096 program words and 128 memory cells, final RAM clock 1024,
top-of-address-space execution and discarded loads into x0. This expands
bounded qualification; it does not establish formal AIR soundness, pinned Rust
acceptance of this RV64 component, or RV64 Sail conformance. The existing Native
Rust interoperability tool supports other example components, not this RV64 AIR.
Those independent authorities remain release gates, not satisfied by Zig-to-Zig
proof verification or Unicorn execution agreement.

## Full single-shot execution profile

The separate `rv64_full` integration now constructs one STARK for one complete
execution journal. It retains the legacy bounded `rv64` version-2/version-3
interfaces and their fixture formats. The full profile has its own transcript;
its geometry admits fewer than `2^22` retirements and 24-bit access clocks. This
is an implementation envelope, not evidence that every workload at that bound
has completed proving or independent qualification.

Execution is captured once into narrow retirement records. The capture does not
execute or prove individual windows. An independently initialized ELF/input
image supplies the full immutable executable map and initial RAM bytes; final
touched RAM values, clocks and CPU state become the request boundary. For the
CSP driver, the terminal halt flag, output length and all output bytes must be
authenticated against the manifest result. Before fresh-process verification,
the driver independently checks the serialized expected statement against the
pinned ELF/input initialization and expected terminal bytes. A producer JSON
success flag or a capture journal cannot establish that authority.

The program ROM owns exact sorted u64 PCs and decode rows without an execution
path, final PC, request state or step count. Its identity is program-only. The
combined preprocessing root also contains CPU domain geometry and the selected
provider tables. The retained setup additionally admits one opcode policy,
which is bound in each request transcript and checked on setup reuse. Reusing
that setup requires the program, geometry and policy to match. Neither identity permits accepting producer-supplied
preprocessing. Each request starts a fresh transcript and fresh multiplicities,
interaction columns and claims.

CPU preprocessing contains only index/first/last geometry. Committed advice
contains an exact active prefix, PC/next-PC chain, Boolean opcode selectors and
a 41-field ROM tuple: validity, PC bytes, opcode ID, effective register indices,
immediate bytes, access enables, and full-width increment/target bytes. The ROM
lookup authenticates those fields. One-hot selector constraints link the opcode
ID to arithmetic dispatch; forbidden public-policy selectors must be zero.
Word and carry enables derive linearly from the selectors and authenticated
access enables, using the existing operation classification authority. They do
not add committed CPU columns. The active-prefix and PC equations bind exactly
the expected retirement count, initial PC and terminal PC, including padding.

One state relation still closes register and RAM chains against independently
expected initial/final boundaries. Each predecessor clock and gap has three
range-checked bytes. Their sum plus one is below `2^25 < M31`, so equality to
the current tick proves strict integer order without modular wrap. Architectural
addresses and values continue to use eight canonical bytes. RAM reads overlapping
ROM must agree with the immutable instruction bytes and cannot gain write
permission.

The ROM, byte-256, AND-65536 and shift-2048 providers use their own domain sizes
inside the same main/interaction commitments, composition polynomial and FRI
transaction. All multiplicities enter the main commitment before shared lookup
challenges. The state claim is receiver-derived; every lookup consumer claim is
paired with its provider's negative claim. All typed claims enter the transcript
before the interaction root. There are no deferred claims, companion component
proofs or wrappers around many small execution proofs.

Quotient evaluation does not retain a 4n evaluation for every CPU column. Four
n-point conjugate cosets cover the canonical quotient domain in contiguous
bit-reversed slices. A preceding trace row crosses to the paired coset; it is
not generally in the same n-point coset. Reusable scratch stores n values per
current column and n extra values only for columns that request a predecessor.
The core index function supplies the exact predecessor position, and each part
retains its original global output position and vanishing denominator. Tests
compare arbitrary polynomial evaluations, direct point evaluations, predecessor
points and quartic quotient residuals against the complete 4n domain. This
reduces that scratch term from `4n * columns` to
`n * (columns + predecessor_columns)`; it does not remove coefficient storage,
commitment trees, composition output, FRI storage or opening work.

Full CSP qualification on 2026-10-30 passes all 17 cases, including valid and
invalid-signature software ECDSA, with one proof per complete halt/output
contract. Every case passes a fresh process receiver after an independent
ELF/input/initial-state/permission/halt/output check. Serial and 18-worker runs
produce identical statement, claim and proof bytes for all 17 cases. Production
security remains 70 FRI queries and 26 proof-of-work bits.

On the local 64 GiB, 18-core Mac, valid ECDSA retires 1,625,938 instructions in
2^21 rows with 519 main and 260 interaction columns. Measured proving is
340.46 seconds serial and 70.52 seconds parallel; the latter process takes
80.38 seconds including witness and setup work. Peak caller allocation is
12.79 GiB, excluding process-wide worker stacks and OS memory. Its proof is
669,304 bytes. Fresh receiver preprocessing takes 139.3 ms and verification
8.88 ms. These are single local runs, not throughput distributions or an OP
block benchmark. All rows and provenance are in
[the comparison report](../../vectors/reports/rv64-qualification-20261030/csp-full-comparison.json)
and [CSV](../../vectors/reports/rv64-qualification-20261030/csp-full-comparison.csv).
Compact proofs, statements and the measured binaries are retained under the
ignored local `vectors/reports/interop_artifacts/rv64-full-20261030` directory;
wide execution/quotient buffers are released rather than stored on disk.

The full profile is experimental. The existing independent Rust adapter
remains limited to its versioned dense five-instruction fixture; it does not
qualify this new profile. Sail qualifies the separately tested ISA executor,
not these AIR constraints. A real OP guest ABI and execution beyond this
profile's bounded 24-bit clock capacity remain separate integration work.


## Whole-prover profiling follow-up

The full proof representation and security configuration are unchanged, but
profiling removed repeated wide-row reconstruction and serial pipeline work.
All 17 cases retain identical statement, claim and proof bytes. Full ECDSA
wall time fell from 80.38 s to 20.62 s in the matched full-suite runs; repeated
optimized runs were 21.07–21.24 s, with a fresh baseline rerun of 76.25 s.
Peak caller allocation remains approximately 12.78 GiB. The earlier measurements
above are retained as the chronological qualification baseline.

Trace construction now validates native chains once, builds physical rows in
bounded parallel bands, and keeps only narrow state/range/table metadata through
interaction closure. Immutable geometry belongs to PreparedSetup. Main witness
storage retires immediately after commitment. Parallel interaction workers fill
independent inverse/contribution rows; a joined logical prefix scan establishes
the original claims before metadata is released. CPU quotient FFTs reuse the
same bounded pool, and one shared polynomial authority supports prepared BYTE
terms, weighted accumulation and reusable logical inflation.

The [performance study](../../vectors/reports/rv64-performance-20261030/README.md)
contains the complete before/after table, phase profiles, repeat measurements,
rejected experiments, memory accounting and remaining bottlenecks. In particular,
constraint-row arithmetic still accounts for about 10 seconds of full ECDSA;
this is not a claim that the 519-main/260-interaction representation is optimal.

The [second profiling round](../../vectors/reports/rv64-performance-round2-20261030/README.md)
shares memory expectation polynomials and transfers the main matrix directly
to the existing PCS arena owner. All 17 exact-proof parity gates pass; valid
ECDSA measures 19.59 seconds end to end in that suite. Whole-job caller peak
remains 12.78 GiB. Forbidden selector coordinates remain arbitrary at OODS;
they cannot justify dropping dependent constraints merely because separate
constraints force those selectors to zero on execution rows.
