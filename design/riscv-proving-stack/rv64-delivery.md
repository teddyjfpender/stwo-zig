# RV64 circuits and lean execution delivery

Active objective: deliver the complete architecture requested in the attachment,
not merely software execution, a cost model, or independently valid primitives.
Attachment SHA-256 is recorded in the receipt. This ledger is a work tracker;
completion requires inspection of the actual code, proofs and measured receivers.

| Required outcome | Current evidence | Remaining acceptance |
| --- | --- | --- |
| Constrained Keccak service | CPU+ROM+DIV/MUL+permutation+25-lane bridge+shared lookups prove in one PCS; inverse/cyclic states and empty roster freshly verify | Complete51-batch block chain and terminal certificate freshly verified; continue measured cost and security qualification |
| Constrained secp256k1 service | Projective ADD/DOUBLE arithmetic and RAM bridges prove with fresh receivers; strict BE/v1 and word/v2 runtime ABIs reproduce block output; word ABI lowers execution to213,659,488 instructions | Full-block typed call coverage verified; complete protocol-security and cost qualification remains |
| Lean CPU and independent expensive arithmetic | CPU+ROM+BYTE/AND/SHIFT+DIV/MUL proof and fresh receivers pass; immutable opcode policy, count-independent fixed keys and cyclic state qualified | Whole-system measured cost win with authenticated RAM and secp |
| Large batches with authenticated RAM/CPU state | Private value-only RAM transition proves roots, cells, policy and hash graph; open CPU debt explicit; owned source release before interactions qualified | Complete retained block accepted; next optimize measured prover and receiver without weakening coverage |
| Witness construction once; immutable setup reuse | 48B tape projects directly into CPU witness; cached decoded ROM avoids batch decoding; rootless materials remove redundant fixed hashing; RAM ragged arena adopted before interactions; bounded first/last capture matches real-block census | Combined ownership transfer and all debts qualified; measured worst-batch peak remains composition-dominated |
| Shared providers and scalable aggregation | One PCS for existing CSP and new standalone permutation+tables | OnePCS perbatch for77,763 services; specialized aggregate with explicit coverage/adjacency remains |
| Complete verified Ethereum milestone | Software RV64IM and Unicorn agree on block24,628,607 | Native proofchain achieved; isolated current-architecture full-job benchmark and specialized aggregation remain |

No row in this ledger can be considered achieved from a host calculation or a
producer-provided receipt alone. Component hash/circuit proofs do not establish
CPU/RAM-call closure, and a small aggregate file does not establish cheap
verification. All performance comparisons include total committed cells,
interactions, degree/domain costs, masks, padding, providers, simultaneous memory,
checkpoint bytes, immutable setup and independent receiver work.

New runtime services are explicit program/ABI profiles. Ordinary RV64IM ECALL
continues to trap. A service output is only witness generation until constrained
caller/control/register/RAM relations close against the arithmetic provider.
Retain the pinned software-only real-block receipt as the comparison control.

## Sustained iteration window

The user requested nine further hours of continuing architectural work, starting
2026-10-30 19:28:48 UTC and extending at least through 2026-10-31 04:28:48 UTC.
The goal remains active across turns. Passing a primitive or reaching the time
boundary does not establish full delivery. Recheck this ledger and the original
attachment when resuming after compaction.

Before promoting each architectural change, reject repeated wide construction,
rare-op CPU width, coupled heights, unclosed claims/state, repeated immutable
setup, or proof-per-call wrapping. Record total cells, interactions, degree/domain
cost, masks, padding, provider costs, peak lifetimes, complete proving and fresh
receiver/checkpoint cost. Keep unqualified designs inactive and name the exact
remaining closure. Preserve the pinned real-block software control and verify
new guest outputs against it after every runtime lowering.

## Current qualification checkpoint

All17 default CSP proofs and fresh receivers pass again. Statement, claims and
proof bytes exactly match the previous optimized baseline; concurrent activity
makes this a functional regression, not a timing comparison. Receipts are in
`vectors/reports/rv64-delivery-20261030/default-artifact-parity.json`.

The isolated cyclic state relation groups the eight signed events3/3/2, replacing
36 interaction columns with12 and opening only the final four at the previous
row. Its AFTER timestamp is deliberately unmasked, keeping all denominators
linear and the residual degree at most four. Alias/padding and full-width RAM
cases match independently calculated original boundary claims; coordinate,
predecessor and claim mutations reject, and dense arbitrary QM31 finite
differences confirm the degree bound. Explicit cyclic-v2 CPU/service production proofs and fresh receivers now pass.
Whole-system total-cost qualification remains pending.

Compact capture restores records from immutable decoded ROM without execution
replay. It owns48B per instruction, sparse8B RAM-before advice and separate
432B service calls. It retains bounded batch storage and rebases proof clocks
without truncating global clocks. The real block has been captured in adjacent
bounded batches with the same output/instruction/call totals. Diagnostic capture
does not establish authenticated continuation; advice may be released during
proving only once the corresponding CPU, RAM and provider obligations are bound.

Exact access census and independent-height source models are recorded separately
from measurements. A2^22-step diagnostic interval is not an admissible proving
batch: the last RAM timestamp4*steps must remain strictly below2^24. Fixed keys
derive from immutable program/profile and component geometry, never observed
per-batch opcodes or request counts. The complete CPU width report must use the
entire expected executable ROM, including unexecuted instructions.

## Latest real-block lowering and native boundary capture

The explicitly versioned word-based projective service guest executes the same
block/output in213,659,488 instructions (74.43% below835,695,366 software control,
16.33% below the255,354,148-instruction BE packet control). It makes32,835 Keccak,
24,960 projective ADD and19,968 DOUBLE calls. These are native execution counts,
not a full-block proof or proving-time forecast. The exact ELF/input/output and
source receipts are in `word-services-execution.json` under the delivery reports.

At2^20 steps per batch, compact capture plus first/last RAM capture and the access
census complete204 batches with98,451,456B process RSS in one instrumented run.
The boundary map records3,877,338 touched cells summed across batches, with a
peak201,293 cells. Both match the independently collected access census exactly.
This capture remains diagnostic until authenticated chunk openings are built
before advancing the image and all same-transcript state obligations close.

The authenticated-execution coordinator now derives one combined fixed root
from rootless CPU/crypto and RAM materials, seals all main columns before shared
challenges, reuses one global BYTE provider and checks RAM state debt against the
expected register boundary. Joined CPU, Keccak, secp ADD/DOUBLE, DIV/MUL and private
RAM proofs pass with fresh receivers for both service ABIs. Serialized-chain
qualification additionally rejects forged coverage, roots, PC/registers, service
IDs, input identity and terminal certificates. The immutable ELF/input establish
initial authority independently of producer metadata.

The complete retained block now passes an independent fresh-process receiver:
51 serialized execution proofs plus the terminal output certificate cover all
213,659,488 instructions,32,835 Keccak,24,960 ADD and19,968 DOUBLE calls for
block24,628,607. Proof bytes total151,966,908. The receiver independently loads
the pinned ELF/SSZ, derives immutable setup and initial RAM, checks every physical
proof and state/counter adjacency, and verifies the exact43B output at terminalPC.
The successful receiver used21.41s wall and3,745,169,408B peak RSS; measured setup
and verification times remain separate in the receipt.

The initial attempt rejected batch47. A final incomplete29-row Keccak group had
an output selector whose +1/+2 references wrapped into the first active group at
logs14/15. The corrected domain-only selector applies only to complete groups;
phase0 remains to enforce the active-prefix transition. Regression gates cover
all admitted logs and prove/freshly verify nonzero inputs at both affected sizes.
Every previously accepted batch used unaffected geometry. Resume first verified
all47 durable proofs, replayed execution and matched RAM/PC/registers/counters to
that receiver-owned boundary before proving the remaining four batches.

The successful-chain proving stages sum2441.774s; this qualification combines
47 earlier batches and4 resumed batches, different storage/optimization versions,
and concurrent engineering. It is not an isolated one-invocation benchmark.
The rejected attempt consumed2447.67s and the successful resume263.00s. An isolated
matched benchmark is next. Full receipts and security-accounting limitations are
in `vectors/reports/rv64-delivery-20261030/complete-block-qualification.json`.
This is a native proof chain, not a recursive aggregate or OP derivation proof.

## Shared main ownership qualification in progress

The next architectural change plans all component geometry before constructing
wide witnesses. CPU, arithmetic, Keccak, secp and private RAM write directly into
one canonical allocation. Narrow multiplicity vectors are copied once at seal;
wide copies are rejected. Borrowed aliases are retired before allocation
ownership transfers to PCS, including error paths. RAM roots remain request data
and never determine immutable setup authority.

Component-level owned/borrowed witness, interaction, allocation-failure and proof
parity gates pass. Combined27-component proof parity and actual Ethereum driver
qualification have passed, including identical real65k-prefix proof bytes and a separate receiver. Matched worst-batch ownership measurements are recorded below. The driver exposes `shared_main_arena` for an
explicit owned control. Do not claim a holistic memory or speed improvement
until matched real-prefix measurements and a fresh serialized receiver pass.

## Current cost-directed iteration

A matched retained-batch26 test (4,194,303 steps and9,845 Keccak calls) proves
byte-identically through both owned and shared-main paths. Prove times were
190.365/189.492s and RSS42.478/42.482GB in one sequential pair. The copy removal
has no material peak-memory or whole-batch win here: the later composition
representation dominates. Do not infer a speedup from ownership alone.

Instrumentation identified another architectural issue: the legacy scheduler
only gives its highest-domain component row parallelism, so the smaller but very
wide Keccak permutation ran serially after CPU work completed. Existing bounded
pool-exclusive component phases are being qualified for CPU and permutation,
leaving ordinary leaves concurrent with the first phase and draining them before
later row-parallel phases. This changes scheduling, not constraints/transcript.

The explicit `limbs24_v2` control representation is also under qualification.
Three separate24/24/16-bit limbs retain full64-bit PC/increment/target/nextPC:
CPUcontrol121→101 columns forEthereum, ROMtuple41→26 and previousnextPC samples
8→3. The actual52-op CPU residual count falls1006→946 at unchanged degree4.
CanonicalROM membership and existing BYTE-authenticated operands bound limbs;
unmasked padding adjacency connects the finalactivePC to the receiver endpoint.
All27-component proofs pass bothABIs×bothcontrolpolicies×owned/shared sources,
with fresh receivers and downgrade rejection. A real65,536-step packed Ethereum
prefix also proves and freshly verifies. Legacy5 proof SHAs and148fresh receiver
attack cases remain exact/pass. Complete packed-block and CSP benchmarks remain
pending; no whole-job speed/peak claim follows from the model alone.

## Exclusive provider scheduling measured

The retained batch26 control uses4,194,303 steps,9,845 Keccak calls,16 workers,
byte control, shared main arena and the same tiled Keccak implementation.
Marking CPU and permutation as pool-exclusive reduced proving from167.287s
to62.318s (62.75%) and maximum RSS42.482GB to37.049GB (12.79%) in one
sequential matched pair. The proof SHA and2,938,992-byte wire artifact remain
identical; an independent complete-chain receiver precedes each reprove.
Composition fell140.979s→35.423s; summed Keccak row intervals129.396s→11.272s.
Stage children can overlap and must not be summed as whole-job time. The
96.06s candidate process also includes20.862s independent baseline verification
and3.010s native prefix replay;62.318s is its proving stage.
Receipt: `pool-exclusive-retained26-v1.json`. Whole-block performance is pending.

Packed control is now also supported by the concrete standalone Full/CSP path.
A dynamic-width handoff bug failed closed during qualification and was fixed;
Safe proof tests pass, high64-bit wrapped AUIPC/JALR proofs freshly verify,
and a real packed keccak128 proof requires the independently supplied packed
receiver policy. Default byte statement/claims/proof remain byte-identical.
Borrowed CPU/RAM constructors additionally reject aliases into immutable
program/statement inputs and unused journal capacity before allocation/write.
All27 authenticated components still pass bothABIs×bothcontrols×owned/borrowed.

## Profiling concurrency qualification correction

A checked consecutive real-block run found that the expensive CPU/Keccak/secp
components shared one serial hierarchical StageRecorder across worker threads.
Recorder stack/child ArrayLists are not thread-safe: concurrent StageScope.end
asserted against incompatible LIFO stacks. This is a confirmed telemetry race
and can explain intermittent allocation failure/list corruption.

The packed full run accepted5batches then stopped with OutOfMemory. Batch5
subsequently accepted with the exact same frozen binary at4workers and16workers,
producing identical proof bytes. Its isolated16worker retry used36.001s proving
and25.488GB RSS; this does not reproduce the original multi-batch failure.
Accepted proofs are preserved; there is no complete packed-block benchmark yet.

Private bounded recorders now bind one stable owner to each concurrent
component. The engine drains workers before the coordinator adopts stage trees,
and component pointers clear before recorder retirement. Adoption OOM preserves
proof ownership and the original proving error. Generic stage-only adoption
passed checked concurrent/ownership/allocator-failure tests. Whole-proof
recorded/unrecorded parity and consecutive real-block qualification are pending.

Earlier parallel per-family timing hierarchy is invalid. Preserve the old
process observations and accepted proof hashes, but repeat performance with
profiling disabled or these private recorders before claiming final speedups.
CSP Full has only one instrumented CPU component and is outside that shared
component-recorder race. Both byte and packed17-case CSP runs freshly verify;
ECDSA proving observed18.545→18.071s and18.450→17.991s in one pair. Small-case
results are mixed, so packed encoding has no universal speed claim.

## Further opt-in representation work

The explicit cyclic_canonical_v3 state profile removes24 redundant BYTE
queries (B, previous_rd, memory_after) from the measured70-query Ethereum CPU
plan, retaining all284 physical data fields and every disabled/write/clock
anchor. BYTE inverse batches drop24→16 and interaction fields by32. The proof
obligation is strict clock induction over globally closed unit state flow from
authenticated initial sources; K/secp bridges retain strict predecessor gaps
and independently canonical output anchors. Ghost-cycle, field-wrap, disabled
value, write-anchor and dense-Q degree4 tests pass. Complete joined proof and
trusted receiver policy tests remain necessary before promotion. See
`rv64-state-range-review.md` and its exact immutable-opmask model.

## Immediate user priority: base-field SIMD

The user explicitly prioritised sixteen-row base-field SIMD, followed by row
width/family separation, batch fan-out+specialized aggregation, one recovery
provider, Keccak interaction cost, corrected contention measurements, Metal,
and a wider clock tuple. This supersedes doing more incidental micro-optimizations
before the lane architecture. Arithmetic lane generics are explicitly requested;
there is still one constraint authority and no machine/type factory.

The first CPU implementation uses16logical rows over native packed M31/QM31
blocks. Main/fixed/local arithmetic remain base-field vectors. Secure relations
retain packed QM31 because Fiat-Shamir coefficients/prefixes are extension
valued. Random powers multiply base residuals directly with packed-secure×base
operations. Each worker owns bounded heap scratch; contiguous domain columns
load directly, required predecessor masks gather narrowly, and four output
coordinate columns receive packed additive stores. ScalarQM31 remains the OODS
authority and an explicit domain qualification oracle. All4cosets, uneven
partitions, partial16 tails, repeated additive waves, failure drains and worker
1/3/8/16 domain parity pass checked tests. Whole joined proofs and matched
real-prefix/CSP benchmarks are next; no SIMD speed claim is established yet.

## Isolated SIMD whole-block measurement

The frozen CPU/Keccak/secp SIMD implementation now completes one uninterrupted
51-batch invocation for all213,659,488 instructions. Producer wall time is
1,225.28s (20m25s), peak RSS36,683,923,456B, and serialized proofs total
150,876,796B including terminal. A separate cold receiver accepts the complete
chain in13.59s with3,461,775,360B peak RSS:12.107s independent setup and0.872s
physical verification. It reports15cache hits and36misses,8retained keys and
391,296B peak narrow-key cache payload. Setup tree reconstruction and temporary
verifier buffers still dominate receiver memory; this is not a small-memory
recursive verifier.

Batch prover calls sum1,068.135s. Composition intervals sum379.641s, authenticated
interaction155.906s, FRI quotient construction/commit119.013s and trace openings
98.320s. CPU FFT intervals195.317s and CPU constraint intervals143.598s sit
inside composition and overlap other components. Do not add these categories
together. Main witness construction98.837s and RAM witness28.815s remain
separate from prover calls. Physical source cells summed across sequential
batches are88,235,897,216main and36,169,680,448interaction, plus
2,376,147,808fixed. They are not simultaneous expanded-buffer memory.

The exact binary/source identities, everybatch proof hash, geometry, source
cells, timers and fresh receiver are retained in
`vectors/reports/rv64-delivery-20261030/complete-block-isolated-simd-v1.json`.
This run excludes the later Keccak RAM-bridge and RAM Poseidon SIMD prototypes.
The prior resumed/concurrent fullchain is not a matched speedup baseline.
Matched scalar/SIMD retained-batch measurements remain the causal comparison.

The compact advice codec now passes64execution tests in bothReleaseSafe and
ReleaseFast, including3focused wire tests and every allocation failure. The
versioned little-endian format serializes initialized used records directly,
admits counts/byte budgets before allocation and rejects malformed/trailing
records. It is untrusted witness advice, not execution or program authority.
Full packet metadata/frontier transport and process fanout remain unfinished.

## Full SIMD coverage and architecture experiments

The next uninterrupted completeblock run also passes a fresh receiver and
reproduces every51proof, receipt and terminal artifact byte-for-byte. It includes
Keccak RAMbridge and RAM Poseidon SIMD, with1MiB actualEthereumworker stacks.
Walltime1234.76s/36,591,828,992B peakRSS and freshreceiver13.66s/3,472,146,432B
show no material whole-job gain over1225.28s. Kbridgebatch26 rowevaluation falls
2.864910s→0.563176s, but composition11.776734s→11.754977s is unchanged because
leaf work overlaps itscriticalpath. Evidence:complete-block-isolated-handoff-simd-v1.json.

The native reference-tuple gather experiment was removed after the active-path
audit: production already uses prepared lookup generation. Its17CSPproofs
reproduce all artifacts but show no material speedup. Retain the report as an
abandoned experiment, not an optimization. The source table_cpu.zig is restored
exactly to its qualified priorhash. Avoid adding duplicate representation layers.

An explicitly experimentalquartet Keccak component now proves degree-five
constraints over the existing4n quotient domain, with q70/P26freshreceiver and
legacytriple artifact parity. Nativeinteractions2596→1948 and standaloneproof
1621800→1418680B (12.524%less). It is not yet enabled by the joinedEthereum
coordinator. Separate its concrete nativekernel from thedefaulttripleroute so
unselected experiments do not duplicate productioncode/kernels.

The inactiveglobalRAM model/collector (19Safe/Fasttests) and typedfixedchip
planner (6Safe/Fasttests) now make transcript, exactcoverage, namespace, boundary,
clock, count, ownership and allocation obligations executable. They do not
establish globalRAM AIR, an aggregate receiver, recursive aggregation or OP
derivation. Source-costreview rejects naïve duplicatedprecommit data: currentRAM
main+inter totals15.777GB cumulative;18memory+2epochfields at everyCPUrow cost
17.113GB beforeboundary/service/initial-ROM/opening costs. Move memory columns
into independently sized load/store tables and reuse their first commitment.

The minimum nine-hour work interval completed2026-10-31 04:28:48UTC. Fullobjective
remains active; the remaining physical architecture gates are not waived.
