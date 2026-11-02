# Ethereum mixed-service global-memory driver

`rv64-word16-ethereum` imports existing retained native packets into the full
Word16 CPU, optional Keccak/ADD/DOUBLE bridges, and independently sized truth
providers. Packet hashes, native execution and old RAM roots are advice only.
One chronological RAM ledger supplies one INIT and one TEARDOWN for the execution.
All physical fixed/MAIN commitments precede the shared-challenge manifest barrier.

Commands (independently pinned request JSON, producer job directory):

```
rv64-word16-ethereum plan CONFIG JOBS unused 0
rv64-word16-ethereum produce CONFIG JOBS NEW_OUTPUT 0
rv64-word16-ethereum verify CONFIG OUTPUT
rv64-word16-ethereum produce CONFIG JOBS NEW_PREFIX_OUTPUT 4
rv64-word16-ethereum verify-prefix CONFIG PREFIX_OUTPUT
```

Count zero requires reaching the trusted terminal PC. A positive count produces
an explicitly partial execution. Receivers consume no work packets or tape and
perform no native replay. Before constructing keys they check the configured
batch schedule, genesis, epoch/CPU adjacency, step budget and completed endpoint.
Geometry selects bounded physical shape; all keys derive from the pristine
pinned ELF/input authority. Setup caches depend on image, geometry and service
kind, while each statement, count, call span and transcript remains separate.

Completed acceptance verifies every CPU and truth STARK, actual committed roots,
all local debts and global RAM/KIO/Wire closure. It then requires the independently
pinned absorbing terminal PC, halt=1, length=43, and expected output read from the
authenticated terminal RAM list. A missing terminal word cannot fall back to a
native memory image. Prefix acceptance returns no completed-block/output claim.

Producer retention is bounded: 128 GiB of temporary unlinked file-backed native
MAIN coefficients, owned by their PCS trees and released on success or error.
CPU and truth MAIN/INTER witnesses move into owned streaming commits; narrow
sources retire once their final proof and receiver obligations are encoded.
Packet import releases each compact tape after adding its records to the
chronological ledger. Capture records and consumed RAM-event lists retire at
their explicit ownership barriers. These changes preserve the proof statement.

`cost.json` reports exact native column cells, active family counts, distinct
setup identities and a base lifted-leaf exposure. The latter is not a compression
count: the current BLAKE2 committer incrementally absorbs native-height groups.
With stage profiling enabled, `physical-NNNN.stages.json` is written after each
proof and separates source, MAIN, mapped retention, interactions, composition,
FRI and decommit. Process counters span all threads and overlapping intervals
are not additive. Peak RSS is a process-lifetime high-water mark at interval end.

The schema3 qualification receipt is
`vectors/reports/rv64-word16-execution-20261031/ethereum-global-driver-prefix-v1.json`.
Four real packets (16,777,212 instructions, 336 Keccak, 817 ADD, 680 DOUBLE)
produce four CPU and three truth proofs with a separate fresh receiver. Mapped
retention plus profiling preserves all seven proofs, manifest and RAM sidecar
byte for byte against resident storage. Complete-mode rejects an early prefix.
Safe/Fast receiver tests also prove programs with false halt, length or output;
these valid prefixes fail completed acceptance. All 25 packets of block24,628,607
have passed advice import and chronological collection, not yet whole-block
proving in this receipt. Concurrent observations establish no speedup or p50.

## Complete block qualification, schema4

`ethereum-full-global-s4-v1.json` records block24,628,607 through all25 CPU and
five independently sized truth STARKs:104,253,913 instructions,32,835 Keccak,
11,496 ADD and9,768 DOUBLE calls,1,347,207 RAM words. The producer and a separate
fresh receiver both require complete global closure and the pinned terminal43B
output. The receiver uses no packet directory, tape or native replay.

This functional run observed313.61s wall/38.67GB peak RSS. The fresh receiver
observed11.78s wall/15.00GB peak RSS, with11.15s loading/setup and0.552s native
verification. These concurrent engineering observations are not controlled
speedups. Native commitments contain24.14G cells(231.53/retirement); physical
proofs total36,647,820B, separately from the RAM sidecar. All45.61GB temporary
MAIN mappings were released. This is a native bundle, not a recursive root.

Root-stage accounting explains289.25s of the290.74s proving interval. Composition
is61.80s; MAIN/INTER commitments68.68s; interaction generation38.51s; FRI40.32s;
source construction34.33s; trace decommit17.98s; mapped writeback11.84s. CPU and
truth portions are separately recorded. Fixed geometry still produces25 distinct
CPU setup identities; eliminating redundant setup and its memory remains work.

`riscv64_word16_profile_report.py DIRECTORY --output NEW_JSON` reproduces root
stage/cell accounting. It rejects incomplete profile sets and never verifies a
proof. Peak values are lifetime process high-water marks, not independently
measured batch peaks. Neither the overall3–5x time target nor the1.5–2x whole-
block memory target is claimed complete by this qualification.

## LS48 complete-block qualification

`ethereum-full-ls48-v1.json` records another complete 25+5 proof bundle and a
separate fresh completed receiver. The canonical-range induction removes
1,766,326,272 interaction cells, taking the block from 24,137,490,240 to
22,371,163,968 native cells. Physical proofs total 35,968,076 bytes, with the
61,971,538-byte public RAM sidecar accounted separately. MAIN retention is
unchanged: interaction reductions do not shrink the stage-one MAIN barrier.

The observed serial run took 294.74s wall; peak RSS was 42.46GB. These numbers
are concurrent engineering observations, not a controlled speed or memory win.
In particular, the higher lifetime RSS prevents claiming a memory improvement.

## Bounded coordinator and ownership policy

The canonical services coordinator has one tagged CPU/truth worker lifecycle:
construct source, seal fixed/MAIN, join the complete manifest, derive its shared
challenges, generate owned INTER, prove, then retain the narrow closure data.
Each phase runs indexed workers independently. Every phase joins all started
threads before success, failure cleanup, or publication. A failed worker cannot
publish a partial manifest or partially initialized proof bundle. Legacy routes
remain compatibility controls; they are not additional production pipelines.

The CLI defaults to two proof lanes, splitting the configured helper budget
between two stable pools. `--proof-jobs=1` preserves serial scheduling;
`--proof-jobs=2` requests the bounded concurrent schedule. A complete stage-one
barrier is mandatory: stage two cannot overlap an unfinished stage-one shard
under the same execution manifest. No worker accepts a caller-selected RAM
challenge. Independent lanes require a thread-safe allocator and disjoint
sources, recorders and result slots.

`--commit-batch-columns=N` controls a requested width (default 64), subject to
the backend's byte budget. It does not promise 64 simultaneous log-22 columns.
CPU fixed evaluation matrices retire after their immutable key is sealed;
native coefficients, commitments and authority metadata remain owned by the
key. `--keep-fixed-witness` retains them as a qualification control. The capture
cache is trimmed before key construction; `--keep-capture-cache` disables that
trim without changing proof bytes. These flags select operational ownership,
never verifier authority or public statements.

Profile schema 2 labels summed stage intervals as worker elapsed time. In a
concurrent run they are not wall time. Whole-process user/system counters are
preserved per interval but are not summed across overlapping proofs. The
top-level producer timer remains the block elapsed measurement.

`ethereum-concurrent-workers-v1.json` qualifies these operational policies on
all104,253,913 instructions. Two8-helper lanes, requested commit width64 and
early CPU fixed retirement preserve all30 physical proofs, bundle manifest,
RAM cells and cost ledger exactly against the serial LS48 control. A separate
fresh process accepts the completed block. MAIN reserved bytes return to zero.
Safe/Fast combined21 tests include joined worker failures, retained-store budget
failure and a valid changed geometry with a rebuilt key and resealed manifest
that still rejects the old physical proof. Safe terminal6 also passes.

The observed candidate wall was240.04s, peak RSS35.87GB and lifetime footprint
36.35GB. The control observed294.74s/42.46GB. Several operational changes and
other concurrent engineering distinguish these runs: this is qualification and
resource observation, not an isolated scheduler speedup. A controlled paired
run must use the same binary and explicit operational flags.

`roster.json` adds generated per-role CPU and service-bridge accounting. Widths
come from the admitted physical shapes and bridge layout authorities; their
native cell sums must equal the column-log inventory in `cost.json`. Active
counts use the same head/tail capacity functions as source construction. Known
padding includes mandatory inactive guard rows. ROM and fixed dictionaries
report unknown active occupancy as null instead of treating their entire table
as unused execution capacity. Truth proofs remain separately counted by the
existing physical cost ledger. The profile summarizer checks role uniqueness,
CPU inventory size and exact cell sums before including this optional ledger.

`cpu-role-accounting-v1.json` pins a four-packet/seven-proof control: all proofs,
manifest, RAM and existing cost bytes remain exact; a fresh prefix receiver
accepts with completed=false/output=null. This adds observability, not a new
acceptance rule or performance claim.

## Joined CPU50/LS71 complete block

`ethereum-full-current-foundation-v1.json` pins the joined CPU50, LS71, ALU32,
SHIFT28, shared-only RAM draw and tiled/parallel-count Keccak implementation at
f4f9cc5ab. All25 CPU and five truth proofs pass complete native closure and a
separate fresh receiver. The final register values also match the pinned legacy
receiver. Both runs use the same ELF/input,104,253,913 instructions and service
counts. This is L1 execution evidence, not OP derivation or a recursive root.

Native cells are21,530,255,168 (206.52/retirement), against65,548,757,120 in the
pinned legacy wide-RV64 receipt: an exact3.044x cell reduction. The observed wall
was194.74s, with40.31GB lifetime peak RSS and34.44GB Darwin footprint. Another
prototype prefix overlapped this engineering run. Neither controlled whole-
block speedup nor the1.5–2x RSS target is established by it. Complete native
verification still requires the public RAM sidecar and statement-specific setup.
