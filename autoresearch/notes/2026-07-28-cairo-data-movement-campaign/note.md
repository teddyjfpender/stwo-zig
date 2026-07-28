# Cairo data-movement campaign (campaign 2)

Successor to `2026-07-28-cairo-superiority-campaign`. That campaign closed with
a converging diagnosis: the remaining Zig-vs-Rust gap is **data movement**, not
instruction count. The roadmap it committed, in the order the evidence ranks
them:

| Item | What | Expected effect |
| --- | --- | --- |
| **D3c** | complete D3 — persist the preprocessed Merkle tree digests so a hit skips `merkle_commit` | ~126 ms/proof fixed cost; largest on small-row workloads |
| **D2** | narrow the u32 witness output planes | proportional to the narrow-column share; scales with rows |
| **D1** | fuse execute → consume per L2-sized row block | largest per-row effect on 2M-7M-row workloads |

D3c is first because it is the smallest, most self-contained change with an
already-proven mechanism (increment 9's authenticated artifact discipline) and
because it finishes a lane the previous campaign left explicitly half-open.

Implementation model: Claude Opus 4.5. Orchestration: Claude Fable 5.

---

## Increment 2.1: preprocessed tree-digest artifact

### Feasibility audit

The question the audit had to answer is whether a Merkle tree can be *loaded*
rather than *built* at the preprocessed commitment, byte-transparently, without
restructuring who owns what in the PCS.

**(a) What tree state does decommitment need later?**

`MerkleProverLifted(H)` (`src/prover/vcs_lifted/prover.zig:21-54`) holds exactly
two fields:

```zig
layers: [][]H.Hash,               // root first: layers[i].len == 1 << i
layer_allocator: std.mem.Allocator,
```

Nothing else. `root()` is `layers[0][0]`; `maxLogSize()` is `layers.len - 1`;
`readHashes(layer_log_size, indices)` indexes `layers[layer_log_size]`.

The decommitment algorithm (`src/prover/vcs_lifted/decommit.zig:56-154`) is
written against a *reader* contract asserted at
`src/prover/vcs_lifted/decommit.zig:345-352`: a reader must declare `maxLogSize`
and one of `readHashes` / `readHashesBatch`. **The column values are passed in
as a separate argument** (`columns: []const []const M31`, line 61) and the
queried values are read straight out of them (lines 76-91); the tree contributes
only sibling hashes and node values. `CommitmentTreeProver.decommit`
(`src/prover/pcs/commitment_tree.zig:165-…`) supplies those columns from
`self.columns`, which this increment still recomputes exactly as today.

So the *complete* state decommitment needs from the tree is the layer hash
array. There is no retained leaf-level auxiliary structure, no index map, no
hasher state. `trace_decommit` and `fri_decommit` consume that same reader
contract. The audit's blocking question is answered in the affirmative: the
artifact is `layers`, and nothing else.

**(b) Can a loaded structure be substituted byte-transparently?**

Yes, and at a single line. The Cairo preprocessed commitment has 161 columns for
`canonical_small`, which is `>= streaming_column_threshold` (128,
`src/prover/pcs/scheme.zig:162`), so `commitOwnedPreparedWithRecorderAndBacking`
dispatches to `commitOwnedStreamingWithRecorder` (`scheme.zig:231-250`). That is
corroborated by the predecessor profile: 161 columns at batch size 64
(`scheme.zig:157`) gives exactly the three `interpolate_columns` /
`evaluate_extended_domain` pairs the profile shows under
`preprocessed_materialize_and_commit`. The `merkle_commit` span for this path is
`scheme.zig:485-491`, wrapping `builder.commit(channel)`.

Inside `StreamingTreeBuilder.commit` (`src/prover/pcs/tree_builders.zig:272-334`)
the tree is produced by one statement:

```zig
var merkle = try self.streaming_committer.commitColumnsWithSparseTail(sorted);
```

(`tree_builders.zig:283`). Everything after it — restoring PCS column order,
assembling coefficients, `adoptStreamingCommitment` (which is the identity for a
host backend and `B.adoptHostMerkle` for a device backend,
`tree_builders.zig:106-118`), and `appendCommittedTree`, which is what mixes the
root into the channel — is independent of *how* `merkle` came to exist. The
substitution therefore needs no ownership change at all: it replaces one
constructor call with another that produces the same type.

Transcript-identity is by construction: the only thing the channel ever observes
from the tree is `tree.root()`, and a byte-equal root is a byte-equal transcript.
A wrong root does not silently produce a wrong-but-accepted proof; it produces a
transcript that diverges from the verifier's, so `--verify` and the official
verifier both fail closed.

**(c) Artifact size for `canonical_small`.**

The preprocessed spec (`src/frontends/cairo/preprocessed/trace.zig:57-59`) caps
`canonical_small` at `max_sequence_log = 20`, and no other preprocessed column
group exceeds log 20. With `log_blowup_factor = 1`
(`src/frontends/cairo/proving/transaction.zig:29`) the committed domain is
log 21, so:

- leaves: `2^21 = 2,097,152` Blake2s hashes
- all layers: `2^22 - 1 = 4,194,303` hashes
- payload: `4,194,303 x 32 B = 134,217,696 B ~= 134 MB`

That is the honest number and it is the design's main cost driver: it is 64x the
2 MB Pedersen artifact, and a *serial* SHA-256 over 134 MB on this host would
itself cost a large fraction of the 126 ms being saved. The integrity digest is
therefore computed as a **parallel chunked SHA-256** (see below) rather than a
single serial pass, which is the one place this artifact's format has to differ
from increment 9's.

**Verdict: feasible.** No blocking structure. Recorded before implementation.

### Key derivation and artifact format

Same discipline as increment 9's table artifact, with a distinct kind tag and a
shape binding the table artifact does not need:

```
SHA256( "stwo-zig/cairo-preprocessed-tree-digests/v1\0"
      ‖ product_identity_digest
      ‖ "preprocessed-merkle-layers\0" ‖ variant_tag ‖ "\0"
      ‖ spec_digest ‖ pcs_digest
      ‖ format_version ‖ kind(=2) ‖ chunk_bytes
      ‖ SHA256( "cairo-preprocessed-tree-shape/v1\0"
              ‖ hasher_tag ‖ hash_bytes ‖ log_size
              ‖ column_count ‖ every committed column log size, in order ) )
```

`product_identity_digest`, `spec_digest` and `pcs_digest` are increment 9's,
unchanged and shared. The shape digest is new and is what makes the artifact
safe to key: a Merkle tree is a function of the hasher, the digest width, the
committed domain and the exact multiset of committed column heights, and all
four are now in the key. **No program, no input, no user-supplied string.** The
CPU and Metal products key separately because their runtime manifests differ,
and a dirty tree keys separately because `dirty_content_sha256` is in the
identity document.

Storage reuses increment 9's directory and opt-out
(`STWO_CAIRO_PREPROCESSED_CACHE=0`, `STWO_CAIRO_PREPROCESSED_CACHE_DIR`), with
extension `.preprocessed-tree`, mode 0600, 1 GiB bound, atomic
temp-fsync-rename write. The 128-byte header carries magic, format version,
kind, the key itself, digest width, domain log size, layer count, chunk size,
payload length and the shape digest. The trailer is a **chunked SHA-256**: the
payload is cut into 4 MiB chunks, each hashed independently and in parallel, and
the trailer is `SHA256(header ‖ chunk digests in order)`. That is forced by
size — a serial SHA-256 over 134 MB would cost ~65 ms of the ~110 ms being
saved. Measured, the entire verified load is 12.5 ms.

### Soundness argument

Three gates admit an artifact: exact expected file size and byte-equality of the
whole header against the header this loader would have written; the chunked
integrity digest, constant-time compared; and re-derivation of every layer of
4096 nodes or fewer from the layer below it using the real `H.hashChildren`,
root included (~8K hashes, microseconds).

Those gates are availability guards, not soundness ones, and the distinction is
the whole argument. The only value the channel ever observes from the tree is
the root (`tree_builders.zig`, `appendCommittedTree` → `MC.mixRoot`). An
artifact that deviates in any byte that matters yields a different root, hence a
transcript the verifier does not reproduce, hence a proof that fails its own
`--verify` replay and the official verifier. An artifact with the right root but
wrong lower layers fails at decommitment verification instead. There is no path
from a bad artifact to an accepted proof — only to a rejected one — so the gates
exist to convert that rejection into a silent recompute. Every failure path
falls back to computing and the subsequent store rewrites a good artifact.
`--verify` ran in every measured run.

### Reading (b): cache hit — the headline

all-opcodes, predecessor `c936e430` vs candidate, A-B-B-A, 3 blocks, 1 untimed
warmup per arm, uninstrumented, complete prove (`timing.prove_ns`).

| Workload | Blocks | Predecessor | Candidate (hit) | Ratio | 95% CI | preprocessed merkle_commit |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| all-opcodes | 3 | 1,192.95 ms | 1,109.34 ms | **`1.0754x`** | **`[1.0219, 1.1316]`** | 87.223 → 15.120 ms |
| arithmetic-2m | 3 | 3,004.15 ms | 3,056.90 ms | `0.9858x` | `[0.8548, 1.1368]` | 133.141 → 18.205 ms |

all-opcodes clears the 1.02x bar with an interval disjoint from parity. The
mechanism is unambiguous on both: the span collapses ~6x, and on all-opcodes the
72.1 ms span reduction sits inside the 83.6 ms paired prove delta.

**arithmetic-2m is not a result.** Its blocks ran at `uptime` load averages of
18-22 (against 3.7-6.3 for all-opcodes) and individual same-arm samples ranged
2,475-3,763 ms — a ±25% spread that swamps a 115 ms effect. Its span collapse is
real and its digests are byte-exact; its ratio is uninformative and is reported
only so the reading is not silently dropped.

### Reading (a): cache-miss parity, and (c) cold write cost

Both readings ran in the same loaded window and are reported for completeness
rather than as evidence.

| Reading | Workload | Blocks | Predecessor | Candidate | Ratio | 95% CI |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| (a) miss (`…CACHE=0`) | all-opcodes | 3 | 1,750.43 ms | 1,701.36 ms | `1.0276x` | `[0.6669, 1.5835]` |
| (c) cold (dir removed per run) | all-opcodes | 3 | 1,785.65 ms | 1,683.63 ms | `1.0633x` | `[0.9425, 1.1994]` |

Miss-mode `merkle_commit` is 122.137 ms predecessor vs 115.694 ms candidate —
parity within noise, which is the regression check that matters, and the code
path with nothing armed is byte-identical to the predecessor's. The cold-write
instrumented store span is **13.3-19.5 ms** for the 134 MB artifact; a cold run
pays it once and recovers it on the next proof roughly six times over. Neither
interval is tight enough to make a claim from, and the honest statement is that
no regression was detected, not that parity was demonstrated.

### Digests

Byte-exact in every mode — hit, miss, cold-write, corrupted-artifact fallback,
truncated-artifact fallback, stale-key, `STWO_ZIG_WORKERS=1`. Every sample in
every reading produced exactly one digest per workload, equal to the campaign-1
values:

| Workload | SHA-256 |
| --- | --- |
| all-opcodes | `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310` |
| arithmetic-2m | `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6` |

### Verification

- **Corrupt artifact** (payload byte flipped): rejected after the integrity
  digest, fell back to computing (`merkle_commit` 128.002 ms, load span 12.003 ms
  — it reads and hashes the whole payload before rejecting), digest unchanged,
  artifact rewritten (store 13.879 ms).
- **Truncated artifact** (cut to 1024 B): rejected on the size check
  (load 0.080 ms), `merkle_commit` 119.456 ms, digest unchanged, self-healed.
- **Stale artifact key** (file renamed to a wrong key hex): not loaded
  (load 0.020 ms), `merkle_commit` 120.034 ms, digest unchanged, a correctly
  keyed artifact rewritten alongside.
- **`STWO_ZIG_WORKERS=1`** arithmetic-2m warm: `25e5719f…`,
  `merkle_commit` 15.548 ms.
- **Official verifier** (`stwo-cairo-official-verifier`, revision `82f21252`) on
  a cache-hit all-opcodes proof: `verified: true`,
  `proof_sha256 = 79ae76e1…`.
- Predecessor and candidate write **separate** table artifacts, observed on
  disk, because the candidate's dirty tree changes its product identity — the
  key discipline behaving as designed.
- `zig build test-cairo-cpu-product test-cairo-frontend test-stwo-prover
  -Doptimize=ReleaseFast` passes (exit 0; `stwo-cairo-cpu closure: PASS`,
  `prover library markers: PASS`, `stwo-prover closure: PASS`). The
  merkle-worker-stress `blake_deep` `InvalidNRounds` known-pre-existing item did
  not surface in this run. Stale untracked `vectors/`/`reports/` artifacts and
  the corpus `pedersen.json` `SegmentPointerOverflow` remain noted-not-chased.

### Not measured in this increment

memory-7m (the third workload) and Metal. The host load spiked mid-increment and
the 100-minute budget was spent; running them under load average 20 would have
produced more numbers of the arithmetic-2m kind rather than more evidence. Both
should be re-run on a quiet host before promotion, along with a repeat of
readings (a) and (c). The D3 design predicts memory-7m below noise (~110 ms on a
6.4 s proof) and Metal to benefit identically, since it shares the host
preprocessed commit path and keys to its own artifact.

### What this costs

134 MB on disk per protocol identity, against 2 MB for the table artifact. On a
developer machine that iterates revisions, each dirty tree keys a new 134 MB
file and nothing prunes them. That is the honest downside and the natural next
piece of work on this lane.

---

## Increment 2.2: narrowed witness planes

**Outcome: rejected-candidate, with a positive audit and a calibrated
conversion factor that reprices the whole D2 lever.**

The audit says D2's bytes are there: **33.6%** of memory-7m's pre-extension
witness plane traffic (3,430 MB of 10,204 MB) is provably narrowable from
structural evidence alone. The implementation delivers exactly the byte
reduction it promises and the touched spans shrink accordingly —
`witness_base_lower` **1.0687x**, `witness_program_execute` **1.0111x**,
`base_trace_build` **1.0220x** (-16.4 ms). But the transfer function from bytes
to time is only about **0.37** on the read side and **0.14** on the write side,
so the full lever projects to roughly **1.011x** on complete prove — below the
campaign's 1.02x bar and, more damning, below the amplitude of the incidental
heap-layout shifts the change itself induces in stages it cannot touch.

The one alternative explanation — that the write restructuring rather than the
conversion factor was the limiter — was tested rather than left as a
recommendation. A fourth arm using an ordinary per-row width branch instead of
hoisted write loops is **indistinguishable** from the hoisted candidate
(`1.0009x`, `[0.9912, 1.0108]`), and both sit at `0.995x` of the predecessor in
the cleanest window measured. **D2 is closed as a lever, not left as an
unfinished implementation.**

Implementation model: Claude Opus 4.5. Orchestration: Claude Fable 5.
Transcript: `transcripts/session-02.md`. Predecessor: pristine `zig-out` tree
from `f7012f6d`. Host: Apple M5 Max, 12 performance + 6 efficiency cores.

### (a) The structural width source

`Program` (`src/frontends/cairo/witness/program.zig:52-59`) carries only
counts — `n_regs`, `n_cols`, `n_lookup_words`, `n_sub_words`. There is **no
declared per-column range** anywhere in the claim registry, the column specs or
the template library. The campaign-1 sketch assumed one ("chosen per column
from the captured program's declared value range"); it does not exist.

What does exist is stronger. `Program.validate`
(`program.zig:124-162`) enforces `inst.dst == next_register` with a
monotonically increasing counter, so every recorded program is **straight-line
SSA**. One forward abstract-interpretation pass over the bytecode therefore
assigns each register a sound upper bound, and a column is narrow when every
`col_write` into it reads a register bounded by 16 bits. Two opcode-level
sources carry the analysis:

| Source | Where | Bound |
| --- | --- | --- |
| `u16_add`, `u16_shl` | `program.zig:465-466` | `0xffff` |
| `u16_shr` | `program.zig:467` | `min(a,0xffff) >> s` |
| `u16_and`, `u32_and` | `program.zig:468` | `imm` |
| `trunc16` | `program.zig:474` | `0xffff` |
| `m31_eq` | `program.zig:479` | `1` |
| `as_m31`, `m31_add`, `m31_mul` | `program.zig:461-475` | propagate operand bounds under the modulus |
| `table_limb` with `inst.b == MEMORY_VALUE_TABLE` | `execution_tables.zig:60`, `:65` | `0x1ff` (nine-bit memory limb) |

Everything else — `input`, `deduce_call` outputs, `m31_sub`, `m31_neg`,
`m31_inverse`, `u32_sub`, and `ADDRESS_TO_ID_TABLE` limbs (encoded ids with a
two-bit tag) — stays 32-bit. The pass is `plane_widths.columnBounds`; it reads
the bytecode and nothing else, so a column admitted narrow is narrow for every
proof that program can ever produce.

The nine-bit memory limb is the single biggest contributor: it feeds 12 of
`add_opcode_small`'s 39 columns and 87 of `add_opcode`'s 103.

**A soundness trap worth recording.** The first implementation classified
`add_opcode_small` column 12 as narrow and produced
`error: ConstraintsNotSatisfied`. The cause was Zig's `@min`, which *narrows
its result type*: `@min(a, m31_max) * @min(b, m31_max)` was evaluated in a
32-bit type and wrapped, and `(2^31-2)^2 mod 2^32 = 4`, so an unbounded value
acquired a bound of 4. A wrapped bound is always the unsound direction. The
fix is explicit saturating u64 arithmetic (`+|`, `*|`, `<<|`). Found by
trapping `value > 0xffff` at the narrow store — a trap worth keeping in any
future width pass.

### (a) Width census, official bundle `witness_programs_v1.bin`

64 programs. Columns / lookup words / sub words provably <= 16 bits:

| | total | <= 16 bit | share | <= 8 bit |
| --- | ---: | ---: | ---: | ---: |
| output columns | 4,947 | 1,988 | **40.2%** | 362 |
| lookup words | 11,025 | 4,878 | **44.2%** | — |
| sub words | 42,268 | 1,108 | 2.6% | — |

The sub-word figure is dominated by `ec_op_builtin`'s 31,516 sub words, which
are inactive on both large workloads; among the components that actually run on
memory-7m the sub-word narrow share is 24.2% by traffic.

Per component, the ones that matter (all-workload activity aside):

| component | cols | <=16 | look | <=16 | sub | <=16 | insts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `add_opcode_small` | 39 | 29 | 116 | 86 | 13 | 5 | 427 |
| `add_opcode` | 103 | 93 | 116 | 89 | 13 | 5 | 482 |
| `jnz_opcode_taken` | 47 | 38 | 83 | 61 | 11 | 6 | 317 |
| `assert_eq_opcode_double_deref` | 19 | 11 | 56 | 34 | 11 | 6 | 222 |
| `assert_eq_opcode` | 12 | 5 | 23 | 5 | 9 | 5 | 150 |
| `call_opcode_rel_imm` | 24 | 17 | 116 | 89 | 13 | 6 | 236 |
| `ret_opcode` | 16 | 10 | 83 | 62 | 11 | 6 | 167 |
| `generic_opcode` | 243 | 115 | 260 | 91 | 99 | 7 | 2,983 |
| `blake_round` | 212 | 144 | 851 | 624 | 129 | 32 | 2,179 |
| `mul_mod_builtin` | 426 | 303 | 1,196 | 750 | 307 | 80 | 6,506 |
| `partial_ec_mul_generic` | 624 | 7 | 989 | 0 | 424 | 0 | 16,999 |

The two elliptic-curve families are the exception: `partial_ec_mul_*` and
`poseidon_*_chain` carry almost nothing narrow, because their columns come out
of `m31_sub` / `m31_inverse` / deduction outputs.

### (a) Traffic math

Each plane cell is written once by the interpreter and read once by its first
consumer — output columns by base lowering (`base_trace.zig`), lookup words by
`interaction_fraction_materialize`, sub words by the gathered/compact input
materializers. Component row counts are the claim log sizes from the measured
proofs.

memory-7m (`add_opcode_small` at 2^22, `assert_eq_opcode` and
`assert_eq_opcode_double_deref` at 2^21, `jnz_opcode_taken` at 2^20, four
components at 2^19):

| plane class | write+read traffic | savable | share |
| --- | ---: | ---: | ---: |
| output columns | 2,369.7 MB | 820.5 MB | 34.6% |
| lookup words | 6,841.1 MB | 2,369.4 MB | 34.6% |
| sub words | 993.2 MB | 240.3 MB | 24.2% |
| **total** | **10,204.0 MB** | **3,430.2 MB** | **33.6%** |

arithmetic-2m (`add_opcode_small` at 2^21):

| plane class | write+read traffic | savable | share |
| --- | ---: | ---: | ---: |
| output columns | 729.0 MB | 267.5 MB | 36.7% |
| lookup words | 2,184.0 MB | 800.0 MB | 36.6% |
| sub words | 261.0 MB | 55.0 MB | 21.1% |
| **total** | **3,174.1 MB** | **1,122.5 MB** | **35.4%** |

**33.6% clears the audit's 15% gate comfortably**, so the audit is positive and
the increment proceeded to implementation. Lookup words are 67% of the traffic
and output columns 23%; that ranking decided the implementation scope below.

### (b) Before-shape: the candidate region on memory-7m

Predecessor, instrumented, `STWO_CAIRO_PREPROCESSED_CACHE=0`:

| span | ms | share of 5,308 ms prove |
| --- | ---: | ---: |
| `witness_program_execute` (all components) | 605.3 | 11.4% |
| `witness_base_lower` | 74.7 | 1.4% |
| `interaction_fraction_materialize` | 387.2 | 7.3% |
| **candidate region** | **1,067.2** | **20.1%** |

10,204 MiB (10.70 GB) across 1,067 ms is an effective 10.0 GB/s — a quarter of this host's
~40 GB/s streaming ceiling. That is the first warning the increment recorded:
the region is *bandwidth-influenced*, not bandwidth-saturated, so halving bytes
cannot be expected to convert 1:1 into time.

### Implementation scope, and why it stopped where it did

Output columns only. They have exactly **one** consumer
(`base_trace.zig` `observeGenerated` → `captureExecution`), no retention past
the component, and no interaction with the producer feeds — so the widening
boundary is a single function. Lookup words, the larger prize, have five
consumer sites (`interaction_source.LookupColumns`, `interaction_topology`,
`cpu_memory_multiplicity`, `fixed_trace`, and the resident/recovery path) and
each would need a width-tagged reader; that did not fit the increment's budget
alongside a full paired measurement, so it is priced below rather than
half-built.

Mechanism:

- `src/frontends/cairo/witness/plane_widths.zig` — the structural width pass
  and the split write plan.
- `program.zig:283-306` `NarrowColumns`; `program.zig:596-614` the hoisted
  writes. The base-column stores are lifted out of the instruction switch into
  **two straight-line loops, one per width**, so the width decision is taken
  once per program and never per row. Deferring them to the end of the row is
  sound because the SSA invariant means no register is rewritten inside a row.
- `component_executor.zig:122-171` splits the output storage into a `[]u32`
  wide arena and a `[]u16` narrow arena, with `Execution.plane(i)` as the
  width-tagged accessor.
- `base_trace.zig` `captureExecution` is the **pre-extension widening
  boundary**: it emits `[]M31` per column exactly as before, so
  `prepareColumnsForCommitOwnedForBackend` and the three PCS consumers
  (`decommit.zig:76-91`, leaf hashing, sampled-value evaluation) see bare
  `[]const M31` and were not touched. Increment 2.1's scoping constraint held
  without strain.

`conformance/base_execution.zig` `compare` also had to learn the tag, because
the oracle column digests are defined over widened values. That is a real cost
of the change: the split representation leaks into the conformance harness.

### (c) Mechanism: the touched spans shrink as the bytes predict

Paired instrumented runs, predecessor vs candidate, same host window:

| span | memory-7m pred | cand | ratio | all-opcodes pred | cand |
| --- | ---: | ---: | ---: | ---: | ---: |
| `witness_program_execute` | 605.345 | 598.705 | **1.0111** | 1.382 | 1.410 |
| `witness_base_lower` | 74.704 | 69.901 | **1.0687** | 0.050 | 0.040 |
| `base_witness_graph` | 714.672 | 697.604 | 1.0245 | 1.640 | 1.712 |
| `base_trace_build` | 763.738 | 747.314 | **1.0220** | 16.992 | 16.716 |
| `witness_output_allocate` | 0.036 | 0.069 | 0.52 | 0.026 | 0.087 |

The mechanism is confirmed and the arithmetic closes:

- **Read side.** Base lowering moves 1,184.9 MB of u32 planes in and
  1,184.9 MB of M31 out. Narrowing the input side to 775.0 MB is a **17.3%**
  byte reduction; measured time fell **6.4%**. Conversion **0.37**.
- **Write side.** Execution writes 5,102 MB of planes; narrowing the column
  share removes 410 MB, an **8.0%** reduction; measured time fell **1.1%**.
  Conversion **0.14**.

The write-side conversion being weaker than the read side is the expected
shape: stores retire into the store buffer and overlap with the interpreter's
dependent vector work, whereas the lowering loop is a pure streaming pass with
nothing to hide latency behind.

The two allocation-side spans are honest small costs: `witness_output_allocate`
roughly doubles (0.036 → 0.069 ms on memory-7m) because it now runs the width
pass and makes two extra allocations per component.

### (d) Prove-level: parity, and the reason it cannot be more

A-B-B-A, 1 untimed warmup per arm, uninstrumented, both arms with
`STWO_CAIRO_PREPROCESSED_CACHE=0`, predecessor = pristine `zig-out` from
`f7012f6d`.

| Workload | Blocks | Predecessor | Candidate | Ratio | 95% CI | host load |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| memory-7m (quiet) | 3 | 5,858.76 ms | 5,819.88 ms | `1.0066x` | `[0.9995, 1.0139]` | 6.2-11.1 |
| memory-7m (loaded) | 3 | 6,602.16 ms | 6,834.27 ms | `0.9673x` | `[0.8924, 1.0484]` | 3.0-12.1 |
| arithmetic-2m | 3 | 2,592.41 ms | 2,594.31 ms | `0.9992x` | `[0.9520, 1.0487]` | 11.3-13.4 |
| all-opcodes (loaded) | 3 | 1,374.79 ms | 1,392.07 ms | `0.9876x` | `[0.9841, 0.9911]` | 10.1-12.0 |

Per-sample ranges: memory-7m predecessor `[5,684.5, 7,136.5]`, candidate
`[5,703.0, 7,210.9]`; arithmetic-2m `[2,466.3, 2,659.3]` / `[2,462.3, 2,717.7]`;
all-opcodes `[1,332.0, 1,514.2]` / `[1,356.2, 1,522.8]`.

The all-opcodes reading looked like a clean 1.2% regression with a tight
interval, and it is the one number in this increment that a load-aware re-run
overturned — see the three-arm decomposition below, where the same workload
reads `1.0001x` in a quiet window. Blocks measured at load average above 10 are
reported but should not be used; that is now twice in this campaign that a
loaded window produced a confidently wrong tight interval.

**No reading clears 1.02x on prove, and no touched span clears 1.10x.**

### (e) Three-arm decomposition: hoisting tax vs narrowing gain

To separate the write-restructuring cost from the byte saving, a third arm was
built with the hoisted writes in place but the width predicate forced to
`false` — same code path, no narrow planes. A-H-B-B-H-A per block.

all-opcodes, 3 blocks, load 2.1-7.7 (quiet):

| | block 1 | block 2 | block 3 | geomean | 95% CI |
| --- | ---: | ---: | ---: | ---: | --- |
| A (pred) ms | 1,253.84 | 1,268.91 | 1,298.35 | | |
| H (hoist only) ms | 1,257.57 | 1,274.66 | 1,309.00 | | |
| B (candidate) ms | 1,255.89 | 1,263.94 | 1,300.83 | | |
| hoisting tax `A/H` | 0.9970 | 0.9955 | 0.9919 | `0.9948x` | `[0.9882, 1.0014]` |
| narrowing gain `H/B` | 1.0013 | 1.0085 | 1.0063 | `1.0054x` | `[0.9963, 1.0145]` |
| total `A/B` | 0.9984 | 1.0039 | 0.9981 | `1.0001x` | `[0.9920, 1.0083]` |

On a workload with no plane traffic to speak of, hoisting costs ~0.5% and
narrowing returns ~0.5%; both intervals touch parity and the net is parity.

memory-7m, 4 blocks. The window started quiet (load 3.5) and climbed to 15.1 by
block 4 despite a load-gated start that waited 460 s for the host:

| | block 1 | block 2 | block 3 | block 4 | geomean | 95% CI |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| A (pred) ms | 6,374.34 | 6,755.30 | 6,903.52 | 6,799.05 | | |
| H (hoist only) ms | 6,389.51 | 6,779.59 | 6,992.20 | 6,948.76 | | |
| B (candidate) ms | 6,259.30 | 6,772.52 | 6,912.29 | 6,775.52 | | |
| hoisting tax `A/H` | 0.9976 | 0.9964 | 0.9873 | 0.9785 | `0.9899x` | `[0.9758, 1.0043]` |
| narrowing gain `H/B` | 1.0208 | 1.0010 | 1.0116 | 1.0256 | `1.0147x` | `[0.9976, 1.0321]` |
| total `A/B` | 1.0184 | 0.9975 | 0.9987 | 1.0035 | `1.0045x` | `[0.9894, 1.0198]` |

Per-sample ranges: A `[6,060.2, 7,226.3]`, H `[6,164.6, 7,374.5]`,
B `[6,203.9, 7,243.0]`.

**This decomposition must not be over-read, and saying why is the point.** Both
component arms are numerically large — 1.0147x is 98 ms and 0.9899x is 68 ms —
while the directly measured mechanism is **11.4 ms** (4.8 ms of base lowering
plus 6.6 ms of execution, from the low-variance instrumented spans). Two
quantities six to nine times the size of the effect they are supposed to
decompose are being read off a series whose same-arm spread is ±9%. The honest
conclusion is that **at an 11 ms mechanism the three arms are not resolvable at
prove level on this host**, and the span measurements are the only trustworthy
evidence in this increment.

### (f) The writer question, settled directly

The one way the lever could still have reached the bar was if the hoisted write
loops were themselves the limiter — the ~1% `A/H` reading above is numerically
consistent with that. So a fourth arm was built: same narrowing, but the width
selected by an ordinary **per-row branch** on the plane tag inside the
`col_write` switch arm, with no hoisting at all. (This deliberately violates the
increment's "no per-row branching on width" constraint; it is a diagnostic arm,
not a candidate.) Byte-exact, `e3317e55…`, `--verify` true.

A = predecessor, P = branch + narrow, B = hoist + narrow. A-P-B-B-P-A per block,
4 blocks, load 4.8-11.2. This is the tightest series of the session — the
predecessor's own samples span only ±3.7%:

| | block 1 | block 2 | block 3 | block 4 | geomean | 95% CI |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| A (pred) ms | 5,674.96 | 5,828.07 | 5,960.31 | 5,973.16 | | |
| P (branch) ms | 5,716.23 | 5,825.97 | 5,977.08 | 6,015.09 | | |
| B (hoist) ms | 5,673.37 | 5,834.77 | 5,992.89 | 6,058.18 | | |
| `A/P` | 0.9928 | 1.0004 | 0.9972 | 0.9930 | `0.9958x` | `[0.9901, 1.0016]` |
| `A/B` | 1.0003 | 0.9989 | 0.9946 | 0.9860 | `0.9949x` | `[0.9847, 1.0052]` |
| `B/P` (hoist vs branch) | 0.9925 | 1.0015 | 1.0026 | 1.0072 | `1.0009x` | `[0.9912, 1.0108]` |

Ranges: A `[5,572.2, 5,999.2]`, P `[5,661.8, 6,061.4]`, B `[5,641.5, 6,112.4]`.

**The two writer designs are indistinguishable** — `B/P = 1.0009x` with an
interval tight around parity — which retires the ~1% hoisting-tax reading as
noise and confirms the choice of write structure is not what limits D2. And both
narrowing arms sit at `0.995x` against the predecessor in the cleanest window
measured all session, against a mechanism the instrumented spans put at
+11.4 ms (+0.19%).

That is the closing argument. Narrowing delivers its bytes, the spans shrink by
the predicted amount, the writer structure is irrelevant, and none of it is
visible at prove level because 11 ms is below this prover's measurement floor on
this host. **D2 is closed as a lever, not as an unfinished implementation.**

### Repricing D2

Applying the measured conversion factors to the full census:

| lever | bytes removed | region span | projected saving |
| --- | ---: | ---: | ---: |
| output columns, read side (landed) | 410 MB of 2,370 | `witness_base_lower` 74.7 ms | 4.8 ms *(measured)* |
| output columns, write side (landed) | 410 MB of 5,102 | `witness_program_execute` 605.3 ms | 6.6 ms *(measured)* |
| lookup words, write side | 1,185 MB of 5,102 | same 605.3 ms | ~19 ms |
| lookup words, read side | 1,185 MB of ~6,800 | `interaction_fraction_materialize` 387.2 ms | ~25 ms |
| sub words, both sides | 240 MB | — | ~5 ms |
| **complete D2** | **3,430 MB of 10,204** | **1,067.2 ms** | **~61 ms** |

61 ms on a 5,860 ms proof is **1.011x**. That is the honest ceiling of the D2
lever on its best workload, and it sits below the 1.02x bar. It also sits below
the noise the change itself introduces elsewhere: the paired phase split shows
`composition_evaluation` +21.7 ms, `main_trace_commit` +11.0 ms and
`interaction_trace_build` +8.6 ms in the candidate on memory-7m — stages that
narrowing cannot touch, moved by the different heap layout that two extra
allocations per component produce. At a 16 ms mechanism, incidental layout
effects are the same size as the signal.

**D2's premise was that a bandwidth-bound region converts bytes into time near
1:1. Measured, it converts at 0.14-0.37.** The region runs at 10.0 GB/s against
a ~40 GB/s ceiling, so it is latency- and occupancy-limited rather than
bandwidth-saturated, and removing bytes from a pass that is not at the
bandwidth wall buys only the fraction of its time that was actually waiting on
the bus. Increment 7's efficiency-core parity and increment 8's worker plateau
established that the region is *not core-bound*; they did not establish that it
is *bus-bound*, and this increment is the first to test the difference.

### Digests

Byte-exact in every mode. Every proof produced in every reading — every timed
and warmup sample of the candidate arm *and* of the hoist-only diagnostic arm,
across all four A-B-B-A / A-H-B-B-H-A series, plus the byte-parity runs under
`--verify`, `STWO_ZIG_WORKERS=1`, and Metal — carried exactly one digest per
workload, equal to the campaign value:

| Workload | SHA-256 |
| --- | --- |
| memory-7m | `e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994` |
| arithmetic-2m | `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6` |
| all-opcodes | `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310` |

### Verification

- `zig build test-cairo-cpu-product test-cairo-frontend test-stwo-prover
  -Doptimize=ReleaseFast` — exit 0. `stwo-cairo-cpu closure: PASS`.
  `src/prover/**` was not touched; `test-stwo-prover` was run anyway.
  The merkle-worker-stress `blake_deep` `InvalidNRounds` known-pre-existing
  item did not surface. Stale untracked `vectors/`/`reports/` artifacts and the
  corpus `pedersen.json` `SegmentPointerOverflow` remain noted-not-chased.
- **Conformance regression found and fixed inside the increment.** The first
  build failed 12 of 20 `test-cairo-frontend` tests
  (`official_base_checkpoint`, `official_interaction_checkpoint`,
  `official_live_geometry`) with `recorded graph mismatch component=add_opcode
  ordinal=0 column=4` — `conformance/base_execution.zig` `compare` read
  `execution.output_columns` directly and saw an empty slice for every narrow
  column. Teaching it `Execution.plane` fixed all 12.
- **Official verifier** (`stwo-cairo-official-verifier`, revision `82f21252`) on
  candidate proofs: memory-7m `verified: true`, `proof_sha256 = e3317e55…`;
  arithmetic-2m `verified: true`, `proof_sha256 = 25e5719f…`.
- **Metal** arithmetic-2m, built with
  `-Dmetal-core-aot-bundle=/private/tmp/cairo-quotient-baseline-v2/aot-bundle`
  (identity `core-aot-manifest-sha256=0bc89238…`): `25e5719f…`,
  `execution: metal-pcs`, `classification: accelerated_without_fallbacks`,
  74 dispatches, **`cpu_fallbacks: 0`**, `--verify` true. The host-shared
  witness planes were inherited cleanly with no Metal-side change.
- **`STWO_ZIG_WORKERS=1`** arithmetic-2m: `25e5719f…`, `--verify` true. Note the
  campaign-1 single-worker `ConstraintsNotSatisfied` defect
  (`component.zig:170-174`) does not reproduce on this head.
- **Byte-parity under `--verify`** on all three workloads before any timing was
  collected.

### What this leaves

The implementation is preserved at `4b106372` (the narrowing) and `f9ae3149`
(the conformance-harness fix), and reverted at `c8481364`, per the rejection
protocol. `src/` is bit-identical to `f7012f6d`, and a proof built from the
reverted head is byte-identical to the predecessor's own proof file, not merely
to its digest.

The two diagnostic arms — hoist-only (width predicate forced `false`) and
per-row-branch — were local edits and are deliberately **not** committed; both
are one-site changes to `plane_widths.plan` and `program.zig`'s `col_write` arm
respectively, described precisely enough above to reproduce from `4b106372`.

`plane_widths.zig` is the durable output: a sound, structural, bytecode-only
width oracle, with the `@min` result-type-narrowing trap documented. Anything
that later wants per-column widths — a layout change, a generated writer, a
device-side plane ABI, a narrower device transfer — can reuse it directly rather
than rediscovering the abstract interpretation and its one sharp edge. The
census itself (40.2% of columns and 44.2% of lookup words provably <= 16 bits)
is reusable evidence independent of this increment's verdict.

### D1 readiness: what the plane lifetimes force

Tracing every plane end to end for the census also settles most of D1's open
design questions, and one of the answers is a hard blocker the campaign-1 sketch
did not anticipate.

**Which consumers can be fused.** The three plane classes have completely
different lifetimes:

| plane | layout | lifetime | first consumer | fusable with execute? |
| --- | --- | --- | --- | --- |
| output columns | column-major `[col][row]` | one component's execution + observer callback, then freed | base lowering (`base_trace.zig`) | **yes** — single consumer, same call |
| lookup words | column-major `imm*rows + row` | retained from `base_trace_build` into `interaction_trace_build` | `interaction_fraction_materialize` | **no** — see below |
| sub words | row-major `row*n_sub + imm` | retained until a *downstream component's* execution | gathered/compact input materializers | only per producer→consumer component pair |
| multiplicity tables | table-indexed accumulate | whole-range only | counting passes | already excluded from partial ranges (`program.zig:351-356`, `component_executor.zig:62`) |

**Lookup words cannot be fused with their interaction consumer, and the reason
is the transcript, not the code.** The interaction trace is built from
`lookup_z` and `lookup_alpha`, which are drawn from the channel *after* the base
commitment is mixed in. `interaction_trace_build` therefore cannot run before
`main_trace_commit`, and no loop interchange can move it earlier without
changing the Fiat-Shamir order. D1's largest single target — 3,420 MB of
lookup-word write traffic and its 387 ms re-read — is out of reach of fusion for
protocol reasons. That should be settled in the design before any code, because
the campaign-1 sketch listed `interaction_trace_build` as a D1 target.

What is left fusable is `execute → base lowering` plus increment 8's counting
passes. That is real but bounded: `witness_base_lower` is **74.7 ms** of a
5,308 ms proof, and fusion converts its DRAM read into an L2 read rather than
removing it, so the ceiling is a fraction of 74.7 ms.

**Tile size.** Once lookup words are excluded from the fused set, the per-row
footprint that has to fit in cache is much smaller than the campaign-1 estimate.
For `add_opcode_small`: 4 input words + 39 output columns = 172 B/row at u32, or
~137 B/row with this increment's narrowing (29 of 39 columns at u16), plus a
~1.2 KB private register file per worker. A 512 KB per-worker slice therefore
holds roughly **3,000 rows**, not the few hundred the "inputs + outputs + lookup
+ sub words" estimate implies. Lookup and sub words remain pure streaming writes
inside the tile — written once, never re-read in the fused region — which is the
cheapest possible traffic pattern and needs no cache residency at all.

Narrowing raises the tile by only ~25% on that footprint, so **D2 is not a
prerequisite for D1** and the two do not compose as strongly as the ranking
assumed.

**Ownership boundaries.** `ComponentObserver.visit` (`live_graph.zig:52-59`) is
currently called once per component with the whole `Execution`. For a tiled
fusion it must become per-tile, which means `Collector.capture` has to accept a
row range: allocate the `[]M31` columns once at component entry, then fill
`values[tile_start..tile_end]` per tile. The label/ordinal validation stays at
component entry. Worker ranges and tiles are two decompositions of one axis and
compose naturally as worker-owns-range / tile-within-range — every write is
already indexed by absolute `row`, rows are disjoint across workers
(`program.zig:327` and the executor's chunk split), and the shared `[]M31`
columns need no synchronisation because each worker touches only its own rows.
The one thing that must not move is the multiplicity accumulation.

**The larger redirect this increment's measurement suggests.** The predecessor
stage ranking on memory-7m:

| stage | ms | share | cumulative |
| --- | ---: | ---: | ---: |
| `composition_evaluation` | 1,063.5 | 20.0% | 20.0% |
| `main_trace_commit` | 1,020.0 | 19.2% | 39.3% |
| `interaction_trace_commit` | 802.4 | 15.1% | 54.4% |
| `base_trace_build` | 763.7 | 14.4% | 68.8% |
| `fri_quotient_build_and_commit` | 540.4 | 10.2% | 78.9% |
| `interaction_trace_build` | 419.3 | 7.9% | 86.8% |
| `sampled_value_evaluation` | 280.7 | 5.3% | 92.1% |

The witness side that D1 and D2 both target is `base_trace_build` +
`interaction_trace_build` = 1,183 ms, **22.3%**. The commit and evaluation side —
`main_trace_commit` + `interaction_trace_commit` + `composition_evaluation` +
`composition_commit` + `fri_quotient_build_and_commit` — is **3,579 ms, 67.4%**,
and `merkle_commit` alone inside the two trace commits is 662.8 + 579.5 = 1,242.3 ms.
Even a *perfect* D1 (witness traffic reduced to zero cost) cannot move the proof
by more than 1.29x, and the measured conversion factors say the realistic figure
is a few percent. The 1.46x gap against pinned Rust is not in the witness
writers; on this workload it is overwhelmingly in Merkle commitment and
constraint evaluation.

---

## Increment 2.3: register-resident compiled AIR evaluation

**Outcome: negative audit. The S1 gate failed at `1.241x` against a `1.5x`
bar. The candidate was built, wired into the product behind structural
admission, proved byte-exact, measured whole-prover, and reverted. The
increment's durable output is the reason it failed: the composition loop is
**QM31-multiply-bound**, not interpreter-bound, and this is the third
independent mechanism to establish that reducing the interpreter's
*instruction count* does not reduce its *cycles*.**

Implementation model: Claude Opus 4.5. Orchestration: Claude Fable 5.
Transcript: `transcripts/session-03.md`. Predecessor: pristine `zig-out` tree
built from `efe4bef3` in a detached worktree. Host: Apple M5 Max, 12
performance + 6 efficiency cores, load average 2.5-6.3 across the session —
the quietest window this campaign has measured in.

### The hypothesis, and what it predicted

Increment 5 left the composition stage at ~22 cycles per interpreted
instruction over 1.09 G executions. Increment 6 removed 21.4% of the
interpreter's machine instructions by strip-mining and moved cycles 1.054x,
which excluded *dispatch* as the binding constraint. The remaining located
hypothesis was the interpreter's **memory-resident register file**: `base` is
`max_base_regs` PackedM31 and `extension` is `max_ext_regs` PackedQm31,
heap-allocated per range (`simd_evaluator.zig:209-212`), so every one of the
771 instructions in the dominant component's program is a load-operands /
compute / store-result round trip against 31.5 KB of L1D. Compiled code would
hold the same values in NEON registers. The peer existence proof is that Rust
stwo-cairo ships statically compiled per-component evaluators and is 1.46x
faster overall.

The prediction that follows is quantitative: if the register file is the cost,
the compiled body's memory operations per group should *collapse*, and cycles
should follow.

### The candidate: mechanical translation, structural admission

`add_opcode_small` is the dominant arithmetic-2m component and matches
increment 5's census exactly — 278 base instructions of which 63 are mask
reads, 493 extension instructions, 32 constraint roots, two distinct mask
offsets (`0` and `-1`), `max_base_regs = 278`, `max_ext_regs = 493`, semantic
hash `0x6e7d9762fbd1969a`. Its opcode mix is worth recording because it is
what the result turns on:

| stream | opcode | count |
| --- | --- | ---: |
| base | `constant` | 71 |
| base | `mul` | 69 |
| base | `trace_col` | 63 |
| base | `sub` | 46 |
| base | `add` | 29 |
| ext | `secure_col` | 132 |
| ext | `add` | 110 |
| ext | `mul` | **107** |
| ext | `param` | 100 |
| ext | `constant` | 24 |
| ext | `sub` | 19 |
| ext | `neg` | 1 |
| fold | roots | 32 |

`generated/add_opcode_small_base.zig` and
`generated/add_opcode_small.zig` are the mechanical translation: one template
instruction, one Zig `const`, the same `m31.addVec4` / `m31.subVec4` /
`m31.mulVec4` / `PackedQm31.{add,sub,mul,neg}` primitive with operands in the
same order, and the same fold (`acc = add(acc, mul(root, coeff))` from zero,
in root order). Base registers reach the extension stream through a generated
struct of 90 named fields rather than an array, so inlining leaves them in
registers instead of materialising a stack array. Row-invariant work — the 100
`param` splats, the 24 `constant` splats and the 32 coefficient splats — is
hoisted to once per range, which is free in compiled form.

The files are emitted by a generator run out-of-tree
(`/private/tmp/inc23/gen.py` in this session); the generator asserts that its
own canonical byte encoding of the program reproduces the program's
`semantic_hash` before emitting, which is what makes the digest below
trustworthy.

**Admission is structural and content-addressed.**
`compiled_evaluator.zig` filters on `Program.semantic_hash` (a cheap 64-bit
FNV-1a the format already carries), then checks the header shape
(`max_base_regs`, `max_ext_regs`, `n_ext_params`, `n_constraints`, both stream
lengths) and then re-hashes the program's *entire* canonical semantic payload —
base constants, extension constants, every base instruction, every extension
instruction, every constraint root — with SHA-256 and compares it against a
32-byte digest baked into the generated module
(`268379031004caf095c8742c7ce45d0ecf96afb173e97a47e7c94a377b0ba1bd`). That is
one pass over ~12 KB per evaluated range, microseconds, and it is
collision-resistant rather than merely a filter. No workload name, input path,
proof digest or component label is inspected anywhere. Every non-matching
program runs the interpreter, which remains the general path.

Two properties made this safe to key. First, the runtime program's semantic
hash is *equal* to the shipped template's: `template_binding.zig` rebinds
constants only for `memory_address_to_id` (`rebindDomainConstants`) and for
builtin segment starts (`rebindSegmentConstant`), and `add_opcode_small` is
neither, so `replaceBaseConstant` never fires and never recomputes the hash.
Second, `setDomainLogSize` touches only the header, which the digest does not
cover — correctly, since the domain size is supplied as an input to the
evaluator rather than compiled into it.

Everything outside the generated body is the interpreter's own code: the domain
checks, `read_plan.build`, the per-group offset map, the mask gather, the
denominator lookup and the scatter. The only difference between the two arms is
how the arithmetic runs.

### S1 gate: the mechanism is confirmed and the mechanism does not pay

`stwo-prof zig` harnesses `i23-interp` / `i23-compiled`, compiled against the
repo's real module graph so both arms execute live working-tree source. The
program is not synthetic: it is parsed out of the shipped
`vectors/cairo/official/all_builtins_canonical_small.air_programs_v1.bin` with
the repo's own parser and rebound to `trace_log 17` / `eval_log 18`, matching
increment 6's sweep shape so the two tables read together. One op is one
four-row group. 12 iterations per round, four rounds.

| arm | instructions/op | cycles/op | IPC | ns/op |
| --- | ---: | ---: | ---: | ---: |
| interpreter | 43,395 | **8,698.3** | 4.99 | 2,025.3 |
| compiled | 30,961 | **7,000.5** | 4.43 | 1,640.1 |
| **ratio** | **1.402x** | **1.242x** | 0.89 | 1.235x |

Per-round cycles/op — dispersion is small and the verdict does not depend on a
round: interpreter `8,522.5 / 8,882.2 / 8,615.2 / 8,773.2`; compiled
`7,054.4 / 6,973.3 / 6,931.3 / 7,042.9`. Instructions/op agree to five
significant figures across rounds in both arms.

**`1.242x` against a `1.5x` gate. The hypothesis is falsified.**

### Why: the register file does not disappear, and it is not the cost anyway

Two facts from `objdump` on the harness binaries settle it. The generated
`evalGroup` is a single straight-line symbol with no loops, so its static
instruction count *is* its dynamic count per four-row group.

| symbol | instructions | loads | stores | calls |
| --- | ---: | ---: | ---: | ---: |
| `generated.add_opcode_small.evalGroup` | 6,552 | 1,513 | 1,397 | 139 |
| `simd_evaluator.PackedQm31.mul` (out of line) | 161 | 5 | 3 | 0 |

**(1) The register-file traffic did not collapse; it moved to the stack.** The
interpreter stores every result by construction: 278 sixteen-byte vector stores
plus 493 × 4 = 1,972, so 2,250 vector stores (36,000 B) per group. The compiled
body issues 1,397 vector stores and 1,513 loads per group. That is a **1.61x
reduction in stores, not an elimination** — 493 live PackedQm31 values are
31.5 KB and 32 NEON registers are 512 B, so LLVM spilled, and a spill slot is
the same L1D round trip the heap register file was. The prediction the
hypothesis made about mem ops is directly contradicted by measurement.

**(2) 72% of the compiled arm's instruction budget is one QM31 multiply.**
`evalGroup` makes exactly 139 calls — 107 extension `mul` instructions plus 32
fold multiplies — into a 161-instruction out-of-line `PackedQm31.mul`. That is
`139 x 161 = 22,379` instructions per group, **72.3%** of the compiled arm's
30,961 and 51.6% of the interpreter's 43,395. The remainder of the compiled arm
is 6,552 for the whole 771-instruction body plus ~1,500 for the driver's gather,
offset map, denominator and scatter. Every instruction is accounted for.

`PackedQm31.mul` costs what it costs because the current QM31 product is
16 `mulVec4` plus 12 `addVec4`/`subVec4` (`simd_evaluator.zig:79-118`): eight
CM31 sub-products, each two M31 multiplies.

**(3) The IPC signature is increment 6's, repeated.** IPC falls 4.99 → 4.43 in
lockstep with the 1.40x instruction reduction, exactly as it fell 5.30 → 4.34
under strip-mining's 1.21x reduction. Three independent mechanisms have now
removed instructions from this loop:

| increment | mechanism | instructions removed | cycles gained |
| --- | --- | ---: | ---: |
| 5 (rejected) | hoist row-invariant instructions | 24.3% | ~1.01x |
| 6 (rejected) | strip-mine over `T` row groups | 21.4% | 1.054x |
| **2.3 (this)** | **compile the program to straight-line Zig** | **28.6%** | **1.242x** |

The trend is monotone and this increment is much the largest of the three, but
it converges on a **cycle floor of ~7,000 per four-row group** that codegen
cannot cross, because at that point three quarters of the machine instructions
are the field arithmetic the AIR actually specifies.

**One diagnostic, and its honest limit.** Marking `PackedQm31.mul` `inline`
takes the interpreter arm from 43,394 to 40,416 instructions/op (−6.9%) and its
cycles from 8,773.2 to 8,667.1 (−1.2%, inside round-to-round spread). The
compiled arm **could not be built** with that change — `m31.zig:255: evaluation
exceeded 1000 backwards branches` — so no compiled inline-mul figure is
reported; an earlier reading that appeared to show one came from a stale binary
and is discarded. The interpreter-side reading is enough to make the point:
call overhead is not where the multiply's cost is.

### Whole-prover corroboration

The S1 gate had already failed, so this is one confirmatory measurement rather
than an acceptance attempt — the same discipline increment 6 used. A-B-B-A cold
processes, three blocks, one untimed warmup process per arm, `--verify` on every
run, uninstrumented binaries both sides, both arms with
`STWO_CAIRO_PREPROCESSED_CACHE=0`, predecessor the pristine `zig-out` tree built
from `efe4bef3`. Host load 4.45 at open, 6.30 at close — no block above 10.

| block | comp pred | comp cand | ratio | prove pred | prove cand | ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 381.909 | 362.720 | 1.0529x | 2,559.856 | 2,536.505 | 1.0092x |
| 2 | 398.032 | 382.997 | 1.0393x | 2,639.375 | 2,606.531 | 1.0126x |
| 3 | 416.825 | 388.102 | 1.0740x | 2,677.059 | 2,659.926 | 1.0064x |
| **geomean** | | | **1.0553x** | | | **1.0094x** |

Per-sample ranges: composition pred `[378.910, 432.078]`, cand
`[360.843, 390.876]` — overlapping; prove pred `[2,541.414, 2,702.353]`, cand
`[2,533.835, 2,664.599]`. Acceptance required either composition `>= 1.10x`
with disjoint ranges in three blocks or prove `>= 1.02x` with non-overlapping
CI. **Neither limb is met**, and the sign is the same in 3 of 3 blocks on both
observables, so the small effect is real but small.

The change is confined, which is the regression check that matters. Pooled
ratios on the stages the candidate does not touch: `base_trace_build` 1.0093x,
`main_trace_commit` 1.0033x, `interaction_trace_commit` 0.9858x,
`interaction_trace_build` 1.0043x, `fri_quotient_build_and_commit` 1.0004x,
`sampled_value_evaluation` 1.0048x — all inside this host's noise, none showing
the incidental heap-layout amplitude increment 2.2 recorded.

**The one number that does not close, stated as such.** S1 says the compiled
component is 1.242x on cycles. If it were 70% of the composition stage — the
share increment 5's census implies from 71% of QM31 multiplications — the stage
should read ~1.157x. It reads 1.0553x, which back-solves to a **27%** share.
Either the census's instruction share overstates its *time* share, or the real
log-22 instance is more mask-gather-bound than the log-18 S1 shape (its columns
are 4.2 M rows and cannot be cache-resident, while the harness's are). Resolving
it needs a per-component composition probe — increment 5's audit instrumentation,
preserved at `bb0de1e5` — and this increment did not spend its remaining budget
there. The discrepancy is recorded rather than explained away.

### Reconciliation with the earlier AOT rejection

The prior "authenticated CPU AIR AOT specialization" on this branch was
rejected at **1.017x geomean for 5.9 MiB of binary**
(`2026-07-27-cairo-system-throughput/note.md`; source not retained). The brief's
working theory was that it failed because it generated code that still routed
values through a memory register file or blew i-cache.

**That theory is wrong, and this increment is the evidence.** This
implementation does not route through a register file — its values are ordinary
locals and its spills are LLVM's own choice — and its `evalGroup` is 26 KB of
text against this host's 192 KB L1I, on one component, with only one component
hot at a time. It is not i-cache-bound and not register-file-bound. It measures
**1.0094x on prove and 1.0553x on the composition stage for 17 KiB**. The old
result and this one are **the same finding at two binary sizes**: compiling the
AIR is worth roughly one percent of prove time, because the AIR's own field
arithmetic — not its interpretation — is what the stage spends its cycles on.
The old verdict is confirmed on better evidence, and the mechanism is now named.

### Digests and verification

Every proof produced in this increment — all 14 candidate arithmetic-2m proofs
(3 blocks × 2 samples, warmup, spot proofs, single-worker) — carried the
campaign digest:

| Workload | SHA-256 |
| --- | --- |
| arithmetic-2m | `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6` |

- **Byte-exactness is structural**, and was confirmed on the first run before
  any timing: the compiled body computes the same values from the same inputs
  with the same primitives in the same operand order, and accumulates rows in
  the same ascending order.
- **Admission was proved to fire, not assumed.** A deliberately sabotaged
  generated body (`return PackedQm31.zero()`) produces
  `error: ConstraintsNotSatisfied` on arithmetic-2m, so the compiled path is
  demonstrably the one executing; with the correct body the digest is
  `25e5719f…`. This also demonstrates the fail-closed property: a wrong
  compiled evaluator cannot yield an accepted proof, only a rejected one,
  because the verifier recomputes the composition polynomial at the OODS point
  through the interpreter path.
- **Official verifier** (`stwo-cairo-official-verifier`, revision `82f21252`)
  on a candidate arithmetic-2m JSON proof: `verified: true`,
  `proof_sha256 = 25e5719f…`.
- `zig build test-cairo-cpu-product test-cairo-frontend -Doptimize=ReleaseFast`
  — exit 0, `stwo-cairo-cpu closure: PASS` over **337** transitive Zig sources
  (335 + the two generated files + the driver). `src/prover/**` untouched, so
  `test-stwo-prover` was not required. A new unit test in
  `compiled_evaluator.zig` re-derives the structural digest from the shipped
  bundle and fails if the generated module ever drifts from the template it was
  generated from.
- **`STWO_ZIG_WORKERS=1`** arithmetic-2m: `25e5719f…`, `--verify` true — the
  serial composition path takes the same compiled call.
- **Metal was not rerun.** The reverted tree is bit-identical to `efe4bef3`,
  whose increment-2.2 record already carries Metal arithmetic-2m at `25e5719f…`
  with `cpu_fallbacks: 0`. The candidate would have inherited it unchanged in
  any case: the compiled evaluator is host-side and Metal supplies its own
  generated composition kernels.
- Known pre-existing items unchanged and not chased: merkle-worker-stress
  `blake_deep` `InvalidNRounds`, stale untracked `vectors/`/`reports/`
  artifacts, corpus `pedersen.json` `SegmentPointerOverflow`.

### Generalization sizing, recorded because the number is cheap and useful

Measured, not estimated: the CPU binary grows from **2,003,632 B** to
**2,021,088 B**, `+17,456 B` for 803 translated template instructions =
**21.7 B per template instruction**. The shipped `canonical_small` bundle holds
**64,193** template instructions across 48 components, so full coverage projects
to **+1.33 MiB** — a quarter of the old AOT's 5.9 MiB, which says the old
implementation emitted roughly 4x more code per instruction than a mechanical
translation needs.

What full coverage would actually require, if a future increment ever wanted it:
a generator tool inside the repo (this session's lived out-of-tree), which means
`build.zig` integration and therefore a governance flag; regeneration keyed to
the bundle so a template change cannot silently leave a stale evaluator behind
(the unit test added here is the cheap version of that guard); and a per-file
split discipline, since one component of 803 instructions already needs two
files under the 850-line ceiling and `partial_ec_mul_generic` has 18,128.
i-cache is **not** the risk it was assumed to be — components run one at a time
and the largest hot body here is 26 KB against 192 KB of L1I. The real cost is
maintenance surface: 64 K lines of generated Zig for ~1% of prove time.

**It should not be done.** Not because it does not work — it works, it is
byte-exact, and it is 1.24x on the loop in isolation — but because 1.0094x on
prove does not justify 1.33 MiB and 64 K generated lines, and because the same
measurement points at a lever with several times the headroom for none of the
surface.

### Where this leaves the composition lane

The implementation is preserved at `bf2fca42` and reverted immediately after,
per the rejection protocol. `src/` returns to bit-identity with `efe4bef3`.

The redirect is specific and it is the increment's real output. The composition
loop spends **72% of its machine instructions inside `PackedQm31.mul`**, at 139
multiplies per four-row group. Two levers act on that, and neither is codegen:

1. **A cheaper QM31 product.** The current one is 16 M31 multiplies. Karatsuba
   at both levels — three CM31 products instead of four, each three M31
   products instead of four — is **9**, a `1.78x` cut on 72% of the instruction
   budget, worth ~1.4x on the loop if cycles follow instructions at all (and
   this increment's own evidence is that they follow at roughly half rate, so
   call it 1.2x on the stage, ~1.04x on prove). It is a change to one function
   in `simd_evaluator.zig`, it benefits the interpreter and any future compiled
   body identically, it needs no admission machinery, and it is byte-exact only
   if the reassociation is proved to preserve canonical representatives — which
   is the one real risk and is checkable at S1 in minutes.
2. **Fewer QM31 products per group.** 132 of 493 extension instructions are
   `secure_col` repacks and 110 are adds; the multiply count is 107. Whether
   constraint-level factoring can share sub-products across the 32 roots is an
   algebraic question about the AIR, not an implementation question, and it is
   the only lever identified in this campaign with more than ~1.1x in it for
   the stage that is now 20% of memory-7m's prove.

Increments 5, 6 and 2.3 have between them closed the entire "make the
interpreter cheaper" family with three measurements. The composition stage's
remaining cost is the field arithmetic, and the next attack on it has to be
arithmetic.
