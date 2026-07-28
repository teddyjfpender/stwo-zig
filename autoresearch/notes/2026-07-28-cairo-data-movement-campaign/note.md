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
