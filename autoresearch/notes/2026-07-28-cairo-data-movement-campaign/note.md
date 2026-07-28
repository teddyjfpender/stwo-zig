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
