# Session 01 — increment 2.1, preprocessed tree-digest artifact

Implementation model: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, predecessor `c936e430` (clean).
Host: Apple M5 Max, 12 performance + 6 efficiency cores, `uptime` load 2.9-6.3
throughout (a loaded host, not a quiet one — see the noise note at the end).

## Reasoning: what the audit had to rule out before any code

The brief allowed a negative audit, and there were two ways this could have
died. The first: decommitment needing leaf-level state that the recomputed
column evaluations do not provide. The second: substitution requiring the PCS
to hand ownership of the tree to someone else.

Both dissolved on reading, and the reason is a design decision that predates
this campaign. `MerkleProverLifted(H)` holds `layers: [][]H.Hash` and an
allocator, and nothing else — `src/prover/vcs_lifted/prover.zig:21-54`. The
decommitment traversal is written against a *reader contract*
(`src/prover/vcs_lifted/decommit.zig:345-352`): declare `maxLogSize`, declare
`readHashes` or `readHashesBatch`. Column values arrive as a separate function
argument and the queried values are read straight out of them
(`decommit.zig:61,76-91`). So the tree contributes sibling hashes and node
values only, and the "tree state decommitment needs later" is exactly the
digest array — which is exactly what the artifact would hold. Nothing else is
retained: no index map, no hasher state, no leaf-to-column mapping.

That reader contract is also why device-resident trees work today, and it is
what makes the artifact idea coherent rather than a hack: the tree is *already*
an opaque hash oracle to everything downstream of the commit.

## Reasoning: finding the substitution point

I initially expected to patch `scheme.zig:319`
(`BackendCommitmentTree.initOwnedWithBacking`, which calls `B.commitMerkle`).
That would have been wrong. The Cairo preprocessed commitment has 161 columns
for `canonical_small`, and `streaming_column_threshold` is 128
(`scheme.zig:162`), so the commit dispatches to the *streaming* path at
`scheme.zig:231-250`.

The predecessor profile corroborates this independently rather than by reading:
161 columns at batch size 64 (`scheme.zig:157`) is three batches, and the
profile shows exactly three `interpolate_columns` / `evaluate_extended_domain`
pairs under `preprocessed_materialize_and_commit`. That is the kind of
cross-check worth doing before writing code against a path you inferred.

The streaming path's tree comes from one statement,
`src/prover/pcs/tree_builders.zig:283`:

```zig
var merkle = try self.streaming_committer.commitColumnsWithSparseTail(sorted);
```

Everything after it — PCS column reordering, coefficient assembly,
`adoptStreamingCommitment` (identity for a host backend, `B.adoptHostMerkle`
for a device one), `appendCommittedTree` which mixes `tree.root()` — is
indifferent to how `merkle` came to exist. One further check mattered: whether
`addColumnsOwnedIndexed` absorbs column data into the leaf hashers during
batching, which would mean part of the hashing had already happened by the time
we reach line 283. It does not (`tree_builders.zig:236-296` only interpolates,
extends and retains). All leaf and layer hashing is inside the one call. So
skipping it skips the whole 100-126 ms.

## Reasoning: the size problem, and why the integrity digest is chunked

`canonical_small` caps preprocessed columns at log 20
(`src/frontends/cairo/preprocessed/trace.zig:57-59`) and `log_blowup_factor` is
1 (`transaction.zig:29`), so the committed domain is log 21:

- leaves `2^21 = 2,097,152` digests
- all layers `2^22 - 1 = 4,194,303` digests
- payload `134,217,696 B ~= 134 MB`

This is 64x increment 9's artifact and it changes the arithmetic. A single
serial SHA-256 over 134 MB on this host runs at roughly 2 GB/s, so ~65 ms — half
of the 126 ms the artifact is supposed to save. Copying the 134 MB adds another
~13 ms. Verifying nothing would have been the alternative and is not acceptable.

So the trailer is a chunked SHA-256: payload cut into 4 MiB chunks whose size is
declared in the header, each chunk hashed independently, trailer =
`SHA256(header ‖ chunk_digest_0 ‖ … ‖ chunk_digest_k)`. Every payload byte is
covered exactly once under a collision-resistant construction, the chunking is
unambiguous for a given header, and the work parallelises. Measured: the whole
load — 134 MB read plus full verification plus the top-layer re-derivation — is
**12.5 ms**, against an 87-126 ms commit.

That is the one place this artifact's format departs from increment 9's, and
the departure is forced by the size, not chosen for convenience.

## Reasoning: what the load actually verifies, and why it is enough

Three gates, in order:

1. **Exact file size** for the expected shape, then **whole-header equality**
   against the header this loader would have written. The header embeds the key
   itself, the digest width, the domain log size, the layer count, the chunk
   size and a digest over (hasher identity ‖ every committed column height).
2. **Chunked integrity digest**, constant-time compared.
3. **Top-layer re-derivation** (`tree_builders.zig`, `topLayersRederive`): every
   layer of 4096 nodes or fewer is recomputed from the layer below it with the
   real `H.hashChildren`. That is ~8K hashes, microseconds. It catches an
   artifact that passes its own digest but is internally inconsistent — written
   by a different revision, or by a writer that produced a well-formed but wrong
   tree. It deliberately includes the root, which is the value the transcript
   commits to.

Why this suffices: the checks are *availability* guards, not soundness ones. The
only value the channel ever observes from the tree is the root. A tree that
deviates in any byte that matters produces a root that differs, which produces a
transcript the verifier does not reproduce, which fails `--verify` and the
official verifier. A tree whose root is right but whose lower layers are wrong
fails at decommitment verification. There is no path from a bad artifact to an
accepted proof; there is only a path to a failed one, and the three gates exist
to make that failure a silent recompute instead.

## Raw per-sample numbers

Times are `timing.prove_ns` from the run report, ms. A = predecessor
(`c936e430` pristine `zig-out`), B = candidate. Order within a block is
A, B, B, A.

### Reading (b) — cache hit, all-opcodes (headline)

| Block | A | B | B | A | A mean | B mean | ratio |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1138.8 | 1080.4 | 1079.8 | 1176.4 | 1157.60 | 1080.12 | 1.0717 |
| 2 | 1161.6 | 1099.8 | 1177.7 | 1242.4 | 1202.01 | 1138.80 | 1.0555 |
| 3 | 1237.5 | 1107.6 | 1110.6 | 1201.0 | 1219.25 | 1109.11 | 1.0993 |

Paired geomean **1.0754x**, 95% CI **[1.0219, 1.1316]** (t, 2 df on log
ratios). Predecessor 1192.95 ms, candidate 1109.34 ms.
Preprocessed `merkle_commit`: A 87.223 ms, B 15.120 ms (n=3 each).
One distinct proof digest across all 12 proofs:
`79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`.

`uptime` load averages across the block boundaries: 3.66, 4.88, 6.25, 5.83.
This was **not** a quiet host. The interval is correspondingly wider than
increment 9's and the lower bound, 1.0219, only just clears the 1.02x bar. The
mechanism evidence — an 87 → 15 ms span collapse whose 72 ms matches the 84 ms
paired prove delta to within host noise — is the stronger of the two claims.

### Single-run mechanism confirmation (before the paired series)

Cold, first run in an empty cache directory:

```
preprocessed_table_build              104.181
  preprocessed_table_cache_load         0.008
  preprocessed_table_cache_store        1.853
preprocessed_materialize_and_commit   129.316
  interpolate_columns  0.509 / 0.497 / 9.043
  evaluate_extended_domain  0.238 / 1.577 / 14.964
  merkle_commit                       100.789
    preprocessed_tree_cache_load        0.034   (miss: file absent)
    preprocessed_tree_cache_store      12.911
```

Warm, both artifacts present:

```
preprocessed_table_build                1.024
  preprocessed_table_cache_load         1.024
preprocessed_materialize_and_commit    41.534
  interpolate_columns  0.464 / 0.410 / 9.120
  evaluate_extended_domain  0.229 / 1.386 / 14.208
  merkle_commit                        13.801
    preprocessed_tree_cache_load       12.490
```

Both proofs `79ae76e1…`. Note the 36 ms of interpolation and extended-domain
evaluation is unchanged between the two, exactly as designed — later stages
consume those evaluations and they are still computed on a hit.

Artifact on disk: `134 MB` tree-digest file plus the `2.1 MB` table file from
increment 9, in the same directory, distinguished by extension and by key.
