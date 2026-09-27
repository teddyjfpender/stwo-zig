# Shared immutable hash plans and topology census

Two related sources of repeated witness/preprocessing work were found:

- Routed frame construction built the same hash DAG for routing, row geometry
  and hash emission. Memory leaves also rebuilt it for witness emission.
- Row sizing invoked complete trusted frame/row emission for every sparse-tree
  node, discarding every row except its count.

Hash witness entry points now accept a borrowed canonical length-owned Plan.
The ordinary wrappers still construct their own plan and use the same writer.
Frame routing, row sizing and emission share one plan. Sparse-tree emission
reuses its existing leaf and node plans across all corresponding nodes. Input
length is checked before borrowed-plan emission; no witness values or digests
are retained in the plan. Plans remain caller-owned, with no global cache.

The census sink has an explicit count operation. Shared sparse-tree census takes
row widths/counts from canonical trusted leaf and node preparations, walks the
same admitted topology, and accounts for frontier producers and the final root
sinks. It does not instantiate every node's G/XOR rows. Live or fixed emission
continues through the original canonical row producers. Sizing skips digest
and fanout scratch arrays used only for actual emission.

ReleaseSafe qualification: ordinary commitment assembly checks optimized counts
against independent complete trusted/live emission and rejects a mutated plan;
5 hash tests and 1 routed-frame witness test pass. These include row/digest parity
for borrowed plans across empty messages, blocks, chunks and unbalanced trees,
wrong-length rejection, direct-column layouts, and allocation-failure cleanup.

`measure.py` compares frozen preceding products against the candidate with
canonical 70 queries / 26 PoW bits, 16 workers and three samples per arm. All
retained proof hashes must match the prior suite and pass fresh verification.
Both ReleaseFast builds passed. All 48 measured proofs verified in process; all 16 retained arm artifacts independently verified and match preceding proof hashes.

## Complete-transaction medians

| Case | CPU control → candidate s | Metal control → candidate s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.171250 → 1.143680 | 1.973087 → 1.892300 |
| sha256-128 | 2.894887 → 2.717680 | 3.039789 → 2.855889 |
| sha256-2048 | 5.205837 → 5.052357 | 5.448285 → 5.269701 |
| keccak-128 | 5.077804 → 4.849863 | 5.067962 → 4.801889 |

CPU Keccak witness medians: 1.105091 → 1.003268 s; admission: 0.434775 →
0.351834 s. Metal Keccak witness: 1.131274 → 1.008346 s; admission:
0.445929 → 0.360471 s. Setup savings are material in those phases but total
improvement is modest. Three fixed-order samples do not establish small changes.
These targeted results do not replace the full CSP suite, and original performance
remains unrecovered.

The first parent command selected the execution-commitment root, which does not
contain this test. Its empty-selection guard failed (`canonical-parent.log`);
that is not successful qualification. The corrected statement-codec root passed in `canonical-parent-qualified.log`.
Both child and parent used 70 queries / 26 PoW bits, with independent verification.
The parent retained its fixed plan through worker rekey, replayed the transcript,
and produced an 850,599-byte artifact; the child artifact was 494,897 bytes.
Worker peak was 15,001,575,082 bytes under its 24 GiB cap. This two-worker functional
test is not a matched recursion performance benchmark.

## Remaining work

Original CSP performance remains unrecovered. Trace commitments still dominate
much of proving time, and witness generation remains roughly one second for
Keccak. Investigate commitment batch sizing/dispatch amortization and further
shared witness costs next. The canonical parent requalification covers the
accumulated shared generator, sampled-value and hash-plan changes for this base
case; it does not establish a 10x recursion gain or repeat all extension parents.
