# Direct original circuit window: bounded architecture decision

The old full-block baseline was deliberately interrupted. It produced all 107
window roots and 25 of 106 upper folds, not a complete block root. The existing
22.1 minutes of original proofs, 105.3 minutes of window wrapping and 19.2 minutes
of completed upper folds are accumulated work, not a complete-block latency.
No new long baseline is needed to identify the dominant wrapper cost.

## Architecture implemented

`src/integrations/circuit_cpu/riscv_originals_v1/` verifies the original execution,
bridge and compact RAM STARKs in one circuit context. The exact existing join DAG
binds actual authenticated endpoint-root variables, physical public claims and
CPU boundary words. A domain-separated ORIGINAL_JOIN statement commits the
ordered original roster, closure program and execution span. Receiver factories
reconstruct all original profiles from the external ELF and checkpoints.

This path produces no intermediate NativeParent proof. It is different from
putting a circuit wrapper after an already expensive NativeParent proof.
The homogeneous circuit fold now recognizes ORIGINAL_JOIN leaves, retaining
CPU/snapshot adjacency, ordered coverage and independently selected full-input
and terminal-output policies. Its direct-leaf proof qualification is separate
from the already qualified old wrapped-leaf fold.

## Authoritative evidence

- `campaign/qualification/new-direct-original-window-context-v1/`: a saved
  nonterminal six-cycle SHA/Keccak fixture passes both QM31 and independent
  NoValue construction, strict finalization, preprocessing multiplicities,
  and changed commitment/sample/CPU controls. The joined context has 71,303,168
  padded variables and 8,388,608 padded BLAKE3 G gates. Independently padding
  those three sources required 92,995,584 variables and 13,107,200 G gates.
- `campaign/qualification/new-direct-original-native-context-v1/`: saved initial
  four-cycle, middle two-cycle and terminal one-cycle originals pass the same
  direct join's assignment checks. This gate constructs circuits, not proofs.
- `campaign/qualification/new-direct-original-window-q70-v1/`: genuine direct
  mixed-window STARK and independent fresh receiving at 70 queries / 26 PoW bits;
  root 1,113,224 bytes, SHA256
  `af0da006af56f4f7336e9a1ff87438f4fc4f5ce7a7e93662c7b2a3ac216b08c0`.
  The original proof expansion, producer circuit and producer key are gone
  before fresh receiving reconstructs its key from metadata.

The actual proof gate used ReleaseSafe and one worker. Production took
139.907 seconds: 0.185 s admission, 0.445 s material, 16.013 s key construction,
2.459 s witness, and 120.805 s proving plus serialization. Fresh receiving took
16.817 s. The entire test gate, including repeated context controls, took
162.63 s and peaked at 38.44 GB RSS. These are fixture qualification costs;
there is no like-for-like production speedup claim or complete-block estimate.

## Decision

The direct path is functionally real, but its current cost does not establish a
10x improvement. Do not repeat the full block on this circuit unchanged. First
qualify a small complete direct-original execution chain and its fresh wire
receiver. Reuse the saved originals for the block-level consumer rather than
rerunning execution or wide witness production.

A concrete next structural target is repeated PCS quotient arithmetic. The
saved mixed source has 28,557 response terms and 70 queries, currently requiring
1,998,990 separate denominator calculations/divisions in the circuit. The native
verifier already groups terms by their canonical opening-point offsets. The
circuit should preserve the original beta ordering and all nonzero guards while
sharing those point/denominator computations. An exact geometry census and
parity control must precede any performance or soundness claim.

Still incomplete: a direct-original initial/middle/terminal proof reduction,
the retained 139,214,856-cycle independently verified single root, and a complete
phase/memory profile. No GPU or full-block speedup is established here.

## Complete small-chain proof qualification

The direct ORIGINAL_JOIN initial/middle/terminal chain subsequently passed at
q70/PoW26: three genuine original bundles, three direct circuit window proofs,
two binary circuit folds with odd carry, one 981,000-byte root. Producer keys,
materials and serialized child proof artifacts were destroyed before the new
version-2 catalog was decoded and a fresh full input/output receiver verified
that root. Root SHA256:
`b4271fd8794c68081a6af81564f281a9ce7d578e654dd711f63d61a1b84b15e9`.

Evidence: `campaign/qualification/new-direct-original-native-fold-q70-v1/`.
The complete qualification gate took 180.51 s, four workers, ReleaseSafe,
18,264,424,448 bytes RSS peak. Fresh serialized full receiving took 11.639 s.
Each direct window's separate admission/material/key/witness/prove+serialize
partition is retained in `window-{0,1,2}.times.json`. The three production totals
were 20.353, 22.838 and 20.371 s; proving plus serialization was 17.154, 19.616
and 17.092 s respectively. These are seven-cycle fixture results, not a
full-block extrapolation or a controlled comparison against another backend.

The exact saved mixed-source quotient census is now recorded in
`campaign/qualification/new-direct-original-quotient-census-v1/`: mixed
28,557 responses / 16 groups, bridge 44 / 2, compact memory 173 / 3. At 70
queries that changes 2,014,180 repeated divisions to 1,470 structurally shared
ones. The grouped implementation remains isolated and unqualified at this
checkpoint. BLAKE3 G work is unchanged by quotient grouping.

## Actual retained mixed-window geometry

The independently pinned retained window 4 census passed in 4.21 s / 428 MB RSS.
It covers 1,048,576 instructions, 507 Keccak calls and 66 recovery calls, using
external checkpoints at cycles 24,641,536 and 25,690,112. It reads no original
proof bodies and performs no proving or proof verification.

Its mixed original has 15,314 columns and 39,540 OODS samples. The caller MAIN
(tree 6) and caller arithmetic interaction (tree 12) account for 6,402 + 6,688
columns and 22,644 + 13,376 samples: 85.5% of mixed columns and 91.1% of its
samples. Tree roles follow `block_v8_endpoint_mixed_proof_v1.zig`'s explicit
commitment order. Component-level attribution within those two caller trees
still needs inspection; these totals alone do not identify one guilty kernel.

The actual mixed response census is 47,760 terms but only 19 distinct geometric
opening points: 3,343,200 divisions become 1,330 with structural batching. Across
mixed/bridge/compact, 3,358,390 become 1,610. These are operation counts, not a
measured timing improvement. Reducing the caller layout's column/sample cost
is a separate major architectural target because denominator batching leaves
BLAKE3 opening work unchanged.

Evidence: `campaign/qualification/new-direct-original-retained-window4-census-v1/`.

The component census now attributes Keccak specifically: 2,204 MAIN columns,
4,164 arithmetic-interaction columns, 18,750 samples (47.4% of the mixed
original's samples). Its 507 calls occupy 254 paired slots, 29 rows per slot,
7,366 live rows padded to 8,192. Those two trace families contain 52,166,656
M31 cells (199 MiB before other proof allocations). The rounds are ALREADY
sequential. A proposed narrower layout must serialize lanes/bitpositions or
factor input/output constraints; claiming a gain merely by unrolling fewer
rounds would be wrong. Interaction columns are another major cost: 2,082 event
ports form 1,041 secure batches represented by four columns each.

The read-only component table and source references are preserved in
`campaign/design/retained-window4-caller-architecture-v1.json`. Transposition
figures in that file are capacity models only. New inter-row state, shuffle,
lookup and call-boundary constraints must be designed and qualified; no narrow
Keccak implementation or corresponding timing improvement is claimed.

## Grouped path and original-only driver: actual proof results

The grouped path is now active only in the direct-original verifier. Its key
identity uses version 2 and the GDP1 layout marker. The existing standalone PCS
and historical NativeParent wrapper retain their prior opening law. Four
separate algebra gates compare native, ungrouped and grouped answers, including
periodicity, heterogeneous logs, duplicate queries, nonzero guards and strict
QM31/NoValue preprocessing. Their separate test root discovered and passed all
four named gates; importing a module through another dependency had not been
sufficient to run them.

The complete saved mixed source proof then passed fresh q70/PoW26 receiving.
In the single-worker ReleaseSafe pair on the same original fixture:

| Measurement | Ungrouped | Grouped |
| --- | ---: | ---: |
| Proving plus serialization | 120.805 s | 57.312 s |
| Producer total including key/witness | 139.907 s | 64.503 s |
| Fresh receiving including independent key rebuild | 16.817 s | 5.777 s |
| Charged peak allocation | 38.423 GB | 20.790 GB |
| Padded variables | 71,303,168 | 46,137,344 |

Padded QM31 arithmetic falls from 33,554,432 to 8,388,608, and equality rows
from 4,194,304 to 131,072. BLAKE3 G gates stay at 8,388,608. This is a single
attributable diagnostic pair, not a median or a full-block speedup claim.
Proof bytes and keys differ intentionally because the circuit topology changed.
The new 981,000-byte mixed root SHA256 is
`adc6e2d46f26d247dc24cf6270696484a064cd7d245e4d3d397b50802a3d4edd`.
Evidence and machine-readable comparison:
`campaign/qualification/new-direct-original-window-grouped-q70-v1/`.

The actual block driver also passed using an input directory containing ONLY
original bundles, with neither old parent public metadata nor old parent
proofs. It reconstructs and publishes canonical thin metadata directly from
originals, then produces three circuit windows, two folds, and a freshly
verified complete seven-cycle root. Driver time is 169.692 s, comprising
65.042 s window production, 7.362 s per-window fresh receiving, 85.858 s fold
production including internal fresh receiving, and 11.313 s final fresh full
receiving, plus preflight/publication overhead. The original wide proof times
are explicitly excluded. The 981,000-byte root SHA256 is
`333136dc08443be90d50280e4c7dbaada8ee1b64ea4d27707cbb3a69e05ef1e8`.
Per-node phases, 220 nested stage records, proof hashes and artifact validation
are retained under
`campaign/qualification/new-direct-original-block-driver-grouped-q70-v1/analysis/`.

The complete retained 139,214,856-cycle root is still unproduced. Its next
bounded qualification is an actual retained one-million-instruction mixed
window, not another tiny-fixture extrapolation. No full-block run was launched
for these decisions.
