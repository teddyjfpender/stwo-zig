# Current OM31 services recursion readiness

The services route proves a complete Ethereum block natively, but its current
OM31/local-GKR statement does **not** yet have an accepting recursive leaf.
The existing recursion lane and small OM31 numerical circuit are useful shared
infrastructure; neither is a qualification of this new complete leaf. The
beta-2/q256/P0/fold4 profile remains an engineering candidate, not a certified
128-bit protocol.

## What is implemented

| Authority | Current coverage | Remaining seam |
|---|---|---|
| `logup_gkr/om31_circuit_verifier.zig` | Actual shared numerical GKR verifier, guessed proof wires, raw-mod OM channel, all eight coordinates; small terminal/pole/mutation fixtures | Production child scope/receipt, physical column terminal binding and independently admitted topology |
| `rv64_recursion/om31_circuit_lane.zig` | OM arithmetic over two QM circuit wires using shared quadratic authority; inverse/error-latch gates | Complete services leaf composition |
| `word16_global_execution/services/gkr_local/binding.zig` | Shared native/packed/circuit-capable projection and Eq/prefix residual algebra | Connect authenticated PCS masks and actual child marginal/point wires in the complete leaf |
| `rv64_recursion/leaf_wrap.zig` | Existing native-QM31 execution leaf and fold machinery | Current services schema7, OM31 PCS/DEEP/FRI and ordered manifest/global claims |
| `logup_gkr/circuit_cost_main.zig` | Real QM mini-AIR numerical/binding fragment on native-authenticated values | Its codec, field, statement and transcript are the old protocol; it cannot consume current OM services files |

A native-fresh-accepted proof is evidence about the native receiver. Guessing
its roots, OODS values or digest into a circuit does not authenticate them by
itself. No fragment below exports acceptance or a substitute recursive proof.

## Actual current topology and bounded numerical cost

The new `scripts/rv64_om_recursion_readiness.py` reads the actual bounded
`RV64MGK1` manifest and each `RV64LGKO` child. It checks framing, order, child
kind, lengths and canonical eight-coordinate values. It preserves exact
polynomial coefficient-vector lengths, including empty/short vectors. It does
not verify field claims or accept execution. Source hashes pin the literal
numerical cost authority and reject an unreviewed source change.

| Numerical GKR kernel only | One real control CPU prefix | Full real beta-2 block |
|---|---:|---:|
| CPU children | 1 | 25 |
| Instances | 18 | 477 |
| OM multiplication calls | 18,428 | 462,151 |
| OM addition calls | 10,673 | 268,382 |
| OM subtraction calls | 7,392 | 184,234 |
| Equality checks | 351 | 8,775 |
| Raw-mod secure draws | 403 | 10,075 |
| Blake compressions | 3,098 | 78,600 |
| Blake G invocations at 80/compression | 247,840 | 6,288,000 |

These are **literal algorithmic counts, not circuit gate counts or time
estimates**. Horner's zero accumulator is counted; a circuit builder may fold
constant operations. Each OM draw consumes one 37-byte hash, without rejection.
Each `mixFelts(n)` hashes the 32-byte prior digest plus `32*n` bytes, including
its terminal block. The cost excludes child initialization/challenge catalog,
receipt hashing, eta, manifest, binding and PCS. Root closure adds 1,908 OM
multiplications, 477 additions, 502 equalities and 477 independently constrained
inverse hints across the block. These are separately reported rather than
silently included in the numerical verifier count.

The full beta-2 declarations exactly match the source-derived 30-worker layout
roster in the report. Across all workers the committed column counts are
3,778 FIXED, 24,040 MAIN, 25,296 INTER and 512 composition columns. The lifted
leaf exposure is 53,626 base words per query summed across proofs. At a
receiver-selected 256 queries this is 13,728,256 nominal base-word query slots
before duplicate-query/path sharing; it is **not** serialized proof size or an
exact Merkle gate count. OODS exposure is 63,041–99,109 secure values (CPU bounds;
truth counts exact), each with eight base coordinates. Each Keccak truth alone
has 13,806 OODS secure values. Native cell savings must not be mistaken for
matching recursion savings: lifted width, masks and query count determine much
of the leaf verifier work.

## Required complete-leaf gates

1. Freeze receiver-owned field/profile, shapes, query/FRI schedule and resource
   limits. Admit topology before allocating/wiring producer-controlled lengths.
   The old four-coordinate `native_verifier.Shape` and proof capture cannot be
   relabelled as an eight-coordinate implementation.
2. Replay the actual child scope from statement, ordinal, FIXED/MAIN roots and
   instance roster. Reuse `om31_circuit_verifier`; constrain root poles and local
   closure. Bind all child terminal N/D marginals, suffix points and eta through
   the shared row projection and Eq/carry/anchor authority. No guessed prefix
   digest may replace this transcript chain.
3. Implement complete OM31 PCS, composition/OODS, DEEP, FRI and Merkle
   authentication on the same masks/column order as the native receiver. Keep
   the already separate CPU2n and Keccak-truth4n shapes explicit.
4. Connect every leaf to the ordered stage-one manifest and independently
   derived global challenges. The final receiver must recompute/admit the
   manifest, coverage/adjacency, expected execution endpoints and pure global
   RAM/KIO/Wire closure. Local output cancellation cannot pay global debt.
5. Build an accepting small complete services fixture with CPU+Keccak+
   ADD/DOUBLE, then a real prefix. Mutate each of the eight coordinates, roots,
   masks, terminal marginals, receipt/manifest entries, geometry/profile/query
   declarations, order, public endpoints and global claims. Require rejection;
   retain legacy controls and zero-inverse same-topology tests.
6. Only then measure the complete graph, topology cache, wrap/fold and outer
   receiver. A complete whole-protocol security budget and outer proof security
   remain separate gates; q256 alone does not establish them.

There is no requirement to create a separate recursive proof for numerical GKR
before wrapping the native batch. The intended complete leaf can verify both
inside one graph, sharing the authenticated roots/statement. Moving to native
`prove -> fold` requires a different folding proof-system architecture; these
counts do not establish that design or its cost.

## Reproduction

Run the bounded report against existing artifacts, with no proving or GPU work:

```sh
python3 scripts/rv64_om_recursion_readiness.py \
  --bundle /tmp/stwo-rv64-om-ethereum-fullblock-candidate-v1 \
  --roster vectors/reports/rv64-om-gkr-fullnode-coordinator-20261101/qualified-legacy-roster.json \
  --contracts vectors/reports/rv64-resident-layout-contract-20261102/beta2-contracts.json \
  --output /tmp/rv64-om-recursion-full.json
python3 -m unittest discover -s scripts -p test_rv64_om_recursion_readiness.py -v
```

The checked-in full and prefix reports pin input hashes. Prefix reports without
contracts expose actual declarations and numerical counts, but omit PCS budget
bounds. Historical layout receipts retain their original hash-state memory
model; that unrelated buffer estimate does not affect column/mask exposure.
