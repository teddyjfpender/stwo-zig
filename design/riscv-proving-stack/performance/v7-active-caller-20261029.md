# V7 finite active caller layout

The pre-code choice follows the earlier caller census and the message proposing
an independently count-derived finite roster. This note records that choice;
implementation and qualification status below must remain separate.

Task and semantics: preserve the actual SHA/Keccak/recovery arithmetic and every
open program, register, word-memory and lookup relation while removing execution
AIRs whose independently admitted call count is zero. Never reuse an old key.

Inputs and scale: the 20,495-cycle streaming fixture has two SHA calls, one Keccak
call and zero signer calls. Ten zero-active signer AIRs contribute 4,001 main and
2,512 interaction columns, but only 13,086 raw cells. The byte provider is not one
of those ten: its 256 fixed table rows remain required until demand analysis
establishes otherwise. See the companion streaming receipt and component TSV.

Canonical match: liveness-based dead-component elimination with stable compaction.
LLVM's [global DCE](https://llvm.org/docs/Passes.html#globaldce-dead-global-elimination)
provides the dependency-closure pattern (sourced), not a STARK soundness theorem.
Here the exact variant has 19 fixed nodes and a four-case independently derived
predicate. Admission and proof obligations, not a compiler heuristic, establish
that the ten removed execution nodes have zero demand (derived).

| Candidate | Relationship | Guarantee and fit | Risk |
|---|---|---|---|
| Finite zero-signer specialization | Exact restricted specialization | Keep byte and five SHA components; zero Keccak also omits its exclusive chi/xor providers; stable compaction in linear column count | Original constructors must see correct offsets |
| Generic dependency-graph pruning | Broader algorithmic reduction | Potentially prune zero SHA/Keccak too | Zero-call SHA has nonzero padded claims; requires additional theorem |
| Row packing alone | Alternative | Reduces rows, leaves thousands of recursive columns | Misses observed dominant recursive width |

Selected transfer: original typed constructors and original projection equations,
with independently derived placements and selected columns. Keep all physical
claim frames, including mandatory zero frames for omitted components. Remove only
zero-signer and zero-Keccak lookup projection slots. Keep byte and all five SHA AIRs, all
external-memory equations, and shared epoch challenge ordering. New B7AL/B7AC version-2
identities bind the layout; current full caller protocol is unchanged.

Complexity: deriving the 19-node mask is constant work; compaction copies O(C)
column headers and O(C) log metadata, not cells. The initial implementation still
constructs full raw arithmetic witnesses/interactions before selecting columns;
it eliminates their commitments and verifier columns, not yet all setup work.

Prediction (derived): zero-signer arithmetic main width falls 6,732 to 2,731 and
interaction width 7,508 to 4,996 for the measured mixed caller. Recovery without Keccak also omits the zero-Keccak components. Recursive runtime
gain remains a hypothesis until measured; the finite keys and parents below are
now qualified at diagnostic security. Falsifier: the genuine STARK or internal relation
closure fails, or recursive width saving is offset elsewhere.

Validation: actual SHA-only, Keccak-only, recovery-only and mixed caller proofs;
fresh fixed-root verification; original quotient equations; signed global export
closure; omitted active family, omitted nonzero physical sum, root and cancelling
claim attacks. Canonical recursive integration is a later explicit qualification.

The first signer-only original proof gate passed all five workloads. Before the
final differential gate, the explicit layout/source version advanced to 2 to add
zero-Keccak omission; no version-1 proof is relabeled. SHA zero-call padding stays
proved. Original lookup projection `n_rows` is padded domain size, so omission
checks the independently admitted caller descriptor live row count instead.

## Qualified original proof result

The final version-2 ReleaseSafe gate passes all 11 tests, including five actual
executed workloads. Producers are destroyed, the STARK is serialized/deserialized
through canonical postcard, and fresh independent fixed-root verification runs.
Every retained physical sum is transcript-bound. Malicious omitted/compensated
claims and self-consistent forged fixed-root/epoch metadata are rejected.

| Workload | Original main | Active main | Original interaction | Active interaction |
|---|---:|---:|---:|---:|
| SHA only | 6,732 | 525 | 7,508 | 824 |
| Keccak only | 6,732 | 2,731 | 7,508 | 4,996 |
| Recovery only | 6,732 | 4,526 | 7,508 | 3,336 |
| SHA + Keccak | 6,732 | 2,731 | 7,508 | 4,996 |
| Recovery + Keccak | 6,732 | 6,732 | 7,508 | 7,508 |

These are arithmetic trace widths, excluding the separate integer-access and
fused-relation columns. SHA-only is 12.82× narrower in main columns and 9.11× in
arithmetic interaction columns; neither is an end-to-end timing claim.

The mixed case proves both the original full layout and the new active layout
under one shared epoch. Every exported global sum and census agrees exactly.
Original OODS samples fall from 49,804 to 32,547 (34.65% fewer). The check does not
compare proof bytes: these are intentionally different protocols/geometries.

Evidence: `vectors/reports/block-v7-caller-active-20261029/results.tsv`,
`original-proof-gate.log`, and `receipt.json`. Security in this focused gate is
q=8, PoW=0. No complete execution or recursive root is claimed. Existing complete
receiver remains on the original full caller protocol. Next required work is
independent selected-family recursive admission/composition/transcript/key and
parent verification before explicit global receiver adoption.


## Qualified recursive parent result

All five actual caller families now produce independently keyed recursive parents
at q=8, PoW=0. The same compile-time verifier implementation serves full and
active protocols; public namespaces and fixed-key identities remain distinct.
All 19 claim frames remain public, and omitted physical and aggregate claims
receive explicit circuit zero constraints. Cold and live fixed rows, namespace
wires and context match exactly. Parent proofs pass fresh detached verification.

| Workload | Composition DAG nodes | Recursive arithmetic rows | Parent bytes |
|---|---:|---:|---:|
| SHA only | 37,797 | 104,246 | 135,186 |
| Keccak only | 175,177 | 462,529 | 147,428 |
| Recovery only | 121,464 | 382,987 | 142,123 |
| SHA + Keccak | 195,060 | 518,226 | 149,644 |
| Recovery + Keccak | 278,732 | 796,498 | 154,955 |

These are measured circuit/proof sizes, not timing ratios or complete block
results. See `recursive-results.tsv`, `recursive-parent-gate.log` and
`recursive-receipt.json` in the same evidence directory. The source version is
still B7AL/B7AC v2; parent/public identities use a separate B7Z namespace.

## Bounded execution integration

`Options.active_callers` selects the new protocol explicitly; the old route is
still the default. The active checkpoint stages raw arithmetic cells and the
three compact fixed/main/access trees, including their original coefficients.
The next caller can then reuse the host budget. After the common epoch is sealed,
one caller is restored at a time without interpolation or Merkle recommitment.
Raw access views and counter snapshots are reconstructed from staged arithmetic
cells. They are producer material, never admission evidence. Both raw and PCS
bytes count against the aggregate checkpoint cap before publication.

Independent original, mixed-public and recursive-key receivers select the new
layout from counts; they never reinterpret a full-caller receipt as active. The assembled original-proof route now freshly verifies both the 20-cycle,
three-segment fixture and the exact 20,495-cycle, two-segment workload. The latter
has 8,293 RAM events and 20,496 ROM fetches and uses six original proofs. Its
checkpoint files are deleted before receiver and metadata admission. Evidence is
in `streaming-results.tsv` and `streaming-receipt.json`.

These diagnostic shared-host runs recorded 6.57 seconds for the small active
source flow and 8.76 seconds for the larger one, with charged allocator peaks of
126.54 MB and 167.46 MB respectively. These are not controlled performance
comparisons or whole-device RSS measurements. Keeping original coefficients
raises caller checkpoint storage from 5,521,176 to 6,164,400 bytes for this
workload; the optimization is narrower proof geometry and no recommitment, not
smaller checkpoint files. Complete mixed recursive-root qualification remains a
separate gate; standalone caller parents do not establish execution closure.


The checkpoint parity gate also passes 10 tests: SHA-only and SHA+Keccak restore
the staged raw witness and all three original trees with coefficients, then
produce byte-identical canonical original STARKs and physical claims. The fresh
verifier accepts them. Changed active entry identity, insufficient allocation
budget and a noncanonical field payload fail closed. See
`checkpoint-parity-gate.log` and `checkpoint-receipt.json`.
