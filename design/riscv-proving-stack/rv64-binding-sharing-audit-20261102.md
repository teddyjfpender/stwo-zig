# Local GKR binding sharing: source-derived audit

Authority: `4d9aafacd`, especially `services/gkr_local/{binding,witness,frame,role_geometry,role,table_role,roster,cpu_components}.zig` under `src/integrations/riscv_cpu/word16_global_execution/`. Instance heights come from CPU0 of the complete retained K18 bundle; its exact hash and geometry are recorded in `vectors/reports/rv64-binding-sharing-audit-20261102/accounting.json`. This is architecture/accounting, not implemented protocol or measured speedup.

Every proof-local instance currently commits **16 base columns: eight OM31 Eq coordinates and eight OM31 prefix coordinates**, regardless of its relation count. Each has two masks per column, or32 OM31 samples before PCS deduplication. Ordinary CPU/arithmetic/table roles use those16 local columns. LS adds16 global RAM columns; Keccak bridges add32 global columns; secp bridges add56. Public INIT/TERM are global-only and carry no local GKR binding. REG and OWNER already belong to local GKR; the shared namespaces are RAM, KIO and Wire.

| Role | Local fractions | Padded lanes | Eq / prefix columns |
|---|---:|---:|---:|
| CPU |15|16|8 /8|
| ALU |13|16|8 /8|
| BINARY |9|16|8 /8|
| SHIFT |11|16|8 /8|
| LS |10|16|8 /8|
| JALR |3|4|8 /8|
| MUL |97|128|8 /8|
| DIV |26|32|8 /8|
| ROM / U16 / U8 / AND |1|1|8 /8|
| Public REG boundary / selection |2|2|8 /8|
| SHIFT table |16|16|8 /8|

The extension coordinates are not generally redundant: verified GKR row challenges and eta live in full OM31, and their products span all eight base coordinates. Dropping the upper half would change authenticated algebra and is not a valid compression. However, `Frame.splitPoint` takes a deterministic suffix of the common verified GKR point. Instances sharing **both row_log and lane_log** consequently have exactly the same row Eq vector. Same row height alone is insufficient.

CPU0 has144,052,736 local binding cells (576,210,944 bytes). Sharing only exact duplicate Eq vectors saves13,631,488 cells (54,525,952 bytes), **9.46% of local binding, about3.25 cells per retirement**. Duplicate classes are ALU/BINARY/SHIFT at log19/lane4, their BINARY/SHIFT/LS tails at log18/lane4, ALU-tail/SHIFT-table at log16/lane4, and U16/AND at log16/lane0. This is useful but cannot justify a large holistic multiplier. A physical implementation would need receiver-derived class identities, one Eq owner and recurrence authority per class, explicit per-role references, unique PCS geometry and admission accounting. Cross-height reuse is not implied.

Sharing prefixes across several same-height instances is a larger protocol change. Their individual terminal marginals must first be fixed, followed by fresh independent batching weights (or a bounded-degree powers challenge) before the INTER commitment. A shared prefix could then authenticate the random weighted sum of their original residuals. Without that late randomness, errors could cancel across instances. The additional batching error belongs in the whole-protocol ledger; masks, transcript and recursion authority change. The sum of degree-two projections times Eq remains degree at most three, but this must be proved per family and mixed geometry. Lifting all providers to CPU log22 would violate independent sizing and can erase the native-cell saving.

Fixed table values do **not** make their bindings free. ROM/range/AND/SHIFT/selection provider numerators contain mutable committed multiplicities. The receiver can derive fixed denominator data, but must still authenticate the numerator MLE against MAIN. Replacing the role with a producer-declared count or unchecked target is unsound. The wholly public32-row REG boundary is different: its64 raw facts can be evaluated by the receiver and its local debt closed explicitly, potentially removing its tiny512-cell binding. That does not generalize to mutable providers.

Deferred stage-one projected storage is a separate, compatible lifetime optimization: retaining only eight unweighted N+etaD planes until stage two can halve barrier binding retention without removing the final16 authenticated columns. Its overlapping restoration/admission and failure ownership require their own qualification; it is not a claim that half the AIR coordinates are redundant.
