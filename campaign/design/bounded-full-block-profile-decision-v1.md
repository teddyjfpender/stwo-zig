# Bounded full-block profile and next structural changes

The retained CPU baseline was deliberately interrupted after the user's
additional ten-minute observation window. It produced all 107 window roots and
25 of 106 upper folds. It did **not** produce or independently verify a complete
block root. Do not publish its interrupted duration as block-proving latency.

The immutable attempt is
`vectors/reports/riscv-cpu-architecture-20261029/full-block-assembly-v1/retained-139m-native4m-workers16-v1/`.
Its invocation, frozen build, proof files, per-stage reports and CSV exports are
preserved. `analysis/bounded-observation-v1.json` records the stop; the process
ended with SIGINT, and `invocation.json` retains `report_checked=false`.

## Measured work

The run covered 139,214,856 guest cycles in 12 native and 95 mixed windows,
including 32,835 Keccak and 78 recovery calls. Security was 70 queries and
26 PoW bits, with 16 CPU workers and a 60 GiB shared host budget.

| Completed window phase | Seconds | Minutes |
|---|---:|---:|
| Original bundles | 1,323.41 | 22.06 |
| Window wrappers | 6,315.17 | 105.25 |
| Wrapper parent proof generation | 2,743.53 | 45.73 |
| Wrapper parent witness construction | 1,465.58 | 24.43 |
| Wrapper fixed compilation and commitment | 840.07 | 14.00 |
| Wrapper planning | 371.66 | 6.19 |
| Wrapper encoding | 1.40 | 0.02 |
| Other wrapper work | 892.91 | 14.88 |

The detailed wrapper rows partition the enclosing wrapper timer; they must not
be added to that enclosing total. "Other" is a residual, not a separately
measured key-derivation or receiving stage. Sources are
`analysis/completed-window-cost-partition-v1.json`, `windows.csv`, and `stages.csv`.

The 25 completed folds consumed 1,154.07 seconds in total. These are first-layer
folds; they do not measure deeper descendant-key reconstruction. Fold 107 took
48.55 seconds overall, with 13.49 seconds of parent proving and 8.22 seconds of
witness construction. Per-fold source reports remain under `proof/node-*`.

The interrupted process ran for 8,819.11 seconds. `/usr/bin/time -l` recorded
40,771,928,064 bytes maximum resident size and 40,788,842,848 bytes peak memory
footprint. These cover the interrupted process, not an unobserved complete tree.

## Decisions

1. **Reuse independently derived admissions and completed proofs.** The driver
   currently reconstructs descendant keys through the reduction tree. Qualify
   the opt-in immutable cache using saved real roots, fresh mathematical proof
   verification and hostile key/coverage controls. Reuse saved folds only after
   independent verification; never promote file presence or a receipt into
   authority. Keep final full receiving uncached and independent.
2. **Qualify the homogeneous circuit wrapper and fold.** Parent proof and witness
   work alone consume 66.6% of window-wrapper time. Cache-only changes cannot
   remove that work. The new circuit path must verify all typed AIR and PCS
   obligations, verify both child circuit proofs, and bind the same statement
   wires to digest, adjacency and coverage. Compare matched phases and memory
   only after actual proofs and fresh receiving pass. Lower column counts alone
   are not a speedup result.
3. **Keep native Word16 lowering secondary to recursion qualification.** Its
   compact source layout is written, but provider/clock/ROM closure, actual
   original proofs and recursive integration remain unqualified. Original
   bundles were only 17.3% of the completed window-production time, so native
   layout work alone cannot address the dominant measured cost.

Do not repeat the complete original/window phase to test these decisions.
Use the preserved artifacts and short representative gates first. A later
resumed full root must report current verification/proving separately from
historical production, and cannot be presented as a fresh full-block benchmark.

Receiving still requires large public checkpoint data and statement-dependent
keys. This campaign has not established a universal fixed-key, bounded-input
receiver or Ethereum consensus validation beyond the pinned guest program.
