# Reduce repeated caller width before recursive verification

The independently verified 20,495-cycle canonical B7UF proof contains **34,534
QM31 OODS values; 32,447 (93.96%) are in the caller's four trees**. This identifies
a much larger recursion target than fixed-column deduplication. It is an opening
inventory, not a CPU-time profile or an achieved speedup.

The input is the qualified `q70-contiguous/proof.stark.postcard` under
`vectors/reports/block-v7-complete-union-20261029`, SHA-256
`62f94cd2d70b5f3eba3aae3196047dbc9175957ca7f5daaedc9db9196f338efb`.
The bounded wire reload gate independently verified the same saved original
STARK. The diagnostic parser below grants no verification authority.

| Original tree family | Columns | OODS QM31 values |
|---|---:|---:|
| Caller arithmetic main | 2,731 | 10,971 |
| Caller memory access | 3,552 | 3,552 |
| Caller arithmetic interaction | 4,996 | 9,192 |
| Caller relation interaction | 4,366 | 8,732 |
| All other trees combined | 1,446 | 2,087 |
| **Total** | **17,091** | **34,534** |

The complete tree-by-tree data is
[the TSV census](v7-original-union-opening-census-20261029.tsv).

```sh
python3 scripts/analyze_v7_union_openings.py \
  --proof vectors/reports/block-v7-complete-union-20261029/q70-contiguous/proof.stark.postcard \
  --output /tmp/v7-union-opening-census.tsv
```

## What this changes about priorities

The current multiwindow union shares a STARK shell but still appends each
caller's original column inventory. Identical caller inventories therefore
repeat these 32,447 values per caller-bearing window. Combining the proofs into
one FRI does not remove the original AIR evaluations or openings.

An independent three-window fixed-column census found 62 duplicate fixed
columns among 179, but only 4.51% of fixed LDE cells. Removing those 62 fixed
openings is about 0.18% of the measured total above. That does not justify an
indexed fixed-column protocol redesign as the next large optimization.

The stronger hypothesis is **row-batch calls by arithmetic family across
execution windows**, retaining a bounded number of global caller/provider
inventories. More calls then grow row counts and proof domains rather than
replicating every column and opening. A hypothetical eight callers of identical
shape repeat 259,576 caller openings today; one batched inventory could amortize
that width. This is not a projection of total proving time: padded row domains,
different active families, provenance columns, and memory residency all cost
work. Actual Ethereum caller distribution must be measured separately.

## Required authority boundary

The current caller protocol deliberately binds one execution:

- `block_v7_caller_active_source_v1.Pin` commits `execution_index`, the native
  execution identity, local-clock frame and component inventory. `require`
  checks that exact native entry in the epoch.
- `block_v7_caller_active_schedule_v1` derives memory, program and table
  projections from that admitted statement and one frame. Raw concatenation
  does not preserve this relationship for multiple frames.
- `block_v7_execution_claim_closure_v1.Accumulator` closes state and register
  residuals **per window**, in addition to global RAM/ROM/lookup closure.
- Caller-specific relations are drawn after the caller entry. Existing
  per-caller interaction columns cannot be concatenated and treated as one
  existing proof under different challenges.

Consequently a global caller needs a new explicit protocol/version and a
proof-constrained provenance relation. Each active call must bind its owning
window, bounded local clock, opcode, register operands/results and RAM effects
to the native execution that issued it. A fixed admitted roster maps window
indices to exact execution identities, clock intervals and boundary state.
Ownership cannot come from an unchecked host annotation.

The native-to-caller call relation must preserve per-window state/register
custody. Simply replacing the vector of zero residuals with one aggregate sum
would permit cross-window cancellation where local clocks repeat. Candidate
designs are an explicitly window-tagged relation or a uniquely bounded global
clock representation plus independently constrained boundary ownership. Both
require equation changes and negative tests; neither is implemented by the
current B7UM union.

Original physical claims must remain transcript-bound before interaction
commitment. Global ROM, lookup, RAM first-touch, terminal output and first-halt
closure remain mandatory. Zero-call windows, absent arithmetic families,
duplicate calls, moved calls, omitted owners, substituted identities, crossing
clock bounds and compensating claims must all fail independently.

## Experiment sequence

1. Qualify the existing multiwindow engine with actual calls in at least two
   windows and different active family mixes. A many-window/one-caller fixture
   does not cover this case.
2. Retain exact original proofs as the differential oracle. Record call counts,
   per-family rows, padded cells, memory and opening census before redesign.
3. Prototype the proof-bound ownership relation and one row-batched arithmetic
   family, retaining original arithmetic equations. Close all provider claims
   and verify after destroying producer objects.
4. Compare complete original proofs and their public statements; a changed
   protocol need not yield identical bytes, but no native execution or provider
   obligation may disappear. Measure full preparation/proving/verification and
   allocator/process peaks, including batching and transfers.
5. Expand the batch family mix and separately qualify its recursion adapter.
   Do not advertise the opening-count model as an end-to-end block speedup.

The complementary capacity work is coefficient-backed input PCS storage and
bounded quotient evaluation. Reducing opening width alone does not make all
block witnesses resident at once; eliminating repeated wide storage and proving
work remains necessary.
