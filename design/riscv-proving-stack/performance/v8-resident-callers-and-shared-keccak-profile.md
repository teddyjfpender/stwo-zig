# Resident callers in endpoint cohorts

Status: preparation helpers only; production inactive. Native-only V8 local
originals remain the qualified baseline. These helpers do not qualify mixed
execution, caller halt semantics, a complete block, or a new Keccak profile.

## Minimal mixed original

`block_v8_endpoint_caller_plan_v1.zig` independently derives the existing active
caller arithmetic layout, program/state/table schedules and actual RAM
projection descriptors. Its inventory has no integer/WORD witness columns and
no external-access commitment. `block_v8_endpoint_caller_raw_stage_v1.zig` owns
one actual caller witness and resident selected fixed/main columns under a
shared bounded allocator. It performs no commitment or checkpoint write/read.
The planned halt auxiliary width is accounted for, but those auxiliaries and
their constraints are not implemented by these preparation helpers.

Reuse `block_v8_caller_ram_owner_v1.Owner.initComplete`, its
`CompleteInteractions`, and the original V7 active arithmetic assembly. They
already combine authentic arithmetic with program/state/table/RAM projections
without the old WORD partition. The wrapper currently uses distinct arithmetic
and relation interaction trees. Reusing the existing empty ROM-main tree for
its empty witness slot adds caller-main and two caller-interaction trees to the
11-tree local layout: **14 trace trees**, plus composition. A later explicit
placed-component layout can merge the interaction trees; this is not required
to avoid duplicated proofs.

The mixed source must bind admitted caller counts, semantic/profile identities,
full local clock frame, native external-retirement count and every first root
before challenges. The native layout/preprocessing must receive that admitted
external count. Existing native-only closure must not run before caller claims
are added: state, register and local RAM obligations can cross those partitions.

The new ledger must close these obligations separately:

- public register state + native state + caller state;
- public register memory + native register/clock + caller register projections;
- native RAM + native RAM-clock + caller RAM + endpoint-local plane;
- native and caller program requests + boundary fetch + ROM;
- native and caller table requests + endpoint byte requests + lookup providers;
- caller arithmetic internal relations with their authenticated physical claims.

Every caller RAM access also needs the nonterminal halt-access constraint. An
endpoint-only check cannot reject writing one and clearing it inside a cohort.
The endpoint-global plane remains open, and the existing late bridge must open
exactly the same authenticated 23-column endpoint-main root under the shared
global challenge. The compact global provider then closes the global relation.
No caller-specific companion proof is needed.

## Actual retained Keccak workload

The pinned `keccak-131072` capture starts at cycle 42,700,000 and contains
130,182 native retirements and 890 Keccak calls. Its original caller statement
has log14, 12,905 live arithmetic rows, 2,204 main columns and 4,164 interaction
columns. The raw power-of-two domains therefore contain:

| Inventory | Cells | Bytes at M31 = 4 bytes |
| --- | ---: | ---: |
| Existing Keccak main | 36,110,336 | 144,441,344 |
| Existing Keccak interactions | 68,222,976 | 272,891,904 |
| 50 new RAM projections, 4 columns each | 3,276,800 | 13,107,200 |
| Planned 2 halt auxiliaries per RAM descriptor | 1,638,400 | 6,553,600 |

These are raw columns, not peak process memory or timings. LDE, commitments,
fixed providers, native execution and other projections are additional costs.
The prior V7 retained run wrote a 1,063,136,144-byte caller checkpoint. The
resident design avoids that checkpoint, but its speedup remains unmeasured.

## Next profile: share the large Keccak tables

Current compact tables favor small proofs. Existing throughput and XOR-only
interaction plans preserve execution semantics but change the authenticated
lookup interpretation. Their source-derived per-shard widths are:

| Profile | Chi lookups/round | XOR lookups/round | Permutation batches | Caller batches | Total batches | Interaction columns |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Compact | 1,600 | 320 | 961 | 80 | 1,041 | 4,164 |
| Three-position XOR only | 1,600 | 107 | 855 | 80 | 935 | 3,740 |
| Full throughput | 320 | 107 | 215 | 80 | 295 | 1,180 |

The full profile uses `ceil((320+107+2)/2) = 215` permutation batches.
The XOR-only plan separates `ceil((1600+107)/2) = 854` table batches and one
state-I/O batch. Caller batches remain the same. Thus full throughput cuts
this shard's interaction-column width by **3.529×**, not 4×; this is not an
end-to-end speedup.

The larger tables dominate small instances:

| Table universes | Chi padded rows | XOR padded rows | Total committed table cells (12 columns per row) |
| --- | ---: | ---: | ---: |
| Compact | 8,192 | 1,024 | 110,592 |
| Full throughput | 2,097,152 | 65,536 | 25,952,256 |

The existing source-area model, reproduced in
[the tiled problem match](keccak-tiled-problem-match-20261029.md), selects compact
at 2 and 16 calls, XOR-only at 128, and full tables at 1,024 and 4,096 calls.
For example, at 1,024 calls its raw committed-cell totals are 104,951,808
compact, 98,779,136 XOR-only and 81,903,616 full tables. These are area-model
crossover observations, not measured runtime thresholds.

The production experiment should keep one authenticated large-table provider
across many bounded caller cohorts. Each cohort exports independently framed,
physically authenticated requests under the common table relation; a final
provider proof closes their sum exactly once. This requires a new profile,
transcript/key identities, table census bounds and recursive closure. Larger
tables cannot simply be omitted from local proofs without replacing their
proof obligation. Existing adaptive profiles remain inactive.

## Required qualification

First retain the current compact profile: actual Keccak131K mixed original,
late bridge and compact global provider at 70 queries/26 PoW bits; destroy
producer owners and verify serialized bytes with independent ELF/snapshot
pins. Then repeat on the recovery131K capture. Negative gates must cover an
omitted or duplicate external retirement, changed Keccak +27 output state,
wrong consumed/local clocks, compensated physical claims and transient caller
halt writes. Only after that should the versioned shared-throughput profile
be compared with this complete baseline.

### Common challenge scheduling is a real obligation

Current independent local epochs draw different Keccak lookup challenges. Their
fractions cannot be added and closed against one table provider. A shared-table
profile must explicitly choose one of these strategies:

1. Commit every source in a bounded group first, draw one common lookup relation
   from that roster and the table first roots, then produce each group's local
   original and one provider original. Wide caller roots/coefficients remain
   resident until their originals finish; group size must obey the host budget.
2. Define a conditional local profile whose lookup equations are explicitly
   deferred. A late same-root lookup component proves those equations exactly
   once under the common relation and binds the retained caller-main roots.
   This needs a new component/recursive identity; it cannot simply set old
   claimed sums to zero or accept host-computed request counts.
3. Reprove request fractions under a second common relation while retaining the
   current local interactions. This repeats wide interaction work and is a
   control experiment, not the preferred witness-once architecture.

A cached immutable fixed table does not eliminate its input-dependent
multiplicity columns or lookup proof. The first strategy is the smallest sound
implementation to investigate after complete compact mixed-original closure.
