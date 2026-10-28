# Wider native domains: rejected for this CPU path

Increasing native opcode domains did **not** improve complete verified bundle
time. Both tested layouts are rejected as defaults. The original log-16
producer, statement admission and witness routing have been restored exactly.
The experimental implementations remain reproducible at their recorded commits.

## Matched canonical results

All rows execute the same 1,310,734-cycle SHA/Keccak/arithmetic/RAM guest on the
M5 Max, eight workers, ReleaseFast, q70/PoW26. The experiment preserves ELF,
input, output and endpoints. It repeatedly accesses one RAM word, not an
Ethereum-sized address set. Each executable completed all 12 selected tests,
including fresh complete-bundle verification, additional cold verification,
changed final-root rejection and missing batch proof rejection.

| Native row layout | Segments | Driver | Charged peak | Native components¹ | Native cells | Companion cells² | Recursive cells³ |
|---|---:|---:|---:|---:|---:|---:|---:|
| Original log-16 cap | 1 | 39.826 s | 4.509 GB | 24 | 95.946M | 146.802M | 499.792M |
| Uniform log-20 cap | 1 | 68.890 s | 15.044 GB | 5 | 178.258M | 288.359M | 574.478M |
| Dyadic log-20 cap | 1 | 45.315 s | 7.391 GB | 7 | 95.946M | 146.802M | 518.486M |
| Original log-16 cap | 4 | 75.250 s | 12.925 GB | 30 | 95.946M | 146.802M | 1,648.878M |
| Uniform log-20 cap | 4 | 102.547 s | 15.898 GB | 15 | 161.088M | 254.280M | 1,939.562M |
| Dyadic log-20 cap | 4 | 82.796 s | 15.873 GB | 23 | 95.946M | 146.802M | 1,941.987M |

¹ Includes the native infrastructure components. ² Auxiliary columns only;
shared native trees are excluded. ³ Recursive component fixed/main/interaction
cells, excluding shared lookup tables, PCS expansion and temporary storage.
These partial counters cannot be summed into a complete whole-job area.
Memory-provider area stayed 89.129M cells in all six arms. GB is decimal;
charged allocator peak is not process RSS. Full phase data is in the CSVs.

One measurement per arm, sequential on the same host. PoW is stochastic, so
wall-time ratios are observations rather than stable medians. The deterministic
increase in recursive area and substantial memory regressions independently
argue against enabling these layouts. No 10× gain or block latency is claimed.

## What failed

The uniform layout pads a family just above a power-of-two boundary into a
much larger domain. It roughly doubled native/companion area in the one-segment
case. The dyadic revision coalesces full old shards into descending powers of
two and retains a small tail. Unit tests establish identical padded area to
the old layout at the tested boundaries, including multiple full log-20 tiles.
Its complete proofs exercised larger domains and nonuniform tail routing.

Even the area-preserving revision did not reduce recursive area. Fewer
component descriptors and opening groups are insufficient predictors of the
complete recursive proof. Domain-dependent opening work and power-of-two
padding of recursive AIR cohorts must be included in the planner. This run
does not isolate their individual contributions; do not attribute the entire
regression to one kernel or solely to FFT size.

Four layout unit tests passed (ReleaseSafe): old/wide admission, malformed
partitions, padded-area parity and row placement at legacy/wide boundaries.
An end-to-end run spanning multiple full log-20 shards was not performed:
the smaller complete experiment already falsified the performance selection.
There is no reason to spend another large proof run qualifying a rejected
default. No new production layout remains active.

## Retained architectural result

The [original-domain partition comparison](closed-tiling-m5-20261028.md)
demonstrates 75.250 → 39.826 s and 12.925 → 4.509 GB for the same execution.
Use fewer execution proofs while independently sizing providers. The next
structural priorities remain a single native/companion relation layout and
eliminating repeated wide commitments. Raising row limits alone is not a
substitute for those changes. The complete bundle still requires global
provider proof files; recursive closure to one standalone root remains open.

## Evidence and reproduction

| Layout | Source commit | Machine-readable results |
|---|---|---|
| Original | `5ea22942f51327b13af1b4fb6cb37d78b21569c8` | [JSON](block-v6-closed-tiling-m5-20261028.json), [CSV](block-v6-closed-tiling-m5-20261028.csv) |
| Uniform wide | `906b41ad8` | [JSON](block-v6-uniform-wide-rejected-m5-20261028.json), [CSV](block-v6-uniform-wide-rejected-m5-20261028.csv) |
| Dyadic | `13745dc77` | [JSON](block-v6-dyadic-rejected-m5-20261028.json), [CSV](block-v6-dyadic-rejected-m5-20261028.csv) |

JSON files contain full source SHAs and raw log digests. Use the standalone
build/run commands in the original-domain report at each source revision.
The strict parser rejects incomplete arms, mismatched execution identities,
missing negative checks and invalid timing partitions. The pre-code
[problem match](native-domain-tiling-problem-match-20261028.md) records the
falsifiable prediction and the revision after the first regression.
