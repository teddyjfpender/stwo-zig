# CPU-only census of admitted recursive leaf assignments

`rv64-word16-ethereum-gkr-recursion inspect-recursion-schedule CONFIG PROOFDIR [ORDINAL]`
is a read-only diagnostic in the CPU recursion product. Ordinal defaults to 0.
The selected candidate security profile is explicit or follows the existing
q108/P20/fold4 default. GPU factories and resident sessions are refused.

The command reuses the receiver's image, bundle, independent keys and fixed
binding setup. Inventory admission and manifest decoding/sealing precede the
selected original native CPU/truth capture and trace-only statement graph.
It then applies the EXACT outer-wrapper padding expression before building the
original witness schedule. It does not build PP, commit an outer authority,
produce a recursive proof, or verify every other native PCS proof. Its JSON
always says `accepted:false`, with a selected-native-capture diagnostic scope.
No GPU context is created.

The diagnostic has a 24 GiB requested-live cap. The 12 GiB fixed-cache cap is a
subset of it, together with native and metadata caches. The existing recycler
may retain up to 4 GiB of freed backing allocations outside requested-live counts;
four operational workers have a conservative 4 MiB OS-stack upper bound outside
that count. Thus fixed-cache 12 GiB must NOT be added again to obtain 44 GiB.
These are requested allocation/cache limits, not an RSS limit. Measured peaks
and the budget snapshot accompany each result.

## Two real post-padding captures

The immutable proof directory was block 24628607's accepted complete native
bundle. A copied request changed only ELF/input paths to durable files with the
same identity hashes and the operational worker count 16→4. Original files were
unchanged. Both captures matched the retained GPU log's variables, task count
and total level count exactly:

| Native leaf | Padded variables | Tasks | Total / nonempty levels | Projected 128 calls | Projected 256 calls | Tasks in 256-thread runs |
|---|---:|---:|---:|---:|---:|---:|
| CPU0 |45,088,768|18,990,989|120,241 /120,240|22,542|6,869|24.37%|
| Keccak7 |26,738,688|13,484,113|146,140 /146,139|23,410|3,712|38.05%|

Projection groups at most 256 consecutive eligible levels and leaves singleton
and broad levels on their original route. The original level-kernel counts
are 120,240 and146,139; the seed kernel is separate. A 256-thread proposal would
reduce those assignment-level call counts by 94.29% and 97.46%. These are schedule
counts, NOT measured CUDA speedups or reductions in all proving launches.
Broad levels still contain most tasks and retain their parallel kernels.

Padding added 11,815,722 variables /4,064,058 tasks to CPU0, and 2,283,696 /
1,904,304 to Keccak7. The level-width count histogram happened to remain the
same as the exploratory unpadded graphs, but task mass and allocation geometry
did not. The original pre-padding captures are preserved and labelled
exploratory; they are not the qualified production assignment geometry.

CPU0 used 3.097 GB peak requested live allocations and 5.620 GB measured RSS;
Keccak7 used 2.704 GB and 4.767 GB. End-to-end diagnostic times were 14.31 s and 13.32 s
on the local ARM machine, including independent key setup. This is not a GPU
benchmark or a comparison to rented-x86 timings.

The compact committed receipt records histogram counts AND task mass, gate and
hint counts, skipped generation definitions, source/binary/result/log hashes
and one unchanged-artifact-set digest. Full raw reports and 43-file hash lists
are durable under `rv64-proof-artifacts/20261104/evidence/recursion-schedule-census`.
Skipped generation definitions do not remove constraints from the original
statement graph.

## Checks

Three pure parser/census tests pass, as does the production semantic check.
Two selected real post-padding captures pass. Negative ordinal and extra
arguments reject before image/key setup; an ordinal outside the loaded roster
rejects before Keys.init. A private one-bit native-proof mutation rejects at
the existing bundle-integrity layer (`WideBundleFileChanged`). No canonical
proof or metadata file changed. These negative cases do not claim a new AIR
soundness review.

The separate optional narrow-kernel candidate is OFF and CUDA-uncompiled.
The 256-thread choice is motivated by these actual schedules; numerical parity,
barrier/error qualification, memory/race checking and representative performance
remain mandatory before any activation.
