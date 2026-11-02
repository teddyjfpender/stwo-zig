# Bounded parallel classic OM31 interactions

Whole-block profiling found about64.2s and62.3s of interaction generation in the first two Keccak truth proofs. Their PCS stages were far smaller. The shared classic witness generator was still serial:256-row chunks, scalar OM31 batch inversion/contributions, and logical-row writes scattered across thousands of physical columns. This slice targets that measured producer cost without changing equations or global closure.

Validated immutable metadata providers explicitly opt in. The three production wrappers read const source/challenge data and allocate nothing in callbacks. Other providers retain the original serial logical-order implementation; stateful provider behavior is tested. There is no producer-controlled argument/degree flag.

Generation jobs own32-row relative128-byte physical blocks and contiguous output spans per inverse-column group. Base alignment is not assumed to establish an absolute machine cache-line guarantee. Native packed OM31 Montgomery chains use the existing inverse scratch, preserve all zero-denominator failures and share one scalar tail inversion across lanes. Packed numerator-times-inverse handles base, secure and mixed weights. The rational triple numerator additionally reuses denominator pair products and scales native weights by M31; native production and AIR emission share this algebra.

The existing prefix planes temporarily hold per-row contributions. A joined logical prefix wave writes chunk-relative prefixes; the coordinator combines partial claims in ordinal order, then a joined physical correction wave adds offsets and subtracts the final claim. Correction uses the actual scheduler end cuts, rather than guessing its uneven partition formula. The three-worker regression caught this distinction before qualification. No extra execution-sized plane, wide MAIN copy or tuple matrix is created.

`Classic.scratchByteUpperBound` is the single checked scratch authority for runtime planning, truth admission and CPU/truth retention estimates. All parallel tile allocations together stay within the former serial scratch allowance, with a64MiB outer ceiling. Jobs divide that allowance into smaller native-pack-aligned chunks: at16workers the640-inverse catalog uses16-row tiles. Job ownership remains32-row aligned. Helper records, partial totals and a4KiB correction tile are bounded stack metadata; existing pool stacks/envelopes belong to pool admission. All heap buffers are allocated by the coordinator before callbacks, and all consumers join before scratch release or error return.

Truth admission includes every coexisting local/global output, the maximum of local and global generation scratch, and the secp global Source descriptor arrays. The same descriptor-byte helper is used by its allocator and admission. A hard HostBudgetAllocator test proves actual requested peak remains within the exact output-plus-shared-scratch allowance and returns to zero after witness release. Requested bytes are not an RSS claim.

Focused Safe/Fast suites pass8tests: full cell/claim parity against the untouched serial reference at1/3/7/16workers, the640-inverse catalog, four groups, zero weights, strict poles, immutable inputs, unavailable leases, stateful providers, partial allocation failures, packed tails and admission. Complete two-CPU plus K/ADD/DOUBLE physical proofs remain byte-identical to the historical pinned digest and independently fresh-verify all global closure:

`eaa04370373513f54f8c7435f1453983681413dfd978f56026f363ed8fa9f386`

Both Safe/Fast physical gates pass. Independent source review found no ownership/concurrency blocker. Kernel and whole-block performance remain unmeasured at this source commit; the optional benchmark is serialized under the shared heavy lock and must be reported separately. No transcript, statement, field, security claim or receiver authority changes.

Commands and raw logs are in `vectors/reports/rv64-classic-witness-parallel-20261102/`.

The subsequent locked synthetic640-inverse kernel run used the committed source24d1ebf5c atlog12 with84,017,152output bytes. Serial took339.90ms; optimized1/4/16workers took114.63/38.58/72.00ms, respectively, with exact cells/claims. Every case used16,384,000scratch bytes; chunk sizes were256/64/16rows. Four workers won this small memory-heavy case, so higher fanout is not assumed to improve time. The synthetic provider excludes actual truth tuple projection. This is not a whole-truth/block improvement; the parent real2×8run remains the required measurement.
