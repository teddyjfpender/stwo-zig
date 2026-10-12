# Shared readonly providers v2 (source engineering)

The original B5IR/B5IC standalone grammar remains unchanged. This new protocol is not active in the default CPU driver and has not yet qualified a positive proof. Its source proofs leave provider and native/caller-source joins open. File hashes, proposed counter digests and collection census never substitute for fresh proof verification.

## Shared epoch and exact source groups

The common source seal commits the independently enumerated v2 source, provider and dedicated range first roots before challenges. `Global.Challenges` draws the original universal47 + Word5 prefix, then two classification/read pairs after the Plan and complete roster digests. Every source uses its independently admitted group ID as a final tuple coordinate. For the original classifier arity this is expressed as `z_group = z - alpha^arity * group_id`; recursive recorders export the unshifted54 draw pairs and derive the same shift in equations.

Groups contain whole sources in deterministic order and have exact integer all-RW mass below the M31 modulus. This bound is needed across the entire group, not merely each provider shard: otherwise globally cancelling shards could hide a modulus-sized multiplicity discrepancy. Providers and final joins cannot cancel different groups. The independently admitted group/source census preserves dense native and sparse caller ordinals, roots and mutable/readonly totals.

## Fragmented provider witness

`FragmentCursor` streams one borrowed u64 interval counter vector into nonzero `(interval_index:u32,count:u16)` fragments. One large interval may occupy multiple fragments; sources are not capped at65535 events. A provider shard has at most32768 fragments, so its largest exact mass is2147418112, below M31. Its shape carries group/index, first-fragment ordinal, logical row count, row log and exact integer counts. An independently pinned ordered ordinal inventory reconstructs the fixed tuples from the admitted Plan; it is only operand transport metadata.

The real provider component has10 fixed columns,18 main columns and44 interaction columns. Fixed columns are activity, first/last physical-domain selectors, the original five-cell interval tuple and exact byte-addressLE16x2. Main holds one16-bit multiplicity, total and readonly u64 prefix limbs, eight Boolean carry cells and one inverse-count cell. Forty-eight equations prove nonzero active counts, zero padding counts/inverse/carries, unsigned limb recurrences, zero top carries, final public totals and the eleven original rational prefix relations. Width of all nine dynamic count/prefix limbs is supplied by a genuine separate range16 proof.

The9 range requests per physical row include padding, whose prefix cells retain final totals. Each provider has one separately admitted range shard with exact request count, first roots, config and counter transport digest. `Provider.verifyPairOwned` freshly verifies both proofs through the original WordPCS/range AIR, then closes the nine request sums against that precise range supply. It returns an open source-provider receipt, not a whole-memory or block receipt.

## Actual source proof kernel

`NativeSource.Proof` uses the original205 classifier equations and original103 main/20 interaction cells under distinct B5IN2 transcript framing. The concrete independently admitted roster supplies ordinal, group, original source index/root inventory, classification first roots, full census and source identity. The proof carries only the original four secure claims and readonly count. It carries no per-source interval counter array and does not re-run the original per-source public-provider graph. Fresh verification enforces the original fixed census, component, PCS and FRI; separate provider and actual-source joins remain required.

The new replay `Trace` reuses original matrix ownership and `witnessRow`, binary-searches the admitted intervals, and owns an empty counter slice. It does not allocate or clear an interval-sized vector per replayed source. First-pass collection still requires care: feeding dense per-source counters from the old inspector into one job vector reduces retained ownership but leaves O(intervals × sources) scans/clears. Streaming counter updates are a separate collector task.

## Qualification and remaining connection

Current new sources have only been formatted and inspected by the author. The focused root retains actual source/provider/range producing, capture and fresh verification bodies without invoking them. Pure fixtures cover the original provider scalar oracle, scalar/SIMD equations, group separation, integer carry and padding mutations, exact range request supply, streaming fragmentation and allocator failure. The recursive provider recorder uses those same equations.

Native and provider recursive public buses/admissions/leaf stages, caller-v2 adapters, bounded group aggregation, actual native/caller source equations and transition/public/source-PAGE joins must be completed before changing the fail-closed driver selection. The original wide classifier still costs fixed1/main103/inter20 =124 cells per event, including60 gap bits, versus the replaced two-lane RAM85 cells per event. Moving provider work does not by itself establish a speedup or justify default readonly activation. Same-root fusion or genuinely coupled narrow range gaps is future work.
