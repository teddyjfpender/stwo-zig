# Explicit v5 caller geometry

The first canonical 2M-cycle mainnet attempt stopped during caller collection
with `CallRangeTooLarge`. Its isolated process ran 370.04 seconds and reached
6,044,762,112 bytes peak RSS; no complete block proof was produced. The source
path was `block_v5_precompile_witness_v1.Witness.initSegment` → the default
Ethereum witness constructor → legacy Keccak log16. One such shard admits
4,518 calls. That caller source path had not selected the already implemented
Ethereum log18 geometry.

The v5 caller route now selects explicit `CircuitProfileV1.ethereum_v5 = 2`.
Keccak trace generation, canonical statement geometry, independent admission,
standalone arithmetic assembly and strict staged codec all use that profile.
Its log18 capacity is 18,078 calls; this remains an enforced, finite bound.
The exact complete call census and canonical padded domain are checked before
large allocation. Six-table coefficient headroom, 14 byte queries per memory
event and independently planned field-safe lookup groups remain enforced.

`block_v5_precompile_protocol_v1.VERSION` is now two. The caller key and
private transcript bind the explicit circuit-profile tag. This distinguishes
the v5 selection even when a small caller's physical log16 columns are
identical. Old full-native/v4 constructors retain their explicit legacy
defaults. Native-v3's protocol and root construction are unchanged.

The new `block_v5_precompile_large_profile_test.zig` executes 4,519 real
Keccak calls from a release ELF, builds its actual log17 witness, and derives
51 access slots, 230,469 events and 3,226,566 byte requests. It rejects legacy
geometry and changed canonical log size. The fixture also generates an actual
family11 arithmetic STARK and a packed same-root family13 STARK, round-trips
the arithmetic codec and freshly verifies both under expected caller policy.
It rejects the legacy version-one key. Its other roster entries are scoped
transcript fixtures and confer no native/global/complete authority. The test
passed its larger-domain runtime gate **13/13** with allocator-clean teardown
(`/tmp/block-v5-cpu-delivery-large-optimized-gate.log`). The named canonical
three-segment complete-driver case also passed with fresh all-family reception
(`/tmp/block-v5-cpu-delivery-protocol2-gate.log`); that enclosing command was
interrupted during a later case and is not a suite pass. The large caller test
remains scoped and does not claim global or complete closure. Exact evidence
is recorded in [block-v5-caller-protocol2-qualification.json](block-v5-caller-protocol2-qualification.json).
The subsequent selected-domain implementation passed **14/14**
(`/tmp/block-v5-cpu-delivery-selected-domain-gate.log`), including the same
4,519-call arithmetic and packed proofs under the unchanged point verifier.
It selects 32 Keccak state-bit columns per memory slot and zero for pointer
slot 0, while preserving full descriptor bounds, PCS masks, the +27 output
offset and degree-checked recovery. Nonbinary field-input and zero-enabler
parity passed; SHA fixed-selector log matching remains enforced. This is a
qualified implementation revision, not a performance comparison or Complete
qualification for the large caller. Both protocol-v2 products built in
ReleaseFast. The [mainnet-v2 rerun](block-v5-mainnet-24628607-2m-canonical-v2/measurement.json)
collected all 67 segments and externally sorted 356,303,914 memory events
across 139,214,856 guest cycles, with 14 lookup groups. It then stopped at
global source-root construction with `InvalidV5InitialSourceLayout`, after
1,173.87 seconds at 9,642,622,976 bytes peak RSS. The wrapper recorded resources
automatically. No complete proof or fresh verification finished. The shared
source-layout correction passes pinned real-ELF/input source writing and
full-root checks without STARK proving. The latest canonical recovery gate
passed **14/14**, including fresh three-segment q70/26-PoW Complete reception
with consuming native rows, shared transforms and tiny-log1 recovery. Its
in-process collection/proving/forest/verification times were
0.995/25.211/118.485/2.590 seconds; no memory peak was reported. This resolves
the earlier canonical `InvalidLogSize` failure. The preceding 26-case gate
remains 25 passes and 1 failure, with meaningful large-caller and cache/cleanup
named positives retained; it is not a 26-case suite pass. Both v3 products built
successfully in ReleaseFast. The canonical [mainnet-v3 run](block-v5-mainnet-24628607-2m-canonical-v3/measurement.json)
is running under separately pinned binary hashes; it remains unqualified, with
no complete result or producer report yet.

The source audit found no per-row full-domain validation scan in caller
collection. Retained-column validation checks lengths and geometry; selected
recovery performs one complete-domain FFT and degree check per selected
column. Access traces read fixed-width row data, with Keccak's authenticated
+27 output offset, and perform linear padded witness/census/range passes.
No performance tuning or claimed speedup accompanied this correctness fix.
