# Native fixed-cost optimization: CPU and Metal

The bounded milestone is complete: attribute a dominant cost, remove measured scalar hashing work without changing the proof protocol, repeat complete proofs on both native backends, and exercise actual memory-opening growth at fixed execution size. Formal CSP performance promotion remains pending a quiet-host run.

- [Attribution and implementation](analysis.md): source/table payload, overlapping versus exclusive timings, and the selected shared Poseidon SIMD change. CPU main/interaction Merkle work fell from 3.816 to 1.459 seconds in the diagnostic profiles.
- [Instruction before/after and historical memory results](results.md), with [checked original 66-run summary](summary.json): 64-instruction median complete requests fell from 8.963 to 5.340 seconds on CPU and 5.074 to 3.978 seconds on Metal. Fresh native verification fell about 57% on both routes. These are three-sample local measurements; no faster Metal device kernel is claimed.
- [Revised memory ladder](memory-v2-results.md), with [checked 18-run summary](memory-v2-summary.json): zero-initialized, 128-byte-spaced addresses at 64 instructions; 450/473/569 measured sparse-node calls. The original contiguous-word fixture's flat 560-call results remain retained rather than overwritten.
- [CSP preservation](csp-results.md): 16 cases, both backends, two paired rounds, 128 launches and 640 timed samples. All proof/statement identities and policy checks passed; no repeated >5% proof-time or memory increase. All host preflights failed strict quiet-host admission, so this remains diagnostic evidence and does not authorize performance promotion.
- [Runnable development commands](../../../../design/riscv-proving-stack/small-recursive-benchmark.md): canonical CPU/Metal lifecycle, instruction/memory checks, profiling and the maintained paired CSP runner.

## Acceptance and scope

All 84 retained small complete-proof processes verified canonical serialized native and outer proofs after producer destruction, rejected truncated/trailing outer artifacts, and reported zero remaining producer allocator payload. Each request proves one native child plus its 39-component, 47-domain CPU outer proof. A 16-cycle continuation is executed and state-checked, not separately proved. Native Metal uses authenticated AOT dispatch; fresh native verification and outer proving are CPU operations.

The native q1 / outer q3 / PoW0 development profiles are unchanged. This is native-assisted recursive verification, not a detached root, a production-security benchmark, a two-child recursive proof, or Ethereum block proving. Canonical artifact-size equality is not claimed as byte equality; scalar-oracle full-tree tests separately check identical Merkle layers. CSP uses its separate unchanged secure profile.

The final semantic gate passes 19 tests, including mixed domains, streamed groups, uneven three-worker SIMD partitions, and required-scratch OOM cleanup. Its build took about 4 seconds and test execution 311 ms. Both revised fixture builds pass independent instruction/memory/state and corruption checks. Full integration compilation still takes roughly two minutes per backend; no integration build-speed improvement is claimed. The original broad proof/mutation gate and CLI rejection checks are retained in `complete-gates.json`.

## Provenance

The instruction optimization checkpoint is `ad273a96721e1ccc1dd62a861fac11b44d0c680d`; `implementation-source.json` pins its source files. Reconstruct the pre-optimization small-run baseline from `a66af315ec1752635a2349b65b3a8daf6bee47e3`, `baseline-source.patch`, and the exact initially untracked files in `baseline-new-source/`. Those archived sources are evidence, not a second active implementation.

`baseline-*-binary.json` and `optimized-*-binary.json` pin retained executables. The fixture and parallel-test checkpoint is `bf36c95936274abcbfae83efa9da84962935ebc0`, pinned in `memory-v2-implementation-source.json`. `memory-v2-source.patch` binds the integration fixture revision relative to the optimization checkpoint; its CPU/Metal build receipts pin the corresponding new executables and execution checks. The subsequently extended standalone Merkle test root is not an input to either integration binary. Each measurement directory records log hashes, executable hashes, source-patch snapshots, command arguments and raw process RSS.

A measurement runner's current HEAD or dirty patch alone is not proof of an older executable's build source; use the matching build receipt and archived source. Machine-local executables and AOT bundles remain under `.git/local-*` and are not portable dependencies. Logs, source reconstruction data, receipts and reports are durable here; this change adds no runtime dependency on `autoresearch/`.

Per-component source and retained-column payload models are not measured live memory. Native allocator counters exclude size-routed Merkle mmap and device allocations; process RSS is separately recorded. The fixed lookup domains still force native commitment height 21, and this optimization does not materially reduce retained memory.
