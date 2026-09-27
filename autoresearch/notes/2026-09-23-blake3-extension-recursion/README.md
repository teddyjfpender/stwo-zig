# BLAKE3 extension recursion

The recursive verifier now recognizes a closed set of typed extension captures
(Ethereum and guest Poseidon). Both reuse admitted component assembly, DEEP masks,
root binding, transcript replay, and the existing BLAKE3 parent prover. Guest
Poseidon composition records the existing generic caller/provider AIR equations;
it does not implement a second permutation or substitute a RISC-V verifier.

The added guest challenge pair is exported from the transcript and linked to the
composition circuit. Detailed claim totals, guest request/supply cancellation,
and the structurally zero provider batch are explicit circuit constraints.
Ordinary execution commitments and the recursive proof use BLAKE3; the guest's
requested Poseidon operation keeps its semantics.

CPU canonical qualification passed: leaf and parent both q70/PoW26, independently
verified parent after worker and prepared rows were released, and serialized
parent round trip. The fixture contains one guest call. Parent artifact:
867,999 bytes; prepared rows: 2,707,426,052 bytes; tracked worker allocation peak:
15,439,320,518 bytes, below the 38,654,705,664-byte limit. The four-minute wrapper
run includes compilation, leaf proving, preparation, parent proving and tests;
it is not isolated parent latency or an end-to-end speedup measurement.

A focused composition/DEEP/transcript replay regression is also provided for both
profiles, including rejection of a changed claim input, to avoid re-proving a
parent for every future edit. Separate authenticated-AOT Metal qualification
runs the same canonical leaf/parent chain with fresh CPU verification.

Default promotion and obsolete prover-owned commitment route removal remain
pending. Clean ReleaseFast CSP measurement and the original recursion performance
objective also remain pending; a 10x improvement is not established here.


Metal guest Poseidon qualification also passed at q70/PoW26 for both leaf and
parent. CPU and Metal preprocessing roots and key identities match. The leaf
proof is independently verified and captured on CPU before recursive preparation.
Parent artifact: 867,999 bytes; tracked worker peak: 12,979,996,846 bytes;
117 Metal dispatches and 2 CPU fallbacks during parent proving. Native leaf
proving records 270 dispatches / 30 fallbacks. The serialized parent is verified
on CPU after worker and rows are released. Matching CPU/Metal artifact lengths
are not a byte-identity assertion: these tests do not retain the parent bytes.

The focused replay regressions passed for both extension profiles, including
composition, DEEP, transcript and rejection of an altered claim input. CSP
benchmarks now always pass an explicit suite flag, including BLAKE2s, so changing
the CLI default cannot silently change a requested benchmark protocol. All 73
focused benchmark, precompile, suite and full-width reader tests pass. This does
not yet change the default suite or publish a new benchmark matrix.

Commands:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe '-Driscv-test-filter=guest Poseidon canonical recursive parent' --summary all
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe '-Driscv-test-filter=full proof independently verifies' --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-poseidon-parent-aot test-blake3-ethereum-parent-aot -Dmetal-core-aot-bundle=/tmp/stwo-blake3-core-aot-20260922 -Doptimize=ReleaseSafe --summary all
python3 -m unittest scripts.tests.test_riscv_csp_benchmark scripts.tests.test_riscv_csp_precompile scripts.tests.test_riscv_csp_proof_suites scripts.tests.test_riscv_csp_full_width
```


Canonical Ethereum Metal recursion also passed after the shared-path and generic
extension changes: parent artifact 907,299 bytes, tracked worker peak
27,580,232,194 bytes, 168 dispatches / 2 CPU fallbacks. Leaf and parent use
q70/PoW26; the parent is independently verified on CPU after worker and row
release. The combined Metal command passed all 16 tests. The Ethereum test's
four-minute runtime includes leaf proving, preparation, parent proving and
verification, and is not an isolated parent benchmark.

The retained compiler sample shows LLVM DWARF location-list generation dominating
one sampled second of Ethereum test compilation. Focused CPU execution-commitment
and Metal full-width qualification roots now omit debug symbols by default;
`-Dqualification-debug-info=true` restores them. ReleaseSafe runtime checks remain
enabled. These qualification receipts were produced before that build-only change.

Both build graphs accept the debug-info option; the root CPU dispatcher forwards
it to the focused sub-build. Help receipts are retained beside the compiler sample.

The focused guest Poseidon witness qualification also passes through the root
CPU build with the new stripped ReleaseSafe default. See the retained build log.
