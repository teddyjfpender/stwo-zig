# RV64 second-pass audit — 2026-10-30

This pass found and fixed a real integration regression: exporting AIR through
the standalone execution module broke diagnostic builds. Execution remains
`riscv.rv64`; the full frontend exports AIR separately as `riscv.rv64_air`.
The focused execution gate now compiles diagnostic, CSP execution and benchmark
tools without injected proof modules, preventing that dependency regression.

Verifier OODS evaluation now streams constraints into the core accumulator,
removing a temporary vector allocated through a hidden page allocator. The native
verifier also rejects malformed tree, column, opening and query shapes before
cryptographic processing. Ordinary tests live under their owners' `tests/`
directories; focused roots select them, and standalone execution tests still run.

[Exact source hashes and qualification receipt](qualification.json) bind the
results. The earlier [compact-layout results](../rv64-air-20261030/README.md)
remain historical evidence; this pass does not overwrite them.

| Check | Result |
|---|---|
| Execution-focused gate, standalone tests and tool builds | Passed, ReleaseSafe |
| AIR suite: 10 named tests | Passed, Debug / ReleaseSafe / ReleaseFast |
| Native proof suite: 8 named tests | Passed, ReleaseSafe / ReleaseFast |
| Independent Unicorn 2.1.4 execution comparisons | 14,815 cached + 14,815 uncached passed |
| Independently compiled guest | 1,025 retirements and expected output matched |
| Python tool tests, formatting and diff whitespace | Passed |

The execution-focused aggregate has a 49-test compilation floor; it also includes
shared utility and RV32 decode tests, so that is not a count of 49 distinct RV64
instruction tests. This audit separately adds 1,792 deterministic random
full-width arithmetic cases. Projection checks compare every logical coordinate
and padding row across representative instruction families. Streaming and
buffered accumulation agree on full-extension-field samples; the degree-bound
check remains in place.

Complete native proofs now cover both 128- and 256-step domains with a
4,096-word program, 128 explicit memory cells and reads at address `2^64-8`.
The last RAM access clock reaches 1024. Separate proofs verify PC wraparound
from the highest instruction address and discarded loads into x0. Malformed
proof arrays, invalid public geometry, duplicate/read-only cells, failed
interaction publication and existing captured register/RAM/permission forgeries
are also checked. The malicious proofs fail fresh verification with
`OodsNotMatching`, not merely host witness validation.

The five-instruction proof remains 127,224 bytes with 700 physical columns and
22,400 committed trace cells. The tracked producer peak remains 995,370 bytes;
removing the untracked OODS buffer does not establish a reduction in this peak
counter. Timings in the receipt are single observations, not a speedup benchmark.
No CSP, precompile, recursion or block proving result is inferred from them.

Reproduce from the repository root:

```sh
zig build test-riscv64-execution test-riscv64-air test-riscv64-proof -Doptimize=ReleaseSafe
zig build test-riscv64-air test-riscv64-proof -Doptimize=ReleaseFast
zig build test-riscv64-air -Doptimize=Debug
zig build test --build-file src/frontends/riscv/rv64/build.zig -Doptimize=ReleaseSafe
python3 -m unittest scripts/tests/test_riscv64_tools.py
# Requires the isolated Unicorn 2.1.4 environment:
/tmp/stwo-rv64-oracle-venv/bin/python scripts/riscv64_differential.py --report /tmp/rv64-oracle.json
```

Pinned Rust acceptance of this RV64 component and RV64 Sail qualification remain
open. Existing Rust interoperability examples do not verify this custom AIR.
Broad source/package gates also retain unrelated failures. Full CSP/OP proving,
continuation, independently sized providers, specialized recursion and a complete
retained-block run remain outside this bounded qualification. This is expanded
test evidence and source review, not a formal soundness proof or a release-gate
pass.
