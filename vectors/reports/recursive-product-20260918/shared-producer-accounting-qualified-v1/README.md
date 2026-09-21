# Shared producer accounting and integrated device ladder

The tracked SMP allocator now belongs to `src/prover/tracked_smp_allocator.zig`.
The former Ethereum runtime name is a type alias. The legacy outer engine and
actual detached native-leaf producer reference the shared owner directly, so
neither imports Ethereum runtime policy to obtain allocation accounting.
The entire allocator implementation is byte-identical after normalizing the type
name. Historical error names, diagnostic text and snapshot fields are preserved.
There is one implementation and the original growth/concurrency test was moved,
not copied.

## Focused development loop

```
zig test src/prover/tracked_smp_allocator_test.zig -O ReleaseSafe
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-runtime-ownership test-recursive-segment-v2-outer-engine -Doptimize=ReleaseSafe --summary all
python3 -m unittest scripts.tests.test_product_closure.RecursionOwnershipTest
```

The three selected tests and 15 ownership checks pass. The transferred allocator
test exercises reallocation, 8,193 simultaneously live allocations (beyond the
old fixed capacity), accounting restoration, and concurrent growth/release on
four threads. Runtime-policy tests retain their original worker/receipt checks.
The new dependency guard constrains the tracker to `std` and rejects restoring
the Ethereum dependency in the two recursive producer consumers.

## Complete proofs and scaling

Fresh pinned CPU and Metal builds pass 384 canonical-tree checks, including
producer destruction, standalone verification, malformed proofs and same-geometry
statement substitution. All 21 artifacts remain canonical-baseline-identical.
Those exact binaries and the freshly built AOT bundle were then reused, without
rebuilding between rungs, for the 16-address 1/2/4/8 ladder.

The ladder passes 1,110 checks. All 78 key/claim/proof artifacts are identical
between CPU, Metal and the prior ladder baseline. Existing independently admitted
keys and expected statements are reused; no new key is derived from a candidate
proof. Every node also rejects an independently admitted alternate-seed statement
under its original key. Roots verify in standalone processes without native inputs.

Every Metal leaf requires 36 active typed components / 144 dispatches, plus six
native tables / 24 dispatches. Every parent requires 29 typed components / 116
dispatches. The inactive row-10 path remains authenticated and generates no device
work. Per-rung summaries retain explicit counts and replay commands.

Single complete-production observations follow. They exclude compilation, lock
waits and hostile verification. Rungs ran sequentially; these are not statistical
speedup claims. Peak RSS is measured at process scope.

| Segments | CPU production (s) | Metal production (s) | CPU/Metal peak RSS (GB) | Root proof (MB) | CPU/Metal verification (ms) |
|---|---:|---:|---:|---:|---:|
| 1 | 8.613 | 7.024 | 2.898 / 2.570 | 2.482 | 74.13 / 73.30 |
| 2 | 27.822 | 21.442 | 4.077 / 4.524 | 2.419 | 65.01 / 67.27 |
| 4 | 67.322 | 49.621 | 4.085 / 4.535 | 2.288 | 68.68 / 68.19 |
| 8 | 145.605 | 105.922 | 4.086 / 4.536 | 2.297 | 68.79 / 66.35 |

## Evidence and remaining scope

Source snapshots cover one frozen revision for both canonical gates and all
ladder rungs. `source.patch.gz` captures the cumulative authorized worktree;
report files and the following documentation update are outside that snapshot.
The transfer audit and original allocator body allow direct comparison.
`replay-ladder.py` and per-rung commands retain exact binary/input/AOT hashes.
Admissions and their content-addressed inputs remain in the sibling
`larger-memory-ladder-qualified-v1` report.

This closes the pending qualification of the integrated leaf device path on the
larger ladder. It does not move the legacy outer-wrapper publication mint or
claim production-security/Ethereum readiness. The live legacy path needs its own
publication/witness and concrete proof coverage before migration; see
[remaining-wrapper-audit.md](remaining-wrapper-audit.md). Independent host domain
audits remain in the leaf device path, and no speedup is claimed for this move.
