# DEEP four-member combination experiment: deferred

The four-member M31 dot-product experiment stays on `codex/rv64-deep-dot4-combine`. Its production branching is **not promoted**: the isolated arithmetic kernel improves on a favorable synthetic fixture, but the real CPU0 pair does not establish a whole-proof gain. The integrated packed-OM ABI cleanup is a separate change and remains qualified.

Source-pinned evidence:

| Evidence | Commit |
|---|---|
| Same-source frozen baseline | `664f8adc3` |
| Four same-view/full-span member reducer and exact fallback | `665f8a10c` |
| Safe3/Fast3 gates, durable tests, matched-pool micro and reproducer | `b6b93ca91` |
| Actual CPU0 artifacts, fresh receivers and complete invocation | `5ef209c5c` |

These commits remain available on the pushed experimental branch. The detailed evidence is under `vectors/reports/rv64-deep-dot4-checkpoint-20261102/` at that branch tip; this docs-only decision carries a compact source-pinned summary in `vectors/reports/rv64-deep-dot4-deferred-20261102/decision.json`.

The reducer groups four consecutive members only if they share a destination view and all source lengths cover the current chunk. Existing canonical `m31.dot4Packed`/`dot4` reduces their products once and updates the destination once. Partial, interleaved, leftover and empty members use the old path. No additional planes, caches, protocol changes or field assumptions are involved. Three focused tests pass in both Safe and Fast, including Q/OM coordinates, worst canonical values, mixed views/partial sources/tails, pooled disjoint rows and exhaustive allocation failures.

Valid synthetic micro samples bind the explicit frozen old-source pool and candidate pool to identical worker counts. All outputs match exactly; sample0 is excluded from medians. Full same-view fixtures improve about1.52x serial and1.41x OM/1.47x Q at8workers. Deliberately interleaved zero-coverage fixtures are about4–6% slower serial and approximately flat pooled. Their coverage is synthetic; actual production eligibility was not instrumented.

One clean real CPU0 pair uses matched `664f8adc3` code except this reducer, identical dense-control flags, q70/P26/fold4 and16workers. The quotient stage is1.251686→1.233252s, while proving is8.489411→8.536042s. All8 authoritative artifacts match and both independent fresh receivers accept. These are shared-host observations, not a controlled causal estimate; no whole-proof speedup is established. The added fallback checks and production branching are therefore deferred in this scope.

Two exploratory data sets are explicitly excluded. The first micro bound only the candidate module's pool; the old-source module has independent TLS and lazily selected a different worker count. The first CPU0 pair overlapped this agent's own pre-push tests. The hook process tree was stopped, the pair rerun, and only the clean rerun supports the table above. These mistakes do not invalidate the exact-output tests but must not be used as performance evidence.

This evidence does not qualify GPU execution, complete Ethereum acceptance, recursion or a128-bit security construction.
