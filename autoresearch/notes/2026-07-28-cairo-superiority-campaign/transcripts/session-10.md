# Session 10 — increment 3.9: preprocessed-cache productization (pruning + ops)

Implementation model: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, predecessor `dcef25bb`, draft PR
#125. Host: Apple M5 Max, 12 performance + 6 efficiency cores, macOS.

A fill-in increment while the critical path waits on the external metallib mint
(issue #124). Ops only: no proof bytes move and no timing claim is made.

## The problem, restated from increment 2.1

Two protocol-identity-keyed artifacts share one cache directory: the ~2 MB
Pedersen affine point table (`.preprocessed`, increment 9) and the ~134 MB
preprocessed tree-digest artifact (`.preprocessed-tree`, increment 2.1). Both
key on the product's authenticated identity document, which includes
`dirty_content_sha256`. A developer iterating therefore mints a fresh key on
every build and writes ~136 MB that nothing ever reclaims. Increment 2.1 landed
with that flagged as a known cost; this increment closes it.

## Reasoning trail

**The budget belongs to the directory, not to an artifact kind.** Both kinds
already share the directory and the opt-out, and the runaway growth is a
property of the *set* of generations, not of either kind. So `budget_bytes`
went on `product_cache.Config` (which the tree cache already reads through
`currentConfig()`), and one `enforceBudget` serves both store paths. The
alternative — a per-kind cap — would have needed two budgets to express one
disk claim and would have let the 134 MB kind starve the 2 MB kind or vice
versa depending on which cap the user got wrong.

**atime was never a candidate.** `relatime` is the Linux default and macOS
coalesces atime updates; an eviction policy keyed on it would evict artifacts
that are in daily use. The marker has to be written by the cache.

**Sidecar vs in-band mtime.** The brief allowed either. I took the mtime:

- The sidecar's failure modes are all new surface. It doubles the entry count;
  it needs orphan reclamation on eviction and after a crashed writer; and it
  introduces a second file that can disagree with the artifact, which then
  needs its own corruption handling. The brief asked for a "corrupted sidecar
  handled" test, and the honest answer with an in-band marker is stronger than
  a test: **there is no sidecar to corrupt.** The marker is metadata on the
  artifact whose contents the integrity trailer already covers, so the marker
  and the artifact cannot disagree.
- The cost is that mtime stops meaning "written at". I checked both formats:
  neither the key derivation, the header, the size check, nor either integrity
  trailer reads mtime. Nothing regresses.

The analogous hazard for an in-band marker is a directory the cache does not
solely own — junk it cannot parse, names that carry its extension but cannot be
keys, another process's in-flight temporary — so that is what the test covers
instead, plus reclamation of a genuinely stale temporary.

**"Never evict the current product identity" needed a definition.** The set of
keys one product identity can address is not enumerable from the identity
digest: the tree artifact's key binds the hasher, the committed domain and every
committed column height, none of which are derivable from the identity alone. I
therefore made the protected set the keys the run *derives*, registered before
any filesystem access, in `pedersenTable` and in the tree cache's `load` and
`store`. That is a superset of "the artifact just written" and exactly the
working set the run needs to keep. When the protections leave the directory over
budget the pass stops and reports the overage rather than forcing it — a run
that cannot keep its own working set gains nothing by evicting it.

**Concurrency needed no lock, only a proof that there is no third state.**
Eviction only unlinks whole artifact files; nothing is ever mutated in place or
truncated. A reader with an open descriptor keeps reading the whole inode
(POSIX), so its integrity trailer verifies. A reader that has not opened yet
gets `FileNotFound`, which both load paths already treat as fail-open. Verified
by test rather than asserted: the reader-with-open-fd case reads all 4096 bytes
of an unlinked artifact intact, and the not-yet-opened case gets
`error.FileNotFound`.

## What changed

| File | Change |
| --- | --- |
| `src/frontends/cairo/preprocessed/product_cache.zig` | `Config.budget_bytes`; per-run `Accounting` + `accountingSnapshot`/`resetAccounting`/`recordHit`/`recordMiss`/`recordStore`; `protectKey` registry; `touchArtifact`; `enforceBudget`; `configure` now resets both registries |
| `src/frontends/cairo/preprocessed/tree_digest_cache.zig` | key registration in `load`/`store`; marker refresh after integrity verification; hit/miss/store accounting and the eviction pass in the thunks |
| `src/products/cairo/shared/preprocessed_cache.zig` | `STWO_CAIRO_PREPROCESSED_CACHE_BUDGET` parsing (decimal bytes, `0` = unbounded, unparseable keeps the default) |
| `src/products/cairo/shared/application.zig` | `preprocessed_cache` object in the run report, read before the activation is torn down |
| `src/frontends/cairo/tests/preprocessed_cache_eviction.zig` | new; 13 cases |
| `src/frontends/cairo/tests/mod.zig` | registers the new suite |

The tests live in the frontend *test root* rather than beside the module
because that is the root module `test-cairo-frontend` compiles; `test`
declarations inside the `cairo_frontend` module itself are not collected by any
gate, so a case written beside `product_cache.zig` would never have run.

## Verification log — INCOMPLETE, and the reason is mechanical

The 90-minute budget was consumed by build time, not by the increment. This
worktree had a cold `cairo_cpu` AOT cache, and the Debug-mode
`cairo-witness-cpu-aot` C translation units (`ec_op_builtin.c`,
`partial_ec_mul_window_bits_{9,18}.c`, `partial_ec_mul_generic.c`,
`pedersen_aggregator_window_bits_9.c`) ran ten clang processes at 100% for over
fifty minutes without finishing, starving everything else on the host (load
average 13). `test-cairo-cpu-product` never reached its Zig compile;
`test-cairo-frontend` compiled and started its test binary but had not finished
when the budget expired. Nothing here indicates a problem with the change — it
is a cold-cache cost that a successor inherits as *warm*.

What did complete:

```
zig ast-check on all five changed/added Zig sources    OK
zig build package-workspace                            PASS
  17 packages, 17 public modules, 51 dependency edges
pre-commit hooks (both commits)                        PASS
  source conformance: 5 explained legacy findings, no new violations
  21 tests OK
zig build test-cairo-frontend
  compiled clean (this is what proves product_cache.zig,
  tree_digest_cache.zig and the new 13-case suite type-check);
  test binary still running at budget expiry — result NOT observed
zig build test-cairo-cpu-product
  still in AOT C compilation at budget expiry — NOT observed
```

What was NOT run, and must be run before this is accepted:

```
test-cairo-frontend            (to completion — the 13 new cases)
test-cairo-cpu-product
test-cairo-metal-product
byte-exact digests, CPU + Metal, all-opcodes 79ae76e1… and
  arithmetic-2m 25e5719f…, with the cache enabled AND disabled
evict-then-reprove smoke (cache hit still works after an eviction pass)
STWO_ZIG_WORKERS=1 spot
store+evict timing (the bounded-cost claim: one store+evict pass in ms)
```

The store+evict cost is *argued* rather than measured: the pass is one
`openDirAbsolute`, one `iterate` bounded at 8192 entries, one `statFile` per
entry, a sort of the candidate subset, and one `unlink` per eviction. On a
directory holding fifteen generations that is ~30 stats. It is reported through
`preprocessed_cache.eviction_ns` in every run report, so the number is one prove
away — but this session did not produce it, and the claim stands unmeasured.

Corpus for the missing runs: `/private/tmp/stwo-cairo-holistic-corpus-20260727/`
(`all-opcodes.prover-input.json`, `arithmetic-2m.prover-input.json`).

## Residual debt

Recorded in the note. In short: the budget is enforced only at store time, so a
process that only ever hits never prunes; there is no `cache` subcommand to
inspect or clear the directory; the protected set is capped at 16 keys per run;
and `directory_bytes` counts foreign files against the budget while refusing to
evict them, which is honest but means a shared directory can wedge the cache
into permanent overage.
