# Roadmap: apples-to-apples Ethereum block proof against ZisK on one laptop

Date 2026-09-04. Host: Apple M5 Max, 18 CPUs, 64 GiB. Goal: prove mainnet block 24628607 with the RV32
frontend, on this machine, fast enough and honestly enough to stand next to a ZisK proof of the same
block. This note is the standing list of what blocks that, in the order the blockers actually bite.

Companion notes: `2026-09-03-d5-leaf-metal-host-throughput/note.md` (provider throughput and the leaf
baseline), `2026-09-03-leaf-route-flip-plan/note.md` (the 12-step route flip),
`2026-09-04-recursion-architecture-review/note.md` (soundness/parallelism review),
`autoresearch/benchmarks/ETHEREUM_BLOCK.md` (the block statement and the ZisK side).

## 0. The three things to say out loud before any comparison

1. **Memory and program Merkle roots are single 31-bit M31 words.** `hashPair` returns Poseidon2 output
   lane 0 (`src/frontends/riscv/air/memory_commitment/poseidon2.zig:16`), the sparse tree stores `u32`
   nodes and root (`sparse_merkle.zig:4-9,365`), and the V2 wire carries entry/exit continuation roots as
   scalar `u32` (`statement_v2.zig:520-540`). The cross-leaf fold compares only `MachineState`, so a
   forged entry snapshot that collides on a 31-bit root is authenticated by the leaf's Merkle relation and
   accepted by the fold: roughly 2^31 permutations to hit a chosen root. **This gates any production
   claim**, and it is independent of every performance change below. Fix: widen node/root commitments to
   at least four M31 lanes through the sparse tree, the Merkle AIR tuple, the V2 wire,
   `canonicalCorePublicData` and `MachineState`.
2. **The control plane executes one node at a time and proves leaves on CPU.**
   `ZigWorkerAdapter.max_parallelism = 1` and the scheduler pool is the minimum over adapters
   (`scripts/recursive_pipeline_registry.py:72,564`), while the leaf worker builds a CPU engine
   (`recursive_pipeline_worker_native_leaf_v4.zig:38`), not the Metal engine the benchmark commands use.
   Raising parallelism also needs the registry's `_request`/lease bookkeeping made thread-safe.
   **Memory, not core count, will cap concurrency**: a leaf peaks at 21.2 GB resident
   (`producer_peak_footprint` 21,245,608,088 B), so a 64 GiB laptop holds about two concurrent leaves.
   Cutting leaf peak memory is worth as much as cutting leaf time.
3. **Transport pins 210 segments and the leaf statement caps global cycles at 2^24.**
   `CANONICAL_SEGMENT_COUNT = MAX_SEGMENT_COUNT = 210` (`ethereum_incremental_capture_publication_v4.zig:16`,
   and `MAX_REAL_LEAF_COUNT = 210` on the Python side); `MAX_GLOBAL_CYCLES = 1 << 24`
   (`segment_statement_v2_contract.zig:30`). The real block is **389 segments and 1,630,632,307 cycles**.
   An apples-to-apples full-block comparison therefore needs a protocol change (512-leaf transport and a
   wider global-cycle range), not only speed work. Today's 210-leaf campaign is not the full block, and
   any published number must say so.

## 1. Where the time goes today (measured)

| unit | measured | note |
| --- | ---: | --- |
| Full leaf, segment 1 | 192-234 s transaction, prove 176-216 s | artifact sha `20baa3ae…` matches the pinned reference |
| Leaf cold CPU verify | 21-24 s | |
| Leaf peak RSS | 21.2 GB | binds concurrency on 64 GiB |
| D5 provider shards (same 6,671,301 calls) | Stage A ~1.1 s + Metal prove ~2.2 s | not yet leaf-bound |
| Block, naive serial | 389 x ~200 s = ~21 h | plus aggregation |

Inside the leaf's 176-216 s prove: FRI quotient 48 s, base-trace Merkle commit 44 s, interaction Merkle
commit 35 s, composition 9 s. About 47% of leaf wall is the main thread parked in `waitUntilCompleted`,
and `producer_parallelism_milli` is 465-523, i.e. under one core busy on average.

## 1b. Route-flip progress (2026-09-04)

Steps 0-4 of `2026-09-03-leaf-route-flip-plan` have landed on this working tree:

| step | what | evidence |
| --- | --- | --- |
| 0 | red omit gate fixed (projected core no longer routed through ordinary admission) | `test-ethereum-segment-transcript-extension` exit 0, 1/1, 41 min |
| 1 | O(1) validated authorities threaded through the whole omit path | new proving-parity gate digests every byte of the omitted-core proof both ways |
| 2 | route protocol module: comptime pins, pre-Tree0 frame, leaf omission authority | `test-incremental-ethereum-omit-protocol-v4`, 7/7 |
| 3 | `additional_registration` optional | candidate-leaf proof-identity guard unchanged |
| 4 | V4 omitted-provider orchestration + cold verifier (1393 lines) | `test-incremental-ethereum-omit-orchestration-v4` 6/6; `check-ethereum-incremental-omitted-route-v4` analyses both generic entries against the real q193 CPU engine, 31 s |

Identity neutrality after steps 0-3 was proven by rebuilding and re-running the D5 sweep: proof identity
`89ee5ce2…`, fresh `64ed3a58…`, 19,856,500 bytes, all bit-exact. Steps 5-7 (shared-transcript source and
adapter, prepared-transaction entry, shared-transcript D5 batch) are in flight; steps 8-11 (STWIOL01
envelope, Metal command wiring, tests, first measured run) follow.

Also repaired: two stale tests in `prover/incremental_bridge_external_v3.zig` that had never compiled
(they called `GeometryV3.canonical` with a zero-column prefix that the validator rejects). Frontend
package failures went 17 to 15; the remaining 15 predate this campaign.

## 2. Ordered plan to the comparison

1. **Route flip** (`2026-09-03-leaf-route-flip-plan`). Moves the 445-column Poseidon provider out of the
   leaf core and onto the 26 D5 shards under one shared relation draw. This is the single largest lever on
   leaf time and it must go through the omit protocol: the standalone shard proofs are not bound to any
   leaf (each draws its own relation context), so a projected core plus unbound shards would leave an open
   Poseidon bus residual.
2. **Leaf peak memory.** Profile the 21.2 GB and cut it; every gigabyte saved is directly more concurrent
   leaves. Cheapest suspects: retained Stage-A schemes, the composition scratch pool, and full-witness
   materialization.
3. **Control-plane concurrency.** Make the registry thread-safe, raise `max_parallelism`, and give the
   worker the Metal engine. Bound concurrency by measured peak RSS, not by core count.
4. **Per-leaf fixed prefix.** Each leaf reopens the whole campaign, re-parses the ELF and re-derives the
   call corpus (~50 s in the sweep). Amortize per block with the prepared-program cache.
5. **Verification cost.** Transitive cold-open is O(N log N) native re-verifications and the CAS rehashes
   every object on reopen; for 210 leaves that is hundreds of gigabytes of SHA-256. Needed before the
   aggregate story is credible.
6. **Protocol capacity** for 389 segments and 1.63 G cycles (item 0.3).
7. **Soundness gate** (item 0.1) before publishing any comparison as a proof claim rather than a
   throughput measurement.

## 3. Developer loop

A one-line change to any file in the leaf or sweep module graph currently costs a ~10-minute ReleaseFast
rebuild, and a shader change costs a further ~9-minute AOT remint. That is the dominant cost of every
iteration in this campaign; the throughput work above was paced by it. Reducing it is on the critical
path for the same reason the proving time is: see section 4 for measurements and the plan.

## 4. Build-time findings (measured 2026-09-04)

The 40-minute-feeling loop is real and it is **semantic-analysis bound, not codegen bound**. Measured on
this host, `stage101-degree5-provider-sweep-v1`:

| action | wall |
| --- | ---: |
| product build, `install-*`, ReleaseFast | ~9:45 |
| product **check** (`-fno-emit-bin`, no LLVM, no link), ReleaseFast | 9:35 |
| product check, Debug | 9:24 |
| product check, Debug + `-fincremental`, warm, after a one-line edit | 9:35 |
| product check, cached no-op | 0.25 s |
| focused test root (`test-incremental-ethereum-omit-protocol-v4`), cached no-op | 0.18 s |
| focused test root, after a one-line edit to a file it imports | **2.5 s** |
| second focused root (`test-ethereum-omit-validated-parity`), after a one-line edit | **11 s** |

Readings:

- Skipping codegen and linking entirely saves about 4%. Optimization mode is irrelevant. Zig's
  `-fincremental` does nothing for this graph on aarch64/LLVM: the warm rebuild after a one-line edit
  cost exactly as much as the cold one.
- So the ~9.5 minutes is Zig analysing the product's reachable graph. The only way to make it cheaper is
  to analyse less code per iteration.
- Analysing less code is already a 200x: the same one-line edit validated through a focused test root
  costs 2.5 to 11 seconds.

What was done: `src/integrations/riscv_metal/build.zig` now exposes `check-stage101-leaf-autoresearch-v1`,
`check-stage101-degree5-provider-sweep-v1` and an aggregate `check`. A Compile whose emitted binary
nothing requests is passed `-fno-emit-bin`, so these are analysis-only. They are not the 10x (see the
table); they exist so a type error is caught by the same analysis pass the product build would run,
without also paying for codegen and linking, and so a cached no-op costs 0.25 s.

**The actual 10x is the loop, not the flag.** For campaign work:

1. Edit frontend/prover/backend source and validate with the focused test root that covers it
   (2.5-11 s). Add a focused root when one does not exist; that is what
   `test-incremental-ethereum-omit-protocol-v4` and `test-ethereum-omit-validated-parity` are.
2. Run `zig build check` in `src/integrations/riscv_metal` before committing to a product build.
3. Build the product only to benchmark or to produce an artifact, and expect ~10 minutes; a shader change
   additionally costs a ~9-minute AOT remint plus repinning four SHAs.

**On a package/library split.** Zig compiles a module graph as one unit, and separately compiled static
libraries only help across *non-generic* seams. This codebase's hot seams are generic and comptime:
`ProverEngine(Backend)`, `ComponentProver` vtables built from comptime AIR, `Builder(S)` over field
types. Splitting those into precompiled libraries means giving each a concrete, non-generic ABI, which is
a real redesign rather than a build-file change. Worth doing eventually at exactly one seam, the
backend boundary, since that is where the CPU/Metal instantiations already differ. Until then the loop
above is the win, and it is available today.

### Attribution (bisected 2026-09-05)

| unit analysed | wall | peak RSS |
| --- | ---: | ---: |
| Metal backend `mod.zig` alone, comptime backend-contract assert included | 0.23 s | 117 MB |
| frontend + prover + CPU engine + the whole omit route (`check-ethereum-incremental-omitted-route-v4`) | 28 s | 4 GB |
| Metal backend package, all its own tests (`src/backends/metal: zig build test`) | 8m43 | 3 GB |
| Metal product check (`check-stage101-degree5-provider-sweep-v1`) | 9m07 | 3 GB |
| the 1.4 MB comptime shader amalgamation on its own | 0.5 s | - |

So it is not one pathological blob. The shader amalgamation is cheap, the comptime SHA-256 never runs at
comptime (it would blow the branch quota), and the backend module in isolation is free because Zig is
lazy. The nine minutes is Zig analysing the *instantiated* prover, PCS, FRI, quotient and decommit code
paths over `MetalCommitBackend` (plus the CPU verifier engine in the same binary). The same route code
over the CPU backend is 28 s, so the multiplier is the size of the Metal backend's implementations of the
backend contract, not any single construct. Reducing it means either fewer instantiations per binary
(split prove and verify into separate binaries) or a non-generic backend seam, which is the redesign
noted above.

### Root cause found and fixed (2026-09-05, commit d09674bf)

The attribution table above was right about *where* (the Metal backend) and wrong about *why*. Timing each
of the Metal package's eleven focused test roots from a cold cache showed ten of them compile in 1-2 s and
one, `test-sampled-coefficient-work-receipt`, takes 9 minutes alone. Probing that root's imports one at a
time with a 90-second cutoff (each probe a one-line test root referencing a single function) walked the
chain `MetalMerkleTree.deinit` -> `shared_runtime` -> `core_aot` -> `abi_contract`, and there it was:

```zig
const declaration_digests: [manifest.native_exports.len][64]u8 = build: {
    @setEvalBranchQuota(10_000_000);
    for (manifest.native_exports, 0..) |entry, index| {
        const declaration = kernelDeclaration(manifest.native_amalgamated_source, entry.name) ...
        result[index] = std.fmt.bytesToHex(canonicalDeclarationDigest(declaration), .lower);
```

One file-scope comptime table: 166 `std.mem.indexOf` searches over the 1.4 MB amalgamated shader source
plus 166 SHA-256s, all in the comptime interpreter. Every binary that reaches the Metal runtime resolves it.

The digests now come from a generated file (`shaders/abi_declaration_digests.zig`, produced natively by
`zig build update-abi-declaration-digests` in 5 s). The contract refuses to compile if export names drift
from the table, and a runtime test recomputes every digest so a stale table fails closed. All 166 generated
digests equal the pinned v25 bundle manifest byte for byte, so authenticated admission is unchanged.

| unit, cold cache | before | after |
| --- | ---: | ---: |
| `test-sampled-coefficient-work-receipt` | 9m00 | 7 s |
| `src/backends/metal` `zig build test` | 8m43 | 7 s |
| `riscv_metal` product check, ReleaseFast | 9m07 | 13 s |

End-to-end validation of the fix: a cold ReleaseFast build of the D5 sweep now takes 57 s (compile 53 s,
2 GB), and the rebuilt binary reproduces the pinned proof identity exactly (`ordered_proof_identity_sha256`
89ee5ce2ec0ed975…, fresh 64ed3a589c76248a…, 19,856,500 bytes; Stage A 1.27 s, Metal prove 2.34 s, CPU
verify 3.54 s). The build-and-verify loop went from about eleven minutes to about two.

The run also tripped over the `/private/tmp` purge a second time (212 pinned leaf-source files this time).
`scripts/restore_campaign_inputs.py <materialization-v2.json> <cas>` now restores every pinned path from the
content-addressed store and verifies size and SHA-256, so that is a one-command fix from here on.

Two lessons worth keeping. First, "it is sema-bound and spread across a huge instantiated graph" was a
plausible story that the per-root bisect falsified in twenty minutes; the earlier probes had only touched
the amalgamation's `.len`, which Zig resolves without evaluating the concatenation. Second, when a build
is slow, time the package's focused roots before theorizing: the outlier is usually one declaration.

### The thrash, and the guard for it

On 2026-09-04 two agents ran heavy builds at once. Each compilation peaks at 3-15 GB, the machine went to
36 GB of swap, and a nine-minute check took **two and a half hours** before it was killed. Waiting is
always faster than thrashing, so `scripts/zig_serial_build.py` now takes a machine-wide exclusive lock for
the duration of a build and passes `--maxrss` (default 24 GiB) to the build system:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal \
    check-stage101-degree5-provider-sweep-v1 -Doptimize=ReleaseFast
```

A second invocation prints `waiting` and then `acquired after Ns` rather than competing. Use it for
anything that touches a product graph; focused roots do not need it.
