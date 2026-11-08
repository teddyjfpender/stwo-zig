# native-review-fixes receipts

Stream `codex/rv64-m8-native-review-fixes`, cut from `codex/rv64-m7-integrate` @ 2b7eceb8c. This stream applies the confirmed review findings on native-finish-p3. Everything stays default-off. `jobs/mod.zig provider()` is unchanged, so `STWO_RV64_M8_JOBS=1` still fails closed with `M8RequestProviderNotLanded`. No new job flag becomes reachable from a request.

## Fixes

| finding (severity) | fix | test / evidence |
|---|---|---|
| Stage2's composition seam dropped the device claims (major, x3) | `Composition.enqueue(ctx, e, Inputs{alpha, claims, status, root_out, trees})`. Stage2 passes the **same slice it mixed**. `NativeComposition` calls `enqueueWithClaims`. | `native_stage2_test` (GPU): the producer receives exactly the mixed claims, and the status field it writes is accepted. Real-block parity goes through `S2.NativeComposition.producer()`: `through_seam=true` on 11/11 + 14/14. |
| Claim-slot indices followed a layout the harness invented (major) | New `jobs/native_claims.zig` holds the single layout authority: `cpu_components.Plan` claim offsets plus `global_cpu.claimsFromVector` order. `native_global.Plan.init` checks its groups against it (`claimsIn`). `Roles.fromItemsWith(device_claims)` maps P.claims+r to `Slot.index[r]` and keeps a host mirror in the same layout. Absent relations stay zero. | Host test against `claimsFromVector`. Real block: every CPU row's claims buffer is the **native_global jobs' output** for that segment (`claims_source=native_global`) and equals the host claims word for word (`claims_match_host=true`). |
| NativeComposition status never cleared or checked (major) | `enqueueWithClaims` clears the status itself. `Stage2.Fields.status` plus `native_stage2.accept()`. | The harness poisons the status to 0xffffffff before the producer runs. Every row ends with status 0. |
| GPU tests skip silently (major) | `STWO_RV64_M8_REQUIRE_GPU=1` turns a missing GPU base/addon into `error.GpuTestsRequired`. Each GPU test that runs prints a `GPU_M8_TEST_RAN <name>` line. | Pod: without libs, 4 failures (as intended). With libs: 285/286 passed, 4 GPU tests ran (commit, stage1, stage2, tail). The 1 skip is `native_pcs_scale_test`, gated by `STWO_RV64_M8_PCS_SCALE`. See `host-tests.txt`. |
| Scheduler OOM with the mutex held (minor, x2) | Reserves every cross-thread list for all nodes before threads start. Takes them by `std.mem.swap` under the mutex, so the loop never allocates there. `InvalidRelease` and the `promote` OOM latch the error and drain instead of returning. | `scheduler_test`: a FailingAllocator sweep over indices 0..11 with prep_threads=2 gives OutOfMemory before any job, or success. No hang and no leak. |
| Failed park leaves an unusable worker, then a double free (minor) | Park marks the worker parked whenever the arena is gone. `releasePersistent` is best effort: each buffer is freed once and dropped, and the first error is reported. | `worker_service_test`: an injected free failure leaves the worker parked; unpark recovers it; `bad_frees == 0`. |
| park/unpark single control slot (minor) | `unparking` guard (`WorkerBusy`). `acquireArena` refuses when an arena is live. | 6 concurrent unparks: exactly 1 acquires and 1 arena is allocated. |
| Lazy pinned growth calls cudaFreeHost in `stage` (minor) | The replaced slot is retired and freed at the next park/unpark or at shutdown. Growth goes to the next power of two, at least 1 granule. | No host free while jobs run. 3 retired buffers are freed at park. |
| Stage1 checks the verdict late (minor) | `enqueue` refuses when a binding is set. `enqueueBound` validates everything before `initFromCheckpoint`. | Host test (every refusal precedes the first enqueue). |
| Binding authority check unspecified (minor) | `Binding.enqueueWithAuthority` copies the eta seed, per-instance claims and OOD point (`Plan.authorityWords`). `checkAuthority` is the legacy `validateArtifact`, moved to finish. `Stage1.enqueueBound(…, authority)`. | Host test (layout, mismatch on point/digest). Not yet called by a provider: there is none. |
| Binding ABI structs duplicated (minor) | Field order is pinned against `NAT/rv64/binding.h` by parsing the header. Named `metadata_words`/`point_words`/`carry_words`/`max_row_log`. | Host test. |
| Composition precomputes twiddles eagerly (minor) | Host trees are built only in `stage` when the region is fresh. Lengths come from `twLen`, checked against `precomputeM31`. | Host test, plus real-block parity. |
| Harness 24 GiB default, env undocumented (minor) | Default is now 20 GiB. All `STWO_RV64_M8_PARITY_*` variables are documented in the header. `ONLY` is parsed once into an enum. `ONLY=composition` + `DEVICE_CLAIMS=1` installs the global decorator. | Runs 11/12 used the default arena: global 76/76 + 127/127. |

Not changed:
- **Delegated kernel-id table copy (minor).** The fix edits legacy `resident_composition.zig`, which is read-only in this pass.
- **Twiddle region keyed by (log, direction) across producers, and the composition commit tail via CommitPlan (minor, quality).** This is a larger refactor.
- **A synthetic-role NativeComposition GPU fixture.** It needs a real role kernel. Real-block parity through the seam covers it instead.

## Real-block parity [M]

`rv64-m8-native-parity`, source 914f4273c, addon sha256 2ac8930e…, legacy on GPU0, job worker on GPU1, `STWO_RV64_M8_PARITY_ONLY=composition STWO_RV64_M8_PARITY_COMPOSITION=1 STWO_RV64_M8_PARITY_DEVICE_CLAIMS=1`, arena 20 GiB (default).

| check | 26235156 (run parity-11) | 24628607 (run parity-12) |
|---|---|---|
| composition through the Stage2 seam (root + every coefficient word, status 0) | 11/11 (4 CPU, 3 truth-classic, 4 truth-delegated) | 14/14 (7 CPU, 3 + 4 truth) |
| CPU rows: device claims are native_global's output and equal the host claims (Stage2 layout) | 4/4 (claim_count 24–26) | 7/7 (claim_count 15–28) |
| global slots in the same run (claims, verdict, INTER witness) | 76/76 | 127/127 |

Receipts: `composition-device-claims-<block>.json`.

Custody caveat: native_global's claims reach the composition job through the slab readback of the global parity job. That hop exists because cross-job retained device memory is not landed yet. The values and their layout come from the device; the hop between the two jobs is through the host. In one Stage2 job the buffer would be the slab field native_global wrote.

## Gates

[M] Source 914f4273c: default gate **PASS** on 26235156 and on 24628607 (byte-identical to the frozen D2 golden, receivers accepted). `--env STWO_RV64_M8_JOBS=1` on both blocks fails closed with `M8RequestProviderNotLanded`, the same as integrate (no provider yet). Pod GPU host tests: 285/286 passed with `STWO_RV64_M8_REQUIRE_GPU=1`, and 4 GPU tests ran. See `gates.json` and `host-tests.txt`.
