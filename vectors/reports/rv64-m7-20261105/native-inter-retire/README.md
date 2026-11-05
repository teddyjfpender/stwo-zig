# CPU global evaluation retirement candidate

Status: **CPU lifetime tests PASS 4/4; GPU/production unqualified. Default OFF.**

`STWO_RV64_NATIVE_INTER_RETIRE_GLOBALS=1` releases each old `DeviceGlobal.Witness` immediately after its synchronous INTER commit succeeds and its independent coefficient tree is adopted. Absent/0 preserves the original deferred cleanup; other values fail closed. The candidate changes no arithmetic, transcript, tree ordering, or proof encoding. Byte identity remains a required integration gate, not an established result.

## Ownership argument

- `cpu_worker.zig::complete` allocates nullable device-witness owners with a final cleanup defer. It copies their claims into the separately owned claims array before constructing `Components.Set`. The only later witness readers assemble INTER input descriptors before `stage.commit`. After successful adoption, RC/PCS read the scheme's coefficient trees and component claims, not the old evaluation headers.
- `global_stage.zig::Job.run` allocates one output lease per witness; every published evaluation column belongs to that generation. `Owner.release` submits an exact full-lease release to the same service before freeing host headers/claims. Binding projection/Eq/prefix and its distinct coefficient owner are outside this hook.
- `trace_commit.zig::copyInputs` uses `scoped_device_copy.execute`: both source and destination range, generation, context, and request scope are validated before D2D enqueue. Adjacent-copy merging does not replace authority.
- For beta=1 with the separate-coefficients path, the committer allocates a **new kind-2 lease**, copies evaluation inputs there, interpolates there, and produces the root. `streamRoot` joins its root readback before `publish`. The legacy root path also joins before publishing.
- For beta=2 (the qualified D2 native profile) and other nonseparate paths, inputs first enter an independent scratch arena. After root readback joins, a **new kind-2 coefficient lease** is allocated and receives the final coefficient D2D copy; a second explicit join precedes publication. Thus the returned tree cannot borrow the original global output allocation.
- Both publication paths rebind the new lease to the final source-owned scope and retain it in the service registry. `commitImpl` synchronously submits the job, checks callback failure/status, and returns only the published tree. `adoptDeviceOm31TraceTree` validates descriptors and mixes the same root; adoption itself is not relied on to join.
- The extra helper validates the **entire wave before its first release**: nonempty exact-power-of-two device evaluation inputs, one nonzero generation per witness, common nonzero context, independent valid output generations, and no overlapping address envelopes. A disjoint slice of the same generation is rejected because deinit frees the whole allocation. No ownership transfers on validation failure. On success deinit followed by null assignment keeps the original error-path defer exactly-once safe.

The service release API returns void at the witness boundary and preserves its existing error handling. `published_input_bytes` is the sum of published column spans, **not measured physical freed bytes**. A poisoned service/release failure must still fail the enclosing request and leave cleanup to its owning context; these statistics must never authorize memory admission without a fresh live snapshot.

## Evidence and potential

The standalone Zig 0.15.2 ReleaseSafe test uses no GPU. Four tests cover independent coefficient survival after poisoning old storage; exactly-once cleanup after later failure; same-generation/disjoint-range and forged-generation/overlapping-range rejection; foreign context, stale geometry, mixed owner rejection before any release; strict flag parsing and empty-wave behavior. Raw output and source SHA256 values are in `unit-test.log` and `receipt.json`.

Source-derived headline census: old CPU global evaluation columns total **1,026,137,088 B across seven CPU proofs**, split 657,912,832 / 368,224,256 B by physical GPU. Each CPU's eligible payload is recorded separately. This is **not a simultaneous live set or measured request-peak saving**. Each witness allocation is independently arena-rounded, and most retirement opportunities occur at different times. The default inverse-prefix layout already includes prefix columns: no second prefix allowance is added.

## Integration gate

1. Compile the full production CPU worker against the selected source/runtime, preserving native's optional timestamp lines when cherry-picking the six-line hook.
2. On each dev block compare OFF/ON complete artifact hashes using the same binary/profile/assets, then verify roots in fresh independent CPU receiver processes.
3. Exercise normal completion and forced post-INTER failure under memcheck; check no later read references the freed generation and no double release occurs.
4. Record exact arena live/managed lease values immediately before/after retirement and before the next RC allocation. Measure actual process peak separately. Do not infer the <=28 GB gate from payload sums.

This candidate retires old CPU **global evaluation** ownership only. It does not free retained native MAIN/FIXED, old native binding coefficients, GKR workspace, truth global outputs, or request caches. No global planner coverage or two-lane activation is claimed.
