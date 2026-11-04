# Incremental native candidate qualification after the two-GPU basket

Prepared only: no remote compilation, GPU job, runtime replacement or new timing measurement. Keep the accepted phase252 runtime and all active benchmark processes immutable. Candidate order is idle-cache cap (`b08bb3803`), narrow assignment (`ac9efd7f6`), then padding ranges (`698381bf4`). Every option remains off.

## Build inputs and the missing-object constraint

The existing safe builder is `scripts/rv64_cuda_native_library_build.py`: dependency-hashed compilation, a complete relocatable-object list, private host helper localization, device link and required-export checks. A one-TU replacement requires that exact object inventory. The 1.8 GB linked ELF cannot be used as a substitute relocatable object, and extracting fatbins does not recover its host launch stubs or prior device-link inputs. Do not use binary patching, LD_PRELOAD or symbol-by-symbol allocator interposition.

Preferred path: retrieve the original phase252 `build.json`, all listed objects (including localized copies and device-link inputs), their source/dependency stamps and link command from an existing archive/volume without restarting or disturbing the measured host. Validate every SHA before compiling. If those files cannot be recovered, a standalone monolithic one-TU relink is unavailable. A full AOT rebuild is a separate expensive fallback, not an incremental command.

A possible bounded alternative is an explicitly linked dependency image: compile the changed native units into a new DSO with an absolute immutable `DT_NEEDED` dependency on the accepted base ELF. This is a new two-DSO deployment candidate, not a drop-in monolithic relink or an already-qualified shortcut. It needs the extra ownership/origin gates below before any real proof. Do not silently choose it during the basket.

## First candidate: upper idle-cache cap

Source compatibility is unusually narrow. `b08bb3803^` and the qualified phase-lifetime source `ece170700` have IDENTICAL `pcs_native.cu` SHA `e8dd7d28603a1c429c07a7a3b81f5c2e4a59dc752f0a874afd718e6010bb6423`; their `pcs_pipeline.cuh` files also match SHA `77fa70ee2caf1c0773a6985312a8afc7d776a1f78f13bb61f5f4c1f0b258d062`. Apply only the cap delta and new `pcs_idle_cache.h` to that frozen source/dependency snapshot. Do not compile an arbitrary newer whole-tree PCS body and call it a one-change experiment.

The candidate adds one field to the private `ResidentOwner` layout and touches joined retirement/reset. Therefore ALL session/lease/immutable/PCS owner entry points must come from one new `pcs_native.o`. Mixing old and new owner methods against a session would corrupt private offsets. It does not change public C layouts, source arithmetic or the PCS pipeline. Unset retains existing behavior. An explicit canonical decimal `STWO_RV64_PCS_IDLE_CACHE_BYTES` caps only unused upper-cache blocks; start qualification with 0 and a nonzero bounded value. Physical release is not implied: returned blocks enter the same async pool.

The evidence motivating this is historical recovery telemetry, including the parent's two-GPU FIXED run's 28 recoveries/33 nodes. That is not evidence that this candidate reduces recoveries or wall time.

After the benchmark is terminal and compile time is authorized, the bounded compile command is:

```sh
/usr/local/cuda/bin/nvcc -O3 -std=c++17 -lineinfo \
  -gencode arch=compute_120,code=sm_120 -Xcompiler=-fPIC,-pthread \
  -I "$FROZEN/src/backends/cuda/native" -MD -MF "$OUT/pcs_native.d" \
  -c "$FROZEN/src/backends/cuda/native/rv64/pcs_native.cu" \
  -o "$OUT/pcs_native.o"
```

Own the complete compiler process group with a 120 s limit; retain logs and the CUDA12.8 compiler version, full flags, dependency hashes and object SHA. This is an upper bound, not a measured compile estimate. No AOT TU needs recompilation.

With the full original inventory recovered, localize only approved private host helpers using the existing builder, replace exactly the PCS object, preserve every other object SHA, and replay the recorded device-link command:

```sh
/usr/local/cuda/bin/nvcc -shared -Xcompiler=-pthread -Xlinker=-Bsymbolic \
  -rdc=true -gencode arch=compute_120,code=sm_120 \
  @validated-objects.rsp -o "$OUT/.candidate.pending.so"
```

The response file must come from a hash-checked manifest, not shell glob ordering. Preserve the complete old `stwo_*` export set, then `ctypes.CDLL`/typed API-load every required symbol before atomic publication under a new SHA-named path. Never replace the accepted library inode.

If objects are unavailable and the explicit dependency candidate is approved, its prospective link command is instead:

```sh
/usr/local/cuda/bin/nvcc -shared -Xcompiler=-pthread -Xlinker=-Bsymbolic \
  "$OUT/pcs_native.o" -Xlinker=--no-as-needed "$PINNED_BASE" \
  -o "$OUT/.candidate.pending.so"
```

This command is NOT yet qualified. Inspect `readelf -d` to require exactly the intended immutable base dependency and resolve all CUDA/runtime dependencies; capture their hashes. Test actual `dlopen` lookup origins with `dladdr`: ALL `stwo_rv64_pcs_native_*`, `stwo_rv64_gpu_session_*`, `stwo_rv64_gpu_lease_*`, and immutable-owner functions must resolve to the candidate, while the unchanged numerical/AOT functions resolve to the base. Audit the frozen base for internal calls into owner APIs: `-Bsymbolic` means such calls would bypass the replacement, so any such call makes the dependency route unacceptable. The reviewed source only calls owner APIs inside `pcs_native.cu`; validate the actual frozen base, not this assumption. Prove one runtime context/allocation registry is used by both images; check CUDA runtime/fatbin registration and error-state behavior. Do not infer safety from an export list alone.

Gate sequence: existing host cap parser/partial-free/ownership tests; old/new lease/custody checks; same tiny outer protocol proof with unset,0,nonzero cap, exact CPU/cold/warm bytes and fresh CPU receiver; then the SAME real block and caps as the two-GPU ready CPU-FIXED control. Record actual idle-trim lines, recovery count, request leases, active/immutable preservation and per-device physical peaks. Numerics should need seconds of GPU time; real-block timing uses the existing measured request duration, not a claimed subsecond gate. No all-15 replay is required just to decide whether the option is worth a broader run.

## Next: narrow assignment

Compile only `rv64/circuit_assignment.cu` with the same bounded command/flags, replacing its original object or adding it to a separately approved dependency candidate. The old 56-byte job and16-kind capability stay unchanged; only `stwo_circuit_assignment_narrow_run_on` is added. Require all original entry-point behavior plus malformed coverage/reserved/alias/context rejection, invalid-task barrier completion, independent scalar values, prior-level dependencies, and a257-task broad barrier. The existing `tests/cuda/rv64/assignment_narrow_run_smoke.cu` is the intended numerical fixture. It is still CUDA-uncompiled.

Then use the existing `--outer-dag-proof` fixture, require a positive actual `narrow_run_calls` marker, exact CPU proof bytes and a fresh CPU receiver. Only afterward run a real CPU0/Keccak leaf and full-block control. The matched padded census projects CPU0 120,240 nonempty levels to6,869 calls and Keccak146,139 to3,712 for width256; this does not establish GPU speed or occupancy. Keep one256-thread CTA only for bounded consecutive narrow levels; broad levels retain their original stream barrier.

## Then: padding ranges; combine only after independent gates

`698381bf4` adds the small `circuit_assignment_ranges.cu`; no replacement of the original assignment kernel is needed. Its typed lease/session validation must bind to the SAME owner implementation used to create the leases, particularly if using the dependency-image experiment. Compile one additional TU, preserve the base exports and add only `stwo_circuit_assignment_ranges_on`.

The existing `tests/cuda/rv64/qualify_assignment_ranges.py` runs CPU control, two device proofs, full generated-assignment reference comparison, positive range-call counters, exact proof bytes and two fresh CPU receivers. Retain that one pipeline. After the tiny gate, qualify real CPU0 all45,088,768 values and full circuit acceptance before any speed claim.

The narrow and range source branches BOTH modify `outer_assignment.zig` from different bases. Do not wholesale cherry-pick one module over the other or over current packing/planning improvements. First port each independently onto the pinned producer. A combined successor must group the new prefix schedule (not the removed canonical suffix), then fill ranges exactly once before later readers; counters and CPU reference checks must show both routes executed. Independent results do not qualify this combination.

No option is enabled by availability of a symbol. Keep the original base image, source/binary hashes, authored manifest, explicit caps and strict offhost receiver intact for each one-change comparison. The next actual action is object-archive availability verification or explicit approval of the dependency-image experiment, after the current basket releases the measured host.
