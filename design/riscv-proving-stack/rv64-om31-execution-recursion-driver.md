# Current-services OM31 recursion driver

The linked `rv64-word16-ethereum-gkr-recursion` product reuses the native Ethereum receiver's request parser, image authority, independently reconstructed CPU/truth keys, fixed authority and source bounds. It does not add circuit dependencies to the resident native producer. The latter rejects recursion mode with `RecursionProductRequired`.

```sh
zig build rv64-word16-ethereum-gkr-recursion -Doptimize=ReleaseFast -j2
zig-out/bin/rv64-word16-ethereum-gkr-recursion \
  --security-profile conjectured128_b2_q108_p20_fold4 \
  recurse-candidate REQUEST.json NATIVE_PROOF_DIRECTORY 12884901888 51539607552
```

The final two arguments are explicit immutable FIXED and host receiver byte budgets. The output directory `NATIVE_PROOF_DIRECTORY/recursion-om31` must not already exist for a new run. Incomplete runs leave artifacts but never write a successful report. Use `resume-recursion-candidate` with the same arguments to reuse existing leaf/fold artifacts. Every reused proof is freshly decoded, checked against the independently regenerated graph authority and expected output digest, and freshly verified. A corrupted or mismatched cache fails closed; it is never silently accepted or replaced.

`leaf_graph` independently admits and captures each native physical proof, checks the original local-GKR, terminal binding, AIR and native PCS equations, and exposes exactly eight reserved public digest words. The statement frame remains witness data, not topology constants. `outer_wrap` pads the concrete circuit deterministically, builds independently pinned native OM31 circuit authority, proves under q108/P20/fold4, freshly verifies, and serializes with the new bounded OM31 codec.

`execution_wrap` uses a bounded binary-carry stack: it folds adjacent equal-size blocks as each leaf arrives, then combines the remaining blocks from right to left. This produces the same ordered pair-fold tree with odd promotion, while retaining O(log workers) keys/proofs instead of the complete tree. With the existing 256-worker admission bound, the stack has nine slots and at most ten live authorities including a parent under construction. Child PP/FIXED/witness material is released only after the new parent has a complete freshly verified proof and durable bytes. Narrow authenticated words, claims, terminal marginals and tree metadata survive those releases. Every parent verifies both physical child proofs and commits both admitted key identities and public outputs. The final receiver freshly verifies the root, checks its reconstructed ordered digest and complete leaf coverage, and checks the independently reconstructed manifest, RAM/KIO/Wire closure, boundary claims, input/output and adjacency through `services_root`. Ethereum completion additionally requires the original terminal-output authority in the shared receiver.

Artifacts are `leaf-*.proof`, `fold-*.proof`, `root.proof`, `tree.json` and `report.json`. The report separates graph/capture, wrap, fold and root reception timings. The schema-2 report also records restored leaf/fold counts and peak live pending authorities; `outer_backend` is currently `cpu`. `native_prove_ns` is null because this command consumes existing proofs; native proving time must come from the separately pinned producer receipt. Recursive total time excludes the original native production, and excludes the loader/setup reported separately by the CLI.

## Qualification boundary

The concrete CPU fixture has an actual q108/P20 outer proof and fresh acceptance: 5,570,560 padded variables, 30.478 seconds proving, 0.0636 seconds fresh verification. Its native inner proof uses q2/P0 and is explicitly not the production block. The typed CPU and Keccak graph constructors and the separate native outer wire roundtrip pass. The complete orchestration route type-checks without emitting a binary (`zig build check-rv64-ethereum-recursion`); the complete real production block is now recursively accepted: seven CPU proofs and ten truth proofs wrapped into seventeen real leaves, sixteen binary parents, and one freshly verified 717,048-byte root. Root SHA-256 is `b82a740f62829dbf795e711e686c3b8e90be88b877005552786eb8459ddb538f`; the root includes independent execution/manifest/boundary and Ethereum terminal checks. The initial real run qualified all seven CPU leaves and three Keccak leaves, but exhausted the 48 GiB host budget at the eleventh leaf because all keys were retained. This prompted bounded streaming retention and independently reverified resume, rather than raising the memory budget. The successful mixed recovery run took 884.648 seconds inside recursion (894.06 seconds process wall), with ten earlier leaves freshly restored, seven new leaf proofs, and all sixteen new parent proofs. It used 42.168 GB maximum RSS and 46.466 GB peak physical footprint under the unchanged 48 GiB host payload budget. Final root verification plus metadata closure took 0.315 seconds with admitted regenerated authority. This is CPU outer proving; the 7.71-second native GPU result excludes recursion. Resumed-run timing is explicitly not a cold full-recursion benchmark.

After fresh verification and durable serialization, the driver now also calls explicit prover-data retirement: full PP column buffers and committed FIXED LDE/coefficients are freed, while the original root, profile, bound AIR, geometry and output count remain available for child/root verification. Re-proving a retired authority fails closed. Full-block retirement replay is qualified: all seventeen leaves and sixteen parents freshly re-admitted under regenerated authority, parents verified against retired child keys, fresh root/closure/terminal acceptance, and all thirty-four published proof artifacts byte-identical to the production reference. The replay retired 18.590 GB of PP column storage cumulatively (FIXED trees were freed as well), with 10.017 GB peak physical footprint. Its 44.439-second recursive stage / 53.75-second process wall is **cached-proof verification and key reconstruction**, not a proving speedup; restored counts are 17/16.

The new root artifact does **not** carry authority to replace its verifier key. The current receiver owns the regenerated immutable key in process; `portable_root_key_admission=false` states that an independent new-process root-only key admission/cache still needs qualification. The output sidecar is accepted only alongside the proof-authenticated ordered frame digest. Arbitrary sidecar words alone are not execution acceptance.

The native and outer profile names express a 128-bit security target under documented assumptions, not a whole-protocol certificate. Legacy QM31 proof codecs and registry keys are not accepted by the new OM31 wrapper.

## Explicit CUDA outer controller

A separate CUDA-linked product selects the concrete device factory. The CPU product and ordinary resident native producer retain their default paths.

```sh
zig build --build-file src/integrations/riscv_cuda/build.zig \
  build-rv64-ethereum-gpu-recursion -Doptimize=ReleaseFast \
  -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4 -j2
STWO_RV64_GPU_LIBRARY=/absolute/path/qualified-native-image.so \
STWO_RV64_GPU_DEVICE=0 STWO_RV64_GPU_BYTE_CAP=30064771072 \
  src/integrations/riscv_cuda/zig-out/bin/rv64-word16-ethereum-gpu-recursion \
  --security-profile conjectured128_b2_q108_p20_fold4 \
  recurse-candidate REQUEST.json NATIVE_PROOF_DIRECTORY 12884901888 51539607552
```

The factory is explicit and receives a deterministic unique stream-node ordinal for both leaves and parents. GPU refusals propagate; the controller never switches to CPU proving. Missing library/kernel capabilities fail closed. The current product supports one selected device and rejects the multi-device-list variable rather than silently ignoring it. Every generated proof still receives independent native CPU verification before durable admission.

This is **CUDA proving from CPU-built circuit assignments**: MAIN, INTER, composition and PCS are device stages, while circuit graph/assignment construction and immutable key derivation remain CPU work. It is not yet compact-proof-input-to-GPU-witness residency. Reports label `cuda_from_host_assignment`, and count actual newly proved GPU leaves/folds separately. Restored bytes bypass proving and are never presented as a GPU proving measurement.

Host qualification covers terminal device refusal, correct unique ordinal forwarding, cached-proof backend bypass, the CPU path, and native producer dependency/type-check parity. The concrete factory has an independently qualified tiny native-OM31 proof with exact CPU bytes and fresh receivers. Real production CPU0/complete-root GPU qualification is the next gate; the previously accepted real root remains the CPU outer reference.

## Combined native GPU proving and recursion

The explicit combined product calls the existing native producer and then wraps its live bundle before the independently derived keys and fixed authority are released. It does not reload the serialized native bundle or reconstruct a second set of native authorities. Native proof publication remains available for independent inspection. Ordinary native GPU and standalone recursion products keep their existing entrypoints.

```sh
zig build --build-file src/integrations/riscv_cuda/build.zig \
  build-rv64-ethereum-gpu-combined -Doptimize=ReleaseFast \
  -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha -j2
STWO_RV64_GPU_LIBRARY=/absolute/path/qualified-complete-native-image.so \
STWO_RV64_GPU_DEVICES=0 STWO_RV64_GPU_DEVICE_CAPS=30064771072 \
STWO_RV64_GPU_PLANNED_CPU_WORKERS=7 STWO_RV64_GPU_RETAINED_SCOPES=7 \
STWO_RV64_GPU_CPU_REPLAY=1 \
  src/integrations/riscv_cuda/zig-out/bin/rv64-word16-ethereum-gpu-combined \
  --security-profile conjectured128_b2_q108_p20_fold4 \
  produce-and-recurse-candidate REQUEST.json - NEW_OUTPUT_DIRECTORY 0 RESOURCE.json
```

This mode requires the complete resident native pipeline, a device recursion factory and a complete block. It rejects host MAIN parking, prefix runs, resumed recursive proofs and multiple devices. The persistent native context has a 28 GiB device cap and an explicit 2 GiB immutable setup budget shared by native proving and recursion. The host budget defaults to 48 GiB and can be specified with `STWO_RV64_RECURSION_HOST_BYTES`. The existing 4 GiB `ResidentSession` cache shares independently derived native geometry classes within that host budget; it does not admit producer-supplied verifier keys. Runtime images must contain the native CPU and truth catalogs, the outer circuit catalog and the production witness-generation capabilities; missing capabilities are terminal.

`report.json` retains native capture/setup/prove/verify times. `combined-report.json` adds measured authority setup, native publication, recursion and combined pipeline times. `combined-entry.json` is written only after the device lifecycle audit succeeds and includes GPU initialization and entry wall time. Recursion uses the same original proof profile and records newly proved GPU nodes; it never treats restored bytes as a fresh benchmark. Implementation and semantic checks do not establish a speedup: the combined real-block gate must pin the image, guest, request and all native/recursive proof hashes before reporting measurements.

The combined build above requires an x86 host with SHA instructions. This changes host hashing implementation, not proof bytes; the deployment must check CPU feature support. Production witness generation also receives an explicit 16-kind kernel preflight before native capture or circuit construction.
