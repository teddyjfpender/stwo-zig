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

The concrete CPU fixture has an actual q108/P20 outer proof and fresh acceptance: 5,570,560 padded variables, 30.478 seconds proving, 0.0636 seconds fresh verification. Its native inner proof uses q2/P0 and is explicitly not the production block. The typed CPU and Keccak graph constructors and the separate native outer wire roundtrip pass. The complete orchestration route type-checks without emitting a binary (`zig build check-rv64-ethereum-recursion`); full production 17-leaf wrap/fold runtime qualification is still pending. The initial real run qualified all seven CPU leaves and three Keccak leaves, but exhausted the 48 GiB host budget at the eleventh leaf because all keys were retained. This prompted bounded streaming retention and independently reverified resume, rather than raising the memory budget. Resumed-run timing is explicitly not a cold full-recursion benchmark.

The new root artifact does **not** carry authority to replace its verifier key. The current receiver owns the regenerated immutable key in process; `portable_root_key_admission=false` states that an independent new-process root-only key admission/cache still needs qualification. The output sidecar is accepted only alongside the proof-authenticated ordered frame digest. Arbitrary sidecar words alone are not execution acceptance.

The native and outer profile names express a 128-bit security target under documented assumptions, not a whole-protocol certificate. Legacy QM31 proof codecs and registry keys are not accepted by the new OM31 wrapper.
