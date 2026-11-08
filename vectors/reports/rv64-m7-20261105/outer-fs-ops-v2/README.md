# Resident outer composition challenge powers

Status: **1,270/1,270 GPU checks pass on two RTX 5090s; memcheck reports zero errors.** This qualifies the native helpers only. The real composition consumer, full transcript residency, proof-byte parity and P1 blocking-call/busy gates are pending.

The optional V2 addon retains the lookup helper and adds `stwo_rv64_outer_fs_powers_on(context, lane, alpha8, first_u64, count_u32, powers8count, status1)`. It enqueues powers `alpha^(first+i)` in contiguous eight-coordinate OM31 order. The owner must use the existing reverse global constraint-root order when borrowing each role's slice. No CPU power-table upload is needed by that future consumer. Input, output and status ranges are validated before enqueue; no allocation or synchronization occurs in the helper.

Count zero, count above 2^20 and exponent-range overflow are refused on the host before a launch. Noncanonical coordinates latch status bit 0 and leave outputs unchanged. Existing status bits are preserved. The caller remains responsible for generation/scope handles, stream dependencies, checking status and refusing publication on failure.

The independent Core reference consumes the V1 84-case corpus, then computes each starting power with Core's u256 exponentiation and advances sequentially. For each alpha it checks six ranges: first 0/count 6, 1/19, 19/257, 2^32+1/6, u64 max/1, and u64 max−256/257. These cover zero alpha, exponent zero, a partial CUDA block, the top exponent bit and the last legal multi-element exponent range. The GPU derives each exponent separately by binary exponentiation. Additional tests cover all eight invalid coordinates at both p and u32 max, sticky status, unchanged invalid outputs, range sizes, aliases, host/foreign/retired pointers, invalid lanes and count/overflow refusal. V1 lookup tests are rerun against V2 as well. The fixture's deliberate observation joins are not production blocking-call counts.

V1 remains frozen at `/workspace/m3/build/m7-outer-fs-ops/`; V2 is separate at `/workspace/m3/build/m7-outer-fs-ops-v2/`. V2 addon SHA-256 is `1324a16ca1d1830fd0abb89b4f82a63734771fd6da2a1a946817ef2d1f37ea7c`, linked to unchanged base image `a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45`. `build.json` preserves commands, post-build dependency hashes and artifact identities. Its reference program takes the V1 `core-reference.bin` on stdin; the resulting powers corpus is retained on the pod and identified by hash.

Run the existing lookup fixture command with the V2 addon and add:

```sh
--powers-reference /workspace/m3/build/m7-outer-fs-ops-v2/core-powers-reference.bin
```

The harness owns the GPU lock and disables the arena. No concurrent-proof, arena-reuse, whole-request memory or performance qualification follows from these tests. Independent review found no native-helper blocker; full production-consumer gates remain separate.
