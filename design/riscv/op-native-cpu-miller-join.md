# Closed OP native CPU/Miller join

The focused `test-riscv64-op-native-join` gate now proves a real 640-byte
Miller-line ECALL in the CPU and its arithmetic provider under the pure-P2
manifest. Independent receiver setup and fixed keys accept both proofs and
close global RAM and Wire debts. CPU proof: 599,024 bytes; truth: 555,856 bytes.
These are correctness results, not full-block timings or production admission.

`pure_p2_cpu_worker.Worker.initForOp` and `verifyForOp` reuse the existing
pipeline with an explicit `OpTowerSpan`. Legacy entrypoints reject OP setup.
`Key.initForOp` separates immutable OP source authority from request identity:
ordered geometry and source roots belong in the key; calls and first_id belong
in `statementForOp`. The source-owned OP GKR roster closes OWNER and ranges;
the extra global component exports only RAM and Wire claims. Both sender and
fresh receiver recompute the extra 160 RAM/32 Wire mass per call.

Worker initialization requires explicit local/global limits. Source-checkpoint
planning matches the numerical implementation, and synchronized allocator
owners remain alive until retained numerical results are freed. Terminal
binding uses the same local budget; classic global buffers use a separate cap.
Setup, source construction, commitment trees, PCS/FFT scratch and thread stacks
remain outside these payload limits. A one-byte local budget is rejected before
owned MAIN is consumed; the fixture uses 1 GiB per payload family.

The fixture rejects wrong span/presence/profile, missing local/global providers,
manifest authority changes, altered physical claims and changed manifest digest.
The original two-CPU/five-step native pure-P2 fixture also passes. The receipt
pins its proof hashes to support independent legacy parity checks.

Open work remains the actual guest's other truth providers, complete block
inventory/framing and fresh-process receiver, source-bound recursion, and a
controlled full-heavy benchmark. The profile targets 128-bit security under
documented assumptions; this gate does not certify the entire construction.
