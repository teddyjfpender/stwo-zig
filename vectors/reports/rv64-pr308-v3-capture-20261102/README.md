# V3 execution and classic proving baseline

Pinned snapshot2490495dd, RV64IM evmone v3:26,894,777 instructions,7CPU+6truth proofs. Complete classic services proof: **37.711s proving**, **42.76s process wall**, **20.893GB peak RSS**. A fresh receiver accepts the full block and expected43-byte output. Exact MAIN+INTER cells: **5,411,549,280** (CPU3,693,026,400, truths1,718,522,880); fixed cells excluded.

This uses **QM31/q70/P26/blowup1/fold1**, nominal96-bit PCS control. It is not an OM31/GKR or128-bit-target result, and its timing cannot be compared as an equally secure alternative to the143.85s native OM/GKR v2 run.

The full v3 guest exercises bulk/JUMPDEST, sponge, SHA256 and arith256_mod, plus the existing Keccak/secp providers. Default LS-D64, fused-tail/U8-pair CPU geometry and throughput Keccak are captured in plan.json. BN/BLS providers are not exercised by this block. GKR admission correctly rejects this inventory withGkrV3ServiceUnsupported.

These packets and the accepted classic proof provide the reference for v3 OM/GKR adapter work while PR308 continues. Large artifacts remain in the scratch paths recorded in request.json; hashes and reports are committed. No GPU, recursion or final-client EEST qualification is implied.

The first OM31 adapter prerequisite is implemented: two bulk rational-query helpers no longer require QM31-only challenges. Safe/Fast tests exercise all nine bulk/JUMPDEST kinds with full eight-coordinate OM31 challenges against paired independent QM31 evaluations. Weights and relation ordering match. This does not enable v3 admission or constitute a complete OM31 bulk PCS proof.
