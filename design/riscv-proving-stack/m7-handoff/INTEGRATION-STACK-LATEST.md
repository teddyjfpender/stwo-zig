# M7 combined stack: latest measured status

The new combined stack has not completed a root proof. The requested interleaved three-warm-request comparison per arm has **NOT RUN**. R1 is OFF in both timed arms; its earlier diagnostics are separate.

| Configuration / evidence | Status | Actual result | Limits |
|---|---|---|---|
| Accepted D2 + truth coalescing, headline 24628607 | **ACCEPTED; diagnostic timing** | Warm request **12.935343494 s**; 14 native leaves, 19 recursive nodes; fresh CPU acceptance | Historical frozen 9cf/a25 pair, profiled and not quiet-qualified; not the new 3+3 comparison. Automatic arena; 28 GB memory target failed. |
| New matched headline baseline/fullstack, three warm requests each | **NOT RUN** | No medians or speedup | Waiting for combined correctness, complete payload parity and fresh receiver. |
| R1 OFF, GLOBAL1, frozen 6e8, small 26235156 | **FAILED** | Native output completed; first PP-pack allocation lacked a permit, ticket=0 | No root, warm request or fresh receiver. |
| R1 OFF, GLOBAL0 fallback, frozen 6e8, same small block | **FAILED: real arena OOM** | RC requested **11,240,738,728 B**, with **13,616,468,480 B** already live against a **23,622,320,128 B** arena | Removing admission did not make two-lane residency fit. No root or timing qualification. |
| PP-entry permit fix, frozen 9a3/a25, GLOBAL1 | **FAILED: liveness stall** | Passed the previous PP-pack failure; 200 admitted stages and one Sparse completion; native payload **13/13** files plus bundle matched control, published recursive files **3/3** matched | Watchdog at 120 s. Partial parity only; no root, full parity, warm request or fresh receiver. |
| Authorized same-9a3 bounded stall capture | **FAILED: reproduced stall; diagnostic captured** | Last admitted stage193. Both GPUs sampled at 0% for approximately **97 s** before watchdog; native payload **13/13** plus bundle matched, recursive partial **2/2** matched | GDB attach refused by container ptrace; blocked request/capacity locals remain unknown. No repeat authorized. |
| V2 runtime + new driver | **BUILD / FIXTURE PENDING** | Admission WAIT diagnostics and concurrent-owner accounting prepared | No candidate proof, performance or memory-success claim until actual selected-artifact receipt. |

The full arm uses a physical reservation guard whose enforced prover ceiling is **27,998,552,064 B per GPU**. This is a hard availability bound, **not an observed process peak**. Failed runs do not establish a proof under the bound. The original baseline is unguarded with its automatic arena, preserving the accepted baseline configuration.

The accepted historical result is documented in [the D2 receipt report](../../../vectors/reports/rv64-m7-20261105/d2-composed/README.md). Current partial-artifact hashes and stall diagnostics are in [integration-stack receipts](../../../vectors/reports/rv64-m7-20261105/integration-stack/). The raw failure monitor remains on the pod at `/workspace/m3/runs/m7-one-stack-pp/daemon-26235156-r1-one-stack-stall-9a3-00-fullstack/resource-final.json`; it is also preserved in the local artifact archive. NVML utilization is sampled whole-device activity, not process-exclusive GPU time.

Selected failed driver: `9a3c814047fa491d1e03dca372a6e489c715212978fd6794bd654c4f1bf41bdb`; image: `a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45`. No proof-size candidate or R1 diagnostic is included in the timed stack. Next status change requires an actual new V2 smoke receipt.
