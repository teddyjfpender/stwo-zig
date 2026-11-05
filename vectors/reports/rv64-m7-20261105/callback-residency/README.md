# Callback ownership [M: two headline profiler captures; one cold scale probe]

The exact-v3 preset capture has two independently accepted headline proofs and every native/bundle/recursive-tree/node byte matches the M6 default. The first launch omitted parts of that performance preset; it is retained as diagnostic evidence and is not an A/B control. Neither one-shot capture establishes a latency gain. Small-block closure for these instrumentation changes is still pending.

The exact-preset warm headline request is17.604s, capture2.032s, native setup0.137s and native proving4.519s. This is consistent with the historical17.3s result within pod noise, not a new speedup. GPU work is assigned by CUDA runtime correlation IDs, including kernels that execute after their enqueue range closes. No activities lack a unique runtime correlation. NVTX totals below are clipped to after native completion plus a5ms boundary uncertainty band.

| After-native owner/stage | Headline warm host-thread s | Headline kernel GPU-s | Scale cold host-thread s | Scale kernel GPU-s |
|---|---:|---:|---:|---:|
| All ordinary owner callbacks |11.602|7.055|24.497|12.846|
| PCS owner |3.206|2.999|5.802|5.444|
| MAIN assignment, inside callbacks |2.446|1.575|4.257|2.855|
| INTER witness, inside callbacks |1.340|1.134|2.695|2.065|
| Trace MAIN, inside callbacks |1.146|0.739|2.059|1.348|
| Trace INTER, inside callbacks |1.755|1.356|3.956|2.494|
| Composition, inside callbacks |2.926|2.055|7.253|3.732|

Rows are inclusive: callback children must not be added to their parent, and host-thread seconds across GPUs are not request wall seconds. GPU-seconds are interval unions separately per physical GPU. The headline PCS retirement wait1.058s is largely waiting for kernels enqueued in earlier PCS phases; a zero-kernel retirement label does not make that wait avoidable CPU overhead. Similarly, composition's2.083s stream-sync host time overlaps its2.055GPU-s of kernels. Its VMM mapping/access plus unmapping host calls total~0.472s; these are measured calls, not a proven critical-path saving. Ordinary owner callback host waits include3.664s event sync,3.467s stream sync and0.545s VMM access calls. Deleting every wait is not a valid speedup model.

The only24697070 request is a cold scale probe:69.871s request,3.262s capture,23.239s setup,13.557s native,29.419s harness recursion stage; a fresh CPU receiver accepted in91.5s. Its cold class construction and setup must not be treated as warm steady-state latency. No larger block was run.

Driveraf386 was built from integratione4ef plus the hashed overrides, including the fail-closed early-recursion capability gate. It is not the historic197b binary. Runtime05e preserves the qualified fused-Blake numerical objects and adds parent/nested ranges; its full build receipt is in the device-fs report. Raw receipts retain the stale source marker unchanged; driver-source-hashes.json is the explicit source attestation. The build's initial local-name shadowing failure is retained and fixed by renaming the capability callback before the successful executable build.
