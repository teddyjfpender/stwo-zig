# H200 circuit witness replay, 2026-10-01

This is the same two continuous Starknet PIEs and production security registry
as the [original 32.308 s H100 receipt](../cuda-resident-pipeline-h100-20261001/receipt.json).
The scope starts with already adapted PIE inputs and ends with a verified
recursive root; PIE execution, adaptation, queueing, and build are excluded.
The exact measurements, digests, and CUDA ingress timings are in
[measurements.json](measurements.json).

The change retains authenticated static Cairo assets across both requests,
and on a cached circuit topology computes variable values without rebuilding
gate arrays. Padding gates with constant outputs are bulk-filled. The
independent CUDA proof verifier and expected preprocessed commitment remain
in the publication path. The first leaf still constructs the topology; the
second leaf reuses it. The canonical root still has the pinned Rust proof
bytes. The compact terminal root is a separate, experimental circuit whose
proof bytes differ; only its output digest is compared with the qualified
reference.

| Configuration | Adapted input to root | Cairo | Two wraps | Fold | Process overhead | Peak host RSS | Peak device use |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| H100 original, separate processes | 32.308 s | 9.494 s | 12.579 s | 9.021 s | 1.214 s | 4.70 GiB | not sampled |
| H200 canonical, earlier integrated run | 15.195–15.323 s | 7.321–7.349 s | 3.983–4.220 s | 2.904–2.914 s | 0.868–0.960 s | not recorded | not sampled |
| H200 canonical, witness replay, warm | 15.372 s | 7.744 s | 3.339 s | 2.156 s | 1.200 s | 2.93 GiB | not sampled |
| H200 compact terminal, earlier warm | 13.363 s | 6.987 s | 4.074 s | 1.340 s | 0.962 s | not recorded | ~54.9 GB, separate sample |
| H200 compact terminal, witness replay, two warm trials | 13.203–13.548 s | 6.978–7.290 s | 3.028–3.079 s | 0.982–1.187 s | 1.052–1.296 s | 2.78 GiB | 51.11 GiB, sampled trial |

The first profiled canonical trial took 20.485 s because the fixed-image
upload/load took 9.703 s; it is recorded in the JSON but excluded from warm
comparisons. The second profiled request did reuse the authenticated image.
The warm canonical trial matched the pinned Rust-qualified leaf and root
proof, root outputs, and packed-root digests. Both compact trials matched the
leaf proof and root output digests. The compact root needs a versioned registry
and an external verifier before it can replace the canonical protocol.

The replay change reduced the pair of leaf wraps, but **did not materially
improve end-to-end latency**. In the memory-sampled compact trial, Cairo alone
took 6.978 s. Its two actual Cairo GPU proof-execute/decode calls took about
0.439 and 0.336 s; the rest was ingress and setup. The first fixed-image load
took 2.769 s; source preparation took 1.166 and 0.674 s. Source-stage profiling
attributed 0.907 and 0.481 s to adapted-input read/parse, and 0.222 and
0.189 s to request compilation. The two circuit proof calls took about 0.470
and 0.493 s; their independent verifications took about 4 ms each. The cached
leaf still spends substantial time computing its 44.5-million-variable
witness on the host.

The 10× target from the H100 receipt is **3.231 s** and remains unachieved.
The next architecture should retain the fixed GPU image and canonical request
plan in a long-lived worker, compile/replay the verifier witness with the
topology rather than running the builder for each leaf, and remove repeated
JSON parse work at the adapter boundary. Only then is it useful to schedule
independent PIE/leaf lanes concurrently within the measured device-memory
budget; the earlier two-process overlap was slower because it duplicated
static setup and competed for the GPU. Each step needs same-host full-pipeline
timing, whole-device memory, and exact qualified proof/output digests.
