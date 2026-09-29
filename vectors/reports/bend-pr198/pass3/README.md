# Complete experimental Bend proving backend: CSP end-to-end evidence

Continues [PR #199](https://github.com/teddyjfpender/stwo-zig/pull/199), stacked
on [PR #198](https://github.com/teddyjfpender/stwo-zig/pull/198). These are real
RV32IM executions and complete STARK proofs, not FFT timings or extrapolations.

## Outcome

All 18 proofs pass: three alternating CPU/Bend pairs for each of SHA-256,
Keccak and Poseidon2 M31. Every pair has byte-identical serialized proof bytes.
Every Bend proof is verified by the ordinary CPU engine, and the prover/verifier
transcript state matches. The canonical CSP public output and cycle count are
checked against the authenticated manifest before accepting any timing.

**Bend is proof-capable, but remains slower end to end on this CPU host.**
This is a complete experimental backend integration with explicit host services,
not an all-Bend prover or a production release.

| CSP target | Input size | VM cycles | CPU median s | Bend median s | Bend / CPU |
|---|---:|---:|---:|---:|---:|
| sha256 | 128 | 14,056 | 1.991 | 16.786 | 8.43x |
| keccak | 128 | 19,114 | 1.687 | 16.854 | 9.99x |
| poseidon2_m31 | 2 | 82,297 | 1.657 | 16.176 | 9.76x |

These medians include guest execution, witness construction and proof generation.
Verification and serialization are outside that metric and reported separately.
Raw process wall time includes the complete command. The first and third pairs
run CPU then Bend; the second reverses order. No warmups or sample filtering.
Minimum canonical inputs only; ECDSA and the complete CSP size matrix were not
measured. There is no GPU, recursion or official CSP leaderboard claim.

## What is actually executed

| Operation | Owner |
|---|---|
| Circle FFT / IFFT | Bend, then exact Zig parity check |
| Combined 2x LDE | Bend IFFT plus specialized Bend forward extension |
| Secure composition interpolation | Four Bend coordinate transforms |
| Circle-to-line FRI, line and multi-fold FRI | Bend, then exact core parity check |
| FRI inverse preparation | Host batch inversion |
| Merkle commitments and lazy commitments | Existing host prover implementation |
| Composition evaluation | Injected CpuBackend implementation |
| Typed interaction generation / tuple projection | Existing host paths |
| Protocol, transcript, proof format, verifier | Unchanged Zig implementation |

Unsupported resident/device operations continue through generic host paths.
The public `BendBackendWithHost` factory injects host composition at the
integration boundary without a backend-to-backend dependency. `BendBackend`
alone supplies host commitments and generic composition. Both satisfy the full
hash-specific prover contract. There is no runtime fallback after Bend failures.

The benchmark records completed Bend requests rather than inferring execution
from the backend name. CPU samples require all counters zero; Bend samples
require actual inverse, forward and FRI calls. Per-proof observations:

| Target | FFT | IFFT | LDE forward | FRI | Request MiB | Response MiB |
|---|---:|---:|---:|---:|---:|---:|
| sha256 | 8 | 1424 | 1420 | 20 | 1221.4 | 606.7 |
| keccak | 8 | 1424 | 1420 | 20 | 1231.9 | 612.0 |
| poseidon2_m31 | 8 | 1487 | 1483 | 20 | 1225.9 | 609.0 |

Multiply/prefix prototypes are not mislabeled as typed interaction acceleration:
those counters remain zero in these proofs. The large traffic volume reflects
host serialization of every column and twiddle plan. Persistent execution removes
repeated process startup, but it does not create resident arrays or shared plans.
The parity gate deliberately adds Zig computation to Bend computation.

## Further optimizations

- One persistent native worker per proof, serialized behind a mutex. The worker
  supports 65,536 framed requests and is explicitly shut down after proving.
  Old one-shot framing remains supported; persistent mode uses distinct BND2
  magic and fails closed on an incompatible binary.
- Buffered 64 KiB IO removes per-word stdio calls. Input uses partial `read(2)`
  blocks, so a short request cannot deadlock while the caller awaits its reply.
  The C bridge still implements no field arithmetic.
- Exact 2x LDE omits the first forward butterfly layer: the upper coefficient
  half is validated as zero, then Bend clones the lower half into independent
  child transforms. The execution receipt records the skipped layer.
- FRI computes host domain inverses in one batch rather than exponentiating
  each point. Multi-fold ownership now matches the backend's consuming contract.

An exploratory unbuffered SHA run was about 22 seconds; the final median is
16.8 seconds. That was not an alternating isolated transport comparison, so it
is not reported as a controlled speedup attribution. The final paired CPU/Bend
result above is the performance conclusion.

## FRI discrepancy and qualification

The original seed42 request is unchanged. Its old ReleaseFast result differed
from Debug and Bend. Calling the existing core FRI routine with an explicit
`@call(.never_inline, ...)` boundary reproduces the retained Debug/Bend result.
The same boundary is used by the backend's numerical oracle. Core field and FRI
algorithms were not modified. This is a compiler-context workaround, not a claim
that the underlying compiler issue has been diagnosed or repaired globally.

`fri-regression.json` retains old/new words. `fri-release.json` and
`fri-debug.json` each contain 1,024 seeded fold fixtures plus larger log16-word
comparisons. Both pass. Debug timings are correctness evidence only, never the
optimized baseline. Native tests cover persistent repeated transforms, 2x LDE,
consuming three-fold FRI and circle accumulation into nonzero output. ReleaseFast
and ReleaseSafe native tests pass (5/5); integration contract tests pass (2/2).
The package-workspace audit retains the same 15 existing #198 failures, with no
new Bend/package-layer errors. Seven concrete Bend proof examples pass.

## Reproducibility and limits

`csp.json` retains all raw samples, proof hashes, public values, operation counts,
transport bytes, CPU time and per-process RSS. `build.json` binds the native and
proof executables, integration/backend sources, pinned toolchain and host.
Zig is 0.15.2 ReleaseFast; Bend is pinned 2.0.5. The native worker uses one CPU
thread because the measured workloads contain many small transforms. Host
frequency and scheduling are uncontrolled. RSS is a high-water mark, not summed
live memory across the entire process tree.

Secure PCS parameters are unchanged: pow_bits=26, n_queries=70,
log_blowup_factor=1, log_last_layer_degree_bound=0, fold_step=1. Inputs and RV32IM
ELFs come from the committed, hash-validated CSP manifest. The experimental
runner does not weaken or enroll itself into the released CSP product registry.
Proof artifacts are emitted to the harness artifact directory; recorded SHA-256
hashes bind their exact bytes, and the same commands regenerate them.

```sh
python3 scripts/build_bend_experiment.py --bend-root /path/to/pinned/bend --output .zig-cache/bend-pass3/native
zig build --build-file src/integrations/riscv_bend/build.zig -Doptimize=ReleaseFast -Dbend-executable="$PWD/.zig-cache/bend-pass3/native" --prefix "$PWD/.zig-cache/bend-pass3/qualified" -j2
python3 autoresearch/benchmarks/bend_csp.py --cli .zig-cache/bend-pass3/qualified/bin/bend-csp-bench --bend .zig-cache/bend-pass3/native --samples 3 --output /tmp/bend-csp.json
zig build test test-integration --build-file src/backends/bend/build.zig -Doptimize=ReleaseFast -Dbend-executable="$PWD/.zig-cache/bend-pass3/native" -j2
zig build test --build-file src/integrations/riscv_bend/build.zig -Doptimize=ReleaseFast -j2
```

Pinned Rust qualification, actual GPU execution, production cancellation and
full typed interaction lowering remain open. These results justify a next
experiment in resident/shared-plan execution; they do not justify selecting
Bend over CPU for production proof latency today.
