# Session 06: Mixed-Service Hardware Closure

Commit `71bda1cd41a8a539554524d4c9e7401274c4b563` was built cleanly
with Zig 0.15.2, CUDA 12.8, and authenticated SM89 AOT modules on the locked
RTX 4090 host. The product executed two deterministic
wide-Fibonacci/Poseidon/state-machine cycles through one process-owned runtime.

The six-request service completed in 60.011 ms after runtime and shape
preparation. The first request paid graph warmup; the second cycle's verified
requests were 4.459 ms, 4.485 ms, and 2.559 ms respectively. Aggregate service
throughput was 10.955 row-MHz and 372.943 million committed cells/s. These
heterogeneous units are diagnostic and are not compared as a single proof
speed.

Every request:

- used exact authenticated AOT on SM89;
- was resident with zero CPU fallback;
- performed one terminal proof read;
- passed the Zig verifier;
- produced the same canonical bytes as its repeated family request; and
- was independently accepted by the pinned Rust Stwo verifier binary
  `a14c130ce59379fb2ede7f45c132aa864cef4a22119504ec4014a6f3e4d1e04a`.

The immutable product report correctly recorded that oracle receipts were
absent when it was published. The external `mixed-service/receipt.json`
supersedes that missing-evidence blocker without rewriting the report. It
binds the report, product binary, device, all six artifact hashes, and all six
Rust acceptances.

The sustained row remains disabled in the structural controller because that
controller only understands one-proof product reports. Enabling it requires a
service-schema adapter and locked-host A/A calibration. Exact Native
Plonk/LogUp CUDA coverage remains a separate blocker for `core_cuda`.
