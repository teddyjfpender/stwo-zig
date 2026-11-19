# Shared support modules

This layer owns small platform and I/O helpers. The build wires these
modules into existing products and compatibility surfaces.

| Directory | Interfaces |
| --- | --- |
| [`io/`](io/) | `atomic_file` prepares and publishes files exclusively. `output_transaction` prepares and publishes proof/report outputs. `bzip2.compressAlloc` encodes a buffer. |
| [`shims/`](shims/) | `stwo_std_shims.verifier_profile` exposes lightweight verifier-specific shims and a freestanding entry point. |
| [`tracing/`](tracing/) | `stwo_tracing.SpanAccumulator` groups span durations by class and can export CSV. |

Proving, statement and verifier behavior belongs to the owning protocol or
product package.
