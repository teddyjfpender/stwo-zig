# BLAKE3 product defaults

The shared CPU/Metal RISC-V CLI now defaults to BLAKE3, including regular prove,
bench, verify and CSP ECDSA commands. Explicit `--proof-suite blake2s` remains
available for historical artifacts and comparisons. The CSP runner and its
software/precompile entry points also default to BLAKE3, and always send an
explicit suite to the executable. This changes the selected protocol, not the
canonical CSP security parameters (70 queries, 26 PoW bits).

Focused selection tests cover ordinary and ECDSA command defaults, explicit
historical selection, and malformed/duplicate suite arguments. CSP runner tests
exercise default and explicit suite propagation through measurement and report
publication. Legacy report-decoder defaults remain BLAKE2s for their historical
schemas; measurement callers supply their selected suite explicitly.

The default switch does not remove the legacy proving implementation. Remaining
production cleanup includes the legacy branch in proof_adapter.zig, guest_profile
routing, and the legacy CSP proving branch in products/riscv_shared/csp_ecdsa.zig.
Historical artifact verification must retain exact suite and wire admission.
Guest Poseidon permutation semantics are intentionally preserved.

CPU/Metal product builds and default-route runtime checks pass. This note
is not a new performance result. Clean CSP benchmarks and the original recursion
performance objective remain unfinished.


Metal default-route qualification passed without a suite flag: the real guest
Poseidon precompile ELF produces a BLAKE3 full-width artifact at q70/PoW26.
Its 1,091,213 bytes exactly match the retained explicit-suite artifact. Separate
verification also passes with a nonexistent AOT bundle path, demonstrating that
verification does not initialize the proving device. The retained input and ELF
are in the sibling shared-extension-pipeline evidence directory. This was a dirty
ReleaseSafe qualification overlapping CPU compilation, not a speed measurement.
The suite-selection test, 73 CSP reader/precompile tests and 14 runner-wiring tests
pass. The latter cover default selection and explicit historical-suite override.

CPU default-route proving and standalone verification also pass. The CPU artifact
is byte-identical to the Metal and retained explicit-suite artifacts. The combined
product build passes all four build steps; build and verification receipts are retained.
