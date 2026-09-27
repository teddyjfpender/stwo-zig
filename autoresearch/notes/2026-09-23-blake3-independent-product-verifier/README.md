# Device-independent full-width product verification

Inspection found that the new artifact verifier used the selected proving backend
to reconstruct its trusted fixed key. In a Metal verify-only process, the product
intentionally does not initialize a device runtime. Verification now constructs
the key and verifies on the CPU backend in both products. In-process publication
verification also uses CPU, independently of Metal proof generation. Metal proof
dispatch telemetry remains scoped to proving.

The shared adapter reuses the CPU facade's existing backend module, avoiding Zig
file/module duplication, and creates a CPU backend only for a facade without one.
The Metal source closure explicitly admits this verifier dependency. The initial
CPU graph attempt failed on duplicate modules; that failure motivated the reuse.

Qualification pending:
- /tmp/blake3-artifact-metal-product-build-v2.log (target stwo-riscv-metal)
- /tmp/blake3-artifact-cpu-independent-verifier-build-v2.log

Next checks: Metal product proves with authenticated AOT and verifies on CPU;
verify-only operation succeeds even with an invalid AOT environment path; CPU
product freshly verifies the retained canonical artifact. Earlier base product
qualification remains in the release-artifact directory, predating this graph
change. No default promotion or extension migration is claimed.


## Metal product qualification passed

Metal product build passed. Explicit BLAKE3 secure proof generation with the
identity-bound AOT bundle completed and independently verified on CPU before
publication: 67 proof device dispatches, six CPU fallbacks, 609,851 artifact bytes.
Its statement identity and transcript exactly match the CPU canonical artifact
from the release-artifact evidence directory (same ELF, q70/26).

Separate Metal executable processes verified both CPU and Metal artifacts while
STWO_RISCV_METAL_AOT_BUNDLE pointed at /tmp/nonexistent-blake3-verifier-bundle.
This confirms verification does not enter AOT/runtime initialization. Receipts
and Metal artifact are retained here. CPU rebuild after module reuse fix remains
pending. These tiny ReleaseSafe runs qualify integration, not CSP performance.


## CPU rebuild and cross-product verification passed

The corrected CPU product build passed. Fresh processes of that rebuilt executable
verified both retained CPU and Metal canonical artifacts, matching their original
transcripts. Together with the Metal verify-only checks above, all four producer /
verifier combinations are qualified on the tiny canonical base fixture. Full
product test suites and broad extension/CSP migration are not claimed by this gate.
