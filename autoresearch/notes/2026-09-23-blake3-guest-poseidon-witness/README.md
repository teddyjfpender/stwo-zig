# Guest Poseidon over BLAKE3 execution commitments

Problem: the guest Poseidon adapter still required the legacy program/memory
admission certificate, preventing removal of prover-owned Poseidon commitments.
The guest permutation itself remains part of the guest ISA and must be preserved.

Implemented full-width witness ownership, typed admission, independently checked
ELF/input binding, guest main/interaction generation, and shared fixed-table
registration. Guest rows reuse the existing caller/provider construction and row
preflight. Native relation challenges come from the universal BLAKE3 providers;
only the guest-specific challenge pair is appended. Ethereum and Poseidon now
share the conservative BLAKE3 fixed-table and memory coefficient bounds.

Qualification: ReleaseSafe focused guest compatibility gate passed. The Ethereum
external witness census also passed with the extracted shared bounds: one Keccak
and one signer call, closed relations, and no legacy commitment components. The actual
Poseidon guest fixture publishes an empty output through the release ABI. Its
native + BLAKE3 + guest interaction claims cancel, its native roster has no legacy
commitment components, and every external fetch is included in the program plan.
Mutated call counts and admission certificates reject. Independent source
validation reconstructs the full-width roots from the supplied ELF/input.

The first fixture omitted the required output-length store and correctly failed
with OutputAddressNotAccessed; the fixture was corrected. Compatibility testing
also caught a malformed-count error-order regression; the previous validation
order was restored before the passing run.

Commands:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe '-Driscv-test-filter=guest' --summary all
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe '-Driscv-test-filter=Ethereum external witness census' --summary all
```

This is witness/admission qualification, not a new complete guest Poseidon proof
or a performance result. Still required: proof assembly and transcript, independently
pinned artifact/key decoding, product routing, recursive capture support, and
CPU/Metal proof qualification. Existing base/Ethereum products have not been
switched by this work. Default promotion and removal of obsolete commitment
routes remain pending, as do clean ReleaseFast CSP timings and the original
recursion performance work.
