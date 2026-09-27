# Full-width CSP ECDSA command integration

The BLAKE3 dedicated command now delegates to the shared full-width product
transaction. Fresh verification checks the external statement pin, canonical
70-query/26-PoW-bit policy, actual ELF/input, and authenticated CSP public output.
The public summary requires one signer, no Keccak, halt, and the exact success
output. CPU verification requires no device runtime. Historical legacy-memory
ECDSA timings are not full-width migration results.

Evidence so far: CPU product build passed; 29 focused Python tests passed;
standalone Zig public-summary contract test passed. CLI rejected missing,
malformed and invalid-hex external statement pins. Final CPU/Metal build and real
canonical ECDSA qualification were still running when this checkpoint was written.
The retained stack sample observed actual parallel Merkle hashing and 44.1 GiB
physical footprint; it is not an end-to-end benchmark. No performance claim.

New full-width precompile reports use disjoint phase accounting and fresh retained
CSP verification. The reader preserves clean-build publication checks and never
invents software trace evidence for the different precompile guest.


## Qualification outcome and storage follow-up

Both CPU and Metal command builds passed (4/4 build steps). The canonical CPU
ECDSA run was stopped with SIGTERM (exit 143) after a second stack sample measured
81.2 GiB physical footprint on this 64 GiB host. No proof or benchmark report was
published. The lower RSS observed between samples reflected residency, not a
reduction in the process's charged memory footprint. Both samples locate active
work in PCS Merkle leaf construction; no deadlock was observed.

The full-width leaf prover and independent key derivation now opt out of retaining
coefficient duplicates and prepare borrowed columns in batches of eight. This
uses ordinary in-memory storage, preserves source ownership, and does not alter
protocol parameters. A focused PCS gate passed 3/3 tests, including complete proof
equality/fresh verification and allocation-failure ownership. This is evidence
for storage semantics, not yet evidence that ECDSA fits or becomes fast.
Final product builds with this storage change remain in progress.


## Storage change qualification

Final CPU/Metal products passed 4/4 build steps. The secure (70 queries, 26 PoW
bits) base ELF proof passed on both backends. Statement, transcript, artifact
size and complete artifact SHA-256 exactly match the pre-change retained CPU
result. CPU and Metal also produced identical artifacts. Separate cross-verifiers
passed; Metal verification used an intentionally absent AOT path, confirming no
runtime requirement for verification.

Metal telemetry for this bounded preparation was 131 dispatches / 36 CPU
fallbacks, versus the earlier base path's 67 / 6. This is a storage policy change,
not a measured performance improvement. Full ECDSA memory admission, successful
canonical ECDSA verification, and CPU/Metal suite timings remain outstanding.
Do not repeat the unbounded ECDSA run without addressing the measured host limit.
