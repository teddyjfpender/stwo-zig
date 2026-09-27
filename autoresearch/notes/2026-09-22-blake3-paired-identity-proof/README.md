# Paired BLAKE3 identity STARK proof

Added a dedicated test-riscv-blake3-identities gate. It proves the paired job and
statement hashes with shared scalar packing/canonical encoding, both full BLAKE3
hash graphs and the range/bitwise lookup tables. Trusted preprocessing is generated
independently using the paired plan's message-free constructors. Public scalar
boundary rows pin the canonical statement words for this fixture.

The ReleaseSafe gate passed (30 seconds build/run, 1 GB reported peak RSS). The
existing shared proof gate proves and verifies under BLAKE3 PCS/transcript,
compares live and trusted fixed columns, and checks rejection against preprocessing
with a changed high-bit job digest. This is a real CPU STARK proof at diagnostic
parameters: 8 FRI queries and 0 PoW bits. These timings are build/run qualification,
not a prover performance measurement or canonical CSP security configuration.

The proof does not include production statement ingress, semantic folding AIR,
memory/continuation commitments or recursive child proof verification. The separate
joined-row tests establish the new consumers' differential compatibility with
row-11 fanout; that connection still needs production proof assembly. Public
scalar inputs here must not be mistaken for production private statement admission.

Remaining: integrate the identity roster/claims into production recursion and key
admission, migrate remaining Poseidon commitments and qualify multiple recursion
levels on CPU/Metal before promoting defaults.
